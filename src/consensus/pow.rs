//! Proof-of-work mining for shielded blocks.

use crate::core::{BlockHeaderHashPrefix, ShieldedBlock};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex,
};

/// Mine a block by finding a valid nonce.
///
/// Increments the nonce until the block hash meets the difficulty target.
/// Returns the number of hashes computed.
pub fn mine_block(block: &mut ShieldedBlock) -> u64 {
    mine_block_with_jobs(block, 1)
}

/// Mine a block using multiple threads.
///
/// Each thread searches a disjoint nonce sequence to avoid duplicate hashes.
/// Returns the number of hashes computed.
pub fn mine_block_with_jobs(block: &mut ShieldedBlock, jobs: usize) -> u64 {
    let jobs = jobs.max(1);
    if jobs == 1 {
        return mine_block_single(block);
    }

    let found = Arc::new(AtomicBool::new(false));
    let attempts_total = Arc::new(AtomicU64::new(0));
    let result = Arc::new(Mutex::new(None));

    let mut handles = Vec::with_capacity(jobs);
    for worker_id in 0..jobs {
        let mut local_block = block.clone();
        local_block.header.nonce = local_block
            .header
            .nonce
            .wrapping_add(worker_id as u64);

        let prefix = BlockHeaderHashPrefix::new(&local_block.header);
        let found = Arc::clone(&found);
        let attempts_total = Arc::clone(&attempts_total);
        let result = Arc::clone(&result);
        let step = jobs as u64;

        handles.push(std::thread::spawn(move || {
            let mut attempts = 0u64;
            loop {
                if found.load(Ordering::Relaxed) {
                    break;
                }

                if prefix.meets_difficulty(
                    local_block.header.timestamp,
                    local_block.header.difficulty,
                    local_block.header.nonce,
                ) {
                    if !found.swap(true, Ordering::Relaxed) {
                        let mut guard = result.lock().unwrap();
                        *guard = Some(local_block.clone());
                    }
                    break;
                }

                local_block.header.nonce = local_block.header.nonce.wrapping_add(step);
                attempts += 1;

                if attempts % 1_000_000 == 0 {
                    local_block.header.timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                }
            }

            attempts_total.fetch_add(attempts, Ordering::Relaxed);
        }));
    }

    for handle in handles {
        let _ = handle.join();
    }

    if let Some(winner) = result.lock().unwrap().take() {
        *block = winner;
    }

    attempts_total.load(Ordering::Relaxed)
}

fn mine_block_single(block: &mut ShieldedBlock) -> u64 {
    let prefix = BlockHeaderHashPrefix::new(&block.header);
    let mut attempts = 0u64;

    loop {
        if prefix.meets_difficulty(
            block.header.timestamp,
            block.header.difficulty,
            block.header.nonce,
        ) {
            return attempts;
        }

        block.header.nonce = block.header.nonce.wrapping_add(1);
        attempts += 1;

        // Update timestamp periodically to avoid stale blocks
        if attempts % 1_000_000 == 0 {
            block.header.timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
        }
    }
}

/// A miner that can be started and stopped.
pub struct Miner {
    running: std::sync::atomic::AtomicBool,
}

impl Miner {
    pub fn new() -> Self {
        Self {
            running: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn stop(&self) {
        self.running
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn start(&self) {
        self.running
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Default for Miner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_miner_state() {
        let miner = Miner::new();

        assert!(!miner.is_running());

        miner.start();
        assert!(miner.is_running());

        miner.stop();
        assert!(!miner.is_running());
    }
}
