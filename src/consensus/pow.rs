//! Proof-of-work mining for shielded blocks.

use crate::core::ShieldedBlock;

/// Mine a block by finding a valid nonce.
///
/// Increments the nonce until the block hash meets the difficulty target.
/// Returns the number of hashes computed.
pub fn mine_block(block: &mut ShieldedBlock) -> u64 {
    let mut attempts = 0u64;

    loop {
        if block.header.meets_difficulty() {
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
