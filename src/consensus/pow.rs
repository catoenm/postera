//! Proof-of-work mining for shielded blocks.

use crate::core::{BlockHeader, BlockHeaderHashPrefix, ShieldedBlock};
use sha2::compress256;
use sha2::digest::generic_array::GenericArray;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc, Arc, Mutex,
};
use std::thread::JoinHandle;

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
///
/// Note: this spawns new worker threads each call. For repeated mining,
/// create a `MiningPool` and reuse it across blocks.
pub fn mine_block_with_jobs(block: &mut ShieldedBlock, jobs: usize) -> u64 {
    let jobs = jobs.max(1);
    if jobs == 1 {
        return mine_block_single(block);
    }

    let pool = MiningPool::new(jobs);
    pool.mine_block(block)
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

enum WorkerCommand {
    Mine(MineJob),
    Stop,
}

/// Optional SIMD mode for mining.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SimdMode {
    Neon,
}

impl SimdMode {
    pub fn is_supported(self) -> bool {
        match self {
            SimdMode::Neon => neon_supported(),
        }
    }
}

struct MineJob {
    template: ShieldedBlock,
    found: Arc<AtomicBool>,
    attempts_total: Arc<AtomicU64>,
    result: Arc<Mutex<Option<ShieldedBlock>>>,
    done_tx: mpsc::Sender<()>,
}

struct FastHashPrefix {
    state_after_prefix: [u32; 8],
    tail_block: [u8; 64],
}

impl FastHashPrefix {
    fn new(header: &BlockHeader) -> Self {
        let mut prefix = [0u8; 132];
        prefix[0..4].copy_from_slice(&header.version.to_le_bytes());
        prefix[4..36].copy_from_slice(&header.prev_hash);
        prefix[36..68].copy_from_slice(&header.merkle_root);
        prefix[68..100].copy_from_slice(&header.commitment_root);
        prefix[100..132].copy_from_slice(&header.nullifier_root);

        let mut state = SHA256_INIT;
        let block0 = GenericArray::from_slice(&prefix[0..64]);
        let block1 = GenericArray::from_slice(&prefix[64..128]);
        compress256(&mut state, std::slice::from_ref(block0));
        compress256(&mut state, std::slice::from_ref(block1));

        let mut tail_block = [0u8; 64];
        tail_block[0..4].copy_from_slice(&prefix[128..132]);
        tail_block[28] = 0x80;
        tail_block[56..64].copy_from_slice(&(HEADER_LEN_BYTES as u64 * 8).to_be_bytes());

        Self {
            state_after_prefix: state,
            tail_block,
        }
    }

    fn meets_difficulty(&mut self, timestamp: u64, difficulty: u64, nonce: u64) -> bool {
        self.tail_block[4..12].copy_from_slice(&timestamp.to_le_bytes());
        self.tail_block[12..20].copy_from_slice(&difficulty.to_le_bytes());
        self.tail_block[20..28].copy_from_slice(&nonce.to_le_bytes());

        let mut state = self.state_after_prefix;
        let block = GenericArray::from_slice(&self.tail_block);
        compress256(&mut state, std::slice::from_ref(block));

        let mut hash = [0u8; 32];
        for (i, word) in state.iter().enumerate() {
            hash[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }

        count_leading_zeros_scalar(&hash) >= difficulty as usize
    }
}

/// Persistent worker threads for mining multiple blocks efficiently.
pub struct MiningPool {
    jobs: usize,
    simd: Option<SimdMode>,
    senders: Vec<mpsc::Sender<WorkerCommand>>,
    handles: Mutex<Vec<JoinHandle<()>>>,
}

impl MiningPool {
    pub fn new(jobs: usize) -> Self {
        Self::new_with_simd(jobs, None)
    }

    pub fn new_with_simd(jobs: usize, simd: Option<SimdMode>) -> Self {
        let jobs = jobs.max(1);
        let mut senders = Vec::with_capacity(jobs);
        let mut handles = Vec::with_capacity(jobs);

        for worker_id in 0..jobs {
            let (tx, rx) = mpsc::channel();
            senders.push(tx);

            let simd = simd;
            let handle = std::thread::spawn(move || {
                while let Ok(command) = rx.recv() {
                    match command {
                        WorkerCommand::Mine(job) => run_mining_job(job, worker_id, jobs, simd),
                        WorkerCommand::Stop => break,
                    }
                }
            });

            handles.push(handle);
        }

        Self {
            jobs,
            simd,
            senders,
            handles: Mutex::new(handles),
        }
    }

    pub fn jobs(&self) -> usize {
        self.jobs
    }

    pub fn mine_block(&self, block: &mut ShieldedBlock) -> u64 {
        let found = Arc::new(AtomicBool::new(false));
        let attempts_total = Arc::new(AtomicU64::new(0));
        let result = Arc::new(Mutex::new(None));
        let (done_tx, done_rx) = mpsc::channel();

        let template = block.clone();
        let mut active_workers = 0usize;

        for sender in &self.senders {
            let job = MineJob {
                template: template.clone(),
                found: Arc::clone(&found),
                attempts_total: Arc::clone(&attempts_total),
                result: Arc::clone(&result),
                done_tx: done_tx.clone(),
            };

            if sender.send(WorkerCommand::Mine(job)).is_ok() {
                active_workers += 1;
            }
        }

        drop(done_tx);

        for _ in 0..active_workers {
            let _ = done_rx.recv();
        }

        if let Some(winner) = result.lock().unwrap().take() {
            *block = winner;
        }

        attempts_total.load(Ordering::Relaxed)
    }
}

impl Drop for MiningPool {
    fn drop(&mut self) {
        for sender in &self.senders {
            let _ = sender.send(WorkerCommand::Stop);
        }

        self.senders.clear();

        if let Ok(mut handles) = self.handles.lock() {
            for handle in handles.drain(..) {
                let _ = handle.join();
            }
        }
    }
}

fn run_mining_job(job: MineJob, worker_id: usize, jobs: usize, simd: Option<SimdMode>) {
    let MineJob {
        mut template,
        found,
        attempts_total,
        result,
        done_tx,
    } = job;

    template.header.nonce = template.header.nonce.wrapping_add(worker_id as u64);

    let prefix = BlockHeaderHashPrefix::new(&template.header);
    let step = jobs as u64;
    let use_neon = simd == Some(SimdMode::Neon) && neon_supported();
    let mut fast_prefix = if use_neon {
        Some(FastHashPrefix::new(&template.header))
    } else {
        None
    };
    let mut attempts = 0u64;

    loop {
        if found.load(Ordering::Relaxed) {
            break;
        }

        if meets_difficulty_simd(
            fast_prefix.as_mut(),
            &prefix,
            template.header.timestamp,
            template.header.difficulty,
            template.header.nonce,
        ) {
            if !found.swap(true, Ordering::Relaxed) {
                let mut guard = result.lock().unwrap();
                *guard = Some(template.clone());
            }
            break;
        }

        template.header.nonce = template.header.nonce.wrapping_add(step);
        attempts += 1;

        if attempts % 1_000_000 == 0 {
            template.header.timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
        }
    }

    attempts_total.fetch_add(attempts, Ordering::Relaxed);
    let _ = done_tx.send(());
}

fn meets_difficulty_simd(
    fast_prefix: Option<&mut FastHashPrefix>,
    prefix: &BlockHeaderHashPrefix,
    timestamp: u64,
    difficulty: u64,
    nonce: u64,
) -> bool {
    if let Some(fast) = fast_prefix {
        fast.meets_difficulty(timestamp, difficulty, nonce)
    } else {
        prefix.meets_difficulty(timestamp, difficulty, nonce)
    }
}

#[cfg(target_arch = "aarch64")]
fn neon_supported() -> bool {
    std::arch::is_aarch64_feature_detected!("neon")
        && std::arch::is_aarch64_feature_detected!("sha2")
}

#[cfg(not(target_arch = "aarch64"))]
fn neon_supported() -> bool {
    false
}

const HEADER_LEN_BYTES: usize = 4 + 32 * 4 + 8 * 3;
const SHA256_INIT: [u32; 8] = [
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19,
];

fn count_leading_zeros_scalar(bytes: &[u8]) -> usize {
    let mut zeros = 0;
    for byte in bytes {
        if *byte == 0 {
            zeros += 8;
        } else {
            zeros += byte.leading_zeros() as usize;
            break;
        }
    }
    zeros
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
