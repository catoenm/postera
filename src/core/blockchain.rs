//! Shielded blockchain implementation.
//!
//! The blockchain manages the chain of shielded blocks, the commitment tree,
//! and the nullifier set. All transaction data is private - only fees and
//! roots are visible.

use std::collections::HashMap;
use std::sync::Arc;

use crate::consensus::{
    calculate_next_difficulty, should_adjust_difficulty, ADJUSTMENT_INTERVAL, MIN_DIFFICULTY,
};
use crate::crypto::{
    note::{Note, ViewingKey},
    proof::VerifyingParams,
};
use crate::storage::Database;

use super::block::{BlockError, ShieldedBlock, BLOCK_HASH_SIZE};
use super::state::{ShieldedState, StateError};
use super::transaction::{CoinbaseTransaction, ShieldedTransaction};

/// The mining reward in smallest units.
pub const BLOCK_REWARD: u64 = 50_000_000_000; // 50 coins with 9 decimal places

/// The shielded blockchain - manages chain, commitment tree, and nullifier set.
pub struct ShieldedBlockchain {
    /// All blocks indexed by hash.
    blocks: HashMap<[u8; 32], ShieldedBlock>,
    /// Block hashes by height.
    height_index: Vec<[u8; 32]>,
    /// Current shielded state (commitment tree + nullifier set).
    state: ShieldedState,
    /// Current mining difficulty.
    difficulty: u64,
    /// Optional persistent storage.
    db: Option<Arc<Database>>,
    /// Orphan blocks (blocks whose parent we don't have yet).
    orphans: HashMap<[u8; 32], ShieldedBlock>,
    /// Verifying parameters for zk-SNARK proof verification.
    verifying_params: Option<Arc<VerifyingParams>>,
}

impl ShieldedBlockchain {
    /// Create a new blockchain with a genesis block (in-memory only).
    pub fn new(difficulty: u64, genesis_coinbase: CoinbaseTransaction) -> Self {
        let genesis = ShieldedBlock::genesis(difficulty, genesis_coinbase.clone());
        let genesis_hash = genesis.hash();

        let mut blocks = HashMap::new();
        blocks.insert(genesis_hash, genesis);

        // Initialize state with genesis coinbase
        let mut state = ShieldedState::new();
        state.apply_coinbase(&genesis_coinbase);

        Self {
            blocks,
            height_index: vec![genesis_hash],
            state,
            difficulty,
            db: None,
            orphans: HashMap::new(),
            verifying_params: None,
        }
    }

    /// Create a new blockchain with a default genesis block for the given miner.
    /// This is a convenience method for standalone mining.
    pub fn with_miner(difficulty: u64, miner_pk_hash: [u8; 32], viewing_key: &ViewingKey) -> Self {
        let genesis_coinbase = Self::create_genesis_coinbase(miner_pk_hash, viewing_key);
        Self::new(difficulty, genesis_coinbase)
    }

    /// Open a persisted blockchain from disk, or create a new one.
    ///
    /// If the database contains existing blocks, they are loaded and the state
    /// is rebuilt by replaying all blocks from genesis.
    pub fn open(db_path: &str, difficulty: u64) -> Result<Self, BlockchainError> {
        use crate::crypto::commitment::NoteCommitment;
        use crate::crypto::note::EncryptedNote;

        // Open the database
        let db = Database::open(db_path)
            .map_err(|e| BlockchainError::StorageError(e.to_string()))?;
        let db = Arc::new(db);

        // Check if we have existing blocks
        let stored_height = db
            .get_height()
            .map_err(|e| BlockchainError::StorageError(e.to_string()))?;

        if let Some(height) = stored_height {
            // Load existing chain
            tracing::info!("Loading blockchain from disk (height: {})", height);

            let mut blocks = HashMap::new();
            let mut height_index = Vec::new();
            let mut state = ShieldedState::new();

            // Load all blocks and rebuild state
            for h in 0..=height {
                let block = db
                    .load_block_by_height(h)
                    .map_err(|e| BlockchainError::StorageError(e.to_string()))?
                    .ok_or_else(|| {
                        BlockchainError::StorageError(format!("Missing block at height {}", h))
                    })?;

                let hash = block.hash();

                // Apply transactions to state
                for tx in &block.transactions {
                    state.apply_transaction(tx);
                }
                state.apply_coinbase(&block.coinbase);

                blocks.insert(hash, block);
                height_index.push(hash);
            }

            // Load difficulty from metadata or use last block's difficulty
            let current_difficulty = db
                .get_metadata("difficulty")
                .map_err(|e| BlockchainError::StorageError(e.to_string()))?
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(difficulty);

            tracing::info!(
                "Blockchain loaded: height={}, commitments={}, nullifiers={}",
                height,
                state.commitment_count(),
                state.nullifier_count()
            );

            Ok(Self {
                blocks,
                height_index,
                state,
                difficulty: current_difficulty,
                db: Some(db),
                orphans: HashMap::new(),
                verifying_params: None,
            })
        } else {
            // Create a fresh chain with a dummy genesis
            tracing::info!("Creating new blockchain");

            let genesis_coinbase = CoinbaseTransaction::new(
                NoteCommitment([0u8; 32]),
                EncryptedNote {
                    ciphertext: vec![0; 64],
                    ephemeral_pk: vec![0; 32],
                },
                BLOCK_REWARD,
                0,
            );

            let genesis = ShieldedBlock::genesis(difficulty, genesis_coinbase.clone());
            let genesis_hash = genesis.hash();

            // Save genesis to database
            db.save_block(&genesis, 0)
                .map_err(|e| BlockchainError::StorageError(e.to_string()))?;
            db.set_metadata("difficulty", &difficulty.to_string())
                .map_err(|e| BlockchainError::StorageError(e.to_string()))?;
            db.flush()
                .map_err(|e| BlockchainError::StorageError(e.to_string()))?;

            let mut blocks = HashMap::new();
            blocks.insert(genesis_hash, genesis);

            // Initialize state with genesis coinbase
            let mut state = ShieldedState::new();
            state.apply_coinbase(&genesis_coinbase);

            Ok(Self {
                blocks,
                height_index: vec![genesis_hash],
                state,
                difficulty,
                db: Some(db),
                orphans: HashMap::new(),
                verifying_params: None,
            })
        }
    }

    /// Create a genesis coinbase for a miner.
    pub fn create_genesis_coinbase(
        miner_pk_hash: [u8; 32],
        _viewing_key: &ViewingKey,  // Kept for API compatibility but not used
    ) -> CoinbaseTransaction {
        let mut rng = ark_std::rand::thread_rng();
        let note = Note::new(BLOCK_REWARD, miner_pk_hash, &mut rng);
        // Encrypt using miner's pk_hash so they can decrypt it
        let miner_key = ViewingKey::from_pk_hash(miner_pk_hash);
        let encrypted = miner_key.encrypt_note(&note, &mut rng);

        CoinbaseTransaction::new(note.commitment(), encrypted, BLOCK_REWARD, 0)
    }

    /// Set the verifying parameters for proof verification.
    pub fn set_verifying_params(&mut self, params: Arc<VerifyingParams>) {
        self.verifying_params = Some(params);
    }

    /// Get the verifying parameters for proof verification.
    pub fn verifying_params(&self) -> Option<&Arc<VerifyingParams>> {
        self.verifying_params.as_ref()
    }

    /// Get the current chain height (0-indexed).
    pub fn height(&self) -> u64 {
        self.height_index.len() as u64 - 1
    }

    /// Get the current difficulty.
    pub fn difficulty(&self) -> u64 {
        self.difficulty
    }

    /// Calculate the next block's difficulty based on recent block times.
    pub fn next_difficulty(&self) -> u64 {
        let height = self.height();

        if height < ADJUSTMENT_INTERVAL {
            return self.difficulty.max(MIN_DIFFICULTY);
        }

        if should_adjust_difficulty(height + 1) {
            let window_start = height + 1 - ADJUSTMENT_INTERVAL;
            let first_block = self.get_block_by_height(window_start);
            let last_block = self.get_block_by_height(height);

            if let (Some(first), Some(last)) = (first_block, last_block) {
                return calculate_next_difficulty(
                    self.difficulty,
                    first.header.timestamp,
                    last.header.timestamp,
                    ADJUSTMENT_INTERVAL,
                );
            }
        }

        self.difficulty.max(MIN_DIFFICULTY)
    }

    /// Get timestamps of recent blocks.
    pub fn recent_timestamps(&self, count: usize) -> Vec<u64> {
        let start = self.height_index.len().saturating_sub(count);
        self.height_index[start..]
            .iter()
            .filter_map(|hash| self.blocks.get(hash))
            .map(|block| block.header.timestamp)
            .collect()
    }

    /// Get the latest block hash.
    pub fn latest_hash(&self) -> [u8; 32] {
        *self.height_index.last().unwrap()
    }

    /// Get the latest block.
    pub fn latest_block(&self) -> &ShieldedBlock {
        self.blocks.get(&self.latest_hash()).unwrap()
    }

    /// Get a block by hash.
    pub fn get_block(&self, hash: &[u8; 32]) -> Option<&ShieldedBlock> {
        self.blocks.get(hash)
    }

    /// Get a block by height.
    pub fn get_block_by_height(&self, height: u64) -> Option<&ShieldedBlock> {
        self.height_index
            .get(height as usize)
            .and_then(|hash| self.blocks.get(hash))
    }

    /// Get the current shielded state.
    pub fn state(&self) -> &ShieldedState {
        &self.state
    }

    /// Get the current commitment tree root.
    pub fn commitment_root(&self) -> [u8; 32] {
        self.state.commitment_root()
    }

    /// Get the number of commitments in the tree.
    pub fn commitment_count(&self) -> u64 {
        self.state.commitment_count()
    }

    /// Get the number of spent nullifiers.
    pub fn nullifier_count(&self) -> usize {
        self.state.nullifier_count()
    }

    /// Validate a block before adding it.
    pub fn validate_block(&self, block: &ShieldedBlock) -> Result<(), BlockchainError> {
        // Check previous hash
        if block.header.prev_hash != self.latest_hash() {
            return Err(BlockchainError::InvalidPrevHash);
        }

        // Check block structure and proof-of-work
        block.verify().map_err(BlockchainError::BlockError)?;

        // Check difficulty
        let expected_difficulty = self.next_difficulty();
        if block.header.difficulty != expected_difficulty {
            return Err(BlockchainError::InvalidDifficulty);
        }

        // Validate coinbase
        let expected_height = self.height() + 1;
        let total_fees = block.total_fees();
        let expected_reward = BLOCK_REWARD + total_fees;

        self.state
            .validate_coinbase(&block.coinbase, expected_reward, expected_height)
            .map_err(|e| BlockchainError::StateError(e))?;

        // Validate all transactions
        if let Some(ref params) = self.verifying_params {
            for tx in &block.transactions {
                self.state
                    .validate_transaction(tx, params)
                    .map_err(|e| BlockchainError::StateError(e))?;
            }
        } else {
            // If no verifying params, just do basic validation
            for tx in &block.transactions {
                self.state
                    .validate_transaction_basic(tx)
                    .map_err(|e| BlockchainError::StateError(e))?;
            }
        }

        // Verify commitment root matches expected
        let mut temp_state = self.state.snapshot();
        for tx in &block.transactions {
            temp_state.apply_transaction(tx);
        }
        temp_state.apply_coinbase(&block.coinbase);

        if temp_state.commitment_root() != block.header.commitment_root {
            return Err(BlockchainError::InvalidCommitmentRoot);
        }

        Ok(())
    }

    /// Add a validated block to the chain.
    pub fn add_block(&mut self, block: ShieldedBlock) -> Result<(), BlockchainError> {
        // Validate first
        self.validate_block(&block)?;

        let hash = block.hash();
        let new_height = self.height_index.len() as u64;

        // Persist block and nullifiers if we have a database
        if let Some(ref db) = self.db {
            // Save block
            db.save_block(&block, new_height)
                .map_err(|e| BlockchainError::StorageError(e.to_string()))?;

            // Save nullifiers from this block
            for tx in &block.transactions {
                for spend in &tx.spends {
                    db.save_nullifier(&spend.nullifier.to_bytes())
                        .map_err(|e| BlockchainError::StorageError(e.to_string()))?;
                }
            }

            // Update metadata
            db.set_metadata("difficulty", &block.header.difficulty.to_string())
                .map_err(|e| BlockchainError::StorageError(e.to_string()))?;

            // Flush to ensure durability
            db.flush()
                .map_err(|e| BlockchainError::StorageError(e.to_string()))?;
        }

        // Apply transactions to state
        for tx in &block.transactions {
            self.state.apply_transaction(tx);
        }
        self.state.apply_coinbase(&block.coinbase);

        // Update difficulty
        self.difficulty = block.header.difficulty;

        // Add to in-memory structures
        self.blocks.insert(hash, block);
        self.height_index.push(hash);

        Ok(())
    }

    /// Try to add a block, handling orphans and potential reorgs.
    pub fn try_add_block(&mut self, block: ShieldedBlock) -> Result<bool, BlockchainError> {
        let block_hash = block.hash();

        // Already have this block?
        if self.blocks.contains_key(&block_hash) {
            return Ok(false);
        }

        // Does it extend our current chain?
        if block.header.prev_hash == self.latest_hash() {
            self.add_block(block)?;
            self.process_orphans()?;
            return Ok(true);
        }

        // Do we have the parent block?
        if !self.blocks.contains_key(&block.header.prev_hash) {
            // Store as orphan
            self.orphans.insert(block_hash, block);
            return Ok(false);
        }

        // We have the parent but it's not our tip - potential fork
        let fork_height = self.calculate_chain_height(&block);
        let current_height = self.height();

        if fork_height > current_height {
            // Fork is longer - reorganize
            self.reorganize_to_block(block)?;
            self.process_orphans()?;
            return Ok(true);
        }

        // Fork is not longer - store but don't switch
        self.blocks.insert(block_hash, block);
        Ok(false)
    }

    /// Calculate the height a block would have if added.
    fn calculate_chain_height(&self, block: &ShieldedBlock) -> u64 {
        let mut height = 1u64;
        let mut prev_hash = block.header.prev_hash;

        while let Some(parent) = self.blocks.get(&prev_hash) {
            height += 1;
            if parent.header.prev_hash == [0u8; BLOCK_HASH_SIZE] {
                break;
            }
            prev_hash = parent.header.prev_hash;
        }

        height
    }

    /// Process orphan blocks to see if any can now be connected.
    fn process_orphans(&mut self) -> Result<(), BlockchainError> {
        let mut connected = true;

        while connected {
            connected = false;
            let orphan_hashes: Vec<[u8; 32]> = self.orphans.keys().cloned().collect();

            for hash in orphan_hashes {
                if let Some(orphan) = self.orphans.get(&hash).cloned() {
                    if orphan.header.prev_hash == self.latest_hash() {
                        self.orphans.remove(&hash);
                        if self.add_block(orphan).is_ok() {
                            connected = true;
                        }
                    } else if self.blocks.contains_key(&orphan.header.prev_hash) {
                        let fork_height = self.calculate_chain_height(&orphan);
                        if fork_height > self.height() {
                            self.orphans.remove(&hash);
                            self.reorganize_to_block(orphan)?;
                            connected = true;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Reorganize the chain to include the given block.
    fn reorganize_to_block(&mut self, new_tip: ShieldedBlock) -> Result<(), BlockchainError> {
        // Build the new chain path from genesis to new_tip
        let mut new_chain: Vec<ShieldedBlock> = vec![new_tip.clone()];
        let mut prev_hash = new_tip.header.prev_hash;

        while prev_hash != [0u8; 32] {
            if let Some(block) = self.blocks.get(&prev_hash).cloned() {
                prev_hash = block.header.prev_hash;
                new_chain.push(block);
            } else {
                return Err(BlockchainError::InvalidPrevHash);
            }
        }

        new_chain.reverse();

        // Rebuild state from genesis
        let mut new_state = ShieldedState::new();
        let mut new_height_index = Vec::new();
        let mut new_difficulty = self.difficulty;

        for block in &new_chain {
            for tx in &block.transactions {
                new_state.apply_transaction(tx);
            }
            new_state.apply_coinbase(&block.coinbase);
            new_height_index.push(block.hash());
            new_difficulty = block.header.difficulty;
        }

        // Add new tip to blocks
        let new_tip_hash = new_tip.hash();
        self.blocks.insert(new_tip_hash, new_tip.clone());

        // Switch to new chain
        self.state = new_state;
        self.height_index = new_height_index.clone();
        self.difficulty = new_difficulty;

        // Persist the reorganized chain if we have a database
        if let Some(ref db) = self.db {
            tracing::info!("Persisting chain reorganization (new height: {})", new_height_index.len() - 1);

            // Clear nullifiers and rebuild from new chain
            db.clear_nullifiers()
                .map_err(|e| BlockchainError::StorageError(e.to_string()))?;

            // Re-persist all blocks in the new chain
            for (height, hash) in new_height_index.iter().enumerate() {
                if let Some(block) = self.blocks.get(hash) {
                    db.save_block(block, height as u64)
                        .map_err(|e| BlockchainError::StorageError(e.to_string()))?;

                    // Save nullifiers from this block
                    for tx in &block.transactions {
                        for spend in &tx.spends {
                            db.save_nullifier(&spend.nullifier.to_bytes())
                                .map_err(|e| BlockchainError::StorageError(e.to_string()))?;
                        }
                    }
                }
            }

            // Update metadata
            db.set_metadata("difficulty", &new_difficulty.to_string())
                .map_err(|e| BlockchainError::StorageError(e.to_string()))?;

            db.flush()
                .map_err(|e| BlockchainError::StorageError(e.to_string()))?;
        }

        Ok(())
    }

    /// Get the number of orphan blocks.
    pub fn orphan_count(&self) -> usize {
        self.orphans.len()
    }

    /// Create a coinbase transaction for a new block.
    pub fn create_coinbase(
        &self,
        miner_pk_hash: [u8; 32],
        _viewing_key: &ViewingKey,  // Kept for API compatibility but not used
        extra_fees: u64,
    ) -> CoinbaseTransaction {
        let mut rng = ark_std::rand::thread_rng();
        let height = self.height() + 1;
        let reward = BLOCK_REWARD + extra_fees;

        let note = Note::new(reward, miner_pk_hash, &mut rng);
        // Encrypt using miner's pk_hash so they can decrypt it
        let miner_key = ViewingKey::from_pk_hash(miner_pk_hash);
        let encrypted = miner_key.encrypt_note(&note, &mut rng);

        CoinbaseTransaction::new(note.commitment(), encrypted, reward, height)
    }

    /// Create a new block template for mining.
    pub fn create_block_template(
        &self,
        miner_pk_hash: [u8; 32],
        viewing_key: &ViewingKey,
        transactions: Vec<ShieldedTransaction>,
    ) -> ShieldedBlock {
        let total_fees: u64 = transactions.iter().map(|tx| tx.fee).sum();
        let coinbase = self.create_coinbase(miner_pk_hash, viewing_key, total_fees);

        // Calculate commitment root after applying transactions
        let mut temp_state = self.state.snapshot();
        for tx in &transactions {
            temp_state.apply_transaction(tx);
        }
        temp_state.apply_coinbase(&coinbase);
        let commitment_root = temp_state.commitment_root();

        // Nullifier root (simplified - just hash the count for now)
        let nullifier_root = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&(temp_state.nullifier_count() as u64).to_le_bytes());
            let hash: [u8; 32] = hasher.finalize().into();
            hash
        };

        ShieldedBlock::new(
            self.latest_hash(),
            transactions,
            coinbase,
            commitment_root,
            nullifier_root,
            self.next_difficulty(),
        )
    }

    /// Get chain info for API responses.
    pub fn info(&self) -> ChainInfo {
        ChainInfo {
            height: self.height(),
            latest_hash: hex::encode(self.latest_hash()),
            difficulty: self.difficulty,
            next_difficulty: self.next_difficulty(),
            commitment_count: self.commitment_count(),
            nullifier_count: self.nullifier_count() as u64,
        }
    }

    /// Get recent block hashes (for sync protocol).
    pub fn recent_hashes(&self, count: usize) -> Vec<[u8; 32]> {
        let start = self.height_index.len().saturating_sub(count);
        self.height_index[start..].to_vec()
    }

    /// Get a Merkle path for a commitment at a given position.
    pub fn get_merkle_path(
        &self,
        position: u64,
    ) -> Option<crate::crypto::merkle_tree::MerklePath> {
        self.state.get_merkle_path(position)
    }

    /// Get recent valid anchors.
    pub fn recent_anchors(&self) -> Vec<[u8; 32]> {
        self.state.recent_roots().to_vec()
    }
}

/// Summary information about the chain.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChainInfo {
    pub height: u64,
    pub latest_hash: String,
    pub difficulty: u64,
    pub next_difficulty: u64,
    pub commitment_count: u64,
    pub nullifier_count: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum BlockchainError {
    #[error("Block error: {0}")]
    BlockError(#[from] BlockError),

    #[error("State error: {0}")]
    StateError(#[from] StateError),

    #[error("Invalid previous block hash")]
    InvalidPrevHash,

    #[error("Invalid difficulty")]
    InvalidDifficulty,

    #[error("Invalid coinbase")]
    InvalidCoinbase,

    #[error("Invalid coinbase amount")]
    InvalidCoinbaseAmount,

    #[error("Invalid commitment root")]
    InvalidCommitmentRoot,

    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    #[error("Storage error: {0}")]
    StorageError(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::note::{compute_pk_hash, ViewingKey};

    fn test_viewing_key() -> ViewingKey {
        ViewingKey::new(b"test_miner_key")
    }

    fn test_pk_hash() -> [u8; 32] {
        compute_pk_hash(b"test_miner_public_key")
    }

    #[test]
    fn test_new_blockchain() {
        let vk = test_viewing_key();
        let pk_hash = test_pk_hash();
        let coinbase = ShieldedBlockchain::create_genesis_coinbase(pk_hash, &vk);
        let chain = ShieldedBlockchain::new(MIN_DIFFICULTY, coinbase);

        assert_eq!(chain.height(), 0);
        assert!(chain.get_block_by_height(0).is_some());
        assert_eq!(chain.commitment_count(), 1); // Genesis coinbase
    }

    #[test]
    fn test_chain_info() {
        let vk = test_viewing_key();
        let pk_hash = test_pk_hash();
        let coinbase = ShieldedBlockchain::create_genesis_coinbase(pk_hash, &vk);
        let chain = ShieldedBlockchain::new(8, coinbase);

        let info = chain.info();
        assert_eq!(info.height, 0);
        assert_eq!(info.difficulty, 8);
        assert_eq!(info.commitment_count, 1);
        assert_eq!(info.nullifier_count, 0);
    }

    #[test]
    fn test_create_block_template() {
        let vk = test_viewing_key();
        let pk_hash = test_pk_hash();
        let coinbase = ShieldedBlockchain::create_genesis_coinbase(pk_hash, &vk);
        let chain = ShieldedBlockchain::new(MIN_DIFFICULTY, coinbase);

        let template = chain.create_block_template(pk_hash, &vk, vec![]);

        assert_eq!(template.header.prev_hash, chain.latest_hash());
        assert_eq!(template.coinbase.height, 1);
        assert_eq!(template.coinbase.reward, BLOCK_REWARD);
    }

    #[test]
    fn test_commitment_tracking() {
        let vk = test_viewing_key();
        let pk_hash = test_pk_hash();
        let coinbase = ShieldedBlockchain::create_genesis_coinbase(pk_hash, &vk);
        let chain = ShieldedBlockchain::new(MIN_DIFFICULTY, coinbase);

        // Genesis creates one commitment
        assert_eq!(chain.commitment_count(), 1);

        // Commitment root should not be empty
        assert_ne!(chain.commitment_root(), [0u8; 32]);
    }

    #[test]
    fn test_persistence_roundtrip() {
        use tempfile::tempdir;

        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test_blockchain");
        let db_path_str = db_path.to_str().unwrap();

        let genesis_hash;
        let genesis_commitment_root;

        // Create and persist a blockchain
        {
            let chain = ShieldedBlockchain::open(db_path_str, MIN_DIFFICULTY).unwrap();
            assert_eq!(chain.height(), 0);
            genesis_hash = chain.latest_hash();
            genesis_commitment_root = chain.commitment_root();
        }

        // Reopen and verify data persisted
        {
            let chain = ShieldedBlockchain::open(db_path_str, MIN_DIFFICULTY).unwrap();
            assert_eq!(chain.height(), 0);
            assert_eq!(chain.latest_hash(), genesis_hash);
            assert_eq!(chain.commitment_root(), genesis_commitment_root);
            assert_eq!(chain.commitment_count(), 1);
        }
    }

    #[test]
    fn test_persistence_with_blocks() {
        use tempfile::tempdir;
        use crate::consensus::mine_block;

        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test_blockchain_blocks");
        let db_path_str = db_path.to_str().unwrap();

        let vk = test_viewing_key();
        let pk_hash = test_pk_hash();

        let block1_hash;
        let final_commitment_count;

        // Create blockchain, mine a block, persist
        {
            let mut chain = ShieldedBlockchain::open(db_path_str, MIN_DIFFICULTY).unwrap();
            assert_eq!(chain.height(), 0);

            // Create and mine a block
            let mut block = chain.create_block_template(pk_hash, &vk, vec![]);
            mine_block(&mut block);

            chain.add_block(block.clone()).unwrap();
            assert_eq!(chain.height(), 1);

            block1_hash = block.hash();
            final_commitment_count = chain.commitment_count();
        }

        // Reopen and verify blocks persisted
        {
            let chain = ShieldedBlockchain::open(db_path_str, MIN_DIFFICULTY).unwrap();
            assert_eq!(chain.height(), 1);
            assert_eq!(chain.latest_hash(), block1_hash);
            assert_eq!(chain.commitment_count(), final_commitment_count);

            // Verify we can get the block by height
            let loaded_block = chain.get_block_by_height(1).unwrap();
            assert_eq!(loaded_block.hash(), block1_hash);
        }
    }
}
