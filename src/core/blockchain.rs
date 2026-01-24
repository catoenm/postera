use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use crate::consensus::{
    calculate_next_difficulty, should_adjust_difficulty, ADJUSTMENT_INTERVAL, MIN_DIFFICULTY,
};
use crate::crypto::Address;
use crate::storage::Database;

use super::{Block, BlockError, State, Transaction};

/// The mining reward in smallest units.
pub const BLOCK_REWARD: u64 = 50_000_000_000; // 50 coins with 9 decimal places

/// The blockchain - manages the chain of blocks and world state.
pub struct Blockchain {
    /// All blocks indexed by hash
    blocks: HashMap<[u8; 32], Block>,
    /// Block hashes by height
    height_index: Vec<[u8; 32]>,
    /// Current world state (after applying all blocks)
    state: State,
    /// Current mining difficulty
    difficulty: u64,
    /// Optional persistent storage
    db: Option<Arc<Database>>,
    /// Orphan blocks (blocks whose parent we don't have yet)
    orphans: HashMap<[u8; 32], Block>,
}

impl Blockchain {
    /// Create a new blockchain with a genesis block (in-memory only).
    pub fn new(difficulty: u64) -> Self {
        let genesis = Block::genesis(difficulty);
        let genesis_hash = genesis.hash();

        let mut blocks = HashMap::new();
        blocks.insert(genesis_hash, genesis);

        Self {
            blocks,
            height_index: vec![genesis_hash],
            state: State::new(),
            difficulty,
            db: None,
            orphans: HashMap::new(),
        }
    }

    /// Open a blockchain from persistent storage, or create a new one.
    pub fn open<P: AsRef<Path>>(path: P, difficulty: u64) -> Result<Self, BlockchainError> {
        let db = Database::open(path).map_err(|e| BlockchainError::StorageError(e.to_string()))?;
        let db = Arc::new(db);

        // Check if we have an existing chain
        let stored_height = db
            .get_height()
            .map_err(|e| BlockchainError::StorageError(e.to_string()))?;

        if let Some(height) = stored_height {
            // Load existing chain
            println!("Loading blockchain from disk (height: {})...", height);

            let mut blocks = HashMap::new();
            let mut height_index = Vec::new();
            let mut state = State::new();

            // Load all blocks and rebuild state
            for h in 0..=height {
                let block = db
                    .load_block_by_height(h)
                    .map_err(|e| BlockchainError::StorageError(e.to_string()))?
                    .ok_or_else(|| {
                        BlockchainError::StorageError(format!("Missing block at height {}", h))
                    })?;

                // Apply transactions to state
                for tx in &block.transactions {
                    state
                        .apply_transaction(tx)
                        .map_err(|e| BlockchainError::InvalidTransaction(e.to_string()))?;
                }

                let hash = block.hash();
                blocks.insert(hash, block);
                height_index.push(hash);
            }

            // Load difficulty from metadata or use provided
            let stored_difficulty = db
                .get_metadata("difficulty")
                .map_err(|e| BlockchainError::StorageError(e.to_string()))?
                .and_then(|s| s.parse().ok())
                .unwrap_or(difficulty);

            println!("Loaded {} blocks from disk", height + 1);

            Ok(Self {
                blocks,
                height_index,
                state,
                difficulty: stored_difficulty,
                db: Some(db),
                orphans: HashMap::new(),
            })
        } else {
            // Create new chain with genesis block
            println!("Creating new blockchain...");

            let genesis = Block::genesis(difficulty);
            let genesis_hash = genesis.hash();

            // Save genesis block
            db.save_block(&genesis, 0)
                .map_err(|e| BlockchainError::StorageError(e.to_string()))?;
            db.set_metadata("difficulty", &difficulty.to_string())
                .map_err(|e| BlockchainError::StorageError(e.to_string()))?;

            let mut blocks = HashMap::new();
            blocks.insert(genesis_hash, genesis);

            Ok(Self {
                blocks,
                height_index: vec![genesis_hash],
                state: State::new(),
                difficulty,
                db: Some(db),
                orphans: HashMap::new(),
            })
        }
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
    /// This implements dynamic difficulty adjustment targeting fast block times.
    pub fn next_difficulty(&self) -> u64 {
        let height = self.height();

        // Don't adjust until we have enough blocks
        if height < ADJUSTMENT_INTERVAL {
            return self.difficulty.max(MIN_DIFFICULTY);
        }

        // Check if this is an adjustment point
        if should_adjust_difficulty(height + 1) {
            // Get the timestamps from the adjustment window
            let window_start = height + 1 - ADJUSTMENT_INTERVAL;
            let first_block = self.get_block_by_height(window_start);
            let last_block = self.get_block_by_height(height);

            if let (Some(first), Some(last)) = (first_block, last_block) {
                let new_difficulty = calculate_next_difficulty(
                    self.difficulty,
                    first.header.timestamp,
                    last.header.timestamp,
                    ADJUSTMENT_INTERVAL,
                );

                return new_difficulty;
            }
        }

        self.difficulty.max(MIN_DIFFICULTY)
    }

    /// Get timestamps of recent blocks (for difficulty stats).
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
    pub fn latest_block(&self) -> &Block {
        self.blocks.get(&self.latest_hash()).unwrap()
    }

    /// Get a block by hash.
    pub fn get_block(&self, hash: &[u8; 32]) -> Option<&Block> {
        self.blocks.get(hash)
    }

    /// Get a block by height.
    pub fn get_block_by_height(&self, height: u64) -> Option<&Block> {
        self.height_index
            .get(height as usize)
            .and_then(|hash| self.blocks.get(hash))
    }

    /// Get the current state.
    pub fn state(&self) -> &State {
        &self.state
    }

    /// Get account balance.
    pub fn balance(&self, address: &Address) -> u64 {
        self.state.balance(address)
    }

    /// Get account nonce.
    pub fn nonce(&self, address: &Address) -> u64 {
        self.state.nonce(address)
    }

    /// Validate a block before adding it.
    pub fn validate_block(&self, block: &Block) -> Result<(), BlockchainError> {
        // Check previous hash
        if block.header.prev_hash != self.latest_hash() {
            return Err(BlockchainError::InvalidPrevHash);
        }

        // Check block structure and proof-of-work
        block.verify().map_err(BlockchainError::BlockError)?;

        // Check difficulty - must match the expected next difficulty
        let expected_difficulty = self.next_difficulty();
        if block.header.difficulty != expected_difficulty {
            return Err(BlockchainError::InvalidDifficulty);
        }

        // Validate all transactions
        let mut temp_state = self.state.snapshot();
        let mut total_fees = 0u64;

        for (i, tx) in block.transactions.iter().enumerate() {
            // First transaction should be coinbase
            if i == 0 {
                if !tx.is_coinbase() {
                    return Err(BlockchainError::NoCoinbase);
                }
                // We'll verify the coinbase amount after calculating fees
            } else {
                // Regular transaction
                if tx.is_coinbase() {
                    return Err(BlockchainError::MultipleCoinbase);
                }

                temp_state
                    .validate_transaction(tx)
                    .map_err(|e| BlockchainError::InvalidTransaction(e.to_string()))?;

                total_fees += tx.fee;
            }

            temp_state
                .apply_transaction(tx)
                .map_err(|e| BlockchainError::InvalidTransaction(e.to_string()))?;
        }

        // Verify coinbase amount
        if let Some(coinbase) = block.coinbase() {
            let expected_reward = BLOCK_REWARD + total_fees;
            if coinbase.amount > expected_reward {
                return Err(BlockchainError::InvalidCoinbaseAmount);
            }
        }

        Ok(())
    }

    /// Add a validated block to the chain.
    pub fn add_block(&mut self, block: Block) -> Result<(), BlockchainError> {
        // Validate first
        self.validate_block(&block)?;

        // Apply transactions to state
        for tx in &block.transactions {
            self.state
                .apply_transaction(tx)
                .map_err(|e| BlockchainError::InvalidTransaction(e.to_string()))?;
        }

        // Add to chain
        let hash = block.hash();
        let new_height = self.height_index.len() as u64;

        // Update difficulty to the block's difficulty (it was validated)
        self.difficulty = block.header.difficulty;

        // Persist to disk if we have a database
        if let Some(ref db) = self.db {
            db.save_block(&block, new_height)
                .map_err(|e| BlockchainError::StorageError(e.to_string()))?;

            // Also persist the updated difficulty
            db.set_metadata("difficulty", &self.difficulty.to_string())
                .map_err(|e| BlockchainError::StorageError(e.to_string()))?;
        }

        self.blocks.insert(hash, block);
        self.height_index.push(hash);

        Ok(())
    }

    /// Try to add a block, handling orphans and potential chain reorganizations.
    /// Returns Ok(true) if block was added to main chain, Ok(false) if stored as orphan.
    pub fn try_add_block(&mut self, block: Block) -> Result<bool, BlockchainError> {
        let block_hash = block.hash();

        // Already have this block?
        if self.blocks.contains_key(&block_hash) {
            return Ok(false);
        }

        // Does it extend our current chain?
        if block.header.prev_hash == self.latest_hash() {
            // Normal case: extends the tip
            self.add_block(block)?;
            // Check if any orphans can now be connected
            self.process_orphans()?;
            return Ok(true);
        }

        // Do we have the parent block?
        if !self.blocks.contains_key(&block.header.prev_hash) {
            // Parent not found - store as orphan
            self.orphans.insert(block_hash, block);
            return Ok(false);
        }

        // We have the parent but it's not our tip - this is a potential fork
        // Calculate the height of this block's chain
        let fork_height = self.calculate_chain_height(&block);
        let current_height = self.height();

        if fork_height > current_height {
            // The fork is longer - reorganize
            self.reorganize_to_block(block)?;
            self.process_orphans()?;
            return Ok(true);
        }

        // Fork is not longer - store block but don't switch
        // (Could be useful if it becomes longer later)
        self.blocks.insert(block_hash, block);
        Ok(false)
    }

    /// Calculate the height a block would have if added.
    fn calculate_chain_height(&self, block: &Block) -> u64 {
        let mut height = 1u64;
        let mut prev_hash = block.header.prev_hash;

        while let Some(parent) = self.blocks.get(&prev_hash) {
            height += 1;
            if parent.header.prev_hash == [0u8; 32] {
                break; // Reached genesis
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
                    // Can we connect this orphan now?
                    if orphan.header.prev_hash == self.latest_hash() {
                        self.orphans.remove(&hash);
                        if self.add_block(orphan).is_ok() {
                            connected = true;
                        }
                    } else if self.blocks.contains_key(&orphan.header.prev_hash) {
                        // Parent exists but not at tip - check if fork is longer
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
    /// This rebuilds state from genesis along the new chain path.
    fn reorganize_to_block(&mut self, new_tip: Block) -> Result<(), BlockchainError> {
        // Build the new chain path from genesis to new_tip
        let mut new_chain: Vec<Block> = vec![new_tip.clone()];
        let mut prev_hash = new_tip.header.prev_hash;

        while prev_hash != [0u8; 32] {
            if let Some(block) = self.blocks.get(&prev_hash).cloned() {
                prev_hash = block.header.prev_hash;
                new_chain.push(block);
            } else {
                return Err(BlockchainError::InvalidPrevHash);
            }
        }

        new_chain.reverse(); // Now ordered from genesis to new_tip

        // Rebuild state from genesis
        let mut new_state = State::new();
        let mut new_height_index = Vec::new();
        let mut new_difficulty = self.difficulty;

        for block in &new_chain {
            // Validate and apply each block
            for tx in &block.transactions {
                new_state
                    .apply_transaction(tx)
                    .map_err(|e| BlockchainError::InvalidTransaction(e.to_string()))?;
            }
            new_height_index.push(block.hash());
            new_difficulty = block.header.difficulty;
        }

        // Add the new tip to our blocks
        let new_tip_hash = new_tip.hash();
        self.blocks.insert(new_tip_hash, new_tip);

        // Persist new chain to disk if we have a database
        if let Some(ref db) = self.db {
            for (height, hash) in new_height_index.iter().enumerate() {
                if let Some(block) = self.blocks.get(hash) {
                    db.save_block(block, height as u64)
                        .map_err(|e| BlockchainError::StorageError(e.to_string()))?;
                }
            }
            db.set_metadata("difficulty", &new_difficulty.to_string())
                .map_err(|e| BlockchainError::StorageError(e.to_string()))?;
        }

        // Switch to new chain
        self.state = new_state;
        self.height_index = new_height_index;
        self.difficulty = new_difficulty;

        Ok(())
    }

    /// Get the number of orphan blocks.
    pub fn orphan_count(&self) -> usize {
        self.orphans.len()
    }

    /// Create a new block template for mining.
    /// Uses the dynamically calculated next difficulty.
    pub fn create_block_template(
        &self,
        miner_address: Address,
        transactions: Vec<Transaction>,
    ) -> Block {
        let total_fees: u64 = transactions.iter().map(|tx| tx.fee).sum();
        let coinbase = Transaction::coinbase(miner_address, BLOCK_REWARD + total_fees);

        let mut txs = vec![coinbase];
        txs.extend(transactions);

        // Use the dynamically calculated difficulty for the next block
        Block::new(self.latest_hash(), txs, self.next_difficulty())
    }

    /// Get chain info for API responses.
    pub fn info(&self) -> ChainInfo {
        ChainInfo {
            height: self.height(),
            latest_hash: hex::encode(self.latest_hash()),
            difficulty: self.difficulty,
            next_difficulty: self.next_difficulty(),
            total_accounts: self.state.account_count() as u64,
        }
    }

    /// Get recent block hashes (for sync protocol).
    pub fn recent_hashes(&self, count: usize) -> Vec<[u8; 32]> {
        let start = self.height_index.len().saturating_sub(count);
        self.height_index[start..].to_vec()
    }
}

/// Summary information about the chain.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChainInfo {
    pub height: u64,
    pub latest_hash: String,
    pub difficulty: u64,
    pub next_difficulty: u64,
    pub total_accounts: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum BlockchainError {
    #[error("Block error: {0}")]
    BlockError(#[from] BlockError),
    #[error("Invalid previous block hash")]
    InvalidPrevHash,
    #[error("Invalid difficulty")]
    InvalidDifficulty,
    #[error("Block must start with coinbase transaction")]
    NoCoinbase,
    #[error("Block has multiple coinbase transactions")]
    MultipleCoinbase,
    #[error("Invalid coinbase amount")]
    InvalidCoinbaseAmount,
    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),
    #[error("Storage error: {0}")]
    StorageError(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;

    #[test]
    fn test_new_blockchain() {
        let chain = Blockchain::new(0);

        assert_eq!(chain.height(), 0);
        assert!(chain.get_block_by_height(0).is_some());
    }

    #[test]
    fn test_add_valid_block() {
        let mut chain = Blockchain::new(0); // 0 difficulty for fast tests

        let miner = KeyPair::generate();
        let block = chain.create_block_template(miner.address(), vec![]);

        chain.add_block(block).unwrap();

        assert_eq!(chain.height(), 1);
        assert_eq!(chain.balance(&miner.address()), BLOCK_REWARD);
    }

    #[test]
    fn test_block_with_transaction() {
        let mut chain = Blockchain::new(0);

        // First mine a block to get some coins
        let sender = KeyPair::generate();
        let block1 = chain.create_block_template(sender.address(), vec![]);
        chain.add_block(block1).unwrap();

        // Now send some coins
        let receiver = KeyPair::generate();
        let tx = Transaction::create_signed(&sender, receiver.address(), 1000, 10, 0);

        let miner = KeyPair::generate();
        let block2 = chain.create_block_template(miner.address(), vec![tx]);
        chain.add_block(block2).unwrap();

        assert_eq!(chain.height(), 2);
        assert_eq!(chain.balance(&receiver.address()), 1000);
        assert_eq!(
            chain.balance(&sender.address()),
            BLOCK_REWARD - 1000 - 10
        );
        // Miner gets block reward + fees
        assert_eq!(chain.balance(&miner.address()), BLOCK_REWARD + 10);
    }

    #[test]
    fn test_invalid_prev_hash() {
        let chain = Blockchain::new(0);
        let miner = KeyPair::generate();

        let mut block = Block::new([99u8; 32], vec![], 0); // Wrong prev_hash
        block.transactions = vec![Transaction::coinbase(miner.address(), BLOCK_REWARD)];

        let result = chain.validate_block(&block);
        assert!(matches!(result, Err(BlockchainError::InvalidPrevHash)));
    }

    #[test]
    fn test_chain_info() {
        let chain = Blockchain::new(8);
        let info = chain.info();

        assert_eq!(info.height, 0);
        assert_eq!(info.difficulty, 8);
    }
}
