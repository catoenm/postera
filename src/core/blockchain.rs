use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

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

        // Check difficulty
        if block.header.difficulty != self.difficulty {
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

        // Persist to disk if we have a database
        if let Some(ref db) = self.db {
            db.save_block(&block, new_height)
                .map_err(|e| BlockchainError::StorageError(e.to_string()))?;
        }

        self.blocks.insert(hash, block);
        self.height_index.push(hash);

        Ok(())
    }

    /// Create a new block template for mining.
    pub fn create_block_template(
        &self,
        miner_address: Address,
        transactions: Vec<Transaction>,
    ) -> Block {
        let total_fees: u64 = transactions.iter().map(|tx| tx.fee).sum();
        let coinbase = Transaction::coinbase(miner_address, BLOCK_REWARD + total_fees);

        let mut txs = vec![coinbase];
        txs.extend(transactions);

        Block::new(self.latest_hash(), txs, self.difficulty)
    }

    /// Get chain info for API responses.
    pub fn info(&self) -> ChainInfo {
        ChainInfo {
            height: self.height(),
            latest_hash: hex::encode(self.latest_hash()),
            difficulty: self.difficulty,
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
