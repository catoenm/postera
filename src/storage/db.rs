use std::path::Path;

use crate::core::{Account, ShieldedBlock};
use crate::crypto::Address;

/// Sled-based key-value database for persistent storage.
///
/// Uses separate trees for different data types:
/// - blocks: hash -> block data
/// - block_heights: height -> hash
/// - accounts: address -> account data
/// - metadata: key -> value
pub struct Database {
    db: sled::Db,
    blocks: sled::Tree,
    block_heights: sled::Tree,
    accounts: sled::Tree,
    metadata: sled::Tree,
}

impl Database {
    /// Open or create a database at the given path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, DatabaseError> {
        let db = sled::open(path)?;
        let blocks = db.open_tree("blocks")?;
        let block_heights = db.open_tree("block_heights")?;
        let accounts = db.open_tree("accounts")?;
        let metadata = db.open_tree("metadata")?;

        Ok(Self {
            db,
            blocks,
            block_heights,
            accounts,
            metadata,
        })
    }

    /// Create a temporary in-memory database (for testing).
    pub fn in_memory() -> Result<Self, DatabaseError> {
        let config = sled::Config::new().temporary(true);
        let db = config.open()?;
        let blocks = db.open_tree("blocks")?;
        let block_heights = db.open_tree("block_heights")?;
        let accounts = db.open_tree("accounts")?;
        let metadata = db.open_tree("metadata")?;

        Ok(Self {
            db,
            blocks,
            block_heights,
            accounts,
            metadata,
        })
    }

    /// Save a block to the database.
    pub fn save_block(&self, block: &ShieldedBlock, height: u64) -> Result<(), DatabaseError> {
        let hash = block.hash();
        let data = serde_json::to_vec(block)?;

        // Store block by hash
        self.blocks.insert(&hash, data)?;

        // Store hash by height
        self.block_heights.insert(&height.to_be_bytes(), &hash)?;

        Ok(())
    }

    /// Load a block by hash.
    pub fn load_block(&self, hash: &[u8; 32]) -> Result<Option<ShieldedBlock>, DatabaseError> {
        match self.blocks.get(hash)? {
            Some(data) => {
                let block: ShieldedBlock = serde_json::from_slice(&data)?;
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    /// Load a block by height.
    pub fn load_block_by_height(&self, height: u64) -> Result<Option<ShieldedBlock>, DatabaseError> {
        match self.block_heights.get(&height.to_be_bytes())? {
            Some(hash) => {
                let hash: [u8; 32] = hash
                    .as_ref()
                    .try_into()
                    .map_err(|_| DatabaseError::InvalidData("invalid hash length".into()))?;
                self.load_block(&hash)
            }
            None => Ok(None),
        }
    }

    /// Get the latest block height.
    pub fn get_height(&self) -> Result<Option<u64>, DatabaseError> {
        // Get the last key in the block_heights tree
        match self.block_heights.last()? {
            Some((key, _)) => {
                let bytes: [u8; 8] = key
                    .as_ref()
                    .try_into()
                    .map_err(|_| DatabaseError::InvalidData("invalid height".into()))?;
                Ok(Some(u64::from_be_bytes(bytes)))
            }
            None => Ok(None),
        }
    }

    /// Save an account state.
    pub fn save_account(&self, account: &Account) -> Result<(), DatabaseError> {
        let data = serde_json::to_vec(account)?;
        self.accounts.insert(account.address.as_bytes(), data)?;
        Ok(())
    }

    /// Load an account by address.
    pub fn load_account(&self, address: &Address) -> Result<Option<Account>, DatabaseError> {
        match self.accounts.get(address.as_bytes())? {
            Some(data) => {
                let account: Account = serde_json::from_slice(&data)?;
                Ok(Some(account))
            }
            None => Ok(None),
        }
    }

    /// Save metadata.
    pub fn set_metadata(&self, key: &str, value: &str) -> Result<(), DatabaseError> {
        self.metadata.insert(key.as_bytes(), value.as_bytes())?;
        Ok(())
    }

    /// Load metadata.
    pub fn get_metadata(&self, key: &str) -> Result<Option<String>, DatabaseError> {
        match self.metadata.get(key.as_bytes())? {
            Some(data) => {
                let value = String::from_utf8(data.to_vec())
                    .map_err(|_| DatabaseError::InvalidData("invalid utf8".into()))?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }

    /// Flush all pending writes to disk.
    pub fn flush(&self) -> Result<(), DatabaseError> {
        self.db.flush()?;
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DatabaseError {
    #[error("Sled error: {0}")]
    Sled(#[from] sled::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Invalid data: {0}")]
    InvalidData(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::CoinbaseTransaction;
    use crate::crypto::commitment::NoteCommitment;
    use crate::crypto::note::EncryptedNote;

    fn dummy_coinbase(height: u64) -> CoinbaseTransaction {
        CoinbaseTransaction::new(
            NoteCommitment([1u8; 32]),
            EncryptedNote {
                ciphertext: vec![0; 64],
                ephemeral_pk: vec![0; 32],
            },
            50,
            height,
        )
    }

    #[test]
    fn test_database_creation() {
        let db = Database::in_memory().unwrap();
        assert!(db.get_height().unwrap().is_none());
    }

    #[test]
    fn test_save_and_load_block() {
        let db = Database::in_memory().unwrap();

        let coinbase = dummy_coinbase(0);
        let block = ShieldedBlock::new(
            [0u8; 32],
            vec![],
            coinbase,
            [0u8; 32],
            [0u8; 32],
            0,
        );
        let hash = block.hash();

        db.save_block(&block, 0).unwrap();

        let loaded = db.load_block(&hash).unwrap().unwrap();
        assert_eq!(loaded.hash(), hash);
    }

    #[test]
    fn test_load_block_by_height() {
        let db = Database::in_memory().unwrap();

        let coinbase = dummy_coinbase(42);
        let block = ShieldedBlock::new(
            [0u8; 32],
            vec![],
            coinbase,
            [0u8; 32],
            [0u8; 32],
            0,
        );

        db.save_block(&block, 42).unwrap();

        let loaded = db.load_block_by_height(42).unwrap().unwrap();
        assert_eq!(loaded.hash(), block.hash());
    }

    #[test]
    fn test_get_height() {
        let db = Database::in_memory().unwrap();

        let coinbase = dummy_coinbase(0);
        let block = ShieldedBlock::new(
            [0u8; 32],
            vec![],
            coinbase,
            [0u8; 32],
            [0u8; 32],
            0,
        );

        db.save_block(&block, 0).unwrap();
        assert_eq!(db.get_height().unwrap(), Some(0));

        let coinbase2 = dummy_coinbase(1);
        let block2 = ShieldedBlock::new(
            block.hash(),
            vec![],
            coinbase2,
            [0u8; 32],
            [0u8; 32],
            0,
        );
        db.save_block(&block2, 1).unwrap();
        assert_eq!(db.get_height().unwrap(), Some(1));
    }

    #[test]
    fn test_save_and_load_account() {
        let db = Database::in_memory().unwrap();

        let addr = Address::from_bytes([1u8; 20]);
        let account = Account::with_balance(addr, 1000);

        db.save_account(&account).unwrap();

        let loaded = db.load_account(&addr).unwrap().unwrap();
        assert_eq!(loaded.balance, 1000);
    }

    #[test]
    fn test_metadata() {
        let db = Database::in_memory().unwrap();

        db.set_metadata("difficulty", "8").unwrap();
        assert_eq!(
            db.get_metadata("difficulty").unwrap(),
            Some("8".to_string())
        );
    }
}
