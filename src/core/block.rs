use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{merkle_root, Transaction};

pub const BLOCK_HASH_SIZE: usize = 32;

/// Block header containing metadata and proof-of-work.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Block version (for future upgrades)
    pub version: u32,
    /// Hash of the previous block
    #[serde(with = "hex_array")]
    pub prev_hash: [u8; BLOCK_HASH_SIZE],
    /// Merkle root of transactions
    #[serde(with = "hex_array")]
    pub merkle_root: [u8; BLOCK_HASH_SIZE],
    /// Block creation timestamp (Unix timestamp)
    pub timestamp: u64,
    /// Mining difficulty target
    pub difficulty: u64,
    /// Nonce for proof-of-work
    pub nonce: u64,
}

impl BlockHeader {
    /// Compute the hash of this block header.
    pub fn hash(&self) -> [u8; BLOCK_HASH_SIZE] {
        let mut hasher = Sha256::new();
        hasher.update(&self.version.to_le_bytes());
        hasher.update(&self.prev_hash);
        hasher.update(&self.merkle_root);
        hasher.update(&self.timestamp.to_le_bytes());
        hasher.update(&self.difficulty.to_le_bytes());
        hasher.update(&self.nonce.to_le_bytes());
        hasher.finalize().into()
    }

    /// Get the header hash as a hex string.
    pub fn hash_hex(&self) -> String {
        hex::encode(self.hash())
    }

    /// Check if the header hash meets the difficulty target.
    ///
    /// The hash must have at least `difficulty` leading zero bits.
    pub fn meets_difficulty(&self) -> bool {
        let hash = self.hash();
        count_leading_zeros(&hash) >= self.difficulty as usize
    }
}

/// A complete block with header and transactions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

impl Block {
    /// Create a new block with the given transactions.
    pub fn new(
        prev_hash: [u8; BLOCK_HASH_SIZE],
        transactions: Vec<Transaction>,
        difficulty: u64,
    ) -> Self {
        let tx_hashes: Vec<[u8; 32]> = transactions.iter().map(|tx| tx.hash()).collect();
        let merkle_root = merkle_root(&tx_hashes);

        let header = BlockHeader {
            version: 1,
            prev_hash,
            merkle_root,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            difficulty,
            nonce: 0,
        };

        Self {
            header,
            transactions,
        }
    }

    /// Get the block hash (same as header hash).
    pub fn hash(&self) -> [u8; BLOCK_HASH_SIZE] {
        self.header.hash()
    }

    /// Get the block hash as a hex string.
    pub fn hash_hex(&self) -> String {
        self.header.hash_hex()
    }

    /// Create the genesis block (first block in the chain).
    pub fn genesis(difficulty: u64) -> Self {
        let header = BlockHeader {
            version: 1,
            prev_hash: [0u8; BLOCK_HASH_SIZE],
            merkle_root: [0u8; BLOCK_HASH_SIZE],
            timestamp: 0, // The beginning of time
            difficulty,
            nonce: 0,
        };

        Self {
            header,
            transactions: Vec::new(),
        }
    }

    /// Verify the block's structure and proof-of-work.
    pub fn verify(&self) -> Result<(), BlockError> {
        // Verify merkle root
        let tx_hashes: Vec<[u8; 32]> = self.transactions.iter().map(|tx| tx.hash()).collect();
        let computed_root = merkle_root(&tx_hashes);
        if computed_root != self.header.merkle_root {
            return Err(BlockError::InvalidMerkleRoot);
        }

        // Verify proof-of-work
        if !self.header.meets_difficulty() {
            return Err(BlockError::InsufficientProofOfWork);
        }

        Ok(())
    }

    /// Get the total fees from all transactions in this block.
    pub fn total_fees(&self) -> u64 {
        self.transactions.iter().map(|tx| tx.fee).sum()
    }

    /// Get the coinbase transaction (if any).
    pub fn coinbase(&self) -> Option<&Transaction> {
        self.transactions.first().filter(|tx| tx.is_coinbase())
    }
}

/// Count leading zero bits in a byte slice.
fn count_leading_zeros(bytes: &[u8]) -> usize {
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

#[derive(Debug, thiserror::Error)]
pub enum BlockError {
    #[error("Invalid merkle root")]
    InvalidMerkleRoot,
    #[error("Insufficient proof-of-work")]
    InsufficientProofOfWork,
    #[error("Invalid previous block hash")]
    InvalidPrevHash,
    #[error("Block timestamp is invalid")]
    InvalidTimestamp,
    #[error("No coinbase transaction")]
    NoCoinbase,
    #[error("Invalid coinbase amount")]
    InvalidCoinbaseAmount,
}

/// Helper module for hex serialization of fixed-size arrays
mod hex_array {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("expected 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;

    #[test]
    fn test_genesis_block() {
        let genesis = Block::genesis(8);

        assert_eq!(genesis.header.prev_hash, [0u8; 32]);
        assert_eq!(genesis.header.version, 1);
        assert!(genesis.transactions.is_empty());
    }

    #[test]
    fn test_block_hash_deterministic() {
        let block = Block::genesis(8);

        let hash1 = block.hash();
        let hash2 = block.hash();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_block_with_transactions() {
        let sender = KeyPair::generate();
        let receiver = KeyPair::generate();

        let tx = Transaction::create_signed(&sender, receiver.address(), 100, 1, 0);

        let block = Block::new([0u8; 32], vec![tx], 0);

        // With 0 difficulty, any hash meets the target
        assert!(block.header.meets_difficulty());
    }

    #[test]
    fn test_merkle_root_verification() {
        let sender = KeyPair::generate();
        let receiver = KeyPair::generate();

        let tx = Transaction::create_signed(&sender, receiver.address(), 100, 1, 0);

        let block = Block::new([0u8; 32], vec![tx], 0);

        // Block should verify correctly
        assert!(block.verify().is_ok());
    }

    #[test]
    fn test_leading_zeros_counting() {
        assert_eq!(count_leading_zeros(&[0x00, 0x00, 0xFF]), 16);
        assert_eq!(count_leading_zeros(&[0x0F, 0x00, 0x00]), 4);
        assert_eq!(count_leading_zeros(&[0x80, 0x00, 0x00]), 0);
        assert_eq!(count_leading_zeros(&[0x40, 0x00, 0x00]), 1);
    }

    #[test]
    fn test_block_serialization() {
        let block = Block::genesis(8);

        let json = serde_json::to_string(&block).unwrap();
        let restored: Block = serde_json::from_str(&json).unwrap();

        assert_eq!(block.hash(), restored.hash());
    }
}
