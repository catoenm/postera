//! Block structure for the shielded blockchain.
//!
//! Blocks contain shielded transactions (private) and coinbase (reward).
//! The header includes commitment and nullifier roots for light client verification.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::transaction::{CoinbaseTransaction, ShieldedTransaction};

pub const BLOCK_HASH_SIZE: usize = 32;

/// Block header containing metadata, proof-of-work, and privacy roots.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Block version (for future upgrades).
    pub version: u32,

    /// Hash of the previous block.
    #[serde(with = "hex_array")]
    pub prev_hash: [u8; BLOCK_HASH_SIZE],

    /// Merkle root of transaction hashes.
    #[serde(with = "hex_array")]
    pub merkle_root: [u8; BLOCK_HASH_SIZE],

    /// Commitment tree root after applying this block.
    /// Allows light clients to verify note existence.
    #[serde(with = "hex_array")]
    pub commitment_root: [u8; BLOCK_HASH_SIZE],

    /// Nullifier set root after applying this block (optional).
    /// For light client double-spend verification.
    #[serde(with = "hex_array")]
    pub nullifier_root: [u8; BLOCK_HASH_SIZE],

    /// Block creation timestamp (Unix timestamp).
    pub timestamp: u64,

    /// Mining difficulty target.
    pub difficulty: u64,

    /// Nonce for proof-of-work.
    pub nonce: u64,
}

impl BlockHeader {
    /// Compute the hash of this block header.
    pub fn hash(&self) -> [u8; BLOCK_HASH_SIZE] {
        let mut hasher = Sha256::new();
        hasher.update(&self.version.to_le_bytes());
        hasher.update(&self.prev_hash);
        hasher.update(&self.merkle_root);
        hasher.update(&self.commitment_root);
        hasher.update(&self.nullifier_root);
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
    /// The hash must have at least `difficulty` leading zero bits.
    pub fn meets_difficulty(&self) -> bool {
        let hash = self.hash();
        count_leading_zeros(&hash) >= self.difficulty as usize
    }
}

/// A complete shielded block with header, transactions, and coinbase.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShieldedBlock {
    pub header: BlockHeader,
    pub transactions: Vec<ShieldedTransaction>,
    pub coinbase: CoinbaseTransaction,
}

impl ShieldedBlock {
    /// Create a new shielded block.
    pub fn new(
        prev_hash: [u8; BLOCK_HASH_SIZE],
        transactions: Vec<ShieldedTransaction>,
        coinbase: CoinbaseTransaction,
        commitment_root: [u8; BLOCK_HASH_SIZE],
        nullifier_root: [u8; BLOCK_HASH_SIZE],
        difficulty: u64,
    ) -> Self {
        // Compute merkle root of transaction hashes + coinbase
        let mut tx_hashes: Vec<[u8; 32]> = transactions.iter().map(|tx| tx.hash()).collect();
        tx_hashes.push(coinbase.hash());
        let merkle_root = compute_merkle_root(&tx_hashes);

        let header = BlockHeader {
            version: 2, // Version 2 for shielded blocks
            prev_hash,
            merkle_root,
            commitment_root,
            nullifier_root,
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
            coinbase,
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
    pub fn genesis(difficulty: u64, coinbase: CoinbaseTransaction) -> Self {
        let commitment_root = crate::crypto::merkle_tree::CommitmentTree::empty_root();

        let header = BlockHeader {
            version: 2,
            prev_hash: [0u8; BLOCK_HASH_SIZE],
            merkle_root: coinbase.hash(),
            commitment_root,
            nullifier_root: [0u8; BLOCK_HASH_SIZE], // Empty nullifier set
            timestamp: 0, // The beginning of time
            difficulty,
            nonce: 0,
        };

        Self {
            header,
            transactions: Vec::new(),
            coinbase,
        }
    }

    /// Verify the block's structure and proof-of-work.
    pub fn verify(&self) -> Result<(), BlockError> {
        // Verify merkle root
        let mut tx_hashes: Vec<[u8; 32]> = self.transactions.iter().map(|tx| tx.hash()).collect();
        tx_hashes.push(self.coinbase.hash());
        let computed_root = compute_merkle_root(&tx_hashes);
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

    /// Get all nullifiers introduced by this block.
    pub fn nullifiers(&self) -> Vec<crate::crypto::nullifier::Nullifier> {
        self.transactions
            .iter()
            .flat_map(|tx| tx.nullifiers())
            .cloned()
            .collect()
    }

    /// Get all note commitments created by this block.
    pub fn note_commitments(&self) -> Vec<crate::crypto::commitment::NoteCommitment> {
        let mut commitments: Vec<_> = self
            .transactions
            .iter()
            .flat_map(|tx| tx.note_commitments())
            .cloned()
            .collect();
        commitments.push(self.coinbase.note_commitment);
        commitments
    }

    /// Get the number of transactions (excluding coinbase).
    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }

    /// Get the block height from coinbase.
    pub fn height(&self) -> u64 {
        self.coinbase.height
    }
}

/// Compute the Merkle root of a list of hashes.
fn compute_merkle_root(hashes: &[[u8; 32]]) -> [u8; 32] {
    if hashes.is_empty() {
        return [0u8; 32];
    }

    if hashes.len() == 1 {
        return hashes[0];
    }

    let mut current_level: Vec<[u8; 32]> = hashes.to_vec();

    while current_level.len() > 1 {
        let mut next_level = Vec::new();

        for chunk in current_level.chunks(2) {
            let left = &chunk[0];
            let right = chunk.get(1).unwrap_or(left); // Duplicate if odd

            let mut hasher = Sha256::new();
            hasher.update(left);
            hasher.update(right);
            next_level.push(hasher.finalize().into());
        }

        current_level = next_level;
    }

    current_level[0]
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

    #[error("Invalid coinbase")]
    InvalidCoinbase,

    #[error("Invalid coinbase amount")]
    InvalidCoinbaseAmount,

    #[error("Invalid commitment root")]
    InvalidCommitmentRoot,

    #[error("Invalid nullifier root")]
    InvalidNullifierRoot,

    #[error("Nullifier already spent")]
    NullifierAlreadySpent,

    #[error("Invalid anchor")]
    InvalidAnchor,

    #[error("Invalid proof")]
    InvalidProof,

    #[error("Transaction validation failed: {0}")]
    TransactionError(String),
}

/// Helper module for hex serialization of fixed-size arrays.
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
    fn test_genesis_block() {
        let genesis = ShieldedBlock::genesis(8, dummy_coinbase(0));

        assert_eq!(genesis.header.prev_hash, [0u8; 32]);
        assert_eq!(genesis.header.version, 2);
        assert!(genesis.transactions.is_empty());
        assert_eq!(genesis.coinbase.height, 0);
    }

    #[test]
    fn test_block_hash_deterministic() {
        let block = ShieldedBlock::genesis(8, dummy_coinbase(0));

        let hash1 = block.hash();
        let hash2 = block.hash();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_merkle_root() {
        let hashes = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let root = compute_merkle_root(&hashes);

        // Should be deterministic
        assert_eq!(root, compute_merkle_root(&hashes));
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
        let block = ShieldedBlock::genesis(8, dummy_coinbase(0));

        let json = serde_json::to_string(&block).unwrap();
        let restored: ShieldedBlock = serde_json::from_str(&json).unwrap();

        assert_eq!(block.hash(), restored.hash());
    }

    #[test]
    fn test_block_fees() {
        use crate::core::transaction::{BindingSignature, ShieldedTransaction};

        let tx1 = ShieldedTransaction::new(vec![], vec![], 10, BindingSignature::new(vec![1]));
        let tx2 = ShieldedTransaction::new(vec![], vec![], 20, BindingSignature::new(vec![1]));

        let block = ShieldedBlock::new(
            [0u8; 32],
            vec![tx1, tx2],
            dummy_coinbase(1),
            [0u8; 32],
            [0u8; 32],
            0,
        );

        assert_eq!(block.total_fees(), 30);
    }
}
