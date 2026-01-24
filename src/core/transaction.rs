use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::{sign, verify, Address, KeyPair, Signature};

/// A transaction transferring value between accounts.
///
/// Unlike Bitcoin's UTXO model, we use an account-based model
/// similar to Ethereum. Each account has a balance and nonce,
/// and transactions transfer value directly between accounts.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    /// Sender's address
    pub from: Address,
    /// Recipient's address
    pub to: Address,
    /// Amount to transfer (in smallest units)
    pub amount: u64,
    /// Transaction fee (paid to miner)
    pub fee: u64,
    /// Sender's nonce (for replay protection)
    pub nonce: u64,
    /// Sender's Dilithium public key (~1952 bytes)
    #[serde(with = "hex_bytes")]
    pub public_key: Vec<u8>,
    /// Dilithium signature (~3293 bytes)
    pub signature: Option<Signature>,
}

impl Transaction {
    /// Create a new unsigned transaction.
    pub fn new(from: Address, to: Address, amount: u64, fee: u64, nonce: u64) -> Self {
        Self {
            from,
            to,
            amount,
            fee,
            nonce,
            public_key: Vec::new(),
            signature: None,
        }
    }

    /// Create and sign a transaction with a keypair.
    pub fn create_signed(
        keypair: &KeyPair,
        to: Address,
        amount: u64,
        fee: u64,
        nonce: u64,
    ) -> Self {
        let from = keypair.address();
        let mut tx = Self::new(from, to, amount, fee, nonce);
        tx.public_key = keypair.public_key_bytes().to_vec();
        tx.sign(keypair);
        tx
    }

    /// Get the message bytes that should be signed.
    ///
    /// Includes all transaction fields except the signature itself.
    pub fn signing_message(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(self.from.as_bytes());
        msg.extend_from_slice(self.to.as_bytes());
        msg.extend_from_slice(&self.amount.to_le_bytes());
        msg.extend_from_slice(&self.fee.to_le_bytes());
        msg.extend_from_slice(&self.nonce.to_le_bytes());
        msg.extend_from_slice(&self.public_key);
        msg
    }

    /// Sign this transaction with a keypair.
    pub fn sign(&mut self, keypair: &KeyPair) {
        self.public_key = keypair.public_key_bytes().to_vec();
        let message = self.signing_message();
        self.signature = Some(sign(&message, keypair));
    }

    /// Verify this transaction's signature.
    pub fn verify_signature(&self) -> Result<bool, TransactionError> {
        let signature = self
            .signature
            .as_ref()
            .ok_or(TransactionError::NotSigned)?;

        // Verify that the public key matches the from address
        let derived_address = Address::from_public_key(&self.public_key);
        if derived_address != self.from {
            return Ok(false);
        }

        let message = self.signing_message();
        verify(&message, signature, &self.public_key)
            .map_err(|_| TransactionError::InvalidSignature)
    }

    /// Compute the transaction hash (unique identifier).
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();

        // Include all fields in the hash
        hasher.update(self.from.as_bytes());
        hasher.update(self.to.as_bytes());
        hasher.update(&self.amount.to_le_bytes());
        hasher.update(&self.fee.to_le_bytes());
        hasher.update(&self.nonce.to_le_bytes());
        hasher.update(&self.public_key);

        if let Some(sig) = &self.signature {
            hasher.update(sig.as_bytes());
        }

        hasher.finalize().into()
    }

    /// Get the transaction hash as a hex string.
    pub fn hash_hex(&self) -> String {
        hex::encode(self.hash())
    }

    /// Total amount deducted from sender (amount + fee).
    pub fn total_cost(&self) -> u64 {
        self.amount.saturating_add(self.fee)
    }

    /// Check if this is a coinbase transaction (mining reward).
    pub fn is_coinbase(&self) -> bool {
        self.from.is_zero()
    }

    /// Create a coinbase transaction (mining reward).
    pub fn coinbase(to: Address, reward: u64) -> Self {
        Self {
            from: Address::zero(),
            to,
            amount: reward,
            fee: 0,
            nonce: 0,
            public_key: Vec::new(),
            signature: None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TransactionError {
    #[error("Transaction is not signed")]
    NotSigned,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Insufficient balance")]
    InsufficientBalance,
    #[error("Invalid nonce: expected {expected}, got {got}")]
    InvalidNonce { expected: u64, got: u64 },
    #[error("Public key does not match sender address")]
    PublicKeyMismatch,
}

/// Helper module for hex serialization of byte vectors
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_sign_transaction() {
        let sender = KeyPair::generate();
        let receiver = KeyPair::generate();

        let tx = Transaction::create_signed(&sender, receiver.address(), 100, 1, 0);

        assert_eq!(tx.from, sender.address());
        assert_eq!(tx.to, receiver.address());
        assert_eq!(tx.amount, 100);
        assert_eq!(tx.fee, 1);
        assert!(tx.signature.is_some());
    }

    #[test]
    fn test_verify_valid_signature() {
        let sender = KeyPair::generate();
        let receiver = KeyPair::generate();

        let tx = Transaction::create_signed(&sender, receiver.address(), 100, 1, 0);

        assert!(tx.verify_signature().unwrap());
    }

    #[test]
    fn test_verify_tampered_transaction() {
        let sender = KeyPair::generate();
        let receiver = KeyPair::generate();

        let mut tx = Transaction::create_signed(&sender, receiver.address(), 100, 1, 0);

        // Tamper with the amount
        tx.amount = 999999;

        // Signature should no longer be valid
        assert!(!tx.verify_signature().unwrap());
    }

    #[test]
    fn test_transaction_hash_deterministic() {
        let sender = KeyPair::generate();
        let receiver = KeyPair::generate();

        let tx = Transaction::create_signed(&sender, receiver.address(), 100, 1, 0);

        let hash1 = tx.hash();
        let hash2 = tx.hash();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_coinbase_transaction() {
        let miner = KeyPair::generate();
        let coinbase = Transaction::coinbase(miner.address(), 50);

        assert!(coinbase.is_coinbase());
        assert!(coinbase.from.is_zero());
        assert_eq!(coinbase.amount, 50);
    }

    #[test]
    fn test_transaction_serialization() {
        let sender = KeyPair::generate();
        let receiver = KeyPair::generate();

        let tx = Transaction::create_signed(&sender, receiver.address(), 100, 1, 0);

        let json = serde_json::to_string(&tx).unwrap();
        let restored: Transaction = serde_json::from_str(&json).unwrap();

        assert_eq!(tx.hash(), restored.hash());
    }
}
