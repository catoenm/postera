use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::core::Transaction;
use crate::crypto::{Address, KeyPair};

/// A wallet containing a keypair for signing transactions.
#[derive(Clone)]
pub struct Wallet {
    keypair: KeyPair,
}

impl Wallet {
    /// Generate a new random wallet.
    pub fn generate() -> Self {
        Self {
            keypair: KeyPair::generate(),
        }
    }

    /// Load a wallet from a JSON file.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, WalletError> {
        let data = std::fs::read_to_string(path).map_err(WalletError::IoError)?;
        let stored: StoredWallet =
            serde_json::from_str(&data).map_err(WalletError::ParseError)?;

        let public_key = hex::decode(&stored.public_key).map_err(|_| WalletError::InvalidKey)?;
        let secret_key = hex::decode(&stored.secret_key).map_err(|_| WalletError::InvalidKey)?;

        let keypair =
            KeyPair::from_bytes(&public_key, &secret_key).map_err(|_| WalletError::InvalidKey)?;

        Ok(Self { keypair })
    }

    /// Save the wallet to a JSON file.
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), WalletError> {
        let stored = StoredWallet {
            address: self.address().to_hex(),
            public_key: hex::encode(self.keypair.public_key_bytes()),
            secret_key: hex::encode(self.keypair.secret_key_bytes()),
        };

        let data =
            serde_json::to_string_pretty(&stored).map_err(|e| WalletError::ParseError(e))?;
        std::fs::write(path, data).map_err(WalletError::IoError)?;

        Ok(())
    }

    /// Get the wallet's address.
    pub fn address(&self) -> Address {
        self.keypair.address()
    }

    /// Get the keypair.
    pub fn keypair(&self) -> &KeyPair {
        &self.keypair
    }

    /// Get public key bytes.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.keypair.public_key_bytes().to_vec()
    }

    /// Get secret key bytes.
    pub fn secret_key_bytes(&self) -> Vec<u8> {
        self.keypair.secret_key_bytes().to_vec()
    }

    /// Create wallet from public and secret key bytes.
    pub fn from_keys(public_key: &[u8], secret_key: &[u8]) -> Result<Self, WalletError> {
        let keypair = KeyPair::from_bytes(public_key, secret_key)
            .map_err(|_| WalletError::InvalidKey)?;
        Ok(Self { keypair })
    }

    /// Create and sign a transaction.
    pub fn create_transaction(
        &self,
        to: Address,
        amount: u64,
        fee: u64,
        nonce: u64,
    ) -> Transaction {
        Transaction::create_signed(&self.keypair, to, amount, fee, nonce)
    }
}

#[derive(Serialize, Deserialize)]
struct StoredWallet {
    address: String,
    public_key: String,
    secret_key: String,
}

#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("IO error: {0}")]
    IoError(#[source] std::io::Error),
    #[error("Parse error: {0}")]
    ParseError(#[source] serde_json::Error),
    #[error("Invalid key data")]
    InvalidKey,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_generate_wallet() {
        let wallet = Wallet::generate();
        assert!(!wallet.address().is_zero());
    }

    #[test]
    fn test_save_and_load_wallet() {
        let wallet = Wallet::generate();
        let original_address = wallet.address();

        let temp_file = NamedTempFile::new().unwrap();
        wallet.save(temp_file.path()).unwrap();

        let loaded = Wallet::load(temp_file.path()).unwrap();
        assert_eq!(loaded.address(), original_address);
    }

    #[test]
    fn test_create_transaction() {
        let wallet = Wallet::generate();
        let receiver = Wallet::generate();

        let tx = wallet.create_transaction(receiver.address(), 100, 1, 0);

        assert_eq!(tx.from, wallet.address());
        assert_eq!(tx.to, receiver.address());
        assert_eq!(tx.amount, 100);
        assert!(tx.verify_signature().unwrap());
    }
}
