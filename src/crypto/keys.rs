use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{PublicKey, SecretKey};

use super::Address;

/// A quantum-resistant keypair using CRYSTALS-Dilithium3.
///
/// Dilithium is a lattice-based signature scheme selected by NIST
/// for post-quantum cryptography standardization. It provides
/// security against both classical and quantum computer attacks.
#[derive(Clone)]
pub struct KeyPair {
    public_key: dilithium3::PublicKey,
    secret_key: dilithium3::SecretKey,
}

impl KeyPair {
    /// Generate a new random keypair.
    pub fn generate() -> Self {
        let (public_key, secret_key) = dilithium3::keypair();
        Self {
            public_key,
            secret_key,
        }
    }

    /// Reconstruct a keypair from raw bytes.
    pub fn from_bytes(public_key: &[u8], secret_key: &[u8]) -> Result<Self, KeyError> {
        let public_key = dilithium3::PublicKey::from_bytes(public_key)
            .map_err(|_| KeyError::InvalidPublicKey)?;
        let secret_key = dilithium3::SecretKey::from_bytes(secret_key)
            .map_err(|_| KeyError::InvalidSecretKey)?;
        Ok(Self {
            public_key,
            secret_key,
        })
    }

    /// Get the public key bytes.
    pub fn public_key_bytes(&self) -> &[u8] {
        self.public_key.as_bytes()
    }

    /// Get the secret key bytes.
    pub fn secret_key_bytes(&self) -> &[u8] {
        self.secret_key.as_bytes()
    }

    /// Get a reference to the internal public key.
    pub fn public_key(&self) -> &dilithium3::PublicKey {
        &self.public_key
    }

    /// Get a reference to the internal secret key.
    pub fn secret_key(&self) -> &dilithium3::SecretKey {
        &self.secret_key
    }

    /// Derive the address from this keypair's public key.
    pub fn address(&self) -> Address {
        Address::from_public_key(self.public_key_bytes())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("Invalid public key bytes")]
    InvalidPublicKey,
    #[error("Invalid secret key bytes")]
    InvalidSecretKey,
}

/// Dilithium3 key sizes for reference:
/// - Public key: 1952 bytes
/// - Secret key: 4032 bytes
/// - Signature: 3309 bytes
#[allow(dead_code)]
pub const PUBLIC_KEY_SIZE: usize = 1952;
#[allow(dead_code)]
pub const SECRET_KEY_SIZE: usize = 4032;
#[allow(dead_code)]
pub const SIGNATURE_SIZE: usize = 3309;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = KeyPair::generate();

        assert_eq!(keypair.public_key_bytes().len(), PUBLIC_KEY_SIZE);
        assert_eq!(keypair.secret_key_bytes().len(), SECRET_KEY_SIZE);
    }

    #[test]
    fn test_keypair_roundtrip() {
        let keypair = KeyPair::generate();
        let pk_bytes = keypair.public_key_bytes().to_vec();
        let sk_bytes = keypair.secret_key_bytes().to_vec();

        let restored = KeyPair::from_bytes(&pk_bytes, &sk_bytes).unwrap();

        assert_eq!(restored.public_key_bytes(), keypair.public_key_bytes());
        assert_eq!(restored.secret_key_bytes(), keypair.secret_key_bytes());
    }

    #[test]
    fn test_different_keypairs() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::generate();

        assert_ne!(kp1.public_key_bytes(), kp2.public_key_bytes());
    }
}
