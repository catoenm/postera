use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer, Verifier};
use serde::{Deserialize, Serialize};

use super::keys::{KeyPair, SIGNATURE_SIZE, PUBLIC_KEY_SIZE};

/// A ML-DSA-65 signature wrapper with serialization support.
#[derive(Clone, PartialEq, Eq)]
pub struct Signature(Vec<u8>);

impl Signature {
    /// Create a signature from raw bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Get the raw signature bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Convert to a hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Parse from a hex string.
    pub fn from_hex(s: &str) -> Result<Self, SignatureError> {
        let bytes = hex::decode(s).map_err(|_| SignatureError::InvalidHex)?;
        Ok(Self(bytes))
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Signature({}...)", &self.to_hex()[..16.min(self.0.len() * 2)])
    }
}

/// Sign a message using a keypair.
///
/// Uses ML-DSA-65 (FIPS 204) detached signatures for signing arbitrary data.
/// The signature is 3309 bytes.
pub fn sign(message: &[u8], keypair: &KeyPair) -> Signature {
    // Empty context for basic signing (as per FIPS 204)
    let context: &[u8] = &[];
    let sig: [u8; SIGNATURE_SIZE] = keypair.secret_key().try_sign(message, context).expect("signing failed");
    Signature(sig.to_vec())
}

/// Verify a signature against a message and public key.
///
/// Returns true if the signature is valid, false otherwise.
pub fn verify(message: &[u8], signature: &Signature, public_key: &[u8]) -> Result<bool, SignatureError> {
    let pk_array: [u8; PUBLIC_KEY_SIZE] = public_key
        .try_into()
        .map_err(|_| SignatureError::InvalidPublicKey)?;

    let pk = ml_dsa_65::PublicKey::try_from_bytes(pk_array)
        .map_err(|_| SignatureError::InvalidPublicKey)?;

    let sig_array: [u8; SIGNATURE_SIZE] = signature.0
        .as_slice()
        .try_into()
        .map_err(|_| SignatureError::InvalidSignature)?;

    // Empty context for basic verification (as per FIPS 204)
    let context: &[u8] = &[];
    Ok(pk.verify(message, &sig_array, context))
}

#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("Invalid hex encoding")]
    InvalidHex,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid signature format")]
    InvalidSignature,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let keypair = KeyPair::generate();
        let message = b"Hello, quantum-resistant world!";

        let signature = sign(message, &keypair);

        // Should verify with correct key
        let valid = verify(message, &signature, &keypair.public_key_bytes()).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_signature_size() {
        let keypair = KeyPair::generate();
        let message = b"Test message";

        let signature = sign(message, &keypair);

        // ML-DSA-65 signature size is 3309 bytes
        assert_eq!(signature.as_bytes().len(), SIGNATURE_SIZE);
    }

    #[test]
    fn test_wrong_message_fails() {
        let keypair = KeyPair::generate();
        let message = b"Original message";
        let wrong_message = b"Wrong message";

        let signature = sign(message, &keypair);

        let valid = verify(wrong_message, &signature, &keypair.public_key_bytes()).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_wrong_key_fails() {
        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();
        let message = b"Test message";

        let signature = sign(message, &keypair1);

        // Verify with wrong public key should fail
        let valid = verify(message, &signature, &keypair2.public_key_bytes()).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_signature_hex_roundtrip() {
        let keypair = KeyPair::generate();
        let message = b"Test";

        let signature = sign(message, &keypair);
        let hex = signature.to_hex();
        let restored = Signature::from_hex(&hex).unwrap();

        assert_eq!(signature.as_bytes(), restored.as_bytes());
    }
}
