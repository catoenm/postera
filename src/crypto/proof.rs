//! Groth16 zk-SNARK proof generation and verification.
//!
//! This module provides:
//! - ZkProof: Serializable proof structure
//! - Proving parameters for proof generation
//! - Verifying parameters for proof verification
//! - Functions to create and verify proofs

use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::{
    prepare_verifying_key, Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use super::circuits::{OutputCircuit, SpendCircuit};

/// A serializable zk-SNARK proof.
#[derive(Clone, Debug)]
pub struct ZkProof {
    /// The raw proof data (Groth16 proof serialized).
    proof_data: Vec<u8>,
}

impl ZkProof {
    /// Create from a Groth16 proof.
    pub fn from_groth16_proof(proof: &Proof<Bls12_381>) -> Self {
        let mut proof_data = Vec::new();
        proof.serialize_compressed(&mut proof_data).unwrap();
        Self { proof_data }
    }

    /// Convert to a Groth16 proof.
    pub fn to_groth16_proof(&self) -> Result<Proof<Bls12_381>, &'static str> {
        Proof::deserialize_compressed(&self.proof_data[..])
            .map_err(|_| "Failed to deserialize proof")
    }

    /// Get the raw proof bytes.
    pub fn to_bytes(&self) -> &[u8] {
        &self.proof_data
    }

    /// Create from raw bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { proof_data: bytes }
    }

    /// Get the size of the proof in bytes.
    pub fn size(&self) -> usize {
        self.proof_data.len()
    }
}

impl Serialize for ZkProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.proof_data)
    }
}

impl<'de> Deserialize<'de> for ZkProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let proof_data: Vec<u8> = Vec::deserialize(deserializer)?;
        Ok(Self { proof_data })
    }
}

/// Parameters needed to generate proofs.
pub struct ProvingParams {
    /// Spend circuit proving key.
    pub spend_pk: ProvingKey<Bls12_381>,
    /// Output circuit proving key.
    pub output_pk: ProvingKey<Bls12_381>,
}

impl ProvingParams {
    /// Serialize to bytes for storage.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Serialize spend proving key
        let mut spend_bytes = Vec::new();
        self.spend_pk.serialize_compressed(&mut spend_bytes).unwrap();
        bytes.extend_from_slice(&(spend_bytes.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&spend_bytes);

        // Serialize output proving key
        let mut output_bytes = Vec::new();
        self.output_pk.serialize_compressed(&mut output_bytes).unwrap();
        bytes.extend_from_slice(&(output_bytes.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&output_bytes);

        bytes
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        let mut offset = 0;

        // Read spend proving key
        let spend_len = u64::from_le_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .map_err(|_| "Invalid format")?,
        ) as usize;
        offset += 8;
        let spend_pk = ProvingKey::deserialize_compressed(&bytes[offset..offset + spend_len])
            .map_err(|_| "Failed to deserialize spend proving key")?;
        offset += spend_len;

        // Read output proving key
        let output_len = u64::from_le_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .map_err(|_| "Invalid format")?,
        ) as usize;
        offset += 8;
        let output_pk = ProvingKey::deserialize_compressed(&bytes[offset..offset + output_len])
            .map_err(|_| "Failed to deserialize output proving key")?;

        Ok(Self { spend_pk, output_pk })
    }
}

/// Parameters needed to verify proofs.
pub struct VerifyingParams {
    /// Prepared spend circuit verifying key.
    pub spend_pvk: PreparedVerifyingKey<Bls12_381>,
    /// Prepared output circuit verifying key.
    pub output_pvk: PreparedVerifyingKey<Bls12_381>,
    /// Raw spend verifying key (for serialization).
    spend_vk: VerifyingKey<Bls12_381>,
    /// Raw output verifying key (for serialization).
    output_vk: VerifyingKey<Bls12_381>,
}

impl VerifyingParams {
    /// Create from verifying keys.
    pub fn new(spend_vk: VerifyingKey<Bls12_381>, output_vk: VerifyingKey<Bls12_381>) -> Self {
        let spend_pvk = prepare_verifying_key(&spend_vk);
        let output_pvk = prepare_verifying_key(&output_vk);
        Self {
            spend_pvk,
            output_pvk,
            spend_vk,
            output_vk,
        }
    }

    /// Serialize to bytes for storage.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Serialize spend verifying key
        let mut spend_bytes = Vec::new();
        self.spend_vk.serialize_compressed(&mut spend_bytes).unwrap();
        bytes.extend_from_slice(&(spend_bytes.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&spend_bytes);

        // Serialize output verifying key
        let mut output_bytes = Vec::new();
        self.output_vk.serialize_compressed(&mut output_bytes).unwrap();
        bytes.extend_from_slice(&(output_bytes.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&output_bytes);

        bytes
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        let mut offset = 0;

        // Read spend verifying key
        let spend_len = u64::from_le_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .map_err(|_| "Invalid format")?,
        ) as usize;
        offset += 8;
        let spend_vk = VerifyingKey::deserialize_compressed(&bytes[offset..offset + spend_len])
            .map_err(|_| "Failed to deserialize spend verifying key")?;
        offset += spend_len;

        // Read output verifying key
        let output_len = u64::from_le_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .map_err(|_| "Invalid format")?,
        ) as usize;
        offset += 8;
        let output_vk = VerifyingKey::deserialize_compressed(&bytes[offset..offset + output_len])
            .map_err(|_| "Failed to deserialize output verifying key")?;

        Ok(Self::new(spend_vk, output_vk))
    }
}

/// Generate a spend proof.
pub fn generate_spend_proof<R: RngCore + CryptoRng>(
    circuit: SpendCircuit,
    proving_params: &ProvingParams,
    rng: &mut R,
) -> Result<ZkProof, &'static str> {
    let proof = Groth16::<Bls12_381>::prove(&proving_params.spend_pk, circuit, rng)
        .map_err(|_| "Failed to generate spend proof")?;

    Ok(ZkProof::from_groth16_proof(&proof))
}

/// Verify a spend proof.
pub fn verify_spend_proof(
    proof: &ZkProof,
    public_inputs: &[Fr],
    verifying_params: &VerifyingParams,
) -> bool {
    let groth16_proof = match proof.to_groth16_proof() {
        Ok(p) => p,
        Err(_) => return false,
    };

    Groth16::<Bls12_381>::verify_with_processed_vk(
        &verifying_params.spend_pvk,
        public_inputs,
        &groth16_proof,
    )
    .unwrap_or(false)
}

/// Generate an output proof.
pub fn generate_output_proof<R: RngCore + CryptoRng>(
    circuit: OutputCircuit,
    proving_params: &ProvingParams,
    rng: &mut R,
) -> Result<ZkProof, &'static str> {
    let proof = Groth16::<Bls12_381>::prove(&proving_params.output_pk, circuit, rng)
        .map_err(|_| "Failed to generate output proof")?;

    Ok(ZkProof::from_groth16_proof(&proof))
}

/// Verify an output proof.
pub fn verify_output_proof(
    proof: &ZkProof,
    public_inputs: &[Fr],
    verifying_params: &VerifyingParams,
) -> bool {
    let groth16_proof = match proof.to_groth16_proof() {
        Ok(p) => p,
        Err(_) => return false,
    };

    Groth16::<Bls12_381>::verify_with_processed_vk(
        &verifying_params.output_pvk,
        public_inputs,
        &groth16_proof,
    )
    .unwrap_or(false)
}

/// Convert spend public inputs from bytes to field elements.
///
/// The new circuit design uses 3 field elements as public inputs:
/// - merkle_root: Tree root as a single field element
/// - nullifier: Nullifier as a single field element
/// - value_commitment_hash: Hash of value commitment as a single field element
pub fn spend_bytes_to_public_inputs(
    merkle_root: &[u8; 32],
    nullifier: &[u8; 32],
    value_commitment_hash: &[u8; 32],
) -> Vec<Fr> {
    use super::poseidon::bytes32_to_field;
    vec![
        bytes32_to_field(merkle_root),
        bytes32_to_field(nullifier),
        bytes32_to_field(value_commitment_hash),
    ]
}

/// Convert output public inputs from bytes to field elements.
///
/// The new circuit design uses 2 field elements as public inputs:
/// - note_commitment: Note commitment as a single field element
/// - value_commitment_hash: Hash of value commitment as a single field element
pub fn output_bytes_to_public_inputs(
    note_commitment: &[u8; 32],
    value_commitment_hash: &[u8; 32],
) -> Vec<Fr> {
    use super::poseidon::bytes32_to_field;
    vec![
        bytes32_to_field(note_commitment),
        bytes32_to_field(value_commitment_hash),
    ]
}

/// Alias for backwards compatibility
pub fn bytes_to_public_inputs(
    merkle_root: &[u8; 32],
    nullifier: &[u8; 32],
    value_commitment_hash: &[u8; 32],
) -> Vec<Fr> {
    spend_bytes_to_public_inputs(merkle_root, nullifier, value_commitment_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zkproof_serialization() {
        // Create a dummy proof (just bytes for this test)
        let proof_data = vec![1, 2, 3, 4, 5];
        let proof = ZkProof::from_bytes(proof_data.clone());

        assert_eq!(proof.to_bytes(), &proof_data[..]);
        assert_eq!(proof.size(), 5);
    }
}
