mod keys;
mod address;
mod signature;
pub mod poseidon;
pub mod commitment;
pub mod nullifier;
pub mod note;
pub mod merkle_tree;
pub mod proof;
pub mod snarkjs;
pub mod binding;

pub use keys::KeyPair;
pub use address::Address;
pub use signature::{sign, verify, Signature};
pub use poseidon::{
    poseidon_hash, poseidon_hash_2, bytes32_to_field, field_to_bytes32,
    DOMAIN_NOTE_COMMITMENT, DOMAIN_VALUE_COMMITMENT_HASH, DOMAIN_NULLIFIER,
    DOMAIN_MERKLE_EMPTY, DOMAIN_MERKLE_NODE,
};
pub use commitment::{NoteCommitment, ValueCommitment, commit_to_value, commit_to_note};
pub use nullifier::{Nullifier, NullifierKey, derive_nullifier};
pub use note::{Note, EncryptedNote, ViewingKey};
pub use merkle_tree::{CommitmentTree, MerklePath};
pub use proof::{ZkProof, CircomVerifyingParams, verify_spend_proof, verify_output_proof, bytes_to_public_inputs, output_bytes_to_public_inputs};
pub use snarkjs::{CircomVerifyingKey, verify_proof, parse_proof, parse_public_signals};
