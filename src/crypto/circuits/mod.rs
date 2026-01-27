//! zk-SNARK circuits for private transactions.
//!
//! This module contains the R1CS circuits for:
//! - Spend: Proves valid consumption of a note
//! - Output: Proves valid creation of a note
//! - Poseidon gadget: Provides Poseidon hash constraints

pub mod spend;
pub mod output;
pub mod poseidon_gadget;

pub use spend::SpendCircuit;
pub use output::OutputCircuit;
pub use poseidon_gadget::{
    poseidon_hash_gadget, note_commitment_gadget, nullifier_gadget, merkle_hash_gadget,
};

use ark_bls12_381::Fr;
use ark_ff::PrimeField;

/// Convert bytes to field element.
pub fn bytes_to_field(bytes: &[u8; 32]) -> Fr {
    Fr::from_le_bytes_mod_order(bytes)
}

/// Convert a u64 to field element.
pub fn u64_to_field(value: u64) -> Fr {
    Fr::from(value)
}
