//! zk-SNARK circuits for private transactions.
//!
//! This module contains the R1CS circuits for:
//! - Spend: Proves valid consumption of a note
//! - Output: Proves valid creation of a note

pub mod spend;
pub mod output;

pub use spend::SpendCircuit;
pub use output::OutputCircuit;

use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};

/// Convert bytes to field element.
pub fn bytes_to_field(bytes: &[u8; 32]) -> Fr {
    Fr::from_le_bytes_mod_order(bytes)
}

/// Convert a u64 to field element.
pub fn u64_to_field(value: u64) -> Fr {
    Fr::from(value)
}
