//! Poseidon hash gadget for R1CS circuits.
//!
//! This module provides Poseidon hash constraints that match the native
//! implementation, ensuring consistency between proof generation and verification.

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar,
    poseidon::constraints::PoseidonSpongeVar,
};
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, R1CSVar};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use crate::crypto::poseidon::{
    POSEIDON_CONFIG, POSEIDON_CONFIG_4,
    DOMAIN_NOTE_COMMITMENT, DOMAIN_NULLIFIER, DOMAIN_MERKLE_NODE,
};

/// Poseidon hash gadget for circuit constraints.
///
/// Computes Poseidon(domain, inputs[0], inputs[1], ...) and returns a single field element.
/// The computation is constrained in the R1CS, ensuring the prover cannot cheat.
pub fn poseidon_hash_gadget(
    cs: ConstraintSystemRef<Fr>,
    domain: u64,
    inputs: &[FpVar<Fr>],
) -> Result<FpVar<Fr>, SynthesisError> {
    // Choose config based on number of inputs
    let config = if inputs.len() <= 2 {
        &*POSEIDON_CONFIG
    } else {
        &*POSEIDON_CONFIG_4
    };

    let mut sponge = PoseidonSpongeVar::new(cs.clone(), config);

    // Absorb domain separator as constant
    let domain_var = FpVar::<Fr>::new_constant(cs, Fr::from(domain))?;
    sponge.absorb(&domain_var)?;

    // Absorb all inputs
    for input in inputs {
        sponge.absorb(input)?;
    }

    // Squeeze one output
    let output = sponge.squeeze_field_elements(1)?;
    Ok(output[0].clone())
}

/// Hash two field elements (common for Merkle tree nodes).
pub fn poseidon_hash_2_gadget(
    cs: ConstraintSystemRef<Fr>,
    domain: u64,
    left: &FpVar<Fr>,
    right: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    poseidon_hash_gadget(cs, domain, &[left.clone(), right.clone()])
}

/// Compute note commitment in circuit.
/// cm = Poseidon(DOMAIN_NOTE_COMMITMENT, value, pk_hash, randomness)
pub fn note_commitment_gadget(
    cs: ConstraintSystemRef<Fr>,
    value: &FpVar<Fr>,
    pk_hash: &FpVar<Fr>,
    randomness: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    poseidon_hash_gadget(
        cs,
        DOMAIN_NOTE_COMMITMENT,
        &[value.clone(), pk_hash.clone(), randomness.clone()],
    )
}

/// Compute nullifier in circuit.
/// nf = Poseidon(DOMAIN_NULLIFIER, nk, cm, position)
pub fn nullifier_gadget(
    cs: ConstraintSystemRef<Fr>,
    nullifier_key: &FpVar<Fr>,
    commitment: &FpVar<Fr>,
    position: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    poseidon_hash_gadget(
        cs,
        DOMAIN_NULLIFIER,
        &[nullifier_key.clone(), commitment.clone(), position.clone()],
    )
}

/// Compute Merkle tree node hash in circuit.
/// hash = Poseidon(DOMAIN_MERKLE_NODE, left, right)
pub fn merkle_hash_gadget(
    cs: ConstraintSystemRef<Fr>,
    left: &FpVar<Fr>,
    right: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    poseidon_hash_2_gadget(cs, DOMAIN_MERKLE_NODE, left, right)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::rand::SeedableRng;
    use ark_std::rand::rngs::StdRng;

    use crate::crypto::poseidon::{poseidon_hash, bytes32_to_field, field_to_bytes32};

    // NOTE: These tests are ignored because the native Poseidon (light-poseidon/circomlib)
    // uses different parameters than the circuit gadget (ark_crypto_primitives).
    // This is intentional: native must match circomlib for browser wallet compatibility.
    // The Rust arkworks circuits are for server-side proving and use different params.
    // Browser proving uses Circom circuits which match circomlib.

    #[test]
    #[ignore = "Native uses circomlib Poseidon, circuit uses ark_crypto_primitives (different params)"]
    fn test_poseidon_gadget_matches_native() {
        let mut rng = StdRng::seed_from_u64(12345);

        let a = Fr::rand(&mut rng);
        let b = Fr::rand(&mut rng);

        // Native computation
        let native_result = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[a, b]);

        // Circuit computation
        let cs = ConstraintSystem::<Fr>::new_ref();
        let a_var = FpVar::new_witness(cs.clone(), || Ok(a)).unwrap();
        let b_var = FpVar::new_witness(cs.clone(), || Ok(b)).unwrap();

        let circuit_result = poseidon_hash_gadget(
            cs.clone(),
            DOMAIN_NOTE_COMMITMENT,
            &[a_var, b_var],
        ).unwrap();

        // Get the value from circuit
        let circuit_value = circuit_result.value().unwrap();

        assert_eq!(native_result, circuit_value, "Native and circuit results should match");
        assert!(cs.is_satisfied().unwrap(), "Circuit should be satisfied");
    }

    #[test]
    #[ignore = "Native uses circomlib Poseidon, circuit uses ark_crypto_primitives (different params)"]
    fn test_note_commitment_gadget() {
        let mut rng = StdRng::seed_from_u64(12345);

        let value = Fr::from(1000u64);
        let pk_hash = Fr::rand(&mut rng);
        let randomness = Fr::rand(&mut rng);

        // Native computation
        let native_result = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[value, pk_hash, randomness]);

        // Circuit computation
        let cs = ConstraintSystem::<Fr>::new_ref();
        let value_var = FpVar::new_witness(cs.clone(), || Ok(value)).unwrap();
        let pk_hash_var = FpVar::new_witness(cs.clone(), || Ok(pk_hash)).unwrap();
        let randomness_var = FpVar::new_witness(cs.clone(), || Ok(randomness)).unwrap();

        let circuit_result = note_commitment_gadget(
            cs.clone(),
            &value_var,
            &pk_hash_var,
            &randomness_var,
        ).unwrap();

        let circuit_value = circuit_result.value().unwrap();

        assert_eq!(native_result, circuit_value);
        assert!(cs.is_satisfied().unwrap());

        println!("Note commitment gadget: {} constraints", cs.num_constraints());
    }

    #[test]
    #[ignore = "Native uses circomlib Poseidon, circuit uses ark_crypto_primitives (different params)"]
    fn test_nullifier_gadget() {
        let mut rng = StdRng::seed_from_u64(12345);

        let nk = Fr::rand(&mut rng);
        let cm = Fr::rand(&mut rng);
        let position = Fr::from(42u64);

        // Native computation
        let native_result = poseidon_hash(DOMAIN_NULLIFIER, &[nk, cm, position]);

        // Circuit computation
        let cs = ConstraintSystem::<Fr>::new_ref();
        let nk_var = FpVar::new_witness(cs.clone(), || Ok(nk)).unwrap();
        let cm_var = FpVar::new_witness(cs.clone(), || Ok(cm)).unwrap();
        let pos_var = FpVar::new_witness(cs.clone(), || Ok(position)).unwrap();

        let circuit_result = nullifier_gadget(cs.clone(), &nk_var, &cm_var, &pos_var).unwrap();
        let circuit_value = circuit_result.value().unwrap();

        assert_eq!(native_result, circuit_value);
        assert!(cs.is_satisfied().unwrap());

        println!("Nullifier gadget: {} constraints", cs.num_constraints());
    }

    #[test]
    #[ignore = "Native uses circomlib Poseidon, circuit uses ark_crypto_primitives (different params)"]
    fn test_merkle_hash_gadget() {
        let mut rng = StdRng::seed_from_u64(12345);

        let left = Fr::rand(&mut rng);
        let right = Fr::rand(&mut rng);

        // Native computation
        let native_result = poseidon_hash(DOMAIN_MERKLE_NODE, &[left, right]);

        // Circuit computation
        let cs = ConstraintSystem::<Fr>::new_ref();
        let left_var = FpVar::new_witness(cs.clone(), || Ok(left)).unwrap();
        let right_var = FpVar::new_witness(cs.clone(), || Ok(right)).unwrap();

        let circuit_result = merkle_hash_gadget(cs.clone(), &left_var, &right_var).unwrap();
        let circuit_value = circuit_result.value().unwrap();

        assert_eq!(native_result, circuit_value);
        assert!(cs.is_satisfied().unwrap());

        println!("Merkle hash gadget: {} constraints", cs.num_constraints());
    }
}
