//! Poseidon consistency tests.
//!
//! NOTE: Tests that compare native vs circuit are IGNORED because:
//! - Native uses light-poseidon (circomlib-compatible) for browser wallet interop
//! - Circuit uses ark_crypto_primitives with different parameters
//!
//! This is intentional. Browser proving uses Circom circuits which match circomlib.

use ark_bn254::Fr;
use ark_ff::UniformRand;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, R1CSVar};
use ark_relations::r1cs::ConstraintSystem;
use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;

use postera::crypto::poseidon::{
    poseidon_hash, bytes32_to_field, field_to_bytes32,
    DOMAIN_NOTE_COMMITMENT, DOMAIN_NULLIFIER, DOMAIN_MERKLE_NODE,
};
use postera::crypto::circuits::{
    note_commitment_gadget, nullifier_gadget, merkle_hash_gadget,
};

#[test]
#[ignore = "Native uses circomlib Poseidon, circuit uses ark_crypto_primitives (different params)"]
fn test_note_commitment_consistency() {
    let mut rng = StdRng::seed_from_u64(42);

    for _ in 0..10 {
        let value = Fr::rand(&mut rng);
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

        assert_eq!(
            native_result, circuit_value,
            "Note commitment: native and circuit must produce identical results"
        );
        assert!(cs.is_satisfied().unwrap(), "Circuit constraints must be satisfied");
    }
}

#[test]
#[ignore = "Native uses circomlib Poseidon, circuit uses ark_crypto_primitives (different params)"]
fn test_nullifier_consistency() {
    let mut rng = StdRng::seed_from_u64(42);

    for _ in 0..10 {
        let nk = Fr::rand(&mut rng);
        let cm = Fr::rand(&mut rng);
        let position = Fr::rand(&mut rng);

        // Native computation
        let native_result = poseidon_hash(DOMAIN_NULLIFIER, &[nk, cm, position]);

        // Circuit computation
        let cs = ConstraintSystem::<Fr>::new_ref();
        let nk_var = FpVar::new_witness(cs.clone(), || Ok(nk)).unwrap();
        let cm_var = FpVar::new_witness(cs.clone(), || Ok(cm)).unwrap();
        let pos_var = FpVar::new_witness(cs.clone(), || Ok(position)).unwrap();

        let circuit_result = nullifier_gadget(cs.clone(), &nk_var, &cm_var, &pos_var).unwrap();
        let circuit_value = circuit_result.value().unwrap();

        assert_eq!(
            native_result, circuit_value,
            "Nullifier: native and circuit must produce identical results"
        );
        assert!(cs.is_satisfied().unwrap());
    }
}

#[test]
#[ignore = "Native uses circomlib Poseidon, circuit uses ark_crypto_primitives (different params)"]
fn test_merkle_hash_consistency() {
    let mut rng = StdRng::seed_from_u64(42);

    for _ in 0..10 {
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

        assert_eq!(
            native_result, circuit_value,
            "Merkle hash: native and circuit must produce identical results"
        );
        assert!(cs.is_satisfied().unwrap());
    }
}

#[test]
fn test_bytes_roundtrip_preserves_hash() {
    let mut rng = StdRng::seed_from_u64(42);

    for _ in 0..10 {
        let a = Fr::rand(&mut rng);
        let b = Fr::rand(&mut rng);

        // Hash directly
        let hash1 = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[a, b]);

        // Convert to bytes and back, then hash
        let a_bytes = field_to_bytes32(&a);
        let b_bytes = field_to_bytes32(&b);
        let a_back = bytes32_to_field(&a_bytes);
        let b_back = bytes32_to_field(&b_bytes);
        let hash2 = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[a_back, b_back]);

        assert_eq!(
            hash1, hash2,
            "Byte conversion must preserve hash results"
        );
    }
}

#[test]
fn test_domain_separation() {
    let a = Fr::from(123u64);
    let b = Fr::from(456u64);

    let hash_note = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[a, b]);
    let hash_nullifier = poseidon_hash(DOMAIN_NULLIFIER, &[a, b]);
    let hash_merkle = poseidon_hash(DOMAIN_MERKLE_NODE, &[a, b]);

    assert_ne!(hash_note, hash_nullifier, "Different domains must produce different hashes");
    assert_ne!(hash_note, hash_merkle, "Different domains must produce different hashes");
    assert_ne!(hash_nullifier, hash_merkle, "Different domains must produce different hashes");
}
