//! End-to-end ZK proof tests.
//!
//! These tests verify the complete ZK proof flow:
//! 1. Generate parameters (trusted setup)
//! 2. Create circuits with correct witnesses
//! 3. Generate proofs
//! 4. Verify proofs

use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;

use postera::crypto::{
    circuits::{SpendCircuit, OutputCircuit},
    poseidon::{poseidon_hash, DOMAIN_NOTE_COMMITMENT, DOMAIN_NULLIFIER, DOMAIN_MERKLE_NODE},
    proof::{generate_spend_proof, verify_spend_proof, generate_output_proof, verify_output_proof},
    setup::generate_parameters,
    merkle_tree::TREE_DEPTH,
};

#[test]
fn test_output_proof_e2e() {
    let mut rng = StdRng::seed_from_u64(12345);

    // 1. Generate parameters
    println!("Generating parameters...");
    let (proving_params, verifying_params) = generate_parameters(&mut rng)
        .expect("Parameter generation should succeed");

    // 2. Create note values
    let value = 1000u64;
    let pk_hash = Fr::rand(&mut rng);
    let randomness = Fr::rand(&mut rng);

    // 3. Compute the note commitment natively
    let value_fe = Fr::from(value);
    let note_cm = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[value_fe, pk_hash, randomness]);

    // Value commitment hash (simplified)
    let value_commitment_hash = Fr::from(0u64);

    // 4. Create the circuit
    let circuit = OutputCircuit::new(
        note_cm,
        value_commitment_hash,
        value,
        pk_hash,
        randomness,
        Fr::from(0u64),
    );

    // 5. Generate proof
    println!("Generating output proof...");
    let proof = generate_output_proof(circuit.clone(), &proving_params, &mut rng)
        .expect("Proof generation should succeed");

    // 6. Verify proof
    println!("Verifying output proof...");
    let public_inputs = circuit.public_inputs();
    let is_valid = verify_output_proof(&proof, &public_inputs, &verifying_params);

    assert!(is_valid, "Output proof should verify");
    println!("Output proof verified successfully!");
}

#[test]
fn test_spend_proof_e2e() {
    let mut rng = StdRng::seed_from_u64(12345);

    // 1. Generate parameters
    println!("Generating parameters...");
    let (proving_params, verifying_params) = generate_parameters(&mut rng)
        .expect("Parameter generation should succeed");

    // 2. Create note values
    let value = 1000u64;
    let pk_hash = Fr::rand(&mut rng);
    let randomness = Fr::rand(&mut rng);
    let nullifier_key = Fr::rand(&mut rng);
    let position = 5u64;

    // 3. Compute note commitment
    let value_fe = Fr::from(value);
    let cm = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[value_fe, pk_hash, randomness]);

    // 4. Create Merkle path (all zeros for simplicity)
    let merkle_path = vec![Fr::from(0u64); TREE_DEPTH];

    // 5. Compute the root by hashing up the tree
    let mut current = cm;
    for i in 0..TREE_DEPTH {
        let sibling = merkle_path[i];
        let (left, right) = if (position >> i) & 1 == 0 {
            (current, sibling)
        } else {
            (sibling, current)
        };
        current = poseidon_hash(DOMAIN_MERKLE_NODE, &[left, right]);
    }
    let merkle_root = current;

    // 6. Compute nullifier
    let position_fe = Fr::from(position);
    let nullifier = poseidon_hash(DOMAIN_NULLIFIER, &[nullifier_key, cm, position_fe]);

    // Value commitment hash (simplified)
    let value_commitment_hash = Fr::from(0u64);

    // 7. Create the circuit
    let circuit = SpendCircuit::new(
        merkle_root,
        nullifier,
        value_commitment_hash,
        value,
        pk_hash,
        randomness,
        nullifier_key,
        merkle_path,
        position,
        Fr::from(0u64),
    );

    // 8. Generate proof
    println!("Generating spend proof...");
    let proof = generate_spend_proof(circuit.clone(), &proving_params, &mut rng)
        .expect("Proof generation should succeed");

    // 9. Verify proof
    println!("Verifying spend proof...");
    let public_inputs = circuit.public_inputs();
    let is_valid = verify_spend_proof(&proof, &public_inputs, &verifying_params);

    assert!(is_valid, "Spend proof should verify");
    println!("Spend proof verified successfully!");
}

#[test]
fn test_proof_fails_with_wrong_witness() {
    let mut rng = StdRng::seed_from_u64(12345);

    // Generate parameters
    let (proving_params, verifying_params) = generate_parameters(&mut rng)
        .expect("Parameter generation should succeed");

    // Create note values
    let value = 1000u64;
    let pk_hash = Fr::rand(&mut rng);
    let randomness = Fr::rand(&mut rng);

    // Compute the note commitment natively
    let value_fe = Fr::from(value);
    let note_cm = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[value_fe, pk_hash, randomness]);

    // Create circuit with WRONG value (2000 instead of 1000)
    let wrong_value = 2000u64;
    let circuit = OutputCircuit::new(
        note_cm,               // Correct commitment (computed with value=1000)
        Fr::from(0u64),
        wrong_value,           // WRONG value!
        pk_hash,
        randomness,
        Fr::from(0u64),
    );

    // Proof generation may fail or produce invalid proof
    let proof_result = generate_output_proof(circuit.clone(), &proving_params, &mut rng);

    match proof_result {
        Ok(proof) => {
            // If proof was generated, it should NOT verify
            let public_inputs = vec![note_cm, Fr::from(0u64)];
            let is_valid = verify_output_proof(&proof, &public_inputs, &verifying_params);
            assert!(!is_valid, "Proof with wrong witness should NOT verify");
        }
        Err(_) => {
            // It's also acceptable for proof generation to fail
            println!("Proof generation failed as expected with wrong witness");
        }
    }
}

#[test]
fn test_proof_fails_with_wrong_public_inputs() {
    let mut rng = StdRng::seed_from_u64(12345);

    // Generate parameters
    let (proving_params, verifying_params) = generate_parameters(&mut rng)
        .expect("Parameter generation should succeed");

    // Create note values
    let value = 1000u64;
    let pk_hash = Fr::rand(&mut rng);
    let randomness = Fr::rand(&mut rng);

    // Compute the note commitment natively
    let value_fe = Fr::from(value);
    let note_cm = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[value_fe, pk_hash, randomness]);

    // Create correct circuit
    let circuit = OutputCircuit::new(
        note_cm,
        Fr::from(0u64),
        value,
        pk_hash,
        randomness,
        Fr::from(0u64),
    );

    // Generate proof
    let proof = generate_output_proof(circuit, &proving_params, &mut rng)
        .expect("Proof generation should succeed");

    // Try to verify with WRONG public inputs
    let wrong_commitment = Fr::rand(&mut rng);
    let wrong_public_inputs = vec![wrong_commitment, Fr::from(0u64)];

    let is_valid = verify_output_proof(&proof, &wrong_public_inputs, &verifying_params);
    assert!(!is_valid, "Proof should NOT verify with wrong public inputs");
}
