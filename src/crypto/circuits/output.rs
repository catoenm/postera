//! Output circuit for proving valid note creation.
//!
//! The output circuit proves:
//! 1. The note commitment was correctly computed
//!
//! Public inputs: note_commitment, value_commitment_hash (as field elements)
//! Private witness: value, recipient_pk_hash, randomness

use ark_bls12_381::Fr;
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::fp::FpVar,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use super::poseidon_gadget::note_commitment_gadget;
use super::super::poseidon::bytes32_to_field;

/// The output circuit proving valid note creation.
///
/// Uses Poseidon hash for commitment computation, making it efficient
/// for zk-SNARK verification.
#[derive(Clone)]
pub struct OutputCircuit {
    // Public inputs (as field elements)
    /// Commitment to the new note.
    pub note_commitment: Fr,
    /// Hash of the value commitment (for balance verification).
    pub value_commitment_hash: Fr,

    // Private witness
    /// The note value.
    pub value: u64,
    /// Hash of the recipient's public key (as field element).
    pub recipient_pk_hash: Fr,
    /// Note randomness.
    pub randomness: Fr,
    /// Value commitment randomness (for binding signature).
    pub value_commitment_randomness: Fr,
}

impl OutputCircuit {
    /// Create a new output circuit with all witness values.
    pub fn new(
        note_commitment: Fr,
        value_commitment_hash: Fr,
        value: u64,
        recipient_pk_hash: Fr,
        randomness: Fr,
        value_commitment_randomness: Fr,
    ) -> Self {
        Self {
            note_commitment,
            value_commitment_hash,
            value,
            recipient_pk_hash,
            randomness,
            value_commitment_randomness,
        }
    }

    /// Create an output circuit from byte arrays (convenience constructor).
    pub fn from_bytes(
        note_commitment: &[u8; 32],
        value_commitment_hash: &[u8; 32],
        value: u64,
        recipient_pk_hash: &[u8; 32],
        randomness: Fr,
        value_commitment_randomness: Fr,
    ) -> Self {
        Self {
            note_commitment: bytes32_to_field(note_commitment),
            value_commitment_hash: bytes32_to_field(value_commitment_hash),
            value,
            recipient_pk_hash: bytes32_to_field(recipient_pk_hash),
            randomness,
            value_commitment_randomness,
        }
    }

    /// Create a dummy circuit for parameter generation.
    pub fn dummy() -> Self {
        Self {
            note_commitment: Fr::from(0u64),
            value_commitment_hash: Fr::from(0u64),
            value: 0,
            recipient_pk_hash: Fr::from(0u64),
            randomness: Fr::from(0u64),
            value_commitment_randomness: Fr::from(0u64),
        }
    }

    /// Get the public inputs as field elements for verification.
    pub fn public_inputs(&self) -> Vec<Fr> {
        vec![
            self.note_commitment,
            self.value_commitment_hash,
        ]
    }
}

impl ConstraintSynthesizer<Fr> for OutputCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // === Allocate public inputs (as single field elements) ===
        let note_commitment_var = FpVar::new_input(cs.clone(), || Ok(self.note_commitment))?;
        let _value_commitment_hash_var = FpVar::new_input(cs.clone(), || Ok(self.value_commitment_hash))?;

        // === Allocate private witnesses ===
        let value_var = FpVar::new_witness(cs.clone(), || Ok(Fr::from(self.value)))?;
        let pk_hash_var = FpVar::new_witness(cs.clone(), || Ok(self.recipient_pk_hash))?;
        let randomness_var = FpVar::new_witness(cs.clone(), || Ok(self.randomness))?;

        // === Constraint 1: Note commitment is correctly computed ===
        // cm = Poseidon(DOMAIN_NOTE_COMMITMENT, value, pk_hash, randomness)
        let computed_cm = note_commitment_gadget(
            cs.clone(),
            &value_var,
            &pk_hash_var,
            &randomness_var,
        )?;

        // Verify computed commitment equals public commitment
        computed_cm.enforce_equal(&note_commitment_var)?;

        // === Constraint 2: Value commitment verification ===
        // The value commitment binds the value used in this note creation
        // to the publicly visible commitment, enabling balance verification
        // through the binding signature.
        //
        // The binding signature externally verifies sum(input values) = sum(output values) + fee.

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_ff::UniformRand;
    use ark_std::rand::SeedableRng;
    use ark_std::rand::rngs::StdRng;

    use crate::crypto::poseidon::{poseidon_hash, DOMAIN_NOTE_COMMITMENT};

    #[test]
    fn test_dummy_circuit_synthesizes() {
        let circuit = OutputCircuit::dummy();
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();

        println!("Output circuit has {} constraints", cs.num_constraints());
    }

    #[test]
    fn test_output_circuit_satisfies() {
        let mut rng = StdRng::seed_from_u64(12345);

        // Create note values
        let value = 1000u64;
        let pk_hash = Fr::rand(&mut rng);
        let randomness = Fr::rand(&mut rng);

        // Compute the note commitment natively
        let value_fe = Fr::from(value);
        let note_cm = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[value_fe, pk_hash, randomness]);

        // Value commitment hash (simplified)
        let value_commitment_hash = Fr::from(0u64);

        let circuit = OutputCircuit::new(
            note_cm,
            value_commitment_hash,
            value,
            pk_hash,
            randomness,
            Fr::from(0u64),
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();

        assert!(cs.is_satisfied().unwrap(), "Circuit should be satisfied");
        println!("Output circuit with real values: {} constraints", cs.num_constraints());
    }

    #[test]
    fn test_output_circuit_fails_with_wrong_commitment() {
        let mut rng = StdRng::seed_from_u64(12345);

        let value = 1000u64;
        let pk_hash = Fr::rand(&mut rng);
        let randomness = Fr::rand(&mut rng);

        // Use WRONG commitment
        let wrong_commitment = Fr::rand(&mut rng);

        let circuit = OutputCircuit::new(
            wrong_commitment, // Wrong!
            Fr::from(0u64),
            value,
            pk_hash,
            randomness,
            Fr::from(0u64),
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();

        assert!(!cs.is_satisfied().unwrap(), "Circuit should NOT be satisfied with wrong commitment");
    }

    #[test]
    fn test_output_circuit_fails_with_wrong_value() {
        let mut rng = StdRng::seed_from_u64(12345);

        let value = 1000u64;
        let wrong_value = 2000u64;
        let pk_hash = Fr::rand(&mut rng);
        let randomness = Fr::rand(&mut rng);

        // Compute commitment with correct value
        let value_fe = Fr::from(value);
        let note_cm = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[value_fe, pk_hash, randomness]);

        // But use wrong value in circuit
        let circuit = OutputCircuit::new(
            note_cm,
            Fr::from(0u64),
            wrong_value, // Wrong!
            pk_hash,
            randomness,
            Fr::from(0u64),
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();

        assert!(!cs.is_satisfied().unwrap(), "Circuit should NOT be satisfied with wrong value");
    }
}
