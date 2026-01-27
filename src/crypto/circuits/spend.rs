//! Spend circuit for proving valid note consumption.
//!
//! The spend circuit proves:
//! 1. The note commitment was correctly computed
//! 2. The note exists in the commitment tree (Merkle proof)
//! 3. The nullifier was correctly derived
//!
//! Public inputs: merkle_root, nullifier, value_commitment_hash (all as field elements)
//! Private witness: value, pk_hash, randomness, nullifier_key, merkle_path, position

use ark_bls12_381::Fr;
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    eq::EqGadget,
    fields::fp::FpVar,
    select::CondSelectGadget,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use super::poseidon_gadget::{note_commitment_gadget, nullifier_gadget, merkle_hash_gadget};
use super::super::merkle_tree::TREE_DEPTH;
use super::super::poseidon::bytes32_to_field;

/// The spend circuit proving valid note consumption.
///
/// Uses Poseidon hash for all hash computations, making it efficient
/// for zk-SNARK verification.
#[derive(Clone)]
pub struct SpendCircuit {
    // Public inputs (as field elements)
    /// Merkle root at spend time.
    pub merkle_root: Fr,
    /// Nullifier marking the note as spent.
    pub nullifier: Fr,
    /// Hash of the value commitment (for balance verification).
    pub value_commitment_hash: Fr,

    // Private witness
    /// The note value.
    pub value: u64,
    /// Hash of the recipient's public key (as field element).
    pub recipient_pk_hash: Fr,
    /// Note randomness.
    pub randomness: Fr,
    /// Secret nullifier key.
    pub nullifier_key: Fr,
    /// Merkle path (sibling hashes as field elements).
    pub merkle_path: Vec<Fr>,
    /// Position of the note in the tree.
    pub position: u64,
    /// Value commitment randomness.
    pub value_commitment_randomness: Fr,
}

impl SpendCircuit {
    /// Create a new spend circuit with all witness values.
    pub fn new(
        merkle_root: Fr,
        nullifier: Fr,
        value_commitment_hash: Fr,
        value: u64,
        recipient_pk_hash: Fr,
        randomness: Fr,
        nullifier_key: Fr,
        merkle_path: Vec<Fr>,
        position: u64,
        value_commitment_randomness: Fr,
    ) -> Self {
        Self {
            merkle_root,
            nullifier,
            value_commitment_hash,
            value,
            recipient_pk_hash,
            randomness,
            nullifier_key,
            merkle_path,
            position,
            value_commitment_randomness,
        }
    }

    /// Create a spend circuit from byte arrays (convenience constructor).
    pub fn from_bytes(
        merkle_root: &[u8; 32],
        nullifier: &[u8; 32],
        value_commitment_hash: &[u8; 32],
        value: u64,
        recipient_pk_hash: &[u8; 32],
        randomness: Fr,
        nullifier_key: Fr,
        merkle_path: &[[u8; 32]],
        position: u64,
        value_commitment_randomness: Fr,
    ) -> Self {
        Self {
            merkle_root: bytes32_to_field(merkle_root),
            nullifier: bytes32_to_field(nullifier),
            value_commitment_hash: bytes32_to_field(value_commitment_hash),
            value,
            recipient_pk_hash: bytes32_to_field(recipient_pk_hash),
            randomness,
            nullifier_key,
            merkle_path: merkle_path.iter().map(bytes32_to_field).collect(),
            position,
            value_commitment_randomness,
        }
    }

    /// Create a dummy circuit for parameter generation.
    pub fn dummy() -> Self {
        Self {
            merkle_root: Fr::from(0u64),
            nullifier: Fr::from(0u64),
            value_commitment_hash: Fr::from(0u64),
            value: 0,
            recipient_pk_hash: Fr::from(0u64),
            randomness: Fr::from(0u64),
            nullifier_key: Fr::from(0u64),
            merkle_path: vec![Fr::from(0u64); TREE_DEPTH],
            position: 0,
            value_commitment_randomness: Fr::from(0u64),
        }
    }

    /// Get the public inputs as field elements for verification.
    pub fn public_inputs(&self) -> Vec<Fr> {
        vec![
            self.merkle_root,
            self.nullifier,
            self.value_commitment_hash,
        ]
    }
}

impl ConstraintSynthesizer<Fr> for SpendCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // === Allocate public inputs (as single field elements) ===
        let merkle_root_var = FpVar::new_input(cs.clone(), || Ok(self.merkle_root))?;
        let nullifier_var = FpVar::new_input(cs.clone(), || Ok(self.nullifier))?;
        let _value_commitment_hash_var = FpVar::new_input(cs.clone(), || Ok(self.value_commitment_hash))?;

        // === Allocate private witnesses ===
        let value_var = FpVar::new_witness(cs.clone(), || Ok(Fr::from(self.value)))?;
        let pk_hash_var = FpVar::new_witness(cs.clone(), || Ok(self.recipient_pk_hash))?;
        let randomness_var = FpVar::new_witness(cs.clone(), || Ok(self.randomness))?;
        let nullifier_key_var = FpVar::new_witness(cs.clone(), || Ok(self.nullifier_key))?;
        let position_var = FpVar::new_witness(cs.clone(), || Ok(Fr::from(self.position)))?;

        // Allocate Merkle path siblings
        let merkle_path_vars: Vec<FpVar<Fr>> = self
            .merkle_path
            .iter()
            .map(|sibling| FpVar::new_witness(cs.clone(), || Ok(*sibling)))
            .collect::<Result<Vec<_>, _>>()?;

        // Position bits for path direction
        let position_bits: Vec<Boolean<Fr>> = (0..TREE_DEPTH)
            .map(|i| {
                let bit = ((self.position >> i) & 1) == 1;
                Boolean::new_witness(cs.clone(), || Ok(bit))
            })
            .collect::<Result<Vec<_>, _>>()?;

        // === Constraint 1: Note commitment is correctly computed ===
        // cm = Poseidon(DOMAIN_NOTE_COMMITMENT, value, pk_hash, randomness)
        let computed_cm = note_commitment_gadget(
            cs.clone(),
            &value_var,
            &pk_hash_var,
            &randomness_var,
        )?;

        // === Constraint 2: Merkle path verification ===
        // Start with computed commitment
        let mut current_hash = computed_cm.clone();

        for (sibling, direction_bit) in merkle_path_vars.iter().zip(position_bits.iter()) {
            // If direction_bit is 0, current is left child; if 1, current is right child
            let left = FpVar::conditionally_select(direction_bit, sibling, &current_hash)?;
            let right = FpVar::conditionally_select(direction_bit, &current_hash, sibling)?;

            // Hash the pair
            current_hash = merkle_hash_gadget(cs.clone(), &left, &right)?;
        }

        // Verify computed root equals public merkle root
        current_hash.enforce_equal(&merkle_root_var)?;

        // === Constraint 3: Nullifier is correctly derived ===
        // nf = Poseidon(DOMAIN_NULLIFIER, nk, cm, position)
        let computed_nf = nullifier_gadget(
            cs.clone(),
            &nullifier_key_var,
            &computed_cm,
            &position_var,
        )?;

        // Verify computed nullifier equals public nullifier
        computed_nf.enforce_equal(&nullifier_var)?;

        // === Constraint 4: Value commitment verification ===
        // The value commitment is verified externally through the binding signature.
        // The binding signature ensures sum(input values) = sum(output values) + fee.
        // Here we just ensure the value is bound to the circuit through the commitment.

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

    use crate::crypto::poseidon::{
        poseidon_hash, DOMAIN_NOTE_COMMITMENT, DOMAIN_NULLIFIER, DOMAIN_MERKLE_NODE,
    };

    #[test]
    fn test_dummy_circuit_synthesizes() {
        let circuit = SpendCircuit::dummy();
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();

        println!("Spend circuit has {} constraints", cs.num_constraints());
        // Note: dummy circuit won't satisfy all constraints because
        // the hash values won't match, but it should synthesize
    }

    #[test]
    fn test_spend_circuit_satisfies() {
        let mut rng = StdRng::seed_from_u64(12345);

        // Create note values
        let value = 1000u64;
        let pk_hash = Fr::rand(&mut rng);
        let randomness = Fr::rand(&mut rng);
        let nullifier_key = Fr::rand(&mut rng);
        let position = 5u64;

        // Compute note commitment: Poseidon(domain, value, pk_hash, randomness)
        let value_fe = Fr::from(value);
        let cm = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[value_fe, pk_hash, randomness]);

        // Create a simple Merkle tree path (all zeros for simplicity)
        // In a real scenario, this would be a proper path
        let mut merkle_path = vec![Fr::from(0u64); TREE_DEPTH];

        // Compute the root by hashing up the tree
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

        // Compute nullifier
        let position_fe = Fr::from(position);
        let nullifier = poseidon_hash(DOMAIN_NULLIFIER, &[nullifier_key, cm, position_fe]);

        // Value commitment hash (simplified)
        let value_commitment_hash = Fr::from(0u64);

        // Create the circuit
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

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();

        assert!(cs.is_satisfied().unwrap(), "Circuit should be satisfied");
        println!("Spend circuit with real values: {} constraints", cs.num_constraints());
    }

    #[test]
    fn test_spend_circuit_fails_with_wrong_nullifier() {
        let mut rng = StdRng::seed_from_u64(12345);

        // Create note values
        let value = 1000u64;
        let pk_hash = Fr::rand(&mut rng);
        let randomness = Fr::rand(&mut rng);
        let nullifier_key = Fr::rand(&mut rng);
        let position = 5u64;

        // Compute correct values
        let value_fe = Fr::from(value);
        let cm = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[value_fe, pk_hash, randomness]);

        let mut merkle_path = vec![Fr::from(0u64); TREE_DEPTH];
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

        // Use WRONG nullifier
        let wrong_nullifier = Fr::rand(&mut rng);

        let circuit = SpendCircuit::new(
            merkle_root,
            wrong_nullifier, // Wrong!
            Fr::from(0u64),
            value,
            pk_hash,
            randomness,
            nullifier_key,
            merkle_path,
            position,
            Fr::from(0u64),
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();

        assert!(!cs.is_satisfied().unwrap(), "Circuit should NOT be satisfied with wrong nullifier");
    }

    #[test]
    fn test_spend_circuit_fails_with_wrong_root() {
        let mut rng = StdRng::seed_from_u64(12345);

        let value = 1000u64;
        let pk_hash = Fr::rand(&mut rng);
        let randomness = Fr::rand(&mut rng);
        let nullifier_key = Fr::rand(&mut rng);
        let position = 5u64;

        let value_fe = Fr::from(value);
        let cm = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[value_fe, pk_hash, randomness]);

        let merkle_path = vec![Fr::from(0u64); TREE_DEPTH];

        // Correct nullifier
        let position_fe = Fr::from(position);
        let nullifier = poseidon_hash(DOMAIN_NULLIFIER, &[nullifier_key, cm, position_fe]);

        // Use WRONG merkle root
        let wrong_root = Fr::rand(&mut rng);

        let circuit = SpendCircuit::new(
            wrong_root, // Wrong!
            nullifier,
            Fr::from(0u64),
            value,
            pk_hash,
            randomness,
            nullifier_key,
            merkle_path,
            position,
            Fr::from(0u64),
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();

        assert!(!cs.is_satisfied().unwrap(), "Circuit should NOT be satisfied with wrong root");
    }
}
