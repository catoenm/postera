//! Plonky2 circuit definition for post-quantum transaction verification.
//!
//! This module defines the arithmetic circuit that proves:
//! 1. Spend validity - notes exist in the commitment tree
//! 2. Output validity - commitments are correctly formed
//! 3. Balance constraint - sum(inputs) = sum(outputs) + fee
//!
//! The circuit uses Poseidon hash over the Goldilocks field, matching
//! our existing `poseidon_pq.rs` implementation.

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::PoseidonGoldilocksConfig;

// Domain separators as u64 values (matching poseidon_pq.rs)
const DOMAIN_NOTE_COMMIT: u64 = 1;
const DOMAIN_NULLIFIER: u64 = 3;
const DOMAIN_MERKLE_NODE: u64 = 5;

/// Field type (Goldilocks - same as poseidon_pq.rs)
pub type F = GoldilocksField;

/// Extension degree
pub const D: usize = 2;

/// Config type
pub type C = PoseidonGoldilocksConfig;

/// Merkle tree depth
pub const TREE_DEPTH: usize = 32;

/// Transaction circuit for V2 post-quantum transactions.
///
/// This circuit proves that a transaction is valid without revealing
/// the values being transferred. The proof is quantum-resistant
/// because it only relies on hash function security.
pub struct TransactionCircuit {
    /// Number of spends (inputs)
    pub num_spends: usize,
    /// Number of outputs
    pub num_outputs: usize,
}

/// Targets for a single spend in the circuit.
#[derive(Clone)]
pub struct SpendTargets {
    /// Note value (private)
    pub value: Target,
    /// Public key hash (private)
    pub pk_hash: [Target; 4],
    /// Note randomness (private)
    pub randomness: [Target; 4],
    /// Nullifier key (private)
    pub nullifier_key: [Target; 4],
    /// Position in tree (private)
    pub position: Target,
    /// Merkle path siblings (private)
    pub merkle_path: Vec<[Target; 4]>,
    /// Path direction bits (private)
    pub path_indices: Vec<BoolTarget>,
    /// Expected merkle root (public)
    pub merkle_root: [Target; 4],
    /// Expected nullifier (public)
    pub nullifier: [Target; 4],
}

/// Targets for a single output in the circuit.
#[derive(Clone)]
pub struct OutputTargets {
    /// Note value (private)
    pub value: Target,
    /// Public key hash (private)
    pub pk_hash: [Target; 4],
    /// Note randomness (private)
    pub randomness: [Target; 4],
    /// Expected note commitment (public)
    pub note_commitment: [Target; 4],
}

/// All targets for a transaction circuit.
pub struct TransactionTargets {
    /// Spend targets
    pub spends: Vec<SpendTargets>,
    /// Output targets
    pub outputs: Vec<OutputTargets>,
    /// Fee (public)
    pub fee: Target,
}

impl TransactionCircuit {
    /// Create a new transaction circuit for the given shape.
    pub fn new(num_spends: usize, num_outputs: usize) -> Self {
        Self {
            num_spends,
            num_outputs,
        }
    }

    /// Build the circuit and return circuit data + targets for witness assignment.
    pub fn build(&self) -> (CircuitData<F, C, D>, TransactionTargets) {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let mut spend_targets = Vec::with_capacity(self.num_spends);
        let mut output_targets = Vec::with_capacity(self.num_outputs);

        // Track total input and output values for balance check
        let mut total_input = builder.zero();
        let mut total_output = builder.zero();

        // === Build spend circuits ===
        for _ in 0..self.num_spends {
            let targets = self.build_spend(&mut builder);

            // Accumulate input value
            total_input = builder.add(total_input, targets.value);

            // Register public inputs (merkle root and nullifier)
            for &elem in &targets.merkle_root {
                builder.register_public_input(elem);
            }
            for &elem in &targets.nullifier {
                builder.register_public_input(elem);
            }

            spend_targets.push(targets);
        }

        // === Build output circuits ===
        for _ in 0..self.num_outputs {
            let targets = self.build_output(&mut builder);

            // Accumulate output value
            total_output = builder.add(total_output, targets.value);

            // Register public inputs (note commitment)
            for &elem in &targets.note_commitment {
                builder.register_public_input(elem);
            }

            output_targets.push(targets);
        }

        // === Fee (public input) ===
        let fee = builder.add_virtual_target();
        builder.register_public_input(fee);

        // === Balance constraint ===
        // total_input == total_output + fee
        let output_plus_fee = builder.add(total_output, fee);
        builder.connect(total_input, output_plus_fee);

        let data = builder.build::<C>();

        let targets = TransactionTargets {
            spends: spend_targets,
            outputs: output_targets,
            fee,
        };

        (data, targets)
    }

    /// Build circuit for a single spend.
    fn build_spend(&self, builder: &mut CircuitBuilder<F, D>) -> SpendTargets {
        // Private inputs
        let value = builder.add_virtual_target();
        let pk_hash = [
            builder.add_virtual_target(),
            builder.add_virtual_target(),
            builder.add_virtual_target(),
            builder.add_virtual_target(),
        ];
        let randomness = [
            builder.add_virtual_target(),
            builder.add_virtual_target(),
            builder.add_virtual_target(),
            builder.add_virtual_target(),
        ];
        let nullifier_key = [
            builder.add_virtual_target(),
            builder.add_virtual_target(),
            builder.add_virtual_target(),
            builder.add_virtual_target(),
        ];
        let position = builder.add_virtual_target();

        // Merkle path
        let mut merkle_path = Vec::with_capacity(TREE_DEPTH);
        let mut path_indices = Vec::with_capacity(TREE_DEPTH);
        for _ in 0..TREE_DEPTH {
            merkle_path.push([
                builder.add_virtual_target(),
                builder.add_virtual_target(),
                builder.add_virtual_target(),
                builder.add_virtual_target(),
            ]);
            path_indices.push(builder.add_virtual_bool_target_safe());
        }

        // Public inputs (will be constrained)
        let merkle_root = [
            builder.add_virtual_target(),
            builder.add_virtual_target(),
            builder.add_virtual_target(),
            builder.add_virtual_target(),
        ];
        let nullifier = [
            builder.add_virtual_target(),
            builder.add_virtual_target(),
            builder.add_virtual_target(),
            builder.add_virtual_target(),
        ];

        // 1. Compute note commitment
        let note_commitment =
            self.compute_note_commitment(builder, value, &pk_hash, &randomness);

        // 2. Verify Merkle path
        let computed_root =
            self.verify_merkle_path(builder, &note_commitment, &merkle_path, &path_indices);

        // Constrain computed root == expected root
        for i in 0..4 {
            builder.connect(computed_root[i], merkle_root[i]);
        }

        // 3. Compute nullifier
        let computed_nullifier =
            self.compute_nullifier(builder, &nullifier_key, &note_commitment, position);

        // Constrain computed nullifier == expected nullifier
        for i in 0..4 {
            builder.connect(computed_nullifier[i], nullifier[i]);
        }

        SpendTargets {
            value,
            pk_hash,
            randomness,
            nullifier_key,
            position,
            merkle_path,
            path_indices,
            merkle_root,
            nullifier,
        }
    }

    /// Build circuit for a single output.
    fn build_output(&self, builder: &mut CircuitBuilder<F, D>) -> OutputTargets {
        // Private inputs
        let value = builder.add_virtual_target();
        let pk_hash = [
            builder.add_virtual_target(),
            builder.add_virtual_target(),
            builder.add_virtual_target(),
            builder.add_virtual_target(),
        ];
        let randomness = [
            builder.add_virtual_target(),
            builder.add_virtual_target(),
            builder.add_virtual_target(),
            builder.add_virtual_target(),
        ];

        // Public input (will be constrained)
        let note_commitment = [
            builder.add_virtual_target(),
            builder.add_virtual_target(),
            builder.add_virtual_target(),
            builder.add_virtual_target(),
        ];

        // Compute note commitment
        let computed_commitment =
            self.compute_note_commitment(builder, value, &pk_hash, &randomness);

        // Constrain computed commitment == expected commitment
        for i in 0..4 {
            builder.connect(computed_commitment[i], note_commitment[i]);
        }

        OutputTargets {
            value,
            pk_hash,
            randomness,
            note_commitment,
        }
    }

    /// Compute note commitment: Poseidon(DOMAIN, value, pk_hash, randomness)
    fn compute_note_commitment(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        value: Target,
        pk_hash: &[Target; 4],
        randomness: &[Target; 4],
    ) -> [Target; 4] {
        let domain = builder.constant(F::from_canonical_u64(DOMAIN_NOTE_COMMIT));

        // Build input: [domain, value, pk_hash[0..4], randomness[0..4]]
        let mut inputs = vec![domain, value];
        inputs.extend_from_slice(pk_hash);
        inputs.extend_from_slice(randomness);

        self.poseidon_hash(builder, &inputs)
    }

    /// Compute nullifier: Poseidon(DOMAIN, nk, commitment, position)
    fn compute_nullifier(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        nullifier_key: &[Target; 4],
        commitment: &[Target; 4],
        position: Target,
    ) -> [Target; 4] {
        let domain = builder.constant(F::from_canonical_u64(DOMAIN_NULLIFIER));

        // Build input: [domain, nk[0..4], commitment[0..4], position]
        let mut inputs = vec![domain];
        inputs.extend_from_slice(nullifier_key);
        inputs.extend_from_slice(commitment);
        inputs.push(position);

        self.poseidon_hash(builder, &inputs)
    }

    /// Verify a Merkle path and return the computed root.
    fn verify_merkle_path(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        leaf: &[Target; 4],
        path: &[[Target; 4]],
        indices: &[BoolTarget],
    ) -> [Target; 4] {
        let domain = builder.constant(F::from_canonical_u64(DOMAIN_MERKLE_NODE));
        let mut current = *leaf;

        for (sibling, is_right) in path.iter().zip(indices.iter()) {
            // Select left and right based on index
            // If is_right=true, we're on the right, so sibling is left
            let mut left = [builder.zero(); 4];
            let mut right = [builder.zero(); 4];

            for i in 0..4 {
                // left = is_right ? sibling : current
                left[i] = builder.select(is_right.clone(), sibling[i], current[i]);
                // right = is_right ? current : sibling
                right[i] = builder.select(is_right.clone(), current[i], sibling[i]);
            }

            // Hash: Poseidon(domain, left, right)
            let mut inputs = vec![domain];
            inputs.extend_from_slice(&left);
            inputs.extend_from_slice(&right);

            current = self.poseidon_hash(builder, &inputs);
        }

        current
    }

    /// Compute Poseidon hash of inputs, returning 4 field elements.
    fn poseidon_hash(&self, builder: &mut CircuitBuilder<F, D>, inputs: &[Target]) -> [Target; 4] {
        let hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs.to_vec());
        hash.elements
    }
}

/// Pre-built circuits for common transaction shapes.
pub struct CircuitCache {
    /// 1 spend, 1 output
    pub circuit_1_1: (CircuitData<F, C, D>, TransactionTargets),
    /// 1 spend, 2 outputs
    pub circuit_1_2: (CircuitData<F, C, D>, TransactionTargets),
    /// 2 spends, 1 output
    pub circuit_2_1: (CircuitData<F, C, D>, TransactionTargets),
    /// 2 spends, 2 outputs
    pub circuit_2_2: (CircuitData<F, C, D>, TransactionTargets),
}

impl CircuitCache {
    /// Build all common circuit shapes.
    pub fn new() -> Self {
        Self {
            circuit_1_1: TransactionCircuit::new(1, 1).build(),
            circuit_1_2: TransactionCircuit::new(1, 2).build(),
            circuit_2_1: TransactionCircuit::new(2, 1).build(),
            circuit_2_2: TransactionCircuit::new(2, 2).build(),
        }
    }

    /// Get the appropriate circuit for a transaction shape.
    pub fn get(&self, num_spends: usize, num_outputs: usize) -> Option<&(CircuitData<F, C, D>, TransactionTargets)> {
        match (num_spends, num_outputs) {
            (1, 1) => Some(&self.circuit_1_1),
            (1, 2) => Some(&self.circuit_1_2),
            (2, 1) => Some(&self.circuit_2_1),
            (2, 2) => Some(&self.circuit_2_2),
            _ => None,
        }
    }
}

impl Default for CircuitCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_builds() {
        let circuit = TransactionCircuit::new(1, 1);
        let (data, _targets) = circuit.build();
        assert!(data.common.degree_bits() > 0);
    }

    #[test]
    fn test_circuit_cache() {
        let cache = CircuitCache::new();
        assert!(cache.get(1, 1).is_some());
        assert!(cache.get(2, 2).is_some());
        assert!(cache.get(5, 5).is_none());
    }
}
