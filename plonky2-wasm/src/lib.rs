//! WebAssembly bindings for Postera's Plonky2 prover.
//!
//! This crate provides browser-compatible proof generation for post-quantum
//! shielded transactions. It wraps the Plonky2 prover in wasm-bindgen exports.
//!
//! ## Usage (JavaScript)
//!
//! ```javascript
//! import init, { WasmProver } from 'postera-plonky2-wasm';
//!
//! await init();
//! const prover = new WasmProver();
//!
//! const proof = prover.prove(JSON.stringify({
//!     spends: [...],
//!     outputs: [...],
//!     fee: "1000"
//! }));
//! ```

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

// Type aliases matching the main crate
type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

// Domain separators (must match poseidon_pq.rs)
const DOMAIN_NOTE_COMMIT: u64 = 1;
const DOMAIN_NULLIFIER: u64 = 3;
const DOMAIN_MERKLE_NODE: u64 = 5;

// Merkle tree depth
const TREE_DEPTH: usize = 32;

/// Console logging for debugging
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

/// Input witness for a spend (JSON-serializable).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpendWitnessJs {
    /// Note value as string (for BigInt compatibility)
    pub value: String,
    /// Recipient public key hash (hex)
    pub recipient_pk_hash: String,
    /// Note randomness (hex)
    pub randomness: String,
    /// Nullifier key (hex)
    pub nullifier_key: String,
    /// Position in tree as string
    pub position: String,
    /// Merkle root (hex)
    pub merkle_root: String,
    /// Merkle path siblings (array of hex strings)
    pub merkle_path: Vec<String>,
    /// Path direction bits (0 = left, 1 = right)
    pub path_indices: Vec<u8>,
}

/// Input witness for an output (JSON-serializable).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutputWitnessJs {
    /// Note value as string
    pub value: String,
    /// Recipient public key hash (hex)
    pub recipient_pk_hash: String,
    /// Note randomness (hex)
    pub randomness: String,
}

/// Complete transaction witness (JSON-serializable).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionWitnessJs {
    pub spends: Vec<SpendWitnessJs>,
    pub outputs: Vec<OutputWitnessJs>,
    /// Fee as string
    pub fee: String,
}

/// Proof output (JSON-serializable).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofOutputJs {
    /// Serialized proof bytes (hex)
    pub proof_bytes: String,
    /// Merkle roots from spends (array of hex strings)
    pub merkle_roots: Vec<String>,
    /// Nullifiers (array of hex strings)
    pub nullifiers: Vec<String>,
    /// Note commitments from outputs (array of hex strings)
    pub note_commitments: Vec<String>,
    /// Fee
    pub fee: String,
}

/// Circuit targets for witness assignment.
struct SpendTargets {
    value: Target,
    pk_hash: [Target; 4],
    randomness: [Target; 4],
    nullifier_key: [Target; 4],
    position: Target,
    merkle_path: Vec<[Target; 4]>,
    path_indices: Vec<BoolTarget>,
    merkle_root: [Target; 4],
    nullifier: [Target; 4],
}

struct OutputTargets {
    value: Target,
    pk_hash: [Target; 4],
    randomness: [Target; 4],
    note_commitment: [Target; 4],
}

struct TransactionTargets {
    spends: Vec<SpendTargets>,
    outputs: Vec<OutputTargets>,
    fee: Target,
}

/// WebAssembly prover for Postera transactions.
///
/// This prover generates Plonky2 STARK proofs for shielded transactions.
/// It pre-builds circuits for common transaction shapes to speed up proving.
#[wasm_bindgen]
pub struct WasmProver {
    // Pre-built circuits for common shapes
    circuit_1_1: Option<(CircuitData<F, C, D>, TransactionTargets)>,
    circuit_1_2: Option<(CircuitData<F, C, D>, TransactionTargets)>,
    circuit_2_1: Option<(CircuitData<F, C, D>, TransactionTargets)>,
    circuit_2_2: Option<(CircuitData<F, C, D>, TransactionTargets)>,
}

#[wasm_bindgen]
impl WasmProver {
    /// Create a new prover instance.
    ///
    /// This pre-builds circuits for common transaction shapes.
    /// Call this once and reuse for multiple proofs.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        console_log!("WasmProver: Initializing...");

        Self {
            circuit_1_1: None,
            circuit_1_2: None,
            circuit_2_1: None,
            circuit_2_2: None,
        }
    }

    /// Pre-build a circuit for a specific transaction shape.
    ///
    /// Call this before proving to reduce latency on first proof.
    #[wasm_bindgen]
    pub fn prebuild_circuit(&mut self, num_spends: usize, num_outputs: usize) -> Result<(), JsError> {
        console_log!("WasmProver: Pre-building circuit for {} spends, {} outputs", num_spends, num_outputs);

        let circuit = build_transaction_circuit(num_spends, num_outputs);

        match (num_spends, num_outputs) {
            (1, 1) => self.circuit_1_1 = Some(circuit),
            (1, 2) => self.circuit_1_2 = Some(circuit),
            (2, 1) => self.circuit_2_1 = Some(circuit),
            (2, 2) => self.circuit_2_2 = Some(circuit),
            _ => return Err(JsError::new(&format!(
                "Unsupported transaction shape: {} spends, {} outputs",
                num_spends, num_outputs
            ))),
        }

        console_log!("WasmProver: Circuit pre-built successfully");
        Ok(())
    }

    /// Generate a proof for a transaction.
    ///
    /// # Arguments
    /// * `witness_json` - JSON string containing the transaction witness
    ///
    /// # Returns
    /// * JSON string containing the proof and public inputs
    #[wasm_bindgen]
    pub fn prove(&mut self, witness_json: &str) -> Result<String, JsError> {
        console_log!("WasmProver: Starting proof generation");

        // Parse witness
        let witness: TransactionWitnessJs = serde_json::from_str(witness_json)
            .map_err(|e| JsError::new(&format!("Failed to parse witness: {}", e)))?;

        let num_spends = witness.spends.len();
        let num_outputs = witness.outputs.len();

        console_log!("WasmProver: Transaction has {} spends, {} outputs", num_spends, num_outputs);

        // Get or build circuit
        let (circuit_data, targets) = self.get_or_build_circuit(num_spends, num_outputs)?;

        // Build partial witness
        let mut pw = PartialWitness::new();

        // Set spend witnesses
        for (spend_witness, spend_targets) in witness.spends.iter().zip(targets.spends.iter()) {
            set_spend_witness(&mut pw, spend_witness, spend_targets)?;
        }

        // Set output witnesses
        for (output_witness, output_targets) in witness.outputs.iter().zip(targets.outputs.iter()) {
            set_output_witness(&mut pw, output_witness, output_targets)?;
        }

        // Set fee
        let fee: u64 = witness.fee.parse()
            .map_err(|_| JsError::new("Invalid fee value"))?;
        pw.set_target(targets.fee, F::from_canonical_u64(fee))
            .map_err(|e| JsError::new(&format!("Failed to set fee: {}", e)))?;

        console_log!("WasmProver: Witness assigned, generating proof...");

        // Generate proof
        let proof = circuit_data.prove(pw)
            .map_err(|e| JsError::new(&format!("Proof generation failed: {}", e)))?;

        console_log!("WasmProver: Proof generated successfully");

        // Extract public inputs and serialize
        let output = extract_proof_output(&proof, num_spends, num_outputs, fee);
        let output_json = serde_json::to_string(&output)
            .map_err(|e| JsError::new(&format!("Failed to serialize proof: {}", e)))?;

        Ok(output_json)
    }

    /// Verify a proof.
    ///
    /// # Arguments
    /// * `proof_json` - JSON string containing the proof
    /// * `num_spends` - Number of spends in the transaction
    /// * `num_outputs` - Number of outputs in the transaction
    #[wasm_bindgen]
    pub fn verify(&mut self, proof_json: &str, num_spends: usize, num_outputs: usize) -> Result<bool, JsError> {
        console_log!("WasmProver: Verifying proof");

        let proof_output: ProofOutputJs = serde_json::from_str(proof_json)
            .map_err(|e| JsError::new(&format!("Failed to parse proof: {}", e)))?;

        // Get circuit for verification
        let (circuit_data, _) = self.get_or_build_circuit(num_spends, num_outputs)?;

        // Deserialize proof
        let proof_bytes = hex::decode(&proof_output.proof_bytes)
            .map_err(|e| JsError::new(&format!("Invalid proof hex: {}", e)))?;

        let proof: ProofWithPublicInputs<F, C, D> =
            ProofWithPublicInputs::from_bytes(proof_bytes, &circuit_data.common)
                .map_err(|e| JsError::new(&format!("Failed to deserialize proof: {}", e)))?;

        // Verify
        circuit_data.verify(proof)
            .map_err(|e| JsError::new(&format!("Verification failed: {}", e)))?;

        console_log!("WasmProver: Proof verified successfully");
        Ok(true)
    }

    fn get_or_build_circuit(
        &mut self,
        num_spends: usize,
        num_outputs: usize,
    ) -> Result<&(CircuitData<F, C, D>, TransactionTargets), JsError> {
        // Check if we have a pre-built circuit
        let needs_build = match (num_spends, num_outputs) {
            (1, 1) => self.circuit_1_1.is_none(),
            (1, 2) => self.circuit_1_2.is_none(),
            (2, 1) => self.circuit_2_1.is_none(),
            (2, 2) => self.circuit_2_2.is_none(),
            _ => return Err(JsError::new(&format!(
                "Unsupported transaction shape: {} spends, {} outputs",
                num_spends, num_outputs
            ))),
        };

        if needs_build {
            self.prebuild_circuit(num_spends, num_outputs)?;
        }

        // Return reference to circuit
        match (num_spends, num_outputs) {
            (1, 1) => Ok(self.circuit_1_1.as_ref().unwrap()),
            (1, 2) => Ok(self.circuit_1_2.as_ref().unwrap()),
            (2, 1) => Ok(self.circuit_2_1.as_ref().unwrap()),
            (2, 2) => Ok(self.circuit_2_2.as_ref().unwrap()),
            _ => unreachable!(),
        }
    }
}

impl Default for WasmProver {
    fn default() -> Self {
        Self::new()
    }
}

/// Build a transaction circuit for the given shape.
fn build_transaction_circuit(
    num_spends: usize,
    num_outputs: usize,
) -> (CircuitData<F, C, D>, TransactionTargets) {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let mut spend_targets = Vec::with_capacity(num_spends);
    let mut output_targets = Vec::with_capacity(num_outputs);

    let mut total_input = builder.zero();
    let mut total_output = builder.zero();

    // Build spend circuits
    for _ in 0..num_spends {
        let targets = build_spend_circuit(&mut builder);
        total_input = builder.add(total_input, targets.value);

        // Register public inputs
        for &elem in &targets.merkle_root {
            builder.register_public_input(elem);
        }
        for &elem in &targets.nullifier {
            builder.register_public_input(elem);
        }

        spend_targets.push(targets);
    }

    // Build output circuits
    for _ in 0..num_outputs {
        let targets = build_output_circuit(&mut builder);
        total_output = builder.add(total_output, targets.value);

        // Register public inputs
        for &elem in &targets.note_commitment {
            builder.register_public_input(elem);
        }

        output_targets.push(targets);
    }

    // Fee (public)
    let fee = builder.add_virtual_target();
    builder.register_public_input(fee);

    // Balance constraint: total_input == total_output + fee
    let output_plus_fee = builder.add(total_output, fee);
    builder.connect(total_input, output_plus_fee);

    let circuit_data = builder.build::<C>();

    let targets = TransactionTargets {
        spends: spend_targets,
        outputs: output_targets,
        fee,
    };

    (circuit_data, targets)
}

fn build_spend_circuit(builder: &mut CircuitBuilder<F, D>) -> SpendTargets {
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

    // Public inputs (constrained)
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
    let note_commitment = compute_note_commitment(builder, value, &pk_hash, &randomness);

    // 2. Verify Merkle path
    let computed_root = verify_merkle_path(builder, &note_commitment, &merkle_path, &path_indices);
    for i in 0..4 {
        builder.connect(computed_root[i], merkle_root[i]);
    }

    // 3. Compute nullifier
    let computed_nullifier = compute_nullifier(builder, &nullifier_key, &note_commitment, position);
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

fn build_output_circuit(builder: &mut CircuitBuilder<F, D>) -> OutputTargets {
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

    // Public input (constrained)
    let note_commitment = [
        builder.add_virtual_target(),
        builder.add_virtual_target(),
        builder.add_virtual_target(),
        builder.add_virtual_target(),
    ];

    // Compute and constrain commitment
    let computed = compute_note_commitment(builder, value, &pk_hash, &randomness);
    for i in 0..4 {
        builder.connect(computed[i], note_commitment[i]);
    }

    OutputTargets {
        value,
        pk_hash,
        randomness,
        note_commitment,
    }
}

fn compute_note_commitment(
    builder: &mut CircuitBuilder<F, D>,
    value: Target,
    pk_hash: &[Target; 4],
    randomness: &[Target; 4],
) -> [Target; 4] {
    let domain = builder.constant(F::from_canonical_u64(DOMAIN_NOTE_COMMIT));
    let mut inputs = vec![domain, value];
    inputs.extend_from_slice(pk_hash);
    inputs.extend_from_slice(randomness);
    let hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs);
    hash.elements
}

fn compute_nullifier(
    builder: &mut CircuitBuilder<F, D>,
    nk: &[Target; 4],
    commitment: &[Target; 4],
    position: Target,
) -> [Target; 4] {
    let domain = builder.constant(F::from_canonical_u64(DOMAIN_NULLIFIER));
    let mut inputs = vec![domain];
    inputs.extend_from_slice(nk);
    inputs.extend_from_slice(commitment);
    inputs.push(position);
    let hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs);
    hash.elements
}

fn verify_merkle_path(
    builder: &mut CircuitBuilder<F, D>,
    leaf: &[Target; 4],
    path: &[[Target; 4]],
    indices: &[BoolTarget],
) -> [Target; 4] {
    let domain = builder.constant(F::from_canonical_u64(DOMAIN_MERKLE_NODE));
    let mut current = *leaf;

    for (sibling, is_right) in path.iter().zip(indices.iter()) {
        let mut left = [builder.zero(); 4];
        let mut right = [builder.zero(); 4];

        for i in 0..4 {
            left[i] = builder.select(*is_right, sibling[i], current[i]);
            right[i] = builder.select(*is_right, current[i], sibling[i]);
        }

        let mut inputs = vec![domain];
        inputs.extend_from_slice(&left);
        inputs.extend_from_slice(&right);

        let hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs);
        current = hash.elements;
    }

    current
}

fn set_spend_witness(
    pw: &mut PartialWitness<F>,
    witness: &SpendWitnessJs,
    targets: &SpendTargets,
) -> Result<(), JsError> {
    let map_err = |e: anyhow::Error| JsError::new(&e.to_string());

    // Value
    let value: u64 = witness.value.parse()
        .map_err(|_| JsError::new("Invalid spend value"))?;
    pw.set_target(targets.value, F::from_canonical_u64(value)).map_err(map_err)?;

    // PK hash
    let pk_hash_bytes = hex_to_bytes32(&witness.recipient_pk_hash)?;
    let pk_hash_fields = bytes_to_field_elements(&pk_hash_bytes);
    for (i, &val) in pk_hash_fields.iter().enumerate() {
        pw.set_target(targets.pk_hash[i], val).map_err(map_err)?;
    }

    // Randomness
    let randomness_bytes = hex_to_bytes32(&witness.randomness)?;
    let randomness_fields = bytes_to_field_elements(&randomness_bytes);
    for (i, &val) in randomness_fields.iter().enumerate() {
        pw.set_target(targets.randomness[i], val).map_err(map_err)?;
    }

    // Nullifier key
    let nk_bytes = hex_to_bytes32(&witness.nullifier_key)?;
    let nk_fields = bytes_to_field_elements(&nk_bytes);
    for (i, &val) in nk_fields.iter().enumerate() {
        pw.set_target(targets.nullifier_key[i], val).map_err(map_err)?;
    }

    // Position
    let position: u64 = witness.position.parse()
        .map_err(|_| JsError::new("Invalid position"))?;
    pw.set_target(targets.position, F::from_canonical_u64(position)).map_err(map_err)?;

    // Merkle path
    for (i, sibling_hex) in witness.merkle_path.iter().enumerate() {
        let sibling_bytes = hex_to_bytes32(sibling_hex)?;
        let sibling_fields = bytes_to_field_elements(&sibling_bytes);
        for (j, &val) in sibling_fields.iter().enumerate() {
            pw.set_target(targets.merkle_path[i][j], val).map_err(map_err)?;
        }
    }

    // Path indices
    for (i, &idx) in witness.path_indices.iter().enumerate() {
        pw.set_bool_target(targets.path_indices[i], idx != 0).map_err(map_err)?;
    }

    // Merkle root (public)
    let root_bytes = hex_to_bytes32(&witness.merkle_root)?;
    let root_fields = bytes_to_field_elements(&root_bytes);
    for (i, &val) in root_fields.iter().enumerate() {
        pw.set_target(targets.merkle_root[i], val).map_err(map_err)?;
    }

    // Compute and set nullifier (public)
    // We need to compute it from the witness data
    let nullifier = compute_nullifier_from_witness(witness)?;
    let nf_fields = bytes_to_field_elements(&nullifier);
    for (i, &val) in nf_fields.iter().enumerate() {
        pw.set_target(targets.nullifier[i], val).map_err(map_err)?;
    }

    Ok(())
}

fn set_output_witness(
    pw: &mut PartialWitness<F>,
    witness: &OutputWitnessJs,
    targets: &OutputTargets,
) -> Result<(), JsError> {
    let map_err = |e: anyhow::Error| JsError::new(&e.to_string());

    // Value
    let value: u64 = witness.value.parse()
        .map_err(|_| JsError::new("Invalid output value"))?;
    pw.set_target(targets.value, F::from_canonical_u64(value)).map_err(map_err)?;

    // PK hash
    let pk_hash_bytes = hex_to_bytes32(&witness.recipient_pk_hash)?;
    let pk_hash_fields = bytes_to_field_elements(&pk_hash_bytes);
    for (i, &val) in pk_hash_fields.iter().enumerate() {
        pw.set_target(targets.pk_hash[i], val).map_err(map_err)?;
    }

    // Randomness
    let randomness_bytes = hex_to_bytes32(&witness.randomness)?;
    let randomness_fields = bytes_to_field_elements(&randomness_bytes);
    for (i, &val) in randomness_fields.iter().enumerate() {
        pw.set_target(targets.randomness[i], val).map_err(map_err)?;
    }

    // Compute and set note commitment (public)
    let commitment = compute_commitment_from_witness(witness)?;
    let cm_fields = bytes_to_field_elements(&commitment);
    for (i, &val) in cm_fields.iter().enumerate() {
        pw.set_target(targets.note_commitment[i], val).map_err(map_err)?;
    }

    Ok(())
}

fn extract_proof_output(
    proof: &ProofWithPublicInputs<F, C, D>,
    num_spends: usize,
    num_outputs: usize,
    fee: u64,
) -> ProofOutputJs {
    let proof_bytes = hex::encode(proof.to_bytes());
    let pis = &proof.public_inputs;

    let mut idx = 0;
    let mut merkle_roots = Vec::with_capacity(num_spends);
    let mut nullifiers = Vec::with_capacity(num_spends);

    // Extract spend public inputs
    for _ in 0..num_spends {
        let root = field_elements_to_bytes(&pis[idx..idx + 4]);
        merkle_roots.push(hex::encode(root));
        idx += 4;

        let nf = field_elements_to_bytes(&pis[idx..idx + 4]);
        nullifiers.push(hex::encode(nf));
        idx += 4;
    }

    // Extract output public inputs
    let mut note_commitments = Vec::with_capacity(num_outputs);
    for _ in 0..num_outputs {
        let cm = field_elements_to_bytes(&pis[idx..idx + 4]);
        note_commitments.push(hex::encode(cm));
        idx += 4;
    }

    ProofOutputJs {
        proof_bytes,
        merkle_roots,
        nullifiers,
        note_commitments,
        fee: fee.to_string(),
    }
}

// Helper functions

fn hex_to_bytes32(hex: &str) -> Result<[u8; 32], JsError> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes = hex::decode(hex)
        .map_err(|e| JsError::new(&format!("Invalid hex: {}", e)))?;
    if bytes.len() != 32 {
        return Err(JsError::new(&format!("Expected 32 bytes, got {}", bytes.len())));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn bytes_to_field_elements(bytes: &[u8; 32]) -> [F; 4] {
    let mut result = [F::ZERO; 4];
    for i in 0..4 {
        let mut chunk = [0u8; 8];
        chunk.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        let val = u64::from_le_bytes(chunk);
        result[i] = F::from_noncanonical_u64(val);
    }
    result
}

fn field_elements_to_bytes(fields: &[F]) -> [u8; 32] {
    let mut result = [0u8; 32];
    for (i, &f) in fields.iter().take(4).enumerate() {
        let bytes = f.to_canonical_u64().to_le_bytes();
        result[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
    }
    result
}

/// Compute nullifier from witness (outside circuit for setting public input).
fn compute_nullifier_from_witness(witness: &SpendWitnessJs) -> Result<[u8; 32], JsError> {
    // This computes: Poseidon(DOMAIN_NULLIFIER, nk, commitment, position)
    // We need to first compute the note commitment, then the nullifier

    let value: u64 = witness.value.parse().map_err(|_| JsError::new("Invalid value"))?;
    let pk_hash = hex_to_bytes32(&witness.recipient_pk_hash)?;
    let randomness = hex_to_bytes32(&witness.randomness)?;
    let nk = hex_to_bytes32(&witness.nullifier_key)?;
    let position: u64 = witness.position.parse().map_err(|_| JsError::new("Invalid position"))?;

    // Compute note commitment
    let commitment = native_note_commitment(value, &pk_hash, &randomness);

    // Compute nullifier
    let nullifier = native_nullifier(&nk, &commitment, position);

    Ok(nullifier)
}

/// Compute note commitment from output witness.
fn compute_commitment_from_witness(witness: &OutputWitnessJs) -> Result<[u8; 32], JsError> {
    let value: u64 = witness.value.parse().map_err(|_| JsError::new("Invalid value"))?;
    let pk_hash = hex_to_bytes32(&witness.recipient_pk_hash)?;
    let randomness = hex_to_bytes32(&witness.randomness)?;

    Ok(native_note_commitment(value, &pk_hash, &randomness))
}

/// Native Poseidon hash for computing commitments outside the circuit.
fn native_poseidon(inputs: &[F]) -> [F; 4] {
    use plonky2::hash::hash_types::HashOut;
    use plonky2::hash::poseidon::PoseidonHash;
    use plonky2::plonk::config::Hasher;

    let hash: HashOut<F> = PoseidonHash::hash_no_pad(inputs);
    hash.elements
}

fn native_note_commitment(value: u64, pk_hash: &[u8; 32], randomness: &[u8; 32]) -> [u8; 32] {
    let domain = F::from_canonical_u64(DOMAIN_NOTE_COMMIT);
    let value_f = F::from_canonical_u64(value);
    let pk_fields = bytes_to_field_elements(pk_hash);
    let rand_fields = bytes_to_field_elements(randomness);

    let mut inputs = vec![domain, value_f];
    inputs.extend_from_slice(&pk_fields);
    inputs.extend_from_slice(&rand_fields);

    let hash = native_poseidon(&inputs);
    field_elements_to_bytes(&hash)
}

fn native_nullifier(nk: &[u8; 32], commitment: &[u8; 32], position: u64) -> [u8; 32] {
    let domain = F::from_canonical_u64(DOMAIN_NULLIFIER);
    let nk_fields = bytes_to_field_elements(nk);
    let cm_fields = bytes_to_field_elements(commitment);
    let pos_f = F::from_canonical_u64(position);

    let mut inputs = vec![domain];
    inputs.extend_from_slice(&nk_fields);
    inputs.extend_from_slice(&cm_fields);
    inputs.push(pos_f);

    let hash = native_poseidon(&inputs);
    field_elements_to_bytes(&hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prover_creation() {
        let prover = WasmProver::new();
        assert!(prover.circuit_1_1.is_none());
    }

    #[test]
    fn test_circuit_prebuild() {
        let mut prover = WasmProver::new();
        prover.prebuild_circuit(1, 1).unwrap();
        assert!(prover.circuit_1_1.is_some());
    }

    #[test]
    fn test_bytes_roundtrip() {
        let original = [42u8; 32];
        let fields = bytes_to_field_elements(&original);
        let recovered = field_elements_to_bytes(&fields);
        assert_eq!(original, recovered);
    }
}
