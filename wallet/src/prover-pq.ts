/**
 * Plonky2 proof generation for post-quantum transactions.
 *
 * This module provides the interface to Plonky2's STARK-based proving system
 * for V2 transactions. It uses the WASM prover for browser-based proving.
 *
 * ## Architecture
 *
 * The prover generates a combined STARK proof that verifies:
 * 1. All spends are valid (Merkle paths, nullifier derivation)
 * 2. All outputs are valid (commitment formation)
 * 3. Balance constraint: sum(inputs) = sum(outputs) + fee
 *
 * This replaces the individual Groth16 proofs + binding signature from V1.
 *
 * ## Browser Support
 *
 * Plonky2 compiles to WebAssembly, enabling client-side proving in browsers.
 * This is critical for self-custody wallets where users shouldn't need to
 * trust a third-party proving service.
 */

import {
  poseidonPQHash,
  bytesToGoldilocks,
  goldilocksToBytes,
  computeMerkleRootPQ,
  DOMAIN_NOTE_COMMIT_PQ,
  DOMAIN_NULLIFIER_PQ,
} from './poseidon-pq';
import { bytesToHex, hexToBytes } from './crypto';

// @ts-ignore - WASM module is loaded dynamically
import init, { WasmProver } from 'postera-plonky2-wasm';

// Singleton prover instance
let wasmProver: WasmProver | null = null;
let initPromise: Promise<void> | null = null;

// Tree depth (must match Rust)
const TREE_DEPTH = 32;

/**
 * Spend witness for V2 transactions.
 */
export interface SpendWitnessPQ {
  value: bigint;
  recipientPkHash: Uint8Array;
  randomness: Uint8Array;
  nullifierKey: Uint8Array;
  position: bigint;
  merkleRoot: Uint8Array;
  merklePath: Uint8Array[];  // Array of 32-byte siblings
  pathIndices: number[];     // 0 = left, 1 = right
}

/**
 * Output witness for V2 transactions.
 */
export interface OutputWitnessPQ {
  value: bigint;
  recipientPkHash: Uint8Array;
  randomness: Uint8Array;
}

/**
 * Public inputs from a transaction proof.
 */
export interface TransactionPublicInputs {
  merkleRoots: Uint8Array[];
  nullifiers: Uint8Array[];
  noteCommitments: Uint8Array[];
  fee: bigint;
}

/**
 * A Plonky2 proof for a V2 transaction.
 */
export interface Plonky2Proof {
  proofBytes: Uint8Array;
  publicInputs: TransactionPublicInputs;
}

/**
 * Proof generation error.
 */
export class ProofError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ProofError';
  }
}

/**
 * Initialize the WASM prover.
 *
 * Call this once before generating proofs. Multiple calls are safe.
 */
export async function initProver(): Promise<void> {
  if (wasmProver) return;

  if (initPromise) {
    await initPromise;
    return;
  }

  initPromise = (async () => {
    try {
      await init();
      wasmProver = new WasmProver();
      console.log('Plonky2 WASM prover initialized');
    } catch (e) {
      initPromise = null;
      throw new ProofError(`Failed to initialize WASM prover: ${e}`);
    }
  })();

  await initPromise;
}

/**
 * Pre-build a circuit for a specific transaction shape.
 *
 * This reduces latency on the first proof of each shape.
 *
 * @param numSpends - Number of spends in the transaction
 * @param numOutputs - Number of outputs in the transaction
 */
export async function prebuildCircuit(numSpends: number, numOutputs: number): Promise<void> {
  await initProver();
  wasmProver!.prebuild_circuit(numSpends, numOutputs);
}

/**
 * Compute note commitment from witness.
 */
function computeNoteCommitment(
  value: bigint,
  pkHash: Uint8Array,
  randomness: Uint8Array
): bigint {
  const pkHashFe = bytesToGoldilocks(pkHash);
  const randomnessFe = bytesToGoldilocks(randomness);
  return poseidonPQHash([DOMAIN_NOTE_COMMIT_PQ, value, pkHashFe, randomnessFe]);
}

/**
 * Compute nullifier from witness.
 */
function computeNullifier(
  nullifierKey: Uint8Array,
  commitment: bigint,
  position: bigint
): bigint {
  const nkFe = bytesToGoldilocks(nullifierKey);
  return poseidonPQHash([DOMAIN_NULLIFIER_PQ, nkFe, commitment, position]);
}

/**
 * Validate a spend witness locally before proving.
 */
function validateSpendWitness(spend: SpendWitnessPQ): void {
  // Check commitment matches Merkle root via path
  const commitment = computeNoteCommitment(
    spend.value,
    spend.recipientPkHash,
    spend.randomness
  );

  const pathElements = spend.merklePath.map(bytesToGoldilocks);
  const computedRoot = computeMerkleRootPQ(commitment, pathElements, spend.pathIndices);
  const expectedRoot = bytesToGoldilocks(spend.merkleRoot);

  if (computedRoot !== expectedRoot) {
    throw new ProofError('Merkle path does not verify');
  }
}

/**
 * Generate a transaction proof using Plonky2 WASM prover.
 *
 * @param spendWitnesses - Witnesses for all spends
 * @param outputWitnesses - Witnesses for all outputs
 * @param fee - Transaction fee
 * @returns Plonky2 proof with public inputs
 */
export async function generateTransactionProofPQ(
  spendWitnesses: SpendWitnessPQ[],
  outputWitnesses: OutputWitnessPQ[],
  fee: bigint
): Promise<Plonky2Proof> {
  await initProver();

  // 1. Validate balance constraint
  const totalInputs = spendWitnesses.reduce((sum, s) => sum + s.value, 0n);
  const totalOutputs = outputWitnesses.reduce((sum, o) => sum + o.value, 0n);

  if (totalInputs !== totalOutputs + fee) {
    throw new ProofError(
      `Balance mismatch: inputs=${totalInputs}, outputs=${totalOutputs}, fee=${fee}`
    );
  }

  // 2. Validate all spend witnesses locally
  for (let i = 0; i < spendWitnesses.length; i++) {
    try {
      validateSpendWitness(spendWitnesses[i]);
    } catch (e) {
      throw new ProofError(`Spend ${i} invalid: ${e}`);
    }
  }

  // 3. Convert witnesses to JSON for WASM prover
  const witnessJson = JSON.stringify({
    spends: spendWitnesses.map(s => ({
      value: s.value.toString(),
      recipientPkHash: bytesToHex(s.recipientPkHash),
      randomness: bytesToHex(s.randomness),
      nullifierKey: bytesToHex(s.nullifierKey),
      position: s.position.toString(),
      merkleRoot: bytesToHex(s.merkleRoot),
      merklePath: s.merklePath.map(bytesToHex),
      pathIndices: s.pathIndices,
    })),
    outputs: outputWitnesses.map(o => ({
      value: o.value.toString(),
      recipientPkHash: bytesToHex(o.recipientPkHash),
      randomness: bytesToHex(o.randomness),
    })),
    fee: fee.toString(),
  });

  // 4. Generate proof using WASM prover
  console.log('Generating Plonky2 proof...');
  const startTime = Date.now();

  let proofJson: string;
  try {
    proofJson = wasmProver!.prove(witnessJson);
  } catch (e) {
    throw new ProofError(`WASM proof generation failed: ${e}`);
  }

  const elapsed = Date.now() - startTime;
  console.log(`Proof generated in ${elapsed}ms`);

  // 5. Parse proof output
  const proofOutput = JSON.parse(proofJson) as {
    proofBytes: string;
    merkleRoots: string[];
    nullifiers: string[];
    noteCommitments: string[];
    fee: string;
  };

  return {
    proofBytes: hexToBytes(proofOutput.proofBytes),
    publicInputs: {
      merkleRoots: proofOutput.merkleRoots.map(hexToBytes),
      nullifiers: proofOutput.nullifiers.map(hexToBytes),
      noteCommitments: proofOutput.noteCommitments.map(hexToBytes),
      fee: BigInt(proofOutput.fee),
    },
  };
}

/**
 * Verify a Plonky2 proof.
 *
 * @param proof - The proof to verify
 * @param numSpends - Number of spends
 * @param numOutputs - Number of outputs
 * @returns True if valid
 */
export async function verifyProofPQ(
  proof: Plonky2Proof,
  numSpends: number,
  numOutputs: number
): Promise<boolean> {
  await initProver();

  const proofJson = JSON.stringify({
    proofBytes: bytesToHex(proof.proofBytes),
    merkleRoots: proof.publicInputs.merkleRoots.map(bytesToHex),
    nullifiers: proof.publicInputs.nullifiers.map(bytesToHex),
    noteCommitments: proof.publicInputs.noteCommitments.map(bytesToHex),
    fee: proof.publicInputs.fee.toString(),
  });

  try {
    return wasmProver!.verify(proofJson, numSpends, numOutputs);
  } catch (e) {
    throw new ProofError(`Verification failed: ${e}`);
  }
}

/**
 * Get the size of a proof in bytes.
 */
export function getProofSize(proof: Plonky2Proof): number {
  return proof.proofBytes.length;
}

/**
 * Serialize a proof to bytes for network transmission.
 */
export function serializeProof(proof: Plonky2Proof): Uint8Array {
  const json = JSON.stringify({
    proofBytes: bytesToHex(proof.proofBytes),
    publicInputs: {
      merkleRoots: proof.publicInputs.merkleRoots.map(bytesToHex),
      nullifiers: proof.publicInputs.nullifiers.map(bytesToHex),
      noteCommitments: proof.publicInputs.noteCommitments.map(bytesToHex),
      fee: proof.publicInputs.fee.toString(),
    },
  });
  return new TextEncoder().encode(json);
}

/**
 * Deserialize a proof from bytes.
 */
export function deserializeProof(bytes: Uint8Array): Plonky2Proof {
  const json = new TextDecoder().decode(bytes);
  const data = JSON.parse(json) as {
    proofBytes: string;
    publicInputs: {
      merkleRoots: string[];
      nullifiers: string[];
      noteCommitments: string[];
      fee: string;
    };
  };

  return {
    proofBytes: hexToBytes(data.proofBytes),
    publicInputs: {
      merkleRoots: data.publicInputs.merkleRoots.map(hexToBytes),
      nullifiers: data.publicInputs.nullifiers.map(hexToBytes),
      noteCommitments: data.publicInputs.noteCommitments.map(hexToBytes),
      fee: BigInt(data.publicInputs.fee),
    },
  };
}

// Legacy exports for compatibility during migration

/**
 * @deprecated Use Plonky2Proof instead
 */
export interface RiscZeroReceipt {
  receiptBytes: Uint8Array;
  imageId: Uint8Array;
  journal: TransactionJournal;
}

/**
 * @deprecated Use TransactionPublicInputs instead
 */
export interface TransactionJournal {
  merkleRoots: Uint8Array[];
  nullifiers: Uint8Array[];
  noteCommitments: Uint8Array[];
  fee: bigint;
  spendMessages: Uint8Array[];
}

/**
 * @deprecated Use verifyProofPQ instead
 */
export async function verifyReceiptPQ(
  receipt: RiscZeroReceipt,
  _expectedImageId: Uint8Array
): Promise<TransactionJournal> {
  // Legacy compatibility - return journal directly
  return receipt.journal;
}

/**
 * @deprecated Use getProofSize instead
 */
export function getReceiptSize(receipt: RiscZeroReceipt): number {
  return receipt.receiptBytes.length + receipt.imageId.length;
}

/**
 * @deprecated
 */
export function isPlaceholderReceipt(receipt: RiscZeroReceipt): boolean {
  return receipt.imageId.every(b => b === 0);
}

/**
 * @deprecated Use deserializeProof instead
 */
export function deserializeJournal(bytes: Uint8Array): TransactionJournal {
  // Legacy format parsing
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let offset = 0;

  const numRoots = view.getUint32(offset, true);
  offset += 4;
  const merkleRoots: Uint8Array[] = [];
  for (let i = 0; i < numRoots; i++) {
    merkleRoots.push(bytes.slice(offset, offset + 32));
    offset += 32;
  }

  const numNullifiers = view.getUint32(offset, true);
  offset += 4;
  const nullifiers: Uint8Array[] = [];
  for (let i = 0; i < numNullifiers; i++) {
    nullifiers.push(bytes.slice(offset, offset + 32));
    offset += 32;
  }

  const numCommitments = view.getUint32(offset, true);
  offset += 4;
  const noteCommitments: Uint8Array[] = [];
  for (let i = 0; i < numCommitments; i++) {
    noteCommitments.push(bytes.slice(offset, offset + 32));
    offset += 32;
  }

  const fee = view.getBigUint64(offset, true);
  offset += 8;

  const numMessages = view.getUint32(offset, true);
  offset += 4;
  const spendMessages: Uint8Array[] = [];
  for (let i = 0; i < numMessages; i++) {
    spendMessages.push(bytes.slice(offset, offset + 96));
    offset += 96;
  }

  return {
    merkleRoots,
    nullifiers,
    noteCommitments,
    fee,
    spendMessages,
  };
}
