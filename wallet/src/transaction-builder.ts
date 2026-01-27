/**
 * Shielded transaction builder.
 *
 * Creates shielded transactions with spends and outputs.
 * Generates real ZK proofs using snarkjs in the browser.
 */

import {
  computeNoteCommitment,
  encryptNote,
  generateRandomness,
  deriveViewingKey,
} from './shielded-crypto';
import { sign, hexToBytes, bytesToHex } from './crypto';
import { getWitnessByPosition } from './api';
import {
  generateSpendProof,
  generateOutputProof,
  proofToBytes,
  areProvingKeysLoaded,
  type SpendWitness,
  type OutputWitness,
} from './prover';
import {
  bytes32ToBigint,
  bigintToBytes32,
  DOMAIN_VALUE_COMMITMENT_HASH,
  poseidonHash,
} from './poseidon';
import type { WalletNote, WitnessResponse } from './types';

/**
 * Rust serialization format reference:
 *
 * SpendDescription:
 *   - anchor: hex string (hex_bytes_32)
 *   - nullifier: byte array [u8; 32] (default serde for Nullifier)
 *   - value_commitment: hex string (hex_bytes_32)
 *   - proof: byte array (ZkProof uses serialize_bytes)
 *   - signature: hex string (Signature uses serialize_str with hex)
 *   - public_key: hex string (hex_bytes)
 *
 * OutputDescription:
 *   - note_commitment: byte array [u8; 32] (default serde for NoteCommitment)
 *   - value_commitment: hex string (hex_bytes_32)
 *   - encrypted_note: { ciphertext: byte array, ephemeral_pk: byte array }
 *   - proof: byte array (ZkProof)
 *
 * BindingSignature:
 *   - signature: hex string (hex_bytes)
 */

export interface SpendDescription {
  anchor: string;           // hex string
  nullifier: number[];      // byte array [u8; 32]
  value_commitment: string; // hex string
  proof: number[];          // byte array
  signature: string;        // hex string
  public_key: string;       // hex string
}

export interface OutputDescription {
  note_commitment: number[]; // byte array [u8; 32]
  value_commitment: string;  // hex string
  encrypted_note: {
    ciphertext: number[];    // byte array
    ephemeral_pk: number[];  // byte array
  };
  proof: number[];           // byte array
}

export interface ShieldedTransaction {
  spends: SpendDescription[];
  outputs: OutputDescription[];
  fee: number;
  binding_sig: {
    signature: string;       // hex string
  };
}

export interface TransactionParams {
  spendNotes: WalletNote[];
  recipients: { pkHash: string; amount: bigint }[];
  fee: bigint;
  secretKey: Uint8Array;
  publicKey: Uint8Array;
  senderPkHash: Uint8Array;
}

/**
 * Compute a value commitment hash for use in circuits.
 * This is a placeholder - real value commitments use Pedersen.
 */
function computeValueCommitmentHash(value: bigint): bigint {
  // For now, use a simple hash of the value
  // In production, this would be the hash of a Pedersen commitment
  return poseidonHash(DOMAIN_VALUE_COMMITMENT_HASH, [value]);
}

function createPlaceholderBindingSignature(): string {
  return bytesToHex(new Uint8Array(64));
}

function toByteArray(bytes: Uint8Array): number[] {
  return Array.from(bytes);
}

/**
 * Convert path indices from position to binary array (0 = left, 1 = right).
 */
function positionToPathIndices(position: bigint, depth: number): number[] {
  const indices: number[] = [];
  let pos = position;
  for (let i = 0; i < depth; i++) {
    indices.push(Number(pos & 1n));
    pos >>= 1n;
  }
  return indices;
}

export async function createShieldedTransaction(
  params: TransactionParams
): Promise<ShieldedTransaction> {
  const { spendNotes, recipients, fee, secretKey, publicKey, senderPkHash } = params;

  // Check if proving keys are loaded
  if (!areProvingKeysLoaded()) {
    throw new Error('Proving keys not loaded. Call loadProvingKeys() first.');
  }

  const totalSpend = spendNotes.reduce((sum, n) => sum + n.value, 0n);
  const totalOutput = recipients.reduce((sum, r) => sum + r.amount, 0n);
  const change = totalSpend - totalOutput - fee;

  if (change < 0n) {
    throw new Error(
      `Insufficient funds: spending ${totalSpend}, outputs ${totalOutput}, fee ${fee}`
    );
  }

  // Generate spend proofs in parallel
  const spendPromises = spendNotes.map((note) =>
    createSpendDescription(note, secretKey, publicKey)
  );
  const spends = await Promise.all(spendPromises);

  // Generate output proofs
  const outputs: OutputDescription[] = [];
  const viewingKey = deriveViewingKey(secretKey);

  // Build output list (recipients + change)
  const outputParams: { pkHash: string; amount: bigint }[] = [...recipients];
  if (change > 0n) {
    outputParams.push({
      pkHash: bytesToHex(senderPkHash),
      amount: change,
    });
  }

  // Generate output proofs in parallel
  const outputPromises = outputParams.map((output) =>
    createOutputDescription(output.pkHash, output.amount, viewingKey)
  );
  const generatedOutputs = await Promise.all(outputPromises);
  outputs.push(...generatedOutputs);

  return {
    spends,
    outputs,
    fee: Number(fee),
    binding_sig: {
      signature: createPlaceholderBindingSignature(),
    },
  };
}

const TREE_DEPTH = 32;

async function createSpendDescription(
  note: WalletNote,
  secretKey: Uint8Array,
  publicKey: Uint8Array
): Promise<SpendDescription> {
  // Get Merkle witness from server
  let witness: WitnessResponse;
  try {
    witness = await getWitnessByPosition(note.position);
  } catch (e) {
    throw new Error(`Failed to get witness for position ${note.position}: ${e}`);
  }

  const anchor = witness.root;
  const nullifierHex = note.nullifier!;
  const nullifierBytes = hexToBytes(nullifierHex);

  // Compute value commitment hash for the circuit
  const valueCommitmentHashFe = computeValueCommitmentHash(note.value);
  const valueCommitmentHashBytes = bigintToBytes32(valueCommitmentHashFe);
  const valueCommitmentHex = bytesToHex(valueCommitmentHashBytes);

  // Convert note data to field elements for the witness
  const merkleRootFe = bytes32ToBigint(hexToBytes(witness.root));
  const nullifierFe = bytes32ToBigint(nullifierBytes);
  const pkHashFe = bytes32ToBigint(hexToBytes(note.recipientPkHash));
  const randomnessFe = bytes32ToBigint(hexToBytes(note.randomness));

  // Derive nullifier key from secret key
  const { blake2s } = await import('@noble/hashes/blake2.js');
  const nullifierKeyBytes = blake2s(
    new Uint8Array([
      ...new TextEncoder().encode('Postera_NullifierKey'),
      ...secretKey,
    ]),
    { dkLen: 32 }
  );
  const nullifierKeyFe = bytes32ToBigint(nullifierKeyBytes);

  // Pad path elements to TREE_DEPTH
  const pathElements = witness.path.map((p) => bytes32ToBigint(hexToBytes(p)));
  while (pathElements.length < TREE_DEPTH) {
    pathElements.push(0n);
  }

  // Get path indices from position
  const pathIndices = positionToPathIndices(note.position, TREE_DEPTH);

  // Build spend witness for circuit
  const spendWitness: SpendWitness = {
    merkleRoot: merkleRootFe.toString(10),
    nullifier: nullifierFe.toString(10),
    valueCommitmentHash: valueCommitmentHashFe.toString(10),
    value: note.value.toString(10),
    recipientPkHash: pkHashFe.toString(10),
    noteRandomness: randomnessFe.toString(10),
    nullifierKey: nullifierKeyFe.toString(10),
    pathElements: pathElements.map((fe) => fe.toString(10)),
    pathIndices: pathIndices,
    position: note.position.toString(10),
  };

  // DEBUG: Compute note commitment and compare
  const { noteCommitment: computeCommitment } = await import('./poseidon');
  const computedCommitment = computeCommitment(note.value, pkHashFe, randomnessFe);
  const storedCommitment = bytes32ToBigint(hexToBytes(note.commitment));
  console.log('=== SPEND DEBUG ===');
  console.log('Note value:', note.value.toString());
  console.log('pkHashFe:', pkHashFe.toString(16));
  console.log('randomnessFe:', randomnessFe.toString(16));
  console.log('Computed commitment:', computedCommitment.toString(16));
  console.log('Stored commitment:', storedCommitment.toString(16));
  console.log('Commitments match:', computedCommitment === storedCommitment);
  console.log('Merkle root:', merkleRootFe.toString(16));
  console.log('Position:', note.position.toString());
  console.log('Path length:', witness.path.length);
  console.log('===================');

  // Generate ZK proof
  const { proof } = await generateSpendProof(spendWitness);
  const proofBytes = proofToBytes(proof);

  // Sign the spend authorization
  const message = new Uint8Array([
    ...hexToBytes(anchor),
    ...nullifierBytes,
    ...valueCommitmentHashBytes,
  ]);
  const signature = sign(message, secretKey);

  return {
    anchor,
    nullifier: toByteArray(nullifierBytes),
    value_commitment: valueCommitmentHex,
    proof: toByteArray(proofBytes),
    signature: bytesToHex(signature),
    public_key: bytesToHex(publicKey),
  };
}

async function createOutputDescription(
  recipientPkHashHex: string,
  amount: bigint,
  viewingKey: Uint8Array
): Promise<OutputDescription> {
  const pkHash = hexToBytes(recipientPkHashHex);
  const randomness = generateRandomness();

  // Compute note commitment
  const commitment = computeNoteCommitment(amount, pkHash, randomness);
  const noteCommitmentFe = bytes32ToBigint(commitment);

  // Compute value commitment hash for the circuit
  const valueCommitmentHashFe = computeValueCommitmentHash(amount);
  const valueCommitmentHashBytes = bigintToBytes32(valueCommitmentHashFe);
  const valueCommitmentHex = bytesToHex(valueCommitmentHashBytes);

  // Build output witness for circuit
  const outputWitness: OutputWitness = {
    noteCommitment: noteCommitmentFe.toString(10),
    valueCommitmentHash: valueCommitmentHashFe.toString(10),
    value: amount.toString(10),
    recipientPkHash: bytes32ToBigint(pkHash).toString(10),
    noteRandomness: bytes32ToBigint(randomness).toString(10),
  };

  // Generate ZK proof
  const { proof } = await generateOutputProof(outputWitness);
  const proofBytes = proofToBytes(proof);

  // Encrypt note for recipient
  const encrypted = encryptNote(amount, pkHash, randomness, viewingKey);

  return {
    note_commitment: toByteArray(commitment),
    value_commitment: valueCommitmentHex,
    encrypted_note: {
      ciphertext: toByteArray(encrypted.ciphertext),
      ephemeral_pk: toByteArray(encrypted.ephemeralPk),
    },
    proof: toByteArray(proofBytes),
  };
}

export function estimateFee(numSpends: number, numOutputs: number): bigint {
  const baseFee = 1_000_000n;
  const perSpend = 500_000n;
  const perOutput = 500_000n;
  return baseFee + BigInt(numSpends) * perSpend + BigInt(numOutputs) * perOutput;
}

export function validateTransactionParams(params: TransactionParams): string | null {
  const { spendNotes, recipients, fee } = params;

  if (spendNotes.length === 0) {
    return 'No notes to spend';
  }

  if (recipients.length === 0) {
    return 'No recipients specified';
  }

  for (const note of spendNotes) {
    if (note.spent) {
      return `Note at position ${note.position} is already spent`;
    }
    if (!note.nullifier) {
      return `Note at position ${note.position} has no nullifier`;
    }
  }

  for (const recipient of recipients) {
    if (recipient.amount <= 0n) {
      return 'Recipient amount must be positive';
    }
    if (recipient.pkHash.length !== 64) {
      return 'Invalid recipient pk_hash length (expected 64 hex chars)';
    }
  }

  if (fee < 0n) {
    return 'Fee must be non-negative';
  }

  const totalSpend = spendNotes.reduce((sum, n) => sum + n.value, 0n);
  const totalOutput = recipients.reduce((sum, r) => sum + r.amount, 0n);

  if (totalSpend < totalOutput + fee) {
    return `Insufficient funds: have ${totalSpend}, need ${totalOutput + fee}`;
  }

  return null;
}

export function formatTransactionSummary(
  spendNotes: WalletNote[],
  recipients: { pkHash: string; amount: bigint }[],
  fee: bigint
): string {
  const DECIMALS = 9;
  const formatValue = (v: bigint) => {
    const divisor = 10n ** BigInt(DECIMALS);
    const whole = v / divisor;
    const frac = v % divisor;
    const fracStr = frac.toString().padStart(DECIMALS, '0').replace(/0+$/, '');
    return fracStr ? `${whole}.${fracStr}` : whole.toString();
  };

  const totalSpend = spendNotes.reduce((sum, n) => sum + n.value, 0n);
  const totalOutput = recipients.reduce((sum, r) => sum + r.amount, 0n);
  const change = totalSpend - totalOutput - fee;

  let summary = `Spending ${spendNotes.length} note(s) (${formatValue(totalSpend)} PSTR)\n`;
  summary += `Sending to ${recipients.length} recipient(s) (${formatValue(totalOutput)} PSTR)\n`;
  summary += `Fee: ${formatValue(fee)} PSTR\n`;
  if (change > 0n) {
    summary += `Change: ${formatValue(change)} PSTR`;
  }

  return summary;
}

// Re-export prover functions for convenient access
export { loadProvingKeys, areProvingKeysLoaded, setCircuitBasePath } from './prover';
