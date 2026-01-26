/**
 * Shielded transaction builder.
 *
 * Creates shielded transactions with spends and outputs.
 * Uses placeholder proofs (192 zero bytes) and binding signatures (64 zero bytes).
 */

import {
  computeNoteCommitment,
  encryptNote,
  generateRandomness,
  deriveViewingKey,
} from './shielded-crypto';
import { sign, hexToBytes, bytesToHex } from './crypto';
import { getWitnessByPosition } from './api';
import type { WalletNote, WitnessResponse } from './types';

/**
 * Spend description for a shielded transaction.
 * Fields match the Rust struct serialization format.
 */
export interface SpendDescription {
  anchor: string;           // hex string (uses hex_bytes_32 serde)
  nullifier: number[];      // byte array [u8; 32] (default serde)
  value_commitment: string; // hex string (uses hex_bytes_32 serde)
  proof: number[];          // byte array (default serde for ZkProof)
  signature: string;        // hex string
  public_key: string;       // hex string
}

/**
 * Output description for a shielded transaction.
 */
export interface OutputDescription {
  note_commitment: number[]; // byte array [u8; 32]
  value_commitment: string;  // hex string
  encrypted_note: {
    ciphertext: number[];    // byte array
    ephemeral_pk: number[];  // byte array
  };
  proof: number[];           // byte array
}

/**
 * A complete shielded transaction.
 */
export interface ShieldedTransaction {
  spends: SpendDescription[];
  outputs: OutputDescription[];
  fee: number;
  binding_sig: {
    signature: number[];     // byte array
  };
}

/**
 * Parameters for creating a transaction.
 */
export interface TransactionParams {
  /** Notes to spend */
  spendNotes: WalletNote[];
  /** Recipient outputs: { pkHash, amount } */
  recipients: { pkHash: string; amount: bigint }[];
  /** Transaction fee in smallest units */
  fee: bigint;
  /** Sender's secret key (for signing) */
  secretKey: Uint8Array;
  /** Sender's public key */
  publicKey: Uint8Array;
  /** Sender's pk_hash (for change) */
  senderPkHash: Uint8Array;
}

/**
 * Create a placeholder ZK proof (192 zero bytes).
 */
function createPlaceholderProof(): number[] {
  return Array.from(new Uint8Array(192));
}

/**
 * Create a placeholder binding signature (64 zero bytes).
 */
function createPlaceholderBindingSignature(): number[] {
  return Array.from(new Uint8Array(64));
}

/**
 * Create a random value commitment (32 bytes) as hex string.
 * In a real implementation, this would be a Pedersen commitment.
 */
function createPlaceholderValueCommitment(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
}

/**
 * Convert Uint8Array to number array for JSON serialization.
 */
function toByteArray(bytes: Uint8Array): number[] {
  return Array.from(bytes);
}

/**
 * Build a shielded transaction.
 */
export async function createShieldedTransaction(
  params: TransactionParams
): Promise<ShieldedTransaction> {
  const { spendNotes, recipients, fee, secretKey, publicKey, senderPkHash } = params;

  // Calculate totals
  const totalSpend = spendNotes.reduce((sum, n) => sum + n.value, 0n);
  const totalOutput = recipients.reduce((sum, r) => sum + r.amount, 0n);
  const change = totalSpend - totalOutput - fee;

  if (change < 0n) {
    throw new Error(
      `Insufficient funds: spending ${totalSpend}, outputs ${totalOutput}, fee ${fee}`
    );
  }

  // Create spends
  const spends: SpendDescription[] = [];
  for (const note of spendNotes) {
    const spend = await createSpendDescription(note, secretKey, publicKey);
    spends.push(spend);
  }

  // Create outputs
  const outputs: OutputDescription[] = [];
  const viewingKey = deriveViewingKey(secretKey);

  // Recipient outputs
  for (const recipient of recipients) {
    const output = createOutputDescription(recipient.pkHash, recipient.amount, viewingKey);
    outputs.push(output);
  }

  // Change output (if any)
  if (change > 0n) {
    const changeOutput = createOutputDescription(
      bytesToHex(senderPkHash),
      change,
      viewingKey
    );
    outputs.push(changeOutput);
  }

  return {
    spends,
    outputs,
    fee: Number(fee),
    binding_sig: {
      signature: createPlaceholderBindingSignature(),
    },
  };
}

/**
 * Create a spend description for a note.
 */
async function createSpendDescription(
  note: WalletNote,
  secretKey: Uint8Array,
  publicKey: Uint8Array
): Promise<SpendDescription> {
  // Get witness (Merkle path) for the note by position
  let witness: WitnessResponse;
  try {
    witness = await getWitnessByPosition(note.position);
  } catch (e) {
    throw new Error(`Failed to get witness for position ${note.position}: ${e}`);
  }

  const anchor = witness.root;
  const nullifierHex = note.nullifier!;
  const nullifierBytes = hexToBytes(nullifierHex);
  const valueCommitment = createPlaceholderValueCommitment();

  // Create signing message: anchor || nullifier || value_commitment
  const message = new Uint8Array([
    ...hexToBytes(anchor),
    ...nullifierBytes,
    ...hexToBytes(valueCommitment),
  ]);

  // Sign with ML-DSA-65
  const signature = sign(message, secretKey);

  return {
    anchor,
    nullifier: toByteArray(nullifierBytes),
    value_commitment: valueCommitment,
    proof: createPlaceholderProof(),
    signature: bytesToHex(signature),
    public_key: bytesToHex(publicKey),
  };
}

/**
 * Create an output description.
 */
function createOutputDescription(
  recipientPkHashHex: string,
  amount: bigint,
  viewingKey: Uint8Array
): OutputDescription {
  const pkHash = hexToBytes(recipientPkHashHex);
  const randomness = generateRandomness();

  // Compute note commitment
  const commitment = computeNoteCommitment(amount, pkHash, randomness);

  // Encrypt the note
  const encrypted = encryptNote(amount, pkHash, randomness, viewingKey);

  return {
    note_commitment: toByteArray(commitment),
    value_commitment: createPlaceholderValueCommitment(),
    encrypted_note: {
      ciphertext: toByteArray(encrypted.ciphertext),
      ephemeral_pk: toByteArray(encrypted.ephemeralPk),
    },
    proof: createPlaceholderProof(),
  };
}

/**
 * Estimate the fee for a transaction.
 * Simple estimation based on number of spends and outputs.
 */
export function estimateFee(numSpends: number, numOutputs: number): bigint {
  // Base fee + per-spend + per-output
  const baseFee = 1_000_000n; // 0.001 PSTR
  const perSpend = 500_000n;  // 0.0005 PSTR
  const perOutput = 500_000n; // 0.0005 PSTR

  return baseFee + BigInt(numSpends) * perSpend + BigInt(numOutputs) * perOutput;
}

/**
 * Validate transaction parameters before building.
 */
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

  return null; // Valid
}

/**
 * Format transaction summary for display.
 */
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
