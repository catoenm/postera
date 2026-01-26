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

function createPlaceholderProof(): number[] {
  return Array.from(new Uint8Array(192));
}

function createPlaceholderBindingSignature(): string {
  return bytesToHex(new Uint8Array(64));
}

function createPlaceholderValueCommitment(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
}

function toByteArray(bytes: Uint8Array): number[] {
  return Array.from(bytes);
}

export async function createShieldedTransaction(
  params: TransactionParams
): Promise<ShieldedTransaction> {
  const { spendNotes, recipients, fee, secretKey, publicKey, senderPkHash } = params;

  const totalSpend = spendNotes.reduce((sum, n) => sum + n.value, 0n);
  const totalOutput = recipients.reduce((sum, r) => sum + r.amount, 0n);
  const change = totalSpend - totalOutput - fee;

  if (change < 0n) {
    throw new Error(
      `Insufficient funds: spending ${totalSpend}, outputs ${totalOutput}, fee ${fee}`
    );
  }

  const spends: SpendDescription[] = [];
  for (const note of spendNotes) {
    const spend = await createSpendDescription(note, secretKey, publicKey);
    spends.push(spend);
  }

  const outputs: OutputDescription[] = [];
  const viewingKey = deriveViewingKey(secretKey);

  for (const recipient of recipients) {
    const output = createOutputDescription(recipient.pkHash, recipient.amount, viewingKey);
    outputs.push(output);
  }

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

async function createSpendDescription(
  note: WalletNote,
  secretKey: Uint8Array,
  publicKey: Uint8Array
): Promise<SpendDescription> {
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

  const message = new Uint8Array([
    ...hexToBytes(anchor),
    ...nullifierBytes,
    ...hexToBytes(valueCommitment),
  ]);

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

function createOutputDescription(
  recipientPkHashHex: string,
  amount: bigint,
  viewingKey: Uint8Array
): OutputDescription {
  const pkHash = hexToBytes(recipientPkHashHex);
  const randomness = generateRandomness();

  const commitment = computeNoteCommitment(amount, pkHash, randomness);
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
