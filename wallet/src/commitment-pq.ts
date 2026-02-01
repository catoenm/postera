/**
 * Hash-based commitments for post-quantum security.
 *
 * This module provides quantum-resistant commitment schemes using
 * Poseidon hash over the Goldilocks field, replacing the BN254-based
 * Pedersen commitments used in V1.
 *
 * ## Security Model
 *
 * Hash-based commitments provide:
 * - **Hiding**: Cannot determine committed value from commitment (randomness)
 * - **Binding**: Cannot find two values with same commitment (collision resistance)
 *
 * Unlike Pedersen commitments, these are NOT homomorphic.
 * Balance verification happens inside the STARK proof instead.
 */

import {
  poseidonPQHash,
  bytesToGoldilocks,
  goldilocksToBytes,
  DOMAIN_NOTE_COMMIT_PQ,
  DOMAIN_VALUE_COMMIT_PQ,
  DOMAIN_NULLIFIER_PQ,
} from './poseidon-pq';
import { hexToBytes, bytesToHex } from './crypto';

/**
 * A hash-based value commitment (post-quantum secure).
 */
export interface ValueCommitmentPQ {
  commitment: Uint8Array;
}

/**
 * A hash-based note commitment (post-quantum secure).
 */
export interface NoteCommitmentPQ {
  commitment: Uint8Array;
}

/**
 * Compute a value commitment using Poseidon hash.
 *
 * @param value - The value to commit to
 * @param randomness - 32 bytes of randomness
 * @returns The commitment
 */
export function commitToValuePQ(value: bigint, randomness: Uint8Array): Uint8Array {
  if (randomness.length !== 32) {
    throw new Error('Randomness must be 32 bytes');
  }

  const randomnessFe = bytesToGoldilocks(randomness);
  const hash = poseidonPQHash([DOMAIN_VALUE_COMMIT_PQ, value, randomnessFe]);

  return goldilocksToBytes(hash);
}

/**
 * Compute a note commitment using Poseidon hash.
 *
 * @param value - The note value
 * @param pkHash - Recipient public key hash (32 bytes)
 * @param randomness - Note randomness (32 bytes)
 * @returns The commitment
 */
export function commitToNotePQ(
  value: bigint,
  pkHash: Uint8Array,
  randomness: Uint8Array
): Uint8Array {
  if (pkHash.length !== 32) {
    throw new Error('pkHash must be 32 bytes');
  }
  if (randomness.length !== 32) {
    throw new Error('Randomness must be 32 bytes');
  }

  const pkHashFe = bytesToGoldilocks(pkHash);
  const randomnessFe = bytesToGoldilocks(randomness);
  const hash = poseidonPQHash([DOMAIN_NOTE_COMMIT_PQ, value, pkHashFe, randomnessFe]);

  return goldilocksToBytes(hash);
}

/**
 * Derive a nullifier for a note (PQ version).
 *
 * @param nullifierKey - The nullifier key (32 bytes)
 * @param commitment - The note commitment (32 bytes)
 * @param position - Position in the commitment tree
 * @returns The nullifier (32 bytes)
 */
export function deriveNullifierPQ(
  nullifierKey: Uint8Array,
  commitment: Uint8Array,
  position: bigint
): Uint8Array {
  if (nullifierKey.length !== 32) {
    throw new Error('nullifierKey must be 32 bytes');
  }
  if (commitment.length !== 32) {
    throw new Error('commitment must be 32 bytes');
  }

  const nkFe = bytesToGoldilocks(nullifierKey);
  const cmFe = bytesToGoldilocks(commitment);
  const hash = poseidonPQHash([DOMAIN_NULLIFIER_PQ, nkFe, cmFe, position]);

  return goldilocksToBytes(hash);
}

/**
 * Verify a value commitment.
 *
 * @param commitment - The commitment to verify
 * @param value - The claimed value
 * @param randomness - The claimed randomness
 * @returns True if the commitment is valid
 */
export function verifyValueCommitmentPQ(
  commitment: Uint8Array,
  value: bigint,
  randomness: Uint8Array
): boolean {
  const expected = commitToValuePQ(value, randomness);
  return arraysEqual(commitment, expected);
}

/**
 * Verify a note commitment.
 *
 * @param commitment - The commitment to verify
 * @param value - The claimed value
 * @param pkHash - The claimed recipient pk hash
 * @param randomness - The claimed randomness
 * @returns True if the commitment is valid
 */
export function verifyNoteCommitmentPQ(
  commitment: Uint8Array,
  value: bigint,
  pkHash: Uint8Array,
  randomness: Uint8Array
): boolean {
  const expected = commitToNotePQ(value, pkHash, randomness);
  return arraysEqual(commitment, expected);
}

/**
 * Generate random 32 bytes for commitment randomness.
 */
export function generateRandomnessPQ(): Uint8Array {
  const randomness = new Uint8Array(32);
  crypto.getRandomValues(randomness);
  return randomness;
}

/**
 * Convenience function: commit to value and return hex string.
 */
export function commitToValuePQHex(value: bigint, randomnessHex: string): string {
  const randomness = hexToBytes(randomnessHex);
  const commitment = commitToValuePQ(value, randomness);
  return bytesToHex(commitment);
}

/**
 * Convenience function: commit to note and return hex string.
 */
export function commitToNotePQHex(
  value: bigint,
  pkHashHex: string,
  randomnessHex: string
): string {
  const pkHash = hexToBytes(pkHashHex);
  const randomness = hexToBytes(randomnessHex);
  const commitment = commitToNotePQ(value, pkHash, randomness);
  return bytesToHex(commitment);
}

/**
 * Convenience function: derive nullifier and return hex string.
 */
export function deriveNullifierPQHex(
  nullifierKeyHex: string,
  commitmentHex: string,
  position: bigint
): string {
  const nullifierKey = hexToBytes(nullifierKeyHex);
  const commitment = hexToBytes(commitmentHex);
  const nullifier = deriveNullifierPQ(nullifierKey, commitment, position);
  return bytesToHex(nullifier);
}

/**
 * Helper function to compare two Uint8Arrays.
 */
function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
