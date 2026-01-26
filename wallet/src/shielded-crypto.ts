/**
 * Shielded cryptographic operations for note encryption/decryption.
 *
 * These functions match the Rust implementation exactly, using the same
 * domain separators and algorithms (BLAKE2s-256 for hashing, ChaCha20-Poly1305 for encryption).
 */

import { blake2s } from '@noble/hashes/blake2.js';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { hexToBytes } from './crypto';

// Note structure: 8 bytes value + 32 bytes pk_hash + 32 bytes randomness = 72 bytes
// Ciphertext: 72 + 16 (poly1305 tag) = 88 bytes

/**
 * Derive a viewing key from the wallet's secret key material.
 * ViewingKey = BLAKE2s("Postera_ViewingKey" || secretBytes)
 */
export function deriveViewingKey(secretBytes: Uint8Array): Uint8Array {
  const input = new Uint8Array([
    ...new TextEncoder().encode('Postera_ViewingKey'),
    ...secretBytes,
  ]);
  return blake2s(input, { dkLen: 32 });
}

/**
 * Derive a nullifier key from the wallet's secret key material.
 * NullifierKey = BLAKE2s("Postera_NullifierKey" || secretBytes)
 *
 * Note: The Rust implementation converts this to a field element (Fr),
 * but for nullifier derivation we use the raw 32 bytes.
 */
export function deriveNullifierKey(secretBytes: Uint8Array): Uint8Array {
  const input = new Uint8Array([
    ...new TextEncoder().encode('Postera_NullifierKey'),
    ...secretBytes,
  ]);
  return blake2s(input, { dkLen: 32 });
}

/**
 * Compute the public key hash for receiving notes.
 * PkHash = BLAKE2s("Postera_PkHash" || publicKey)
 */
export function computePkHash(publicKey: Uint8Array): Uint8Array {
  const input = new Uint8Array([
    ...new TextEncoder().encode('Postera_PkHash'),
    ...publicKey,
  ]);
  return blake2s(input, { dkLen: 32 });
}

/**
 * Derive the encryption key for note decryption/encryption.
 * EncKey = BLAKE2s("Postera_NoteEncryption" || viewingSecret || ephemeralPk)
 */
export function deriveEncryptionKey(viewingSecret: Uint8Array, ephemeralPk: Uint8Array): Uint8Array {
  const input = new Uint8Array([
    ...new TextEncoder().encode('Postera_NoteEncryption'),
    ...viewingSecret,
    ...ephemeralPk,
  ]);
  return blake2s(input, { dkLen: 32 });
}

/**
 * Compute a note commitment.
 * cm = BLAKE2s("Postera_NoteCommitment" || value_le || pk_hash || randomness)
 *
 * The randomness is the first 32 bytes of the Fr field element serialization.
 */
export function computeNoteCommitment(value: bigint, pkHash: Uint8Array, randomness: Uint8Array): Uint8Array {
  // Value as 8-byte little-endian
  const valueBytes = new Uint8Array(8);
  const view = new DataView(valueBytes.buffer);
  view.setBigUint64(0, value, true);

  const input = new Uint8Array([
    ...new TextEncoder().encode('Postera_NoteCommitment'),
    ...valueBytes,
    ...pkHash,
    ...randomness,
  ]);
  return blake2s(input, { dkLen: 32 });
}

/**
 * Derive a nullifier for a note.
 * nf = BLAKE2s("Postera_Nullifier" || nk_bytes || commitment || position_le)
 *
 * Note: The Rust implementation serializes the nullifier key as an Fr field element.
 * We use the raw 32 bytes here.
 */
export function deriveNullifier(nullifierKey: Uint8Array, commitment: Uint8Array, position: bigint): Uint8Array {
  // Position as 8-byte little-endian
  const positionBytes = new Uint8Array(8);
  const view = new DataView(positionBytes.buffer);
  view.setBigUint64(0, position, true);

  const input = new Uint8Array([
    ...new TextEncoder().encode('Postera_Nullifier'),
    ...nullifierKey,
    ...commitment,
    ...positionBytes,
  ]);
  return blake2s(input, { dkLen: 32 });
}

/**
 * Derive an ephemeral "public key" from random bytes.
 * Used for note encryption.
 * EphemeralPk = BLAKE2s("Postera_EphemeralPK" || ephemeralSecret)
 */
export function deriveEphemeralPk(ephemeralSecret: Uint8Array): Uint8Array {
  const input = new Uint8Array([
    ...new TextEncoder().encode('Postera_EphemeralPK'),
    ...ephemeralSecret,
  ]);
  return blake2s(input, { dkLen: 32 });
}

/**
 * Serialized note structure.
 */
export interface SerializedNote {
  value: bigint;
  recipientPkHash: Uint8Array;
  randomness: Uint8Array;
}

/**
 * Serialize a note to bytes.
 * Format: value (8 bytes LE) || pk_hash (32 bytes) || randomness (32 bytes)
 */
export function serializeNote(value: bigint, pkHash: Uint8Array, randomness: Uint8Array): Uint8Array {
  const bytes = new Uint8Array(72);
  const view = new DataView(bytes.buffer);
  view.setBigUint64(0, value, true);
  bytes.set(pkHash, 8);
  bytes.set(randomness, 40);
  return bytes;
}

/**
 * Deserialize a note from bytes.
 */
export function deserializeNote(bytes: Uint8Array): SerializedNote {
  if (bytes.length < 72) {
    throw new Error('Note bytes too short');
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const value = view.getBigUint64(0, true);
  const recipientPkHash = bytes.slice(8, 40);
  const randomness = bytes.slice(40, 72);
  return { value, recipientPkHash, randomness };
}

/**
 * Encrypted note structure.
 */
export interface EncryptedNote {
  ciphertext: Uint8Array;
  ephemeralPk: Uint8Array;
}

/**
 * Encrypt a note so only the recipient can decrypt it.
 * Uses ChaCha20-Poly1305 with:
 * - Key: derived from viewing key and ephemeral public key
 * - Nonce: first 12 bytes of ephemeral public key
 */
export function encryptNote(
  value: bigint,
  pkHash: Uint8Array,
  randomness: Uint8Array,
  viewingKey: Uint8Array
): EncryptedNote {
  // Generate ephemeral randomness
  const ephemeralSecret = new Uint8Array(32);
  crypto.getRandomValues(ephemeralSecret);

  // Derive ephemeral public key
  const ephemeralPk = deriveEphemeralPk(ephemeralSecret);

  // Derive encryption key
  const encryptionKey = deriveEncryptionKey(viewingKey, ephemeralPk);

  // Use first 12 bytes of ephemeral_pk as nonce
  const nonce = ephemeralPk.slice(0, 12);

  // Serialize the note
  const plaintext = serializeNote(value, pkHash, randomness);

  // Encrypt using ChaCha20-Poly1305
  const cipher = chacha20poly1305(encryptionKey, nonce);
  const ciphertext = cipher.encrypt(plaintext);

  return { ciphertext, ephemeralPk };
}

/**
 * Decrypt an encrypted note.
 * Returns null if decryption fails (note wasn't for us).
 */
export function decryptNote(
  encrypted: EncryptedNote,
  viewingKey: Uint8Array
): SerializedNote | null {
  try {
    // Derive encryption key
    const encryptionKey = deriveEncryptionKey(viewingKey, encrypted.ephemeralPk);

    // Use first 12 bytes of ephemeral_pk as nonce
    if (encrypted.ephemeralPk.length < 12) {
      return null;
    }
    const nonce = encrypted.ephemeralPk.slice(0, 12);

    // Decrypt using ChaCha20-Poly1305
    const cipher = chacha20poly1305(encryptionKey, nonce);
    const plaintext = cipher.decrypt(encrypted.ciphertext);

    // Deserialize the note
    return deserializeNote(plaintext);
  } catch {
    // Decryption failed - note wasn't for us
    return null;
  }
}

/**
 * Try to decrypt an encrypted note from hex-encoded data.
 */
export function tryDecryptNoteFromHex(
  ciphertextHex: string,
  ephemeralPkHex: string,
  viewingKey: Uint8Array
): SerializedNote | null {
  const encrypted: EncryptedNote = {
    ciphertext: hexToBytes(ciphertextHex),
    ephemeralPk: hexToBytes(ephemeralPkHex),
  };
  return decryptNote(encrypted, viewingKey);
}

/**
 * Generate random 32 bytes for note randomness.
 */
export function generateRandomness(): Uint8Array {
  const randomness = new Uint8Array(32);
  crypto.getRandomValues(randomness);
  return randomness;
}

/**
 * Check if we can decrypt a note (i.e., it's for our viewing key).
 */
export function canDecryptNote(encrypted: EncryptedNote, viewingKey: Uint8Array): boolean {
  return decryptNote(encrypted, viewingKey) !== null;
}
