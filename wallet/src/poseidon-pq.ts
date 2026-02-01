/**
 * Poseidon hash implementation over Goldilocks field for post-quantum security.
 *
 * This implementation MUST produce identical results to the Rust PQ implementation.
 * It uses the Goldilocks field (p = 2^64 - 2^32 + 1) which is compatible with
 * RISC Zero's STARK proofs.
 *
 * ## Field Choice Rationale
 *
 * - BN254 (V1): 254-bit field, requires pairings, vulnerable to quantum
 * - Goldilocks (V2): 64-bit field, hash-based STARKs, quantum-resistant
 *
 * The smaller field is secure because STARKs don't rely on discrete log.
 */

// Goldilocks prime: p = 2^64 - 2^32 + 1
export const GOLDILOCKS_PRIME = 0xFFFF_FFFF_0000_0001n;

// Domain separation constants for PQ (V2) - must match Rust
export const DOMAIN_NOTE_COMMIT_PQ = 1n;
export const DOMAIN_VALUE_COMMIT_PQ = 2n;
export const DOMAIN_NULLIFIER_PQ = 3n;
export const DOMAIN_MERKLE_EMPTY_PQ = 4n;
export const DOMAIN_MERKLE_NODE_PQ = 5n;

// Round constants for Poseidon (same as Rust)
const ROUND_CONSTANTS: bigint[][] = [
  [0x67f52a8e0e7bce9fn, 0x8c73f9fd68aa9d92n, 0x2a69fa48c0f9ae81n],
  [0x3c8d2a8bd8fe6d05n, 0x9e6c49d3e27a8f01n, 0x5a1f8d3c4e7b2a96n],
  [0x1d4e7a2c3f8b9d05n, 0x6a3f8e1d2c7b4a95n, 0x8c2e5a1f3d9b7c06n],
  [0x4f2d8a3e1c7b9605n, 0x2c7a1f4e3d8b5a96n, 0x9a3f2e1d4c8b7a05n],
  [0x5e3d7a2f1c8b9406n, 0x7a2f3e1d4c9b8a05n, 0x1c8a3f2e5d7b4a96n],
  [0x8f1e3a2d4c7b9506n, 0x3d8a2f1e5c7b4a95n, 0x6a1f3e2d4c9b8a06n],
  [0x2e4d7a3f1c8b9506n, 0x9a2f3e1d5c7b4a96n, 0x4c8a1f3e2d7b5a06n],
  [0x7f2e3a1d4c8b9506n, 0x1d9a3f2e4c7b5a96n, 0x3a8f2e1d5c7b4a06n],
  [0x6e3d7a2f1c9b8405n, 0x4a2f3e1d5c8b7a96n, 0x8c1a3f2e4d7b5a06n],
  [0x1f4e3a2d5c7b9806n, 0x7a3f2e1d4c9b8a05n, 0x2d8a1f3e5c7b4a96n],
  [0x9e2d7a3f1c8b9405n, 0x5a2f3e1d4c7b8a96n, 0x3c9a1f2e4d8b7a05n],
  [0x4f3e7a2d1c9b8506n, 0x8a2f1e3d5c7b4a96n, 0x1d7a3f2e4c9b8a06n],
  [0x2e5d3a7f1c8b9406n, 0x6a3f2e1d4c8b7a95n, 0x9c1a2f3e5d7b4a06n],
  [0x7f4e2a3d1c9b8506n, 0x3a2f1e4d5c7b8a96n, 0x4c8a3f2e1d9b7a05n],
  [0x1e6d3a7f2c8b9405n, 0x9a3f2e1d5c7b4a96n, 0x2d7a1f3e4c8b9a06n],
  [0x5f2e4a3d1c7b9806n, 0x4a2f3e1d5c9b8a95n, 0x8c3a1f2e4d7b5a06n],
  [0x3e7d2a4f1c9b8506n, 0x7a3f1e2d4c8b7a96n, 0x1d9a2f3e5c7b4a05n],
  [0x6f4e3a2d1c8b9705n, 0x2a3f1e5d4c7b9a96n, 0x5c8a3f2e1d7b4a06n],
  [0x8e2d5a3f1c7b9406n, 0x1a4f3e2d5c9b8a95n, 0x3d7a2f1e4c8b9a06n],
  [0x4f3e2a7d1c9b8506n, 0x6a2f3e1d4c7b8a96n, 0x9c1a3f2e5d8b7a05n],
  [0x1e5d4a3f2c8b9706n, 0x8a3f2e1d5c7b4a96n, 0x2d9a1f3e4c7b8a06n],
  [0x7f2e3a5d1c8b9406n, 0x3a4f2e1d5c9b7a95n, 0x6c8a1f3e2d7b5a06n],
  [0x5e4d2a3f1c7b9806n, 0x9a2f3e1d4c8b7a96n, 0x1d7a3f2e5c9b4a05n],
  [0x2f3e5a4d1c9b8706n, 0x4a3f2e1d5c7b8a96n, 0x8c9a1f2e3d7b5a06n],
  [0x6e2d4a3f1c8b9506n, 0x1a3f2e5d4c9b7a95n, 0x3d8a2f1e5c7b4a06n],
  [0x9f4e2a3d1c7b9806n, 0x7a2f3e1d5c8b4a96n, 0x5c1a3f2e4d9b7a05n],
  [0x3e5d4a2f1c9b8706n, 0x2a4f3e1d5c7b9a96n, 0x8d7a1f2e3c8b5a06n],
  [0x1f2e5a3d4c8b9706n, 0x6a3f2e1d5c9b8a95n, 0x4c8a3f1e2d7b5a06n],
  [0x7e4d2a3f1c8b9506n, 0x9a2f3e5d1c7b4a96n, 0x2d1a3f2e5c9b8a05n],
  [0x5f3e4a2d1c7b9806n, 0x3a4f2e1d5c8b7a96n, 0x6c9a1f3e2d7b5a06n],
];

// MDS matrix
const MDS_MATRIX: bigint[][] = [
  [1n, 1n, 2n],
  [1n, 2n, 1n],
  [2n, 1n, 1n],
];

/**
 * Field addition in Goldilocks.
 */
function fieldAdd(a: bigint, b: bigint): bigint {
  return (a + b) % GOLDILOCKS_PRIME;
}

/**
 * Field multiplication in Goldilocks.
 */
function fieldMul(a: bigint, b: bigint): bigint {
  return (a * b) % GOLDILOCKS_PRIME;
}

/**
 * Field exponentiation in Goldilocks.
 */
function fieldPow(base: bigint, exp: bigint): bigint {
  let result = 1n;
  let b = base % GOLDILOCKS_PRIME;
  let e = exp;

  while (e > 0n) {
    if (e & 1n) {
      result = fieldMul(result, b);
    }
    b = fieldMul(b, b);
    e >>= 1n;
  }

  return result;
}

/**
 * S-box: x^7 in Goldilocks field.
 */
function sbox(x: bigint): bigint {
  return fieldPow(x, 7n);
}

/**
 * Apply MDS matrix multiplication.
 */
function mdsMultiply(state: bigint[]): void {
  const old = [...state];
  for (let i = 0; i < 3; i++) {
    let sum = 0n;
    for (let j = 0; j < 3; j++) {
      sum = fieldAdd(sum, fieldMul(old[j], MDS_MATRIX[i][j]));
    }
    state[i] = sum;
  }
}

/**
 * Add round constants.
 */
function addRoundConstants(state: bigint[], round: number): void {
  for (let i = 0; i < 3; i++) {
    state[i] = fieldAdd(state[i], ROUND_CONSTANTS[round][i] % GOLDILOCKS_PRIME);
  }
}

/**
 * Poseidon permutation over Goldilocks field.
 */
function poseidonPermutation(state: bigint[]): void {
  const RF = 8;  // Full rounds
  const RP = 22; // Partial rounds

  // First half of full rounds
  for (let r = 0; r < RF / 2; r++) {
    addRoundConstants(state, r);
    for (let i = 0; i < 3; i++) {
      state[i] = sbox(state[i]);
    }
    mdsMultiply(state);
  }

  // Partial rounds
  for (let r = 0; r < RP; r++) {
    addRoundConstants(state, RF / 2 + r);
    state[0] = sbox(state[0]); // Only S-box on first element
    mdsMultiply(state);
  }

  // Second half of full rounds
  for (let r = 0; r < RF / 2; r++) {
    addRoundConstants(state, RF / 2 + RP + r);
    for (let i = 0; i < 3; i++) {
      state[i] = sbox(state[i]);
    }
    mdsMultiply(state);
  }
}

/**
 * Poseidon hash function for post-quantum commitments.
 * Uses sponge construction with rate 2.
 */
export function poseidonPQHash(inputs: bigint[]): bigint {
  const state: bigint[] = [0n, 0n, 0n];

  // Absorb inputs in chunks of 2
  for (let i = 0; i < inputs.length; i += 2) {
    state[0] = fieldAdd(state[0], inputs[i] % GOLDILOCKS_PRIME);
    if (i + 1 < inputs.length) {
      state[1] = fieldAdd(state[1], inputs[i + 1] % GOLDILOCKS_PRIME);
    }
    poseidonPermutation(state);
  }

  return state[0];
}

/**
 * Convert 32 bytes to a Goldilocks field element.
 * Takes first 8 bytes and reduces modulo p.
 */
export function bytesToGoldilocks(bytes: Uint8Array): bigint {
  // Take first 8 bytes as little-endian
  let value = 0n;
  for (let i = 7; i >= 0 && i < bytes.length; i--) {
    value = (value << 8n) | BigInt(bytes[i]);
  }
  return value % GOLDILOCKS_PRIME;
}

/**
 * Convert a Goldilocks field element to 32 bytes.
 * Pads with zeros.
 */
export function goldilocksToBytes(field: bigint): Uint8Array {
  const result = new Uint8Array(32);
  let temp = field;
  for (let i = 0; i < 8; i++) {
    result[i] = Number(temp & 0xFFn);
    temp >>= 8n;
  }
  return result;
}

/**
 * Compute a PQ note commitment.
 * cm = Poseidon(DOMAIN_NOTE_COMMIT_PQ, value, pkHash, randomness)
 */
export function noteCommitmentPQ(value: bigint, pkHash: bigint, randomness: bigint): bigint {
  return poseidonPQHash([DOMAIN_NOTE_COMMIT_PQ, value, pkHash, randomness]);
}

/**
 * Compute a PQ value commitment.
 * cm = Poseidon(DOMAIN_VALUE_COMMIT_PQ, value, randomness)
 */
export function valueCommitmentPQ(value: bigint, randomness: bigint): bigint {
  return poseidonPQHash([DOMAIN_VALUE_COMMIT_PQ, value, randomness]);
}

/**
 * Derive a PQ nullifier.
 * nf = Poseidon(DOMAIN_NULLIFIER_PQ, nk, cm, position)
 */
export function deriveNullifierPQ(nullifierKey: bigint, commitment: bigint, position: bigint): bigint {
  return poseidonPQHash([DOMAIN_NULLIFIER_PQ, nullifierKey, commitment, position]);
}

/**
 * Compute a PQ Merkle tree node hash.
 */
export function merkleHashPQ(left: bigint, right: bigint): bigint {
  return poseidonPQHash([DOMAIN_MERKLE_NODE_PQ, left, right]);
}

/**
 * Compute the empty leaf hash for PQ Merkle tree.
 */
export function emptyLeafHashPQ(): bigint {
  return poseidonPQHash([DOMAIN_MERKLE_EMPTY_PQ]);
}

/**
 * Compute Merkle root from leaf and path (PQ version).
 */
export function computeMerkleRootPQ(
  leaf: bigint,
  pathElements: bigint[],
  pathIndices: number[]
): bigint {
  let current = leaf;

  for (let i = 0; i < pathElements.length; i++) {
    const sibling = pathElements[i];
    const isRight = pathIndices[i] === 1;

    if (isRight) {
      current = merkleHashPQ(sibling, current);
    } else {
      current = merkleHashPQ(current, sibling);
    }
  }

  return current;
}

/**
 * Convert a bigint to a 32-byte Uint8Array (little-endian).
 */
export function bigintToBytes32PQ(n: bigint): Uint8Array {
  return goldilocksToBytes(n);
}

/**
 * Convert a 32-byte Uint8Array to a bigint (little-endian).
 */
export function bytes32ToBigintPQ(bytes: Uint8Array): bigint {
  return bytesToGoldilocks(bytes);
}
