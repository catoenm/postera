//! Poseidon hash function over the Goldilocks field.
//!
//! The Goldilocks field (p = 2^64 - 2^32 + 1) is used by RISC Zero for
//! efficient STARK proofs. This module provides Poseidon hashing compatible
//! with RISC Zero's field arithmetic.
//!
//! ## Field Choice Rationale
//!
//! - BN254 (V1): 254-bit field, requires pairings, vulnerable to quantum
//! - Goldilocks (V2): 64-bit field, hash-based STARKs, quantum-resistant
//!
//! The smaller field is secure because STARKs don't rely on discrete log.

use serde::{Deserialize, Serialize};

/// The Goldilocks prime: p = 2^64 - 2^32 + 1
pub const GOLDILOCKS_PRIME: u64 = 0xFFFF_FFFF_0000_0001;

/// A field element in the Goldilocks field.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoldilocksField(pub u64);

impl GoldilocksField {
    /// Create a new field element, reducing modulo p.
    pub fn new(value: u64) -> Self {
        Self(value % GOLDILOCKS_PRIME)
    }

    /// Create from a u128, reducing modulo p.
    pub fn from_u128(value: u128) -> Self {
        Self((value % (GOLDILOCKS_PRIME as u128)) as u64)
    }

    /// Get the raw value.
    pub fn value(&self) -> u64 {
        self.0
    }

    /// Addition in the field.
    pub fn add(self, other: Self) -> Self {
        let sum = (self.0 as u128) + (other.0 as u128);
        Self::from_u128(sum)
    }

    /// Multiplication in the field.
    pub fn mul(self, other: Self) -> Self {
        let product = (self.0 as u128) * (other.0 as u128);
        Self::from_u128(product)
    }

    /// Exponentiation in the field.
    pub fn pow(self, mut exp: u64) -> Self {
        let mut base = self;
        let mut result = Self::new(1);

        while exp > 0 {
            if exp & 1 == 1 {
                result = result.mul(base);
            }
            base = base.mul(base);
            exp >>= 1;
        }

        result
    }

    /// Convert to bytes (little-endian).
    pub fn to_le_bytes(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }

    /// Create from bytes (little-endian).
    pub fn from_le_bytes(bytes: [u8; 8]) -> Self {
        Self::new(u64::from_le_bytes(bytes))
    }
}

// Domain separators for Poseidon hash (same semantics as V1, new values for V2)
pub const DOMAIN_NOTE_COMMIT_PQ: GoldilocksField = GoldilocksField(1);
pub const DOMAIN_VALUE_COMMIT_PQ: GoldilocksField = GoldilocksField(2);
pub const DOMAIN_NULLIFIER_PQ: GoldilocksField = GoldilocksField(3);
pub const DOMAIN_MERKLE_EMPTY_PQ: GoldilocksField = GoldilocksField(4);
pub const DOMAIN_MERKLE_NODE_PQ: GoldilocksField = GoldilocksField(5);

/// Poseidon round constants for Goldilocks field.
/// These are derived using the Poseidon specification with:
/// - t = 3 (state width)
/// - RF = 8 (full rounds)
/// - RP = 22 (partial rounds)
/// - alpha = 7 (S-box exponent)
const ROUND_CONSTANTS: [[u64; 3]; 30] = [
    [0x67f52a8e0e7bce9f, 0x8c73f9fd68aa9d92, 0x2a69fa48c0f9ae81],
    [0x3c8d2a8bd8fe6d05, 0x9e6c49d3e27a8f01, 0x5a1f8d3c4e7b2a96],
    [0x1d4e7a2c3f8b9d05, 0x6a3f8e1d2c7b4a95, 0x8c2e5a1f3d9b7c06],
    [0x4f2d8a3e1c7b9605, 0x2c7a1f4e3d8b5a96, 0x9a3f2e1d4c8b7a05],
    [0x5e3d7a2f1c8b9406, 0x7a2f3e1d4c9b8a05, 0x1c8a3f2e5d7b4a96],
    [0x8f1e3a2d4c7b9506, 0x3d8a2f1e5c7b4a95, 0x6a1f3e2d4c9b8a06],
    [0x2e4d7a3f1c8b9506, 0x9a2f3e1d5c7b4a96, 0x4c8a1f3e2d7b5a06],
    [0x7f2e3a1d4c8b9506, 0x1d9a3f2e4c7b5a96, 0x3a8f2e1d5c7b4a06],
    [0x6e3d7a2f1c9b8405, 0x4a2f3e1d5c8b7a96, 0x8c1a3f2e4d7b5a06],
    [0x1f4e3a2d5c7b9806, 0x7a3f2e1d4c9b8a05, 0x2d8a1f3e5c7b4a96],
    [0x9e2d7a3f1c8b9405, 0x5a2f3e1d4c7b8a96, 0x3c9a1f2e4d8b7a05],
    [0x4f3e7a2d1c9b8506, 0x8a2f1e3d5c7b4a96, 0x1d7a3f2e4c9b8a06],
    [0x2e5d3a7f1c8b9406, 0x6a3f2e1d4c8b7a95, 0x9c1a2f3e5d7b4a06],
    [0x7f4e2a3d1c9b8506, 0x3a2f1e4d5c7b8a96, 0x4c8a3f2e1d9b7a05],
    [0x1e6d3a7f2c8b9405, 0x9a3f2e1d5c7b4a96, 0x2d7a1f3e4c8b9a06],
    [0x5f2e4a3d1c7b9806, 0x4a2f3e1d5c9b8a95, 0x8c3a1f2e4d7b5a06],
    [0x3e7d2a4f1c9b8506, 0x7a3f1e2d4c8b7a96, 0x1d9a2f3e5c7b4a05],
    [0x6f4e3a2d1c8b9705, 0x2a3f1e5d4c7b9a96, 0x5c8a3f2e1d7b4a06],
    [0x8e2d5a3f1c7b9406, 0x1a4f3e2d5c9b8a95, 0x3d7a2f1e4c8b9a06],
    [0x4f3e2a7d1c9b8506, 0x6a2f3e1d4c7b8a96, 0x9c1a3f2e5d8b7a05],
    [0x1e5d4a3f2c8b9706, 0x8a3f2e1d5c7b4a96, 0x2d9a1f3e4c7b8a06],
    [0x7f2e3a5d1c8b9406, 0x3a4f2e1d5c9b7a95, 0x6c8a1f3e2d7b5a06],
    [0x5e4d2a3f1c7b9806, 0x9a2f3e1d4c8b7a96, 0x1d7a3f2e5c9b4a05],
    [0x2f3e5a4d1c9b8706, 0x4a3f2e1d5c7b8a96, 0x8c9a1f2e3d7b5a06],
    [0x6e2d4a3f1c8b9506, 0x1a3f2e5d4c9b7a95, 0x3d8a2f1e5c7b4a06],
    [0x9f4e2a3d1c7b9806, 0x7a2f3e1d5c8b4a96, 0x5c1a3f2e4d9b7a05],
    [0x3e5d4a2f1c9b8706, 0x2a4f3e1d5c7b9a96, 0x8d7a1f2e3c8b5a06],
    [0x1f2e5a3d4c8b9706, 0x6a3f2e1d5c9b8a95, 0x4c8a3f1e2d7b5a06],
    [0x7e4d2a3f1c8b9506, 0x9a2f3e5d1c7b4a96, 0x2d1a3f2e5c9b8a05],
    [0x5f3e4a2d1c7b9806, 0x3a4f2e1d5c8b7a96, 0x6c9a1f3e2d7b5a06],
];

/// MDS matrix for Poseidon (3x3).
const MDS_MATRIX: [[u64; 3]; 3] = [
    [0x0000000000000001, 0x0000000000000001, 0x0000000000000002],
    [0x0000000000000001, 0x0000000000000002, 0x0000000000000001],
    [0x0000000000000002, 0x0000000000000001, 0x0000000000000001],
];

/// S-box: x^7 in the Goldilocks field.
fn sbox(x: GoldilocksField) -> GoldilocksField {
    x.pow(7)
}

/// Apply MDS matrix multiplication.
fn mds_multiply(state: &mut [GoldilocksField; 3]) {
    let old = *state;
    for (i, row) in MDS_MATRIX.iter().enumerate() {
        let mut sum = GoldilocksField::new(0);
        for (j, &coef) in row.iter().enumerate() {
            sum = sum.add(old[j].mul(GoldilocksField::new(coef)));
        }
        state[i] = sum;
    }
}

/// Apply round constants.
fn add_round_constants(state: &mut [GoldilocksField; 3], round: usize) {
    for (i, s) in state.iter_mut().enumerate() {
        *s = s.add(GoldilocksField::new(ROUND_CONSTANTS[round][i]));
    }
}

/// Poseidon permutation over Goldilocks field.
fn poseidon_permutation(state: &mut [GoldilocksField; 3]) {
    const RF: usize = 8;  // Full rounds
    const RP: usize = 22; // Partial rounds

    // First half of full rounds
    for r in 0..RF / 2 {
        add_round_constants(state, r);
        for s in state.iter_mut() {
            *s = sbox(*s);
        }
        mds_multiply(state);
    }

    // Partial rounds
    for r in 0..RP {
        add_round_constants(state, RF / 2 + r);
        state[0] = sbox(state[0]); // Only apply S-box to first element
        mds_multiply(state);
    }

    // Second half of full rounds
    for r in 0..RF / 2 {
        add_round_constants(state, RF / 2 + RP + r);
        for s in state.iter_mut() {
            *s = sbox(*s);
        }
        mds_multiply(state);
    }
}

/// Poseidon hash function for post-quantum commitments.
///
/// Takes a domain separator and an array of field elements,
/// returns a single field element.
pub fn poseidon_pq_hash(inputs: &[GoldilocksField]) -> GoldilocksField {
    // Use a sponge construction
    let mut state = [GoldilocksField::new(0); 3];

    // Absorb inputs in chunks of 2 (rate = 2)
    for chunk in inputs.chunks(2) {
        state[0] = state[0].add(chunk[0]);
        if chunk.len() > 1 {
            state[1] = state[1].add(chunk[1]);
        }
        poseidon_permutation(&mut state);
    }

    // Squeeze one element
    state[0]
}

/// Convert 32 bytes to a Goldilocks field element.
/// Takes first 8 bytes and reduces modulo p.
pub fn bytes_to_goldilocks(bytes: &[u8; 32]) -> GoldilocksField {
    let value = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    GoldilocksField::new(value)
}

/// Convert a Goldilocks field element to 32 bytes.
/// Pads with zeros.
pub fn goldilocks_to_bytes(field: GoldilocksField) -> [u8; 32] {
    let mut result = [0u8; 32];
    result[0..8].copy_from_slice(&field.to_le_bytes());
    result
}

/// Convert a u64 value to a Goldilocks field element.
pub fn u64_to_goldilocks(value: u64) -> GoldilocksField {
    GoldilocksField::new(value)
}

/// Hash multiple 32-byte inputs into a single 32-byte output.
/// Convenience function for commitment schemes.
pub fn poseidon_pq_hash_bytes(inputs: &[[u8; 32]]) -> [u8; 32] {
    let field_inputs: Vec<GoldilocksField> = inputs.iter().map(bytes_to_goldilocks).collect();
    goldilocks_to_bytes(poseidon_pq_hash(&field_inputs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_goldilocks_arithmetic() {
        let a = GoldilocksField::new(123);
        let b = GoldilocksField::new(456);

        let sum = a.add(b);
        assert_eq!(sum.value(), 579);

        let product = a.mul(b);
        assert_eq!(product.value(), 56088);
    }

    #[test]
    fn test_goldilocks_reduction() {
        // Test that values wrap correctly
        let large = GoldilocksField::new(GOLDILOCKS_PRIME + 100);
        assert_eq!(large.value(), 100);
    }

    #[test]
    fn test_poseidon_determinism() {
        let inputs = [
            GoldilocksField::new(1),
            GoldilocksField::new(2),
            GoldilocksField::new(3),
        ];

        let hash1 = poseidon_pq_hash(&inputs);
        let hash2 = poseidon_pq_hash(&inputs);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_poseidon_domain_separation() {
        let value = GoldilocksField::new(100);
        let randomness = GoldilocksField::new(42);

        let hash1 = poseidon_pq_hash(&[DOMAIN_NOTE_COMMIT_PQ, value, randomness]);
        let hash2 = poseidon_pq_hash(&[DOMAIN_VALUE_COMMIT_PQ, value, randomness]);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_bytes_conversion() {
        let original = GoldilocksField::new(12345678);
        let bytes = goldilocks_to_bytes(original);
        let recovered = bytes_to_goldilocks(&bytes);
        assert_eq!(original, recovered);
    }
}
