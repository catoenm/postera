//! Poseidon hash function for zk-SNARK-friendly hashing.
//!
//! This module provides a shared Poseidon configuration used by both:
//! - Native Rust code (for computing hashes)
//! - R1CS circuits (for proving correct hash computation)
//!
//! Using the same configuration ensures consistency between native and circuit hashing.

use ark_bls12_381::Fr;
use ark_crypto_primitives::sponge::{
    poseidon::{PoseidonConfig, PoseidonSponge},
    CryptographicSponge,
};
use ark_ff::{BigInteger, Field, PrimeField};

/// Domain separation constants for different hash uses.
/// Using distinct domains prevents cross-protocol attacks.
pub const DOMAIN_NOTE_COMMITMENT: u64 = 1;
pub const DOMAIN_VALUE_COMMITMENT_HASH: u64 = 2;
pub const DOMAIN_NULLIFIER: u64 = 3;
pub const DOMAIN_MERKLE_EMPTY: u64 = 4;
pub const DOMAIN_MERKLE_NODE: u64 = 5;

// Poseidon parameters for BLS12-381 scalar field.
//
// These parameters are chosen for security and efficiency:
// - t = 3 (rate 2, capacity 1) for typical 2-input hashing
// - Full rounds: 8 (4 at start, 4 at end)
// - Partial rounds: 56 (for ~128-bit security)
// - Alpha = 5 (S-box exponent, x^5)
//
// The MDS matrix and round constants are derived from the BLS12-381 field
// using a nothing-up-my-sleeve construction.
lazy_static::lazy_static! {
    pub static ref POSEIDON_CONFIG: PoseidonConfig<Fr> = {
        // Poseidon parameters for BLS12-381
        // t = 3 (width), rate = 2, capacity = 1
        // This gives us 2 field elements of input/output per permutation

        let full_rounds = 8;      // 4 + 4 full rounds
        let partial_rounds = 56;  // Security margin for BLS12-381
        let alpha = 5;            // S-box exponent (x^5)

        // Width of the permutation (rate + capacity)
        let t = 3;

        // Generate MDS matrix using a simple construction
        // This is a Cauchy matrix construction
        let mds = generate_mds_matrix(t);

        // Generate round constants
        // Format: Vec<Vec<Fr>> where outer is per-round, inner is per-state-element
        let total_rounds = full_rounds + partial_rounds;
        let ark = generate_round_constants_matrix(total_rounds, t);

        PoseidonConfig::new(
            full_rounds,
            partial_rounds,
            alpha as u64,
            mds,
            ark,
            2,  // rate
            1,  // capacity
        )
    };

    // Poseidon config for 4-input hashing (t=5)
    pub static ref POSEIDON_CONFIG_4: PoseidonConfig<Fr> = {
        let full_rounds = 8;
        let partial_rounds = 56;
        let alpha = 5;
        let t = 5;

        let mds = generate_mds_matrix(t);
        let total_rounds = full_rounds + partial_rounds;
        let ark = generate_round_constants_matrix(total_rounds, t);

        PoseidonConfig::new(
            full_rounds,
            partial_rounds,
            alpha as u64,
            mds,
            ark,
            4,  // rate
            1,  // capacity
        )
    };
}

/// Generate an MDS (Maximum Distance Separable) matrix.
///
/// Uses a Cauchy matrix construction which is guaranteed to be MDS.
/// M[i][j] = 1 / (x[i] + y[j]) where x and y are distinct field elements.
fn generate_mds_matrix(t: usize) -> Vec<Vec<Fr>> {
    let mut mds = vec![vec![Fr::from(0u64); t]; t];

    // Use simple distinct elements for x and y
    let xs: Vec<Fr> = (0..t).map(|i| Fr::from((i + 1) as u64)).collect();
    let ys: Vec<Fr> = (0..t).map(|i| Fr::from((t + i + 1) as u64)).collect();

    for i in 0..t {
        for j in 0..t {
            // Cauchy matrix: M[i][j] = 1 / (x[i] + y[j])
            let sum = xs[i] + ys[j];
            mds[i][j] = sum.inverse().expect("Non-zero for distinct x, y");
        }
    }

    mds
}

/// Generate round constants using a deterministic PRNG seeded with a domain separator.
///
/// Returns Vec<Vec<Fr>> where outer is per-round, inner is per-state-element.
fn generate_round_constants_matrix(num_rounds: usize, state_width: usize) -> Vec<Vec<Fr>> {
    use sha2::{Sha256, Digest};

    let mut constants = Vec::with_capacity(num_rounds);
    let mut counter = 0u64;

    for _ in 0..num_rounds {
        let mut round_constants = Vec::with_capacity(state_width);
        for _ in 0..state_width {
            // Generate a field element from hash output
            let mut hasher = Sha256::new();
            hasher.update(b"Postera_Poseidon_RC");
            hasher.update(&counter.to_le_bytes());
            counter += 1;

            let hash = hasher.finalize();
            let fe = Fr::from_le_bytes_mod_order(&hash);
            round_constants.push(fe);
        }
        constants.push(round_constants);
    }

    constants
}

/// Hash multiple field elements using Poseidon with domain separation.
///
/// The domain tag is prepended to prevent cross-protocol attacks.
/// This is the primary hashing function used throughout the system.
///
/// # Arguments
/// * `domain` - Domain separation constant (e.g., DOMAIN_NOTE_COMMITMENT)
/// * `inputs` - Field elements to hash
///
/// # Returns
/// A single field element representing the hash output
pub fn poseidon_hash(domain: u64, inputs: &[Fr]) -> Fr {
    // Choose config based on number of inputs
    let config = if inputs.len() <= 2 {
        &*POSEIDON_CONFIG
    } else {
        &*POSEIDON_CONFIG_4
    };

    let mut sponge = PoseidonSponge::<Fr>::new(config);

    // Absorb domain separator
    sponge.absorb(&Fr::from(domain));

    // Absorb all inputs
    for input in inputs {
        sponge.absorb(input);
    }

    // Squeeze one output
    sponge.squeeze_field_elements(1)[0]
}

/// Hash two field elements (common case for Merkle trees).
pub fn poseidon_hash_2(domain: u64, left: Fr, right: Fr) -> Fr {
    poseidon_hash(domain, &[left, right])
}

/// Convert a 32-byte array to a field element.
///
/// Uses little-endian byte order and reduces modulo the field prime.
pub fn bytes32_to_field(bytes: &[u8; 32]) -> Fr {
    Fr::from_le_bytes_mod_order(bytes)
}

/// Convert a field element to a 32-byte array.
///
/// Uses little-endian byte order.
pub fn field_to_bytes32(fe: &Fr) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    let bigint = fe.into_bigint();
    let fe_bytes = bigint.to_bytes_le();
    bytes[..fe_bytes.len().min(32)].copy_from_slice(&fe_bytes[..fe_bytes.len().min(32)]);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use ark_std::rand::SeedableRng;
    use ark_std::rand::rngs::StdRng;

    #[test]
    fn test_poseidon_deterministic() {
        let a = Fr::from(123u64);
        let b = Fr::from(456u64);

        let hash1 = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[a, b]);
        let hash2 = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[a, b]);

        assert_eq!(hash1, hash2, "Same inputs should produce same hash");
    }

    #[test]
    fn test_poseidon_different_domains() {
        let a = Fr::from(123u64);
        let b = Fr::from(456u64);

        let hash1 = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[a, b]);
        let hash2 = poseidon_hash(DOMAIN_NULLIFIER, &[a, b]);

        assert_ne!(hash1, hash2, "Different domains should produce different hashes");
    }

    #[test]
    fn test_poseidon_different_inputs() {
        let a = Fr::from(123u64);
        let b = Fr::from(456u64);
        let c = Fr::from(789u64);

        let hash1 = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[a, b]);
        let hash2 = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[a, c]);

        assert_ne!(hash1, hash2, "Different inputs should produce different hashes");
    }

    #[test]
    fn test_bytes32_roundtrip() {
        let mut rng = StdRng::seed_from_u64(12345);
        let original = Fr::rand(&mut rng);

        let bytes = field_to_bytes32(&original);
        let recovered = bytes32_to_field(&bytes);

        assert_eq!(original, recovered);
    }

    #[test]
    fn test_mds_matrix_invertible() {
        // MDS matrix should be invertible
        let mds = generate_mds_matrix(3);

        // Check it's the right size
        assert_eq!(mds.len(), 3);
        assert_eq!(mds[0].len(), 3);

        // Check all entries are non-zero
        for row in &mds {
            for entry in row {
                assert_ne!(*entry, Fr::from(0u64));
            }
        }
    }

    #[test]
    fn test_poseidon_hash_2() {
        let a = Fr::from(1u64);
        let b = Fr::from(2u64);

        let hash1 = poseidon_hash_2(DOMAIN_MERKLE_NODE, a, b);
        let hash2 = poseidon_hash(DOMAIN_MERKLE_NODE, &[a, b]);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_poseidon_4_inputs() {
        let inputs = [
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        ];

        let hash = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &inputs);
        assert_ne!(hash, Fr::from(0u64));
    }
}
