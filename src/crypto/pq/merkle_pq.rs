//! Post-quantum Merkle tree using Poseidon hash over Goldilocks field.
//!
//! This provides the same functionality as the V1 Merkle tree but uses
//! quantum-resistant hash functions.
//!
//! ## Hash Format
//!
//! To match Plonky2's circuit, hashes are 4 Goldilocks field elements (256 bits).
//! This is stored as 32 bytes in serialized form.
//!
//! ## Architecture
//!
//! Uses a sparse HashMap to store only non-empty nodes, giving:
//! - O(1) root lookup
//! - O(depth) append (32 hash operations)
//! - O(depth) witness generation (32 lookups)

use std::collections::{HashMap, VecDeque};

use serde::{Deserialize, Serialize};

use super::commitment_pq::NoteCommitmentPQ;
use super::poseidon_pq::{
    poseidon_pq_hash, bytes_to_hash_out, hash_out_to_bytes,
    DOMAIN_MERKLE_EMPTY_PQ, DOMAIN_MERKLE_NODE_PQ, GoldilocksField, HashOut,
};

/// Depth of the Merkle tree (same as V1 for compatibility).
pub const TREE_DEPTH_PQ: usize = 32;

/// Number of recent roots to keep for anchor validation.
/// Each commitment append creates a new root entry, so the window in blocks
/// is RECENT_ROOTS_COUNT / (avg commitments per block). With ~3 commits/block
/// and 10s blocks, 10_000 roots ≈ 9+ hours of validity.
const RECENT_ROOTS_COUNT: usize = 10_000;

/// Hash type for tree nodes (4 field elements = 256 bits = 32 bytes).
pub type TreeHashPQ = [u8; 32];

/// Internal hash representation (4 field elements).
type InternalHash = HashOut;

/// Precomputed empty hashes at each depth level.
/// EMPTY_HASHES_PQ[0] = hash of empty leaf
/// EMPTY_HASHES_PQ[d] = hash_node(EMPTY_HASHES_PQ[d-1], EMPTY_HASHES_PQ[d-1])
lazy_static::lazy_static! {
    static ref EMPTY_HASHES_PQ: Vec<InternalHash> = {
        let mut hashes = Vec::with_capacity(TREE_DEPTH_PQ + 1);
        // Level 0: empty leaf hash
        hashes.push(poseidon_pq_hash(&[DOMAIN_MERKLE_EMPTY_PQ]));
        // Level d: hash of two empty children at level d-1
        for _ in 1..=TREE_DEPTH_PQ {
            let child = hashes.last().unwrap();
            let mut inputs = vec![DOMAIN_MERKLE_NODE_PQ];
            inputs.extend_from_slice(child);
            inputs.extend_from_slice(child);
            hashes.push(poseidon_pq_hash(&inputs));
        }
        hashes
    };
}

/// Compute the root of an empty tree.
pub fn empty_root_pq() -> TreeHashPQ {
    hash_out_to_bytes(&EMPTY_HASHES_PQ[TREE_DEPTH_PQ])
}

/// Compute a node hash from two children (each 4 field elements).
fn hash_node(left: &InternalHash, right: &InternalHash) -> InternalHash {
    let mut inputs = vec![DOMAIN_MERKLE_NODE_PQ];
    inputs.extend_from_slice(left);
    inputs.extend_from_slice(right);
    poseidon_pq_hash(&inputs)
}

/// A Merkle path proving membership.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerklePathPQ {
    /// Sibling hashes from leaf to root.
    pub siblings: Vec<TreeHashPQ>,
    /// Path indices (0 = left, 1 = right).
    pub indices: Vec<u8>,
}

impl MerklePathPQ {
    /// Verify that this path leads from `leaf` to `root`.
    pub fn verify(&self, leaf: &TreeHashPQ, root: &TreeHashPQ) -> bool {
        if self.siblings.len() != TREE_DEPTH_PQ || self.indices.len() != TREE_DEPTH_PQ {
            return false;
        }

        let mut current = bytes_to_hash_out(leaf);

        for (sibling, &index) in self.siblings.iter().zip(self.indices.iter()) {
            let sibling_hash = bytes_to_hash_out(sibling);
            current = if index == 0 {
                hash_node(&current, &sibling_hash)
            } else {
                hash_node(&sibling_hash, &current)
            };
        }

        hash_out_to_bytes(&current) == *root
    }

    /// Get the path depth.
    pub fn depth(&self) -> usize {
        self.siblings.len()
    }
}

/// Witness for spending a note (Merkle path + position).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleWitnessPQ {
    /// The Merkle path.
    pub path: MerklePathPQ,
    /// Position in the tree.
    pub position: u64,
    /// Root at the time of witness generation.
    pub root: TreeHashPQ,
}

impl MerkleWitnessPQ {
    /// Verify this witness for a given commitment.
    pub fn verify(&self, commitment: &NoteCommitmentPQ) -> bool {
        self.path.verify(&commitment.to_bytes(), &self.root)
    }
}

/// Serializable representation of a hash (4 field elements as u64s).
type SerializableHash = [u64; 4];

fn hash_to_serializable(hash: &InternalHash) -> SerializableHash {
    [hash[0].0, hash[1].0, hash[2].0, hash[3].0]
}

fn serializable_to_hash(s: &SerializableHash) -> InternalHash {
    [
        GoldilocksField(s[0]),
        GoldilocksField(s[1]),
        GoldilocksField(s[2]),
        GoldilocksField(s[3]),
    ]
}

/// Snapshot of the commitment tree state for fast loading.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitmentTreeSnapshot {
    /// Number of leaves in the tree.
    pub size: u64,
    /// Sparse node storage as Vec of ((level, index), hash).
    pub nodes: Vec<((usize, u64), SerializableHash)>,
    /// Recent roots for anchor validation.
    pub recent_roots: Vec<TreeHashPQ>,
    /// Version for future compatibility.
    pub version: u32,
}

/// A commitment tree for storing note commitments.
///
/// Uses a sparse HashMap to store only non-empty nodes:
/// - O(1) root lookup (just read nodes[(TREE_DEPTH, 0)])
/// - O(depth) append (update 32 parent hashes)
/// - O(depth) witness generation (read 32 sibling hashes)
#[derive(Clone, Debug)]
pub struct CommitmentTreePQ {
    /// Number of leaves in the tree.
    size: u64,
    /// Sparse node storage: (level, index) -> hash.
    /// Level 0 = leaves, level TREE_DEPTH_PQ = root.
    /// Only stores nodes that differ from the precomputed empty hash.
    nodes: HashMap<(usize, u64), InternalHash>,
    /// Recent roots for anchor validation.
    recent_roots: VecDeque<TreeHashPQ>,
}

impl Default for CommitmentTreePQ {
    fn default() -> Self {
        Self::new()
    }
}

impl CommitmentTreePQ {
    /// Create a new empty commitment tree.
    pub fn new() -> Self {
        let mut tree = Self {
            size: 0,
            nodes: HashMap::new(),
            recent_roots: VecDeque::with_capacity(RECENT_ROOTS_COUNT),
        };

        // Initialize with empty root
        let empty_root = empty_root_pq();
        tree.recent_roots.push_back(empty_root);

        tree
    }

    /// Get a node from the tree, returning the precomputed empty hash if absent.
    fn get_node(&self, level: usize, index: u64) -> InternalHash {
        self.nodes
            .get(&(level, index))
            .copied()
            .unwrap_or(EMPTY_HASHES_PQ[level])
    }

    /// Set a node in the tree. Removes the entry if it equals the empty hash
    /// to keep storage sparse.
    fn set_node(&mut self, level: usize, index: u64, hash: InternalHash) {
        if hash == EMPTY_HASHES_PQ[level] {
            self.nodes.remove(&(level, index));
        } else {
            self.nodes.insert((level, index), hash);
        }
    }

    /// Get the current root — O(1).
    pub fn root(&self) -> TreeHashPQ {
        hash_out_to_bytes(&self.get_node(TREE_DEPTH_PQ, 0))
    }

    /// Get the empty root (for comparison).
    pub fn empty_root() -> TreeHashPQ {
        empty_root_pq()
    }

    /// Get the number of commitments in the tree.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Check if a root is valid (in recent roots).
    pub fn is_valid_root(&self, root: &TreeHashPQ) -> bool {
        self.recent_roots.contains(root)
    }

    /// Get recent roots.
    pub fn recent_roots(&self) -> &VecDeque<TreeHashPQ> {
        &self.recent_roots
    }

    /// Append a commitment to the tree — O(depth).
    pub fn append(&mut self, commitment: &NoteCommitmentPQ) {
        let leaf = bytes_to_hash_out(&commitment.to_bytes());
        let position = self.size;
        self.size += 1;

        // Set the leaf
        self.set_node(0, position, leaf);

        // Update parent hashes up to the root
        let mut current_index = position;
        for level in 0..TREE_DEPTH_PQ {
            let parent_index = current_index / 2;
            let left = self.get_node(level, parent_index * 2);
            let right = self.get_node(level, parent_index * 2 + 1);
            let parent_hash = hash_node(&left, &right);
            self.set_node(level + 1, parent_index, parent_hash);
            current_index = parent_index;
        }

        // Update recent roots
        let new_root = self.root();
        self.recent_roots.push_back(new_root);
        if self.recent_roots.len() > RECENT_ROOTS_COUNT {
            self.recent_roots.pop_front();
        }
    }

    /// Get a Merkle path for a commitment at the given position — O(depth).
    pub fn get_path(&self, position: u64) -> Option<MerklePathPQ> {
        if position >= self.size {
            return None;
        }

        let mut siblings = Vec::with_capacity(TREE_DEPTH_PQ);
        let mut indices = Vec::with_capacity(TREE_DEPTH_PQ);
        let mut current_index = position;

        for level in 0..TREE_DEPTH_PQ {
            let sibling_index = current_index ^ 1;
            let sibling = self.get_node(level, sibling_index);

            siblings.push(hash_out_to_bytes(&sibling));
            indices.push((current_index & 1) as u8);

            current_index /= 2;
        }

        Some(MerklePathPQ { siblings, indices })
    }

    /// Get a witness for spending a note at the given position.
    pub fn witness(&self, position: u64) -> Option<MerkleWitnessPQ> {
        let path = self.get_path(position)?;
        Some(MerkleWitnessPQ {
            path,
            position,
            root: self.root(),
        })
    }

    /// Create a snapshot of the tree state for persistence.
    pub fn snapshot(&self) -> CommitmentTreeSnapshot {
        CommitmentTreeSnapshot {
            size: self.size,
            nodes: self.nodes
                .iter()
                .map(|(&key, hash)| (key, hash_to_serializable(hash)))
                .collect(),
            recent_roots: self.recent_roots.iter().cloned().collect(),
            version: 2,
        }
    }

    /// Restore tree state from a snapshot.
    pub fn from_snapshot(snapshot: CommitmentTreeSnapshot) -> Self {
        let nodes: HashMap<(usize, u64), InternalHash> = snapshot.nodes
            .iter()
            .map(|&(key, ref hash)| (key, serializable_to_hash(hash)))
            .collect();

        Self {
            size: snapshot.size,
            nodes,
            recent_roots: snapshot.recent_roots.into_iter().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_tree() {
        let tree = CommitmentTreePQ::new();
        assert_eq!(tree.size(), 0);
        assert_eq!(tree.root(), empty_root_pq());
    }

    #[test]
    fn test_single_commitment() {
        let mut tree = CommitmentTreePQ::new();
        let cm = NoteCommitmentPQ::from_bytes([1u8; 32]);

        tree.append(&cm);

        assert_eq!(tree.size(), 1);
        assert_ne!(tree.root(), empty_root_pq());
    }

    #[test]
    fn test_root_changes() {
        let mut tree = CommitmentTreePQ::new();
        let root1 = tree.root();

        tree.append(&NoteCommitmentPQ::from_bytes([1u8; 32]));
        let root2 = tree.root();

        tree.append(&NoteCommitmentPQ::from_bytes([2u8; 32]));
        let root3 = tree.root();

        assert_ne!(root1, root2);
        assert_ne!(root2, root3);
        assert_ne!(root1, root3);
    }

    #[test]
    fn test_valid_anchor() {
        let mut tree = CommitmentTreePQ::new();
        let root_before = tree.root();

        tree.append(&NoteCommitmentPQ::from_bytes([1u8; 32]));
        let root_after = tree.root();

        // Both should be valid
        assert!(tree.is_valid_root(&root_before));
        assert!(tree.is_valid_root(&root_after));

        // Random root should not be valid
        assert!(!tree.is_valid_root(&[99u8; 32]));
    }

    #[test]
    fn test_merkle_path() {
        let mut tree = CommitmentTreePQ::new();
        let cm = NoteCommitmentPQ::from_bytes([1u8; 32]);

        tree.append(&cm);

        let path = tree.get_path(0).expect("Should have path");
        assert_eq!(path.depth(), TREE_DEPTH_PQ);

        // Verify path leads to root
        assert!(path.verify(&cm.to_bytes(), &tree.root()));
    }

    #[test]
    fn test_witness() {
        let mut tree = CommitmentTreePQ::new();
        let cm = NoteCommitmentPQ::from_bytes([1u8; 32]);

        tree.append(&cm);

        let witness = tree.witness(0).expect("Should have witness");
        assert!(witness.verify(&cm));
        assert_eq!(witness.position, 0);
    }

    #[test]
    fn test_multiple_commitments() {
        let mut tree = CommitmentTreePQ::new();

        for i in 0..10 {
            let mut bytes = [0u8; 32];
            bytes[0] = i as u8;
            tree.append(&NoteCommitmentPQ::from_bytes(bytes));
        }

        assert_eq!(tree.size(), 10);

        // Each commitment should have a valid path
        for i in 0..10 {
            let mut bytes = [0u8; 32];
            bytes[0] = i as u8;
            let cm = NoteCommitmentPQ::from_bytes(bytes);

            let witness = tree.witness(i).expect("Should have witness");
            assert!(witness.verify(&cm), "Position {} failed verification", i);
        }
    }
}
