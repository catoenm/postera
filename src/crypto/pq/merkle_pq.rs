//! Post-quantum Merkle tree using Poseidon hash over Goldilocks field.
//!
//! This provides the same functionality as the V1 Merkle tree but uses
//! quantum-resistant hash functions.

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

use super::commitment_pq::NoteCommitmentPQ;
use super::poseidon_pq::{
    poseidon_pq_hash, bytes_to_goldilocks, goldilocks_to_bytes,
    DOMAIN_MERKLE_EMPTY_PQ, DOMAIN_MERKLE_NODE_PQ, GoldilocksField,
};

/// Depth of the Merkle tree (same as V1 for compatibility).
pub const TREE_DEPTH_PQ: usize = 32;

/// Number of recent roots to keep for anchor validation.
const RECENT_ROOTS_COUNT: usize = 100;

/// Hash type for tree nodes.
pub type TreeHashPQ = [u8; 32];

/// Compute the empty tree hash at a given depth.
/// This is cached for efficiency.
fn empty_hash_at_depth(depth: usize) -> GoldilocksField {
    if depth == 0 {
        // Leaf level: hash of empty commitment
        poseidon_pq_hash(&[DOMAIN_MERKLE_EMPTY_PQ])
    } else {
        // Internal node: hash of two empty children
        let child = empty_hash_at_depth(depth - 1);
        poseidon_pq_hash(&[DOMAIN_MERKLE_NODE_PQ, child, child])
    }
}

/// Compute the root of an empty tree.
pub fn empty_root_pq() -> TreeHashPQ {
    goldilocks_to_bytes(empty_hash_at_depth(TREE_DEPTH_PQ))
}

/// Compute a node hash from two children.
fn hash_node(left: GoldilocksField, right: GoldilocksField) -> GoldilocksField {
    poseidon_pq_hash(&[DOMAIN_MERKLE_NODE_PQ, left, right])
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

        let mut current = bytes_to_goldilocks(leaf);

        for (sibling, &index) in self.siblings.iter().zip(self.indices.iter()) {
            let sibling_fe = bytes_to_goldilocks(sibling);
            current = if index == 0 {
                hash_node(current, sibling_fe)
            } else {
                hash_node(sibling_fe, current)
            };
        }

        goldilocks_to_bytes(current) == *root
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

/// A commitment tree for storing note commitments.
///
/// Uses an incremental Merkle tree structure where:
/// - Leaves are added left-to-right
/// - Only the frontier (rightmost path) is stored in memory
/// - Recent roots are cached for anchor validation
#[derive(Clone, Debug, Default)]
pub struct CommitmentTreePQ {
    /// Number of leaves in the tree.
    size: u64,
    /// Frontier: hashes at each level on the rightmost path.
    /// frontier[0] is the most recent leaf, frontier[31] is the root.
    frontier: Vec<GoldilocksField>,
    /// Recent roots for anchor validation.
    recent_roots: VecDeque<TreeHashPQ>,
    /// All leaves (for witness generation in testing/local mode).
    /// In production, this would be stored externally.
    leaves: Vec<GoldilocksField>,
}

impl CommitmentTreePQ {
    /// Create a new empty commitment tree.
    pub fn new() -> Self {
        let mut tree = Self {
            size: 0,
            frontier: vec![GoldilocksField::new(0); TREE_DEPTH_PQ],
            recent_roots: VecDeque::with_capacity(RECENT_ROOTS_COUNT),
            leaves: Vec::new(),
        };

        // Initialize with empty root
        let empty_root = empty_root_pq();
        tree.recent_roots.push_back(empty_root);

        tree
    }

    /// Get the current root.
    pub fn root(&self) -> TreeHashPQ {
        if self.size == 0 {
            return empty_root_pq();
        }

        // Compute root from frontier
        let mut current = self.frontier[0];
        let mut position = self.size - 1;

        for depth in 0..TREE_DEPTH_PQ {
            let empty = empty_hash_at_depth(depth);
            if position & 1 == 0 {
                // We're on the left, sibling is empty
                current = hash_node(current, empty);
            } else {
                // We're on the right, use frontier
                current = hash_node(self.frontier[depth], current);
            }
            position >>= 1;
        }

        goldilocks_to_bytes(current)
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

    /// Append a commitment to the tree.
    pub fn append(&mut self, commitment: &NoteCommitmentPQ) {
        let leaf = bytes_to_goldilocks(&commitment.to_bytes());
        self.leaves.push(leaf);

        let mut current = leaf;
        let mut position = self.size;

        for depth in 0..TREE_DEPTH_PQ {
            if position & 1 == 0 {
                // This is a left child - save to frontier
                self.frontier[depth] = current;
                break;
            } else {
                // This is a right child - hash with frontier
                current = hash_node(self.frontier[depth], current);
            }
            position >>= 1;
        }

        self.size += 1;

        // Update recent roots
        let new_root = self.root();
        self.recent_roots.push_back(new_root);
        if self.recent_roots.len() > RECENT_ROOTS_COUNT {
            self.recent_roots.pop_front();
        }
    }

    /// Get a Merkle path for a commitment at the given position.
    pub fn get_path(&self, position: u64) -> Option<MerklePathPQ> {
        if position >= self.size {
            return None;
        }

        let mut siblings = Vec::with_capacity(TREE_DEPTH_PQ);
        let mut indices = Vec::with_capacity(TREE_DEPTH_PQ);
        let mut pos = position;

        // Build path from stored leaves
        // This is O(n) but works for testing. Production would use a database.
        let mut level: Vec<GoldilocksField> = self.leaves.clone();

        // Pad to next power of 2 with empty leaves
        let target_size = 1u64 << TREE_DEPTH_PQ;
        while (level.len() as u64) < target_size && level.len() < (1 << 20) {
            // Limit padding for memory
            level.push(empty_hash_at_depth(0));
        }

        for depth in 0..TREE_DEPTH_PQ {
            let sibling_pos = if pos & 1 == 0 { pos + 1 } else { pos - 1 };

            let sibling = if sibling_pos < level.len() as u64 {
                level[sibling_pos as usize]
            } else {
                empty_hash_at_depth(depth)
            };

            siblings.push(goldilocks_to_bytes(sibling));
            indices.push((pos & 1) as u8);

            // Move up the tree
            let mut next_level = Vec::with_capacity(level.len() / 2 + 1);
            for chunk in level.chunks(2) {
                let left = chunk[0];
                let right = if chunk.len() > 1 {
                    chunk[1]
                } else {
                    empty_hash_at_depth(depth)
                };
                next_level.push(hash_node(left, right));
            }
            level = next_level;
            pos >>= 1;
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
            assert!(witness.verify(&cm));
        }
    }
}
