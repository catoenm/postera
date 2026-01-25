//! Transaction mempool for shielded transactions.

use std::collections::{HashMap, HashSet};

use crate::core::{ShieldedState, ShieldedTransaction};
use crate::crypto::nullifier::Nullifier;

/// The mempool holds pending shielded transactions waiting to be mined.
#[derive(Debug, Default)]
pub struct Mempool {
    /// Pending transactions by hash.
    transactions: HashMap<[u8; 32], ShieldedTransaction>,
    /// Pending nullifiers (to detect double-spends before confirmation).
    pending_nullifiers: HashSet<Nullifier>,
}

impl Mempool {
    pub fn new() -> Self {
        Self {
            transactions: HashMap::new(),
            pending_nullifiers: HashSet::new(),
        }
    }

    /// Add a transaction to the mempool.
    /// Returns false if transaction already exists or would cause double-spend.
    pub fn add(&mut self, tx: ShieldedTransaction) -> bool {
        let hash = tx.hash();
        if self.transactions.contains_key(&hash) {
            return false;
        }

        // Check for nullifier conflicts
        for nullifier in tx.nullifiers() {
            if self.pending_nullifiers.contains(nullifier) {
                return false; // Double-spend attempt
            }
        }

        // Add nullifiers to pending set
        for nullifier in tx.nullifiers() {
            self.pending_nullifiers.insert(*nullifier);
        }

        self.transactions.insert(hash, tx);
        true
    }

    /// Remove a transaction from the mempool.
    pub fn remove(&mut self, hash: &[u8; 32]) -> Option<ShieldedTransaction> {
        if let Some(tx) = self.transactions.remove(hash) {
            // Remove associated nullifiers
            for nullifier in tx.nullifiers() {
                self.pending_nullifiers.remove(nullifier);
            }
            Some(tx)
        } else {
            None
        }
    }

    /// Get a transaction by hash.
    pub fn get(&self, hash: &[u8; 32]) -> Option<&ShieldedTransaction> {
        self.transactions.get(hash)
    }

    /// Check if a transaction is in the mempool.
    pub fn contains(&self, hash: &[u8; 32]) -> bool {
        self.transactions.contains_key(hash)
    }

    /// Check if a nullifier is pending in the mempool.
    pub fn has_pending_nullifier(&self, nullifier: &Nullifier) -> bool {
        self.pending_nullifiers.contains(nullifier)
    }

    /// Get all transactions, sorted by fee (highest first).
    pub fn get_transactions(&self, limit: usize) -> Vec<ShieldedTransaction> {
        let mut txs: Vec<_> = self.transactions.values().cloned().collect();
        txs.sort_by(|a, b| b.fee.cmp(&a.fee));
        txs.truncate(limit);
        txs
    }

    /// Number of transactions in the mempool.
    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    /// Check if the mempool is empty.
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    /// Remove transactions that are now in a block.
    pub fn remove_confirmed(&mut self, tx_hashes: &[[u8; 32]]) {
        for hash in tx_hashes {
            self.remove(hash);
        }
    }

    /// Remove transactions with nullifiers that are now spent on-chain.
    pub fn remove_spent_nullifiers(&mut self, spent_nullifiers: &[Nullifier]) {
        let mut to_remove = Vec::new();

        for (hash, tx) in &self.transactions {
            for nullifier in tx.nullifiers() {
                if spent_nullifiers.contains(nullifier) {
                    to_remove.push(*hash);
                    break;
                }
            }
        }

        for hash in to_remove {
            self.remove(&hash);
        }
    }

    /// Clear all transactions.
    pub fn clear(&mut self) {
        self.transactions.clear();
        self.pending_nullifiers.clear();
    }

    /// Re-validate all transactions against the current chain state.
    /// Returns the number of transactions removed.
    pub fn revalidate(&mut self, state: &ShieldedState) -> usize {
        let mut invalid_hashes = Vec::new();

        for (hash, tx) in &self.transactions {
            // Check anchors are still valid
            for anchor in tx.anchors() {
                if !state.is_valid_anchor(anchor) {
                    invalid_hashes.push(*hash);
                    break;
                }
            }

            // Check nullifiers aren't spent
            for nullifier in tx.nullifiers() {
                if state.is_nullifier_spent(nullifier) {
                    invalid_hashes.push(*hash);
                    break;
                }
            }
        }

        let removed = invalid_hashes.len();
        for hash in invalid_hashes {
            self.remove(&hash);
        }

        removed
    }

    /// Get all transaction hashes.
    pub fn get_hashes(&self) -> Vec<[u8; 32]> {
        self.transactions.keys().cloned().collect()
    }

    /// Get total fees in the mempool.
    pub fn total_fees(&self) -> u64 {
        self.transactions.values().map(|tx| tx.fee).sum()
    }

    /// Get the pending nullifiers set (for conflict checking).
    pub fn pending_nullifiers(&self) -> &HashSet<Nullifier> {
        &self.pending_nullifiers
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::BindingSignature;

    fn dummy_tx(fee: u64) -> ShieldedTransaction {
        ShieldedTransaction::new(vec![], vec![], fee, BindingSignature::new(vec![1; 64]))
    }

    #[test]
    fn test_mempool_add_and_get() {
        let mut mempool = Mempool::new();

        let tx = dummy_tx(10);
        let hash = tx.hash();

        assert!(mempool.add(tx));
        assert!(mempool.contains(&hash));
        assert_eq!(mempool.len(), 1);
    }

    #[test]
    fn test_mempool_no_duplicates() {
        let mut mempool = Mempool::new();

        let tx = dummy_tx(10);
        assert!(mempool.add(tx.clone()));
        assert!(!mempool.add(tx)); // Should fail, duplicate
        assert_eq!(mempool.len(), 1);
    }

    #[test]
    fn test_mempool_sorted_by_fee() {
        let mut mempool = Mempool::new();

        let tx1 = dummy_tx(1);
        let tx2 = dummy_tx(5);
        let tx3 = dummy_tx(3);

        mempool.add(tx1);
        mempool.add(tx2);
        mempool.add(tx3);

        let txs = mempool.get_transactions(10);
        assert_eq!(txs[0].fee, 5);
        assert_eq!(txs[1].fee, 3);
        assert_eq!(txs[2].fee, 1);
    }

    #[test]
    fn test_mempool_total_fees() {
        let mut mempool = Mempool::new();

        mempool.add(dummy_tx(10));
        mempool.add(dummy_tx(20));
        mempool.add(dummy_tx(30));

        assert_eq!(mempool.total_fees(), 60);
    }
}
