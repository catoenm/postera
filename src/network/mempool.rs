use std::collections::HashMap;

use crate::core::{State, Transaction};

/// The mempool holds pending transactions waiting to be mined.
#[derive(Debug, Default)]
pub struct Mempool {
    transactions: HashMap<[u8; 32], Transaction>,
}

impl Mempool {
    pub fn new() -> Self {
        Self {
            transactions: HashMap::new(),
        }
    }

    /// Add a transaction to the mempool.
    pub fn add(&mut self, tx: Transaction) -> bool {
        let hash = tx.hash();
        if self.transactions.contains_key(&hash) {
            return false;
        }
        self.transactions.insert(hash, tx);
        true
    }

    /// Remove a transaction from the mempool.
    pub fn remove(&mut self, hash: &[u8; 32]) -> Option<Transaction> {
        self.transactions.remove(hash)
    }

    /// Get a transaction by hash.
    pub fn get(&self, hash: &[u8; 32]) -> Option<&Transaction> {
        self.transactions.get(hash)
    }

    /// Check if a transaction is in the mempool.
    pub fn contains(&self, hash: &[u8; 32]) -> bool {
        self.transactions.contains_key(hash)
    }

    /// Get all transactions, sorted by fee (highest first).
    pub fn get_transactions(&self, limit: usize) -> Vec<Transaction> {
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
            self.transactions.remove(hash);
        }
    }

    /// Clear all transactions.
    pub fn clear(&mut self) {
        self.transactions.clear();
    }

    /// Re-validate all transactions against the current chain state.
    /// Returns the number of transactions removed.
    pub fn revalidate(&mut self, state: &State) -> usize {
        let mut invalid_hashes = Vec::new();

        // Check each transaction against current state
        for (hash, tx) in &self.transactions {
            if state.validate_transaction(tx).is_err() {
                invalid_hashes.push(*hash);
            }
        }

        // Remove invalid transactions
        let removed = invalid_hashes.len();
        for hash in invalid_hashes {
            self.transactions.remove(&hash);
        }

        removed
    }

    /// Get all transaction hashes.
    pub fn get_hashes(&self) -> Vec<[u8; 32]> {
        self.transactions.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;

    #[test]
    fn test_mempool_add_and_get() {
        let mut mempool = Mempool::new();

        let sender = KeyPair::generate();
        let receiver = KeyPair::generate();
        let tx = Transaction::create_signed(&sender, receiver.address(), 100, 1, 0);
        let hash = tx.hash();

        assert!(mempool.add(tx));
        assert!(mempool.contains(&hash));
        assert_eq!(mempool.len(), 1);
    }

    #[test]
    fn test_mempool_no_duplicates() {
        let mut mempool = Mempool::new();

        let sender = KeyPair::generate();
        let receiver = KeyPair::generate();
        let tx = Transaction::create_signed(&sender, receiver.address(), 100, 1, 0);

        assert!(mempool.add(tx.clone()));
        assert!(!mempool.add(tx)); // Should fail, duplicate
        assert_eq!(mempool.len(), 1);
    }

    #[test]
    fn test_mempool_sorted_by_fee() {
        let mut mempool = Mempool::new();

        let sender = KeyPair::generate();
        let receiver = KeyPair::generate();

        let tx1 = Transaction::create_signed(&sender, receiver.address(), 100, 1, 0);
        let tx2 = Transaction::create_signed(&sender, receiver.address(), 100, 5, 1);
        let tx3 = Transaction::create_signed(&sender, receiver.address(), 100, 3, 2);

        mempool.add(tx1);
        mempool.add(tx2);
        mempool.add(tx3);

        let txs = mempool.get_transactions(10);
        assert_eq!(txs[0].fee, 5);
        assert_eq!(txs[1].fee, 3);
        assert_eq!(txs[2].fee, 1);
    }
}
