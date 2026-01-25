//! Shielded state model for private transactions.
//!
//! Instead of account balances, we track:
//! - CommitmentTree: All note commitments ever created
//! - NullifierSet: All nullifiers (spent notes)
//!
//! This enables full transaction privacy - no balances are visible on-chain.

use std::collections::HashSet;

use crate::crypto::{
    commitment::NoteCommitment,
    merkle_tree::{CommitmentTree, TreeHash},
    nullifier::Nullifier,
    proof::{
        bytes_to_public_inputs, output_bytes_to_public_inputs, verify_output_proof,
        verify_spend_proof, VerifyingParams,
    },
};

use super::transaction::{CoinbaseTransaction, ShieldedTransaction, TransactionError};

/// The shielded state containing commitment tree and nullifier set.
///
/// This is the privacy-preserving state model. No account balances
/// are stored - only cryptographic commitments and nullifiers.
#[derive(Clone, Debug, Default)]
pub struct ShieldedState {
    /// Tree of all note commitments ever created.
    commitment_tree: CommitmentTree,
    /// Set of all spent nullifiers.
    nullifier_set: HashSet<Nullifier>,
}

impl ShieldedState {
    /// Create a new empty shielded state.
    pub fn new() -> Self {
        Self {
            commitment_tree: CommitmentTree::new(),
            nullifier_set: HashSet::new(),
        }
    }

    /// Get the current commitment tree root.
    pub fn commitment_root(&self) -> TreeHash {
        self.commitment_tree.root()
    }

    /// Get the number of commitments in the tree.
    pub fn commitment_count(&self) -> u64 {
        self.commitment_tree.size()
    }

    /// Get the number of spent nullifiers.
    pub fn nullifier_count(&self) -> usize {
        self.nullifier_set.len()
    }

    /// Check if a nullifier has been spent.
    pub fn is_nullifier_spent(&self, nullifier: &Nullifier) -> bool {
        self.nullifier_set.contains(nullifier)
    }

    /// Check if a root is a valid recent root.
    pub fn is_valid_anchor(&self, anchor: &TreeHash) -> bool {
        self.commitment_tree.is_valid_root(anchor)
    }

    /// Get the commitment tree (for witness generation).
    pub fn commitment_tree(&self) -> &CommitmentTree {
        &self.commitment_tree
    }

    /// Get the nullifier set.
    pub fn nullifier_set(&self) -> &HashSet<Nullifier> {
        &self.nullifier_set
    }

    /// Validate a shielded transaction.
    ///
    /// Checks:
    /// 1. All zk-proofs are valid
    /// 2. All anchors are valid recent roots
    /// 3. No nullifiers are already spent
    /// 4. Binding signature verifies (value balance)
    /// 5. All spend signatures are valid
    pub fn validate_transaction(
        &self,
        tx: &ShieldedTransaction,
        verifying_params: &VerifyingParams,
    ) -> Result<(), StateError> {
        // Must have at least one spend or output
        if tx.spends.is_empty() && tx.outputs.is_empty() {
            return Err(StateError::EmptyTransaction);
        }

        // Validate all spends
        for spend in &tx.spends {
            // Check anchor is valid
            if !self.is_valid_anchor(&spend.anchor) {
                return Err(StateError::InvalidAnchor);
            }

            // Check nullifier not already spent
            if self.is_nullifier_spent(&spend.nullifier) {
                return Err(StateError::NullifierAlreadySpent(spend.nullifier));
            }

            // Verify spend signature
            if !spend.verify_signature().map_err(|_| StateError::InvalidSignature)? {
                return Err(StateError::InvalidSignature);
            }

            // Verify spend proof
            let public_inputs = bytes_to_public_inputs(
                &spend.anchor,
                &spend.nullifier.to_bytes(),
                &spend.value_commitment,
            );
            if !verify_spend_proof(&spend.proof, &public_inputs, verifying_params) {
                return Err(StateError::InvalidProof);
            }
        }

        // Validate all outputs
        for output in &tx.outputs {
            // Verify output proof
            let public_inputs = output_bytes_to_public_inputs(
                &output.note_commitment.to_bytes(),
                &output.value_commitment,
            );
            if !verify_output_proof(&output.proof, &public_inputs, verifying_params) {
                return Err(StateError::InvalidProof);
            }
        }

        // Verify binding signature (proves value balance)
        if !tx.binding_sig.verify(&tx.spends, &tx.outputs, tx.fee) {
            return Err(StateError::InvalidBindingSignature);
        }

        Ok(())
    }

    /// Validate a transaction without proof verification.
    /// Used when proofs have already been verified or for testing.
    pub fn validate_transaction_basic(&self, tx: &ShieldedTransaction) -> Result<(), StateError> {
        // Must have at least one spend or output (or be fee-only)
        if tx.spends.is_empty() && tx.outputs.is_empty() && tx.fee == 0 {
            return Err(StateError::EmptyTransaction);
        }

        // Validate all spends
        for spend in &tx.spends {
            // Check anchor is valid
            if !self.is_valid_anchor(&spend.anchor) {
                return Err(StateError::InvalidAnchor);
            }

            // Check nullifier not already spent
            if self.is_nullifier_spent(&spend.nullifier) {
                return Err(StateError::NullifierAlreadySpent(spend.nullifier));
            }
        }

        Ok(())
    }

    /// Apply a validated transaction to the state.
    ///
    /// This:
    /// 1. Adds all nullifiers to the spent set
    /// 2. Adds all output commitments to the tree
    pub fn apply_transaction(&mut self, tx: &ShieldedTransaction) {
        // Add nullifiers to spent set
        for spend in &tx.spends {
            self.nullifier_set.insert(spend.nullifier);
        }

        // Add output commitments to tree
        for output in &tx.outputs {
            self.commitment_tree.append(&output.note_commitment);
        }
    }

    /// Validate and apply a transaction atomically.
    pub fn validate_and_apply(
        &mut self,
        tx: &ShieldedTransaction,
        verifying_params: &VerifyingParams,
    ) -> Result<(), StateError> {
        self.validate_transaction(tx, verifying_params)?;
        self.apply_transaction(tx);
        Ok(())
    }

    /// Apply a coinbase transaction.
    /// Adds the reward note commitment to the tree.
    pub fn apply_coinbase(&mut self, coinbase: &CoinbaseTransaction) {
        self.commitment_tree.append(&coinbase.note_commitment);
    }

    /// Validate a coinbase transaction.
    pub fn validate_coinbase(
        &self,
        coinbase: &CoinbaseTransaction,
        expected_reward: u64,
        expected_height: u64,
    ) -> Result<(), StateError> {
        if coinbase.reward != expected_reward {
            return Err(StateError::InvalidCoinbaseReward {
                expected: expected_reward,
                got: coinbase.reward,
            });
        }

        if coinbase.height != expected_height {
            return Err(StateError::InvalidCoinbaseHeight {
                expected: expected_height,
                got: coinbase.height,
            });
        }

        Ok(())
    }

    /// Create a snapshot of the current state.
    pub fn snapshot(&self) -> ShieldedState {
        self.clone()
    }

    /// Check if any of the given nullifiers conflict with pending nullifiers.
    /// Used by mempool to detect double-spend attempts.
    pub fn check_nullifier_conflicts(
        &self,
        nullifiers: &[&Nullifier],
        pending: &HashSet<Nullifier>,
    ) -> Option<Nullifier> {
        for nf in nullifiers {
            if self.nullifier_set.contains(*nf) || pending.contains(*nf) {
                return Some(**nf);
            }
        }
        None
    }

    /// Get recent roots for anchor validation.
    pub fn recent_roots(&self) -> &[TreeHash] {
        self.commitment_tree.recent_roots()
    }

    /// Get a Merkle path for a commitment at the given position.
    pub fn get_merkle_path(&self, position: u64) -> Option<crate::crypto::merkle_tree::MerklePath> {
        self.commitment_tree.get_path(position)
    }

    /// Get a commitment witness for spending.
    pub fn get_witness(
        &self,
        position: u64,
    ) -> Option<crate::crypto::merkle_tree::CommitmentWitness> {
        self.commitment_tree.witness(position)
    }
}

/// State errors for shielded transactions.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("Invalid transaction signature")]
    InvalidSignature,

    #[error("Invalid zk-SNARK proof")]
    InvalidProof,

    #[error("Invalid anchor (not a recent root)")]
    InvalidAnchor,

    #[error("Nullifier already spent: {0:?}")]
    NullifierAlreadySpent(Nullifier),

    #[error("Invalid binding signature (value balance incorrect)")]
    InvalidBindingSignature,

    #[error("Transaction has no spends or outputs")]
    EmptyTransaction,

    #[error("Invalid coinbase reward: expected {expected}, got {got}")]
    InvalidCoinbaseReward { expected: u64, got: u64 },

    #[error("Invalid coinbase height: expected {expected}, got {got}")]
    InvalidCoinbaseHeight { expected: u64, got: u64 },

    #[error("Transaction error: {0}")]
    TransactionError(#[from] TransactionError),
}

// ============================================================================
// Legacy State Support (for migration)
// ============================================================================

use std::collections::HashMap;
use crate::crypto::Address;

/// Legacy account for backwards compatibility.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Account {
    pub address: Address,
    pub balance: u64,
    pub nonce: u64,
}

impl Account {
    pub fn new(address: Address) -> Self {
        Self {
            address,
            balance: 0,
            nonce: 0,
        }
    }

    pub fn with_balance(address: Address, balance: u64) -> Self {
        Self {
            address,
            balance,
            nonce: 0,
        }
    }

    pub fn credit(&mut self, amount: u64) {
        self.balance = self.balance.saturating_add(amount);
    }

    pub fn debit(&mut self, amount: u64, fee: u64) -> Result<(), &'static str> {
        let total = amount.saturating_add(fee);
        if self.balance < total {
            return Err("Insufficient balance");
        }
        self.balance -= total;
        self.nonce += 1;
        Ok(())
    }

    pub fn can_afford(&self, amount: u64, fee: u64) -> bool {
        self.balance >= amount.saturating_add(fee)
    }
}

/// Legacy state for backwards compatibility during migration.
#[derive(Clone, Debug, Default)]
pub struct LegacyState {
    accounts: HashMap<Address, Account>,
}

impl LegacyState {
    pub fn new() -> Self {
        Self {
            accounts: HashMap::new(),
        }
    }

    pub fn get_account(&self, address: &Address) -> Account {
        self.accounts
            .get(address)
            .cloned()
            .unwrap_or_else(|| Account::new(*address))
    }

    pub fn get_account_mut(&mut self, address: &Address) -> &mut Account {
        self.accounts
            .entry(*address)
            .or_insert_with(|| Account::new(*address))
    }

    pub fn set_account(&mut self, account: Account) {
        self.accounts.insert(account.address, account);
    }

    pub fn balance(&self, address: &Address) -> u64 {
        self.get_account(address).balance
    }

    pub fn nonce(&self, address: &Address) -> u64 {
        self.get_account(address).nonce
    }

    pub fn accounts(&self) -> impl Iterator<Item = &Account> {
        self.accounts.values()
    }

    pub fn account_count(&self) -> usize {
        self.accounts.len()
    }

    pub fn top_holders(&self, limit: usize) -> Vec<&Account> {
        let mut accounts: Vec<_> = self.accounts.values().collect();
        accounts.sort_by(|a, b| b.balance.cmp(&a.balance));
        accounts.truncate(limit);
        accounts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::commitment::NoteCommitment;
    use crate::crypto::nullifier::Nullifier;

    #[test]
    fn test_empty_shielded_state() {
        let state = ShieldedState::new();

        assert_eq!(state.commitment_count(), 0);
        assert_eq!(state.nullifier_count(), 0);
        assert_eq!(state.commitment_root(), CommitmentTree::empty_root());
    }

    #[test]
    fn test_nullifier_tracking() {
        let mut state = ShieldedState::new();
        let nf = Nullifier([1u8; 32]);

        assert!(!state.is_nullifier_spent(&nf));

        state.nullifier_set.insert(nf);

        assert!(state.is_nullifier_spent(&nf));
    }

    #[test]
    fn test_commitment_tracking() {
        let mut state = ShieldedState::new();
        let cm = NoteCommitment([1u8; 32]);

        let initial_root = state.commitment_root();
        state.commitment_tree.append(&cm);

        assert_eq!(state.commitment_count(), 1);
        assert_ne!(state.commitment_root(), initial_root);
    }

    #[test]
    fn test_anchor_validation() {
        let mut state = ShieldedState::new();

        let root_before = state.commitment_root();
        let cm = NoteCommitment([1u8; 32]);
        state.commitment_tree.append(&cm);
        let root_after = state.commitment_root();

        // Both roots should be valid
        assert!(state.is_valid_anchor(&root_before));
        assert!(state.is_valid_anchor(&root_after));

        // Random root should not be valid
        assert!(!state.is_valid_anchor(&[99u8; 32]));
    }

    #[test]
    fn test_snapshot() {
        let mut state = ShieldedState::new();
        state.nullifier_set.insert(Nullifier([1u8; 32]));

        let snapshot = state.snapshot();

        // Snapshot should have same data
        assert!(snapshot.is_nullifier_spent(&Nullifier([1u8; 32])));

        // Modifying original shouldn't affect snapshot
        state.nullifier_set.insert(Nullifier([2u8; 32]));
        assert!(!snapshot.is_nullifier_spent(&Nullifier([2u8; 32])));
    }

    #[test]
    fn test_nullifier_conflict_detection() {
        let mut state = ShieldedState::new();
        let nf1 = Nullifier([1u8; 32]);
        let nf2 = Nullifier([2u8; 32]);
        let nf3 = Nullifier([3u8; 32]);

        state.nullifier_set.insert(nf1);

        let mut pending = HashSet::new();
        pending.insert(nf2);

        // nf1 is in state
        assert_eq!(
            state.check_nullifier_conflicts(&[&nf1], &pending),
            Some(nf1)
        );

        // nf2 is in pending
        assert_eq!(
            state.check_nullifier_conflicts(&[&nf2], &pending),
            Some(nf2)
        );

        // nf3 has no conflict
        assert_eq!(state.check_nullifier_conflicts(&[&nf3], &pending), None);
    }
}
