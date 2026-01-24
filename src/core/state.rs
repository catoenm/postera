use std::collections::HashMap;

use crate::crypto::Address;

use super::{Account, Transaction};

/// The world state - a mapping of addresses to account states.
///
/// This is the account-based state model. Each address has exactly
/// one account state with a balance and nonce.
#[derive(Clone, Debug, Default)]
pub struct State {
    accounts: HashMap<Address, Account>,
}

impl State {
    /// Create a new empty state.
    pub fn new() -> Self {
        Self {
            accounts: HashMap::new(),
        }
    }

    /// Get an account by address (returns default if not found).
    pub fn get_account(&self, address: &Address) -> Account {
        self.accounts
            .get(address)
            .cloned()
            .unwrap_or_else(|| Account::new(*address))
    }

    /// Get a mutable reference to an account, creating it if needed.
    pub fn get_account_mut(&mut self, address: &Address) -> &mut Account {
        self.accounts
            .entry(*address)
            .or_insert_with(|| Account::new(*address))
    }

    /// Check if an account exists.
    pub fn has_account(&self, address: &Address) -> bool {
        self.accounts.contains_key(address)
    }

    /// Set an account state directly.
    pub fn set_account(&mut self, account: Account) {
        self.accounts.insert(account.address, account);
    }

    /// Get the balance of an address.
    pub fn balance(&self, address: &Address) -> u64 {
        self.get_account(address).balance
    }

    /// Get the nonce of an address.
    pub fn nonce(&self, address: &Address) -> u64 {
        self.get_account(address).nonce
    }

    /// Validate a transaction against the current state.
    pub fn validate_transaction(&self, tx: &Transaction) -> Result<(), StateError> {
        // Coinbase transactions skip normal validation
        if tx.is_coinbase() {
            return Ok(());
        }

        // Verify signature
        if !tx.verify_signature().map_err(|_| StateError::InvalidSignature)? {
            return Err(StateError::InvalidSignature);
        }

        let sender = self.get_account(&tx.from);

        // Check nonce
        if tx.nonce != sender.nonce {
            return Err(StateError::InvalidNonce {
                expected: sender.nonce,
                got: tx.nonce,
            });
        }

        // Check balance
        if !sender.can_afford(tx.amount, tx.fee) {
            return Err(StateError::InsufficientBalance {
                required: tx.total_cost(),
                available: sender.balance,
            });
        }

        Ok(())
    }

    /// Apply a transaction to the state.
    ///
    /// This modifies account balances and nonces. The transaction
    /// should be validated first.
    pub fn apply_transaction(&mut self, tx: &Transaction) -> Result<(), StateError> {
        if tx.is_coinbase() {
            // Coinbase: just credit the recipient
            self.get_account_mut(&tx.to).credit(tx.amount);
            return Ok(());
        }

        // Debit sender
        let sender = self.get_account_mut(&tx.from);
        sender
            .debit(tx.amount, tx.fee)
            .map_err(|_| StateError::InsufficientBalance {
                required: tx.total_cost(),
                available: sender.balance,
            })?;

        // Credit recipient
        self.get_account_mut(&tx.to).credit(tx.amount);

        Ok(())
    }

    /// Apply a transaction and return the fee collected.
    pub fn apply_transaction_with_fee(&mut self, tx: &Transaction) -> Result<u64, StateError> {
        let fee = tx.fee;
        self.apply_transaction(tx)?;
        Ok(fee)
    }

    /// Get all accounts (for serialization/persistence).
    pub fn accounts(&self) -> impl Iterator<Item = &Account> {
        self.accounts.values()
    }

    /// Get the number of accounts.
    pub fn account_count(&self) -> usize {
        self.accounts.len()
    }

    /// Create a snapshot of the current state.
    pub fn snapshot(&self) -> State {
        self.clone()
    }

    /// Get top accounts by balance.
    pub fn top_holders(&self, limit: usize) -> Vec<&Account> {
        let mut accounts: Vec<_> = self.accounts.values().collect();
        accounts.sort_by(|a, b| b.balance.cmp(&a.balance));
        accounts.truncate(limit);
        accounts
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("Invalid transaction signature")]
    InvalidSignature,
    #[error("Invalid nonce: expected {expected}, got {got}")]
    InvalidNonce { expected: u64, got: u64 },
    #[error("Insufficient balance: required {required}, available {available}")]
    InsufficientBalance { required: u64, available: u64 },
    #[error("Account not found")]
    AccountNotFound,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;

    #[test]
    fn test_empty_state() {
        let state = State::new();
        let addr = Address::from_bytes([1u8; 20]);

        assert_eq!(state.balance(&addr), 0);
        assert_eq!(state.nonce(&addr), 0);
    }

    #[test]
    fn test_set_and_get_account() {
        let mut state = State::new();
        let addr = Address::from_bytes([1u8; 20]);

        let account = Account::with_balance(addr, 1000);
        state.set_account(account);

        assert_eq!(state.balance(&addr), 1000);
    }

    #[test]
    fn test_apply_transaction() {
        let mut state = State::new();

        let sender = KeyPair::generate();
        let receiver = KeyPair::generate();

        // Give sender some coins
        let sender_account = Account::with_balance(sender.address(), 1000);
        state.set_account(sender_account);

        // Create and apply transaction
        let tx = Transaction::create_signed(&sender, receiver.address(), 100, 1, 0);

        state.validate_transaction(&tx).unwrap();
        state.apply_transaction(&tx).unwrap();

        assert_eq!(state.balance(&sender.address()), 899); // 1000 - 100 - 1
        assert_eq!(state.balance(&receiver.address()), 100);
        assert_eq!(state.nonce(&sender.address()), 1);
    }

    #[test]
    fn test_invalid_nonce() {
        let mut state = State::new();

        let sender = KeyPair::generate();
        let receiver = KeyPair::generate();

        let sender_account = Account::with_balance(sender.address(), 1000);
        state.set_account(sender_account);

        // Transaction with wrong nonce
        let tx = Transaction::create_signed(&sender, receiver.address(), 100, 1, 5);

        let result = state.validate_transaction(&tx);
        assert!(matches!(result, Err(StateError::InvalidNonce { .. })));
    }

    #[test]
    fn test_insufficient_balance() {
        let mut state = State::new();

        let sender = KeyPair::generate();
        let receiver = KeyPair::generate();

        let sender_account = Account::with_balance(sender.address(), 50);
        state.set_account(sender_account);

        let tx = Transaction::create_signed(&sender, receiver.address(), 100, 1, 0);

        let result = state.validate_transaction(&tx);
        assert!(matches!(result, Err(StateError::InsufficientBalance { .. })));
    }

    #[test]
    fn test_coinbase_transaction() {
        let mut state = State::new();

        let miner = KeyPair::generate();
        let coinbase = Transaction::coinbase(miner.address(), 50);

        state.validate_transaction(&coinbase).unwrap();
        state.apply_transaction(&coinbase).unwrap();

        assert_eq!(state.balance(&miner.address()), 50);
    }
}
