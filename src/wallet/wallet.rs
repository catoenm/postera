//! Shielded wallet for private transactions.
//!
//! The wallet tracks owned notes and can:
//! - Scan blocks to discover incoming notes
//! - Calculate balance (sum of unspent notes)
//! - Create shielded transactions

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;

use ark_bn254::Fr;

use crate::core::{
    BindingSignature, OutputDescription, ShieldedBlock,
    ShieldedState, ShieldedTransaction, SpendDescription,
};
use crate::crypto::{
    commitment::{commit_to_value, NoteCommitment},
    note::{compute_pk_hash, Note, ViewingKey},
    nullifier::{derive_nullifier, Nullifier, NullifierKey},
    poseidon::{bytes32_to_field, field_to_bytes32, poseidon_hash, DOMAIN_NULLIFIER, DOMAIN_MERKLE_NODE, DOMAIN_NOTE_COMMITMENT},
    proof::{generate_output_proof, generate_spend_proof, ProvingParams, ZkProof},
    circuits::{OutputCircuit, SpendCircuit},
    sign, Address, KeyPair,
};

/// A note owned by the wallet.
#[derive(Clone, Debug)]
pub struct WalletNote {
    /// The note itself.
    pub note: Note,
    /// The note commitment.
    pub commitment: NoteCommitment,
    /// Position in the commitment tree.
    pub position: u64,
    /// Block height where this note was created.
    pub height: u64,
    /// Whether this note has been spent.
    pub is_spent: bool,
    /// The nullifier for this note (computed lazily).
    nullifier: Option<Nullifier>,
}

impl WalletNote {
    /// Create a new wallet note.
    pub fn new(note: Note, commitment: NoteCommitment, position: u64, height: u64) -> Self {
        Self {
            note,
            commitment,
            position,
            height,
            is_spent: false,
            nullifier: None,
        }
    }

    /// Get or compute the nullifier.
    pub fn nullifier(&mut self, nullifier_key: &NullifierKey) -> Nullifier {
        if self.nullifier.is_none() {
            self.nullifier = Some(derive_nullifier(nullifier_key, &self.commitment, self.position));
        }
        self.nullifier.unwrap()
    }

    /// Check if this note has been spent.
    pub fn mark_spent(&mut self) {
        self.is_spent = true;
    }
}

/// A shielded wallet with privacy features.
pub struct ShieldedWallet {
    /// The signing keypair (Dilithium for ownership proofs).
    keypair: KeyPair,
    /// Secret nullifier key (derived from keypair secret).
    nullifier_key: NullifierKey,
    /// Viewing key for scanning blockchain.
    viewing_key: ViewingKey,
    /// Hash of our public key (for note matching).
    pk_hash: [u8; 32],
    /// Notes owned by this wallet.
    notes: Vec<WalletNote>,
    /// Optional proving parameters (expensive to generate).
    proving_params: Option<Arc<ProvingParams>>,
    /// Last scanned block height.
    last_scanned_height: u64,
}

impl ShieldedWallet {
    /// Generate a new random wallet.
    pub fn generate() -> Self {
        let keypair = KeyPair::generate();
        let secret_bytes = keypair.secret_key_bytes();

        let nullifier_key = NullifierKey::new(&secret_bytes);
        let viewing_key = ViewingKey::new(&secret_bytes);
        let pk_hash = compute_pk_hash(&keypair.public_key_bytes());

        Self {
            keypair,
            nullifier_key,
            viewing_key,
            pk_hash,
            notes: Vec::new(),
            proving_params: None,
            last_scanned_height: 0,
        }
    }

    /// Load a wallet from a JSON file.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, WalletError> {
        let data = std::fs::read_to_string(path).map_err(WalletError::IoError)?;
        let stored: StoredShieldedWallet =
            serde_json::from_str(&data).map_err(WalletError::ParseError)?;

        let public_key = hex::decode(&stored.public_key).map_err(|_| WalletError::InvalidKey)?;
        let secret_key = hex::decode(&stored.secret_key).map_err(|_| WalletError::InvalidKey)?;

        let keypair =
            KeyPair::from_bytes(&public_key, &secret_key).map_err(|_| WalletError::InvalidKey)?;

        let nullifier_key = NullifierKey::new(&secret_key);
        let viewing_key = ViewingKey::new(&secret_key);
        let pk_hash = compute_pk_hash(&public_key);

        // Load notes from stored data
        let notes = stored
            .notes
            .into_iter()
            .filter_map(|sn| {
                let note = Note::from_bytes(&hex::decode(&sn.note_data).ok()?).ok()?;
                let commitment = NoteCommitment::from_bytes(
                    hex::decode(&sn.commitment).ok()?.try_into().ok()?,
                );
                Some(WalletNote {
                    note,
                    commitment,
                    position: sn.position,
                    height: sn.height,
                    is_spent: sn.is_spent,
                    nullifier: None,
                })
            })
            .collect();

        Ok(Self {
            keypair,
            nullifier_key,
            viewing_key,
            pk_hash,
            notes,
            proving_params: None,
            last_scanned_height: stored.last_scanned_height,
        })
    }

    /// Save the wallet to a JSON file.
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), WalletError> {
        let stored_notes: Vec<StoredNote> = self
            .notes
            .iter()
            .map(|wn| StoredNote {
                note_data: hex::encode(wn.note.to_bytes()),
                commitment: hex::encode(wn.commitment.to_bytes()),
                position: wn.position,
                height: wn.height,
                is_spent: wn.is_spent,
            })
            .collect();

        let stored = StoredShieldedWallet {
            address: self.address().to_hex(),
            public_key: hex::encode(self.keypair.public_key_bytes()),
            secret_key: hex::encode(self.keypair.secret_key_bytes()),
            pk_hash: hex::encode(self.pk_hash),
            notes: stored_notes,
            last_scanned_height: self.last_scanned_height,
        };

        let data =
            serde_json::to_string_pretty(&stored).map_err(|e| WalletError::ParseError(e))?;
        std::fs::write(path, data).map_err(WalletError::IoError)?;

        Ok(())
    }

    /// Get the wallet's address.
    pub fn address(&self) -> Address {
        self.keypair.address()
    }

    /// Get the wallet's public key hash (for receiving notes).
    pub fn pk_hash(&self) -> [u8; 32] {
        self.pk_hash
    }

    /// Get the viewing key.
    pub fn viewing_key(&self) -> &ViewingKey {
        &self.viewing_key
    }

    /// Get the nullifier key.
    pub fn nullifier_key(&self) -> &NullifierKey {
        &self.nullifier_key
    }

    /// Set the proving parameters.
    pub fn set_proving_params(&mut self, params: Arc<ProvingParams>) {
        self.proving_params = Some(params);
    }

    /// Get the current balance (sum of unspent notes).
    pub fn balance(&self) -> u64 {
        self.notes
            .iter()
            .filter(|n| !n.is_spent)
            .map(|n| n.note.value)
            .sum()
    }

    /// Get unspent notes.
    pub fn unspent_notes(&self) -> Vec<&WalletNote> {
        self.notes.iter().filter(|n| !n.is_spent).collect()
    }

    /// Get all notes.
    pub fn notes(&self) -> &[WalletNote] {
        &self.notes
    }

    /// Get the number of unspent notes.
    pub fn unspent_count(&self) -> usize {
        self.notes.iter().filter(|n| !n.is_spent).count()
    }

    /// Alias for unspent_count.
    pub fn note_count(&self) -> usize {
        self.unspent_count()
    }

    /// Scan a block for incoming notes.
    /// Returns the number of new notes discovered.
    pub fn scan_block(&mut self, block: &ShieldedBlock, start_position: u64) -> usize {
        let height = block.height();
        let mut position = start_position;
        let mut new_notes = 0;

        // Create decryption key from our pk_hash (matches how notes are encrypted)
        let decryption_key = ViewingKey::from_pk_hash(self.pk_hash);

        // Scan transaction outputs
        for tx in &block.transactions {
            for output in &tx.outputs {
                if let Some(note) = decryption_key.decrypt_note(&output.encrypted_note) {
                    // Check if this note is for us
                    if note.recipient_pk_hash == self.pk_hash {
                        let wallet_note = WalletNote::new(
                            note,
                            output.note_commitment,
                            position,
                            height,
                        );
                        self.notes.push(wallet_note);
                        new_notes += 1;
                    }
                }
                position += 1;
            }
        }

        // Scan coinbase
        if let Some(note) = decryption_key.decrypt_note(&block.coinbase.encrypted_note) {
            if note.recipient_pk_hash == self.pk_hash {
                let wallet_note = WalletNote::new(
                    note,
                    block.coinbase.note_commitment,
                    position,
                    height,
                );
                self.notes.push(wallet_note);
                new_notes += 1;
            }
        }

        self.last_scanned_height = height;
        new_notes
    }

    /// Mark notes as spent based on observed nullifiers.
    pub fn mark_spent_nullifiers(&mut self, nullifiers: &[Nullifier]) {
        for note in &mut self.notes {
            if !note.is_spent {
                let nf = note.nullifier(&self.nullifier_key);
                if nullifiers.contains(&nf) {
                    note.mark_spent();
                }
            }
        }
    }

    /// Select notes to spend for a given amount.
    /// Returns indices of notes to spend.
    fn select_notes(&self, amount: u64) -> Option<Vec<usize>> {
        let mut selected = Vec::new();
        let mut total = 0u64;

        // Simple greedy selection (could be optimized)
        for (i, note) in self.notes.iter().enumerate() {
            if !note.is_spent {
                selected.push(i);
                total += note.note.value;
                if total >= amount {
                    return Some(selected);
                }
            }
        }

        None // Not enough funds
    }

    /// Create a shielded transaction with real ZK proofs.
    ///
    /// # Arguments
    /// * `state` - Current blockchain state for witness generation
    /// * `outputs` - List of (pk_hash, amount) pairs for outputs
    /// * `fee` - Transaction fee
    ///
    /// # Returns
    /// A signed shielded transaction, or an error.
    pub fn create_transaction(
        &mut self,
        state: &ShieldedState,
        outputs: Vec<([u8; 32], u64)>,
        fee: u64,
    ) -> Result<ShieldedTransaction, WalletError> {
        let total_output: u64 = outputs.iter().map(|(_, v)| *v).sum();
        let total_needed = total_output + fee;

        // Select notes to spend
        let note_indices = self
            .select_notes(total_needed)
            .ok_or(WalletError::InsufficientFunds)?;

        let total_input: u64 = note_indices
            .iter()
            .map(|&i| self.notes[i].note.value)
            .sum();

        let change = total_input - total_needed;

        let mut rng = ark_std::rand::thread_rng();

        // Get proving params (required for proof generation)
        let proving_params = self.proving_params.as_ref()
            .ok_or(WalletError::NoProvingParams)?;

        // Create spend descriptions
        let mut spends = Vec::new();
        for &idx in &note_indices {
            let note = &mut self.notes[idx];

            // Get witness from state
            let witness = state
                .get_witness(note.position)
                .ok_or(WalletError::WitnessNotFound)?;

            // Create value commitment
            let value_commitment = commit_to_value(note.note.value, &mut rng);
            let value_commitment_hash = value_commitment.commitment_hash();

            // Compute nullifier
            let nullifier = note.nullifier(&self.nullifier_key);

            // Convert witness data to field elements for circuit
            let merkle_root_fe = bytes32_to_field(&witness.root);
            let nullifier_fe = bytes32_to_field(&nullifier.to_bytes());
            let value_commitment_hash_fe = bytes32_to_field(&value_commitment_hash);

            // Convert merkle path to field elements
            let merkle_path_fe: Vec<Fr> = witness.path.auth_path
                .iter()
                .map(bytes32_to_field)
                .collect();

            // Create spend circuit
            let circuit = SpendCircuit::new(
                merkle_root_fe,
                nullifier_fe,
                value_commitment_hash_fe,
                note.note.value,
                bytes32_to_field(&note.note.recipient_pk_hash),
                note.note.randomness,
                self.nullifier_key.to_field_element(),
                merkle_path_fe,
                note.position,
                value_commitment.randomness,
            );

            // Generate real spend proof
            let proof = generate_spend_proof(circuit, proving_params.as_ref(), &mut rng)
                .map_err(|_| WalletError::ProofGenerationFailed)?;

            // Sign the spend
            let mut sign_msg = Vec::new();
            sign_msg.extend_from_slice(&witness.root);
            sign_msg.extend_from_slice(nullifier.as_ref());
            sign_msg.extend_from_slice(&value_commitment_hash);

            let signature = sign(&sign_msg, &self.keypair);

            spends.push(SpendDescription {
                anchor: witness.root,
                nullifier,
                value_commitment: value_commitment_hash,
                proof,
                signature,
                public_key: self.keypair.public_key_bytes().to_vec(),
            });
        }

        // Create output descriptions
        let mut output_descs = Vec::new();

        for (recipient_pk_hash, amount) in outputs {
            let output_note = Note::new(amount, recipient_pk_hash, &mut rng);
            let commitment = output_note.commitment();
            let value_commitment = commit_to_value(amount, &mut rng);
            let value_commitment_hash = value_commitment.commitment_hash();

            // Encrypt note for recipient using their pk_hash
            // (recipient can decrypt using their own pk_hash)
            let recipient_key = ViewingKey::from_pk_hash(recipient_pk_hash);
            let encrypted = recipient_key.encrypt_note(&output_note, &mut rng);

            // Create output circuit
            let circuit = OutputCircuit::new(
                bytes32_to_field(&commitment.to_bytes()),
                bytes32_to_field(&value_commitment_hash),
                amount,
                bytes32_to_field(&recipient_pk_hash),
                output_note.randomness,
                value_commitment.randomness,
            );

            // Generate real output proof
            let proof = generate_output_proof(circuit, proving_params.as_ref(), &mut rng)
                .map_err(|_| WalletError::ProofGenerationFailed)?;

            output_descs.push(OutputDescription {
                note_commitment: commitment,
                value_commitment: value_commitment_hash,
                encrypted_note: encrypted,
                proof,
            });
        }

        // Add change output if needed
        if change > 0 {
            let change_note = Note::new(change, self.pk_hash, &mut rng);
            let commitment = change_note.commitment();
            let value_commitment = commit_to_value(change, &mut rng);
            let value_commitment_hash = value_commitment.commitment_hash();
            // Encrypt change note using our own pk_hash (so we can decrypt it)
            let change_key = ViewingKey::from_pk_hash(self.pk_hash);
            let encrypted = change_key.encrypt_note(&change_note, &mut rng);

            // Create output circuit for change
            let circuit = OutputCircuit::new(
                bytes32_to_field(&commitment.to_bytes()),
                bytes32_to_field(&value_commitment_hash),
                change,
                bytes32_to_field(&self.pk_hash),
                change_note.randomness,
                value_commitment.randomness,
            );

            // Generate proof for change output
            let proof = generate_output_proof(circuit, proving_params.as_ref(), &mut rng)
                .map_err(|_| WalletError::ProofGenerationFailed)?;

            output_descs.push(OutputDescription {
                note_commitment: commitment,
                value_commitment: value_commitment_hash,
                encrypted_note: encrypted,
                proof,
            });
        }

        // Create binding signature (simplified - full implementation would use commitment arithmetic)
        let binding_sig = BindingSignature::new(vec![0u8; 64]);

        // Mark spent notes
        for &idx in &note_indices {
            self.notes[idx].mark_spent();
        }

        Ok(ShieldedTransaction::new(
            spends,
            output_descs,
            fee,
            binding_sig,
        ))
    }

    /// Get the last scanned block height.
    pub fn last_scanned_height(&self) -> u64 {
        self.last_scanned_height
    }
}

/// Stored wallet format for serialization.
#[derive(Serialize, Deserialize)]
struct StoredShieldedWallet {
    address: String,
    public_key: String,
    secret_key: String,
    pk_hash: String,
    notes: Vec<StoredNote>,
    last_scanned_height: u64,
}

/// Stored note format.
#[derive(Serialize, Deserialize)]
struct StoredNote {
    note_data: String,
    commitment: String,
    position: u64,
    height: u64,
    is_spent: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("IO error: {0}")]
    IoError(#[source] std::io::Error),

    #[error("Parse error: {0}")]
    ParseError(#[source] serde_json::Error),

    #[error("Invalid key data")]
    InvalidKey,

    #[error("Insufficient funds")]
    InsufficientFunds,

    #[error("Witness not found for note")]
    WitnessNotFound,

    #[error("Proving parameters not set")]
    NoProvingParams,

    #[error("Proof generation failed")]
    ProofGenerationFailed,
}

// ============================================================================
// Legacy Wallet Support
// ============================================================================

use crate::core::LegacyTransaction;

/// Legacy wallet for backwards compatibility.
#[derive(Clone)]
pub struct LegacyWallet {
    keypair: KeyPair,
}

impl LegacyWallet {
    pub fn generate() -> Self {
        Self {
            keypair: KeyPair::generate(),
        }
    }

    pub fn address(&self) -> Address {
        self.keypair.address()
    }

    pub fn keypair(&self) -> &KeyPair {
        &self.keypair
    }

    pub fn create_transaction(
        &self,
        to: Address,
        amount: u64,
        fee: u64,
        nonce: u64,
    ) -> LegacyTransaction {
        let mut msg = Vec::new();
        msg.extend_from_slice(self.keypair.address().as_bytes());
        msg.extend_from_slice(to.as_bytes());
        msg.extend_from_slice(&amount.to_le_bytes());
        msg.extend_from_slice(&fee.to_le_bytes());
        msg.extend_from_slice(&nonce.to_le_bytes());

        LegacyTransaction {
            from: self.keypair.address(),
            to,
            amount,
            fee,
            nonce,
            public_key: self.keypair.public_key_bytes().to_vec(),
            signature: Some(sign(&msg, &self.keypair)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_generate_wallet() {
        let wallet = ShieldedWallet::generate();
        assert!(!wallet.address().is_zero());
        assert_eq!(wallet.balance(), 0);
    }

    #[test]
    fn test_wallet_keys() {
        let wallet = ShieldedWallet::generate();

        // pk_hash should be deterministic from public key
        let expected_pk_hash = compute_pk_hash(&wallet.keypair.public_key_bytes());
        assert_eq!(wallet.pk_hash(), expected_pk_hash);
    }

    #[test]
    fn test_save_and_load_wallet() {
        let wallet = ShieldedWallet::generate();
        let original_address = wallet.address();
        let original_pk_hash = wallet.pk_hash();

        let temp_file = NamedTempFile::new().unwrap();
        wallet.save(temp_file.path()).unwrap();

        let loaded = ShieldedWallet::load(temp_file.path()).unwrap();
        assert_eq!(loaded.address(), original_address);
        assert_eq!(loaded.pk_hash(), original_pk_hash);
    }

    #[test]
    fn test_note_discovery() {
        use crate::crypto::commitment::NoteCommitment;

        let mut wallet = ShieldedWallet::generate();

        // Create a note for this wallet
        let mut rng = ark_std::rand::thread_rng();
        let note = Note::new(1000, wallet.pk_hash(), &mut rng);
        let _commitment = note.commitment();

        // Create a mock encrypted note using pk_hash (new encryption scheme)
        let encryption_key = ViewingKey::from_pk_hash(wallet.pk_hash());
        let encrypted = encryption_key.encrypt_note(&note, &mut rng);

        // Try to decrypt using pk_hash
        let decryption_key = ViewingKey::from_pk_hash(wallet.pk_hash());
        let decrypted = decryption_key.decrypt_note(&encrypted).unwrap();
        assert_eq!(decrypted.value, 1000);
        assert_eq!(decrypted.recipient_pk_hash, wallet.pk_hash());
    }

    #[test]
    fn test_balance_calculation() {
        let mut wallet = ShieldedWallet::generate();

        // Add some fake notes
        let mut rng = ark_std::rand::thread_rng();
        for value in [100, 200, 300] {
            let note = Note::new(value, wallet.pk_hash(), &mut rng);
            let commitment = note.commitment();
            wallet.notes.push(WalletNote::new(note, commitment, 0, 0));
        }

        assert_eq!(wallet.balance(), 600);
        assert_eq!(wallet.unspent_count(), 3);

        // Mark one as spent
        wallet.notes[0].mark_spent();
        assert_eq!(wallet.balance(), 500);
        assert_eq!(wallet.unspent_count(), 2);
    }

    #[test]
    fn test_note_selection() {
        let mut wallet = ShieldedWallet::generate();

        // Add notes
        let mut rng = ark_std::rand::thread_rng();
        for value in [100, 200, 300] {
            let note = Note::new(value, wallet.pk_hash(), &mut rng);
            let commitment = note.commitment();
            wallet.notes.push(WalletNote::new(note, commitment, 0, 0));
        }

        // Select for 250 (should pick 100 + 200 or similar)
        let selected = wallet.select_notes(250).unwrap();
        let total: u64 = selected
            .iter()
            .map(|&i| wallet.notes[i].note.value)
            .sum();
        assert!(total >= 250);

        // Select for 1000 (should fail)
        assert!(wallet.select_notes(1000).is_none());
    }
}
