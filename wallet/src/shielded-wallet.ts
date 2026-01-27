/**
 * Shielded wallet state management.
 *
 * Handles note scanning, balance tracking, and note selection for spending.
 * Persists state to localStorage for resumable scanning.
 */

import {
  deriveViewingKey,
  deriveNullifierKey,
  computePkHash,
  tryDecryptNoteFromHex,
  deriveNullifier,
  initPoseidon,
} from './shielded-crypto';
import { hexToBytes, bytesToHex } from './crypto';
import { getOutputsSince, checkNullifiers } from './api';
import { loadProvingKeys, areProvingKeysLoaded } from './prover';
import type { WalletNote, ShieldedState, EncryptedOutput } from './types';

/** Whether cryptographic primitives have been initialized */
let cryptoInitialized = false;

const STORAGE_KEY = 'postera_shielded_state';

/**
 * Shielded wallet for managing private notes and balances.
 */
export class ShieldedWallet {
  /** Viewing key for decrypting notes */
  viewingKey: Uint8Array;
  /** Nullifier key for computing nullifiers */
  nullifierKey: Uint8Array;
  /** Public key hash (recipient identifier) */
  pkHash: Uint8Array;
  /** Full public key (for verification) */
  publicKey: Uint8Array;
  /** All known notes */
  notes: WalletNote[];
  /** Last scanned block height */
  lastScannedHeight: number;
  /** Scanning state */
  private scanning: boolean = false;

  constructor(secretKey: Uint8Array, publicKey: Uint8Array) {
    this.viewingKey = deriveViewingKey(secretKey);
    this.nullifierKey = deriveNullifierKey(secretKey);
    this.pkHash = computePkHash(publicKey);
    this.publicKey = publicKey;
    this.notes = [];
    this.lastScannedHeight = -1;

    // Load persisted state
    this.loadState();
  }

  /**
   * Create a ShieldedWallet from hex-encoded keys.
   */
  static fromHex(secretKeyHex: string, publicKeyHex: string): ShieldedWallet {
    return new ShieldedWallet(hexToBytes(secretKeyHex), hexToBytes(publicKeyHex));
  }

  /**
   * Initialize cryptographic primitives required for the shielded wallet.
   * Must be called before using note commitments, nullifiers, or creating transactions.
   *
   * @param loadProver - If true, also loads ZK proving keys (required for transactions)
   * @param onProgress - Optional callback for progress updates
   */
  static async initialize(
    loadProver: boolean = false,
    onProgress?: (msg: string) => void
  ): Promise<void> {
    if (!cryptoInitialized) {
      onProgress?.('Initializing Poseidon hash...');
      await initPoseidon();
      cryptoInitialized = true;
    }

    if (loadProver && !areProvingKeysLoaded()) {
      onProgress?.('Loading ZK proving keys (~100-200MB)...');
      await loadProvingKeys();
      onProgress?.('Proving keys loaded.');
    }
  }

  /**
   * Check if cryptographic primitives are initialized.
   */
  static get isInitialized(): boolean {
    return cryptoInitialized;
  }

  /**
   * Check if ZK proving keys are loaded (required for creating transactions).
   */
  static get isProverReady(): boolean {
    return areProvingKeysLoaded();
  }

  /**
   * Get the public key hash as hex string (for sharing with senders).
   */
  get pkHashHex(): string {
    return bytesToHex(this.pkHash);
  }

  /**
   * Get the total balance of unspent notes.
   */
  get balance(): bigint {
    return this.notes
      .filter((n) => !n.spent)
      .reduce((sum, n) => sum + n.value, 0n);
  }

  /**
   * Get the number of unspent notes.
   */
  get unspentCount(): number {
    return this.notes.filter((n) => !n.spent).length;
  }

  /**
   * Get all unspent notes.
   */
  get unspentNotes(): WalletNote[] {
    return this.notes.filter((n) => !n.spent);
  }

  /**
   * Check if currently scanning.
   */
  get isScanning(): boolean {
    return this.scanning;
  }

  /**
   * Scan the blockchain for incoming notes.
   * Fetches all outputs since lastScannedHeight and attempts decryption.
   */
  async scan(onProgress?: (msg: string) => void): Promise<number> {
    if (this.scanning) {
      return 0;
    }

    this.scanning = true;
    let newNotesFound = 0;

    try {
      // API expects unsigned height, use 0 for initial scan
      // When sinceHeight=0, API returns ALL outputs including genesis
      // When sinceHeight>0, API returns outputs from sinceHeight+1 onwards
      const sinceHeight = this.lastScannedHeight < 0 ? 0 : this.lastScannedHeight;

      onProgress?.(`Fetching outputs since height ${sinceHeight}...`);

      const response = await getOutputsSince(sinceHeight);
      const { outputs, current_height } = response;

      onProgress?.(`Processing ${outputs.length} outputs...`);

      for (const output of outputs) {
        const note = this.tryDecryptOutput(output);
        if (note) {
          // Check if we already have this note (by commitment)
          const existing = this.notes.find((n) => n.commitment === note.commitment);
          if (!existing) {
            this.notes.push(note);
            newNotesFound++;
            onProgress?.(`Found note: ${this.formatValue(note.value)} PSTR at height ${note.blockHeight}`);
          }
        }
      }

      this.lastScannedHeight = current_height;

      // Check for spent notes
      onProgress?.('Checking for spent notes...');
      await this.checkSpent();

      // Persist state
      this.saveState();

      onProgress?.(`Scan complete. Found ${newNotesFound} new notes.`);
    } finally {
      this.scanning = false;
    }

    return newNotesFound;
  }

  /**
   * Try to decrypt an encrypted output.
   * Returns a WalletNote if successful, null otherwise.
   */
  private tryDecryptOutput(output: EncryptedOutput): WalletNote | null {
    const decrypted = tryDecryptNoteFromHex(
      output.ciphertext,
      output.ephemeral_pk,
      this.viewingKey
    );

    if (!decrypted) {
      return null;
    }

    // Verify the note is for our pk_hash
    const recipientPkHashHex = bytesToHex(decrypted.recipientPkHash);
    if (recipientPkHashHex !== this.pkHashHex) {
      // Note is not for us (decryption succeeded but it's for a different recipient)
      return null;
    }

    // Use the commitment from the blockchain (already verified by consensus)
    // We derive nullifier using the commitment bytes from the chain
    const commitmentBytes = hexToBytes(output.note_commitment);
    const nullifier = deriveNullifier(
      this.nullifierKey,
      commitmentBytes,
      BigInt(output.position)
    );

    return {
      value: decrypted.value,
      recipientPkHash: recipientPkHashHex,
      randomness: bytesToHex(decrypted.randomness),
      commitment: output.note_commitment,
      position: BigInt(output.position),
      blockHeight: output.block_height,
      spent: false,
      nullifier: bytesToHex(nullifier),
    };
  }

  /**
   * Check which of our notes have been spent.
   */
  async checkSpent(): Promise<void> {
    const unspentNotes = this.notes.filter((n) => !n.spent && n.nullifier);

    if (unspentNotes.length === 0) {
      return;
    }

    const nullifiers = unspentNotes.map((n) => n.nullifier!);
    const response = await checkNullifiers(nullifiers);

    for (const spentNf of response.spent) {
      const note = this.notes.find((n) => n.nullifier === spentNf);
      if (note) {
        note.spent = true;
      }
    }

    this.saveState();
  }

  /**
   * Select notes for spending a given amount.
   * Uses a greedy algorithm: largest notes first until we have enough.
   */
  selectNotes(amount: bigint): WalletNote[] {
    const available = this.unspentNotes.sort((a, b) =>
      a.value > b.value ? -1 : a.value < b.value ? 1 : 0
    );

    const selected: WalletNote[] = [];
    let total = 0n;

    for (const note of available) {
      if (total >= amount) {
        break;
      }
      selected.push(note);
      total += note.value;
    }

    if (total < amount) {
      throw new Error(`Insufficient balance: have ${total}, need ${amount}`);
    }

    return selected;
  }

  /**
   * Format a value for display (convert from smallest units to PSTR).
   */
  formatValue(value: bigint): string {
    const DECIMALS = 9;
    const divisor = 10n ** BigInt(DECIMALS);
    const whole = value / divisor;
    const frac = value % divisor;
    const fracStr = frac.toString().padStart(DECIMALS, '0').replace(/0+$/, '');
    return fracStr ? `${whole}.${fracStr}` : whole.toString();
  }

  /**
   * Parse a PSTR amount string to smallest units.
   */
  static parseAmount(amountStr: string): bigint {
    const DECIMALS = 9;
    const parts = amountStr.split('.');
    const whole = BigInt(parts[0] || '0');
    const fracStr = (parts[1] || '').padEnd(DECIMALS, '0').slice(0, DECIMALS);
    const frac = BigInt(fracStr);
    return whole * 10n ** BigInt(DECIMALS) + frac;
  }

  /**
   * Load persisted state from localStorage.
   */
  private loadState(): void {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        const state: ShieldedState = JSON.parse(stored, (key, value) => {
          // Convert position and value back to bigint
          if (key === 'position' || key === 'value') {
            return BigInt(value);
          }
          return value;
        });

        this.notes = state.notes;
        this.lastScannedHeight = state.lastScannedHeight;
      }
    } catch (e) {
      console.error('Failed to load shielded state:', e);
    }
  }

  /**
   * Save state to localStorage.
   */
  private saveState(): void {
    try {
      const state: ShieldedState = {
        notes: this.notes,
        lastScannedHeight: this.lastScannedHeight,
      };

      // Custom serialization to handle bigint
      const json = JSON.stringify(state, (_, value) => {
        if (typeof value === 'bigint') {
          return value.toString();
        }
        return value;
      });

      localStorage.setItem(STORAGE_KEY, json);
    } catch (e) {
      console.error('Failed to save shielded state:', e);
    }
  }

  /**
   * Clear all wallet state.
   */
  clearState(): void {
    this.notes = [];
    this.lastScannedHeight = -1;
    localStorage.removeItem(STORAGE_KEY);
  }

  /**
   * Get a summary of the wallet state.
   */
  getSummary(): {
    balance: string;
    balanceRaw: bigint;
    unspentCount: number;
    totalNotes: number;
    spentNotes: number;
    lastScannedHeight: number;
  } {
    return {
      balance: this.formatValue(this.balance),
      balanceRaw: this.balance,
      unspentCount: this.unspentCount,
      totalNotes: this.notes.length,
      spentNotes: this.notes.filter((n) => n.spent).length,
      lastScannedHeight: this.lastScannedHeight,
    };
  }
}

/**
 * Hook to use ShieldedWallet in React components.
 */
export function createShieldedWallet(secretKeyHex: string, publicKeyHex: string): ShieldedWallet {
  return ShieldedWallet.fromHex(secretKeyHex, publicKeyHex);
}
