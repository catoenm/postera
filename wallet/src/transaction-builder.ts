/**
 * Shielded transaction builder.
 *
 * Creates shielded transactions with spends and outputs.
 * Generates real ZK proofs using snarkjs in the browser.
 */

import {
  computeNoteCommitment,
  encryptNote,
  generateRandomness,
  deriveViewingKey,
  deriveNullifierKey,
} from './shielded-crypto';
import { sign, hexToBytes, bytesToHex } from './crypto';
import { getWitnessByPosition } from './api';
import {
  generateSpendProof,
  generateOutputProof,
  areProvingKeysLoaded,
  type SpendWitness,
  type OutputWitness,
  type SnarkJsProof,
} from './prover';
import {
  bytes32ToBigint,
  bigintToBytes32,
  DOMAIN_VALUE_COMMITMENT_HASH,
  poseidonHash,
} from './poseidon';
import {
  BindingContext,
  serializeCommitment,
} from './binding';
import type { WalletNote, WitnessResponse } from './types';

/**
 * Rust serialization format reference:
 *
 * SpendDescription:
 *   - anchor: hex string (hex_bytes_32)
 *   - nullifier: byte array [u8; 32] (default serde for Nullifier)
 *   - value_commitment: hex string (hex_bytes_32)
 *   - proof: byte array (ZkProof uses serialize_bytes)
 *   - signature: hex string (Signature uses serialize_str with hex)
 *   - public_key: hex string (hex_bytes)
 *
 * OutputDescription:
 *   - note_commitment: byte array [u8; 32] (default serde for NoteCommitment)
 *   - value_commitment: hex string (hex_bytes_32)
 *   - encrypted_note: { ciphertext: byte array, ephemeral_pk: byte array }
 *   - proof: byte array (ZkProof)
 *
 * BindingSignature:
 *   - signature: hex string (hex_bytes)
 */

export interface SpendDescription {
  anchor: string;           // hex string
  nullifier: number[];      // byte array [u8; 32]
  value_commitment: string; // hex string
  proof: SnarkJsProof;      // snarkjs proof object (NOT bytes)
  signature: string;        // hex string
  public_key: string;       // hex string
}

export interface OutputDescription {
  note_commitment: number[]; // byte array [u8; 32]
  value_commitment: string;  // hex string
  encrypted_note: {
    ciphertext: number[];    // byte array
    ephemeral_pk: number[];  // byte array
  };
  proof: SnarkJsProof;       // snarkjs proof object (NOT bytes)
}

export interface ShieldedTransaction {
  spends: SpendDescription[];
  outputs: OutputDescription[];
  fee: number;
  binding_sig: {
    signature: string;       // hex string
  };
}

export interface TransactionParams {
  spendNotes: WalletNote[];
  recipients: { pkHash: string; amount: bigint }[];
  fee: bigint;
  secretKey: Uint8Array;
  publicKey: Uint8Array;
  senderPkHash: Uint8Array;
  onProgress?: (status: string) => void;
}

/**
 * Compute a value commitment hash for use in ZK circuits.
 * This is used as a public input to bind the value to the proof.
 */
function computeValueCommitmentHash(value: bigint): bigint {
  return poseidonHash(DOMAIN_VALUE_COMMITMENT_HASH, [value]);
}

function toByteArray(bytes: Uint8Array): number[] {
  return Array.from(bytes);
}

/**
 * Convert path indices from position to binary array (0 = left, 1 = right).
 */
function positionToPathIndices(position: bigint, depth: number): number[] {
  const indices: number[] = [];
  let pos = position;
  for (let i = 0; i < depth; i++) {
    indices.push(Number(pos & 1n));
    pos >>= 1n;
  }
  return indices;
}

export async function createShieldedTransaction(
  params: TransactionParams
): Promise<ShieldedTransaction> {
  const { spendNotes, recipients, fee, secretKey, publicKey, senderPkHash, onProgress } = params;

  const progress = (msg: string) => {
    if (onProgress) onProgress(msg);
  };

  // Check if proving keys are loaded
  if (!areProvingKeysLoaded()) {
    throw new Error('Proving keys not loaded. Call loadProvingKeys() first.');
  }

  const totalSpend = spendNotes.reduce((sum, n) => sum + n.value, 0n);
  const totalOutput = recipients.reduce((sum, r) => sum + r.amount, 0n);
  const change = totalSpend - totalOutput - fee;

  if (change < 0n) {
    throw new Error(
      `Insufficient funds: spending ${totalSpend}, outputs ${totalOutput}, fee ${fee}`
    );
  }

  // Build output list (recipients + change)
  const outputParams: { pkHash: string; amount: bigint }[] = [...recipients];
  if (change > 0n) {
    outputParams.push({
      pkHash: bytesToHex(senderPkHash),
      amount: change,
    });
  }

  // Initialize binding context for tracking value commitments
  const bindingCtx = new BindingContext();
  bindingCtx.setFee(fee);

  const totalSteps = spendNotes.length + outputParams.length;
  let currentStep = 0;

  // Generate spend proofs sequentially with progress
  const spends: SpendDescription[] = [];
  for (let i = 0; i < spendNotes.length; i++) {
    currentStep++;
    progress(`Creating spend proof ${i + 1}/${spendNotes.length} (step ${currentStep}/${totalSteps})...`);

    // Create Pedersen value commitment for this spend
    const valueCommit = bindingCtx.addSpend(spendNotes[i].value);
    const valueCommitBytes = serializeCommitment(valueCommit);

    const spend = await createSpendDescription(
      spendNotes[i],
      secretKey,
      publicKey,
      valueCommitBytes
    );
    spends.push(spend);
  }

  // Derive viewing key for note encryption
  const viewingKey = deriveViewingKey(secretKey);

  // Generate output proofs sequentially with progress
  const outputs: OutputDescription[] = [];
  for (let i = 0; i < outputParams.length; i++) {
    currentStep++;
    const isChange = i === outputParams.length - 1 && change > 0n;
    const label = isChange ? 'change' : `recipient ${i + 1}`;
    progress(`Creating output proof for ${label} (step ${currentStep}/${totalSteps})...`);

    // Create Pedersen value commitment for this output
    const valueCommit = bindingCtx.addOutput(outputParams[i].amount);
    const valueCommitBytes = serializeCommitment(valueCommit);

    const output = await createOutputDescription(
      outputParams[i].pkHash,
      outputParams[i].amount,
      viewingKey,
      valueCommitBytes
    );
    outputs.push(output);
  }

  progress('Creating binding signature...');

  // Collect nullifiers and output commitments for binding message
  const nullifiers = spends.map(s => new Uint8Array(s.nullifier));
  const outputCommitments = outputs.map(o => new Uint8Array(o.note_commitment));

  // Create binding signature
  const bindingSig = bindingCtx.createSignature(nullifiers, outputCommitments);

  progress('Transaction complete.');

  return {
    spends,
    outputs,
    fee: Number(fee),
    binding_sig: {
      signature: bytesToHex(bindingSig),
    },
  };
}

const TREE_DEPTH = 32;

async function createSpendDescription(
  note: WalletNote,
  secretKey: Uint8Array,
  publicKey: Uint8Array,
  _valueCommitmentBytes: Uint8Array // Pedersen commitment (used for binding sig in caller)
): Promise<SpendDescription> {
  // Get Merkle witness from server
  let witness: WitnessResponse;
  try {
    witness = await getWitnessByPosition(note.position);
  } catch (e) {
    throw new Error(`Failed to get witness for position ${note.position}: ${e}`);
  }

  const anchor = witness.root;
  const nullifierHex = note.nullifier!;
  const nullifierBytes = hexToBytes(nullifierHex);

  // Compute value commitment hash for the ZK circuit public input
  // This is what the circuit uses as public input (Poseidon hash of value)
  const valueCommitmentHashFe = computeValueCommitmentHash(note.value);
  const valueCommitmentHashBytes = bigintToBytes32(valueCommitmentHashFe);
  const valueCommitmentHashHex = bytesToHex(valueCommitmentHashBytes);

  // Convert note data to field elements for the witness
  const merkleRootFe = bytes32ToBigint(hexToBytes(witness.root));
  const nullifierFe = bytes32ToBigint(nullifierBytes);
  const pkHashFe = bytes32ToBigint(hexToBytes(note.recipientPkHash));
  const randomnessFe = bytes32ToBigint(hexToBytes(note.randomness));

  // Derive nullifier key from secret key
  const { blake2s } = await import('@noble/hashes/blake2.js');
  const nullifierKeyBytes = blake2s(
    new Uint8Array([
      ...new TextEncoder().encode('Postera_NullifierKey'),
      ...secretKey,
    ]),
    { dkLen: 32 }
  );
  const nullifierKeyFe = bytes32ToBigint(nullifierKeyBytes);

  // Pad path elements to TREE_DEPTH
  const pathElements = witness.path.map((p) => bytes32ToBigint(hexToBytes(p)));
  while (pathElements.length < TREE_DEPTH) {
    pathElements.push(0n);
  }

  // Get path indices from position
  const pathIndices = positionToPathIndices(note.position, TREE_DEPTH);

  // Build spend witness for circuit
  const spendWitness: SpendWitness = {
    merkleRoot: merkleRootFe.toString(10),
    nullifier: nullifierFe.toString(10),
    valueCommitmentHash: valueCommitmentHashFe.toString(10),
    value: note.value.toString(10),
    recipientPkHash: pkHashFe.toString(10),
    noteRandomness: randomnessFe.toString(10),
    nullifierKey: nullifierKeyFe.toString(10),
    pathElements: pathElements.map((fe) => fe.toString(10)),
    pathIndices: pathIndices,
    position: note.position.toString(10),
  };

  // DEBUG: Compute note commitment and compare
  const { noteCommitment: computeCommitment } = await import('./poseidon');
  const computedCommitment = computeCommitment(note.value, pkHashFe, randomnessFe);
  const storedCommitment = bytes32ToBigint(hexToBytes(note.commitment));
  console.log('=== SPEND DEBUG ===');
  console.log('Note value:', note.value.toString());
  console.log('pkHashFe:', pkHashFe.toString(16));
  console.log('randomnessFe:', randomnessFe.toString(16));
  console.log('Computed commitment:', computedCommitment.toString(16));
  console.log('Stored commitment:', storedCommitment.toString(16));
  console.log('Commitments match:', computedCommitment === storedCommitment);
  console.log('Merkle root:', merkleRootFe.toString(16));
  console.log('Position:', note.position.toString());
  console.log('Path length:', witness.path.length);
  console.log('===================');

  // Generate ZK proof
  const { proof } = await generateSpendProof(spendWitness);

  // Sign the spend authorization
  // Message must match what Rust verifies: anchor + nullifier + value_commitment
  // value_commitment contains the hash (same as ZK public input)
  const message = new Uint8Array([
    ...hexToBytes(anchor),
    ...nullifierBytes,
    ...valueCommitmentHashBytes, // Use hash (same as sent in value_commitment field)
  ]);
  const signature = sign(message, secretKey);

  return {
    anchor,
    nullifier: toByteArray(nullifierBytes),
    value_commitment: valueCommitmentHashHex, // Send hash (matches ZK public input)
    proof: proof as SnarkJsProof, // Send proof object directly
    signature: bytesToHex(signature),
    public_key: bytesToHex(publicKey),
  };
}

async function createOutputDescription(
  recipientPkHashHex: string,
  amount: bigint,
  viewingKey: Uint8Array,
  _valueCommitmentBytes: Uint8Array // Pedersen commitment (used for binding sig in caller)
): Promise<OutputDescription> {
  const pkHash = hexToBytes(recipientPkHashHex);
  const randomness = generateRandomness();

  // Compute note commitment
  const commitment = computeNoteCommitment(amount, pkHash, randomness);
  const noteCommitmentFe = bytes32ToBigint(commitment);

  // Compute value commitment hash for the ZK circuit public input
  const valueCommitmentHashFe = computeValueCommitmentHash(amount);
  const valueCommitmentHashHex = bytesToHex(bigintToBytes32(valueCommitmentHashFe));

  // Build output witness for circuit
  const outputWitness: OutputWitness = {
    noteCommitment: noteCommitmentFe.toString(10),
    valueCommitmentHash: valueCommitmentHashFe.toString(10),
    value: amount.toString(10),
    recipientPkHash: bytes32ToBigint(pkHash).toString(10),
    noteRandomness: bytes32ToBigint(randomness).toString(10),
  };

  // Generate ZK proof
  const { proof } = await generateOutputProof(outputWitness);

  // Encrypt note for recipient using viewing key
  const encrypted = encryptNote(amount, pkHash, randomness, viewingKey);

  return {
    note_commitment: toByteArray(commitment),
    value_commitment: valueCommitmentHashHex, // Send hash (matches ZK public input)
    encrypted_note: {
      ciphertext: toByteArray(encrypted.ciphertext),
      ephemeral_pk: toByteArray(encrypted.ephemeralPk),
    },
    proof: proof as SnarkJsProof, // Send proof object directly
  };
}

export function estimateFee(numSpends: number, numOutputs: number): bigint {
  const baseFee = 1_000_000n;
  const perSpend = 500_000n;
  const perOutput = 500_000n;
  return baseFee + BigInt(numSpends) * perSpend + BigInt(numOutputs) * perOutput;
}

export function validateTransactionParams(params: TransactionParams): string | null {
  const { spendNotes, recipients, fee } = params;

  if (spendNotes.length === 0) {
    return 'No notes to spend';
  }

  if (recipients.length === 0) {
    return 'No recipients specified';
  }

  for (const note of spendNotes) {
    if (note.spent) {
      return `Note at position ${note.position} is already spent`;
    }
    if (!note.nullifier) {
      return `Note at position ${note.position} has no nullifier`;
    }
  }

  for (const recipient of recipients) {
    if (recipient.amount <= 0n) {
      return 'Recipient amount must be positive';
    }
    if (recipient.pkHash.length !== 64) {
      return 'Invalid recipient pk_hash length (expected 64 hex chars)';
    }
  }

  if (fee < 0n) {
    return 'Fee must be non-negative';
  }

  const totalSpend = spendNotes.reduce((sum, n) => sum + n.value, 0n);
  const totalOutput = recipients.reduce((sum, r) => sum + r.amount, 0n);

  if (totalSpend < totalOutput + fee) {
    return `Insufficient funds: have ${totalSpend}, need ${totalOutput + fee}`;
  }

  return null;
}

export function formatTransactionSummary(
  spendNotes: WalletNote[],
  recipients: { pkHash: string; amount: bigint }[],
  fee: bigint
): string {
  const DECIMALS = 9;
  const formatValue = (v: bigint) => {
    const divisor = 10n ** BigInt(DECIMALS);
    const whole = v / divisor;
    const frac = v % divisor;
    const fracStr = frac.toString().padStart(DECIMALS, '0').replace(/0+$/, '');
    return fracStr ? `${whole}.${fracStr}` : whole.toString();
  };

  const totalSpend = spendNotes.reduce((sum, n) => sum + n.value, 0n);
  const totalOutput = recipients.reduce((sum, r) => sum + r.amount, 0n);
  const change = totalSpend - totalOutput - fee;

  let summary = `Spending ${spendNotes.length} note(s) (${formatValue(totalSpend)} PSTR)\n`;
  summary += `Sending to ${recipients.length} recipient(s) (${formatValue(totalOutput)} PSTR)\n`;
  summary += `Fee: ${formatValue(fee)} PSTR\n`;
  if (change > 0n) {
    summary += `Change: ${formatValue(change)} PSTR`;
  }

  return summary;
}

// Re-export prover functions for convenient access
export { loadProvingKeys, areProvingKeysLoaded, setCircuitBasePath } from './prover';

// ============================================================================
// V2 Transaction Support (Post-Quantum)
// ============================================================================

import {
  generateTransactionProofPQ,
  type SpendWitnessPQ,
  type OutputWitnessPQ,
  type RiscZeroReceipt,
} from './prover-pq';
import {
  commitToNotePQ,
  generateRandomnessPQ,
} from './commitment-pq';
import { bytesToGoldilocks, goldilocksToBytes } from './poseidon-pq';

/**
 * V2 spend description (post-quantum).
 * No value commitment or individual proof - balance proven in combined proof.
 */
export interface SpendDescriptionV2 {
  anchor: string;           // hex string
  nullifier: Uint8Array;    // 32 bytes
  signature: string;        // hex string (ML-DSA-65)
  public_key: string;       // hex string (ML-DSA-65)
}

/**
 * V2 output description (post-quantum).
 * No value commitment or individual proof.
 */
export interface OutputDescriptionV2 {
  note_commitment: Uint8Array;  // 32 bytes (Poseidon/Goldilocks)
  encrypted_note: {
    ciphertext: Uint8Array;
    ephemeral_pk: Uint8Array;
  };
}

/**
 * V2 shielded transaction (post-quantum).
 */
export interface ShieldedTransactionV2 {
  version: 2;
  spends: SpendDescriptionV2[];
  outputs: OutputDescriptionV2[];
  fee: number;
  transaction_proof: {
    receipt_bytes: string;  // hex
    image_id: string;       // hex
  };
}

/**
 * Transaction creation options.
 */
export interface TransactionOptions {
  /** Transaction version: 1 (legacy) or 2 (post-quantum) */
  version?: 1 | 2;
}

/**
 * Create a shielded transaction (supports both V1 and V2).
 *
 * @param params - Transaction parameters
 * @param options - Transaction options (version selection)
 * @returns V1 or V2 transaction based on version option
 */
export async function createShieldedTransactionVersioned(
  params: TransactionParams,
  options: TransactionOptions = { version: 2 }
): Promise<ShieldedTransaction | ShieldedTransactionV2> {
  if (options.version === 2) {
    return createShieldedTransactionV2(params);
  }
  return createShieldedTransaction(params);
}

/**
 * Create a V2 (post-quantum) shielded transaction.
 *
 * This uses:
 * - Hash-based commitments (Poseidon/Goldilocks)
 * - Combined STARK proof (RISC Zero)
 * - ML-DSA-65 signatures (already quantum-safe)
 *
 * No binding signature needed - balance is proven in the STARK.
 */
export async function createShieldedTransactionV2(
  params: TransactionParams
): Promise<ShieldedTransactionV2> {
  const { spendNotes, recipients, fee, secretKey, publicKey, senderPkHash, onProgress } = params;

  const progress = (msg: string) => {
    if (onProgress) onProgress(msg);
  };

  // Calculate totals
  const totalSpend = spendNotes.reduce((sum, n) => sum + n.value, 0n);
  const totalOutput = recipients.reduce((sum, r) => sum + r.amount, 0n);
  const change = totalSpend - totalOutput - fee;

  if (change < 0n) {
    throw new Error(
      `Insufficient funds: spending ${totalSpend}, outputs ${totalOutput}, fee ${fee}`
    );
  }

  // Build output list
  const outputParams: { pkHash: string; amount: bigint }[] = [...recipients];
  if (change > 0n) {
    outputParams.push({
      pkHash: bytesToHex(senderPkHash),
      amount: change,
    });
  }

  const totalSteps = spendNotes.length + outputParams.length + 1;
  let currentStep = 0;

  // Build spend witnesses for STARK proof
  progress('Building spend witnesses...');
  const spendWitnesses: SpendWitnessPQ[] = [];
  const spendDescriptions: SpendDescriptionV2[] = [];

  for (let i = 0; i < spendNotes.length; i++) {
    currentStep++;
    progress(`Processing spend ${i + 1}/${spendNotes.length} (step ${currentStep}/${totalSteps})...`);

    const note = spendNotes[i];

    // Get Merkle witness from server
    const witness = await getWitnessByPosition(note.position);

    // Build spend witness for STARK
    const spendWitness: SpendWitnessPQ = {
      value: note.value,
      recipientPkHash: hexToBytes(note.recipientPkHash),
      randomness: hexToBytes(note.randomness),
      nullifierKey: deriveNullifierKey(secretKey),
      position: note.position,
      merkleRoot: hexToBytes(witness.root),
      merklePath: witness.path.map((p) => hexToBytes(p)),
      pathIndices: positionToPathIndices(note.position, 32),
    };
    spendWitnesses.push(spendWitness);
  }

  // Build output witnesses for STARK proof
  progress('Building output witnesses...');
  const outputWitnesses: OutputWitnessPQ[] = [];
  const outputDescriptions: OutputDescriptionV2[] = [];
  const viewingKey = deriveViewingKey(secretKey);

  for (let i = 0; i < outputParams.length; i++) {
    currentStep++;
    const isChange = i === outputParams.length - 1 && change > 0n;
    const label = isChange ? 'change' : `recipient ${i + 1}`;
    progress(`Processing output for ${label} (step ${currentStep}/${totalSteps})...`);

    const { pkHash, amount } = outputParams[i];
    const pkHashBytes = hexToBytes(pkHash);
    const randomness = generateRandomnessPQ();

    // Build output witness for STARK
    outputWitnesses.push({
      value: amount,
      recipientPkHash: pkHashBytes,
      randomness,
    });

    // Compute PQ commitment
    const commitment = commitToNotePQ(amount, pkHashBytes, randomness);

    // Encrypt note
    const encrypted = encryptNote(amount, pkHashBytes, randomness, viewingKey);

    outputDescriptions.push({
      note_commitment: commitment,
      encrypted_note: {
        ciphertext: encrypted.ciphertext,
        ephemeral_pk: encrypted.ephemeralPk,
      },
    });
  }

  // Generate combined STARK proof
  currentStep++;
  progress(`Generating STARK proof (step ${currentStep}/${totalSteps})...`);

  const receipt = await generateTransactionProofPQ(
    spendWitnesses,
    outputWitnesses,
    fee
  );

  // Sign spends with ML-DSA-65
  progress('Signing spends...');

  for (let i = 0; i < spendNotes.length; i++) {
    const message = receipt.journal.spendMessages[i];
    const signature = sign(message, secretKey);

    spendDescriptions.push({
      anchor: bytesToHex(spendWitnesses[i].merkleRoot),
      nullifier: receipt.journal.nullifiers[i],
      signature: bytesToHex(signature),
      public_key: bytesToHex(publicKey),
    });
  }

  progress('V2 transaction complete.');

  return {
    version: 2,
    spends: spendDescriptions,
    outputs: outputDescriptions,
    fee: Number(fee),
    transaction_proof: {
      receipt_bytes: bytesToHex(receipt.receiptBytes),
      image_id: bytesToHex(receipt.imageId),
    },
  };
}

/**
 * Estimate fee for a V2 transaction.
 * V2 transactions have different size characteristics than V1.
 */
export function estimateFeeV2(numSpends: number, numOutputs: number): bigint {
  // V2 fees are generally lower per-spend due to combined proof
  const baseFee = 1_500_000n;
  const perSpend = 300_000n;  // Lower than V1
  const perOutput = 300_000n; // Lower than V1
  const proofFee = 500_000n;  // Fixed cost for STARK proof
  return baseFee + BigInt(numSpends) * perSpend + BigInt(numOutputs) * perOutput + proofFee;
}

/**
 * Validate V2 transaction parameters.
 */
export function validateTransactionParamsV2(params: TransactionParams): string | null {
  // Same validation as V1
  return validateTransactionParams(params);
}

/**
 * Format V2 transaction summary.
 */
export function formatTransactionSummaryV2(
  spendNotes: WalletNote[],
  recipients: { pkHash: string; amount: bigint }[],
  fee: bigint
): string {
  const summary = formatTransactionSummary(spendNotes, recipients, fee);
  return `[V2/Post-Quantum]\n${summary}`;
}
