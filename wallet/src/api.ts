import type {
  Account,
  Transaction,
  OutputsSinceResponse,
  CheckNullifiersResponse,
  WitnessResponse,
} from './types';

// API base URL - use relative paths in production, configurable for dev
const API_BASE = '';

export async function getAccount(address: string): Promise<Account | null> {
  try {
    const res = await fetch(`${API_BASE}/account/${address}`);
    if (!res.ok) return null;
    return res.json();
  } catch {
    return null;
  }
}

export async function getTransactions(address: string): Promise<Transaction[]> {
  try {
    const res = await fetch(`${API_BASE}/transactions/${address}`);
    if (!res.ok) return [];
    return res.json();
  } catch {
    return [];
  }
}

export interface SubmitTxRequest {
  from: number[];
  to: number[];
  amount: number;
  fee: number;
  nonce: number;
  public_key: string;
  signature: string;
}

export async function submitTransaction(tx: SubmitTxRequest): Promise<{ hash: string } | { error: string }> {
  const res = await fetch(`${API_BASE}/tx`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ transaction: tx }),
  });

  const data = await res.json();
  if (!res.ok) {
    return { error: typeof data === 'string' ? data : JSON.stringify(data) };
  }
  return data;
}

// ============ Shielded Wallet API ============

/**
 * Get all encrypted outputs since a given block height.
 * Used for scanning the blockchain for incoming notes.
 */
export async function getOutputsSince(height: number): Promise<OutputsSinceResponse> {
  const res = await fetch(`${API_BASE}/outputs/since/${height}`);
  if (!res.ok) {
    throw new Error(`Failed to fetch outputs: ${res.status}`);
  }
  return res.json();
}

/**
 * Check which nullifiers are spent.
 * Used to determine which of our notes have been consumed.
 */
export async function checkNullifiers(nullifiers: string[]): Promise<CheckNullifiersResponse> {
  const res = await fetch(`${API_BASE}/nullifiers/check`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ nullifiers }),
  });
  if (!res.ok) {
    throw new Error(`Failed to check nullifiers: ${res.status}`);
  }
  return res.json();
}

/**
 * Get a Merkle witness for a commitment.
 * Used when creating spend proofs.
 */
export async function getWitness(commitment: string): Promise<WitnessResponse> {
  const res = await fetch(`${API_BASE}/witness/${commitment}`);
  if (!res.ok) {
    throw new Error(`Failed to get witness: ${res.status}`);
  }
  return res.json();
}

/**
 * Get a Merkle witness by position (more reliable than by commitment).
 */
export async function getWitnessByPosition(position: number | bigint): Promise<WitnessResponse> {
  const res = await fetch(`${API_BASE}/witness/position/${position}`);
  if (!res.ok) {
    throw new Error(`Failed to get witness by position: ${res.status}`);
  }
  return res.json();
}

/**
 * Submit a V1 shielded transaction.
 */
export async function submitShieldedTransaction(tx: unknown): Promise<{ hash: string; status: string } | { error: string }> {
  const res = await fetch(`${API_BASE}/tx`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ transaction: tx }),
  });

  // Handle both JSON and plain text responses
  const text = await res.text();
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    // Response was plain text
    if (!res.ok) {
      return { error: text };
    }
    return { error: `Unexpected response: ${text}` };
  }

  if (!res.ok) {
    return { error: typeof data === 'string' ? data : JSON.stringify(data) };
  }
  return data as { hash: string; status: string };
}

/**
 * Submit a V2 (post-quantum) shielded transaction.
 */
export async function submitShieldedTransactionV2(tx: unknown): Promise<{ hash: string; status: string } | { error: string }> {
  const res = await fetch(`${API_BASE}/tx/v2`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ transaction: tx }),
  });

  // Handle both JSON and plain text responses
  const text = await res.text();
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    // Response was plain text
    if (!res.ok) {
      return { error: text };
    }
    return { error: `Unexpected response: ${text}` };
  }

  if (!res.ok) {
    return { error: typeof data === 'string' ? data : JSON.stringify(data) };
  }
  return data as { hash: string; status: string };
}

/**
 * Get chain info (height, difficulty, etc.)
 */
export async function getChainInfo(): Promise<{
  height: number;
  latest_hash: string;
  difficulty: number;
  commitment_count: number;
  nullifier_count: number;
}> {
  const res = await fetch(`${API_BASE}/chain/info`);
  if (!res.ok) {
    throw new Error(`Failed to get chain info: ${res.status}`);
  }
  return res.json();
}
