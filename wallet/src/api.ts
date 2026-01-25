import type { Account, Transaction } from './types';

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
