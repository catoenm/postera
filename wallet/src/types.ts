export interface Wallet {
  address: string;
  public_key: string;
  secret_key: string;
}

export interface Account {
  address: string;
  balance: number;
  nonce: number;
}

export interface Transaction {
  hash: string;
  from: string;
  to: string;
  amount: number;
  fee: number;
  nonce: number;
  status?: 'pending' | 'confirmed';
}
