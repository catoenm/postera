import { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import {
  generateKeyPair,
  deriveAddress,
  bytesToHex,
  hexToBytes,
  sign,
  createSigningMessage,
  MLDSA65_PK_SIZE,
  MLDSA65_SK_SIZE,
} from './crypto';
import { getAccount, getTransactions, submitTransaction } from './api';
import type { Wallet as WalletType, Account, Transaction } from './types';
import './App.css';

const STORAGE_KEY = 'postera_wallet';
const COIN = 1_000_000_000n; // 1 coin = 10^9 base units

function formatAmount(amount: number): string {
  return (amount / Number(COIN)).toFixed(6);
}

export default function Wallet() {
  const [wallet, setWallet] = useState<WalletType | null>(null);
  const [account, setAccount] = useState<Account | null>(null);
  const [transactions, setTransactions] = useState<Transaction[]>([]);
  const [loading, setLoading] = useState(true);
  const [view, setView] = useState<'wallet' | 'send' | 'receive' | 'history'>('wallet');

  // Send form state
  const [sendTo, setSendTo] = useState('');
  const [sendAmount, setSendAmount] = useState('');
  const [sendFee, setSendFee] = useState('0.000001');
  const [sendStatus, setSendStatus] = useState<{ type: 'success' | 'error' | 'loading'; message: string } | null>(null);

  // Import form state
  const [showImport, setShowImport] = useState(false);
  const [importPk, setImportPk] = useState('');
  const [importSk, setImportSk] = useState('');

  // Show keys state
  const [showKeys, setShowKeys] = useState(false);

  // Load wallet from storage
  useEffect(() => {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) {
      try {
        setWallet(JSON.parse(stored));
      } catch (e) {
        console.error('Failed to load wallet:', e);
      }
    }
    setLoading(false);
  }, []);

  // Refresh account balance
  const refreshBalance = useCallback(async () => {
    if (!wallet) return;
    const acc = await getAccount(wallet.address);
    setAccount(acc);
  }, [wallet]);

  // Load transactions
  const loadTransactions = useCallback(async () => {
    if (!wallet) return;
    const txs = await getTransactions(wallet.address);
    setTransactions(txs);
  }, [wallet]);

  // Refresh data when wallet changes
  useEffect(() => {
    if (wallet) {
      refreshBalance();
      loadTransactions();
      // Set up polling
      const interval = setInterval(() => {
        refreshBalance();
        loadTransactions();
      }, 10000);
      return () => clearInterval(interval);
    }
  }, [wallet, refreshBalance, loadTransactions]);

  // Create new wallet
  const createWallet = async () => {
    setLoading(true);
    try {
      const { publicKey, secretKey } = generateKeyPair();
      const address = await deriveAddress(publicKey);

      const newWallet: WalletType = {
        address,
        public_key: bytesToHex(publicKey),
        secret_key: bytesToHex(secretKey),
      };

      localStorage.setItem(STORAGE_KEY, JSON.stringify(newWallet));
      setWallet(newWallet);
    } catch (e) {
      alert('Failed to create wallet: ' + (e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  // Import wallet
  const importWallet = async () => {
    const pk = importPk.trim();
    const sk = importSk.trim();

    if (!pk || !sk) {
      alert('Please enter both public and secret keys');
      return;
    }

    if (pk.length !== MLDSA65_PK_SIZE * 2) {
      alert(`Invalid public key length. Expected ${MLDSA65_PK_SIZE * 2} hex characters`);
      return;
    }

    if (sk.length !== MLDSA65_SK_SIZE * 2) {
      alert(`Invalid secret key length. Expected ${MLDSA65_SK_SIZE * 2} hex characters`);
      return;
    }

    try {
      const publicKeyBytes = hexToBytes(pk);
      const address = await deriveAddress(publicKeyBytes);

      const newWallet: WalletType = {
        address,
        public_key: pk,
        secret_key: sk,
      };

      localStorage.setItem(STORAGE_KEY, JSON.stringify(newWallet));
      setWallet(newWallet);
      setShowImport(false);
      setImportPk('');
      setImportSk('');
    } catch (e) {
      alert('Failed to import wallet: ' + (e as Error).message);
    }
  };

  // Logout
  const logout = () => {
    if (confirm('Are you sure you want to logout? Make sure you have backed up your keys!')) {
      localStorage.removeItem(STORAGE_KEY);
      setWallet(null);
      setAccount(null);
      setTransactions([]);
    }
  };

  // Send transaction
  const handleSend = async () => {
    if (!wallet) return;

    const to = sendTo.trim();
    if (!to || to.length !== 40) {
      setSendStatus({ type: 'error', message: 'Invalid recipient address (40 hex characters)' });
      return;
    }

    const amountCoins = parseFloat(sendAmount);
    if (!amountCoins || amountCoins <= 0) {
      setSendStatus({ type: 'error', message: 'Invalid amount' });
      return;
    }

    const feeCoins = parseFloat(sendFee) || 0.000001;
    const amount = BigInt(Math.round(amountCoins * Number(COIN)));
    const fee = BigInt(Math.round(feeCoins * Number(COIN)));

    setSendStatus({ type: 'loading', message: 'Fetching account nonce...' });

    try {
      // Get current nonce
      const acc = await getAccount(wallet.address);
      const nonce = BigInt(acc?.nonce || 0);

      setSendStatus({ type: 'loading', message: 'Signing transaction...' });

      // Build and sign transaction
      const signingMessage = createSigningMessage(
        wallet.address,
        to,
        amount,
        fee,
        nonce,
        wallet.public_key
      );

      const secretKeyBytes = hexToBytes(wallet.secret_key);
      const signatureBytes = sign(signingMessage, secretKeyBytes);
      const signature = bytesToHex(signatureBytes);

      setSendStatus({ type: 'loading', message: 'Submitting transaction...' });

      // Submit
      const fromBytes = Array.from(hexToBytes(wallet.address));
      const toBytes = Array.from(hexToBytes(to));

      const result = await submitTransaction({
        from: fromBytes,
        to: toBytes,
        amount: Number(amount),
        fee: Number(fee),
        nonce: Number(nonce),
        public_key: wallet.public_key,
        signature,
      });

      if ('error' in result) {
        setSendStatus({ type: 'error', message: result.error });
      } else {
        setSendStatus({ type: 'success', message: `Transaction sent! Hash: ${result.hash.slice(0, 16)}...` });
        setSendTo('');
        setSendAmount('');
        setTimeout(() => {
          refreshBalance();
          loadTransactions();
        }, 1000);
      }
    } catch (e) {
      setSendStatus({ type: 'error', message: (e as Error).message });
    }
  };

  // Loading state
  if (loading) {
    return (
      <div className="container">
        <div className="loading">Loading...</div>
      </div>
    );
  }

  // No wallet - show create/import
  if (!wallet) {
    return (
      <div className="container">
        <h1>Postera Wallet</h1>
        <p className="subtitle">Quantum-resistant cryptocurrency wallet</p>

        <div className="card info">
          <strong>Post-Quantum Security</strong>
          <p>Uses ML-DSA-65 (FIPS 204) for quantum-resistant signatures.</p>
          <p>All keys are generated and stored locally in your browser.</p>
        </div>

        <div className="card">
          <h2>Get Started</h2>
          <button onClick={createWallet}>Create New Wallet</button>
          <button className="secondary" onClick={() => setShowImport(true)}>
            Import Existing Wallet
          </button>
        </div>

        {showImport && (
          <div className="card">
            <h2>Import Wallet</h2>
            <div className="form-group">
              <label>Public Key (hex)</label>
              <textarea
                value={importPk}
                onChange={(e) => setImportPk(e.target.value)}
                placeholder="Enter your public key..."
              />
            </div>
            <div className="form-group">
              <label>Secret Key (hex)</label>
              <textarea
                value={importSk}
                onChange={(e) => setImportSk(e.target.value)}
                placeholder="Enter your secret key..."
              />
            </div>
            <button onClick={importWallet}>Import</button>
            <button className="secondary" onClick={() => setShowImport(false)}>
              Cancel
            </button>
          </div>
        )}
      </div>
    );
  }

  // Wallet view
  return (
    <div className="container">
      <h1>Postera Wallet</h1>
      <p className="subtitle">Quantum-resistant cryptocurrency</p>

      <nav className="nav-tabs">
        <Link to="/explorer">Explorer</Link>
        <a className={view === 'wallet' ? 'active' : ''} onClick={() => setView('wallet')}>
          Wallet
        </a>
        <a className={view === 'send' ? 'active' : ''} onClick={() => setView('send')}>
          Send
        </a>
        <a className={view === 'receive' ? 'active' : ''} onClick={() => setView('receive')}>
          Receive
        </a>
        <a className={view === 'history' ? 'active' : ''} onClick={() => setView('history')}>
          History
        </a>
      </nav>

      {view === 'wallet' && (
        <>
          <div className="card">
            <h2>Balance</h2>
            <div className="balance">
              {account ? formatAmount(account.balance) : '0.000000'} PSTR
            </div>
            <p className="address">
              <span className="label">Address:</span>
              <code>{wallet.address}</code>
            </p>
            <button className="secondary" onClick={refreshBalance}>
              Refresh
            </button>
          </div>

          <div className="card">
            <h2>Backup Keys</h2>
            <p className="warning">Save these keys securely. If you lose them, you lose access to your funds.</p>
            <button className="secondary" onClick={() => setShowKeys(!showKeys)}>
              {showKeys ? 'Hide Keys' : 'Show Keys'}
            </button>
            <button className="danger" onClick={logout}>
              Logout
            </button>

            {showKeys && (
              <div className="keys-display">
                <div className="form-group">
                  <label>Public Key (1952 bytes)</label>
                  <textarea readOnly value={wallet.public_key} />
                </div>
                <div className="form-group">
                  <label>Secret Key (4032 bytes)</label>
                  <textarea readOnly value={wallet.secret_key} />
                </div>
              </div>
            )}
          </div>
        </>
      )}

      {view === 'send' && (
        <div className="card">
          <h2>Send PSTR</h2>
          <div className="form-group">
            <label>Recipient Address</label>
            <input
              type="text"
              value={sendTo}
              onChange={(e) => setSendTo(e.target.value)}
              placeholder="Enter recipient address..."
            />
          </div>
          <div className="form-group">
            <label>Amount (PSTR)</label>
            <input
              type="number"
              step="0.000001"
              value={sendAmount}
              onChange={(e) => setSendAmount(e.target.value)}
              placeholder="0.000000"
            />
          </div>
          <div className="form-group">
            <label>Fee (PSTR)</label>
            <input
              type="number"
              step="0.000001"
              value={sendFee}
              onChange={(e) => setSendFee(e.target.value)}
            />
          </div>
          <button onClick={handleSend} disabled={sendStatus?.type === 'loading'}>
            {sendStatus?.type === 'loading' ? 'Sending...' : 'Send'}
          </button>

          {sendStatus && (
            <div className={`status-message ${sendStatus.type}`}>
              {sendStatus.message}
            </div>
          )}
        </div>
      )}

      {view === 'receive' && (
        <div className="card">
          <h2>Receive PSTR</h2>
          <p>Share your address to receive funds:</p>
          <div className="address-display">
            <code>{wallet.address}</code>
          </div>
          <button
            className="secondary"
            onClick={() => navigator.clipboard.writeText(wallet.address)}
          >
            Copy Address
          </button>
        </div>
      )}

      {view === 'history' && (
        <div className="card">
          <h2>Transaction History</h2>
          <button className="secondary" onClick={loadTransactions}>
            Refresh
          </button>

          {transactions.length === 0 ? (
            <p className="empty">No transactions yet</p>
          ) : (
            <ul className="tx-list">
              {transactions.map((tx) => (
                <li key={tx.hash} className="tx-item">
                  <div className="tx-row">
                    <span
                      className={`tx-amount ${tx.from === wallet.address ? 'sent' : 'received'}`}
                    >
                      {tx.from === wallet.address ? '-' : '+'}
                      {formatAmount(tx.amount)} PSTR
                    </span>
                    <span className={`status ${tx.status || 'pending'}`}>
                      {tx.status || 'pending'}
                    </span>
                  </div>
                  <div className="tx-hash">{tx.hash.slice(0, 32)}...</div>
                  <div className="tx-parties">
                    {tx.from === wallet.address
                      ? `To: ${tx.to.slice(0, 8)}...`
                      : `From: ${tx.from.slice(0, 8)}...`}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
