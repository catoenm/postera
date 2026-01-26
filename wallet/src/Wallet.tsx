import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  generateKeyPair,
  deriveAddress,
  bytesToHex,
  hexToBytes,
  sign,
  MLDSA65_PK_SIZE,
  MLDSA65_SK_SIZE,
} from './crypto';
import type { Wallet as WalletType } from './types';
import './App.css';

const STORAGE_KEY = 'postera_wallet';

export default function Wallet() {
  const [wallet, setWallet] = useState<WalletType | null>(null);
  const [loading, setLoading] = useState(true);
  const [view, setView] = useState<'wallet' | 'send' | 'receive' | 'sign'>('wallet');

  // Sign message state
  const [messageToSign, setMessageToSign] = useState('');
  const [signedResult, setSignedResult] = useState<{ message: string; signature: string } | null>(null);

  // Send form state (disabled for now - shielded transactions not yet implemented)
  const [sendTo, setSendTo] = useState('');
  const [sendAmount, setSendAmount] = useState('');

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
    }
  };

  // Sign arbitrary message
  const handleSignMessage = () => {
    if (!wallet) return;
    if (!messageToSign.trim()) {
      alert('Please enter a message to sign');
      return;
    }

    try {
      const messageBytes = new TextEncoder().encode(messageToSign);
      const secretKeyBytes = hexToBytes(wallet.secret_key);
      const signatureBytes = sign(messageBytes, secretKeyBytes);
      const signature = bytesToHex(signatureBytes);

      setSignedResult({
        message: messageToSign,
        signature,
      });
    } catch (e) {
      alert('Failed to sign message: ' + (e as Error).message);
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
        <a className={view === 'sign' ? 'active' : ''} onClick={() => setView('sign')}>
          Sign
        </a>
      </nav>

      {view === 'wallet' && (
        <>
          <div className="card">
            <h2>Shielded Balance</h2>
            <div className="balance shielded">
              [Shielded]
            </div>
            <p className="shielded-note">
              Your balance is encrypted on-chain. Note scanning coming soon.
            </p>
            <p className="address">
              <span className="label">Public Key Hash:</span>
              <code>{wallet.address}</code>
            </p>
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
          <p className="shielded-note">
            Shielded transactions require ZK proof generation. Coming soon.
          </p>
          <div className="form-group disabled">
            <label>Recipient Public Key Hash</label>
            <input
              type="text"
              value={sendTo}
              onChange={(e) => setSendTo(e.target.value)}
              placeholder="Enter recipient pk_hash..."
              disabled
            />
          </div>
          <div className="form-group disabled">
            <label>Amount (PSTR)</label>
            <input
              type="number"
              step="0.000001"
              value={sendAmount}
              onChange={(e) => setSendAmount(e.target.value)}
              placeholder="0.000000"
              disabled
            />
          </div>
          <button disabled>
            Send (Coming Soon)
          </button>
        </div>
      )}

      {view === 'receive' && (
        <div className="card">
          <h2>Receive PSTR</h2>
          <p>Share your public key hash to receive shielded funds:</p>
          <div className="form-group">
            <label>Your Public Key Hash (pk_hash)</label>
            <div className="address-display">
              <code>{wallet.address}</code>
            </div>
          </div>
          <button
            className="secondary"
            onClick={() => navigator.clipboard.writeText(wallet.address)}
          >
            Copy pk_hash
          </button>
          <p className="shielded-note" style={{ marginTop: '16px' }}>
            Senders will encrypt notes to your pk_hash. Only you can decrypt them.
          </p>
        </div>
      )}

      {view === 'sign' && (
        <div className="card">
          <h2>Sign Message</h2>
          <p className="info-text">
            Sign any message with your private key. This proves you control this wallet
            without revealing your secret key. The signature is created entirely in your browser.
          </p>
          <div className="form-group">
            <label>Message to Sign</label>
            <textarea
              value={messageToSign}
              onChange={(e) => setMessageToSign(e.target.value)}
              placeholder="Enter any text to sign..."
              rows={4}
            />
          </div>
          <button onClick={handleSignMessage}>
            Sign Message
          </button>

          {signedResult && (
            <div className="sign-result">
              <div className="form-group">
                <label>Original Message</label>
                <textarea readOnly value={signedResult.message} rows={2} />
              </div>
              <div className="form-group">
                <label>Signature (ML-DSA-65, {signedResult.signature.length / 2} bytes)</label>
                <textarea readOnly value={signedResult.signature} rows={6} />
              </div>
              <div className="form-group">
                <label>Your Public Key (for verification)</label>
                <textarea readOnly value={wallet.public_key} rows={4} />
              </div>
              <button
                className="secondary"
                onClick={() => navigator.clipboard.writeText(JSON.stringify({
                  message: signedResult.message,
                  signature: signedResult.signature,
                  public_key: wallet.public_key,
                  address: wallet.address,
                }, null, 2))}
              >
                Copy All (JSON)
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
