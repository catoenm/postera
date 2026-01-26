import { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import './Explorer.css';

interface ChainInfo {
  height: number;
  difficulty: number;
  commitment_count: number;
  nullifier_count: number;
}

interface Block {
  height: number;
  hash: string;
  tx_count: number;
  timestamp: number;
}

interface Transaction {
  hash: string;
  fee: number;
  spend_count: number;
  output_count: number;
  status: 'pending' | 'confirmed';
  block_height: number | null;
}

const COIN = 1_000_000_000;

function formatAmount(amount: number): string {
  return (amount / COIN).toFixed(2);
}

export default function Explorer() {
  const [chainInfo, setChainInfo] = useState<ChainInfo | null>(null);
  const [blocks, setBlocks] = useState<Block[]>([]);
  const [transactions, setTransactions] = useState<Transaction[]>([]);
  const [mempoolCount, setMempoolCount] = useState(0);
  const [search, setSearch] = useState('');

  const fetchData = useCallback(async () => {
    try {
      // Fetch chain info
      const infoRes = await fetch('/chain/info');
      const info: ChainInfo = await infoRes.json();
      setChainInfo(info);

      // Fetch mempool
      const mempoolRes = await fetch('/mempool');
      const mempool = await mempoolRes.json();
      setMempoolCount(mempool.count);

      // Fetch recent blocks
      const fetchedBlocks: Block[] = [];
      for (let h = info.height; h >= Math.max(0, info.height - 9); h--) {
        const blockRes = await fetch(`/block/height/${h}`);
        if (blockRes.ok) {
          fetchedBlocks.push(await blockRes.json());
        }
      }
      setBlocks(fetchedBlocks);

      // Fetch recent transactions (privacy-preserving: only shows fees, not amounts)
      const txRes = await fetch('/transactions/recent');
      const txs: Transaction[] = await txRes.json();
      setTransactions(txs);
    } catch (e) {
      console.error('Failed to fetch data:', e);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, [fetchData]);

  const handleSearch = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      const query = search.trim();
      if (query.length === 64) {
        window.location.href = `/block/${query}`;
      } else if (query.length === 40) {
        window.location.href = `/account/${query}`;
      }
    }
  };

  return (
    <div className="container">
      <nav className="nav-tabs">
        <Link to="/explorer" className="active">Explorer</Link>
        <Link to="/wallet">Wallet</Link>
      </nav>

      <h1>Postera Explorer</h1>
      <p className="subtitle">Quantum-resistant blockchain explorer</p>

      <input
        type="text"
        className="search"
        placeholder="Search by block hash or address..."
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        onKeyPress={handleSearch}
      />

      <div className="card">
        <div className="stats-grid">
          <div className="stat">
            <div className="stat-value">{chainInfo?.height ?? '-'}</div>
            <div className="stat-label">Block Height</div>
          </div>
          <div className="stat">
            <div className="stat-value">{chainInfo?.difficulty ?? '-'}</div>
            <div className="stat-label">Difficulty</div>
          </div>
          <div className="stat">
            <div className="stat-value">{chainInfo?.commitment_count ?? '-'}</div>
            <div className="stat-label">Commitments</div>
          </div>
          <div className="stat">
            <div className="stat-value">{chainInfo?.nullifier_count ?? '-'}</div>
            <div className="stat-label">Nullifiers</div>
          </div>
          <div className="stat">
            <div className="stat-value">{mempoolCount}</div>
            <div className="stat-label">Pending Txs</div>
          </div>
        </div>
      </div>

      <h2>Recent Blocks</h2>
      <div className="card">
        <table>
          <thead>
            <tr>
              <th>Height</th>
              <th>Hash</th>
              <th>Transactions</th>
              <th>Time</th>
            </tr>
          </thead>
          <tbody>
            {blocks.length === 0 ? (
              <tr><td colSpan={4} className="loading">Loading...</td></tr>
            ) : (
              blocks.map((b) => (
                <tr key={b.hash}>
                  <td>{b.height}</td>
                  <td className="hash">{b.hash.substring(0, 16)}...</td>
                  <td>{b.tx_count}</td>
                  <td>{new Date(b.timestamp * 1000).toLocaleString()}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <h2>Recent Transactions</h2>
      <p className="privacy-note">Transaction amounts and addresses are private. Only fees are visible.</p>
      <div className="card">
        <table>
          <thead>
            <tr>
              <th>Hash</th>
              <th>Spends</th>
              <th>Outputs</th>
              <th>Fee</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {transactions.length === 0 ? (
              <tr><td colSpan={5} className="loading">No transactions yet</td></tr>
            ) : (
              transactions.map((tx) => (
                <tr key={tx.hash}>
                  <td className="hash">{tx.hash.substring(0, 16)}...</td>
                  <td>{tx.spend_count}</td>
                  <td>{tx.output_count}</td>
                  <td>{formatAmount(tx.fee)} PSTR</td>
                  <td>
                    <span className={`badge ${tx.status}`}>
                      {tx.status}{tx.block_height !== null ? ` #${tx.block_height}` : ''}
                    </span>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <div className="card info-card">
        <h3>Privacy Notice</h3>
        <p>
          This is a shielded blockchain. Account balances, transaction amounts, and
          sender/receiver addresses are encrypted and not visible on-chain.
        </p>
        <p>
          Only you can see your balance by decrypting your notes with your private key.
        </p>
      </div>
    </div>
  );
}
