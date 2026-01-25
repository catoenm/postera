import { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import './Explorer.css';

interface ChainInfo {
  height: number;
  difficulty: number;
  total_accounts: number;
}

interface Block {
  height: number;
  hash: string;
  tx_count: number;
  timestamp: number;
}

interface Transaction {
  hash: string;
  from: string;
  to: string;
  amount: number;
  is_coinbase: boolean;
  status: 'pending' | 'confirmed';
  block_height: number | null;
}

interface Holder {
  address: string;
  balance: number;
  nonce: number;
}

const COIN = 1_000_000_000;

function formatAmount(amount: number): string {
  return (amount / COIN).toFixed(2);
}

export default function Explorer() {
  const [chainInfo, setChainInfo] = useState<ChainInfo | null>(null);
  const [blocks, setBlocks] = useState<Block[]>([]);
  const [transactions, setTransactions] = useState<Transaction[]>([]);
  const [holders, setHolders] = useState<Holder[]>([]);
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

      // Fetch recent transactions
      const txRes = await fetch('/transactions/recent');
      const txs: Transaction[] = await txRes.json();
      setTransactions(txs);

      // Fetch top holders
      const holdersRes = await fetch('/accounts/top');
      const h: Holder[] = await holdersRes.json();
      setHolders(h);
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
            <div className="stat-value">{chainInfo?.total_accounts ?? '-'}</div>
            <div className="stat-label">Accounts</div>
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
      <div className="card">
        <table>
          <thead>
            <tr>
              <th>Hash</th>
              <th>From</th>
              <th>To</th>
              <th>Amount</th>
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
                  <td className="hash">{tx.is_coinbase ? 'Coinbase' : tx.from.substring(0, 12) + '...'}</td>
                  <td className="hash">{tx.to.substring(0, 12)}...</td>
                  <td>{formatAmount(tx.amount)} coins</td>
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

      <h2>Top Holders</h2>
      <div className="card">
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>Address</th>
              <th>Balance</th>
              <th>Transactions</th>
            </tr>
          </thead>
          <tbody>
            {holders.length === 0 ? (
              <tr><td colSpan={4} className="loading">No accounts yet</td></tr>
            ) : (
              holders.map((h, i) => (
                <tr key={h.address}>
                  <td>{i + 1}</td>
                  <td className="hash">{h.address}</td>
                  <td>{formatAmount(h.balance)} coins</td>
                  <td>{h.nonce}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
