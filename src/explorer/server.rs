use axum::{
    response::Html,
    routing::get,
    Router,
};

/// Create the explorer router (serves at /explorer).
pub fn create_explorer_router() -> Router {
    Router::new()
        .route("/", get(explorer_index))
}

async fn explorer_index() -> Html<&'static str> {
    Html(EXPLORER_HTML)
}

const EXPLORER_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Postera Explorer</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

        * { box-sizing: border-box; margin: 0; padding: 0; }

        :root {
            --bg-primary: #0a0e14;
            --bg-secondary: rgba(22, 27, 34, 0.8);
            --bg-tertiary: rgba(13, 17, 23, 0.6);
            --border-color: rgba(48, 54, 61, 0.6);
            --text-primary: #e6edf3;
            --text-secondary: #8b949e;
            --accent-blue: #58a6ff;
            --accent-purple: #a371f7;
            --accent-gradient: linear-gradient(135deg, #58a6ff 0%, #a371f7 100%);
            --success: #3fb950;
            --danger: #f85149;
            --warning: #d29922;
            --glow-blue: 0 0 20px rgba(88, 166, 255, 0.3);
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: var(--bg-primary);
            background-image:
                radial-gradient(ellipse at top, rgba(88, 166, 255, 0.08) 0%, transparent 50%),
                radial-gradient(ellipse at bottom right, rgba(163, 113, 247, 0.06) 0%, transparent 50%);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 24px;
            min-height: 100vh;
        }

        .container { max-width: 1200px; margin: 0 auto; }

        h1 {
            font-size: 2rem;
            font-weight: 700;
            background: var(--accent-gradient);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 8px;
            letter-spacing: -0.02em;
        }

        .subtitle {
            color: var(--text-secondary);
            margin-bottom: 32px;
            font-size: 0.95rem;
        }

        h2 {
            color: var(--text-primary);
            margin: 24px 0 16px;
            font-size: 1rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .card {
            background: var(--bg-secondary);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 24px;
            margin-bottom: 20px;
            transition: all 0.3s ease;
            box-shadow: 0 4px 24px rgba(0, 0, 0, 0.2);
            animation: fadeIn 0.4s ease-out;
        }

        .card:hover {
            border-color: rgba(88, 166, 255, 0.3);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3), var(--glow-blue);
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
        }

        .stat { text-align: center; }

        .stat-value {
            font-size: 2.5rem;
            font-weight: 700;
            background: var(--accent-gradient);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            letter-spacing: -0.02em;
        }

        .stat-label {
            color: var(--text-secondary);
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-top: 4px;
        }

        table { width: 100%; border-collapse: collapse; }

        th, td {
            padding: 14px 12px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }

        th {
            color: var(--text-secondary);
            font-weight: 500;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        tr:hover { background: rgba(88, 166, 255, 0.05); }
        tr:last-child td { border-bottom: none; }

        .hash {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            color: var(--accent-blue);
        }

        .search {
            width: 100%;
            padding: 14px 16px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            color: var(--text-primary);
            font-family: 'Inter', sans-serif;
            font-size: 0.95rem;
            margin-bottom: 24px;
            transition: all 0.2s ease;
        }

        .search:focus {
            outline: none;
            border-color: var(--accent-blue);
            box-shadow: 0 0 0 3px rgba(88, 166, 255, 0.15), inset 0 0 20px rgba(88, 166, 255, 0.05);
        }

        .search::placeholder { color: #484f58; }

        .loading {
            text-align: center;
            padding: 40px;
            color: var(--text-secondary);
        }

        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .badge.confirmed {
            background: rgba(63, 185, 80, 0.2);
            color: var(--success);
            border: 1px solid rgba(63, 185, 80, 0.3);
        }

        .badge.pending {
            background: rgba(210, 153, 34, 0.2);
            color: var(--warning);
            border: 1px solid rgba(210, 153, 34, 0.3);
        }

        .nav-tabs {
            display: flex;
            gap: 8px;
            margin-bottom: 32px;
            padding: 6px;
            background: var(--bg-secondary);
            border-radius: 12px;
            border: 1px solid var(--border-color);
            width: fit-content;
        }

        .nav-tabs a {
            color: var(--text-secondary);
            text-decoration: none;
            padding: 10px 24px;
            font-weight: 500;
            font-size: 0.9rem;
            border-radius: 8px;
            transition: all 0.2s ease;
        }

        .nav-tabs a:hover {
            color: var(--text-primary);
            background: var(--bg-tertiary);
        }

        .nav-tabs a.active {
            color: white;
            background: var(--accent-gradient);
            box-shadow: 0 2px 8px rgba(88, 166, 255, 0.3);
        }

        ::-webkit-scrollbar { width: 8px; }
        ::-webkit-scrollbar-track { background: var(--bg-primary); }
        ::-webkit-scrollbar-thumb {
            background: var(--border-color);
            border-radius: 4px;
        }
        ::-webkit-scrollbar-thumb:hover { background: #484f58; }
    </style>
</head>
<body>
    <div class="container">
        <div class="nav-tabs">
            <a href="/explorer" class="active">Explorer</a>
            <a href="/wallet">Wallet</a>
        </div>

        <h1>Postera Explorer</h1>
        <p class="subtitle">Quantum-resistant blockchain explorer</p>

        <input type="text" class="search" placeholder="Search by block hash or address..." id="search">

        <div class="card">
            <div class="stats-grid">
                <div class="stat">
                    <div class="stat-value" id="height">-</div>
                    <div class="stat-label">Block Height</div>
                </div>
                <div class="stat">
                    <div class="stat-value" id="difficulty">-</div>
                    <div class="stat-label">Difficulty</div>
                </div>
                <div class="stat">
                    <div class="stat-value" id="accounts">-</div>
                    <div class="stat-label">Accounts</div>
                </div>
                <div class="stat">
                    <div class="stat-value" id="mempool">-</div>
                    <div class="stat-label">Pending Txs</div>
                </div>
            </div>
        </div>

        <h2>Recent Blocks</h2>
        <div class="card">
            <table>
                <thead>
                    <tr>
                        <th>Height</th>
                        <th>Hash</th>
                        <th>Transactions</th>
                        <th>Time</th>
                    </tr>
                </thead>
                <tbody id="blocks">
                    <tr><td colspan="4" class="loading">Loading...</td></tr>
                </tbody>
            </table>
        </div>

        <h2>Recent Transactions</h2>
        <div class="card">
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
                <tbody id="transactions">
                    <tr><td colspan="5" class="loading">Loading...</td></tr>
                </tbody>
            </table>
        </div>

        <h2>Top Holders</h2>
        <div class="card">
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Address</th>
                        <th>Balance</th>
                        <th>Transactions</th>
                    </tr>
                </thead>
                <tbody id="holders">
                    <tr><td colspan="4" class="loading">Loading...</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <script>
        async function fetchData() {
            try {
                // Fetch chain info
                const infoRes = await fetch('/chain/info');
                const info = await infoRes.json();

                document.getElementById('height').textContent = info.height;
                document.getElementById('difficulty').textContent = info.difficulty;
                document.getElementById('accounts').textContent = info.total_accounts;

                // Fetch mempool
                const mempoolRes = await fetch('/mempool');
                const mempool = await mempoolRes.json();
                document.getElementById('mempool').textContent = mempool.count;

                // Fetch recent blocks
                const blocks = [];
                for (let h = info.height; h >= Math.max(0, info.height - 9); h--) {
                    const blockRes = await fetch(`/block/height/${h}`);
                    if (blockRes.ok) {
                        blocks.push(await blockRes.json());
                    }
                }

                const tbody = document.getElementById('blocks');
                tbody.innerHTML = blocks.map(b => `
                    <tr>
                        <td>${b.height}</td>
                        <td class="hash">${b.hash.substring(0, 16)}...</td>
                        <td>${b.tx_count}</td>
                        <td>${new Date(b.timestamp * 1000).toLocaleString()}</td>
                    </tr>
                `).join('');

                // Fetch recent transactions
                const txRes = await fetch('/transactions/recent');
                const transactions = await txRes.json();

                const txBody = document.getElementById('transactions');
                if (transactions.length === 0) {
                    txBody.innerHTML = '<tr><td colspan="5" class="loading">No transactions yet</td></tr>';
                } else {
                    txBody.innerHTML = transactions.map(tx => `
                        <tr>
                            <td class="hash">${tx.hash.substring(0, 16)}...</td>
                            <td class="hash">${tx.is_coinbase ? 'Coinbase' : tx.from.substring(0, 12) + '...'}</td>
                            <td class="hash">${tx.to.substring(0, 12)}...</td>
                            <td>${(tx.amount / 1000000000).toFixed(2)} coins</td>
                            <td><span class="badge ${tx.status}">${tx.status}${tx.block_height !== null ? ' #' + tx.block_height : ''}</span></td>
                        </tr>
                    `).join('');
                }

                // Fetch top holders
                const holdersRes = await fetch('/accounts/top');
                const holders = await holdersRes.json();

                const holdersBody = document.getElementById('holders');
                if (holders.length === 0) {
                    holdersBody.innerHTML = '<tr><td colspan="4" class="loading">No accounts yet</td></tr>';
                } else {
                    holdersBody.innerHTML = holders.map((h, i) => `
                        <tr>
                            <td>${i + 1}</td>
                            <td class="hash">${h.address}</td>
                            <td>${(h.balance / 1000000000).toFixed(2)} coins</td>
                            <td>${h.nonce}</td>
                        </tr>
                    `).join('');
                }

            } catch (e) {
                console.error('Failed to fetch data:', e);
            }
        }

        // Initial load
        fetchData();

        // Refresh every 10 seconds
        setInterval(fetchData, 10000);

        // Search functionality
        document.getElementById('search').addEventListener('keypress', async (e) => {
            if (e.key === 'Enter') {
                const query = e.target.value.trim();
                if (query.length === 64) {
                    // Block hash
                    window.location.href = `/block/${query}`;
                } else if (query.length === 40) {
                    // Address
                    window.location.href = `/account/${query}`;
                }
            }
        });
    </script>
</body>
</html>
"#;
