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
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            line-height: 1.6;
            padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #58a6ff; margin-bottom: 20px; }
        h2 { color: #8b949e; margin: 20px 0 10px; font-size: 1.2em; }
        .card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 16px;
            margin-bottom: 16px;
        }
        .stat { display: inline-block; margin-right: 30px; }
        .stat-value { font-size: 2em; color: #58a6ff; font-weight: bold; }
        .stat-label { color: #8b949e; font-size: 0.9em; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #30363d; }
        th { color: #8b949e; font-weight: 500; }
        .hash { font-family: monospace; font-size: 0.9em; color: #58a6ff; }
        .search {
            width: 100%;
            padding: 12px;
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 6px;
            color: #c9d1d9;
            font-size: 1em;
            margin-bottom: 20px;
        }
        .search:focus { outline: none; border-color: #58a6ff; }
        .loading { text-align: center; padding: 40px; color: #8b949e; }
        .badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.8em;
            background: #238636;
            color: white;
        }
        .badge.pending {
            background: #9e6a03;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Postera Explorer</h1>

        <input type="text" class="search" placeholder="Search by block hash or address..." id="search">

        <div class="card">
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
                            <td>${tx.amount.toLocaleString()}</td>
                            <td><span class="badge ${tx.status === 'pending' ? 'pending' : ''}">${tx.status}${tx.block_height !== null ? ' #' + tx.block_height : ''}</span></td>
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
