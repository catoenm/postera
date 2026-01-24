use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Html,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};

use crate::core::{Block, Blockchain, ChainInfo, Transaction};
use crate::crypto::Address;
use crate::wallet::Wallet;
use tracing::{info, warn};

use super::Mempool;

/// Shared application state for the API.
pub struct AppState {
    pub blockchain: RwLock<Blockchain>,
    pub mempool: RwLock<Mempool>,
    /// List of known peer URLs for gossip
    pub peers: RwLock<Vec<String>>,
}

/// Create the API router.
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/chain/info", get(chain_info))
        .route("/block/:hash", get(get_block))
        .route("/block/height/:height", get(get_block_by_height))
        .route("/account/:address", get(get_account))
        .route("/tx", post(submit_transaction))
        .route("/tx/:hash", get(get_transaction))
        .route("/transactions/recent", get(get_recent_transactions))
        .route("/mempool", get(get_mempool))
        // Peer sync endpoints
        .route("/blocks", post(receive_block))
        .route("/blocks/since/:height", get(get_blocks_since))
        // Peer management
        .route("/peers", get(get_peers))
        .route("/peers", post(add_peer))
        // Transaction relay endpoint (for peer-to-peer relay)
        .route("/tx/relay", post(receive_transaction))
        // Top holders
        .route("/accounts/top", get(get_top_holders))
        // Wallet API
        .route("/wallet/generate", post(generate_wallet))
        .route("/wallet/send", post(wallet_send))
        // Wallet UI
        .route("/wallet", get(wallet_ui))
        .with_state(state)
}

async fn index() -> &'static str {
    "Postera Node API v0.1.0"
}

async fn chain_info(State(state): State<Arc<AppState>>) -> Json<ChainInfo> {
    let chain = state.blockchain.read().unwrap();
    Json(chain.info())
}

#[derive(Serialize)]
struct BlockResponse {
    hash: String,
    height: u64,
    prev_hash: String,
    timestamp: u64,
    difficulty: u64,
    nonce: u64,
    tx_count: usize,
    transactions: Vec<String>,
}

async fn get_block(
    State(state): State<Arc<AppState>>,
    Path(hash): Path<String>,
) -> Result<Json<BlockResponse>, StatusCode> {
    let hash_bytes: [u8; 32] = hex::decode(&hash)
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let chain = state.blockchain.read().unwrap();
    let block = chain.get_block(&hash_bytes).ok_or(StatusCode::NOT_FOUND)?;

    // Find block height
    let height = (0..=chain.height())
        .find(|h| chain.get_block_by_height(*h).map(|b| b.hash()) == Some(hash_bytes))
        .unwrap_or(0);

    Ok(Json(BlockResponse {
        hash: hex::encode(block.hash()),
        height,
        prev_hash: hex::encode(block.header.prev_hash),
        timestamp: block.header.timestamp,
        difficulty: block.header.difficulty,
        nonce: block.header.nonce,
        tx_count: block.transactions.len(),
        transactions: block.transactions.iter().map(|tx| tx.hash_hex()).collect(),
    }))
}

async fn get_block_by_height(
    State(state): State<Arc<AppState>>,
    Path(height): Path<u64>,
) -> Result<Json<BlockResponse>, StatusCode> {
    let chain = state.blockchain.read().unwrap();
    let block = chain
        .get_block_by_height(height)
        .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(BlockResponse {
        hash: hex::encode(block.hash()),
        height,
        prev_hash: hex::encode(block.header.prev_hash),
        timestamp: block.header.timestamp,
        difficulty: block.header.difficulty,
        nonce: block.header.nonce,
        tx_count: block.transactions.len(),
        transactions: block.transactions.iter().map(|tx| tx.hash_hex()).collect(),
    }))
}

#[derive(Serialize)]
struct AccountResponse {
    address: String,
    balance: u64,
    nonce: u64,
}

async fn get_account(
    State(state): State<Arc<AppState>>,
    Path(address): Path<String>,
) -> Result<Json<AccountResponse>, StatusCode> {
    let addr = Address::from_hex(&address).map_err(|_| StatusCode::BAD_REQUEST)?;

    let chain = state.blockchain.read().unwrap();
    let account = chain.state().get_account(&addr);

    Ok(Json(AccountResponse {
        address: addr.to_hex(),
        balance: account.balance,
        nonce: account.nonce,
    }))
}

#[derive(Serialize)]
struct TopHolderResponse {
    address: String,
    balance: u64,
    nonce: u64,
}

async fn get_top_holders(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<TopHolderResponse>> {
    let chain = state.blockchain.read().unwrap();
    let holders: Vec<TopHolderResponse> = chain
        .state()
        .top_holders(10)
        .into_iter()
        .map(|acc| TopHolderResponse {
            address: acc.address.to_hex(),
            balance: acc.balance,
            nonce: acc.nonce,
        })
        .collect();

    Json(holders)
}

#[derive(Serialize)]
struct TransactionResponse {
    hash: String,
    from: String,
    to: String,
    amount: u64,
    fee: u64,
    nonce: u64,
    is_coinbase: bool,
    status: String,
    block_height: Option<u64>,
}

async fn get_transaction(
    State(state): State<Arc<AppState>>,
    Path(hash): Path<String>,
) -> Result<Json<TransactionResponse>, StatusCode> {
    let hash_bytes: [u8; 32] = hex::decode(&hash)
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // Check mempool first
    {
        let mempool = state.mempool.read().unwrap();
        if let Some(tx) = mempool.get(&hash_bytes) {
            return Ok(Json(TransactionResponse {
                hash: tx.hash_hex(),
                from: tx.from.to_hex(),
                to: tx.to.to_hex(),
                amount: tx.amount,
                fee: tx.fee,
                nonce: tx.nonce,
                is_coinbase: tx.is_coinbase(),
                status: "pending".to_string(),
                block_height: None,
            }));
        }
    }

    // Search in blockchain
    let chain = state.blockchain.read().unwrap();
    for h in (0..=chain.height()).rev() {
        if let Some(block) = chain.get_block_by_height(h) {
            for tx in &block.transactions {
                if tx.hash() == hash_bytes {
                    return Ok(Json(TransactionResponse {
                        hash: tx.hash_hex(),
                        from: tx.from.to_hex(),
                        to: tx.to.to_hex(),
                        amount: tx.amount,
                        fee: tx.fee,
                        nonce: tx.nonce,
                        is_coinbase: tx.is_coinbase(),
                        status: "confirmed".to_string(),
                        block_height: Some(h),
                    }));
                }
            }
        }
    }

    Err(StatusCode::NOT_FOUND)
}

async fn get_recent_transactions(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<TransactionResponse>> {
    let mut transactions = Vec::new();

    // Get pending transactions from mempool
    {
        let mempool = state.mempool.read().unwrap();
        for tx in mempool.get_transactions(10) {
            transactions.push(TransactionResponse {
                hash: tx.hash_hex(),
                from: tx.from.to_hex(),
                to: tx.to.to_hex(),
                amount: tx.amount,
                fee: tx.fee,
                nonce: tx.nonce,
                is_coinbase: tx.is_coinbase(),
                status: "pending".to_string(),
                block_height: None,
            });
        }
    }

    // Get recent confirmed transactions from last few blocks
    let chain = state.blockchain.read().unwrap();
    let start_height = chain.height().saturating_sub(5);

    for h in (start_height..=chain.height()).rev() {
        if let Some(block) = chain.get_block_by_height(h) {
            for tx in &block.transactions {
                transactions.push(TransactionResponse {
                    hash: tx.hash_hex(),
                    from: tx.from.to_hex(),
                    to: tx.to.to_hex(),
                    amount: tx.amount,
                    fee: tx.fee,
                    nonce: tx.nonce,
                    is_coinbase: tx.is_coinbase(),
                    status: "confirmed".to_string(),
                    block_height: Some(h),
                });
            }
        }

        if transactions.len() >= 20 {
            break;
        }
    }

    Json(transactions)
}

#[derive(Deserialize)]
struct SubmitTxRequest {
    transaction: Transaction,
}

#[derive(Serialize)]
struct SubmitTxResponse {
    hash: String,
    status: String,
}

async fn submit_transaction(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SubmitTxRequest>,
) -> Result<Json<SubmitTxResponse>, (StatusCode, String)> {
    let tx = req.transaction;
    let hash = tx.hash_hex();

    // Validate transaction
    {
        let chain = state.blockchain.read().unwrap();
        chain
            .state()
            .validate_transaction(&tx)
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    }

    // Add to mempool
    let added = {
        let mut mempool = state.mempool.write().unwrap();
        mempool.add(tx.clone())
    };

    if !added {
        return Err((
            StatusCode::CONFLICT,
            "Transaction already in mempool".to_string(),
        ));
    }

    // Relay to peers (fire and forget)
    let peers = state.peers.read().unwrap().clone();
    if !peers.is_empty() {
        let tx_clone = tx.clone();
        tokio::spawn(async move {
            relay_transaction(&tx_clone, &peers).await;
        });
    }

    Ok(Json(SubmitTxResponse {
        hash,
        status: "pending".to_string(),
    }))
}

#[derive(Serialize)]
struct MempoolResponse {
    count: usize,
    transactions: Vec<String>,
}

async fn get_mempool(State(state): State<Arc<AppState>>) -> Json<MempoolResponse> {
    let mempool = state.mempool.read().unwrap();
    let txs = mempool.get_transactions(100);

    Json(MempoolResponse {
        count: mempool.len(),
        transactions: txs.iter().map(|tx| tx.hash_hex()).collect(),
    })
}

// ============ Peer Sync Endpoints ============

/// Receive a block from a peer node.
async fn receive_block(
    State(state): State<Arc<AppState>>,
    Json(block): Json<Block>,
) -> Result<Json<ReceiveBlockResponse>, (StatusCode, String)> {
    let block_hash = block.hash_hex();

    info!("Received block {} from peer", &block_hash[..16]);

    // Try to add the block (handles orphans and forks)
    let (accepted, status) = {
        let mut chain = state.blockchain.write().unwrap();
        match chain.try_add_block(block.clone()) {
            Ok(true) => {
                info!("Added block {} to chain (height: {})", &block_hash[..16], chain.height());

                // Remove confirmed transactions from mempool
                let tx_hashes: Vec<[u8; 32]> = block
                    .transactions
                    .iter()
                    .skip(1) // Skip coinbase
                    .map(|tx| tx.hash())
                    .collect();

                let mut mempool = state.mempool.write().unwrap();
                mempool.remove_confirmed(&tx_hashes);

                // Re-validate remaining mempool transactions
                let removed = mempool.revalidate(chain.state());
                if removed > 0 {
                    info!("Removed {} invalid transactions from mempool after block", removed);
                }

                (true, "accepted")
            }
            Ok(false) => {
                // Block stored as orphan or already known
                let orphans = chain.orphan_count();
                if orphans > 0 {
                    info!("Block {} stored as orphan (total orphans: {})", &block_hash[..16], orphans);
                    (false, "orphan")
                } else {
                    (false, "duplicate")
                }
            }
            Err(e) => {
                warn!("Block {} rejected: {}", &block_hash[..16], e);
                return Err((StatusCode::BAD_REQUEST, format!("Block rejected: {}", e)));
            }
        }
    };

    // Relay to other peers (gossip protocol) if accepted to main chain
    if accepted {
        let peers = state.peers.read().unwrap().clone();
        if !peers.is_empty() {
            let block_clone = block.clone();
            tokio::spawn(async move {
                relay_block(&block_clone, &peers).await;
            });
        }
    }

    Ok(Json(ReceiveBlockResponse {
        status: status.to_string(),
        hash: block_hash,
    }))
}

#[derive(Serialize)]
struct ReceiveBlockResponse {
    status: String,
    hash: String,
}

/// Get all blocks since a given height (for chain sync).
async fn get_blocks_since(
    State(state): State<Arc<AppState>>,
    Path(since_height): Path<u64>,
) -> Json<Vec<Block>> {
    let chain = state.blockchain.read().unwrap();
    let current_height = chain.height();

    let mut blocks = Vec::new();

    // Return blocks from since_height+1 to current_height
    for h in (since_height + 1)..=current_height {
        if let Some(block) = chain.get_block_by_height(h) {
            blocks.push(block.clone());
        }
    }

    Json(blocks)
}

// ============ Peer Management Endpoints ============

#[derive(Serialize)]
struct PeersResponse {
    peers: Vec<String>,
    count: usize,
}

/// Get the list of known peers.
async fn get_peers(State(state): State<Arc<AppState>>) -> Json<PeersResponse> {
    let peers = state.peers.read().unwrap();
    Json(PeersResponse {
        count: peers.len(),
        peers: peers.clone(),
    })
}

#[derive(Deserialize)]
struct AddPeerRequest {
    url: String,
}

#[derive(Serialize)]
struct AddPeerResponse {
    status: String,
    peer_count: usize,
}

/// Add a new peer to the peer list.
async fn add_peer(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AddPeerRequest>,
) -> Json<AddPeerResponse> {
    let mut peers = state.peers.write().unwrap();

    // Avoid duplicates
    if !peers.contains(&req.url) {
        peers.push(req.url.clone());
        info!("Added peer: {}", req.url);
    }

    Json(AddPeerResponse {
        status: "ok".to_string(),
        peer_count: peers.len(),
    })
}

// ============ Transaction Relay ============

/// Receive a transaction from a peer (relay endpoint).
async fn receive_transaction(
    State(state): State<Arc<AppState>>,
    Json(tx): Json<Transaction>,
) -> Result<Json<SubmitTxResponse>, (StatusCode, String)> {
    let hash = tx.hash_hex();

    // Check if already in mempool
    {
        let mempool = state.mempool.read().unwrap();
        if mempool.contains(&tx.hash()) {
            return Ok(Json(SubmitTxResponse {
                hash,
                status: "duplicate".to_string(),
            }));
        }
    }

    // Validate transaction
    {
        let chain = state.blockchain.read().unwrap();
        chain
            .state()
            .validate_transaction(&tx)
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    }

    // Add to mempool
    let added = {
        let mut mempool = state.mempool.write().unwrap();
        mempool.add(tx.clone())
    };

    if added {
        info!("Added relayed transaction {} to mempool", &hash[..16]);

        // Continue relaying to other peers
        let peers = state.peers.read().unwrap().clone();
        if !peers.is_empty() {
            let tx_clone = tx.clone();
            tokio::spawn(async move {
                relay_transaction(&tx_clone, &peers).await;
            });
        }
    }

    Ok(Json(SubmitTxResponse {
        hash,
        status: if added { "accepted".to_string() } else { "duplicate".to_string() },
    }))
}

// ============ Relay Helper Functions ============

/// Relay a block to all known peers.
async fn relay_block(block: &Block, peers: &[String]) {
    let client = reqwest::Client::new();
    let block_hash = &block.hash_hex()[..16];

    for peer in peers {
        let url = format!("{}/blocks", peer);
        match client.post(&url).json(block).send().await {
            Ok(resp) if resp.status().is_success() => {
                info!("Relayed block {} to {}", block_hash, peer);
            }
            Ok(resp) => {
                // Peer might already have it (duplicate) - not an error
                let status = resp.status();
                if status != StatusCode::BAD_REQUEST {
                    warn!("Relay to {} returned {}", peer, status);
                }
            }
            Err(e) => {
                warn!("Failed to relay block to {}: {}", peer, e);
            }
        }
    }
}

/// Relay a transaction to all known peers.
async fn relay_transaction(tx: &Transaction, peers: &[String]) {
    let client = reqwest::Client::new();
    let tx_hash = &tx.hash_hex()[..16];

    for peer in peers {
        let url = format!("{}/tx/relay", peer);
        match client.post(&url).json(tx).send().await {
            Ok(resp) if resp.status().is_success() => {
                info!("Relayed transaction {} to {}", tx_hash, peer);
            }
            Ok(_) => {
                // Peer might already have it - not an error
            }
            Err(e) => {
                warn!("Failed to relay transaction to {}: {}", peer, e);
            }
        }
    }
}

// ============ Wallet API ============

#[derive(Serialize)]
struct WalletResponse {
    address: String,
    public_key: String,
    secret_key: String,
}

/// Generate a new wallet.
async fn generate_wallet() -> Json<WalletResponse> {
    let wallet = Wallet::generate();

    Json(WalletResponse {
        address: wallet.address().to_hex(),
        public_key: hex::encode(wallet.public_key_bytes()),
        secret_key: hex::encode(wallet.secret_key_bytes()),
    })
}

#[derive(Deserialize)]
struct WalletSendRequest {
    public_key: String,
    secret_key: String,
    to: String,
    amount: u64,
    fee: u64,
}

#[derive(Serialize)]
struct WalletSendResponse {
    hash: String,
    status: String,
    from: String,
    to: String,
    amount: u64,
    fee: u64,
}

/// Sign and send a transaction using wallet keys.
///
/// WARNING: This endpoint receives secret keys over the network.
/// In production, use client-side signing with WASM-compiled Dilithium.
async fn wallet_send(
    State(state): State<Arc<AppState>>,
    Json(req): Json<WalletSendRequest>,
) -> Result<Json<WalletSendResponse>, (StatusCode, String)> {
    // Decode keys
    let pk_bytes = hex::decode(&req.public_key)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid public key hex".to_string()))?;
    let sk_bytes = hex::decode(&req.secret_key)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid secret key hex".to_string()))?;

    // Reconstruct wallet from keys
    let wallet = Wallet::from_keys(&pk_bytes, &sk_bytes)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid keys: {}", e)))?;

    // Parse recipient address
    let to_addr = Address::from_hex(&req.to)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid recipient address".to_string()))?;

    // Get current nonce
    let nonce = {
        let chain = state.blockchain.read().unwrap();
        chain.nonce(&wallet.address())
    };

    // Create and sign transaction
    let tx = wallet.create_transaction(to_addr, req.amount, req.fee, nonce);
    let tx_hash = tx.hash_hex();
    let from_addr = wallet.address().to_hex();

    // Validate transaction
    {
        let chain = state.blockchain.read().unwrap();
        chain
            .state()
            .validate_transaction(&tx)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid transaction: {}", e)))?;
    }

    // Add to mempool
    {
        let mut mempool = state.mempool.write().unwrap();
        if !mempool.add(tx.clone()) {
            return Err((StatusCode::CONFLICT, "Transaction already in mempool".to_string()));
        }
    }

    // Relay to peers
    let peers = state.peers.read().unwrap().clone();
    if !peers.is_empty() {
        tokio::spawn(async move {
            relay_transaction(&tx, &peers).await;
        });
    }

    info!("Wallet {} sent {} to {}", &from_addr[..12], req.amount, &req.to[..12]);

    Ok(Json(WalletSendResponse {
        hash: tx_hash,
        status: "pending".to_string(),
        from: from_addr,
        to: req.to,
        amount: req.amount,
        fee: req.fee,
    }))
}

// ============ Wallet UI ============

async fn wallet_ui() -> Html<&'static str> {
    Html(WALLET_HTML)
}

const WALLET_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Postera Wallet</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            line-height: 1.6;
            padding: 20px;
        }
        .container { max-width: 800px; margin: 0 auto; }
        h1 { color: #58a6ff; margin-bottom: 10px; }
        h2 { color: #8b949e; margin: 20px 0 10px; font-size: 1.2em; }
        .subtitle { color: #8b949e; margin-bottom: 20px; }
        .card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 16px;
            margin-bottom: 16px;
        }
        .info {
            background: #0d2847;
            border-color: #1f6feb;
            color: #79c0ff;
            font-size: 0.9em;
        }
        .balance-display {
            font-size: 2.5em;
            color: #58a6ff;
            font-weight: bold;
        }
        .address-display {
            font-family: monospace;
            font-size: 1.1em;
            word-break: break-all;
            color: #58a6ff;
            background: #0d1117;
            padding: 8px;
            border-radius: 4px;
            margin-top: 8px;
        }
        button {
            background: #238636;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 1em;
            margin-right: 10px;
            margin-top: 10px;
        }
        button:hover { background: #2ea043; }
        button:disabled { background: #484f58; cursor: not-allowed; }
        button.secondary { background: #30363d; }
        button.secondary:hover { background: #484f58; }
        button.danger { background: #da3633; }
        button.danger:hover { background: #f85149; }
        input, textarea {
            width: 100%;
            padding: 10px;
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 6px;
            color: #c9d1d9;
            font-size: 1em;
            margin-bottom: 10px;
        }
        input:focus, textarea:focus { outline: none; border-color: #58a6ff; }
        textarea { resize: vertical; min-height: 80px; font-family: monospace; font-size: 0.85em; }
        label { display: block; color: #8b949e; margin-bottom: 4px; font-size: 0.9em; }
        .form-group { margin-bottom: 15px; }
        .hidden { display: none; }
        .tx-list { list-style: none; }
        .tx-item { padding: 10px; border-bottom: 1px solid #30363d; }
        .tx-item:last-child { border-bottom: none; }
        .tx-hash { font-family: monospace; font-size: 0.85em; color: #58a6ff; }
        .tx-amount { font-weight: bold; }
        .tx-amount.sent { color: #f85149; }
        .tx-amount.received { color: #3fb950; }
        .status { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.8em; }
        .status.pending { background: #9e6a03; }
        .status.confirmed { background: #238636; }
        .nav { margin-bottom: 20px; }
        .nav a { color: #58a6ff; text-decoration: none; margin-right: 15px; }
        .nav a:hover { text-decoration: underline; }
        .empty { color: #8b949e; text-align: center; padding: 20px; }
        .copy-btn { background: #30363d; padding: 4px 8px; font-size: 0.8em; margin-left: 10px; }
        #loading-overlay {
            position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(13, 17, 23, 0.9); display: flex;
            justify-content: center; align-items: center; z-index: 1000;
        }
        .spinner { color: #58a6ff; font-size: 1.2em; }
    </style>
</head>
<body>
    <div id="loading-overlay">
        <div class="spinner">Loading Dilithium cryptography...</div>
    </div>

    <div class="container">
        <div class="nav">
            <a href="/explorer">Explorer</a>
            <a href="/wallet">Wallet</a>
        </div>

        <h1>Postera Wallet</h1>
        <p class="subtitle">Quantum-resistant cryptocurrency wallet</p>

        <div class="card info">
            <strong>Quantum-Resistant:</strong> This wallet uses CRYSTALS-Dilithium3 signatures.
            Keys are stored in your browser's localStorage. Transactions are signed server-side
            (HTTPS required for production). For true client-side signing, a WASM build of
            pqcrypto-dilithium would be needed.
        </div>

        <!-- No wallet state -->
        <div id="no-wallet">
            <div class="card">
                <h2>Get Started</h2>
                <p style="margin-bottom: 15px;">Create a new wallet or import an existing one.</p>
                <button id="create-btn" onclick="createWallet()" disabled>Create New Wallet</button>
                <button class="secondary" onclick="showImport()">Import Wallet</button>
            </div>

            <div id="import-form" class="card hidden">
                <h2>Import Wallet</h2>
                <div class="form-group">
                    <label>Public Key (hex)</label>
                    <textarea id="import-pk" placeholder="Paste your public key (3904 hex chars)..."></textarea>
                </div>
                <div class="form-group">
                    <label>Secret Key (hex)</label>
                    <textarea id="import-sk" placeholder="Paste your secret key (8032 hex chars)..."></textarea>
                </div>
                <button onclick="importWallet()">Import</button>
                <button class="secondary" onclick="hideImport()">Cancel</button>
            </div>
        </div>

        <!-- Wallet loaded state -->
        <div id="wallet-loaded" class="hidden">
            <div class="card">
                <h2>Balance</h2>
                <div class="balance-display" id="balance">0.00</div>
                <div style="color: #8b949e;">coins</div>
                <div style="margin-top: 15px;">
                    <label>Your Address</label>
                    <div class="address-display" id="address">-</div>
                </div>
                <button class="secondary copy-btn" onclick="copyAddress()">Copy Address</button>
                <button class="secondary" onclick="refreshBalance()" style="margin-left: 5px;">Refresh</button>
            </div>

            <div class="card">
                <h2>Send Coins</h2>
                <div class="form-group">
                    <label>Recipient Address</label>
                    <input type="text" id="send-to" placeholder="Enter recipient address (40 hex chars)">
                </div>
                <div class="form-group">
                    <label>Amount (base units)</label>
                    <input type="number" id="send-amount" placeholder="Amount in base units" min="1">
                </div>
                <div class="form-group">
                    <label>Fee</label>
                    <input type="number" id="send-fee" placeholder="Transaction fee" min="1" value="1">
                </div>
                <button id="send-btn" onclick="sendTransaction()">Send</button>
                <div id="send-result" style="margin-top: 10px;"></div>
            </div>

            <div class="card">
                <h2>Recent Transactions</h2>
                <ul class="tx-list" id="tx-list">
                    <li class="empty">Loading transactions...</li>
                </ul>
            </div>

            <div class="card">
                <h2>Backup Keys</h2>
                <p style="margin-bottom: 10px; color: #8b949e;">
                    Save these keys securely. If you lose them, you lose access to your funds.
                </p>
                <button class="secondary" onclick="showKeys()">Show Keys</button>
                <button class="danger" onclick="logout()">Logout</button>
                <div id="keys-display" class="hidden" style="margin-top: 15px;">
                    <div class="form-group">
                        <label>Public Key (1952 bytes)</label>
                        <textarea readonly id="show-pk" style="height: 60px;"></textarea>
                    </div>
                    <div class="form-group">
                        <label>Secret Key (4016 bytes)</label>
                        <textarea readonly id="show-sk" style="height: 100px;"></textarea>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Load Dilithium library - using server-side for Dilithium3 compatibility -->
    <script>
        const STORAGE_KEY = 'postera_wallet';

        // Dilithium3 key sizes (must match Rust backend)
        const DILITHIUM3_PK_SIZE = 1952;  // bytes
        const DILITHIUM3_SK_SIZE = 4016;  // bytes
        const DILITHIUM3_SIG_SIZE = 3309; // bytes

        // For client-side signing, we would need a Dilithium3-compatible JS library.
        // Most JS libraries default to Dilithium5 which is incompatible.
        // We use server-side key generation and signing for Dilithium3 compatibility.
        // Keys are still stored client-side in localStorage.

        let dilithiumReady = false;

        // Initialize
        async function initDilithium() {
            // For now, we rely on server-side crypto for Dilithium3 compatibility
            // Client-side signing would require WASM build of pqcrypto-dilithium
            dilithiumReady = false;

            document.getElementById('loading-overlay').style.display = 'none';
            document.getElementById('create-btn').disabled = false;

            // Load existing wallet
            const wallet = loadWallet();
            if (wallet) {
                showWallet(wallet);
            }
        }

        // Start initialization
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', initDilithium);
        } else {
            initDilithium();
        }

        function loadWallet() {
            const data = localStorage.getItem(STORAGE_KEY);
            return data ? JSON.parse(data) : null;
        }

        function saveWallet(wallet) {
            localStorage.setItem(STORAGE_KEY, JSON.stringify(wallet));
        }

        function clearWallet() {
            localStorage.removeItem(STORAGE_KEY);
        }

        // Convert hex string to Uint8Array
        function hexToBytes(hex) {
            const bytes = new Uint8Array(hex.length / 2);
            for (let i = 0; i < hex.length; i += 2) {
                bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
            }
            return bytes;
        }

        // Convert Uint8Array to hex string
        function bytesToHex(bytes) {
            return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
        }

        // Compute SHA-256 hash
        async function sha256(data) {
            const hashBuffer = await crypto.subtle.digest('SHA-256', data);
            return new Uint8Array(hashBuffer);
        }

        // Derive address from public key (first 20 bytes of SHA-256)
        async function deriveAddress(publicKeyBytes) {
            const hash = await sha256(publicKeyBytes);
            return bytesToHex(hash.slice(0, 20));
        }

        // Create signing message for transaction
        function createSigningMessage(from, to, amount, fee, nonce, publicKey) {
            const fromBytes = hexToBytes(from);
            const toBytes = hexToBytes(to);
            const publicKeyBytes = hexToBytes(publicKey);

            // Allocate buffer: 20 + 20 + 8 + 8 + 8 + pubkey_len
            const msg = new Uint8Array(20 + 20 + 8 + 8 + 8 + publicKeyBytes.length);
            let offset = 0;

            // from (20 bytes)
            msg.set(fromBytes, offset); offset += 20;
            // to (20 bytes)
            msg.set(toBytes, offset); offset += 20;
            // amount (8 bytes, little-endian)
            const amountView = new DataView(new ArrayBuffer(8));
            amountView.setBigUint64(0, BigInt(amount), true);
            msg.set(new Uint8Array(amountView.buffer), offset); offset += 8;
            // fee (8 bytes, little-endian)
            const feeView = new DataView(new ArrayBuffer(8));
            feeView.setBigUint64(0, BigInt(fee), true);
            msg.set(new Uint8Array(feeView.buffer), offset); offset += 8;
            // nonce (8 bytes, little-endian)
            const nonceView = new DataView(new ArrayBuffer(8));
            nonceView.setBigUint64(0, BigInt(nonce), true);
            msg.set(new Uint8Array(nonceView.buffer), offset); offset += 8;
            // public_key
            msg.set(publicKeyBytes, offset);

            return msg;
        }

        async function createWallet() {
            document.getElementById('create-btn').disabled = true;
            document.getElementById('create-btn').textContent = 'Generating keys...';

            try {
                const res = await fetch('/wallet/generate', { method: 'POST' });
                if (!res.ok) {
                    throw new Error('Server error: ' + res.status);
                }
                const wallet = await res.json();
                saveWallet(wallet);
                showWallet(wallet);
            } catch (e) {
                alert('Failed to create wallet: ' + e.message);
            } finally {
                document.getElementById('create-btn').disabled = false;
                document.getElementById('create-btn').textContent = 'Create New Wallet';
            }
        }

        function showImport() {
            document.getElementById('import-form').classList.remove('hidden');
        }

        function hideImport() {
            document.getElementById('import-form').classList.add('hidden');
        }

        async function importWallet() {
            const pk = document.getElementById('import-pk').value.trim();
            const sk = document.getElementById('import-sk').value.trim();

            if (!pk || !sk) {
                alert('Please enter both public and secret keys');
                return;
            }

            // Validate key lengths (Dilithium3: pk=1952 bytes, sk=4016 bytes)
            if (pk.length !== 3904) {
                alert('Invalid public key length. Expected 3904 hex characters (1952 bytes)');
                return;
            }
            if (sk.length !== 8032) {
                alert('Invalid secret key length. Expected 8032 hex characters (4016 bytes)');
                return;
            }

            try {
                const publicKeyBytes = hexToBytes(pk);
                const address = await deriveAddress(publicKeyBytes);

                const wallet = {
                    address: address,
                    public_key: pk,
                    secret_key: sk
                };

                saveWallet(wallet);
                showWallet(wallet);
                hideImport();
            } catch (e) {
                alert('Failed to import wallet: ' + e.message);
            }
        }

        function showWallet(wallet) {
            document.getElementById('no-wallet').classList.add('hidden');
            document.getElementById('wallet-loaded').classList.remove('hidden');
            document.getElementById('address').textContent = wallet.address;
            document.getElementById('show-pk').value = wallet.public_key;
            document.getElementById('show-sk').value = wallet.secret_key;

            refreshBalance();
            loadTransactions();
        }

        async function refreshBalance() {
            const wallet = loadWallet();
            if (!wallet || !wallet.address) {
                document.getElementById('balance').textContent = '?';
                return;
            }

            try {
                const res = await fetch('/account/' + wallet.address);
                if (res.ok) {
                    const account = await res.json();
                    const balance = (account.balance / 1000000000).toFixed(2);
                    document.getElementById('balance').textContent = balance;
                } else {
                    document.getElementById('balance').textContent = '0.00';
                }
            } catch (e) {
                console.error('Failed to fetch balance:', e);
            }
        }

        async function loadTransactions() {
            const wallet = loadWallet();
            if (!wallet || !wallet.address) {
                document.getElementById('tx-list').innerHTML = '<li class="empty">Create a wallet to see transactions</li>';
                return;
            }

            try {
                const res = await fetch('/transactions/recent');
                const txs = await res.json();

                const myTxs = txs.filter(tx =>
                    tx.from === wallet.address || tx.to === wallet.address
                );

                const txList = document.getElementById('tx-list');
                if (myTxs.length === 0) {
                    txList.innerHTML = '<li class="empty">No transactions yet</li>';
                    return;
                }

                txList.innerHTML = myTxs.map(tx => {
                    const isSent = tx.from === wallet.address;
                    const amountClass = isSent ? 'sent' : 'received';
                    const sign = isSent ? '-' : '+';
                    const otherParty = isSent ? tx.to : (tx.is_coinbase ? 'Mining Reward' : tx.from);

                    return `
                        <li class="tx-item">
                            <div class="tx-hash">${tx.hash.substring(0, 24)}...</div>
                            <div>
                                <span class="tx-amount ${amountClass}">${sign}${(tx.amount / 1000000000).toFixed(4)}</span>
                                <span class="status ${tx.status}">${tx.status}${tx.block_height !== null ? ' #' + tx.block_height : ''}</span>
                            </div>
                            <div style="font-size: 0.85em; color: #8b949e;">
                                ${isSent ? 'To' : 'From'}: ${otherParty.substring(0, 16)}...
                            </div>
                        </li>
                    `;
                }).join('');
            } catch (e) {
                console.error('Failed to load transactions:', e);
                document.getElementById('tx-list').innerHTML = '<li class="empty">Failed to load transactions</li>';
            }
        }

        async function sendTransaction() {
            const wallet = loadWallet();
            if (!wallet) {
                alert('No wallet loaded');
                return;
            }

            const to = document.getElementById('send-to').value.trim();
            const amount = parseInt(document.getElementById('send-amount').value);
            const fee = parseInt(document.getElementById('send-fee').value) || 1;

            if (!to || to.length !== 40) {
                alert('Please enter a valid recipient address (40 hex characters)');
                return;
            }

            if (!amount || amount <= 0) {
                alert('Please enter a valid amount');
                return;
            }

            const resultDiv = document.getElementById('send-result');
            const sendBtn = document.getElementById('send-btn');
            sendBtn.disabled = true;
            resultDiv.innerHTML = '<span style="color: #8b949e;">Signing and sending transaction...</span>';

            try {
                const res = await fetch('/wallet/send', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        public_key: wallet.public_key,
                        secret_key: wallet.secret_key,
                        to: to,
                        amount: amount,
                        fee: fee
                    })
                });

                const data = await res.json();

                if (res.ok) {
                    resultDiv.innerHTML = `
                        <span style="color: #3fb950;">Transaction sent!</span><br>
                        <span class="tx-hash">${data.hash}</span>
                    `;
                    document.getElementById('send-to').value = '';
                    document.getElementById('send-amount').value = '';
                    setTimeout(() => { refreshBalance(); loadTransactions(); }, 1000);
                } else {
                    resultDiv.innerHTML = `<span style="color: #f85149;">Error: ${typeof data === 'string' ? data : JSON.stringify(data)}</span>`;
                }
            } catch (e) {
                resultDiv.innerHTML = `<span style="color: #f85149;">Failed: ${e.message}</span>`;
            } finally {
                sendBtn.disabled = false;
            }
        }

        function copyAddress() {
            const address = document.getElementById('address').textContent;
            navigator.clipboard.writeText(address);
            alert('Address copied to clipboard!');
        }

        function showKeys() {
            document.getElementById('keys-display').classList.toggle('hidden');
        }

        function logout() {
            if (confirm('Are you sure? Make sure you have backed up your keys!')) {
                clearWallet();
                document.getElementById('wallet-loaded').classList.add('hidden');
                document.getElementById('no-wallet').classList.remove('hidden');
                document.getElementById('keys-display').classList.add('hidden');
            }
        }

        // Auto-refresh every 30 seconds
        setInterval(() => {
            if (loadWallet()) {
                refreshBalance();
                loadTransactions();
            }
        }, 30000);
    </script>
</body>
</html>
"#;
