use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Html,
    routing::{get, post},
    Json, Router,
};
use tower_http::services::ServeDir;
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
        .route("/transactions/:address", get(get_transactions_by_address))
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
        // React app routes - serve index.html for SPA
        .route("/wallet", get(serve_index))
        .route("/wallet/*path", get(serve_index))
        .route("/explorer", get(serve_index))
        .route("/explorer/*path", get(serve_index))
        // Static assets
        .nest_service("/assets", ServeDir::new("static/assets"))
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

async fn get_transactions_by_address(
    State(state): State<Arc<AppState>>,
    Path(address): Path<String>,
) -> Json<Vec<TransactionResponse>> {
    let mut transactions = Vec::new();

    // Parse the address
    let target_address = address.to_lowercase();

    // Get pending transactions from mempool
    {
        let mempool = state.mempool.read().unwrap();
        for tx in mempool.get_transactions(100) {
            let from = tx.from.to_hex();
            let to = tx.to.to_hex();
            if from == target_address || to == target_address {
                transactions.push(TransactionResponse {
                    hash: tx.hash_hex(),
                    from,
                    to,
                    amount: tx.amount,
                    fee: tx.fee,
                    nonce: tx.nonce,
                    is_coinbase: tx.is_coinbase(),
                    status: "pending".to_string(),
                    block_height: None,
                });
            }
        }
    }

    // Get confirmed transactions from blockchain
    let chain = state.blockchain.read().unwrap();

    for h in (0..=chain.height()).rev() {
        if let Some(block) = chain.get_block_by_height(h) {
            for tx in &block.transactions {
                let from = tx.from.to_hex();
                let to = tx.to.to_hex();
                if from == target_address || to == target_address {
                    transactions.push(TransactionResponse {
                        hash: tx.hash_hex(),
                        from,
                        to,
                        amount: tx.amount,
                        fee: tx.fee,
                        nonce: tx.nonce,
                        is_coinbase: tx.is_coinbase(),
                        status: "confirmed".to_string(),
                        block_height: Some(h),
                    });
                }
            }
        }

        if transactions.len() >= 50 {
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

// ============ React App ============
// Serve index.html for SPA routes (wallet, explorer)
async fn serve_index() -> Html<String> {
    let content = std::fs::read_to_string("static/index.html")
        .unwrap_or_else(|_| "<!DOCTYPE html><html><body>App not found. Run 'cd wallet && npm run build' first.</body></html>".to_string());
    Html(content)
}
