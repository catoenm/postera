//! REST API for the shielded blockchain node.
//!
//! This API is privacy-preserving. Account balances and transaction
//! amounts are not visible through the API. Only publicly observable
//! data (block hashes, timestamps, fees) is exposed.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Html,
    routing::{get, post},
    Json, Router,
};
use tower_http::services::{ServeDir, ServeFile};
use tower_http::limit::RequestBodyLimitLayer;
use tower_governor::{
    governor::GovernorConfigBuilder, key_extractor::SmartIpKeyExtractor, GovernorLayer,
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};

use crate::core::{ShieldedBlock, ShieldedBlockchain, ChainInfo, ShieldedTransaction};
use crate::crypto::nullifier::Nullifier;
use tracing::{info, warn};

use super::Mempool;

/// Maximum request body size (10 MB)
const MAX_BODY_SIZE: usize = 10 * 1024 * 1024;

/// Rate limit: requests per second per IP
const RATE_LIMIT_RPS: u64 = 10000;

/// Rate limit: burst size (max requests before throttling)
const RATE_LIMIT_BURST: u32 = 50000;

/// Shared application state for the API.
pub struct AppState {
    pub blockchain: RwLock<ShieldedBlockchain>,
    pub mempool: RwLock<Mempool>,
    /// List of known peer URLs for gossip
    pub peers: RwLock<Vec<String>>,
    /// Stats for the local miner (if running)
    pub miner_stats: RwLock<MinerStats>,
}

/// Create the API router with rate limiting and request size limits.
///
/// Note: This is a privacy-preserving blockchain. Account balances and
/// transaction amounts are not visible through the API.
///
/// Rate limiting: 50 requests/second per IP with burst of 100.
/// Request body limit: 10 MB max.
pub fn create_router(state: Arc<AppState>) -> Router {
    // Configure rate limiting using Governor
    // Uses SmartIpKeyExtractor to handle proxied requests (X-Forwarded-For)
    let governor_config = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(RATE_LIMIT_RPS)
            .burst_size(RATE_LIMIT_BURST)
            .key_extractor(SmartIpKeyExtractor)
            .finish()
            .expect("Failed to build rate limiter config"),
    );

    let rate_limit_layer = GovernorLayer {
        config: governor_config,
    };

    // Log rate limiter configuration
    info!(
        "Rate limiting enabled: {} req/s, burst size {}",
        RATE_LIMIT_RPS, RATE_LIMIT_BURST
    );
    info!("Request body limit: {} bytes", MAX_BODY_SIZE);

    let api_routes = Router::new()
        .route("/chain/info", get(chain_info))
        .route("/miner/stats", get(miner_stats))
        .route("/block/:hash", get(get_block))
        .route("/block/height/:height", get(get_block_by_height))
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
        // Wallet scanning endpoints
        .route("/outputs/since/:height", get(get_outputs_since))
        .route("/nullifiers/check", post(check_nullifiers))
        .route("/witness/:commitment", get(get_witness))
        .route("/witness/position/:position", get(get_witness_by_position))
        .route("/debug/commitments", get(debug_list_commitments))
        .route("/debug/poseidon", get(debug_poseidon_test))
        .with_state(state)
        // Apply rate limiting (returns 429 Too Many Requests when exceeded)
        .layer(rate_limit_layer)
        // Apply request body size limit (returns 413 Payload Too Large when exceeded)
        .layer(RequestBodyLimitLayer::new(MAX_BODY_SIZE));

    let ui_routes = Router::new()
        // React app routes - serve index.html for SPA
        .route("/", get(serve_index))
        .route("/wallet", get(serve_index))
        .route("/wallet/*path", get(serve_index))
        .route("/explorer", get(serve_index))
        .route("/explorer/*path", get(serve_index))
        // Static assets
        .nest_service("/assets", ServeDir::new("static/assets"))
        // Circuit files (WASM and proving keys)
        .nest_service("/circuits", ServeDir::new("static/circuits"))
        // Root-level static files
        .route_service("/logo.png", ServeFile::new("static/logo.png"))
        .route_service("/vite.svg", ServeFile::new("static/vite.svg"))
        .route_service("/favicon.ico", ServeFile::new("static/logo.png"))
        .route_service("/postera-whitepaper.pdf", ServeFile::new("static/postera-whitepaper.pdf"));

    Router::new().merge(api_routes).merge(ui_routes)
}

async fn chain_info(State(state): State<Arc<AppState>>) -> Json<ChainInfo> {
    let chain = state.blockchain.read().unwrap();
    Json(chain.info())
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MinerStats {
    pub is_mining: bool,
    pub hashrate_hps: u64,
    pub last_attempts: u64,
    pub last_elapsed_ms: u64,
    pub last_updated: u64,
}

async fn miner_stats(State(state): State<Arc<AppState>>) -> Json<MinerStats> {
    let stats = state.miner_stats.read().unwrap().clone();
    Json(stats)
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
    commitment_root: String,
    nullifier_root: String,
    transactions: Vec<String>,
    coinbase_reward: u64,
    total_fees: u64,
    // Encrypted note data for miner monitoring (encrypted, so privacy-preserving)
    coinbase_ephemeral_pk: String,
    coinbase_ciphertext: String,
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

    Ok(Json(block_to_response(block, height)))
}

async fn get_block_by_height(
    State(state): State<Arc<AppState>>,
    Path(height): Path<u64>,
) -> Result<Json<BlockResponse>, StatusCode> {
    let chain = state.blockchain.read().unwrap();
    let block = chain
        .get_block_by_height(height)
        .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(block_to_response(block, height)))
}

fn block_to_response(block: &ShieldedBlock, height: u64) -> BlockResponse {
    BlockResponse {
        hash: hex::encode(block.hash()),
        height,
        prev_hash: hex::encode(block.header.prev_hash),
        timestamp: block.header.timestamp,
        difficulty: block.header.difficulty,
        nonce: block.header.nonce,
        tx_count: block.transactions.len(),
        commitment_root: hex::encode(block.header.commitment_root),
        nullifier_root: hex::encode(block.header.nullifier_root),
        transactions: block.transactions.iter().map(|tx| hex::encode(tx.hash())).collect(),
        coinbase_reward: block.coinbase.reward,
        total_fees: block.total_fees(),
        coinbase_ephemeral_pk: hex::encode(&block.coinbase.encrypted_note.ephemeral_pk),
        coinbase_ciphertext: hex::encode(&block.coinbase.encrypted_note.ciphertext),
    }
}

/// Shielded transaction response - only public data is exposed.
#[derive(Serialize)]
struct TransactionResponse {
    hash: String,
    fee: u64,
    spend_count: usize,
    output_count: usize,
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
                hash: hex::encode(tx.hash()),
                fee: tx.fee,
                spend_count: tx.spends.len(),
                output_count: tx.outputs.len(),
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
                        hash: hex::encode(tx.hash()),
                        fee: tx.fee,
                        spend_count: tx.spends.len(),
                        output_count: tx.outputs.len(),
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
                hash: hex::encode(tx.hash()),
                fee: tx.fee,
                spend_count: tx.spends.len(),
                output_count: tx.outputs.len(),
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
                    hash: hex::encode(tx.hash()),
                    fee: tx.fee,
                    spend_count: tx.spends.len(),
                    output_count: tx.outputs.len(),
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
    transaction: ShieldedTransaction,
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
    let hash = hex::encode(tx.hash());

    // Validate transaction
    {
        let chain = state.blockchain.read().unwrap();
        if let Some(params) = chain.verifying_params() {
            // Full validation with proof verification
            chain
                .state()
                .validate_transaction(&tx, params)
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
        } else {
            // Basic validation (no proof verification) - for development/testing
            // This still checks anchors, nullifiers, and signatures
            chain
                .state()
                .validate_transaction_basic(&tx)
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

            // Verify spend signatures manually since basic validation skips them
            for spend in &tx.spends {
                spend.verify_signature()
                    .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid spend signature".to_string()))?;
            }
        }
    }

    // Add to mempool
    let added = {
        let mut mempool = state.mempool.write().unwrap();
        mempool.add(tx.clone())
    };

    if !added {
        return Err((
            StatusCode::CONFLICT,
            "Transaction already in mempool or conflicts with pending".to_string(),
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
    total_fees: u64,
}

async fn get_mempool(State(state): State<Arc<AppState>>) -> Json<MempoolResponse> {
    let mempool = state.mempool.read().unwrap();
    let txs = mempool.get_transactions(100);

    Json(MempoolResponse {
        count: mempool.len(),
        transactions: txs.iter().map(|tx| hex::encode(tx.hash())).collect(),
        total_fees: mempool.total_fees(),
    })
}

// ============ Peer Sync Endpoints ============

/// Receive a block from a peer node.
async fn receive_block(
    State(state): State<Arc<AppState>>,
    Json(block): Json<ShieldedBlock>,
) -> Result<Json<ReceiveBlockResponse>, (StatusCode, String)> {
    let block_hash = block.hash_hex();

    info!("Received block {} from peer", &block_hash[..16]);

    // Try to add the block (handles forks and reorgs automatically)
    let (accepted, status) = {
        let mut chain = state.blockchain.write().unwrap();
        let old_height = chain.height();
        let old_tip = chain.latest_hash();

        match chain.try_add_block(block.clone()) {
            Ok(true) => {
                let new_height = chain.height();
                let reorged = old_tip != chain.get_block_by_height(old_height.min(new_height - 1))
                    .map(|b| b.hash())
                    .unwrap_or([0u8; 32]);

                if reorged {
                    info!("Chain reorganization! New tip: {} (height: {})", &block_hash[..16], new_height);
                } else {
                    info!("Added block {} to chain (height: {})", &block_hash[..16], new_height);
                }

                // Remove confirmed transactions from mempool
                let tx_hashes: Vec<[u8; 32]> = block
                    .transactions
                    .iter()
                    .map(|tx| tx.hash())
                    .collect();

                let mut mempool = state.mempool.write().unwrap();
                mempool.remove_confirmed(&tx_hashes);

                // Remove transactions with now-spent nullifiers
                let nullifiers: Vec<_> = block.nullifiers();
                mempool.remove_spent_nullifiers(&nullifiers);

                // Re-validate remaining mempool transactions
                let removed = mempool.revalidate(chain.state());
                if removed > 0 {
                    info!("Removed {} invalid transactions from mempool after block", removed);
                }

                (true, "accepted")
            }
            Ok(false) => {
                // Block was duplicate or stored as side chain
                info!("Block {} stored (orphan or side chain)", &block_hash[..16]);
                (false, "stored")
            }
            Err(e) => {
                warn!("Block {} rejected: {}", &block_hash[..16], e);
                return Err((StatusCode::BAD_REQUEST, format!("Block rejected: {}", e)));
            }
        }
    };

    // Relay to other peers (gossip protocol) if accepted
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
    Query(params): Query<BlocksSinceParams>,
) -> Json<Vec<ShieldedBlock>> {
    let chain = state.blockchain.read().unwrap();
    let current_height = chain.height();
    let end_height = match params.limit {
        Some(0) | None => current_height,
        Some(limit) => current_height.min(since_height.saturating_add(limit as u64)),
    };

    let mut blocks = Vec::new();

    // Return blocks from since_height+1 to end_height
    for h in (since_height + 1)..=end_height {
        if let Some(block) = chain.get_block_by_height(h) {
            blocks.push(block.clone());
        }
    }

    Json(blocks)
}

#[derive(Deserialize)]
struct BlocksSinceParams {
    limit: Option<usize>,
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
    Json(tx): Json<ShieldedTransaction>,
) -> Result<Json<SubmitTxResponse>, (StatusCode, String)> {
    let hash = hex::encode(tx.hash());

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
        if let Some(params) = chain.verifying_params() {
            chain
                .state()
                .validate_transaction(&tx, params)
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
        } else {
            chain
                .state()
                .validate_transaction_basic(&tx)
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

            for spend in &tx.spends {
                spend.verify_signature()
                    .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid spend signature".to_string()))?;
            }
        }
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
async fn relay_block(block: &ShieldedBlock, peers: &[String]) {
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
async fn relay_transaction(tx: &ShieldedTransaction, peers: &[String]) {
    let client = reqwest::Client::new();
    let tx_hash = &hex::encode(tx.hash())[..16];

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

// ============ Wallet Scanning Endpoints ============

/// An encrypted output from a block (transaction output or coinbase).
#[derive(Serialize)]
struct EncryptedOutput {
    /// Position in the commitment tree.
    position: u64,
    /// Block height where this output was created.
    block_height: u64,
    /// The note commitment (hex).
    note_commitment: String,
    /// Ephemeral public key for decryption (hex).
    ephemeral_pk: String,
    /// Encrypted note ciphertext (hex).
    ciphertext: String,
}

/// Response for outputs/since/:height endpoint.
#[derive(Serialize)]
struct OutputsSinceResponse {
    outputs: Vec<EncryptedOutput>,
    current_height: u64,
    commitment_root: String,
}

/// Get all encrypted outputs since a given block height.
/// Used by wallets to scan for incoming payments.
/// If since_height is 0, returns ALL outputs including genesis.
async fn get_outputs_since(
    State(state): State<Arc<AppState>>,
    Path(since_height): Path<u64>,
    Query(params): Query<OutputsSinceParams>,
) -> Json<OutputsSinceResponse> {
    let chain = state.blockchain.read().unwrap();
    let current_height = chain.height();
    let commitment_root = hex::encode(chain.commitment_root());
    let end_height = match params.limit {
        Some(0) | None => current_height,
        Some(limit) => current_height.min(since_height.saturating_add(limit as u64)),
    };

    let mut outputs = Vec::new();
    let mut position = 0u64;

    // Determine the starting height for collecting outputs
    // If since_height is 0, we want ALL outputs (initial scan)
    // Otherwise, we want outputs from since_height+1 onwards
    let start_height = if since_height == 0 { 0 } else { since_height + 1 };

    // First, count all commitments before start_height to get starting position
    for h in 0..start_height.min(current_height + 1) {
        if let Some(block) = chain.get_block_by_height(h) {
            for tx in &block.transactions {
                position += tx.outputs.len() as u64;
            }
            position += 1; // coinbase
        }
    }

    // Now collect outputs from start_height onwards
    for h in start_height..=end_height {
        if let Some(block) = chain.get_block_by_height(h) {
            // Transaction outputs
            for tx in &block.transactions {
                for output in &tx.outputs {
                    outputs.push(EncryptedOutput {
                        position,
                        block_height: h,
                        note_commitment: hex::encode(output.note_commitment.to_bytes()),
                        ephemeral_pk: hex::encode(&output.encrypted_note.ephemeral_pk),
                        ciphertext: hex::encode(&output.encrypted_note.ciphertext),
                    });
                    position += 1;
                }
            }

            // Coinbase output
            outputs.push(EncryptedOutput {
                position,
                block_height: h,
                note_commitment: hex::encode(block.coinbase.note_commitment.to_bytes()),
                ephemeral_pk: hex::encode(&block.coinbase.encrypted_note.ephemeral_pk),
                ciphertext: hex::encode(&block.coinbase.encrypted_note.ciphertext),
            });
            position += 1;
        }
    }

    Json(OutputsSinceResponse {
        outputs,
        current_height,
        commitment_root,
    })
}

#[derive(Deserialize)]
struct OutputsSinceParams {
    limit: Option<usize>,
}

/// Request for checking nullifiers.
#[derive(Deserialize)]
struct CheckNullifiersRequest {
    nullifiers: Vec<String>,
}

/// Response for nullifier checking.
#[derive(Serialize)]
struct CheckNullifiersResponse {
    /// List of nullifiers that are spent (exist in nullifier set).
    spent: Vec<String>,
}

/// Check which nullifiers are spent.
/// Used by wallets to determine which of their notes have been consumed.
async fn check_nullifiers(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CheckNullifiersRequest>,
) -> Json<CheckNullifiersResponse> {
    let chain = state.blockchain.read().unwrap();
    let nullifier_set = chain.state().nullifier_set();

    let mut spent = Vec::new();

    for nf_hex in &req.nullifiers {
        if let Ok(nf_bytes) = hex::decode(nf_hex) {
            if nf_bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&nf_bytes);
                let nullifier = Nullifier::from_bytes(arr);

                if nullifier_set.contains(&nullifier) {
                    spent.push(nf_hex.clone());
                }
            }
        }
    }

    Json(CheckNullifiersResponse { spent })
}

/// Response for witness endpoint.
#[derive(Serialize)]
struct WitnessResponse {
    /// The current commitment tree root (hex).
    root: String,
    /// The Merkle path (sibling hashes from leaf to root, hex encoded).
    path: Vec<String>,
    /// Position in the tree.
    position: u64,
}

/// Get a Merkle witness for a commitment.
/// Used when creating spend proofs.
async fn get_witness(
    State(state): State<Arc<AppState>>,
    Path(commitment_hex): Path<String>,
) -> Result<Json<WitnessResponse>, StatusCode> {
    let commitment_bytes: [u8; 32] = hex::decode(&commitment_hex)
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let chain = state.blockchain.read().unwrap();
    let commitment_tree = chain.state().commitment_tree();

    // Find the position of this commitment in the tree
    // We need to search through all positions
    let tree_size = commitment_tree.size();
    let mut found_position: Option<u64> = None;

    for pos in 0..tree_size {
        if let Some(cm) = commitment_tree.get_commitment(pos) {
            if cm.to_bytes() == commitment_bytes {
                found_position = Some(pos);
                break;
            }
        }
    }

    let position = found_position.ok_or(StatusCode::NOT_FOUND)?;

    let merkle_path = commitment_tree.get_path(position)
        .ok_or(StatusCode::NOT_FOUND)?;

    let root = commitment_tree.root();

    Ok(Json(WitnessResponse {
        root: hex::encode(root),
        path: merkle_path.auth_path.iter().map(|h| hex::encode(h)).collect(),
        position,
    }))
}

/// Get witness by position (simpler than searching by commitment).
async fn get_witness_by_position(
    State(state): State<Arc<AppState>>,
    Path(position): Path<u64>,
) -> Result<Json<WitnessResponse>, StatusCode> {
    let chain = state.blockchain.read().unwrap();
    let commitment_tree = chain.state().commitment_tree();

    let commitment = commitment_tree.get_commitment(position)
        .ok_or(StatusCode::NOT_FOUND)?;

    let merkle_path = commitment_tree.get_path(position)
        .ok_or(StatusCode::NOT_FOUND)?;

    let root = commitment_tree.root();

    Ok(Json(WitnessResponse {
        root: hex::encode(root),
        path: merkle_path.auth_path.iter().map(|h| hex::encode(h)).collect(),
        position,
    }))
}

/// Debug endpoint to test Poseidon hash compatibility.
/// Returns the hash of inputs [1,2,3,4] for comparison with circomlibjs.
async fn debug_poseidon_test() -> Json<serde_json::Value> {
    use crate::crypto::poseidon::{poseidon_hash, field_to_bytes32, DOMAIN_NOTE_COMMITMENT};
    use ark_bn254::Fr;
    use light_poseidon::{Poseidon, PoseidonHasher};

    // Test 1: Direct light-poseidon hash of [1,2,3,4]
    let inputs = [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)];
    let mut poseidon = Poseidon::<Fr>::new_circom(4).unwrap();
    let direct_hash = poseidon.hash(&inputs).unwrap();
    let direct_bytes = field_to_bytes32(&direct_hash);

    // Test 2: Our poseidon_hash with domain separation (domain=1, then [2,3,4])
    // This is: poseidon([1, 2, 3, 4]) with 1 as domain
    let domain_hash = poseidon_hash(DOMAIN_NOTE_COMMITMENT, &[Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)]);
    let domain_bytes = field_to_bytes32(&domain_hash);

    Json(serde_json::json!({
        "test": "Poseidon compatibility",
        "direct_hash_1234": {
            "description": "poseidon([1,2,3,4]) - direct light-poseidon",
            "bytes_le": direct_bytes.to_vec(),
            "hex": hex::encode(direct_bytes),
        },
        "domain_hash_1_234": {
            "description": "poseidon_hash(domain=1, [2,3,4]) - our wrapper",
            "bytes_le": domain_bytes.to_vec(),
            "hex": hex::encode(domain_bytes),
        }
    }))
}

/// Debug endpoint to list all commitments in the tree.
async fn debug_list_commitments(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let chain = state.blockchain.read().unwrap();
    let commitment_tree = chain.state().commitment_tree();
    let tree_size = commitment_tree.size();

    let mut commitments = Vec::new();
    for pos in 0..tree_size.min(100) { // Limit to first 100
        if let Some(cm) = commitment_tree.get_commitment(pos) {
            commitments.push(serde_json::json!({
                "position": pos,
                "commitment": hex::encode(cm.to_bytes())
            }));
        }
    }

    Json(serde_json::json!({
        "tree_size": tree_size,
        "root": hex::encode(commitment_tree.root()),
        "commitments": commitments
    }))
}

// ============ React App ============
// Serve index.html for SPA routes (wallet, explorer)
async fn serve_index() -> Html<String> {
    let content = std::fs::read_to_string("static/index.html")
        .unwrap_or_else(|_| "<!DOCTYPE html><html><body>App not found. Run 'cd wallet && npm run build' first.</body></html>".to_string());
    Html(content)
}
