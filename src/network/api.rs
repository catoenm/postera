use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};

use crate::core::{Block, Blockchain, ChainInfo, Transaction};
use crate::crypto::Address;
use tracing::info;

use super::Mempool;

/// Shared application state for the API.
pub struct AppState {
    pub blockchain: RwLock<Blockchain>,
    pub mempool: RwLock<Mempool>,
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
        .route("/mempool", get(get_mempool))
        // Peer sync endpoints
        .route("/blocks", post(receive_block))
        .route("/blocks/since/:height", get(get_blocks_since))
        .with_state(state)
}

async fn index() -> &'static str {
    "Quantum-Resistant Bitcoin Node API v0.1.0"
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
    {
        let mut mempool = state.mempool.write().unwrap();
        if !mempool.add(tx) {
            return Err((
                StatusCode::CONFLICT,
                "Transaction already in mempool".to_string(),
            ));
        }
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

    // Add to blockchain
    let mut chain = state.blockchain.write().unwrap();

    // Check if we already have this block
    if chain.get_block(&block.hash()).is_some() {
        return Ok(Json(ReceiveBlockResponse {
            status: "duplicate".to_string(),
            hash: block_hash,
        }));
    }

    // Validate and add the block
    match chain.add_block(block) {
        Ok(()) => {
            info!("Added block {} to chain (height: {})", &block_hash[..16], chain.height());
            Ok(Json(ReceiveBlockResponse {
                status: "accepted".to_string(),
                hash: block_hash,
            }))
        }
        Err(e) => {
            Err((StatusCode::BAD_REQUEST, format!("Block rejected: {}", e)))
        }
    }
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
