use std::sync::Arc;
use tokio::time::{interval, Duration};
use tracing::{info, warn};

use crate::core::Block;

use super::AppState;

/// Sync the local chain from a peer node.
pub async fn sync_from_peer(state: Arc<AppState>, peer_url: &str) -> Result<u64, SyncError> {
    let client = reqwest::Client::new();

    // Get peer's chain info
    let info_url = format!("{}/chain/info", peer_url);
    let peer_info: PeerChainInfo = client
        .get(&info_url)
        .send()
        .await?
        .json()
        .await?;

    let local_height = {
        let chain = state.blockchain.read().unwrap();
        chain.height()
    };

    if peer_info.height <= local_height {
        info!("Peer {} is not ahead (peer: {}, local: {})", peer_url, peer_info.height, local_height);
        return Ok(0);
    }

    info!(
        "Syncing from peer {} (peer height: {}, local: {})",
        peer_url, peer_info.height, local_height
    );

    // Fetch blocks we don't have
    let blocks_url = format!("{}/blocks/since/{}", peer_url, local_height);
    let blocks: Vec<Block> = client
        .get(&blocks_url)
        .send()
        .await?
        .json()
        .await?;

    let mut synced = 0u64;
    for block in blocks {
        let mut chain = state.blockchain.write().unwrap();
        match chain.add_block(block) {
            Ok(()) => {
                synced += 1;
            }
            Err(e) => {
                warn!("Failed to add block during sync: {}", e);
                break;
            }
        }
    }

    info!("Synced {} blocks from {}", synced, peer_url);
    Ok(synced)
}

/// Broadcast a newly mined block to all peers.
pub async fn broadcast_block(block: &Block, peers: &[String]) -> Vec<Result<(), SyncError>> {
    let client = reqwest::Client::new();
    let mut results = Vec::new();

    for peer in peers {
        let url = format!("{}/blocks", peer);
        let result = client
            .post(&url)
            .json(block)
            .send()
            .await
            .map(|_| ())
            .map_err(SyncError::from);

        if let Err(ref e) = result {
            warn!("Failed to broadcast block to {}: {}", peer, e);
        } else {
            info!("Broadcast block {} to {}", block.hash_hex(), peer);
        }

        results.push(result);
    }

    results
}

/// Background task that periodically syncs with peers.
pub async fn sync_loop(state: Arc<AppState>, peers: Vec<String>, sync_interval_secs: u64) {
    if peers.is_empty() {
        return;
    }

    let mut interval = interval(Duration::from_secs(sync_interval_secs));

    loop {
        interval.tick().await;

        for peer in &peers {
            match sync_from_peer(state.clone(), peer).await {
                Ok(n) if n > 0 => {
                    info!("Synced {} blocks from {}", n, peer);
                }
                Ok(_) => {}
                Err(e) => {
                    warn!("Sync from {} failed: {}", peer, e);
                }
            }
        }
    }
}

#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
struct PeerChainInfo {
    height: u64,
    latest_hash: String,
    difficulty: u64,
    total_accounts: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("Invalid response: {0}")]
    InvalidResponse(String),
}
