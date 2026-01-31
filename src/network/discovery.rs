use std::sync::Arc;
use tokio::time::{interval, Duration};
use tracing::{info, warn};

use super::AppState;

fn is_localhost_peer(peer: &str) -> bool {
    peer.contains("://localhost") || peer.contains("://127.0.0.1")
}

/// Discover peers from known peers and add them to our peer list.
pub async fn discover_from_peer(state: Arc<AppState>, peer_url: &str) -> Result<Vec<String>, DiscoveryError> {
    let client = reqwest::Client::new();

    // Get peer's peer list
    let url = format!("{}/peers", peer_url);
    let response: PeerListResponse = client
        .get(&url)
        .send()
        .await?
        .json()
        .await?;

    let mut new_peers = Vec::new();

    // Add new peers to our list
    {
        let mut our_peers = state.peers.write().unwrap();
        for peer in response.peers {
            // Don't add ourselves or duplicates
            if !our_peers.contains(&peer) && peer != peer_url && !is_localhost_peer(&peer) {
                our_peers.push(peer.clone());
                new_peers.push(peer);
            }
        }
    }

    Ok(new_peers)
}

/// Share our peer list with a peer.
pub async fn share_peers_with(state: Arc<AppState>, peer_url: &str) -> Result<(), DiscoveryError> {
    let client = reqwest::Client::new();

    let our_peers = state.peers.read().unwrap().clone();

    // Send our peers to them
    for peer in &our_peers {
        let url = format!("{}/peers", peer_url);
        let _ = client
            .post(&url)
            .json(&AddPeerRequest { url: peer.clone() })
            .send()
            .await;
    }

    Ok(())
}

/// Background task that periodically discovers new peers.
pub async fn discovery_loop(state: Arc<AppState>, discovery_interval_secs: u64) {
    let mut interval = interval(Duration::from_secs(discovery_interval_secs));

    loop {
        interval.tick().await;

        let peers = state.peers.read().unwrap().clone();

        if peers.is_empty() {
            continue;
        }

        // Try to discover new peers from each known peer
        for peer in &peers {
            match discover_from_peer(state.clone(), peer).await {
                Ok(new_peers) => {
                    if !new_peers.is_empty() {
                        info!("Discovered {} new peers from {}", new_peers.len(), peer);
                    }
                }
                Err(e) => {
                    warn!("Peer discovery from {} failed: {}", peer, e);
                }
            }

            // Also share our peers with them
            if let Err(e) = share_peers_with(state.clone(), peer).await {
                warn!("Failed to share peers with {}: {}", peer, e);
            }
        }
    }
}

/// Announce ourselves to a peer and get their peer list.
pub async fn announce_to_peer(
    our_url: &str,
    peer_url: &str,
) -> Result<Vec<String>, DiscoveryError> {
    let client = reqwest::Client::new();

    // Announce ourselves
    let url = format!("{}/peers", peer_url);
    let _ = client
        .post(&url)
        .json(&AddPeerRequest { url: our_url.to_string() })
        .send()
        .await;

    // Get their peer list
    let response: PeerListResponse = client
        .get(&url)
        .send()
        .await?
        .json()
        .await?;

    Ok(response
        .peers
        .into_iter()
        .filter(|peer| !is_localhost_peer(peer))
        .collect())
}

#[derive(Debug, serde::Deserialize)]
struct PeerListResponse {
    peers: Vec<String>,
    #[allow(dead_code)]
    count: usize,
}

#[derive(Debug, serde::Serialize)]
struct AddPeerRequest {
    url: String,
}

#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),
}
