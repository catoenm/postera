use clap::{Parser, Subcommand};
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use postera::config::{self, GENESIS_DIFFICULTY};
use postera::consensus::mine_block;
use postera::core::Blockchain;
use postera::crypto::Address;
use postera::network::{create_router, Mempool};
use postera::wallet::Wallet;

#[derive(Parser)]
#[command(name = "postera")]
#[command(about = "Postera - A post-quantum cryptocurrency", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new wallet (keypair)
    NewWallet {
        /// Output file for the wallet (default: wallet.json)
        #[arg(short, long, default_value = "wallet.json")]
        output: String,
    },
    /// Check balance of an address
    Balance {
        /// The address to check
        address: String,
        /// Node URL to query
        #[arg(short, long, default_value = "http://localhost:8333")]
        node: String,
    },
    /// Send coins to an address
    Send {
        /// Recipient address
        to: String,
        /// Amount to send
        amount: u64,
        /// Transaction fee
        #[arg(short, long, default_value = "1000")]
        fee: u64,
        /// Wallet file
        #[arg(short, long, default_value = "wallet.json")]
        wallet: String,
        /// Node URL to submit transaction
        #[arg(short, long, default_value = "http://localhost:8333")]
        node: String,
    },
    /// Start mining blocks
    Mine {
        /// Address to receive mining rewards
        #[arg(short, long)]
        address: String,
        /// Number of blocks to mine (0 = unlimited)
        #[arg(short, long, default_value = "0")]
        blocks: u64,
        /// Mining difficulty (leading zero bits)
        #[arg(short, long, default_value = "16")]
        difficulty: u64,
    },
    /// Run a full node
    Node {
        /// Port to listen on (or set POSTERA_PORT env var)
        #[arg(short, long)]
        port: Option<u16>,
        /// Peer nodes to connect to (in addition to seed nodes)
        #[arg(long)]
        peer: Vec<String>,
        /// Data directory (or set POSTERA_DATA_DIR env var)
        #[arg(short, long)]
        data_dir: Option<String>,
        /// Enable mining to this address (or set POSTERA_MINE_ADDRESS env var)
        #[arg(long)]
        mine: Option<String>,
        /// Disable connecting to seed nodes
        #[arg(long)]
        no_seeds: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::NewWallet { output } => {
            cmd_new_wallet(&output)?;
        }
        Commands::Balance { address, node } => {
            cmd_balance(&address, &node).await?;
        }
        Commands::Send {
            to,
            amount,
            fee,
            wallet,
            node,
        } => {
            cmd_send(&to, amount, fee, &wallet, &node).await?;
        }
        Commands::Mine {
            address,
            blocks,
            difficulty,
        } => {
            cmd_mine(&address, blocks, difficulty)?;
        }
        Commands::Node {
            port,
            peer,
            data_dir,
            mine,
            no_seeds,
        } => {
            // Use config defaults, with CLI/env overrides
            let port = port.unwrap_or_else(config::get_port);
            let data_dir = data_dir.unwrap_or_else(config::get_data_dir);
            let mine = mine.or_else(config::get_mining_address);

            // Combine seed nodes with CLI peers
            let mut peers = if no_seeds {
                Vec::new()
            } else {
                config::get_seed_nodes()
            };
            peers.extend(peer);

            cmd_node(port, peers, &data_dir, mine).await?;
        }
    }

    Ok(())
}

fn cmd_new_wallet(output: &str) -> anyhow::Result<()> {
    println!("Generating new Postera wallet...");
    let wallet = Wallet::generate();

    wallet.save(output)?;

    println!("Wallet saved to: {}", output);
    println!("Address: {}", wallet.address().to_hex());
    println!("\nThis wallet uses CRYSTALS-Dilithium post-quantum signatures.");
    Ok(())
}

async fn cmd_balance(address: &str, node: &str) -> anyhow::Result<()> {
    let url = format!("{}/account/{}", node, address);

    let client = reqwest::Client::new();
    let resp = client.get(&url).send().await?;

    if resp.status().is_success() {
        let data: serde_json::Value = resp.json().await?;
        let balance = data["balance"].as_u64().unwrap_or(0);
        let nonce = data["nonce"].as_u64().unwrap_or(0);

        println!("Address: {}", address);
        println!("Balance: {} (smallest units)", balance);
        println!("Nonce:   {}", nonce);
    } else {
        println!("Failed to fetch balance: {}", resp.status());
    }

    Ok(())
}

async fn cmd_send(to: &str, amount: u64, fee: u64, wallet_path: &str, node: &str) -> anyhow::Result<()> {
    // Load wallet
    let wallet = Wallet::load(wallet_path)?;
    println!("Loaded wallet: {}", wallet.address().to_hex());

    // Get current nonce from node
    let url = format!("{}/account/{}", node, wallet.address().to_hex());
    let client = reqwest::Client::new();
    let resp = client.get(&url).send().await?;

    let nonce = if resp.status().is_success() {
        let data: serde_json::Value = resp.json().await?;
        data["nonce"].as_u64().unwrap_or(0)
    } else {
        0
    };

    // Parse recipient address
    let to_addr = Address::from_hex(to)?;

    // Create and sign transaction
    let tx = wallet.create_transaction(to_addr, amount, fee, nonce);

    println!("Created transaction:");
    println!("  From:   {}", tx.from);
    println!("  To:     {}", tx.to);
    println!("  Amount: {}", tx.amount);
    println!("  Fee:    {}", tx.fee);
    println!("  Nonce:  {}", tx.nonce);
    println!("  Hash:   {}", tx.hash_hex());

    // Submit to node
    let submit_url = format!("{}/tx", node);
    let resp = client
        .post(&submit_url)
        .json(&serde_json::json!({ "transaction": tx }))
        .send()
        .await?;

    if resp.status().is_success() {
        let result: serde_json::Value = resp.json().await?;
        println!("\nTransaction submitted!");
        println!("Status: {}", result["status"]);
    } else {
        let error = resp.text().await?;
        println!("\nFailed to submit transaction: {}", error);
    }

    Ok(())
}

fn cmd_mine(address: &str, blocks: u64, difficulty: u64) -> anyhow::Result<()> {
    let miner_address = Address::from_hex(address)?;
    println!("Starting standalone miner...");
    println!("Miner address: {}", miner_address);
    println!("Difficulty: {} leading zero bits", difficulty);

    let mut blockchain = Blockchain::new(difficulty);
    let mut blocks_mined = 0u64;

    loop {
        let mempool_txs = vec![]; // Standalone miner has no mempool
        let mut block = blockchain.create_block_template(miner_address, mempool_txs);

        println!(
            "\nMining block {} (prev: {}...)",
            blockchain.height() + 1,
            &hex::encode(&block.header.prev_hash)[..16]
        );

        let start = std::time::Instant::now();
        let attempts = mine_block(&mut block);
        let elapsed = start.elapsed();

        println!(
            "Block mined! Hash: {}...",
            &block.hash_hex()[..16]
        );
        println!(
            "  {} attempts in {:.2}s ({:.0} H/s)",
            attempts,
            elapsed.as_secs_f64(),
            attempts as f64 / elapsed.as_secs_f64()
        );

        blockchain.add_block(block)?;

        blocks_mined += 1;
        println!(
            "  Chain height: {}, Miner balance: {}",
            blockchain.height(),
            blockchain.balance(&miner_address)
        );

        if blocks > 0 && blocks_mined >= blocks {
            println!("\nMined {} blocks, stopping.", blocks_mined);
            break;
        }
    }

    Ok(())
}

async fn cmd_node(port: u16, peers: Vec<String>, data_dir: &str, mine: Option<String>) -> anyhow::Result<()> {
    use postera::network::{AppState, sync_from_peer, sync_loop, broadcast_block, discovery_loop, announce_to_peer};
    use postera::consensus::mine_block;
    use std::sync::RwLock;

    // Create data directory if needed
    std::fs::create_dir_all(data_dir)?;

    println!("===========================================");
    println!("         Postera Node v0.1.0");
    println!("===========================================");
    println!();
    println!("Network:        {}", config::NETWORK_NAME);
    println!("Genesis diff:   {} leading zero bits", GENESIS_DIFFICULTY);
    println!("Data directory: {}", data_dir);
    println!("API endpoint:   http://0.0.0.0:{}", port);
    println!("Explorer:       http://localhost:{}/explorer", port);
    println!("Wallet:         http://localhost:{}/wallet", port);
    if let Some(ref addr) = mine {
        println!("Mining to:      {}", addr);
    }
    if !peers.is_empty() {
        println!("Seed peers:     {}", peers.len());
    }
    println!();

    // Initialize blockchain with persistence
    // Always use GENESIS_DIFFICULTY for consistent genesis blocks
    let db_path = format!("{}/blockchain", data_dir);
    let blockchain = Blockchain::open(&db_path, GENESIS_DIFFICULTY)?;
    let mempool = Mempool::new();

    let state = Arc::new(AppState {
        blockchain: RwLock::new(blockchain),
        mempool: RwLock::new(mempool),
        peers: RwLock::new(peers.clone()),
    });

    // Create router with API (wallet and explorer are served from static React app)
    let app = create_router(state.clone());

    // Build our own URL for peer announcements
    let our_url = format!("http://localhost:{}", port);

    // Sync from peers on startup
    if !peers.is_empty() {
        println!("Peers: {:?}", peers);
        println!("Syncing from peers...");

        for peer in &peers {
            // Announce ourselves to this peer
            if let Ok(discovered) = announce_to_peer(&our_url, peer).await {
                if !discovered.is_empty() {
                    println!("  Discovered {} peers from {}", discovered.len(), peer);
                    // Add discovered peers to our list
                    let mut our_peers = state.peers.write().unwrap();
                    for p in discovered {
                        if !our_peers.contains(&p) && p != our_url {
                            our_peers.push(p);
                        }
                    }
                }
            }

            match sync_from_peer(state.clone(), peer).await {
                Ok(n) => {
                    if n > 0 {
                        println!("  Synced {} blocks from {}", n, peer);
                    } else {
                        println!("  {} - already in sync", peer);
                    }
                }
                Err(e) => {
                    println!("  {} - sync failed: {}", peer, e);
                }
            }
        }

        // Start background sync loop (checks every 30 seconds)
        let sync_state = state.clone();
        let sync_peers = state.peers.read().unwrap().clone();
        tokio::spawn(async move {
            sync_loop(sync_state, sync_peers, 30).await;
        });

        // Start peer discovery loop (checks every 60 seconds)
        let discovery_state = state.clone();
        tokio::spawn(async move {
            discovery_loop(discovery_state, 60).await;
        });
    }

    // Start integrated miner if requested
    if let Some(miner_addr) = mine {
        let miner_address = Address::from_hex(&miner_addr)?;
        let mine_state = state.clone();

        tokio::spawn(async move {
            println!("Starting integrated miner...");

            loop {
                // Get mempool transactions
                let mempool_txs = {
                    let mempool = mine_state.mempool.read().unwrap();
                    mempool.get_transactions(100)
                };

                // Create block template
                let mut block = {
                    let chain = mine_state.blockchain.read().unwrap();
                    chain.create_block_template(miner_address, mempool_txs)
                };

                let (height, difficulty) = {
                    let chain = mine_state.blockchain.read().unwrap();
                    (chain.height() + 1, block.header.difficulty)
                };

                println!("Mining block {} (difficulty: {})...", height, difficulty);

                // Mine in a blocking task to not block the async runtime
                let mined_block = tokio::task::spawn_blocking(move || {
                    mine_block(&mut block);
                    block
                }).await.unwrap();

                // Add to local chain
                {
                    let mut chain = mine_state.blockchain.write().unwrap();
                    match chain.add_block(mined_block.clone()) {
                        Ok(()) => {
                            println!(
                                "Mined block {} (hash: {}...)",
                                chain.height(),
                                &mined_block.hash_hex()[..16]
                            );

                            // Remove mined transactions from mempool
                            let tx_hashes: Vec<[u8; 32]> = mined_block
                                .transactions
                                .iter()
                                .skip(1) // Skip coinbase
                                .map(|tx| tx.hash())
                                .collect();

                            let mut mempool = mine_state.mempool.write().unwrap();
                            mempool.remove_confirmed(&tx_hashes);

                            // Re-validate remaining mempool transactions
                            let removed = mempool.revalidate(chain.state());
                            if removed > 0 {
                                println!("  Removed {} invalid transactions from mempool", removed);
                            }
                        }
                        Err(e) => {
                            println!("Failed to add mined block: {}", e);
                            continue;
                        }
                    }
                }

                // Broadcast to peers (use current peer list for newly discovered peers)
                let current_peers = mine_state.peers.read().unwrap().clone();
                if !current_peers.is_empty() {
                    broadcast_block(&mined_block, &current_peers).await;
                }
            }
        });
    }

    let chain_height = state.blockchain.read().unwrap().height();
    println!();
    println!("Chain height: {}", chain_height);
    println!("Node is running. Press Ctrl+C to stop.");
    println!();

    // Start server
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
