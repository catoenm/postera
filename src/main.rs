use clap::{Parser, Subcommand};
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use postera::config::{self, GENESIS_DIFFICULTY};
use postera::consensus::MiningPool;
use postera::core::ShieldedBlockchain;
use postera::crypto::note::ViewingKey;
use postera::network::{create_router, Mempool};
use postera::wallet::ShieldedWallet;

#[derive(Parser)]
#[command(name = "postera")]
#[command(about = "Postera - A privacy-preserving post-quantum cryptocurrency", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy)]
enum MiningMode {
    Mine,
    Benchmark,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate ZK proving/verifying parameters (one-time setup)
    Setup {
        /// Output directory for parameter files
        #[arg(short, long, default_value = "params")]
        output_dir: String,
    },
    /// Generate a new shielded wallet
    NewWallet {
        /// Output file for the wallet (default: wallet.json)
        #[arg(short, long, default_value = "wallet.json")]
        output: String,
    },
    /// Show wallet balance (scans blockchain for owned notes)
    Balance {
        /// Wallet file
        #[arg(short, long, default_value = "wallet.json")]
        wallet: String,
        /// Node URL to query
        #[arg(short, long, default_value = "http://localhost:8333")]
        node: String,
    },
    /// Start mining blocks
    Mine {
        /// Wallet file (mining rewards go to this wallet)
        #[arg(short, long, default_value = "wallet.json")]
        wallet: String,
        /// Number of blocks to mine (0 = unlimited)
        #[arg(short, long, default_value = "0")]
        blocks: u64,
        /// Mining difficulty (leading zero bits)
        #[arg(short, long, default_value = "16")]
        difficulty: u64,
        /// Number of mining threads to use
        #[arg(short, long, default_value = "1")]
        jobs: usize,
    },
    /// Run a mining benchmark (mines N blocks and prints avg hashrate)
    Benchmark {
        /// Wallet file (mining rewards go to this wallet)
        #[arg(short, long, default_value = "wallet.json")]
        wallet: String,
        /// Number of blocks to mine
        #[arg(short, long, default_value = "20")]
        blocks: u64,
        /// Mining difficulty (leading zero bits)
        #[arg(short, long, default_value = "20")]
        difficulty: u64,
        /// Number of mining threads to use
        #[arg(short, long, default_value = "1")]
        jobs: usize,
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
        /// Wallet file for mining (enables mining if provided)
        #[arg(long)]
        mine: Option<String>,
        /// Number of mining threads to use
        #[arg(short, long, default_value = "1")]
        jobs: usize,
        /// Disable connecting to seed nodes
        #[arg(long)]
        no_seeds: bool,
        /// Skip ZK proof verification (INSECURE - for development only)
        #[arg(long)]
        skip_proof_verification: bool,
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
        Commands::Setup { output_dir } => {
            cmd_setup(&output_dir)?;
        }
        Commands::NewWallet { output } => {
            cmd_new_wallet(&output)?;
        }
        Commands::Balance { wallet, node } => {
            cmd_balance(&wallet, &node).await?;
        }
        Commands::Mine {
            wallet,
            blocks,
            difficulty,
            jobs,
        } => {
            cmd_mine(
                &wallet,
                blocks,
                difficulty,
                jobs,
                MiningMode::Mine,
            )?;
        }
        Commands::Benchmark {
            wallet,
            blocks,
            difficulty,
            jobs,
        } => {
            cmd_mine(
                &wallet,
                blocks,
                difficulty,
                jobs,
                MiningMode::Benchmark,
            )?;
        }
        Commands::Node {
            port,
            peer,
            data_dir,
            mine,
            jobs,
            no_seeds,
            skip_proof_verification,
        } => {
            // Use config defaults, with CLI/env overrides
            let port = port.unwrap_or_else(config::get_port);
            let data_dir = data_dir.unwrap_or_else(config::get_data_dir);

            // Combine seed nodes with CLI peers
            let mut peers = if no_seeds {
                Vec::new()
            } else {
                config::get_seed_nodes()
            };
            peers.extend(peer);

            cmd_node(port, peers, &data_dir, mine, jobs, skip_proof_verification).await?;
        }
    }

    Ok(())
}

fn cmd_setup(output_dir: &str) -> anyhow::Result<()> {
    use postera::crypto::setup::{save_proving_params, save_verifying_params};
    use postera::crypto::generate_parameters;

    println!("===========================================");
    println!("   Postera ZK Parameter Generation");
    println!("===========================================");
    println!();
    println!("This generates the proving and verifying parameters");
    println!("for the zk-SNARK circuits. This is a one-time setup.");
    println!();
    println!("Output directory: {}", output_dir);
    println!();

    // Create output directory
    std::fs::create_dir_all(output_dir)?;

    let proving_path = format!("{}/proving.params", output_dir);
    let verifying_path = format!("{}/verifying.params", output_dir);

    // Check if files already exist
    if std::path::Path::new(&proving_path).exists() && std::path::Path::new(&verifying_path).exists() {
        println!("Parameter files already exist:");
        println!("  - {}", proving_path);
        println!("  - {}", verifying_path);
        println!();
        println!("To regenerate, delete these files first.");
        return Ok(());
    }

    println!("Generating parameters (this takes 2-5 minutes)...");
    println!();

    let start = std::time::Instant::now();
    let mut rng = ark_std::rand::rngs::OsRng;

    let (proving_params, verifying_params) = generate_parameters(&mut rng)
        .map_err(|e| anyhow::anyhow!("Parameter generation failed: {}", e))?;

    let elapsed = start.elapsed();
    println!("Parameters generated in {:.1}s", elapsed.as_secs_f64());
    println!();

    // Save parameters
    println!("Saving proving parameters to {}...", proving_path);
    save_proving_params(&proving_params, &proving_path)?;

    println!("Saving verifying parameters to {}...", verifying_path);
    save_verifying_params(&verifying_params, &verifying_path)?;

    println!();
    println!("Done! You can now:");
    println!();
    println!("  1. Check params/verifying.params into git (safe to distribute)");
    println!("  2. Keep params/proving.params private or distribute to wallet users");
    println!();
    println!("  Nodes only need verifying.params");
    println!("  Wallets need proving.params to create transactions");
    println!();

    Ok(())
}

fn cmd_new_wallet(output: &str) -> anyhow::Result<()> {
    println!("Generating new Postera shielded wallet...");
    let wallet = ShieldedWallet::generate();

    wallet.save(output)?;

    println!("Wallet saved to: {}", output);
    println!("Address: {}", hex::encode(wallet.pk_hash()));
    println!("\nThis wallet uses:");
    println!("  - CRYSTALS-Dilithium post-quantum signatures");
    println!("  - zk-SNARKs for private transactions");
    println!("\nYour balance is private and can only be viewed with this wallet file.");
    Ok(())
}

async fn cmd_balance(wallet_path: &str, _node: &str) -> anyhow::Result<()> {
    // Load wallet
    let wallet = ShieldedWallet::load(wallet_path)?;

    println!("Wallet: {}", wallet_path);
    println!("Public key hash: {}", hex::encode(wallet.pk_hash()));
    println!();
    println!("Balance: {} (from {} unspent notes)", wallet.balance(), wallet.note_count());
    println!();
    println!("Note: To update your balance, run the node and let the wallet scan the blockchain.");

    Ok(())
}

fn cmd_mine(
    wallet_path: &str,
    blocks: u64,
    difficulty: u64,
    jobs: usize,
    mode: MiningMode,
) -> anyhow::Result<()> {
    let jobs = jobs.max(1);
    // Load wallet for mining rewards
    let wallet = ShieldedWallet::load(wallet_path)?;
    let miner_pk_hash = wallet.pk_hash();
    let viewing_key = wallet.viewing_key().clone();

    match mode {
        MiningMode::Mine => println!("Starting standalone miner..."),
        MiningMode::Benchmark => println!("Starting mining benchmark..."),
    }
    println!("Miner wallet: {}", wallet_path);
    println!("Miner pk_hash: {}", hex::encode(miner_pk_hash));
    println!("Difficulty: {} leading zero bits", difficulty);
    println!("Threads: {}", jobs);
    let pool = MiningPool::new(jobs);
    let mut blockchain = ShieldedBlockchain::with_miner(difficulty, miner_pk_hash, &viewing_key);
    let mut blocks_mined = 0u64;
    let mut total_attempts = 0u64;
    let mut total_elapsed = std::time::Duration::ZERO;

    loop {
        let mempool_txs = vec![]; // Standalone miner has no mempool
        let mut block = blockchain.create_block_template(miner_pk_hash, &viewing_key, mempool_txs);

        println!(
            "\nMining block {} (prev: {}...)",
            blockchain.height() + 1,
            &hex::encode(&block.header.prev_hash)[..16]
        );

        let start = std::time::Instant::now();
        let attempts = pool.mine_block(&mut block);
        let elapsed = start.elapsed();
        total_attempts = total_attempts.saturating_add(attempts);
        total_elapsed += elapsed;

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
            "  Chain height: {}, Commitments: {}",
            blockchain.height(),
            blockchain.state().commitment_count()
        );

        if blocks > 0 && blocks_mined >= blocks {
            println!("\nMined {} blocks, stopping.", blocks_mined);
            if total_elapsed.as_secs_f64() > 0.0 {
                let avg_hashrate = total_attempts as f64 / total_elapsed.as_secs_f64();
                let label = match mode {
                    MiningMode::Mine => "Summary",
                    MiningMode::Benchmark => "Benchmark summary",
                };
                println!("{}:", label);
                println!(
                    "  Total attempts: {} in {:.2}s",
                    total_attempts,
                    total_elapsed.as_secs_f64()
                );
                println!("  Avg hashrate: {:.0} H/s", avg_hashrate);
            }
            break;
        }
    }

    Ok(())
}

async fn cmd_node(
    port: u16,
    peers: Vec<String>,
    data_dir: &str,
    mine_wallet: Option<String>,
    jobs: usize,
    skip_proof_verification: bool,
) -> anyhow::Result<()> {
    use postera::network::{AppState, MinerStats, sync_from_peer, sync_loop, broadcast_block, discovery_loop, announce_to_peer};
    use postera::crypto::get_or_generate_parameters;
    use std::sync::RwLock;

    // Create data directory if needed
    std::fs::create_dir_all(data_dir)?;

    println!("===========================================");
    println!("      Postera Shielded Node v0.2.0");
    println!("===========================================");
    println!();
    println!("Network:        {}", config::NETWORK_NAME);
    println!("Genesis diff:   {} leading zero bits", GENESIS_DIFFICULTY);
    println!("Data directory: {}", data_dir);
    println!("API endpoint:   http://0.0.0.0:{}", port);
    println!("Explorer:       http://localhost:{}/explorer", port);
    println!("Wallet:         http://localhost:{}/wallet", port);

    // Load miner wallet if provided
    let miner_info = if let Some(wallet_path) = &mine_wallet {
        let wallet = ShieldedWallet::load(wallet_path)?;
        let pk_hash = wallet.pk_hash();
        let viewing_key = wallet.viewing_key().clone();
        println!("Mining to:      {} (pk_hash)", hex::encode(pk_hash));
        Some((pk_hash, viewing_key))
    } else {
        None
    };

    if !peers.is_empty() {
        println!("Seed peers:     {}", peers.len());
    }
    println!();

    // Initialize blockchain with persistence
    let db_path = format!("{}/blockchain", data_dir);
    let mut blockchain = ShieldedBlockchain::open(&db_path, GENESIS_DIFFICULTY)?;
    let mempool = Mempool::new();

    // Load or generate ZK verifying parameters for proof verification
    if skip_proof_verification {
        println!();
        println!("WARNING: Proof verification is DISABLED (--skip-proof-verification)");
        println!("         This is INSECURE and should only be used for development.");
        println!();
    } else {
        println!();
        println!("Loading ZK verification parameters...");

        // Check multiple locations for verifying params:
        // 1. Data directory (node-specific cache)
        // 2. params/ directory (pre-generated, checked into git)
        let data_dir_path = format!("{}/verifying.params", data_dir);
        let repo_params_path = "params/verifying.params";

        let verifying_params = if std::path::Path::new(&data_dir_path).exists() {
            // Load from data directory (cached)
            println!("  Loading from {}...", data_dir_path);
            postera::crypto::setup::load_verifying_params(&data_dir_path)
                .map_err(|e| anyhow::anyhow!("Failed to load verifying params: {}", e))?
        } else if std::path::Path::new(repo_params_path).exists() {
            // Load from repo params/ directory (pre-generated)
            println!("  Loading from {}...", repo_params_path);
            let params = postera::crypto::setup::load_verifying_params(repo_params_path)
                .map_err(|e| anyhow::anyhow!("Failed to load verifying params: {}", e))?;

            // Copy to data directory for faster future loads
            println!("  Caching to {}...", data_dir_path);
            postera::crypto::setup::save_verifying_params(&params, &data_dir_path)?;
            params
        } else {
            // Generate new parameters (this takes 2-5 minutes)
            println!("  No pre-generated params found. Generating new parameters...");
            println!("  (This takes 2-5 minutes. Run 'postera setup' to pre-generate.)");
            let mut rng = ark_std::rand::rngs::OsRng;
            let (_proving, verifying) = get_or_generate_parameters(&mut rng)
                .map_err(|e| anyhow::anyhow!("Failed to generate parameters: {}", e))?;

            // Save to data directory for future use
            println!("  Saving to {}...", data_dir_path);
            postera::crypto::setup::save_verifying_params(&verifying, &data_dir_path)?;
            verifying
        };

        blockchain.set_verifying_params(Arc::new(verifying_params));
        println!("  ZK proof verification ENABLED");
        println!();
    }

    let state = Arc::new(AppState {
        blockchain: RwLock::new(blockchain),
        mempool: RwLock::new(mempool),
        peers: RwLock::new(peers.clone()),
        miner_stats: RwLock::new(MinerStats::default()),
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
    if let Some((miner_pk_hash, viewing_key)) = miner_info {
        let jobs = jobs.max(1);
        let mine_state = state.clone();
        let pool = Arc::new(MiningPool::new(jobs));

        tokio::spawn(async move {
            println!("Starting integrated miner...");
            println!("Mining threads: {}", jobs);
            {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let mut stats = mine_state.miner_stats.write().unwrap();
                stats.is_mining = true;
                stats.last_updated = now;
            }

            loop {
                // Get mempool transactions
                let mempool_txs = {
                    let mempool = mine_state.mempool.read().unwrap();
                    mempool.get_transactions(100)
                };

                // Create block template
                let mut block = {
                    let chain = mine_state.blockchain.read().unwrap();
                    chain.create_block_template(miner_pk_hash, &viewing_key, mempool_txs)
                };

                let (height, difficulty) = {
                    let chain = mine_state.blockchain.read().unwrap();
                    (chain.height() + 1, block.header.difficulty)
                };

                println!("Mining block {} (difficulty: {})...", height, difficulty);

                // Mine in a blocking task to not block the async runtime
                let mine_state_for_stats = mine_state.clone();
                let pool = Arc::clone(&pool);
                let mined_block = tokio::task::spawn_blocking(move || {
                    let start = std::time::Instant::now();
                    let attempts = pool.mine_block(&mut block);
                    let elapsed = start.elapsed();
                    let hashrate = if elapsed.as_secs_f64() > 0.0 {
                        (attempts as f64 / elapsed.as_secs_f64()) as u64
                    } else {
                        0
                    };
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();

                    {
                        let mut stats = mine_state_for_stats.miner_stats.write().unwrap();
                        stats.hashrate_hps = hashrate;
                        stats.last_attempts = attempts;
                        stats.last_elapsed_ms = elapsed.as_millis() as u64;
                        stats.last_updated = now;
                    }

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
                                .map(|tx| tx.hash())
                                .collect();

                            let mut mempool = mine_state.mempool.write().unwrap();
                            mempool.remove_confirmed(&tx_hashes);

                            // Remove transactions with spent nullifiers
                            let nullifiers: Vec<_> = mined_block.nullifiers();
                            mempool.remove_spent_nullifiers(&nullifiers);

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

    // Start server with ConnectInfo for rate limiting
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await?;

    Ok(())
}
