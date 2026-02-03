use clap::{Parser, Subcommand, ValueEnum};
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use postera::config::{self, GENESIS_DIFFICULTY};
use postera::consensus::{MiningPool, SimdMode};
use postera::core::{ShieldedBlock, ShieldedBlockchain};
use postera::network::{create_router, Mempool};
use postera::wallet::ShieldedWallet;

#[derive(Parser)]
#[command(name = "postera")]
#[command(about = "Postera - A privacy-preserving post-quantum cryptocurrency", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum SimdArg {
    Neon,
}

impl From<SimdArg> for SimdMode {
    fn from(value: SimdArg) -> Self {
        match value {
            SimdArg::Neon => SimdMode::Neon,
        }
    }
}

fn require_simd_support(simd: Option<SimdMode>) -> Option<SimdMode> {
    if let Some(mode) = simd {
        if !mode.is_supported() {
            eprintln!("SIMD mode {:?} requires ARMv8 NEON+SHA2 support.", mode);
            std::process::exit(1);
        }
    }
    simd
}

/// Expected SHA256 checksums for verification keys (for integrity verification)
const SPEND_VKEY_SHA256: &str = "a1ff15d0968e066b6d8285993580f57065d67fb7ce5625ed7966fd13a8952e27";
const OUTPUT_VKEY_SHA256: &str = "c97a5eb20c85009a2abd2f85b1bece88c054e913a24423e1973e0629537ff038";

/// Find verification keys, checking committed keys first, then build directory.
/// Also verifies checksums for committed keys to ensure integrity.
fn find_verification_keys() -> anyhow::Result<(String, String)> {
    use sha2::{Sha256, Digest};
    use std::path::Path;

    // Paths to check (in order of preference)
    let committed_spend = "circuits/keys/spend_vkey.json";
    let committed_output = "circuits/keys/output_vkey.json";
    let build_spend = "circuits/build/spend_vkey.json";
    let build_output = "circuits/build/output_vkey.json";

    // Check committed keys first (production)
    if Path::new(committed_spend).exists() && Path::new(committed_output).exists() {
        // Verify checksums for committed keys
        let spend_data = std::fs::read(committed_spend)?;
        let output_data = std::fs::read(committed_output)?;

        let spend_hash = hex::encode(Sha256::digest(&spend_data));
        let output_hash = hex::encode(Sha256::digest(&output_data));

        if spend_hash != SPEND_VKEY_SHA256 {
            return Err(anyhow::anyhow!(
                "Spend verification key checksum mismatch!\n  Expected: {}\n  Got: {}\n  File may be corrupted or tampered with.",
                SPEND_VKEY_SHA256, spend_hash
            ));
        }
        if output_hash != OUTPUT_VKEY_SHA256 {
            return Err(anyhow::anyhow!(
                "Output verification key checksum mismatch!\n  Expected: {}\n  Got: {}\n  File may be corrupted or tampered with.",
                OUTPUT_VKEY_SHA256, output_hash
            ));
        }

        println!("  Using committed verification keys (checksums verified)");
        return Ok((committed_spend.to_string(), committed_output.to_string()));
    }

    // Fall back to build directory (local development)
    if Path::new(build_spend).exists() && Path::new(build_output).exists() {
        println!("  Using local build verification keys (development mode)");
        return Ok((build_spend.to_string(), build_output.to_string()));
    }

    Err(anyhow::anyhow!(
        "Verification keys not found.\n\
         For production: Ensure circuits/keys/ directory is present (from git).\n\
         For development: Run 'npm run compile:all && npm run setup:spend && npm run setup:output' in circuits/"
    ))
}

#[derive(Clone, Copy)]
enum MiningMode {
    Mine,
    Benchmark,
}

#[derive(serde::Deserialize)]
struct PeerChainInfo {
    height: u64,
    latest_hash: String,
}

async fn fetch_peer_chain_info(
    client: &reqwest::Client,
    peer_url: &str,
) -> Option<PeerChainInfo> {
    let info_url = format!("{}/chain/info", peer_url);
    let response = client.get(&info_url).send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }
    response.json::<PeerChainInfo>().await.ok()
}

async fn wait_for_initial_sync(
    state: Arc<postera::network::AppState>,
    max_wait_secs: u64,
) -> anyhow::Result<()> {
    use std::time::{Duration, Instant};
    use tokio::time::sleep;

    let client = reqwest::Client::new();
    let deadline = Instant::now() + Duration::from_secs(max_wait_secs);

    loop {
        let peers = { state.peers.read().unwrap().clone() };
        let (local_height, local_hash) = {
            let chain = state.blockchain.read().unwrap();
            (chain.height(), hex::encode(chain.latest_hash()))
        };

        // Allow solo mining when no peers are available (single-node deployment)
        if peers.is_empty() {
            println!("No peers configured. Starting solo mining at height {}...", local_height);
            return Ok(());
        }

        let mut best_peer: Option<(String, PeerChainInfo)> = None;
        for peer in &peers {
            if let Some(info) = fetch_peer_chain_info(&client, peer).await {
                let take = match &best_peer {
                    None => true,
                    Some((_, best_info)) => info.height > best_info.height,
                };
                if take {
                    best_peer = Some((peer.clone(), info));
                }
            }
        }

        if let Some((peer_url, info)) = best_peer {
            if local_height == info.height && local_hash == info.latest_hash {
                println!(
                    "Local chain matches peer {} at height {}.",
                    peer_url, local_height
                );
                return Ok(());
            }

            println!(
                "Waiting for sync... local height={}, peer height={}",
                local_height, info.height
            );
            let _ = postera::network::sync_from_peer(state.clone(), &peer_url).await;
        } else {
            println!("Waiting for sync... no peer info available yet.");
        }

        if Instant::now() >= deadline {
            return Err(anyhow::anyhow!(
                "Timed out waiting for sync; local tip does not match any peer."
            ));
        }

        sleep(Duration::from_secs(5)).await;
    }
}

#[derive(Subcommand)]
enum Commands {
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
        /// SIMD mode (optional). Currently supports: neon
        #[arg(short, long, value_enum)]
        simd: Option<SimdArg>,
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
        /// SIMD mode (optional). Currently supports: neon
        #[arg(short, long, value_enum)]
        simd: Option<SimdArg>,
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
        /// SIMD mode (optional). Currently supports: neon
        #[arg(short, long, value_enum)]
        simd: Option<SimdArg>,
        /// Public URL to announce to peers (e.g. https://example.com)
        #[arg(long)]
        public_url: Option<String>,
        /// Disable connecting to seed nodes
        #[arg(long)]
        no_seeds: bool,
        /// Disable assume-valid and verify all ZK proofs from genesis
        #[arg(long)]
        full_verify: bool,
        /// Allow mining without peer sync verification (for solo/testing)
        #[arg(long)]
        force_mine: bool,
        /// Wallet file for faucet (enables faucet if provided)
        #[arg(long)]
        faucet_wallet: Option<String>,
        /// Override daily faucet limit in PSTR (default: 50)
        #[arg(long)]
        faucet_daily_limit: Option<u64>,
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
        Commands::Balance { wallet, node } => {
            cmd_balance(&wallet, &node).await?;
        }
        Commands::Mine {
            wallet,
            blocks,
            difficulty,
            jobs,
            simd,
        } => {
            cmd_mine(
                &wallet,
                blocks,
                difficulty,
                jobs,
                simd.map(Into::into),
                MiningMode::Mine,
            )?;
        }
        Commands::Benchmark {
            wallet,
            blocks,
            difficulty,
            jobs,
            simd,
        } => {
            cmd_mine(
                &wallet,
                blocks,
                difficulty,
                jobs,
                simd.map(Into::into),
                MiningMode::Benchmark,
            )?;
        }
        Commands::Node {
            port,
            peer,
            data_dir,
            mine,
            jobs,
            simd,
            public_url,
            no_seeds,
            full_verify,
            force_mine,
            faucet_wallet,
            faucet_daily_limit,
        } => {
            // Use config defaults, with CLI/env overrides
            let port = port.unwrap_or_else(config::get_port);
            let data_dir = data_dir.unwrap_or_else(config::get_data_dir);

            // Set full verify mode via environment variable (config.rs checks this)
            if full_verify {
                std::env::set_var("POSTERA_FULL_VERIFY", "1");
            }

            // Combine seed nodes with CLI peers
            let mut peers = if no_seeds {
                Vec::new()
            } else {
                config::get_seed_nodes()
            };
            peers.extend(peer);

            cmd_node(
                port,
                peers,
                &data_dir,
                mine,
                jobs,
                simd.map(Into::into),
                public_url,
                force_mine,
                faucet_wallet,
                faucet_daily_limit,
            )
            .await?;
        }
    }

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
    simd: Option<SimdMode>,
    mode: MiningMode,
) -> anyhow::Result<()> {
    let jobs = jobs.max(1);
    let simd = require_simd_support(simd);
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
    if let Some(simd) = simd {
        println!("SIMD mode: {:?}", simd);
    }
    let pool = MiningPool::new_with_simd(jobs, simd);
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
    simd: Option<SimdMode>,
    public_url: Option<String>,
    force_mine: bool,
    faucet_wallet: Option<String>,
    faucet_daily_limit: Option<u64>,
) -> anyhow::Result<()> {
    use postera::network::{AppState, MinerStats, sync_from_peer, sync_loop, broadcast_block, discovery_loop, announce_to_peer};
    use postera::crypto::proof::CircomVerifyingParams;
    use postera::faucet::FaucetService;
    use postera::storage::Database;
    use std::sync::RwLock;
    use tokio::sync::RwLock as TokioRwLock;

    let simd = require_simd_support(simd);

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

    // Load Circom verification keys for proof verification
    println!();
    println!("Loading Circom verification keys...");

    // Look for verification keys in circuits/keys/ (committed) first, then circuits/build/ (local dev)
    let (spend_vkey_path, output_vkey_path) = find_verification_keys()?;

    println!("  Loading {}...", spend_vkey_path);
    println!("  Loading {}...", output_vkey_path);

    let verifying_params = CircomVerifyingParams::from_files(&spend_vkey_path, &output_vkey_path)
        .map_err(|e| anyhow::anyhow!("Failed to load verification keys: {}", e))?;

    blockchain.set_verifying_params(Arc::new(verifying_params));
    println!("  ZK proof verification ENABLED (Circom/snarkjs)");

    // Show assume-valid checkpoint status
    let assume_valid_height = blockchain.assume_valid_height();
    if assume_valid_height > 0 {
        println!("  Assume-valid checkpoint: height {} (proofs skipped during sync)", assume_valid_height);
    } else {
        println!("  Assume-valid: DISABLED (full proof verification from genesis)");
    }
    println!();

    // Initialize faucet if wallet provided
    let faucet_service = if let Some(faucet_path) = &faucet_wallet {
        let faucet_wlt = ShieldedWallet::load(faucet_path)?;
        let pk_hash = faucet_wlt.pk_hash();
        let faucet_pk_hash_hex = hex::encode(pk_hash);
        println!("Faucet enabled: {} (pk_hash)", &faucet_pk_hash_hex[..16]);

        // Extract keypair for signing
        let keypair = faucet_wlt.keypair().clone();

        // Open database for faucet claims
        let db = Arc::new(Database::open(&format!("{}/faucet", data_dir))?);

        let service = if let Some(limit) = faucet_daily_limit {
            let limit_base = limit * 1_000_000_000; // Convert PSTR to base units
            println!("  Daily limit: {} PSTR", limit);
            FaucetService::with_limits(keypair, pk_hash, db, limit_base, 86400)
        } else {
            println!("  Daily limit: 50 PSTR (default)");
            FaucetService::new(keypair, pk_hash, db)
        };

        Some(TokioRwLock::new(service))
    } else {
        None
    };

    let state = Arc::new(AppState {
        blockchain: RwLock::new(blockchain),
        mempool: RwLock::new(mempool),
        peers: RwLock::new(peers.clone()),
        miner_stats: RwLock::new(MinerStats::default()),
        faucet: faucet_service,
    });

    // Create router with API (wallet and explorer are served from static React app)
    let app = create_router(state.clone());

    // Build our own URL for peer announcements
    let our_url = public_url.unwrap_or_else(|| format!("http://localhost:{}", port));
    println!("Announcing as:  {}", our_url);

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

    // Scan blockchain for faucet notes if enabled
    if state.faucet.is_some() {
        println!("Scanning blockchain for faucet notes...");

        // Do initial scan in a blocking task to avoid blocking the async runtime
        let scan_state = state.clone();
        let (new_notes, balance) = tokio::task::spawn_blocking(move || {
            let blockchain = scan_state.blockchain.read().unwrap();
            let current_height = blockchain.height();

            // Collect blocks into a vec to avoid borrowing issues
            let blocks: Vec<_> = (0..=current_height)
                .filter_map(|h| blockchain.get_block_by_height(h).cloned())
                .collect();
            drop(blockchain);

            if let Some(ref faucet) = scan_state.faucet {
                let mut faucet_guard = faucet.blocking_write();

                let get_block = |height: u64| -> Option<ShieldedBlock> {
                    blocks.get(height as usize).cloned()
                };

                let new_notes = faucet_guard.scan_blockchain(get_block, current_height);
                let balance = faucet_guard.balance();
                (new_notes, balance)
            } else {
                (0, 0)
            }
        }).await.unwrap_or((0, 0));

        if new_notes > 0 {
            println!("  Found {} faucet notes, balance: {} PSTR", new_notes, balance / 1_000_000_000);
        } else {
            println!("  No faucet notes found (balance: {} PSTR)", balance / 1_000_000_000);
        }

        // Start background faucet scanning task (every 30 seconds)
        let faucet_scan_state = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                interval.tick().await;

                let scan_state = faucet_scan_state.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    if let Some(ref faucet) = scan_state.faucet {
                        let blockchain = scan_state.blockchain.read().unwrap();
                        let current_height = blockchain.height();

                        let mut faucet_guard = faucet.blocking_write();
                        let last_scanned = faucet_guard.last_scanned_height();

                        // Only scan if there are new blocks
                        if current_height > last_scanned {
                            // Collect only new blocks
                            let blocks: Vec<_> = ((last_scanned + 1)..=current_height)
                                .filter_map(|h| blockchain.get_block_by_height(h).cloned())
                                .collect();
                            drop(blockchain);

                            let get_block = |height: u64| -> Option<ShieldedBlock> {
                                let idx = height.saturating_sub(last_scanned + 1) as usize;
                                blocks.get(idx).cloned()
                            };

                            let _new_notes = faucet_guard.scan_blockchain(get_block, current_height);
                        }
                    }
                }).await;
            }
        });
    }

    // Start integrated miner if requested
    if let Some((miner_pk_hash, viewing_key)) = miner_info {
        if force_mine {
            println!("Force mining enabled - skipping sync verification");
        } else {
            println!("Waiting for initial sync before mining...");
            wait_for_initial_sync(state.clone(), 300).await?;
        }

        let jobs = jobs.max(1);
        let mine_state = state.clone();
        let announce_url = our_url.clone();
        let local_url = format!("http://localhost:{}", port);
        let local_ip_url = format!("http://127.0.0.1:{}", port);
        if let Some(simd) = simd {
            println!("SIMD mode: {:?}", simd);
        }
        let pool = Arc::new(MiningPool::new_with_simd(jobs, simd));

        tokio::spawn(async move {
            let client = reqwest::Client::new();
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
                // Get mempool transactions (both V1 and V2)
                let (mempool_txs, mempool_txs_v2) = {
                    let mempool = mine_state.mempool.read().unwrap();
                    let v1 = mempool.get_transactions(100);
                    let v2 = mempool.get_shielded_v2_transactions(100);
                    if !v2.is_empty() {
                        println!("  Including {} V2 transactions in block template", v2.len());
                    }
                    (v1, v2)
                };

                // Create block template with both V1 and V2 transactions
                let mut block = {
                    let chain = mine_state.blockchain.read().unwrap();
                    chain.create_block_template_with_v2(miner_pk_hash, &viewing_key, mempool_txs, mempool_txs_v2)
                };

                let (height, difficulty) = {
                    let chain = mine_state.blockchain.read().unwrap();
                    (chain.height() + 1, block.header.difficulty)
                };

                let v2_count = block.transactions_v2.len();
                if v2_count > 0 {
                    println!("Mining block {} (difficulty: {}, V2 txs: {})...", height, difficulty, v2_count);
                } else {
                    println!("Mining block {} (difficulty: {})...", height, difficulty);
                }

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

                            // Remove mined transactions from mempool (both V1 and V2)
                            let mut tx_hashes: Vec<[u8; 32]> = mined_block
                                .transactions
                                .iter()
                                .map(|tx| tx.hash())
                                .collect();
                            tx_hashes.extend(mined_block.transactions_v2.iter().map(|tx| tx.hash()));

                            let mut mempool = mine_state.mempool.write().unwrap();
                            mempool.remove_confirmed(&tx_hashes);

                            // Remove transactions with spent nullifiers (both V1 and V2)
                            let mut nullifiers: Vec<[u8; 32]> = mined_block.nullifiers().iter().map(|n| n.0).collect();
                            nullifiers.extend(mined_block.transactions_v2.iter().flat_map(|tx| tx.spends.iter().map(|s| s.nullifier)));
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
                let mut current_peers = mine_state.peers.read().unwrap().clone();
                current_peers.retain(|peer| {
                    peer != &announce_url && peer != &local_url && peer != &local_ip_url
                });
                if !current_peers.is_empty() {
                    broadcast_block(&mined_block, &current_peers).await;
                }

                // Best-effort: check whether a peer accepted the mined block
                if let Some(peer) = current_peers.first() {
                    let height = mined_block.coinbase.height;
                    let url = format!("{}/block/height/{}", peer, height);
                    let result = client.get(&url).send().await;
                    match result {
                        Ok(resp) if resp.status().is_success() => {
                            if let Ok(info) = resp.json::<serde_json::Value>().await {
                                let peer_hash = info.get("hash").and_then(|v| v.as_str()).unwrap_or("");
                                if peer_hash == mined_block.hash_hex() {
                                    tracing::info!("Peer accepted block at height {}.", height);
                                } else {
                                    tracing::info!("Peer has different block at height {}.", height);
                                }
                            }
                        }
                        _ => {
                            tracing::warn!("Could not confirm peer acceptance for height {}.", height);
                        }
                    }
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
