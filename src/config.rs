/// Network configuration constants
///
/// IMPORTANT: All nodes must use the same GENESIS_DIFFICULTY
/// to have compatible genesis blocks and sync properly.

/// The difficulty used for the genesis block.
/// This MUST be the same for all nodes on the network.
/// Changing this creates an incompatible chain.
pub const GENESIS_DIFFICULTY: u64 = 12;

/// Default seed nodes for the Postera network.
/// These are the initial nodes that new nodes connect to.
/// Add your deployed node URLs here.
pub const SEED_NODES: &[&str] = &[
    // Add your deployed seed nodes here, e.g.:
    // "https://postera-node-1.fly.dev",
    // "https://postera-node-2.fly.dev",
];

/// Network name for identification
pub const NETWORK_NAME: &str = "postera-mainnet";

/// Default port for nodes
pub const DEFAULT_PORT: u16 = 8333;

/// Block reward in base units (50 coins)
pub const BLOCK_REWARD: u64 = 50_000_000_000;

/// Coin decimals (1 coin = 10^9 base units)
pub const COIN_DECIMALS: u32 = 9;

/// Get seed nodes from environment or use defaults
pub fn get_seed_nodes() -> Vec<String> {
    // Check for POSTERA_SEEDS environment variable (comma-separated URLs)
    if let Ok(seeds) = std::env::var("POSTERA_SEEDS") {
        seeds
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    } else {
        SEED_NODES.iter().map(|s| s.to_string()).collect()
    }
}

/// Get the port from environment or use default
pub fn get_port() -> u16 {
    std::env::var("POSTERA_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_PORT)
}

/// Get the data directory from environment or use default
pub fn get_data_dir() -> String {
    std::env::var("POSTERA_DATA_DIR").unwrap_or_else(|_| "./data".to_string())
}

/// Get mining address from environment (optional)
pub fn get_mining_address() -> Option<String> {
    std::env::var("POSTERA_MINE_ADDRESS").ok()
}
