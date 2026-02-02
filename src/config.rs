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

// ============================================================================
// Assume-Valid Checkpoints
// ============================================================================
//
// Assume-valid allows faster initial sync by skipping ZK proof verification
// for blocks before a known-good checkpoint. The block structure, PoW, and
// state transitions are still fully validated - only the expensive STARK/Groth16
// proof verification is skipped.
//
// This is the same approach used by Bitcoin Core since 0.14.0.
//
// To update: Set ASSUME_VALID_HEIGHT to a recent block height and
// ASSUME_VALID_HASH to that block's hash. Nodes will skip proof verification
// for blocks at or below this height.

/// Height of the assume-valid checkpoint.
/// Blocks at or below this height skip ZK proof verification during sync.
/// Set to 0 to disable assume-valid (verify all proofs).
pub const ASSUME_VALID_HEIGHT: u64 = 0;

/// Block hash at the assume-valid height (hex string).
/// Used to verify we're on the correct chain before trusting the checkpoint.
/// Only relevant when ASSUME_VALID_HEIGHT > 0.
pub const ASSUME_VALID_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Check if assume-valid is enabled.
pub fn is_assume_valid_enabled() -> bool {
    ASSUME_VALID_HEIGHT > 0 && !is_assume_valid_disabled_by_env()
}

/// Check if assume-valid is disabled via environment variable.
/// Set POSTERA_FULL_VERIFY=1 to force full verification of all proofs.
pub fn is_assume_valid_disabled_by_env() -> bool {
    std::env::var("POSTERA_FULL_VERIFY")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false)
}

/// Get the assume-valid configuration.
pub fn get_assume_valid_config() -> (u64, String) {
    (ASSUME_VALID_HEIGHT, ASSUME_VALID_HASH.to_string())
}
