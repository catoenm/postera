<p align="center">
  <img src="assets/logo.png" alt="Postera Logo" width="120">
</p>

# Postera

A fully quantum-resistant privacy cryptocurrency combining post-quantum signatures (ML-DSA-65) with post-quantum zero-knowledge proofs (Plonky2 STARKs) for private transactions secure against both classical and quantum adversaries.

## What's New in V2

Postera V2 introduces **fully quantum-resistant privacy** through Plonky2 STARK proofs:

| Component | V1 (Legacy) | V2 (Quantum-Safe) |
|-----------|-------------|-------------------|
| Signatures | ML-DSA-65 | ML-DSA-65 |
| ZK Proofs | Groth16/BN254 | Plonky2 STARKs |
| Commitments | Pedersen/BN254 | Poseidon/Goldilocks |
| Proof Size | ~200 bytes | ~50 KB |
| Proving Time | ~3s | ~2s |
| Quantum Safe | Signatures only | Fully quantum-safe |

## Features

- **Fully Post-Quantum**: Both signatures (ML-DSA-65) AND zero-knowledge proofs (Plonky2 STARKs) are quantum-resistant
- **Shielded Transactions**: Privacy model using hash-based commitments and STARK proofs
- **Browser-Based Proving**: Client-side WASM prover using Plonky2 (keys never leave your browser)
- **Note-Based Model**: UTXO-style notes with commitments, nullifiers, and encrypted payloads
- **Viewing Keys**: Scan the blockchain for incoming transactions without spending ability
- **Dynamic Circuits**: Transaction circuits built on-demand for any input/output configuration
- **Circuit Warmup**: Pre-build common circuits for instant transactions
- **Proof of Work Consensus**: Dynamic difficulty adjustment targeting 10-second block times
- **V1 Migration**: Seamlessly migrate legacy V1 notes to quantum-safe V2 format

## Security Model

### Quantum Resistance

| Attack Vector | V1 Protection | V2 Protection |
|---------------|---------------|---------------|
| Forge signatures | ML-DSA-65 (safe) | ML-DSA-65 (safe) |
| Break ZK proofs | BN254 (vulnerable) | STARKs (safe) |
| Crack commitments | Pedersen (vulnerable) | Poseidon (safe) |
| Brute force hashes | SHA-256 (128-bit QS) | SHA-256 (128-bit QS) |

**V2 provides complete protection** against quantum adversaries for both fund security AND transaction privacy.

## Installation

### From Source

```bash
cargo build --release
```

### With Docker

```bash
docker build -t postera .
docker run -p 8080:8080 postera
```

## Usage

### Run a Node

```bash
# Join the live network
./target/release/postera node --peer https://postera.network

# Join and mine to your wallet
./target/release/postera node --mine my-wallet.json --jobs 8 --peer https://postera.network
```

The node exposes:

- REST API at `http://localhost:8333`
- Block Explorer at `http://localhost:8333/explorer`
- Web Wallet at `http://localhost:8333/wallet`

### Web Wallet

The React wallet provides:

- Client-side ML-DSA-65 key generation (keys never leave your browser)
- V2 quantum-safe transactions with Plonky2 proofs
- Circuit warmup for instant proof generation
- Automatic V1 to V2 migration
- Note scanning with viewing keys

```bash
cd wallet
npm install
npm run dev
```

### Live Network

- **Explorer**: https://postera.network/explorer
- **Wallet**: https://postera.network/wallet
- **API**: https://postera.network/chain/info

## Architecture

```
src/
  crypto/              Cryptographic primitives
    keys.rs            ML-DSA-65 keypair generation
    signature.rs       Post-quantum signatures
    poseidon.rs        Poseidon hash (BN254 for V1)
    poseidon_pq.rs     Poseidon hash (Goldilocks for V2)
    commitment.rs      Note commitments (V1)
    commitment_pq.rs   Note commitments (V2, hash-based)
    nullifier.rs       Nullifier derivation
    note.rs            Note encryption/decryption
    merkle_tree.rs     Commitment tree (V1)
    merkle_tree_pq.rs  Commitment tree (V2, Poseidon/Goldilocks)
    proof.rs           Groth16 proofs (V1)
    circuit_pq.rs      Plonky2 STARK proofs (V2)
  core/                Blockchain primitives
    block.rs           Block structure
    transaction.rs     Shielded transactions (V1 + V2)
    blockchain.rs      Chain validation
    state.rs           Nullifier set and commitment trees
  consensus/           Proof of work mining
  network/             REST API, P2P sync
  storage/             SledDB persistence

plonky2-wasm/          Browser WASM prover
  src/lib.rs           Plonky2 circuit building and proving

wallet/                React web wallet
  src/
    crypto.ts          ML-DSA-65 key generation
    poseidon-pq.ts     Goldilocks Poseidon (fallback)
    commitment-pq.ts   WASM-based commitments
    prover-pq.ts       Plonky2 WASM prover interface
    shielded-wallet.ts Note scanning and balance
    transaction-builder.ts  V1 and V2 transaction building
    coalesce.ts        UTXO consolidation utilities
    components/        Warmup UI components
```

## Cryptography

### Post-Quantum Signatures (ML-DSA-65)

| Parameter | Size |
|-----------|------|
| Public Key | 1,952 bytes |
| Secret Key | 4,032 bytes |
| Signature | 3,309 bytes |

### V2 Zero-Knowledge Proofs (Plonky2 STARKs)

| Component | Description |
|-----------|-------------|
| Proving System | Plonky2 (FRI-based STARKs) |
| Field | Goldilocks (p = 2^64 - 2^32 + 1) |
| Hash Function | Poseidon over Goldilocks |
| Security | 100+ bit post-quantum |
| Proof Size | ~50 KB |

### V2 Commitments

```
Note Commitment = Poseidon(domain=1, value, pk_hash, randomness)
Nullifier = Poseidon(domain=3, nullifier_key, commitment, position)
Merkle Node = Poseidon(domain=5, left, right)
```

All use Plonky2's native Poseidon implementation over the Goldilocks field.

## Network Details

| Parameter | Value |
|-----------|-------|
| Network | postera-mainnet |
| Default Port | 8333 |
| Coin Decimals | 9 (1 PSTR = 10^9 base units) |
| Block Reward | 50 PSTR |
| Target Block Time | 10 seconds |
| Difficulty Adjustment | Every 10 blocks |
| Max Spends per Tx | 10 |
| Max Outputs per Tx | 4 |

## V1 to V2 Migration

Existing V1 notes can be migrated to V2 format:

1. V1 notes are spent using legacy Groth16 proofs
2. New V2 notes are created with Poseidon/Goldilocks commitments
3. The migration transaction is signed with ML-DSA-65

Migration is recommended before quantum computers become practical.

## Deployment

### Fly.io

```bash
fly launch
fly deploy
```

Configuration in `fly.toml`:
- 512MB memory, shared-cpu-1x VM
- Persistent volume for blockchain data
- Health checks via `/chain/info`

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /chain/info` | Blockchain metadata |
| `GET /block/:hash` | Get block by hash |
| `GET /outputs/since/:height` | Scan for new outputs |
| `POST /shielded/v2` | Submit V2 transaction |
| `GET /witness/v2/:commitment` | Get V2 Merkle witness |
| `POST /nullifiers/check` | Check spent nullifiers |

## Development

### Build WASM Prover

```bash
cd plonky2-wasm
./build.sh
```

### Run Tests

```bash
# Rust tests
cargo test

# WASM tests
cd plonky2-wasm && cargo test
```

## License

MIT

## References

- [FIPS 204: ML-DSA Standard](https://csrc.nist.gov/pubs/fips/204/final)
- [Plonky2 Documentation](https://github.com/0xPolygonZero/plonky2)
- [Poseidon Hash Function](https://eprint.iacr.org/2019/458)
- [Zcash Protocol Specification](https://zips.z.cash/protocol/protocol.pdf)
