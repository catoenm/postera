<p align="center">
  <img src="assets/logo.png" alt="Postera Logo" width="120">
</p>

# Postera

A privacy-focused cryptocurrency combining post-quantum cryptography with zero-knowledge proofs for quantum-resistant private transactions.

## Features

- **Post-Quantum Signatures**: Uses ML-DSA-65 (FIPS 204, formerly CRYSTALS-Dilithium), a lattice-based signature scheme standardized by NIST
- **Shielded Transactions**: Privacy model using zk-SNARKs (Groth16 on BLS12-381) - _proof generation in development_
- **Note-Based Model**: UTXO-style notes with commitments, nullifiers, and encrypted payloads (similar to Zcash)
- **Viewing Keys**: Scan the blockchain for incoming transactions without spending ability
- **Proof of Work Consensus**: Dynamic difficulty adjustment targeting 10-second block times
- **Full Node**: Run a node with REST API and web explorer
- **Web Wallet**: React-based wallet with client-side key generation and message signing
- **P2P Networking**: Peer discovery, block broadcasting, and transaction relay
- **Persistent Storage**: SledDB-backed blockchain persistence
- **Docker & Fly.io Deployment**: Production-ready containerization and cloud deployment

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

### Local Multi-Node Setup

```bash
docker compose up
```

This starts 3 nodes locally (ports 8333, 8334, 8335) with Node1 mining enabled.

## Usage

### Generate a Shielded Wallet

```bash
./target/release/postera new-wallet -o my-wallet.json
```

This generates a wallet with:

- ML-DSA-65 keypair (post-quantum signatures)
- Nullifier key (for deriving nullifiers when spending)
- Viewing key (for scanning incoming notes)

### Run a Node

```bash
# Start a node on default port 8333
./target/release/postera node

# Start with mining enabled
./target/release/postera node --mine <your-address>

# Connect to peers
./target/release/postera node --peer http://peer1:8333 --peer http://peer2:8333
```

The node exposes:

- REST API at `http://localhost:8333`
- Block Explorer at `http://localhost:8333/explorer`

### Web Wallet

Run the React wallet application:

```bash
cd wallet
npm install
npm run dev
```

The wallet provides:

- Client-side ML-DSA-65 key generation (keys never leave your browser)
- Wallet import/export
- Message signing with quantum-resistant signatures
- Block explorer integration

### Check Balance

With shielded transactions, balances are computed by scanning the blockchain for notes encrypted to your viewing key:

```bash
./target/release/postera balance -w my-wallet.json
```

### Send Transaction (Coming Soon)

Shielded transactions require ZK proof generation. CLI support in development:

```bash
./target/release/postera send <recipient-pk-hash> <amount> -w my-wallet.json
```

### Standalone Mining

```bash
./target/release/postera mine -a <your-address> -d 16
```

## Environment Variables

| Variable               | Description                       | Default               |
| ---------------------- | --------------------------------- | --------------------- |
| `POSTERA_PORT`         | Listen port                       | 8333 (8080 in Docker) |
| `POSTERA_DATA_DIR`     | Blockchain data directory         | `./data`              |
| `POSTERA_SEEDS`        | Comma-separated seed node URLs    | -                     |
| `POSTERA_MINE_ADDRESS` | Address to receive mining rewards | -                     |
| `RUST_LOG`             | Log level (error/warn/info/debug) | info                  |

## API Endpoints

| Endpoint                    | Description                                    |
| --------------------------- | ---------------------------------------------- |
| `GET /chain/info`           | Blockchain metadata (height, difficulty, etc.) |
| `GET /block/:hash`          | Get block by hash                              |
| `GET /block/height/:height` | Get block by height                            |
| `GET /account/:address`     | Account balance and nonce                      |
| `POST /tx`                  | Submit a signed transaction                    |
| `GET /blocks/since/:height` | Sync blocks from a height                      |
| `GET /peers`                | List connected peers                           |
| `POST /peers`               | Add a new peer                                 |
| `GET /accounts/top`         | View top account holders                       |
| `POST /wallet/generate`     | Generate a new wallet                          |
| `POST /wallet/send`         | Create and broadcast a transaction             |

## Architecture

```
src/
  crypto/           Cryptographic primitives
    keys.rs         ML-DSA-65 keypair generation
    signature.rs    Post-quantum signatures
    commitment.rs   Pedersen commitments for notes and values
    nullifier.rs    Nullifier derivation (prevents double-spending)
    note.rs         Note encryption/decryption with viewing keys
    merkle_tree.rs  Commitment tree for membership proofs
    proof.rs        zk-SNARK proof generation and verification
    setup.rs        Trusted setup parameters (Groth16)
    circuits/       R1CS circuits for spend and output proofs
  core/             Blockchain primitives
    block.rs        Block structure with shielded transactions
    transaction.rs  Shielded transactions (spends, outputs, binding sig)
    blockchain.rs   Chain validation and state management
    state.rs        Nullifier set and commitment tree state
  consensus/        Proof of work mining with dynamic difficulty
  network/          REST API, P2P sync, and peer discovery
  storage/          SledDB persistence
  wallet/           Wallet generation and shielded transaction building
  explorer/         Web-based block explorer

wallet/             React web wallet application
  src/
    crypto.ts       Client-side ML-DSA-65 key generation and signing
    Wallet.tsx      Wallet UI (create, import, sign messages)
    Explorer.tsx    Block explorer UI
```

## Network Details

- **Network**: postera-mainnet
- **Default Port**: 8333
- **Coin Decimals**: 9 (1 coin = 1,000,000,000 base units)
- **Block Reward**: 50 coins
- **Target Block Time**: 10 seconds
- **Difficulty Adjustment**: Every 10 blocks

## Deployment

### Fly.io

The project includes `fly.toml` for Fly.io deployment:

```bash
fly launch
fly deploy
```

Configuration:

- 512MB memory, shared-cpu-1x VM
- Persistent volume for blockchain data
- Health checks via `/chain/info`
- Primary region: San Jose (sjc)

## Cryptography

### Post-Quantum Signatures (ML-DSA-65)

Postera uses ML-DSA-65 (FIPS 204), the NIST-standardized version of CRYSTALS-Dilithium:

| Parameter  | Size        |
| ---------- | ----------- |
| Public Key | 1,952 bytes |
| Secret Key | 4,032 bytes |
| Signature  | 3,309 bytes |

### Zero-Knowledge Proofs (Groth16)

Shielded transactions use zk-SNARKs on the BLS12-381 curve:

| Component         | Description                         |
| ----------------- | ----------------------------------- |
| Proving System    | Groth16 (constant-size proofs)      |
| Curve             | BLS12-381 (128-bit security)        |
| Commitment Scheme | Pedersen commitments                |
| Encryption        | ChaCha20-Poly1305 (note encryption) |

> **Note**: The ZK circuit infrastructure (R1CS constraints, arkworks integration) is implemented, but proof generation is not yet wired into transaction creation. Proofs are currently placeholder values.

## Privacy Model

Postera implements a Zcash-style shielded transaction model:

1. **Notes**: Private UTXOs containing a value and recipient's public key hash
2. **Commitments**: Notes are represented on-chain as Pedersen commitments
3. **Nullifiers**: Unique identifiers derived when spending a note (prevents double-spending)
4. **Encrypted Notes**: Note data is encrypted so only the recipient can decrypt
5. **Viewing Keys**: Derived keys that allow scanning for incoming notes without spending ability
6. **Binding Signatures**: Prove value balance (inputs = outputs + fee) without revealing amounts

### What's Public vs Private

| Public              | Private             |
| ------------------- | ------------------- |
| Transaction fee     | Sender identity     |
| Note commitments    | Recipient identity  |
| Nullifiers (opaque) | Transaction amounts |
| Block height        | Note contents       |

## License

MIT
