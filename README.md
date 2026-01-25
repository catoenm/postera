# Postera

A cryptocurrency using post-quantum cryptography (CRYSTALS-Dilithium signatures) to provide resistance against quantum computer attacks.

## Features

- **Post-Quantum Signatures**: Uses CRYSTALS-Dilithium (Dilithium3), a lattice-based signature scheme selected by NIST for post-quantum standardization
- **Proof of Work Consensus**: Dynamic difficulty adjustment targeting 10-second block times
- **Full Node**: Run a node with REST API and web explorer
- **Wallet Management**: Generate and manage quantum-resistant wallets
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

### Generate a Wallet

```bash
./target/release/postera new-wallet -o my-wallet.json
```

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

### Check Balance

```bash
./target/release/postera balance <address>
```

### Send Transaction

```bash
./target/release/postera send <recipient-address> <amount> -w my-wallet.json
```

### Standalone Mining

```bash
./target/release/postera mine -a <your-address> -d 16
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `POSTERA_PORT` | Listen port | 8333 (8080 in Docker) |
| `POSTERA_DATA_DIR` | Blockchain data directory | `./data` |
| `POSTERA_SEEDS` | Comma-separated seed node URLs | - |
| `POSTERA_MINE_ADDRESS` | Address to receive mining rewards | - |
| `RUST_LOG` | Log level (error/warn/info/debug) | info |

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /chain/info` | Blockchain metadata (height, difficulty, etc.) |
| `GET /block/:hash` | Get block by hash |
| `GET /block/height/:height` | Get block by height |
| `GET /account/:address` | Account balance and nonce |
| `POST /tx` | Submit a signed transaction |
| `GET /blocks/since/:height` | Sync blocks from a height |
| `GET /peers` | List connected peers |
| `POST /peers` | Add a new peer |
| `GET /accounts/top` | View top account holders |
| `POST /wallet/generate` | Generate a new wallet |
| `POST /wallet/send` | Create and broadcast a transaction |

## Architecture

```
src/
  crypto/     Post-quantum cryptography (Dilithium keys, signatures, addresses)
  core/       Blockchain primitives (blocks, transactions, state)
  consensus/  Proof of work mining with dynamic difficulty
  network/    REST API, P2P sync, and peer discovery
  wallet/     Wallet generation and transaction signing
  explorer/   Web-based block explorer
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

Postera uses CRYSTALS-Dilithium (Dilithium3) for all digital signatures:

| Parameter | Size |
|-----------|------|
| Public Key | 1,952 bytes |
| Secret Key | 4,032 bytes |
| Signature | 3,309 bytes |

Addresses are 20-byte SHA-256 hashes of public keys, similar to Ethereum's addressing scheme.

## License

MIT
