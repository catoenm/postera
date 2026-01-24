# Quantum-Resistant Bitcoin

A proof-of-concept cryptocurrency using post-quantum cryptography (CRYSTALS-Dilithium signatures) to provide resistance against quantum computer attacks.

## Features

- **Post-Quantum Signatures**: Uses CRYSTALS-Dilithium, a lattice-based signature scheme selected by NIST for post-quantum standardization
- **Proof of Work Consensus**: Configurable difficulty mining
- **Full Node**: Run a node with REST API and web explorer
- **Wallet Management**: Generate and manage quantum-resistant wallets
- **Peer Sync**: Nodes can sync blockchain state from peers

## Installation

```bash
cargo build --release
```

## Usage

### Generate a Wallet

```bash
./target/release/quantum-resistant-btc new-wallet -o my-wallet.json
```

### Run a Node

```bash
# Start a node on default port 8333
./target/release/quantum-resistant-btc node

# Start with mining enabled
./target/release/quantum-resistant-btc node --mine <your-address>

# Connect to peers
./target/release/quantum-resistant-btc node --peer http://peer1:8333 --peer http://peer2:8333
```

The node exposes:
- REST API at `http://localhost:8333`
- Block Explorer at `http://localhost:8333/explorer`

### Check Balance

```bash
./target/release/quantum-resistant-btc balance <address>
```

### Send Transaction

```bash
./target/release/quantum-resistant-btc send <recipient-address> <amount> -w my-wallet.json
```

### Standalone Mining

```bash
./target/release/quantum-resistant-btc mine -a <your-address> -d 16
```

## Architecture

- `crypto/` - Post-quantum cryptography (Dilithium keys, signatures, addresses)
- `core/` - Blockchain primitives (blocks, transactions, state)
- `consensus/` - Proof of work mining
- `network/` - REST API and peer synchronization
- `wallet/` - Wallet generation and transaction signing
- `explorer/` - Web-based block explorer

## License

MIT
