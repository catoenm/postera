# Frontend build stage
FROM node:22-bookworm-slim AS frontend-builder

WORKDIR /app/wallet

# Copy package files first for better caching
COPY wallet/package.json wallet/package-lock.json ./

# Install dependencies
RUN npm ci

# Copy source and build
COPY wallet/ ./
RUN npm run build

# Rust build stage
FROM rust:1.85-bookworm AS builder

WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Create dummy src to cache dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs && echo "" > src/lib.rs

# Build dependencies (this layer is cached)
RUN cargo build --release && rm -rf src

# Copy actual source code
COPY src ./src

# Build the application
RUN touch src/main.rs src/lib.rs && cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/target/release/postera /app/postera

# Copy built static files from frontend stage
COPY --from=frontend-builder /app/static ./static

# Copy wallet file for mining
COPY wallet.json ./wallet.json

# Create data directory
RUN mkdir -p /app/data

# Expose the default port (Fly.io uses 8080 internally)
EXPOSE 8080
EXPOSE 8333

# Set default environment variables
ENV RUST_LOG=info
ENV POSTERA_DATA_DIR=/app/data
ENV POSTERA_PORT=8080

# Run the node with mining enabled
CMD ["/app/postera", "node", "--mine", "/app/wallet.json"]
