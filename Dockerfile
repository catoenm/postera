# Build stage
FROM rust:1.85-bookworm as builder

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

# Create data directory
RUN mkdir -p /app/data

# Expose the default port (Fly.io uses 8080 internally)
EXPOSE 8080
EXPOSE 8333

# Set default environment variables
ENV RUST_LOG=info
ENV POSTERA_DATA_DIR=/app/data
ENV POSTERA_PORT=8080

# Run the node - uses environment variables for configuration
# Set POSTERA_SEEDS for peer nodes (comma-separated URLs)
# Set POSTERA_MINE_ADDRESS to enable mining
CMD ["/app/postera", "node"]
