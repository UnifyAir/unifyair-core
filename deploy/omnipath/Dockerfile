# Build stage
FROM rust:1.75-slim-bullseye AS builder

WORKDIR /build

# Install build dependencies including libclang
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libclang-dev \
    clang \
    libsctp-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy the entire workspace for proper dependency resolution
COPY . .

# Debug: Show workspace structure
RUN ls -la /build/lightning-cli

# Build the application
WORKDIR /build/lightning-cli
RUN cargo build --release

# Runtime stage
FROM debian:bullseye-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libssl1.1 \
    ca-certificates \
    libsctp1 \
    && rm -rf /var/lib/apt/lists/*

# Create config directory
RUN mkdir -p /app/config

# Copy the binary from builder
COPY --from=builder /build/target/release/lightning-cli /app/lightning-cli

# Copy config file from root config folder
COPY config/amfcfg.yaml /app/config/amfcfg.yaml

# Set the entrypoint with the correct config path
ENTRYPOINT ["/app/lightning-cli", "omnipath", "--config", "/app/config/amfcfg.yaml"]
