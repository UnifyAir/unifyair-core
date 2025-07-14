# --- Chef base image
FROM builder-base AS chef
WORKDIR /unifyair

# --- Planner stage: generate recipe.json for dependencies
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# --- Builder stage: build dependencies only (cached if Cargo.toml/Cargo.lock unchanged)
FROM chef AS builder 
COPY --from=planner /unifyair/recipe.json recipe.json

# TODO: cleanup https://github.com/LukeMathWalker/cargo-chef/issues/271
COPY ./rust-toolchain.toml rust-toolchain.toml
RUN cargo chef cook --release --recipe-path recipe.json
# --- Build application
COPY . .
RUN cargo build --release --package lightning-cli

# --- Runtime stage
FROM executor-base AS executor
WORKDIR /unifyair
RUN mkdir -p /unifyair/config
COPY --from=builder /unifyair/target/release/lightning-cli /unifyair/lightning-cli

EXPOSE 8000