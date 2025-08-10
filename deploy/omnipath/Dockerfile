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
ARG MODE
RUN if [ "$MODE" = "release" ]; then \
        cargo chef cook --release --recipe-path recipe.json; \
    else \
        cargo chef cook --recipe-path recipe.json; \
    fi
# --- Build application
COPY . .
ARG MODE
RUN if [ "$MODE" = "release" ]; then \
        cargo build --release --package lightning-cli; \
    else \
        cargo build --package lightning-cli; \
    fi

# --- Runtime stage
FROM executor-base AS executor
WORKDIR /unifyair
RUN mkdir -p /unifyair/config
ARG MODE
COPY --from=builder /unifyair/target/$MODE/lightning-cli /unifyair/lightning-cli
