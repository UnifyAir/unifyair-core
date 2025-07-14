FROM rust:1.88-slim-bookworm 

LABEL maintainer="UnifyAir <support@unifyair.com>"

# Install build dependencies and cargo-chef
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libclang-dev \
    clang \
    libsctp-dev

RUN cargo install cargo-chef

# Clean apt cache
RUN apt-get clean