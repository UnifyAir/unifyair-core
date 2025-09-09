# Use Python 3.10 slim base image (based on Debian Bookworm)
FROM python:3.10-slim-bookworm

# Set maintainer label
LABEL maintainer="UnifyAir <support@unifyair.com>"

# Install build dependencies and system packages
RUN apt-get update && apt-get install -y \
    libpcap-dev git curl iproute2 supervisor \
    build-essential cmake \
    libsystemd-dev \
    libssh-dev \
    libglib2.0-dev \
    qtbase5-dev \
    qttools5-dev \
    qtmultimedia5-dev \
    libqt5svg5-dev \
    libgcrypt20-dev \
    flex \
    bison \
    wget \
    byacc \
    libc-ares-dev \
    libspeexdsp-dev \
    && rm -rf /var/lib/apt/lists/*

# Create supervisor log directory
RUN mkdir -p /var/log/supervisor

# Download and extract Wireshark source
RUN wget https://www.wireshark.org/download/src/wireshark-4.4.7.tar.xz \
    && tar -xf wireshark-4.4.7.tar.xz

# Compile and install Wireshark (tshark only)
RUN cd wireshark-4.4.7 && mkdir build && cd build \
    && cmake -DBUILD_wireshark=OFF .. \
    && make -j$(nproc) \
    && make install \
    && cd / \
    && rm -rf wireshark-4.4.7* \
    && ldconfig

# Install Python packages
RUN pip install --no-cache-dir scapy colorama watchdog h2 pymongo

# Set working directory
WORKDIR /app