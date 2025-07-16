# Use a slim Python base image
# FROM python:3.10-slim-bookworm
FROM ubuntu:25.10

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
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/log/supervisor

# RUN apt-get install -y cares && rm -rf /var/lib/apt/lists/*

# Download and compile tshark 4.4.7
RUN wget https://www.wireshark.org/download/src/wireshark-4.4.7.tar.xz \
    && tar -xf wireshark-4.4.7.tar.xz 

RUN apt-get update && apt-get install -y libc-ares-dev  libspeexdsp-dev

RUN cd wireshark-4.4.7 && mkdir build && cd build \
    && cmake -DBUILD_wireshark=OFF .. \
    && make -j$(nproc) \
    && make install \
    && cd / \
    && rm -rf wireshark-4.4.7* \
    && ldconfig
RUN apt-get install -y python3 python3-pip python3.13-venv
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install scapy colorama watchdog h2 pymongo

# Set the working directory
WORKDIR /app