# Use a slim Python base image
FROM python:3.12.11-slim-bookworm

# Install system dependencies
RUN apt-get update && apt-get install -y libpcap-dev git curl iproute2 tshark supervisor && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /var/log/supervisor

# Set the working directory
WORKDIR /app

# Install Scapy and Colorama
RUN pip install scapy colorama pyshark


# Copy your scapy script
COPY ./capturer.sh ./capturer.sh
