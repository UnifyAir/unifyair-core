# 🚀 UnifyAir Core - 5G Network Functions Implementation

[![Rust](https://img.shields.io/badge/Rust-1.82+-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/License-AGPL--3.0-green.svg)](LICENSE)
[![Discord](https://img.shields.io/discord/1316430894445105283?color=7289da&label=Discord&logo=discord&logoColor=white)](https://discord.gg/yuJHdZ4vEF)
[![Twitter](https://img.shields.io/twitter/follow/unifyair?style=social)](https://x.com/unifyair)

<picture><img src="https://unifyair.io/assets/top.png" alt="UnifyAir Core"></picture>

⚡ High-performance, 3GPP standards-compliant 5G Core Network Functions implementation in Rust

## 📑 Table of Contents
- [🎯 Project Overview](#-project-overview)
- [💫 Project Scope](#-project-scope)
- [🏗️ Project Structure](#️-project-structure)
- [🚀 Getting Started](#-getting-started)
- [⚙️ Configuration](#-configuration)
- [🧪 Testing](#-testing)
- [🤝 Contributing](#-contributing)
- [🌐 Community](#-community)

## 🎯 Project Overview

UnifyAir Core implements the following Network Functions (NFs):

### ✨ Implemented Network Functions

* **🛡️ Omnipath (AMF - Access and Mobility Management Function)**
  * Handles mobility management
  * User authentication and authorization
  * Access control and security procedures
  * UE registration and connection management

### 🚀 Planned Nf Support
* **🌊 DataWarp (UPF - User Plane Function)**
  * Packet routing and forwarding
  * QoS handling for user plane traffic
  * Traffic measurement and reporting
  * Packet inspection and policy enforcement

* **🔄 InfiniSync (SMF - Session Management Function)**
  * Session establishment, modification, and release
  * IP address allocation and management
  * Traffic steering control
  * QoS policy implementation

## 💫 Project Scope

### Current Features
- ⚡ Async-first architecture using Tokio runtime
- 🚀 High-performance network packet processing
- 📋 Standards-compliant 5G NF implementations
- 🧩 Modular design for easy extension and modification
- 📊 Comprehensive logging and monitoring
- 🔌 REST APIs for configuration and management

### Planned Features
- 🔒 Enhanced security features and encryption
- 🔄 Additional Network Function implementations
- ⚡ Performance optimization and scaling improvements
- 📈 Extended monitoring and analytics
- ☁️ Cloud-native deployment support

## 🏗️ Project Structure
```
unifyair-core/
├── lightning-nf/           # Network Functions implementations
│   └── omnipath/           # AMF (Access and Mobility Management Function)
├── lightning-cli/          # Command-line interface tools
├── utils/                  # Shared utilities and common code
├── config/                 # Configuration files
│   ├── amfcfg.yaml         # AMF configuration
│   ├── smfcfg.yaml         # SMF configuration
│   └── upfcfg.yaml         # UPF configuration
├── Cargo.toml              # Rust package manifest
├── rust-toolchain.toml     # Rust toolchain configuration
└── run.sh                  # Utility script for running the project
```

## 🚀 Getting Started

### Prerequisites
- Rust 1.82 or above nightly
- Cargo package manager

### Local Development Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/unifyair/unifyair-core.git
   cd unifyair-core
   ```

2. Install dependencies:
   ```bash
   cargo build
   ```

3. For detailed setup instructions, refer to [SETUP.md](SETUP.md)

## ⚙️ Configuration

Configuration is managed through:
- Environment variables
- Configuration files in `config/`
- Command line arguments

## 🧪 Testing

Run the test suite:
```bash
cargo test
```

## 🤝 Contributing

We welcome contributions! Please see our [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Process
1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to your fork
5. Submit a Pull Request

## 🌐 Community

- 🌍 [Project Website](https://unifyair.io)
- 🐛 [Issue Tracker](https://github.com/UnifyAir/unifyair-core/issues)
- 💬 [Discord Community](https://discord.gg/yuJHdZ4vEF)
- 🐦 [Twitter](https://x.com/unifyair)
