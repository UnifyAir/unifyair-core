

# 5G Network Functions (NFs) and Local IP Addresses

This document lists all 5G core network functions (NFs) used for integration testing, along with their local unique IP addresses. You can allocate these IPs to the respective NFs for your 5G network testing setup.

| NF Name                                  | Local Unique IP Address(es) |
|------------------------------------------|-----------------------------|
| Access and Mobility Management Function  | 10.0.0.1                    |
| Session Management Function              | 10.0.0.2                    |
| User Plane Function                      | 10.0.0.3                    |
| Network Repository Function              | 10.0.0.4                    |
| Authentication Server Function           | 10.0.0.5                    |
| Policy Control Function                  | 10.0.0.6                    |
| Network Slice Selection Function         | 10.0.0.7                    |
| Unified Data Management                  | 10.0.0.8                    |
| Unified Data Repository                  | 10.0.0.9                    |
| Binding Support Function                 | 10.0.0.10                   |
| Charging Function                        | 10.0.0.11                   |
| Short Message Service Function           | 10.0.0.12                   |
| Non-3GPP Interworking Function           | 10.0.0.13                   |
| Security Edge Protection Proxy           | 10.0.0.14                   |
| Network Data Analytics Function          | 10.0.0.15                   |
| Gateway Mobile Location Centre           | 10.0.0.16                   |
| Service Capability Exposure Function     | 10.0.0.17                   |
| Equipment Identity Register              | 10.0.0.18                   |
| Unstructured Data Storage Function       | 10.0.0.19                   |
| Location Management Function             | 10.0.0.20                   |
| Multicast Broadcast Service Function     | 10.0.0.21                   |
| Network Application Function             | 10.0.0.22                   |
| Network Exposure Function                | 10.0.0.23                   |
| Service Communication Proxy              | 10.0.0.24                   |
| Service Producer Proxy                   | 10.0.0.25                   |
| Home Subscriber Server                   | 10.0.0.26                   |
| Cell Broadcast Centre                    | 10.0.0.27                   |
| Interworking Function                    | 10.0.0.28                   |
| Data Collection Coordination Function    | 10.0.0.29                   |


# Gnb Simulator
Ran1 = Ip Address: 10.0.0.101
Ran2 = Ip Address: 10.0.0.102
Ran3 = Ip Address: 10.0.1.103



## Note for Docker Desktop UI Users

To allow containers to use `localhost` to connect to TCP and UDP services on the host (and vice versa), you must enable the "Host networking" option in Docker Desktop. This is only required if you are using the Docker Desktop UI to manage containers. If you are running containers via the CLI with `--net=host`, this step is not needed.

**How to enable Host Networking in Docker Desktop:**
1. Open Docker Desktop.
2. Go to the **Resources** tab in the left sidebar.
3. Click on the **Networking** section.
4. Enable the option: **"Enable host networking"**.
   - This allows containers started with host networking to use `localhost` for TCP and UDP services on the host, and allows host software to use `localhost` to connect to services in the container.

Enabling this option ensures the local unique IP addresses listed below are reachable as intended for integration testing.