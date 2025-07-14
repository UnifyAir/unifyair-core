use anyhow::{Context, Result};
use pcap::{Packet, PacketHeader};
use std::collections::HashMap;
use std::net::Ipv4Addr;


// Global constants for 5G Network Functions IP addresses
pub const AMF_IP: &str = "10.0.0.2"; // Access and Mobility Management Function
pub const SMF_IP: &str = "10.0.0.3"; // Session Management Function
pub const UPF_IP: &str = "10.0.0.4"; // User Plane Function
pub const NRF_IP: &str = "10.0.0.5"; // Network Repository Function
pub const AUSF_IP: &str = "10.0.0.6"; // Authentication Server Function
pub const PCF_IP: &str = "10.0.0.7"; // Policy Control Function
pub const NSSF_IP: &str = "10.0.0.8"; // Network Slice Selection Function
pub const UDM_IP: &str = "10.0.0.9"; // Unified Data Management
pub const UDR_IP: &str = "10.0.0.10"; // Unified Data Repository
pub const BSF_IP: &str = "10.0.0.11"; // Binding Support Function
pub const CHF_IP: &str = "10.0.0.12"; // Charging Function
pub const SMSF_IP: &str = "10.0.0.13"; // Short Message Service Function
pub const N3IWF_IP: &str = "10.0.0.14"; // Non-3GPP Interworking Function
pub const SEPP_IP: &str = "10.0.0.15"; // Security Edge Protection Proxy
pub const NWDAF_IP: &str = "10.0.0.16"; // Network Data Analytics Function
pub const GMLC_IP: &str = "10.0.0.17"; // Gateway Mobile Location Centre
pub const SCEF_IP: &str = "10.0.0.18"; // Service Capability Exposure Function
pub const EIR_IP: &str = "10.0.0.19"; // Equipment Identity Register
pub const UDSF_IP: &str = "10.0.0.20"; // Unstructured Data Storage Function
pub const LMF_IP: &str = "10.0.0.21"; // Location Management Function
pub const MBSF_IP: &str = "10.0.0.22"; // Multicast Broadcast Service Function
pub const NAF_IP: &str = "10.0.0.23"; // Network Application Function
pub const NEF_IP: &str = "10.0.0.24"; // Network Exposure Function
pub const SCP_IP: &str = "10.0.0.25"; // Service Communication Proxy
pub const SPP_IP: &str = "10.0.0.26"; // Service Producer Proxy
pub const HSS_IP: &str = "10.0.0.27"; // Home Subscriber Server
pub const CBC_IP: &str = "10.0.0.28"; // Cell Broadcast Centre
pub const IWF_IP: &str = "10.0.0.29"; // Interworking Function
pub const DCCF_IP: &str = "10.0.0.30"; // Data Collection Coordination Function

// GNB Simulator IP addresses
pub const RAN1_IP: &str = "10.0.1.0"; // Ran1
pub const RAN2_IP: &str = "10.0.1.1"; // Ran2
pub const RAN3_IP: &str = "10.0.1.2"; // Ran3

// MongoDB
pub const MONGO_IP: &str = "10.0.100.0"; // MongoDB


fn main() {

}