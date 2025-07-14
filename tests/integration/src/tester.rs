use pcap::{Packet, PacketHeader};
use std::collections::HashMap;
use std::net::Ipv4Addr;

use std::{path::Path, process::Command, time::Duration};

use anyhow::{Context, Result};
use pcap::{Active, Capture, Device};

// Import the tester module


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

// Import the IP constants from main.rs
use crate::*;

/// Represents an IP packet header
#[derive(Debug, Clone)]
pub struct IpHeader {
    pub version: u8,
    pub header_length: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub source_ip: Ipv4Addr,
    pub destination_ip: Ipv4Addr,
}

/// Represents a packet flow with source and destination
#[derive(Debug, Clone)]
pub struct PacketFlow {
    pub source_ip: String,
    pub destination_ip: String,
    pub source_name: String,
    pub destination_name: String,
    pub protocol: u8,
    pub length: usize,
    pub timestamp: u64,
}

/// Maps IP addresses to their corresponding network function names
pub fn get_nf_name_by_ip(ip: &str) -> &'static str {
    match ip {
        AMF_IP => "AMF",
        SMF_IP => "SMF", 
        UPF_IP => "UPF",
        NRF_IP => "NRF",
        AUSF_IP => "AUSF",
        PCF_IP => "PCF",
        NSSF_IP => "NSSF",
        UDM_IP => "UDM",
        UDR_IP => "UDR",
        BSF_IP => "BSF",
        CHF_IP => "CHF",
        SMSF_IP => "SMSF",
        N3IWF_IP => "N3IWF",
        SEPP_IP => "SEPP",
        NWDAF_IP => "NWDAF",
        GMLC_IP => "GMLC",
        SCEF_IP => "SCEF",
        EIR_IP => "EIR",
        UDSF_IP => "UDSF",
        LMF_IP => "LMF",
        MBSF_IP => "MBSF",
        NAF_IP => "NAF",
        NEF_IP => "NEF",
        SCP_IP => "SCP",
        SPP_IP => "SPP",
        HSS_IP => "HSS",
        CBC_IP => "CBC",
        IWF_IP => "IWF",
        DCCF_IP => "DCCF",
        RAN1_IP => "RAN1",
        RAN2_IP => "RAN2", 
        RAN3_IP => "RAN3",
        _ => "UNKNOWN",
    }
}

/// Parse IP header from packet data
pub fn parse_ip_header(packet_data: &[u8]) -> Result<Option<IpHeader>> {
    if packet_data.len() < 20 {
        return Ok(None); // Not enough data for IP header
    }

    let version_and_ihl = packet_data[0];
    let version = (version_and_ihl >> 4) & 0x0F;
    let header_length = (version_and_ihl & 0x0F) * 4;

    if version != 4 {
        return Ok(None); // Not IPv4
    }

    if packet_data.len() < header_length as usize {
        return Ok(None); // Not enough data
    }

    let total_length = u16::from_be_bytes([packet_data[2], packet_data[3]]);
    let identification = u16::from_be_bytes([packet_data[4], packet_data[5]]);
    let flags_and_offset = u16::from_be_bytes([packet_data[6], packet_data[7]]);
    let flags = ((flags_and_offset >> 13) & 0x07) as u8;
    let fragment_offset = flags_and_offset & 0x1FFF;
    let ttl = packet_data[8];
    let protocol = packet_data[9];
    let checksum = u16::from_be_bytes([packet_data[10], packet_data[11]]);

    let source_ip = Ipv4Addr::new(
        packet_data[12],
        packet_data[13], 
        packet_data[14],
        packet_data[15]
    );

    let destination_ip = Ipv4Addr::new(
        packet_data[16],
        packet_data[17],
        packet_data[18], 
        packet_data[19]
    );

    Ok(Some(IpHeader {
        version,
        header_length,
        total_length,
        identification,
        flags,
        fragment_offset,
        ttl,
        protocol,
        checksum,
        source_ip,
        destination_ip,
    }))
}

/// Check if an IP address is a known network function
pub fn is_known_nf_ip(ip: &str) -> bool {
    matches!(ip, 
        AMF_IP | SMF_IP | UPF_IP | NRF_IP | AUSF_IP | PCF_IP | NSSF_IP | UDM_IP | UDR_IP |
        BSF_IP | CHF_IP | SMSF_IP | N3IWF_IP | SEPP_IP | NWDAF_IP | GMLC_IP | SCEF_IP |
        EIR_IP | UDSF_IP | LMF_IP | MBSF_IP | NAF_IP | NEF_IP | SCP_IP | SPP_IP |
        HSS_IP | CBC_IP | IWF_IP | DCCF_IP | RAN1_IP | RAN2_IP | RAN3_IP
    )
}

/// Get protocol name from protocol number
pub fn get_protocol_name(protocol: u8) -> &'static str {
    match protocol {
        1 => "ICMP",
        6 => "TCP", 
        17 => "UDP",
        89 => "OSPF",
        132 => "SCTP",
        _ => "UNKNOWN",
    }
}

/// Analyze packet and create packet flow information
pub fn analyze_packet(packet: &Packet) -> Result<Option<PacketFlow>> {
    let packet_data = packet.data;
    
    // Try to parse IP header
    if let Some(ip_header) = parse_ip_header(packet_data)? {
        let source_ip = ip_header.source_ip.to_string();
        let destination_ip = ip_header.destination_ip.to_string();
        
        // Only process packets involving known network functions
        if is_known_nf_ip(&source_ip) || is_known_nf_ip(&destination_ip) {
            let source_name = get_nf_name_by_ip(&source_ip);
            let destination_name = get_nf_name_by_ip(&destination_ip);
            
            let timestamp = packet.header.ts.tv_sec as u64 * 1000000 + packet.header.ts.tv_usec as u64;
            
            return Ok(Some(PacketFlow {
                source_ip,
                destination_ip,
                source_name: source_name.to_string(),
                destination_name: destination_name.to_string(),
                protocol: ip_header.protocol,
                length: packet.len(),
                timestamp,
            }));
        }
    }
    
    Ok(None)
}

/// Print packet flow with arrow notation
pub fn print_packet_flow(flow: &PacketFlow, packet_number: usize) {
    let protocol_name = get_protocol_name(flow.protocol);
    let timestamp_sec = flow.timestamp / 1000000;
    let timestamp_usec = flow.timestamp % 1000000;
    
    println!("📦 Packet #{} | {}:{} → {}:{} | {} | {} bytes | {}s.{}μs", 
        packet_number,
        flow.source_name,
        flow.source_ip,
        flow.destination_name, 
        flow.destination_ip,
        protocol_name,
        flow.length,
        timestamp_sec,
        timestamp_usec
    );
}

/// Process and filter packets based on source and destination
pub fn process_filtered_packets(capture: &mut pcap::Capture<pcap::Active>, duration: std::time::Duration) -> Result<()> {
    println!("🔍 Starting filtered packet analysis...");
    println!("📡 Monitoring traffic between 5G Network Functions...");
    println!("{}", "=".repeat(80));
    
    let start_time = std::time::Instant::now();
    let mut packet_count = 0;
    let mut filtered_count = 0;
    
    // Statistics tracking
    let mut flow_stats: HashMap<String, usize> = HashMap::new();
    
    while start_time.elapsed() < duration {
        match capture.next_packet() {
            Ok(packet) => {
                packet_count += 1;
                
                if let Some(flow) = analyze_packet(&packet)? {
                    filtered_count += 1;
                    print_packet_flow(&flow, filtered_count);
                    
                    // Track flow statistics
                    let flow_key = format!("{} → {}", flow.source_name, flow.destination_name);
                    *flow_stats.entry(flow_key).or_insert(0) += 1;
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                // Timeout is expected, continue
                continue;
            }
            Err(e) => {
                eprintln!("❌ Error capturing packet: {:?}", e);
                break;
            }
        }
    }
    
    // Print summary statistics
    println!("{}", "=".repeat(80));
    println!("📊 Packet Analysis Summary:");
    println!("   Total packets captured: {}", packet_count);
    println!("   Filtered packets (NF traffic): {}", filtered_count);
    println!("   Filter rate: {:.2}%", (filtered_count as f64 / packet_count as f64) * 100.0);
    
    if !flow_stats.is_empty() {
        println!("\n🔄 Top Network Function Flows:");
        let mut sorted_flows: Vec<_> = flow_stats.iter().collect();
        sorted_flows.sort_by(|a, b| b.1.cmp(a.1));
        
        for (flow, count) in sorted_flows.iter().take(10) {
            println!("   {}: {} packets", flow, count);
        }
    }
    
    println!("✅ Packet analysis completed!");
    Ok(())
}

/// Filter packets by specific source and destination IPs
pub fn filter_packets_by_ips(capture: &mut pcap::Capture<pcap::Active>, 
                           source_ip: Option<&str>, 
                           destination_ip: Option<&str>,
                           duration: std::time::Duration) -> Result<()> {
    println!("🎯 Filtering packets with specific criteria...");
    if let Some(src) = source_ip {
        println!("   Source IP: {}", src);
    }
    if let Some(dst) = destination_ip {
        println!("   Destination IP: {}", dst);
    }
    println!("{}", "=".repeat(80));
    
    let start_time = std::time::Instant::now();
    let mut packet_count = 0;
    let mut filtered_count = 0;
    
    while start_time.elapsed() < duration {
        match capture.next_packet() {
            Ok(packet) => {
                packet_count += 1;
                
                if let Some(flow) = analyze_packet(&packet)? {
                    let matches_source = source_ip.map_or(true, |src| flow.source_ip == src);
                    let matches_destination = destination_ip.map_or(true, |dst| flow.destination_ip == dst);
                    
                    if matches_source && matches_destination {
                        filtered_count += 1;
                        print_packet_flow(&flow, filtered_count);
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                continue;
            }
            Err(e) => {
                eprintln!("❌ Error capturing packet: {:?}", e);
                break;
            }
        }
    }
    
    println!("{}", "=".repeat(80));
    println!("📊 Filter Results:");
    println!("   Total packets: {}", packet_count);
    println!("   Matching packets: {}", filtered_count);
    println!("✅ Filtering completed!");
    
    Ok(())
}

/// Example function to demonstrate filtering between specific network functions
pub fn example_filter_amf_to_smf(capture: &mut pcap::Capture<pcap::Active>, duration: std::time::Duration) -> Result<()> {
    println!("🎯 Example: Filtering packets from AMF to SMF...");
    filter_packets_by_ips(capture, Some(AMF_IP), Some(SMF_IP), duration)
}

/// Example function to demonstrate filtering all traffic from RAN
pub fn example_filter_ran_traffic(capture: &mut pcap::Capture<pcap::Active>, duration: std::time::Duration) -> Result<()> {
    println!("🎯 Example: Filtering all RAN traffic...");
    
    let start_time = std::time::Instant::now();
    let mut packet_count = 0;
    let mut filtered_count = 0;
    
    while start_time.elapsed() < duration {
        match capture.next_packet() {
            Ok(packet) => {
                packet_count += 1;
                
                if let Some(flow) = analyze_packet(&packet)? {
                    // Check if source or destination is any RAN
                    let is_ran_source = matches!(flow.source_ip.as_str(), RAN1_IP | RAN2_IP | RAN3_IP);
                    let is_ran_destination = matches!(flow.destination_ip.as_str(), RAN1_IP | RAN2_IP | RAN3_IP);
                    
                    if is_ran_source || is_ran_destination {
                        filtered_count += 1;
                        print_packet_flow(&flow, filtered_count);
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                continue;
            }
            Err(e) => {
                eprintln!("❌ Error capturing packet: {:?}", e);
                break;
            }
        }
    }
    
    println!("{}", "=".repeat(80));
    println!("📊 RAN Traffic Filter Results:");
    println!("   Total packets: {}", packet_count);
    println!("   RAN traffic packets: {}", filtered_count);
    println!("✅ RAN traffic filtering completed!");
    
    Ok(())
}
