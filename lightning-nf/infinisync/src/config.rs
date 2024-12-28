use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::{Ipv4Addr, Ipv6Addr}};

#[derive(Debug, Serialize, Deserialize)]
pub struct InfiniSyncConfig {
	pub info: Info,
	pub configuration: Configuration,
	pub logger: Logger,
	pub ue_routing_info: HashMap<String, UeRoutingInfo>,
	pub route_profile: HashMap<String, RouteProfile>,
	pub pfd_data_for_app: Vec<ApplicationPfd>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Info {
	pub version: String,
	pub description: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Configuration {
	pub smf_name: String,
	pub sbi: Sbi,
	pub service_name_list: Vec<String>,
	pub snssai_infos: Vec<SnssaiInfo>,
	pub plmn_list: Option<Vec<Plmn>>,
	pub locality: String,
	pub pfcp: PfcpConfig,
	pub userplane_information: UserplaneInformation,
	pub t3591: RetransmissionTimer,
	pub t3592: RetransmissionTimer,
	pub nrf_uri: String,
	// pub urr_period: Option<u32>,
	// pub urr_threshold: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Sbi {
	pub scheme: String,
	pub register_ip_v4: Ipv4Addr,
	pub binding_ip_v4: Ipv4Addr,
	pub port: u16,
	pub tls: TlsConfig,
}



#[derive(Debug, Serialize, Deserialize)]
pub struct TlsConfig {
	pub key: String,
	pub pem: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SnssaiInfo {
	pub s_nssai: Snssai,
	pub dnn_infos: Vec<DnnInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Snssai {
	pub sst: u8,
	pub sd: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DnnInfo {
	pub dnn: String,
	pub dns: DnsConfig,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DnsConfig {
	pub ipv4: Ipv4Addr,
	pub ipv6: Ipv6Addr,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Plmn {
	pub mcc: String,
	pub mnc: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PfcpConfig {
	pub node_id: String,
	pub listen_addr: String,
	pub external_addr: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserplaneInformation {
	pub up_nodes: std::collections::HashMap<String, UpNode>,
	pub links: Vec<Link>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpNode {
	#[serde(rename = "type")]
	pub node_type: String,
	pub node_id: Option<String>,
	pub addr: Option<String>,
	pub s_nssai_upf_infos: Option<Vec<SnssaiUpfInfo>>,
	pub interfaces: Option<Vec<Interface>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SnssaiUpfInfo {
	pub s_nssai: Snssai,
	pub dnn_upf_info_list: Vec<DnnUpfInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DnnUpfInfo {
	pub dnn: String,
	pub pools: Vec<CidrPool>,
	pub static_pools: Vec<CidrPool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CidrPool {
	pub cidr: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Interface {
	pub interface_type: String,
	pub endpoints: Vec<String>,
	pub network_instances: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Link {
	#[serde(rename = "A")]
	pub a: String,
	#[serde(rename = "B")]
	pub b: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RetransmissionTimer {
	pub enable: bool,
	pub expire_time: String,
	pub max_retry_times: u8,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Logger {
	pub enable: bool,
	pub level: String,
	pub report_caller: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UeRoutingInfo {
	pub members: Vec<String>,
	pub topology: Vec<Topology>,
	pub specific_path: Vec<SpecificPath>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Topology {
	#[serde(rename = "A")]
	pub a: String,
	#[serde(rename = "B")]
	pub b: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SpecificPath {
	pub dest: String,
	pub path: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RouteProfile {
	pub forwarding_policy_id: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApplicationPfd {
	pub application_id: String,
	pub pfds: Vec<Pfd>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Pfd {
	pub pfd_id: String,
	pub flow_descriptions: Vec<String>,
}
