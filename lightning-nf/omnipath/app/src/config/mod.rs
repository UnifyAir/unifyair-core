use std::{
	net::{IpAddr, Ipv4Addr, ToSocketAddrs},
	str::FromStr,
};

use nf_base::{LoggingConfig, NfConfig, RuntimeConfig};
use nonempty::NonEmpty;
use oasbi::{
	common::{Guami, PlmnId, Snssai, Tai, Uri, UriScheme},
	nrf::types::ServiceName,
};
use serde::{Deserialize, Serialize};
use serde_valid::Validate;
use serde_with::{DisplayFromStr, serde_as};
use tokio_sctp::InitMsg;
use tracing::info;

#[derive(Serialize, Deserialize, Debug, Validate, Default)]
#[serde(rename_all = "camelCase")]
pub struct OmniPathConfig {
	pub info: Info,
	#[validate]
	pub configuration: Configuration,
	pub logger: LoggingConfig,
	pub runtime: RuntimeConfig,
	#[validate]
	pub sbi: Sbi,
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct Info {
	#[serde_as(as = "DisplayFromStr")]
	pub version: versions::SemVer,
	pub description: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Validate, smart_default::SmartDefault)]
#[serde(rename_all = "camelCase")]
pub struct Configuration {
	pub amf_name: String,
	#[serde(deserialize_with = "deserialize_ip_list")]
	pub ngap_ip_list: Vec<IpAddr>,
	pub ngap_port: u16,
	#[default(_code = "NonEmpty::new(Guami::default())")]
	pub served_guami_list: NonEmpty<Guami>,
	#[validate(min_items = 1)]
	pub support_tai_list: Vec<Tai>,
	#[default(_code = "NonEmpty::new(PlmnSupportItem::default())")]
	pub plmn_support_list: NonEmpty<PlmnSupportItem>,
	#[validate(min_items = 1)]
	pub support_dnn_list: Vec<String>,
	pub nrf_uri: Uri,
	pub sctp: SCTP,
	// 	pub security: NasSecurity,
	// 	pub network_name: NetworkName,
	// 	pub t3502_value: u16,
	// 	pub t3512_value: u16,
	// 	pub non3gpp_dereg_timer_value: u16,
	// 	pub t3513: Timer,
	// 	pub t3522: Timer,
	// 	pub t3550: Timer,
	// 	pub t3555: Timer,
	// 	pub t3560: Timer,
	// 	pub t3565: Timer,
	// 	pub t3570: Timer,
	// 	pub locality: String,
	// 	pub default_ue_ctx_req: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, smart_default::SmartDefault, Validate)]
#[serde(rename_all = "camelCase")]
pub struct Sbi {
	#[serde(default = "UriScheme::default")]
	pub scheme: UriScheme,
	#[default(_code = "IpAddr::V4(Ipv4Addr::LOCALHOST)")]
	#[serde(deserialize_with = "deserialize_ip_addr")]
	pub register_ip: IpAddr,
	#[default(_code = "IpAddr::V4(Ipv4Addr::LOCALHOST)")]
	#[serde(deserialize_with = "deserialize_ip_addr")]
	pub binding_ip: IpAddr,
	pub port: u16,
	pub tls: Tls,
	#[validate(min_items = 1)]
	#[validate(custom = enum_list([ServiceName::NamfComm, ServiceName::NamfEvts, ServiceName::NamfMt, ServiceName::NamfLoc]))]
	pub service_name_list: Vec<ServiceName>,
}

#[allow(dead_code)]
pub fn enum_list<const N: usize>(
	enumerate: [ServiceName; N]
) -> impl FnOnce(&Vec<ServiceName>) -> Result<(), serde_valid::validation::Error> {
	move |val: &Vec<ServiceName>| {
		if val.iter().all(|item| enumerate.contains(item)) {
			Ok(())
		} else {
			Err(serde_valid::validation::Error::Custom(format!(
				"Not all elements in {} are present in {}.",
				display_slice(&val),
				display_slice(&enumerate)
			)))
		}
	}
}

#[derive(Serialize, Deserialize, Debug, Clone, smart_default::SmartDefault)]
#[serde(rename_all = "camelCase")]
pub struct PlmnSupportItem {
	pub plmn_id: PlmnId,
	#[default(_code = "NonEmpty::new(Snssai::default())")]
	pub snssai_list: NonEmpty<Snssai>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct Tls {
	pub pem: String,
	pub key: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct NasSecurity {
	pub integrity_order: Vec<String>,
	pub ciphering_order: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct NetworkName {
	pub full: String,
	pub short: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "camelCase")]
pub struct MobilityRestrictionList {
	enable: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "camelCase")]
pub struct MaskedIMEISV {
	enable: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "camelCase")]
pub struct RedirectVoiceFallback {
	enable: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "camelCase")]
pub struct NetworkFeatureSupport5GS {
	enable: bool,
	length: u8,
	ims_vo_ps: u8,
	emc: u8,
	emf: u8,
	iwk_n26: u8,
	mpsi: u8,
	emc_n3: u8,
	mcsi: u8,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "camelCase")]
pub struct Timer {
	enable: bool,
	expire_time: i32,
	max_retry_times: u8,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, Default)]
#[serde(rename_all = "camelCase")]
pub struct SCTP {
	num_ostreams: u16,
	max_instreams: u16,
	max_attempts: u16,
	max_init_timeout: u16,
}

impl Into<InitMsg> for &SCTP {
	fn into(self) -> InitMsg {
		InitMsg {
			num_ostreams: self.num_ostreams,
			max_instreams: self.max_instreams,
			max_attempts: self.max_attempts,
			max_init_timeout: self.max_init_timeout,
		}
	}
}

impl NfConfig for OmniPathConfig {
	fn get_log_config(&self) -> &LoggingConfig {
		&self.logger
	}
	fn get_runtime_config(&self) -> &RuntimeConfig {
		&self.runtime
	}
}

impl Sbi {
	/// Returns the full URI for the service-based interface using the configured scheme, register IP address, and port.
	///
	/// # Examples
	///
	/// ```
	/// let sbi = Sbi {
	///     scheme: Scheme::Http,
	///     register_ip: "127.0.0.1".parse().unwrap(),
	///     binding_ip: "127.0.0.1".parse().unwrap(),
	///     port: 8080,
	///     tls: None,
	///     service_name_list: vec![ServiceName::NamfComm],
	/// };
	/// assert_eq!(sbi.get_ip_uri(), "http://127.0.0.1:8080");
	/// ```
	pub fn get_ip_uri(&self) -> String {
		format!(
			"{}://{}:{}",
			self.scheme.to_string(),
			self.register_ip,
			self.port
		)
	}
}

fn display_slice<T: ToString>(input: &[T]) -> String {
	input
		.iter()
		.map(|item| item.to_string())
		.collect::<Vec<_>>()
		.join(", ")
}

pub struct SerdeValidated<T>(T);
impl<T: Validate> SerdeValidated<T> {
	/// Creates a new `SerdeValidated` instance by validating the provided value.
	///
	/// Returns an error if the value fails validation.
	#[example]
	pub fn new(value: T) -> Result<Self, serde_valid::validation::Errors> {
		value.validate()?;
		Ok(SerdeValidated(value))
	}

	pub fn inner(&self) -> &T {
		&self.0
	}

	/// Consumes the wrapper and returns the inner validated value.
	pub fn into_inner(self) -> T {
		self.0
	}
}

/// Resolves a string to an `IpAddr`, accepting either an IP address or a hostname.
///
/// Attempts to parse the input string as an IP address. If parsing fails, performs a DNS lookup on the hostname and returns the first resolved IP address.
///
/// # Errors
///
/// Returns an error if the string cannot be parsed as an IP address and DNS resolution fails.
///
/// # Examples
///
/// ```
/// let ip = resolve_ip_or_hostname("127.0.0.1").unwrap();
/// assert_eq!(ip, std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)));
///
/// let ip = resolve_ip_or_hostname("localhost").unwrap();
/// assert!(matches!(ip, std::net::IpAddr::V4(_)));
/// ```
fn resolve_ip_or_hostname(s: &str) -> Result<IpAddr, Box<dyn std::error::Error + Send + Sync>> {

	info!("Resolving Address: {s}");

	// First, try to parse as a direct IP address
	if let Ok(ip_addr) = IpAddr::from_str(s) {
		info!("Resolved Address: {ip_addr}");
		return Ok(ip_addr);
	}

	// If direct parsing fails, try DNS lookup using std::net
	let addresses: Vec<std::net::SocketAddr> = (s, 80).to_socket_addrs()?.collect();
	// Take the first resolved address
	if let Some(socket_addr) = addresses.into_iter().next() {
		info!("Resolved Address: {}", socket_addr.ip());
		Ok(socket_addr.ip())
	} else {
		Err(format!("Could not resolve hostname: {}", s).into())
	}
}

/// Deserializes a string into an `IpAddr`, accepting either an IP address or a hostname.
///
/// Attempts to parse the input as an IP address; if parsing fails, resolves the string as a hostname via DNS lookup.
/// Returns the first resolved IP address or an error if resolution is unsuccessful. Intended for use with Serde custom deserialization.
///
/// # Examples
///
/// ```
/// use serde::Deserialize;
/// use std::net::IpAddr;
///
/// #[derive(Deserialize)]
/// struct Example {
///     #[serde(deserialize_with = "deserialize_ip_addr")]
///     ip: IpAddr,
/// }
///
/// // Accepts both "192.168.1.1" and "localhost" as valid inputs.
/// ```
fn deserialize_ip_addr<'de, D>(deserializer: D) -> Result<IpAddr, D::Error>
where
	D: serde::Deserializer<'de>,
{
	let string: String = String::deserialize(deserializer)?;

	resolve_ip_or_hostname(&string).map_err(serde::de::Error::custom)
}

/// Deserializes a list of strings into a vector of `IpAddr`, resolving each entry as either an IP address or a hostname.
///
/// Each string in the input list is parsed as an IP address; if parsing fails, it is resolved as a hostname via DNS lookup. Returns a vector of resolved `IpAddr` values.
///
/// # Examples
///
/// ```
/// use serde::Deserialize;
/// use std::net::IpAddr;
///
/// #[derive(Deserialize)]
/// struct Config {
///     #[serde(deserialize_with = "deserialize_ip_list")]
///     addrs: Vec<IpAddr>,
/// }
///
/// let toml = r#"
/// addrs = ["127.0.0.1", "localhost"]
/// "#;
/// let config: Config = toml::from_str(toml).unwrap();
/// assert!(!config.addrs.is_empty());
/// ```
fn deserialize_ip_list<'de, D>(deserializer: D) -> Result<Vec<IpAddr>, D::Error>
where
	D: serde::Deserializer<'de>,
{
	let strings: Vec<String> = Vec::deserialize(deserializer)?;
	let mut ip_addrs = Vec::new();

	for s in strings {
		let ip_addr = resolve_ip_or_hostname(&s).map_err(serde::de::Error::custom)?;
		ip_addrs.push(ip_addr);
	}

	Ok(ip_addrs)
}
