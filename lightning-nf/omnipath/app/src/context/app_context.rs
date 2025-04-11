use std::{net::IpAddr, ops::Deref, sync::Arc};

use arc_swap::{ArcSwap, Guard};
use nonempty::NonEmpty;
use oasbi::{
	common::{Guami, NfInstanceId, Tai},
	nrf::types::{IpEndPoint, NfService1, NfServiceStatus, NfServiceVersion, TransportProtocol},
};
use tokio::sync::OnceCell;
use uuid::Uuid;

use crate::config::{
	Configuration as OmniPathInnerConfig,
	OmniPathConfig,
	PlmnSupportItem,
	Sbi as SbiConfig,
	SerdeValidated,
};

#[derive(Debug)]
pub struct AppContextInner {
	config: ArcSwap<Configuration>,
	sbi: ArcSwap<SbiConfig>,
}

#[derive(Debug, Clone)]
pub struct Configuration {
	pub name: String,
	pub nf_id: NfInstanceId,
	pub ngap_ips: Vec<IpAddr>,
	pub ngap_port: u16,
	pub served_guami_list: NonEmpty<Guami>,
	pub support_dnn_list: Vec<String>,
	pub support_tai_list: Vec<Tai>,
	pub plmn_support_list: NonEmpty<PlmnSupportItem>,
	pub tnl_weight_factor: u64,
	pub nf_services: Vec<NfService1>,
}

impl Configuration {
	pub fn new(valid_config: &SerdeValidated<OmniPathConfig>) -> Self {
		let config = valid_config.inner();
		let OmniPathInnerConfig {
			amf_name: name,
			ngap_ip_list: ngap_ips,
			served_guami_list,
			support_dnn_list,
			support_tai_list,
			plmn_support_list,
			ngap_port,
			..
		} = config.configuration.clone();
		let nf_id = Uuid::new_v4();

		let nf_services = Self::build_nf_services(valid_config);
		let configuration = Configuration {
			name,
			ngap_ips,
			ngap_port,
			served_guami_list,
			support_dnn_list,
			support_tai_list,
			plmn_support_list,
			nf_services,
			tnl_weight_factor: 0,
			nf_id: NfInstanceId::from(nf_id),
		};
		configuration
	}

	pub fn build_nf_services(config: &SerdeValidated<OmniPathConfig>) -> Vec<NfService1> {
		let config = config.inner();
		let api_prefix = Some(config.sbi.get_ipv4_uri());
		let version_uri = format!("v{}", config.info.version.major);
		let service_list = config
			.sbi
			.service_name_list
			.iter()
			.enumerate()
			.map(|(i, service_name)| -> NfService1 {
				let nf_service = NfService1 {
					api_prefix: api_prefix.clone(),
					service_instance_id: i.to_string(),
					service_name: service_name.to_owned(),
					versions: vec![NfServiceVersion {
						api_full_version: config.info.version.to_string(),
						api_version_in_uri: version_uri.to_owned(),
						expiry: None,
					}],
					scheme: config.sbi.scheme.clone(),
					nf_service_status: NfServiceStatus::Registered,
					ip_end_points: vec![IpEndPoint {
						ipv4_address: Some(config.sbi.register_ipv4.into()),
						transport: Some(TransportProtocol::Tcp),
						port: Some(config.sbi.port),
						..Default::default()
					}],
					..Default::default()
				};
				nf_service
			})
			.collect::<Vec<_>>();

		service_list
	}
}

impl AppContextInner {
	pub fn initialize(config: &SerdeValidated<OmniPathConfig>) -> Self {
		let amf_config = Configuration::new(config);
		Self {
			config: ArcSwap::new(Arc::new(amf_config)),
			sbi: ArcSwap::new(Arc::new(config.inner().sbi.clone())),
		}
	}

	// TODO: Implement access trait for multiple config updates.
	// TODO: Have only one central config
	pub fn update_config(
		&mut self,
		valid_config: &SerdeValidated<OmniPathConfig>,
	) {
		let config = Configuration::new(valid_config);
		self.config.swap(Arc::new(config));
		self.sbi.store(Arc::new(valid_config.inner().sbi.clone()));
	}

	/// Retrieves short-lived access to the configuration. Avoid storing the
	/// returned reference.
	pub fn get_config(&self) -> Guard<Arc<Configuration>> {
		self.config.load()
	}

	/// Retrieves short-lived access to the Sbi configuration. Avoid storing the
	/// returned reference.
	pub fn get_sbi_config(&self) -> Guard<Arc<SbiConfig>> {
		self.sbi.load()
	}

	/// Updates the configuration and commits the changes atomically.
	///
	/// This method takes a closure that modifies the Configuration, applies the
	/// changes, and then commits the updated configuration atomically.
	pub fn commit_config<F>(
		&self,
		update_fn: F,
	) where
		F: FnOnce(&mut Configuration),
	{
		// Clone the current configuration for modification
		let mut new_config = self.get_config().as_ref().clone();

		// Apply the update function to modify the configuration
		update_fn(&mut new_config);

		// Commit the updated configuration atomically
		self.config.store(Arc::new(new_config));
	}

	pub fn get_nf_id(&self) -> NfInstanceId {
		self.get_config().nf_id
	}
}

#[derive(Clone, Debug)]
pub struct AppContext(Arc<AppContextInner>);

impl AppContext {
	pub fn initialize(config: &SerdeValidated<OmniPathConfig>) -> Self {
		let inner_context = AppContextInner::initialize(config);
		Self(Arc::new(inner_context))
	}
}

impl Deref for AppContext {
	type Target = AppContextInner;
	fn deref(&self) -> &Self::Target {
		&self.0
	}
}

pub static APP_CONTEXT: OnceCell<AppContext> = OnceCell::const_new();

pub async fn get_global_app_context() -> &'static AppContext {
	APP_CONTEXT
		.get_or_init(|| async {
			// Safety: The config is initialized in the Start of the application. Thus
			// calling this function would always return an initialized context.
			let config = SerdeValidated::new(OmniPathConfig::default()).unwrap();
			AppContext::initialize(&config)
		})
		.await
}
