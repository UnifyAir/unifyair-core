#![feature(error_generic_member_access)]

pub(crate) mod config;
pub(crate) mod context;
pub mod builder;
pub mod ngap;
pub mod nas;
pub mod utils;
pub use context::app_context::get_global_app_context;

use std::{rc::Rc, sync::Arc};

use client::nrf_client::{NrfClient, NrfManagementError};
use config::OmniPathConfig;
use nf_base::NfInstance;
use oasbi::common::NfType;
use openapi_nrf::models::RegisterNfInstanceHeaderParams;
use reqwest::{Client, Url};
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::{
	config::SerdeValidated,
	context::app_context::{AppContext, Configuration},
	builder::sbi::ModelBuildError,
};
use ngap::{context::NgapContext, network::{Network, NetworkError}};

const SOURCE_TYPE: NfType = NfType::Amf;

#[derive(Error, Debug)]
pub enum OmniPathError {
	#[error("ConfigError: Configuration Error")]
	ConfigError(
		#[from]
		#[backtrace]
		OmniPathConfigError,
	),

	#[error("NrfError: Nrf Error")]
	NrfError(
		#[from]
		#[backtrace]
		NrfError,
	),

	#[error("NgapNetworkError: Ngap Network Error")]
	NgapNetworkError(#[from] NetworkError),

	#[error("GlobalAppContextSetError: Unable to set App Context Error")]
	GlobalAppContextSetError(#[from] tokio::sync::SetError<AppContext>),
}

#[derive(Error, Debug)]
pub enum OmniPathConfigError {
	#[error("InvalidNrfUriError: The Nrf Uri is Invalid: {0} {1}")]
	InvalidNrfUriError(#[source] url::ParseError, String),

	#[error("InvalidConfig: Invalid Configuration")]
	InvalidConfig(#[from] serde_valid::validation::Errors),

	#[error("ClientBuildError: Error While Building the nrf client")]
	ClientBuildError(#[from] reqwest::Error),
}

#[derive(Error, Debug)]
pub enum NrfError {
	#[error("ModelBuildError: Unable to build the model")]
	ModelBuildError(#[from] ModelBuildError),

	#[error("NrfManagementError: Unable to register")]
	NrfManagementError(
		#[from]
		#[backtrace]
		NrfManagementError,
	),
}

pub struct OmniPathApp {
	nrf_client: Arc<NrfClient>,
	config: Rc<SerdeValidated<OmniPathConfig>>,
	shutdown: CancellationToken,
	app_context: AppContext,
	ngap_context: Arc<NgapContext>,
}

pub fn create_nrf_client(url: Url) -> Result<NrfClient, OmniPathConfigError> {
	let client = Client::builder()
		.connection_verbose(true)
		// .https_only(true)
		.build()?;
	Ok(NrfClient::new(client, url, SOURCE_TYPE))
}

fn find_diff<'a, T: serde::Serialize>(
	v1: &'a T,
	v2: &'a T,
) -> String {
	macro_rules! try_with_err_msg {
		($expr:expr, $msg:expr) => {
			match $expr {
				Ok(val) => val,
				Err(err) => {
					let err_str = format!("{}: {}", $msg, err.to_string());
					return err_str;
				}
			}
		};
	}

	let v1 = try_with_err_msg!(serde_json::to_value(v1), "Error While Serializing");
	let v2 = try_with_err_msg!(serde_json::to_value(v2), "Error While Serializing");
	let mut d = treediff::tools::Recorder::default();
	treediff::diff(&v1, &v2, &mut d);
	format!("{:#?}", d)
}

impl NfInstance for OmniPathApp {
	type Config = OmniPathConfig;
	type Error = OmniPathError;

	fn initialize(
		config: Self::Config,
		shutdown: CancellationToken,
	) -> Result<Self, Self::Error> {
		let nrf_uri = &config.configuration.nrf_uri.to_string();
		let nrf_url = Url::parse(nrf_uri)
			.map_err(|e| OmniPathConfigError::InvalidNrfUriError(e, nrf_uri.to_owned()))?;
		let nrf_client = create_nrf_client(nrf_url)?;
		let nrf_client = Arc::new(nrf_client);
		let valid_config =
			SerdeValidated::new(config).map_err(OmniPathConfigError::InvalidConfig)?;
		let app_context = AppContext::initialize(&valid_config);

		let ngap_network = Network::new(
			app_context.get_config().ngap_ips[0],
			app_context.get_config().ngap_port,
			&valid_config.inner().configuration.sctp,
		)?;
		
		let ngap_context = NgapContext::new(ngap_network);
		crate::context::app_context::APP_CONTEXT.set(app_context.clone())?;

		Ok(Self {
			nrf_client,
			shutdown,
			app_context,
			config: Rc::new(valid_config),
			ngap_context: Arc::new(ngap_context),
		})
	}

	async fn start(&self) -> Result<(), Self::Error> {
		let ngap_context = self.ngap_context.clone();
		let shutdown = self.shutdown.clone();
		ngap_context.run(shutdown).await?;
		Ok(())
	}

	async fn register_nf(&self) -> Result<(), Self::Error> {
		let nf_profile = self
			.app_context
			.build_nf_profile()
			.map_err(NrfError::from)?;
		let nf_instance_id = self.app_context.get_nf_id();
		let (nf_profile_resp, instance_id) = self
			.nrf_client
			.register_nf_instance(
				nf_instance_id,
				&RegisterNfInstanceHeaderParams::default(),
				&nf_profile,
			)
			.await
			.map_err(NrfError::from)?;
		info!("Nrf Nf Id: {:#?}", instance_id);
		info!(
			"Nrf Profile Response Diff: {}",
			&find_diff(&nf_profile, &nf_profile_resp)
		);
		if let Some(nf_id) = instance_id {
			if nf_id == self.app_context.get_nf_id() {
				let update_config_fn = move |config: &mut Configuration| {
					config.nf_id = nf_id;
				};
				self.app_context.commit_config(update_config_fn);
			}
		}
		Ok(())
	}

	async fn deregister_nf(&self) -> Result<(), Self::Error> {
		let nf_instance_id = self.app_context.get_nf_id().0;
		self.nrf_client
			.deregister_nf_instance()
			.await
			.map_err(NrfError::from)?;
		Ok(())
	}
}
