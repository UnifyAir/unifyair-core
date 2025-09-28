use std::{
	backtrace::Backtrace,
	str::FromStr,
	sync::Arc,
	time::{SystemTime, UNIX_EPOCH},
};

use arc_swap::ArcSwap;
use formatx::formatx;
use http::{
	HeaderMap,
	Request as HttpRequest,
	header::{self, AUTHORIZATION},
};
use oasbi::{
	DeserResponse,
	common::{
		AccessTokenErr,
		AccessTokenReq,
		AccessTokenReqScope,
		NfInstanceId,
		NfType,
		error::ConversionError,
	},
	service_properties::{
		NrfAccessTokenOperation,
		NrfNFDiscoveryOperation,
		NrfNFManagementOperation,
		NrfService,
		ServiceProperties,
	},
};
use openapi_nrf::{
	apis::{
		access_token_request::AccessTokenRequestResponse,
		nf_instance_id_document::{DeregisterNfInstanceResponse, RegisterNfInstanceResponse},
		nf_instances_store::SearchNfInstancesResponse,
	},
	models::{
		AccessTokenRsp,
		AccessTokenRspTokenType,
		NfProfile1,
		RegisterNfInstanceHeaderParams,
		SearchNfInstancesHeaderParams,
		SearchNfInstancesQueryParams,
		SearchResult,
		ServiceName,
	},
};
use reqwest::{Client, Request, Url};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use tracing::trace;

use crate::{
	ContentType,
	GenericClientError,
	prepare_request,
	token_store::{StoreError, TokenEntry, TokenStore},
};

/// `TraitSatisfier` is an empty enum that exists solely to satisfy trait
/// bounds.
///
/// This enum serves as a "phantom" type, implementing traits without being used
/// directly in any operations. It provides a means to satisfy trait constraints
/// for types or generics that require `Serialize`, `Deserialize`, or `Debug`
/// implementations without having any runtime functionality.
///
///
/// Since `TraitSatisfier` has no variants, it cannot be
/// instantiated.
#[derive(Serialize, Deserialize, Debug)]
pub enum TraitSatisfier {}

pub struct InitConfig {
	pub url: Url,

	// TODO: Convert this to const generic parameter `source: const S: NfType`
	// once const generics feature stabilizes for associated types and complex constants.
	// This will provide compile-time guarantees for NF type consistency and eliminate runtime
	// loads.
	pub source: NfType,
}

/// Configuration that gets populated after successful NF Instance registration
/// with NRF.
///
/// This config maintains runtime state that is established during NF
/// registration:
/// - heartbeat_timer: The keep-alive interval received from NRF
/// - nf_instance_id: The assigned NF Instance ID after successful registration
///
/// Note: While this struct can be Default-initialized, its actual values are
/// meant to be updated post-registration with values received from the NRF.
#[derive(Default, Debug)]
pub struct NfConfig {
	pub heartbeat_timer: u64,
	pub nf_instance_id: NfInstanceId,
	pub oauth_enabled: bool,
}

pub struct NrfClient {
	client: Client,
	init_config: InitConfig,
	nf_config: ArcSwap<NfConfig>,
	nf_token_store: TokenStore<Vec<ServiceName>, AccessTokenRsp>,
}

impl NrfClient {
	fn get_nf_id(&self) -> NfInstanceId {
		self.nf_config.load().nf_instance_id
	}

	fn get_heartbeat_timer(&self) -> u64 {
		self.nf_config.load().heartbeat_timer
	}

	#[inline]
	fn get_oauth_enabled(&self) -> bool {
		self.nf_config.load().oauth_enabled
	}
}

impl NrfClient {
	pub fn new(
		client: Client,
		url: Url,
		source: NfType,
	) -> Self {
		let init_config = InitConfig { url, source };

		Self {
			client,
			init_config,
			nf_config: ArcSwap::from_pointee(NfConfig::default()),
			nf_token_store: TokenStore::new(),
		}
	}

	pub async fn search_nf_instance(
		&self,
		query: SearchNfInstancesQueryParams,
		header: SearchNfInstancesHeaderParams,
	) -> Result<SearchResult, NrfDiscoveryError> {
		let nrf_service_properties =
			NrfService::NFDiscovery(NrfNFDiscoveryOperation::SearchNFInstances);
		let method = nrf_service_properties.get_http_method();
		let path = nrf_service_properties.get_path();
		let request = prepare_request(
			self.init_config.url.clone(),
			&path,
			method,
			Some(&header),
			Some(&query),
			Option::<&TraitSatisfier>::None,
			ContentType::AppJson,
		)?;
		let response = self
			.client
			.execute(request)
			.await
			.map_err(GenericClientError::from)?;
		let (status_code, response) =
			<SearchNfInstancesResponse as DeserResponse>::deserialize(response)
				.await
				.map_err(GenericClientError::from)?;
		match (status_code.as_u16(), response) {
			(_, SearchNfInstancesResponse::Status200 { body, .. }) => Ok(body),
			(status, SearchNfInstancesResponse::Status400(problem))
			| (status, SearchNfInstancesResponse::Status403(problem))
			| (status, SearchNfInstancesResponse::Status404(problem))
			| (status, SearchNfInstancesResponse::Status411(problem))
			| (status, SearchNfInstancesResponse::Status415(problem))
			| (status, SearchNfInstancesResponse::Status429(problem))
			| (status, SearchNfInstancesResponse::Status500(problem))
			| (status, SearchNfInstancesResponse::Status501(problem))
			| (status, SearchNfInstancesResponse::Status503(problem)) => Err(
				GenericClientError::InvalidResponse(status, Some(problem), Backtrace::capture()),
			)?,
			(status, _) => Err(GenericClientError::InvalidResponse(
				status,
				None,
				Backtrace::capture(),
			))?,
		}
	}

	pub async fn register_nf_instance(
		&self,
		nf_instance_id: NfInstanceId,
		header: &RegisterNfInstanceHeaderParams,
		body: &NfProfile1,
	) -> Result<(NfProfile1, Option<NfInstanceId>), NrfManagementError> {
		let nrf_service_properties =
			NrfService::NFManagement(NrfNFManagementOperation::RegisterNFInstance);
		let method = nrf_service_properties.get_http_method();
		let path = formatx!(&nrf_service_properties.get_path(), nf_instance_id.0)
			.map_err(GenericClientError::from)?;
		trace!("path: {path:?}");
		let request = prepare_request(
			self.init_config.url.clone(),
			&path,
			method,
			Some(header),
			Option::<&TraitSatisfier>::None,
			Some(body),
			ContentType::AppJson,
		)?;
		let response = self
			.client
			.execute(request)
			.await
			.map_err(GenericClientError::from)?;
		let (status_code, response) =
			<RegisterNfInstanceResponse as DeserResponse>::deserialize(response)
				.await
				.map_err(GenericClientError::from)?;
		let res = match (status_code.as_u16(), response) {
			(_, RegisterNfInstanceResponse::Status200 { body, .. }) => Ok((body, None)),
			(_, RegisterNfInstanceResponse::Status201 { body, location, .. }) => {
				if let Some(index) = location.rfind('/') {
					trace!("location string: {}", &location[index..]);
					match NfInstanceId::from_str(&location[index + 1..]) {
						Ok(instance) => Ok((body, Some(instance))),
						Err(e) => {
							return Err(NrfManagementError::InvalidLocationSent(
								e,
								location,
								Backtrace::capture(),
							));
						}
					}
				} else {
					Err(NrfManagementError::LocationParseError(
						location,
						Backtrace::capture(),
					))
				}
			}
			(status, RegisterNfInstanceResponse::Status400(problem))
			| (status, RegisterNfInstanceResponse::Status401(problem))
			| (status, RegisterNfInstanceResponse::Status403(problem))
			| (status, RegisterNfInstanceResponse::Status404(problem))
			| (status, RegisterNfInstanceResponse::Status411(problem))
			| (status, RegisterNfInstanceResponse::Status415(problem))
			| (status, RegisterNfInstanceResponse::Status429(problem))
			| (status, RegisterNfInstanceResponse::Status500(problem))
			| (status, RegisterNfInstanceResponse::Status501(problem))
			| (status, RegisterNfInstanceResponse::Status503(problem)) => Err(
				GenericClientError::InvalidResponse(status, Some(problem), Backtrace::capture()),
			)?,
			(status, _) => Err(GenericClientError::InvalidResponse(
				status,
				None,
				Backtrace::capture(),
			))?,
		};
		res.map(|(nf, id)| {
			let heartbeat_timer = nf
				.get()
				.heart_beat_timer
				.as_ref()
				.map_or(0u64, move |v| u64::from(*v));
			let oauth_enabled = match nf.get().custom_info.get("oauth2") {
				Some(Value::Bool(true)) => true,
				_ => false,
			};
			let nf_id = id.map_or(nf_instance_id, |id| id);
			let nf_config = NfConfig {
				oauth_enabled,
				heartbeat_timer,
				nf_instance_id: nf_id,
			};
			self.nf_config.store(Arc::new(nf_config));
			trace!("NfConfig Updated: {:#?}", self.nf_config.load());
			(nf, id)
		})
	}

	pub async fn deregister_nf_instance(&self) -> Result<(), NrfManagementError> {
		let nrf_service_properties =
			NrfService::NFManagement(NrfNFManagementOperation::DeregisterNFInstance);
		let method = nrf_service_properties.get_http_method();
		let nf_instance_id = self.get_nf_id();
		let path = formatx!(&nrf_service_properties.get_path(), nf_instance_id.0)
			.map_err(GenericClientError::from)?;
		let mut request = prepare_request(
			self.init_config.url.clone(),
			&path,
			method,
			Option::<&TraitSatisfier>::None,
			Option::<&TraitSatisfier>::None,
			Option::<&TraitSatisfier>::None,
			ContentType::AppJson,
		)?;
		self.set_auth_token::<{ NfType::Nrf }>(request.headers_mut(), vec![ServiceName::NnrfNfm])
			.await?;
		let response = self
			.client
			.execute(request)
			.await
			.map_err(GenericClientError::from)?;

		let (status_code, response) =
			<DeregisterNfInstanceResponse as DeserResponse>::deserialize(response)
				.await
				.map_err(GenericClientError::from)?;
		match (status_code.as_u16(), response) {
			(_, DeregisterNfInstanceResponse::Status204) => Ok(()),
			(status, DeregisterNfInstanceResponse::Status400(problem))
			| (status, DeregisterNfInstanceResponse::Status401(problem))
			| (status, DeregisterNfInstanceResponse::Status403(problem))
			| (status, DeregisterNfInstanceResponse::Status404(problem))
			| (status, DeregisterNfInstanceResponse::Status411(problem))
			| (status, DeregisterNfInstanceResponse::Status429(problem))
			| (status, DeregisterNfInstanceResponse::Status500(problem))
			| (status, DeregisterNfInstanceResponse::Status501(problem))
			| (status, DeregisterNfInstanceResponse::Status503(problem)) => Err(
				GenericClientError::InvalidResponse(status, Some(problem), Backtrace::capture()),
			)?,
			(status, _) => Err(GenericClientError::InvalidResponse(
				status,
				None,
				Backtrace::capture(),
			))?,
		}
	}

	pub async fn authenticaion_request(
		&self,
		source_instance_id: NfInstanceId,
		source_nf_type: NfType,
		target_nf_type: NfType,
		target_service_name: Vec<ServiceName>,
	) -> Result<AccessTokenRsp, NrfAuthorizationError> {
		let mut token_req = AccessTokenReq::default();
		token_req.target_nf_type = Some(target_nf_type);
		token_req.nf_type = Some(source_nf_type);
		token_req.nf_instance_id = source_instance_id;
		token_req.scope = AccessTokenReqScope::from_str(
			&target_service_name
				.iter()
				.map(|s| s.to_string())
				.collect::<Vec<_>>()
				.join(" "),
		)?;
		let nrf_service_properties =
			NrfService::AccessToken(NrfAccessTokenOperation::AccessTokenRequest);
		let method = nrf_service_properties.get_http_method();
		let path = nrf_service_properties.get_path();

		let request = prepare_request(
			self.init_config.url.clone(),
			&path,
			method,
			Option::<&TraitSatisfier>::None,
			Option::<&TraitSatisfier>::None,
			Some(&token_req),
			ContentType::AppForm,
		)?;
		let response = self
			.client
			.execute(request)
			.await
			.map_err(GenericClientError::from)?;

		let (status_code, response) =
			<AccessTokenRequestResponse as DeserResponse>::deserialize(response)
				.await
				.map_err(GenericClientError::from)?;

		match (status_code.as_u16(), response) {
			(_, AccessTokenRequestResponse::Status200 { body, .. }) => Ok(body),
			(_, AccessTokenRequestResponse::Status400 { body, .. }) => {
				Err(NrfAuthorizationError::AccessTokenError(body))
			}
			(status, AccessTokenRequestResponse::Status401(problem))
			| (status, AccessTokenRequestResponse::Status403(problem))
			| (status, AccessTokenRequestResponse::Status404(problem))
			| (status, AccessTokenRequestResponse::Status411(problem))
			| (status, AccessTokenRequestResponse::Status429(problem))
			| (status, AccessTokenRequestResponse::Status500(problem))
			| (status, AccessTokenRequestResponse::Status501(problem))
			| (status, AccessTokenRequestResponse::Status503(problem)) => Err(
				GenericClientError::InvalidResponse(status, Some(problem), Backtrace::capture()),
			)?,
			(status, _) => Err(GenericClientError::InvalidResponse(
				status,
				None,
				Backtrace::capture(),
			))?,
		}
	}
}

impl NrfClient {
	pub async fn get_token<const T: NfType>(
		&self,
		target_service_name: Vec<ServiceName>,
	) -> Result<TokenEntry<AccessTokenRsp>, NrfAuthorizationError> {
		let token_entry = self.nf_token_store.get(&target_service_name).await?;
		match token_entry {
			Some(entry) if !is_token_expired(entry.get()) => return Ok(entry),
			_ => (),
		};
		let resp = self
			.nf_token_store
			.set(
				target_service_name.clone(),
				self.authenticaion_request(
					self.nf_config.load().nf_instance_id,
					self.init_config.source,
					T,
					target_service_name,
				),
			)
			.await?;
		Ok(resp)
	}

	pub async fn set_auth_token<const T: NfType>(
		&self,
		headers_mut: &mut HeaderMap,
		service_name: Vec<ServiceName>,
	) -> Result<(), NrfAuthorizationError> {
		if self.nf_config.load().oauth_enabled {
			let token_entry = self.get_token::<T>(service_name).await?;
			set_auth_token(headers_mut, token_entry)?;
		}
		Ok(())
	}
}

#[derive(Debug, Error)]
pub enum NrfError {
	#[error("Error Encountered While Discovery")]
	DiscoveryError(
		#[from]
		#[backtrace]
		NrfDiscoveryError,
	),
}

#[derive(Debug, Error)]
pub enum NrfDiscoveryError {
	#[error(transparent)]
	GenericClientError(
		#[from]
		#[backtrace]
		GenericClientError,
	),
}

#[derive(Debug, Error)]
pub enum NrfManagementError {
	#[error("Invalid Location string: {1}")]
	InvalidLocationSent(#[source] uuid::Error, String, #[backtrace] Backtrace),

	#[error("LocationParseError: Unable to get uuid from location {0}")]
	LocationParseError(String, #[backtrace] Backtrace),

	#[error(transparent)]
	GenericClientError(
		#[from]
		#[backtrace]
		GenericClientError,
	),

	#[error("NrfAuthorizationError")]
	NrfAuthorizationError(#[from] NrfAuthorizationError),
}

#[derive(Error, Debug)]
pub enum NrfAuthorizationError {
	#[error("InvalidRequestScope: Converting Services to token scope error")]
	InvalidRequestScope(#[from] ConversionError),

	#[error(transparent)]
	GenericClientError(
		#[from]
		#[backtrace]
		GenericClientError,
	),

	#[error("AccessTokenError: Nrf Token Api Error {0:?}")]
	AccessTokenError(AccessTokenErr),

	#[error("TokenStoreError: Oauth Token Store Error {0:?}")]
	TokenStoreError(#[from] StoreError),

	#[error("TokenParsingError: Invalid Auth Token ")]
	TokenParsingError(#[from] header::InvalidHeaderValue),
}

pub(crate) fn create_token_from_access_token(token_entry: TokenEntry<AccessTokenRsp>) -> String {
	let token: &str = &token_entry.get().access_token;
	let token_type = token_entry.get().token_type;
	match token_type {
		AccessTokenRspTokenType::Bearer => {
			let mut string = "bearer ".to_owned();
			string.push_str(token);
			string
		}
	}
}

pub(crate) fn set_auth_token(
	headers_mut: &mut HeaderMap,
	token_entry: TokenEntry<AccessTokenRsp>,
) -> Result<(), header::InvalidHeaderValue> {
	let token = create_token_from_access_token(token_entry);
	headers_mut.insert(AUTHORIZATION, token.try_into()?);
	Ok(())
}

/// Check if a token is expired based on its expiry time
///
/// Returns `true` if the token is expired or will expire within the buffer time
fn is_token_expired(token: &AccessTokenRsp) -> bool {
	// Get current time
	let now = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		// SAFETY: As now system time should not be before UNIX_EPOCH
		.unwrap_or_default()
		.as_secs();
	// Check if token has expires_in field
	if let Some(expires_in) = token.expires_in {
		// Calculate expiry time (assuming the token was issued recently)
		// In a real implementation, you might want to store the issue time
		// For now, we assume the token was just issued
		let buffer_seconds = 30; // 30 second buffer before expiry
		let expires_at = now + expires_in as u64;
		let expires_with_buffer = expires_at.saturating_sub(buffer_seconds);

		now >= expires_with_buffer
	} else {
		// If no expiry time is provided, assume token is still valid
		// This is a conservative approach
		false
	}
}

#[derive(Debug)]
pub struct Scope(String);

impl From<&[ServiceName]> for Scope {
	fn from(value: &[ServiceName]) -> Self {
		Scope(
			value
				.iter()
				.map(|s| s.to_string())
				.collect::<Vec<_>>()
				.join(" "),
		)
	}
}
