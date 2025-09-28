use std::{
	convert::Infallible,
	iter::once,
	marker::PhantomData,
	net::SocketAddr,
	ops::AsyncFn,
	sync::Arc,
};

use bytes::Bytes;
use http::{
	Method,
	Request as HttpRequest,
	Response as HttpResponse,
	StatusCode,
	Version,
	header::{AUTHORIZATION, CONTENT_TYPE, HeaderName},
	request::Builder as HttpReqBuilder,
};
use http_body_util::BodyExt;
use hyper_util::service;
use oasbi::{DeserResponse, common::NfType, nrf::types::NfProfile};
use openapi_nrf::models::{
	SearchNfInstancesHeaderParams,
	SearchNfInstancesQueryParams,
	SearchResult,
	ServiceName,
};
use reqwest::{Body, Client, ClientBuilder, Request, Response};
use serde::Serialize;
use thiserror::Error;
use tower::{
	BoxError,
	Service,
	ServiceBuilder,
	ServiceExt,
	service_fn,
	util::{MapRequestLayer, ServiceFn},
};
use tower_http::{
	add_extension::AddExtensionLayer,
	classify::{ServerErrorsAsFailures, SharedClassifier},
	compression::CompressionLayer,
	propagate_header::PropagateHeaderLayer,
	sensitive_headers::{SetSensitiveRequestHeaders, SetSensitiveRequestHeadersLayer},
	set_header::{SetRequestHeader, SetResponseHeaderLayer},
	trace::{Trace, TraceLayer},
	validate_request::ValidateRequestHeaderLayer,
};
use tower_reqwest::{HttpClientLayer, HttpClientService};
use url::Url;

pub mod amf;
mod oauth_service;
mod service_discovery;
use oauth_service::OAuthTokenLayer;
use service_discovery::ServiceDiscoveryLayer;

use crate::{
	GenericClientError,
	nf_clients::{oauth_service::OAuthTokenService, service_discovery::ServiceDiscovery},
	nrf_client::{NrfClient, NrfDiscoveryError},
	to_headers,
};

pub trait ApiBaseUrl {
	fn base_url(&self) -> Url;
}

pub trait NfClientController {
	const CLIENT_TYPE: NfType;
	fn profile_selection(
		&self,
		search_result: SearchResult,
	) -> NfProfile;

	fn get_search_params(
		&self,
		requester_nf_type: NfType,
	) -> SearchNfInstancesQueryParams {
		SearchNfInstancesQueryParams {
			requester_nf_type,
			target_nf_type: Self::CLIENT_TYPE,
			..Default::default()
		}
	}
}

type TowerReqwestClient<T, const TARGET_TYPE: NfType> = ServiceDiscovery<
	OAuthTokenService<
		SetSensitiveRequestHeaders<
			Trace<HttpClientService<Client>,
SharedClassifier<ServerErrorsAsFailures>>, 		>,
		TARGET_TYPE,
	>,
	T,
	TARGET_TYPE,
>;

// type TowerReqwestClient<T, const TARGET_TYPE: NfType> = ServiceDiscovery<
// 	SetSensitiveRequestHeaders<
// 		Trace<HttpClientService<Client>, SharedClassifier<ServerErrorsAsFailures>>,
// 	>,
// 	T,
// 	TARGET_TYPE,
// >;

// type TowerReqwestClient<const TARGET_TYPE: NfType> = OAuthTokenService<
// 	SetSensitiveRequestHeaders<
// 		Trace<HttpClientService<Client>, SharedClassifier<ServerErrorsAsFailures>>,
// 	>,
// 	TARGET_TYPE,
// >;

pub struct NFClient<T, const APP_TYPE: NfType, const TARGET_TYPE: NfType>
where
	T: NfClientController + Send + Sync + 'static,
{
	req_client: TowerReqwestClient<T, TARGET_TYPE>,
	controller: PhantomData<T>,
}

impl<T, const APP_TYPE: NfType, const TARGET_TYPE: NfType> NFClient<T, APP_TYPE, TARGET_TYPE>
where
	T: NfClientController + Send + Sync + 'static,
{
	pub async fn new(
		nrf_client: Arc<NrfClient>,
		controller: T,
		services: Vec<ServiceName>,
	) -> Result<Self, NfClientError> {
		// let url = controller.base_url();
		let builder = ClientBuilder::new();
		let client = builder.build()?;
		// let oauth_layer = OAuthTokenLayer::new(nrf_client.clone(), services.clone());
		let arc_services = services.into();
		let arc_controller = Arc::new(controller);

		let service_discovery_layer = ServiceDiscoveryLayer::<T, TARGET_TYPE>::new(
			nrf_client,
			arc_controller,
			T::CLIENT_TYPE,
			arc_services,
		);

		let service = ServiceBuilder::new()
			// Mark the `Authorization` request header as sensitive so it doesn't show in logs
			.layer(service_discovery_layer)
			.layer(oauth_layer)
			.layer(SetSensitiveRequestHeadersLayer::new(once(AUTHORIZATION)))
			// High level logging of requests and responses
			.layer(TraceLayer::new_for_http())
			.layer(HttpClientLayer)
			.service(client);

		Ok(NFClient {
			controller: PhantomData,
			req_client: service,
		})
	}

	pub async fn request<H, Q, B, Resp>(
		&self,
		req: HttpRequest<Body>,
	) -> Result<(StatusCode, Resp), GenericClientError>
	where
		Q: Serialize,
		H: Serialize,
		B: Serialize,
		Resp: DeserResponse,
	{
		let mut service = self.req_client.clone();
		let resp = service.ready().await?.call(req).await?;
		let (parts, body) = resp.into_parts();
		let body_stream = body.into_data_stream();
		let resp_body = Body::wrap_stream(body_stream);
		let resp = HttpResponse::from_parts(parts, resp_body);
		let req_resp = Response::from(resp);
		Ok(Resp::deserialize(req_resp).await?)
	}
}

#[derive(Error, Debug)]
pub enum NfClientError {
	#[error("Error while creating client")]
	ClientCreationError(
		#[from]
		#[backtrace]
		reqwest::Error,
	),
	#[error("Nrf Search Error")]
	NrfDiscoveryError(
		#[from]
		#[backtrace]
		NrfDiscoveryError,
	),
}
