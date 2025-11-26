use std::{
	future::Future,
	pin::Pin,
	sync::Arc,
	task::{Context, Poll},
};

use http::{Request as HttpRequest, Response as HttpResponse};
use oasbi::common::NfType;
use openapi_nrf::models::ServiceName;
use reqwest::Body;
use tower::{BoxError, Layer, Service};

use crate::nrf_client::NrfClient;

/// OAuth Token Service that automatically adds authentication headers to
/// requests
#[derive(Clone)]
pub struct OAuthTokenService<S, const TARGET_NF_TYPE: NfType> {
	inner: S,
	nrf_client: Arc<NrfClient>,
	service_names: Vec<ServiceName>,
}

impl<S, const TARGET_NF_TYPE: NfType> OAuthTokenService<S, TARGET_NF_TYPE> {
	/// Create a new OAuth Token Service
	pub fn new(
		inner: S,
		nrf_client: Arc<NrfClient>,
		service_names: Vec<ServiceName>,
	) -> Self {
		Self {
			inner,
			nrf_client,
			service_names,
		}
	}

	/// Get a reference to the inner service
	pub fn inner(&self) -> &S {
		&self.inner
	}

	/// Get a mutable reference to the inner service
	pub fn inner_mut(&mut self) -> &mut S {
		&mut self.inner
	}

	/// Consume this service and return the inner service
	pub fn into_inner(self) -> S {
		self.inner
	}

	/// Get the service names this service will request tokens for
	pub fn service_names(&self) -> &[ServiceName] {
		&self.service_names
	}

	/// Get a reference to the NRF client
	pub fn nrf_client(&self) -> &Arc<NrfClient> {
		&self.nrf_client
	}
}

impl<S, const TARGET_NF_TYPE: NfType> Service<HttpRequest<Body>>
	for OAuthTokenService<S, TARGET_NF_TYPE>
where
	S: Service<HttpRequest<Body>, Response = HttpResponse<Body>, Error = BoxError>
		+ Clone
		+ Send
		+ 'static,
	S::Future: Send + 'static,
{
	type Response = S::Response;
	type Error = BoxError;
	type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

	fn poll_ready(
		&mut self,
		cx: &mut Context<'_>,
	) -> Poll<Result<(), Self::Error>> {
		self.inner.poll_ready(cx)
	}

	fn call(
		&mut self,
		mut req: HttpRequest<Body>,
	) -> Self::Future {
		let mut inner = self.inner.clone();
		let nrf_client = self.nrf_client.clone();
		let service_names = self.service_names.clone();

		Box::pin(async move {
			// Try to add OAuth token if available and OAuth is enabled
			if let Err(e) = nrf_client
				.set_auth_token::<TARGET_NF_TYPE>(req.headers_mut(), service_names)
				.await
			{
				// Convert NrfAuthorizationError to BoxError
				return Err(Box::new(e) as BoxError);
			}

			// Token added successfully (or OAuth not enabled), proceed with request
			inner.call(req).await
		})
	}
}

/// Layer for creating the OAuth Token Service
#[derive(Clone)]
pub struct OAuthTokenLayer<const TARGET_NF_TYPE: NfType> {
	nrf_client: Arc<NrfClient>,
	service_names: Vec<ServiceName>,
}

impl<const TARGET_NF_TYPE: NfType> OAuthTokenLayer<TARGET_NF_TYPE> {
	/// Create a new OAuth Token Layer
	pub fn new(
		nrf_client: Arc<NrfClient>,
		service_names: Vec<ServiceName>,
	) -> Self {
		Self {
			nrf_client,
			service_names,
		}
	}

	/// Create a new OAuth Token Layer with a single service name
	pub fn with_service(
		nrf_client: Arc<NrfClient>,
		service_name: ServiceName,
	) -> Self {
		Self {
			nrf_client,
			service_names: vec![service_name],
		}
	}

	/// Get the service names this layer will request tokens for
	pub fn service_names(&self) -> &[ServiceName] {
		&self.service_names
	}

	/// Get a reference to the NRF client
	pub fn nrf_client(&self) -> &Arc<NrfClient> {
		&self.nrf_client
	}
}

impl<S, const TARGET_NF_TYPE: NfType> Layer<S> for OAuthTokenLayer<TARGET_NF_TYPE> {
	type Service = OAuthTokenService<S, TARGET_NF_TYPE>;

	fn layer(
		&self,
		inner: S,
	) -> Self::Service {
		OAuthTokenService::new(inner, self.nrf_client.clone(), self.service_names.clone())
	}
}

#[cfg(test)]
mod tests {
	use std::convert::Infallible;

	use tower::service_fn;

	use super::*;

	// Mock service for testing
	fn mock_service()
	-> impl Service<HttpRequest<Body>, Response = HttpResponse<Body>, Error = BoxError> + Clone {
		service_fn(|_req| async { Ok(HttpResponse::new(Body::from("test response"))) })
	}

	#[tokio::test]
	async fn test_oauth_layer_creation() {
		// This test would need a mock NrfClient to run properly
		// Left as a structure example
	}
}
