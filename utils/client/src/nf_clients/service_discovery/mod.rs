mod future;
use std::{
	collections::HashMap,
	future::Future,
	pin::Pin,
	sync::Arc,
	task::{Context, Poll},
	time::{Duration, SystemTime, UNIX_EPOCH},
};

use arc_swap::ArcSwap;
use future::ResponseFuture;
use http::{Request as HttpRequest, Response as HttpResponse, Uri, uri::InvalidUri};
use oasbi::{
	common::NfType,
	nrf::types::{NfProfile, ServiceName},
};
use openapi_nrf::models::SearchNfInstancesHeaderParams;
use reqwest::Body;
use tower::{BoxError, Layer, Service};
use url::Url;

use super::NfClientController;
use crate::nrf_client::{NrfClient, NrfDiscoveryError};

/// Create an empty cached profile
fn empty_cached_profile() -> CachedNfProfile {
	CachedNfProfile {
		nf_profile: None,
		service_urls: HashMap::new(),
		validity_period: None,
		cached_at: UNIX_EPOCH,
	}
}

/// Cached NF profile with validity period
#[derive(Debug, Clone)]
pub struct CachedNfProfile {
	pub nf_profile: Option<NfProfile>,
	pub service_urls: HashMap<ServiceName, Vec<Url>>,
	pub validity_period: Option<i64>,
	pub cached_at: SystemTime,
}

impl CachedNfProfile {
	pub fn new(
		nf_profile: Option<NfProfile>,
		validity_period: Option<i64>,
	) -> Self {
		let service_urls = nf_profile
			.as_ref()
			.map(|profile| {
				let mut map = HashMap::new();
				for service in &profile.nf_services {
					let urls: Vec<Url> = service
						.ip_end_points
						.iter()
						.filter_map(|endpoint| {
							let scheme = service.scheme.to_string();
							let host = endpoint.ipv4_address.as_ref()?;
							let port = endpoint.port?;

							let url_str = format!("{}://{:?}:{}", scheme, host, port);
							Url::parse(&url_str).ok()
						})
						.collect();

					if !urls.is_empty() {
						map.insert(service.service_name.clone(), urls);
					}
				}
				map
			})
			.unwrap_or_default();

		Self {
			nf_profile,
			service_urls,
			validity_period,
			cached_at: SystemTime::now(),
		}
	}

	pub fn is_valid(&self) -> bool {
		if let Some(validity_seconds) = self.validity_period {
			SystemTime::now()
				.duration_since(self.cached_at)
				.unwrap_or(Duration::MAX)
				.as_secs() < validity_seconds as u64
		} else {
			self.nf_profile.is_some() // Valid if we have a profile and no expiry
		}
	}

	pub fn get_base_url(&self) -> Option<&Url> {
		// Return the first URL from the first service
		self.service_urls.values().flatten().next()
	}

	pub fn get_service_urls(
		&self,
		service_name: &ServiceName,
	) -> Option<&Vec<Url>> {
		self.service_urls.get(service_name)
	}

	pub fn get_first_service_url(
		&self,
		service_name: &ServiceName,
	) -> Option<&Url> {
		self.service_urls
			.get(service_name)
			.and_then(|urls| urls.first())
	}
}

/// Service discovery layer with atomic cache
pub struct ServiceDiscoveryLayer<T, const TARGET_NF_TYPE: NfType> {
	// Use ArcSwap for lock-free reads, only one writer at a time
	cached_profile: Arc<ArcSwap<CachedNfProfile>>,
	nrf_client: Arc<NrfClient>,
	controller: Arc<T>,
	service_names: Arc<[ServiceName]>,
	app_type: NfType,
	// Prevent multiple concurrent discoveries
	discovery_semaphore: Arc<tokio::sync::Semaphore>,
}

impl<T, const TARGET_NF_TYPE: NfType> Clone for ServiceDiscoveryLayer<T, TARGET_NF_TYPE> {
	fn clone(&self) -> Self {
		Self {
			cached_profile: self.cached_profile.clone(),
			nrf_client: self.nrf_client.clone(),
			controller: self.controller.clone(),
			app_type: self.app_type,
			discovery_semaphore: self.discovery_semaphore.clone(),
			service_names: self.service_names.clone(),
		}
	}
}

impl<T, const TARGET_NF_TYPE: NfType> ServiceDiscoveryLayer<T, TARGET_NF_TYPE>
where
	T: NfClientController,
{
	pub fn new(
		nrf_client: Arc<NrfClient>,
		controller: Arc<T>,
		app_type: NfType,
		service_names: Arc<[ServiceName]>,
	) -> Self {
		Self {
			cached_profile: Arc::new(ArcSwap::from_pointee(empty_cached_profile())),
			nrf_client,
			controller,
			app_type,
			discovery_semaphore: Arc::new(tokio::sync::Semaphore::new(1)),
			service_names,
		}
	}

	/// Check if the cache is valid (fast path)
	pub fn is_cache_valid(&self) -> bool {
		self.cached_profile.load().is_valid()
	}

	/// Get the cached profile if valid
	pub fn get_cached_profile(&self) -> Option<Arc<CachedNfProfile>> {
		let cached = self.cached_profile.load();
		if cached.is_valid() {
			Some(cached.clone())
		} else {
			None
		}
	}

	/// Private helper to handle the "slow path" where the cache is stale.
	/// This function manages the semaphore to ensure only one discovery happens
	/// at a time.
	pub async fn discover_and_update_cache(
		self: Self
	) -> Result<Arc<CachedNfProfile>, ServiceDiscoveryError> {
		// Acquire a permit. This will pause if another task is already updating.
		let _permit = self.discovery_semaphore.acquire().await.unwrap();

		// Perform the crucial "double-check". The cache might have been
		// updated by the task we were waiting for.
		let cached_after_wait = self.cached_profile.load();
		if cached_after_wait.is_valid() {
			return Ok(cached_after_wait.clone());
		}

		// --- We are the designated "worker" ---
		// The cache is still stale, so we must perform the discovery.
		let search_params = self.controller.get_search_params(self.app_type);
		let header_params = SearchNfInstancesHeaderParams {
			..Default::default()
		};

		match self
			.nrf_client
			.search_nf_instance(search_params, header_params)
			.await
		{
			Ok(search_result) => {
				let validity_period = search_result.validity_period.clone();
				let nf_profile = self.controller.profile_selection(search_result);
				let new_cached_arc =
					Arc::new(CachedNfProfile::new(Some(nf_profile), validity_period));
				self.cached_profile.store(new_cached_arc.clone());
				Ok(new_cached_arc)
			}
			Err(e) => {
				// On failure, clear the cache to ensure the next request can retry.
				self.cached_profile.store(Arc::new(empty_cached_profile()));
				Err(e.into())
			}
		}
	}

	pub fn invalidate_cache(&self) {
		// Atomic invalidation using empty profile
		self.cached_profile.store(Arc::new(empty_cached_profile()));
	}
}

impl<S, T, const TARGET_NF_TYPE: NfType> Layer<S> for ServiceDiscoveryLayer<T, TARGET_NF_TYPE>
where
	T: NfClientController,
{
	type Service = ServiceDiscovery<S, T, TARGET_NF_TYPE>;

	fn layer(
		&self,
		inner: S,
	) -> Self::Service {
		ServiceDiscovery {
			inner,
			layer: self.clone(),
			discovery_future: None,
		}
	}
}

/// Applies service discovery to requests.
pub struct ServiceDiscovery<S, T, const TARGET_NF_TYPE: NfType> {
	inner: S,
	layer: ServiceDiscoveryLayer<T, TARGET_NF_TYPE>,
	// Store the discovery future in the service to poll it in poll_ready
	discovery_future: Option<
		Pin<Box<dyn Future<Output = Result<Arc<CachedNfProfile>, ServiceDiscoveryError>> + Send>>,
	>,
}

impl<S, T, const TARGET_NF_TYPE: NfType> Clone for ServiceDiscovery<S, T, TARGET_NF_TYPE>
where
	S: Clone,
{
	fn clone(&self) -> Self {
		ServiceDiscovery {
			inner: self.inner.clone(),
			layer: self.layer.clone(),
			discovery_future: None, // Don't clone the discovery future
		}
	}
}

impl<S, T, const TARGET_NF_TYPE: NfType> ServiceDiscovery<S, T, TARGET_NF_TYPE> {
	/// Creates a new [`ServiceDiscovery`]
	pub fn new(
		inner: S,
		layer: ServiceDiscoveryLayer<T, TARGET_NF_TYPE>,
	) -> Self {
		ServiceDiscovery {
			inner,
			layer,
			discovery_future: None,
		}
	}

	/// Get a reference to the inner service
	pub fn get_ref(&self) -> &S {
		&self.inner
	}

	/// Get a mutable reference to the inner service
	pub fn get_mut(&mut self) -> &mut S {
		&mut self.inner
	}

	/// Consume `self`, returning the inner service
	pub fn into_inner(self) -> S {
		self.inner
	}
}

impl<S, T, const TARGET_NF_TYPE: NfType> Service<HttpRequest<Body>>
	for ServiceDiscovery<S, T, TARGET_NF_TYPE>
where
	S: Service<HttpRequest<Body>, Response = HttpResponse<Body>>,
	S::Error: Into<BoxError>,
	T: NfClientController + Send + Sync + 'static,
{
	type Response = S::Response;
	type Error = BoxError;
	type Future = ResponseFuture<S::Future>;

	fn poll_ready(
		&mut self,
		cx: &mut Context<'_>,
	) -> Poll<Result<(), Self::Error>> {
		// First check if we have a valid cache (fast path)
		if self.layer.is_cache_valid() {
			// Cache is valid, just check if inner service is ready
			return self.inner.poll_ready(cx).map_err(Into::into);
		}

		// Cache is stale, we need to discover
		loop {
			if let Some(ref mut discovery_fut) = self.discovery_future {
				// We have an ongoing discovery, poll it
				match discovery_fut.as_mut().poll(cx) {
					Poll::Ready(Ok(_cached_profile)) => {
						// Discovery completed successfully
						self.discovery_future = None;
						// Now check if inner service is ready
						return self.inner.poll_ready(cx).map_err(Into::into);
					}
					Poll::Ready(Err(e)) => {
						// Discovery failed
						self.discovery_future = None;
						return Poll::Ready(Err(Box::new(e)));
					}
					Poll::Pending => {
						// Discovery is still in progress
						return Poll::Pending;
					}
				}
			} else {
				// No ongoing discovery, start one
				self.discovery_future = Some(Box::pin(ServiceDiscoveryLayer::discover_and_update_cache(self.layer.clone())));
				// Continue the loop to poll the new future
			}
		}
	}

	fn call(
		&mut self,
		mut request: HttpRequest<Body>,
	) -> Self::Future {
		// At this point, poll_ready has ensured we have a valid cache
		match self.layer.get_cached_profile() {
			Some(cached_profile) => {
				// Update the request URL with the discovered service URL
				match Self::update_request_url(&mut request, &cached_profile) {
					Ok(()) => {
						// URL updated successfully, create the success future
						let inner_future = self.inner.call(request);
						ResponseFuture::new(inner_future)
					}
					Err(e) => {
						// URL update failed, create the error future
						ResponseFuture::error(e.into())
					}
				}
			}
			None => {
				// This should not happen if poll_ready worked correctly,
				// but handle it gracefully by creating an error future.
				let error = Box::new(ServiceDiscoveryError::NoServiceUrl) as BoxError;
				ResponseFuture::error(error)
			}
		}
	}
}

impl<S, T, const TARGET_NF_TYPE: NfType> ServiceDiscovery<S, T, TARGET_NF_TYPE> {
	fn update_request_url(
		request: &mut HttpRequest<Body>,
		cached_profile: &CachedNfProfile,
	) -> Result<(), ServiceDiscoveryError> {
		match cached_profile.get_base_url() {
			Some(base_url) => {
				let original_path = request
					.uri()
					.path_and_query()
					.map(|pq| pq.as_str())
					.unwrap_or("/");

				let new_url = base_url.join(original_path)?;
				let new_uri: Uri = new_url.as_str().parse()?;
				*request.uri_mut() = new_uri;
				Ok(())
			}
			None => Err(ServiceDiscoveryError::NoServiceUrl),
		}
	}
}

#[derive(thiserror::Error, Debug)]
pub enum ServiceDiscoveryError {
	#[error("NRF discovery failed: {0}")]
	NrfError(#[from] NrfDiscoveryError),

	#[error("No service URL found")]
	NoServiceUrl,

	#[error(transparent)]
	UrlParseError(#[from] url::ParseError),

	#[error(transparent)]
	InvalidUri(#[from] InvalidUri),

	#[error(transparent)]
	BoxError(#[from] BoxError),
}
