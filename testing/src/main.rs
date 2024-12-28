#![feature(async_closure)]
use std::{convert::Infallible, iter::once, net::SocketAddr, sync::Arc};

use bytes::Bytes;
use http::{
	Request as HttpRequest,
	Response as HttpResponse,
	header::{AUTHORIZATION, CONTENT_TYPE, HeaderName},
};
use http_body_util::Full;
use reqwest::{Body, Client, ClientBuilder, Request, Response, Url};
use tower::{BoxError, Service, ServiceBuilder, ServiceExt, service_fn, util::MapRequestLayer};
use tower_http::{
	add_extension::AddExtensionLayer,
	classify::StatusInRangeAsFailures,
	compression::CompressionLayer,
	decompression::DecompressionLayer,
	propagate_header::PropagateHeaderLayer,
	sensitive_headers::SetSensitiveRequestHeadersLayer,
	set_header::{SetRequestHeader, SetRequestHeaderLayer, SetResponseHeaderLayer},
	trace::{Trace, TraceLayer},
	validate_request::ValidateRequestHeaderLayer,
};
use tower_http::ServiceBuilderExt;
use tower_reqwest::HttpClientLayer;

#[tokio::main]
async fn main() {
	let builder = ClientBuilder::new();
	let client = builder.build().unwrap();
	// .map_response(map_response));
	let service = ServiceBuilder::new()
		// Mark the `Authorization` request header as sensitive so it doesn't show in logs
		.layer(SetSensitiveRequestHeadersLayer::new(once(AUTHORIZATION)))
		// High level logging of requests and responses
		.layer(TraceLayer::new_for_http())
		.layer(HttpClientLayer)
	    .service(client);
	println!("{:?}", std::any::type_name_of_val(&service));
}


