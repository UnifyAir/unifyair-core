#![feature(error_generic_member_access)]
#![feature(adt_const_params)]
#![feature(generic_const_exprs)]
#![feature(async_closure)]

use std::{backtrace::Backtrace, error::Error, fmt::Debug};

use http::{
	Request as HttpRequest,
	Version,
	header::CONTENT_TYPE,
	request::Builder as HttpReqBuilder,
};
use oasbi::{ReqError, common::ProblemDetails};
use reqwest::{Body, Client, Method, Request, Url};
use serde::Serialize;
use thiserror::Error;
use tracing::trace;

mod content_type;
mod header_map_serializer;
pub mod nf_clients;
pub mod nrf_client;
pub mod token_store;

pub use content_type::ContentType;
pub use header_map_serializer::{HeaderSerDeError, to_headers};

pub struct NFConfig {}

pub trait NFType {}

pub struct AmfClient {
	client: Client,
}

pub struct NFProxy {}

#[derive(Debug, Error)]
pub enum ServiceError<E, I>
where
	E: Error + Debug,
	I: Error + Debug,
{
	#[error("Service Error: {0}")]
	Service(
		#[source]
		#[backtrace]
		E,
	),
	#[error("The Inner Error: {0}")]
	Inner(
		#[from]
		#[backtrace]
		I,
	),
}

#[derive(Debug, Error)]
pub enum GenericClientError {
	#[error("ClientRequestError: Request Execution Failed")]
	ClientRequestError(#[from] reqwest::Error),

	#[error("ResponseParseError: Response Parsing Failed")]
	ResponseParseError(
		#[from]
		#[backtrace]
		ReqError,
	),

	#[error("InvalidResponse: Response Failed with status: {0} {1:#?}")]
	InvalidResponse(u16, Option<ProblemDetails>, #[backtrace] Backtrace),

	#[error("HeaderSerDeError: Invalid Header {0}")]
	HeaderSerDeError(
		#[from] header_map_serializer::HeaderSerDeError,
		#[backtrace] Backtrace,
	),

	#[error("QuerySerDeError: Invalid Query {0}")]
	QuerySerDeError(#[from] serde_urlencoded::ser::Error),

	#[error("QuerySerDeError: Invalid Form {0}")]
	UrlFormEncodedError(#[from] serde_qs::Error),

	#[error("SerializationError: Error while serializing body: {0}")]
	SerializationError(#[from] serde_json::Error),

	#[error("PathCreationError: Error while preparing path: {0}")]
	PathCreationError(#[from] formatx::Error),

	#[error("BuilderError: Error while building the request: {0}")]
	BuilderError(#[from] http::Error),

	#[error("UriBuilderError: Error while building url: {0}")]
	UriBuilderError(#[from] url::ParseError),

	#[error("TowerHttpError: Error While making tower request: {0}")]
	TowerHttpError(#[from] tower_reqwest::Error),
}

pub fn remove_leading_slash(input: &str) -> &str {
	if input.starts_with('/') {
		&input[1..]
	} else {
		input
	}
}

pub fn serialize_body<B: Serialize>(
	body: &B,
	encoding_type: ContentType,
) -> Result<Body, GenericClientError> {
	let encoded = match encoding_type {
		ContentType::AppJson => serde_json::to_vec(body)?,
		ContentType::AppForm => {
			let mut writer = vec![];
			serde_qs::to_writer(body, &mut writer)?;
			writer
		}
		_ => todo!(),
	};
	Ok(encoded.into())
}

pub fn prepare_request<H, Q, B>(
	url: Url,
	path: &str,
	method: Method,
	header: Option<&H>,
	query: Option<&Q>,
	body: Option<&B>,
	encoding_type: ContentType,
) -> Result<Request, GenericClientError>
where
	Q: Serialize,
	H: Serialize,
	B: Serialize,
{
	let mut url = url;
	url.set_path(remove_leading_slash(path));
	trace!("Complete url: {path:?}");
	let mut request = Request::new(method, url);
	let mut pairs = request.url_mut().query_pairs_mut();
	if query.is_some() {
		let serializer = serde_urlencoded::Serializer::new(&mut pairs);
		query.serialize(serializer)?;
	}
	drop(pairs);
	header
		.map(|h| to_headers(&h))
		.transpose()?
		.map(|h| request.headers_mut().extend(h));
	request
		.headers_mut()
		.insert(CONTENT_TYPE, encoding_type.to_header_value());
	*request.body_mut() = body
		.map(|t| serialize_body(&t, encoding_type))
		.transpose()?;
	Ok(request)
}

pub fn prepare_http_request<H, Q, B>(
	base_url: &str,
	path: &str,
	method: Method,
	header: Option<&H>,
	query: Option<&Q>,
	body: Option<&B>,
	encoding_type: ContentType,
) -> Result<HttpRequest<Body>, GenericClientError>
where
	Q: Serialize,
	H: Serialize,
	B: Serialize,
{
	let mut url = Url::parse(base_url)?;
	url.join(path)?;

	query
		.map(|q| serde_urlencoded::to_string(q))
		.transpose()?
		.map(|q| url.set_query(Some(&q)));

	let request = HttpReqBuilder::new()
		.version(Version::HTTP_2)
		.uri(url.to_string())
		.method(method);

	let body: Body = body.map_or(Ok(Body::default()), |b| serialize_body(b, encoding_type))?;
	let mut req = request.body(body)?;
	header
		.map(|h| to_headers(h))
		.transpose()?
		.map(|h| req.headers_mut().extend(h));
	req.headers_mut()
		.insert(CONTENT_TYPE, encoding_type.to_header_value());

	Ok(req)
}
