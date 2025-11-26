use std::{error::Error, fmt::Debug, future::Future};

use asn1_per::PerCodec;
use derive_new::new;
use ngap_models::{ErrorIndication, NgapPdu, ToNgapPdu};
use thiserror::Error;
use tracing::error;

#[derive(Debug)]
pub enum NgapFailure<Failure> {
	Failure(Failure),
	GenericError(ErrorIndication),
}

#[derive(Debug, Error, new)]
pub struct NgapResponseError<Failure: Debug, Err: Debug + Error> {
	pub failure: NgapFailure<Failure>,
	#[source]
	pub error: Err,
}

impl<Failure: Debug, Err: Debug + Error> NgapResponseError<Failure, Err> {
	pub fn new_generic_error(
		failure: ErrorIndication,
		error: impl Into<Err>,
	) -> Self {
		Self {
			failure: NgapFailure::new_generic_error(failure),
			error: error.into(),
		}
	}

	pub fn new_failure_error(
		failure: Failure,
		error: impl Into<Err>,
	) -> Self {
		Self {
			failure: NgapFailure::new_failure(failure),
			error: error.into(),
		}
	}
}

impl<Err: Debug + Error> NgapResponseError<EmptyResponse, Err> {
	pub fn new_empty_failure_error(error: impl Into<Err>) -> Self {
		Self::new_failure_error(EmptyResponse::new(), error)
	}
}

impl<Failure> NgapFailure<Failure> {
	pub fn new_failure(failure: Failure) -> Self {
		Self::Failure(failure)
	}

	pub fn new_generic_error(error: ErrorIndication) -> Self {
		Self::GenericError(error)
	}
}

pub trait ToPdu {
	fn to_pdu(self) -> Option<NgapPdu>;
	fn get_name() -> &'static str {
		stringify!(Self)
	}
}

impl<T> ToPdu for T
where
	T: ToNgapPdu,
{
	fn to_pdu(self) -> Option<NgapPdu> {
		Some(self.to_pdu())
	}
}

#[derive(Debug)]
pub struct EmptyResponse;

impl EmptyResponse {
	pub fn new() -> Self {
		Self
	}
}

impl ToPdu for EmptyResponse {
	fn to_pdu(self) -> Option<NgapPdu> {
		None
	}

	fn get_name() -> &'static str {
		stringify!(EmptyResponse)
	}
}

impl<F> ToNgapPdu for NgapFailure<F>
where
	F: ToNgapPdu,
{
	fn to_pdu(self) -> NgapPdu {
		match self {
			NgapFailure::Failure(failure) => failure.to_pdu(),
			NgapFailure::GenericError(error) => <_ as ToNgapPdu>::to_pdu(error),
		}
	}
}

impl ToPdu for NgapFailure<EmptyResponse> {
	fn to_pdu(self) -> Option<NgapPdu> {
		match self {
			NgapFailure::Failure(_) => None,
			NgapFailure::GenericError(error) => Some(<_ as ToNgapPdu>::to_pdu(error)),
		}
	}
}

pub fn log_and_convert_to_pdu<T, F, E>(result: Result<T, NgapResponseError<F, E>>) -> NgapPdu
where
	T: ToNgapPdu + Debug,
	F: ToNgapPdu + Debug,
	E: Debug + Error,
{
	match result {
		Ok(success) => <_ as ToNgapPdu>::to_pdu(success),
		Err(error) => {
			error!("Error Received: {:?}", error.error);
			<NgapFailure<F> as ToNgapPdu>::to_pdu(error.failure)
		}
	}
}

pub trait NgapRequestHandler<Req: Debug, State> {
	type Success: Debug + Send + 'static + ToPdu;
	type Failure: Debug + Send + 'static + ToPdu;
	type Error: Debug + Error + Send + 'static;

	fn handle_request(
		&self,
		state: State,
		request: Req,
	) -> impl Future<Output = Result<Self::Success, NgapResponseError<Self::Failure, Self::Error>>> + Send;
}

type NgapEmptyFailureError<Err> = NgapResponseError<EmptyResponse, Err>;

pub trait NgapResponseHandler<Req, State> {
	type Success: PerCodec + Debug + Send + 'static + ToPdu;
	type Failure: PerCodec + Debug + Send + 'static + ToPdu;
	type Error: Debug + Error + Send + 'static;

	fn handle_success_response(
		&self,
		state: State,
		response: Self::Success,
	) -> impl Future<Output = Result<EmptyResponse, NgapEmptyFailureError<Self::Error>>> + Send;

	fn handle_failure_response(
		&self,
		state: State,
		response: Self::Failure,
	) -> impl Future<Output = Result<EmptyResponse, NgapEmptyFailureError<Self::Error>>> + Send;
}
