use std::{fmt::Debug, future::Future};

use bytes::Bytes;
use nas_models::{TlvDecode, TlvError};
use ngap_models::NgapPdu;
use thiserror::Error;

use crate::context::GmmState;

// TODO: Convert this State to associated type with ConstParamTy_.
// Rust Lang issue: https://github.com/rust-lang/rust/issues/98210
type State = GmmState;

/// A new, more detailed error for invalid state transitions.
/// It is generic over the request type to provide better context.
#[derive(Error, Debug)]
#[error("Invalid state transition from {state:?} with request: {request:?}")]
pub struct InvalidStateTransition<R: Debug> {
	pub state: State,
	pub request: R,
}

impl<R: Debug> InvalidStateTransition<R> {
	pub fn new(
		state: State,
		request: R,
	) -> Self {
		Self { state, request }
	}
}

/// Defines the contract for handling a NAS message.
/// This version manually specifies `-> impl Future` to avoid the `async-trait`
/// macro and ensures all returned futures are Send and Sync. Their lifetime is
/// correctly tied to the `&mut self` borrow.
pub trait NasMessageHandle: Send + Sync {
	/// The request message type, which must be decodable, debuggable, and safe
	/// to send and share across threads.
	type Request: TlvDecode + Debug + Send + Sync + 'static;

	/// The handler's error type.
	type Error: From<InvalidStateTransition<Self::Request>> + From<TlvError> + Debug;

	/// Decodes raw bytes into the request message.
	fn decode(bytes: Bytes) -> Result<Self::Request, TlvError> {
		let mut bytes = bytes;
		TlvDecode::decode(bytes.len(), &mut bytes)
	}

	/// An optional hook to run before the main state transition logic.
	fn pre_comp_state_change(
		&mut self,
		state: State,
		_req: &mut Self::Request,
	) -> Result<State, Self::Error> {
		Ok(state)
	}

	/// The main state transition dispatcher.
	fn state_transition(
		&mut self,
		from_state: State,
		req: Self::Request,
	) -> impl Future<Output = Result<(State, Option<NgapPdu>), Self::Error>> + Send + Sync {
		async move {
			let mut req = req;
			let from_state = self.pre_comp_state_change(from_state, &mut req)?;
			match from_state {
				GmmState::Deregistered => self.state_transition_deregistered(req).await,
				GmmState::DeregistrationInitiated => {
					self.state_transition_deregistration_initiated(req).await
				}
				GmmState::RegistrationInitiated => {
					self.state_transition_registration_initiated(req).await
				}
				GmmState::Unauthenticated => self.state_transition_unauthenticated(req).await,
				GmmState::Authenticated => self.state_transition_authenticated(req).await,
				GmmState::SecurityModeDone => self.state_transition_security_mode_done(req).await,
				GmmState::Registered => self.state_transition_registered(req).await,
				GmmState::CommonProcedureInitiated => {
					self.state_transition_common_procedure_initiated(req).await
				}
				GmmState::Irrecoverable => self.state_transition_irrecoverable(req).await,
			}
		}
	}

	// --- Default Implementations for each state ---

	fn state_transition_deregistered(
		&mut self,
		req: Self::Request,
	) -> impl Future<Output = Result<(State, Option<NgapPdu>), Self::Error>> + Send + Sync {
		async move { Err(InvalidStateTransition::new(GmmState::Deregistered, req).into()) }
	}

	fn state_transition_deregistration_initiated(
		&mut self,
		req: Self::Request,
	) -> impl Future<Output = Result<(State, Option<NgapPdu>), Self::Error>> + Send + Sync {
		async move { Err(InvalidStateTransition::new(GmmState::DeregistrationInitiated, req).into()) }
	}

	fn state_transition_registration_initiated(
		&mut self,
		req: Self::Request,
	) -> impl Future<Output = Result<(State, Option<NgapPdu>), Self::Error>> + Send + Sync {
		async move { Err(InvalidStateTransition::new(GmmState::RegistrationInitiated, req).into()) }
	}

	fn state_transition_unauthenticated(
		&mut self,
		req: Self::Request,
	) -> impl Future<Output = Result<(State, Option<NgapPdu>), Self::Error>> + Send + Sync {
		async move { Err(InvalidStateTransition::new(GmmState::Unauthenticated, req).into()) }
	}

	fn state_transition_authenticated(
		&mut self,
		req: Self::Request,
	) -> impl Future<Output = Result<(State, Option<NgapPdu>), Self::Error>> + Send + Sync {
		async move { Err(InvalidStateTransition::new(GmmState::Authenticated, req).into()) }
	}

	fn state_transition_security_mode_done(
		&mut self,
		req: Self::Request,
	) -> impl Future<Output = Result<(State, Option<NgapPdu>), Self::Error>> + Send + Sync {
		async move { Err(InvalidStateTransition::new(GmmState::SecurityModeDone, req).into()) }
	}
	fn state_transition_registered(
		&mut self,
		req: Self::Request,
	) -> impl Future<Output = Result<(State, Option<NgapPdu>), Self::Error>> + Send + Sync {
		async move { Err(InvalidStateTransition::new(GmmState::Registered, req).into()) }
	}

	fn state_transition_common_procedure_initiated(
		&mut self,
		req: Self::Request,
	) -> impl Future<Output = Result<(State, Option<NgapPdu>), Self::Error>> + Send + Sync {
		async move { Err(InvalidStateTransition::new(GmmState::CommonProcedureInitiated, req).into()) }
	}

	fn state_transition_irrecoverable(
		&mut self,
		req: Self::Request,
	) -> impl Future<Output = Result<(State, Option<NgapPdu>), Self::Error>> + Send + Sync {
		async move { Err(InvalidStateTransition::new(GmmState::CommonProcedureInitiated, req).into()) }
	}
}

// --- The Tokio Test Case ---
#[cfg(test)]
mod tests {
	use std::{future::Future, sync::Arc};

	use ngap_models::NgapPdu;

	use super::{GmmState, InvalidStateTransition, NasMessageHandle};
	use crate::ngap::engine::EmptyResponse;

	// --- Minimal Handler Implementation ---

	#[derive(Debug, Clone)]
	struct DummyRequest;
	impl nas_models::TlvDecode for DummyRequest {
		fn decode(
			_len: usize,
			_bytes: &mut bytes::Bytes,
		) -> Result<Self, nas_models::TlvError> {
			Ok(DummyRequest)
		}
	}

	#[derive(Debug, thiserror::Error)]
	enum DummyError {
		#[error(transparent)]
		InvalidState(#[from] InvalidStateTransition<DummyRequest>),
		#[error(transparent)]
		Tlv(#[from] nas_models::TlvError),
	}

	#[derive(Debug)]
	struct DummyHandler;

	impl NasMessageHandle for DummyHandler {
		type Request = DummyRequest;
		type Error = DummyError;

		// We only need to override one method for the test.
		fn state_transition_registered(
			&mut self,
			_req: Self::Request,
		) -> impl std::future::Future<Output = Result<(GmmState, Option<NgapPdu>), Self::Error>>
		+ Send
		+ Sync {
			async move { Ok((GmmState::CommonProcedureInitiated, None)) }
		}
	}

	/// Helper to enforce `tokio::spawn` bounds at compile time.
	fn require_spawn_bounds<F>(_future: F)
	where
		F: Future + Send + 'static,
		F::Output: Send + 'static,
	{
		// This function's body is intentionally empty.
		// Successful compilation is the test.
	}

	#[tokio::test]
	async fn handler_future_satisfies_spawn_bounds() {
		// Setup the handler and request.
		let mut handler = DummyHandler;
		let request = DummyRequest;
		let from_state = GmmState::Registered;

		// Create the future that will be tested.
		// It is 'static because it owns all its data (the Arc clone and the request).
		let future_to_test = async move { handler.state_transition(from_state, request).await };

		// This line is the entire test. Successful compilation proves the bounds are
		// met.
		require_spawn_bounds(future_to_test);
	}
}
