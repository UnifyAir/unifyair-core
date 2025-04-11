use bytes::BytesMut;
use nas_models::message::*;
use nas_models::parser::GmmMessage;

use statig::prelude::*;

use crate::context::UeContext;

use super::{
	NasHandler,
	NasBuilder,
	NasHandlerError,
	nas_context::NasContext,
};




#[state_machine(
	initial = "State::deregistered()",
	state(derive(Debug, Clone)),
	superstate(derive(Debug, Clone))
)]
impl NasContext {


	#[state(superstate = "registration_initiated")]
	async fn unauthenticated(
		&mut self,
		context: &mut UeContext,
		event: &GmmMessage,
	) -> Response<State> {
		match event {
			GmmMessage::AuthenticationRequest(inner) => {
				return Transition(State::unauthenticated());
			},
			_ => Super,
		}
	}


	#[state(superstate = "registration_initiated")]
	async fn authenticated(
		&mut self,
		context: &mut UeContext,
		event: &GmmMessage,
	) -> Response<State> {
		todo!();
	}


	#[superstate]
	async fn registration_initiated(
		&mut self,
		context: &mut UeContext,
		event: &GmmMessage,
	) -> Response<State> {
		match event {
			GmmMessage::GmmStatus(inner) => {
				// Send NGAP message
				Handled
			}
			_ => Super,
		}
	}

	#[state]
	async fn deregistered(
		&mut self,
		context: &mut UeContext,
		event: &GmmMessage,
	) -> Response<State> {
		match event {
			GmmMessage::GmmStatus(inner) => {
				return Handled;
			}
			GmmMessage::RegistrationRequest(inner) => match inner.handle(self, context).await {
				Ok(_) => {
					match NasAuthenticationRequest::build(self, context) {
						Ok(authentication_request) => {
							return self.unauthenticated(context, &GmmMessage::AuthenticationRequest(authentication_request)).await;
						},
						Err(err) => {
							return Handled;
						}
					}
				}
				Err(err) => {
					return Handled;
				}
			},
			_ => {
				return Handled;
			}
		};
	}
}
