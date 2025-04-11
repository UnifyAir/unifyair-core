use std::sync::Arc;

use ngap_models::{AmfUeNgapId, InitialUeMessage, RanUeNgapId};
use thiserror::Error;
use statig::awaitable::IntoStateMachineExt;
use tokio::sync::OwnedRwLockWriteGuard;
use crate::context::ue_context::UeContext;
use crate::nas::nas_context::NasContext;

use crate::{
	ngap::{
		context::{
			EmptyResponse,
			GnbContext,
			NgapContext,
			NgapRequestHandler,
			NgapResponseError,
		},
		manager::{ContextError, PinnedSendSyncFuture},
	},
	utils::models::FiveGSTmsi,
};

impl NgapRequestHandler<InitialUeMessage, Arc<GnbContext>> for NgapContext {
	type Success = EmptyResponse;
	type Failure = EmptyResponse;
	type Error = InitialUeMessageError;

	async fn handle_request(
		&self,
		state: Arc<GnbContext>,
		request: InitialUeMessage,
	) -> Result<Self::Success, NgapResponseError<Self::Failure, Self::Error>> {
		// If the UE context already exists, return an empty response
		// TODO: Handle the case where the UE context already exists and the UE is
		// undergoing Registration procedure
		if state
			.ue_context_manager
			.contains_context(&request.ran_ue_ngap_id)
			.await
		{
			return Err(NgapResponseError::new_empty_failure_error(
				UeContextAlreadyExistsError::InitialUeMessage(request),
			));
		}

		let InitialUeMessage {
			ran_ue_ngap_id,
			nas_pdu,
			rrc_establishment_cause,
			five_g_s_tmsi,
			..
		} = request;

		let ue_context = UeContext::new(
			ran_ue_ngap_id,
			AmfUeNgapId(state.amf_ue_id_generator.increment()),
			rrc_establishment_cause,
			state.clone(),
			five_g_s_tmsi.map(FiveGSTmsi::from),
			Arc::new(NasContext::new().state_machine()),
		);

		match state.ue_context_manager.add_context(ue_context).await {
			Err(ContextError::ContextAlreadyExists(_, inner)) => {
				return Err(NgapResponseError::new_empty_failure_error(
					UeContextAlreadyExistsError::UeContext(inner),
				));
			}
			Err(_) => unreachable!(),
			Ok(_) => (),
		};

		let future_closure = move |mut ue_context: OwnedRwLockWriteGuard<UeContext>| {
			let nas_pdu = nas_pdu.0;
			Box::pin(async move {
				ue_context.handle_nas(nas_pdu).await;
			}) as PinnedSendSyncFuture<()>
		};

		state
			.ue_context_manager
			.with_context(ran_ue_ngap_id, future_closure)
			.await
			.map_or(
				Err(NgapResponseError::new_empty_failure_error(
					InitialUeMessageError::UeContextNotFound(ran_ue_ngap_id),
				)),
				|_| Ok(EmptyResponse::new()),
			)
	}
}

#[derive(Debug, Error)]
pub enum InitialUeMessageError {
	#[error("UeContextAlreadyExists")]
	UeContextAlreadyExists(#[from] UeContextAlreadyExistsError),

	#[error("UeContextNotFound")]
	UeContextNotFound(RanUeNgapId),
}

#[derive(Debug, Error)]
pub enum UeContextAlreadyExistsError {
	#[error("InitialUeMessage: {0:?}")]
	InitialUeMessage(InitialUeMessage),

	#[error("UeContext: {0:?}")]
	UeContext(UeContext),
}
