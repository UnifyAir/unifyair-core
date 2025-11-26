use std::sync::Arc;

use ngap_models::{AmfUeNgapId, InitialUeMessage, RanUeNgapId};
use thiserror::Error;
use tokio::sync::{OwnedRwLockWriteGuard, RwLock};

use crate::{
	context::{AtomicGmmState, GmmState, GnbContext, NasContext, NgapContext, UeContext},
	ngap::{
		engine::{EmptyResponse, NgapRequestHandler, NgapResponseError},
		manager::{ContextError, PinnedSendSyncFuture},
	},
	utils::{SeqLock, models::FiveGSTmsi},
};

async fn create_new_context(
	ue_context: UeContext,
	gnb: &GnbContext,
) -> Result<(), UeContext> {
	match gnb.ue_context_manager.add_context(ue_context).await {
		Err(ContextError::ContextAlreadyExists(_, inner)) => {
			return Err(inner);
		}
		Err(_) => unreachable!(),
		Ok(_) => (),
	};
	Ok(())
}

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

		// Add appropriate context to context manager
		match five_g_s_tmsi {
			Some(tmsi) => {
				// Already registered user. Service Request
				// TODO: Fetch the ue context from the idle ue and move it into
				// context manager.
			}
			None => {
				let nas_context =
					NasContext::new(rrc_establishment_cause, five_g_s_tmsi.map(FiveGSTmsi::from));
				let ue_context = UeContext::new(
					ran_ue_ngap_id,
					AmfUeNgapId(state.amf_ue_id_generator.increment()),
					state.clone(),
					AtomicGmmState::new(GmmState::Deregistered),
					nas_context
				);

				match create_new_context(ue_context, &state).await {
					// Another registration has started, so schedule this event onto that.
					// TODO: Add handling of different RRC Establishment Causes
					Err(_) => (),
					Ok(()) => (),
				};
			}
		};

		let future_closure = move |mut ue_context: Arc<SeqLock<UeContext>>| {
			let nas_pdu = nas_pdu.0;
			Box::pin(async move {
				// SAFETY: Context Manager Ensures that futures are executed one by one.
				let ue_context_mut = unsafe { ue_context.get_mut() };
				ue_context_mut.handle_nas(nas_pdu).await;
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
