use ngap_models::{
	AmfName,
	BroadcastPlmnItem,
	Cause,
	CauseMisc,
	GlobalRanNodeId,
	NgSetupFailure,
	NgSetupRequest,
	NgSetupResponse,
	RelativeAmfCapacity,
	SupportedTaItem,
};
use oasbi::common::{PlmnId, Tac as SbiTac, Tai, error::ConversionError};
use thiserror::Error;
use tracing::trace;

use crate::{
	context::{GnbContext, NgapContext, SupportedTai},
	get_global_app_context,
	ngap::{
		core::utils::{new_semantic_error_cause, resolve_ran_name},
		engine::{NgapRequestHandler, NgapResponseError},
	},
	utils::{convert as ngap_convert, try_convert as ngap_try_convert},
};

impl NgapRequestHandler<NgSetupRequest, &mut GnbContext> for NgapContext {
	type Success = NgSetupResponse;
	type Failure = NgSetupFailure;
	type Error = NgSetupError;

	async fn handle_request(
		&self,
		state: &mut GnbContext,
		request: NgSetupRequest,
	) -> Result<Self::Success, NgapResponseError<Self::Failure, Self::Error>> {
		let NgSetupRequest {
			global_ran_node_id,
			ran_node_name,
			supported_ta_list,
			default_paging_drx,
			extended_ran_node_name,
			..
		} = request;

		if self.gnb_contexts.contains_async(&global_ran_node_id).await {
			return Err(NgapResponseError::new_failure_error(
				build_failure(new_semantic_error_cause()),
				NgSetupError::ConflictingRanId(global_ran_node_id),
			));
		}

		// Set RAN ID from global RAN node ID
		state.global_ran_node_id = global_ran_node_id;
		let name = resolve_ran_name(ran_node_name, extended_ran_node_name);
		// Set RAN name if provided
		state.name = name;
		state.default_paging_drx = default_paging_drx;

		let mut supported_tais = vec![];
		for supported_tai in supported_ta_list.0.into_iter() {
			let SupportedTaItem {
				tac,
				broadcast_plmn_list,
				..
			} = supported_tai;
			for broadcast_plmn_item in broadcast_plmn_list.0.into_iter() {
				// let mut ctx_supported_tai_list = Vec::new();
				let BroadcastPlmnItem {
					plmn_identity,
					tai_slice_support_list,
					..
				} = broadcast_plmn_item;
				let plmn_id: PlmnId = ngap_try_convert(&plmn_identity).map_err(|e| {
					NgapResponseError::new_failure_error(
						build_failure(new_semantic_error_cause()),
						e,
					)
				})?;
				let tac: SbiTac = ngap_convert(&tac);
				let tai = Tai {
					plmn_id,
					tac,
					..Default::default()
				};
				let s_nssai_list = tai_slice_support_list
					.0
					.map(|item| ngap_convert(&item.snssai));
				let supported_tai = SupportedTai {
					tai,
					snssais: s_nssai_list,
				};
				supported_tais.push(supported_tai);
			}
		}
		trace!(supported_tais = ?supported_tais);
		let app_context = get_global_app_context().await;
		// Check if at least one TA is supported by AMF
		let amf_supported_tai_list = &app_context.get_config().support_tai_list;

		let ran_tai_set: std::collections::HashSet<_> =
			supported_tais.iter().map(|t| &t.tai).collect();

		// Find first matching TAI
		let found = amf_supported_tai_list
			.iter()
			.any(|supported_tai| ran_tai_set.contains(&supported_tai));

		if !found {
			Err(NgapResponseError::new_failure_error(
				build_failure(Cause::Misc(CauseMisc::UnknownPlmnOrSnpn)),
				NgSetupError::UnsupportedTais(supported_tais),
			))
		} else {
			// Success case
			let amf_name = &app_context.get_config().name;
			let served_guami_list = &app_context.get_config().served_guami_list;
			let plmn_support_list = &app_context.get_config().plmn_support_list;
			let response = Self::Success {
				plmn_support_list: ngap_convert(plmn_support_list),
				served_guami_list: ngap_convert(served_guami_list),
				relative_amf_capacity: RelativeAmfCapacity(u8::MAX),
				amf_name: AmfName(amf_name.to_string()),
				..Default::default()
			};
			Ok(response)
		}
	}
}

#[derive(Debug, Error)]
pub enum NgSetupError {
	#[error("ConversionError: {0}")]
	ConversionError(#[from] ConversionError),

	#[error("UnsupportedTais: {0:?}")]
	UnsupportedTais(Vec<SupportedTai>),

	#[error("ConflictingRanId: {0:?}")]
	ConflictingRanId(GlobalRanNodeId),
}

fn build_failure(cause: Cause) -> NgSetupFailure {
	NgSetupFailure {
		cause,
		..Default::default()
	}
}
