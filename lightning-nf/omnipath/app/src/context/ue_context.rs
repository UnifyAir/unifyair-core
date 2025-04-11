use std::{num::NonZeroU32, sync::Arc};

use derive_new::new;
use ngap_models::{AmfUeNgapId, RanUeNgapId, RrcEstablishmentCause};
use non_empty_string::NonEmptyString;
use statig::awaitable::StateMachine;

use super::GnbContext;
use crate::{nas::nas_context::NasContext, ngap::manager::Identifiable, utils::models::FiveGSTmsi};

#[derive(new)]
pub struct UeContext {
	pub ran_ue_ngap_id: RanUeNgapId,
	pub amf_ue_ngap_id: AmfUeNgapId,
	pub rrc_establishment_cause: RrcEstablishmentCause,
	pub gnb_context: Arc<GnbContext>,
	pub five_g_s_tmsi: Option<FiveGSTmsi>,

	pub gmm: Arc<StateMachine<NasContext>>,
	#[new(default)]
	pub tmsi: Option<NonZeroU32>,
	#[new(default)]
	pub guti: Option<NonEmptyString>,
	#[new(default)]
	pub suci: Option<NonEmptyString>,
	#[new(default)]
	pub pei: Option<NonEmptyString>,
	#[new(default)]
	pub mac_addr: Option<NonEmptyString>,
	#[new(default)]
	pub plmn_id: Option<NonEmptyString>,
}

impl std::fmt::Debug for UeContext {
	fn fmt(
		&self,
		f: &mut std::fmt::Formatter<'_>,
	) -> std::fmt::Result {
		f.debug_struct("UeContext")
			.field("ran_ue_ngap_id", &self.ran_ue_ngap_id)
			.field("amf_ue_ngap_id", &self.amf_ue_ngap_id)
			.field("rrc_establishment_cause", &self.rrc_establishment_cause)
			.field("gnb_context", &self.gnb_context)
			.field("five_g_s_tmsi", &self.five_g_s_tmsi)
			.field("tmsi", &self.tmsi)
			.field("guti", &self.guti)
			.field("suci", &self.suci)
			.field("pei", &self.pei)
			.field("mac_addr", &self.mac_addr)
			.field("plmn_id", &self.plmn_id)
			.finish()
	}
}

impl Identifiable for UeContext {
	type ID = RanUeNgapId;

	fn id(&self) -> &Self::ID {
		&self.ran_ue_ngap_id
	}
}
