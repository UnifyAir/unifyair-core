use std::sync::Arc;

use log::trace;
use ngap_models::{
	AmfUeNgapId,
	DownlinkNasTransport,
	NasPdu,
	RanUeNgapId,
	RrcEstablishmentCause,
	ToNgapPdu,
};

use crate::ngap::context::{
	GnbContext,
	ngap_context::{NgapWriteError, encode_and_write_ngap_pdu},
};
use crate::{ngap::manager::Identifiable, utils::models::FiveGSTmsi};


use std::num::NonZeroU32;

use statig::awaitable::StateMachine;

use non_empty_string::NonEmptyString;
use statig::prelude::*;

use crate::nas::nas_context::NasContext;
use derive_new::new;
use nas_models::parser::GmmMessage;
use bytes::Bytes;


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
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

impl UeContext {

	pub async fn send_downlink_nas_transport(
		&self,
		nas_pdu: Vec<u8>,
	) -> Result<(), NgapWriteError> {
		let nas_pdu = NasPdu(nas_pdu);
		let downlink_nas_transport = DownlinkNasTransport {
			ran_ue_ngap_id: self.ran_ue_ngap_id,
			amf_ue_ngap_id: self.amf_ue_ngap_id,
			nas_pdu,
			..Default::default()
		};

		let pdu = downlink_nas_transport.to_pdu();
		encode_and_write_ngap_pdu(self.gnb_context.tnla_association.as_ref(), pdu).await
	}

	pub async fn handle_nas(&mut self, nas_pdu: Vec<u8>) {

		// Todo: fix this to have a single Bytes for Ngap and Nas
		let mut bytes = Bytes::from(nas_pdu);

		let mut gmm = self.gmm.clone();
		// Safety: unwrap over Arc::get_mut will succeed because 
		// no one will get a mutable reference to the NasContext
		// and that will only be mutated through the StateMachine
		// Todo:: make nas_context internal field private by mod __private
		if let Ok(gmm_message) = GmmMessage::try_from(&mut bytes) {
			Arc::get_mut(&mut gmm).unwrap().handle_with_context(&gmm_message, self);
		} else {
			trace!("Invalid NAS PDU: {:?}", bytes);
		}
	}
}


