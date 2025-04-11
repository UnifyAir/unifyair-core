use ngap_models::{DownlinkNasTransport, NasPdu, ToNgapPdu};

use crate::{
	context::UeContext,
	ngap::engine::controller::{NgapWriteError, encode_and_write_ngap_pdu},
};

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
}
