mod error;

use std::num::NonZeroU32;

pub use error::RegistrationReqError;
use nas_models::{message::NasRegistrationRequest, types::MobileIdentity};
use ngap_models::NgapPdu;
use non_empty_string::NonEmptyString;

use super::{InvalidStateTransition, NasMessageHandle};
use crate::context::{GmmState, UeContext};

impl NasMessageHandle for UeContext {
	type Request = NasRegistrationRequest;
	type Error = RegistrationReqError;

    fn pre_comp_state_change(
            &mut self,
            state: GmmState,
            _req: &mut Self::Request,
        ) -> Result<GmmState, Self::Error> {

       Ok(GmmState::RegistrationInitiated) 
    }

	async fn state_transition_deregistered(
		&mut self,
		req: Self::Request,
	) -> Result<(GmmState, Option<NgapPdu>), Self::Error> {

		match req 
			.nas_5gs_mobile_identity
			.get_mobile_identity()
		{
			MobileIdentity::NoIdentity(_no_identity) => {
				// Todo push some logging here
			}
			MobileIdentity::Suci(suci) => {
				self.nas_context.suci = NonEmptyString::new(suci.to_string()).ok();
			}
			MobileIdentity::FiveGGuti(five_gguti) => {
				self.nas_context.guti = NonEmptyString::new(five_gguti.get_guti_string()).ok();
			}
			MobileIdentity::Imei(imei_or_imei_sv) => {
				self.nas_context.pei = NonEmptyString::new(imei_or_imei_sv.to_string()).ok();
			}
			MobileIdentity::FiveGSTmsi(five_gtmsi) => {
				self.nas_context.tmsi = NonZeroU32::new(five_gtmsi.get_5g_tmsi());
			}
			MobileIdentity::Imeisv(imei_or_imei_sv) => {
				self.nas_context.pei = NonEmptyString::new(imei_or_imei_sv.to_string()).ok();
			}
			MobileIdentity::MacAddress(mac_address) => {
				self.nas_context.mac_addr = NonEmptyString::new(mac_address.to_string()).ok();
			}
			MobileIdentity::Eui64(eui64) => todo!(),
		}




		Ok((GmmState::Authenticated, None))
	}
}
