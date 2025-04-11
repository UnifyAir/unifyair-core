use std::num::NonZeroU32;

use nas_models::message as nas_message;
use nas_models::types as nas_types;
use non_empty_string::NonEmptyString;

use crate::nas::error::NasHandlerError;
use crate::nas::NasContext;
use crate::nas::UeContext;
use crate::nas::NasHandler;


fn initial_registration_handler(nas_registration_request: &nas_message::NasRegistrationRequest, nas_context:&mut NasContext, ue_context: &mut UeContext) -> Result<(), NasHandlerError>{
    // keep registration request for amf re-allocation
    nas_context.registration_request = Some(nas_registration_request.clone());

    match nas_registration_request.nas_5gs_mobile_identity.get_mobile_identity() {
        nas_types::MobileIdentity::NoIdentity(_no_identity) => {
            // Todo push some logging here
        },
        nas_types::MobileIdentity::Suci(suci) => {
            ue_context.suci = NonEmptyString::new(suci.to_string()).ok();
        },
        nas_types::MobileIdentity::FiveGGuti(five_gguti) => {
            ue_context.guti = NonEmptyString::new(five_gguti.get_guti_string()).ok();
        },
        nas_types::MobileIdentity::Imei(imei_or_imei_sv) => {
            ue_context.pei = NonEmptyString::new(imei_or_imei_sv.to_string()).ok();
        },
        nas_types::MobileIdentity::FiveGSTmsi(five_gtmsi) => {
            ue_context.tmsi = NonZeroU32::new(five_gtmsi.get_5g_tmsi());
        },
        nas_types::MobileIdentity::Imeisv(imei_or_imei_sv) => {
            ue_context.pei = NonEmptyString::new(imei_or_imei_sv.to_string()).ok();
        },
        nas_types::MobileIdentity::MacAddress(mac_address) => {
            ue_context.mac_addr = NonEmptyString::new(mac_address.to_string()).ok();
        },
        nas_types::MobileIdentity::Eui64(eui64) => todo!(),
    }

    if let Some(ue_security_capability) = &nas_registration_request.nas_ue_security_capability {
        nas_context.ue_security_capabliity = Some(ue_security_capability.clone());
    } else {
        return Err(NasHandlerError::FiveGmmCauseError(nas_types::FiveGmmCause::protocol_error_unspecified()));
    }



    
    Ok(())
}

impl NasHandler for nas_message::NasRegistrationRequest {
    
    async fn handle(
        &self,
        nas_context: &mut NasContext,
        ue_context: &mut UeContext,
    ) -> Result<(), NasHandlerError> {
        match self.nas_5gs_registration_type.get_registration_type() {
            nas_types::RegistrationType::InitialRegistration => initial_registration_handler(self, nas_context, ue_context),
            nas_types::RegistrationType::MobilityRegistrationUpdating => todo!(),
            nas_types::RegistrationType::PeriodicRegistrationUpdating => todo!(),
            nas_types::RegistrationType::EmergencyRegistration => todo!(),
            nas_types::RegistrationType::SnpnOnboardingRegistration => todo!(),
            nas_types::RegistrationType::DisasterRoamingMobilityRegistrationUpdating => todo!(),
            nas_types::RegistrationType::DisasterRoamingInitialRegistration => todo!(),
        }
    }

}


 
 