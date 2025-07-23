use oasbi::{
	common::NfType,
	nrf::types::{AmfInfo, NfProfile1Unchecked, NfStatus},
};
use openapi_nrf::models::NfProfile1;
use tracing::trace;

use crate::{context::app_context::AppContext, builder::sbi::ModelBuildError};

impl AppContext {
	/// Builds a network function (NF) profile for the AMF based on the current application configuration.
	///
	/// Constructs an `NfProfile1` object by gathering configuration data, including AMF information, PLMN list, supported TAIs, and network services.
	/// The method sets the appropriate IP address (IPv4 or IPv6) in the profile according to the SBI configuration.
	/// Returns the completed and validated NF profile, or a `ModelBuildError` if validation fails.
	///
	/// # Returns
	/// A `Result` containing the constructed `NfProfile1` on success, or a `ModelBuildError` if the profile could not be built or validated.
	///
	/// # Examples
	///
	/// ```
	/// let ctx = AppContext::new();
	/// let profile = ctx.build_nf_profile().unwrap();
	/// assert_eq!(profile.nf_type, NfType::Amf);
	/// ```
	pub fn build_nf_profile(&self) -> Result<NfProfile1, ModelBuildError> {
		let config = self.get_config();
		let sbi = self.get_sbi_config();
		let amf_id = config.served_guami_list[0].amf_id;
		let amf_info = AmfInfo {
			amf_region_id: amf_id.region_id,
			amf_set_id: amf_id.set_id,
			guami_list: config.served_guami_list.clone().into(),
			tai_list: config.support_tai_list.clone(),
			..Default::default()
		};
		let plmn_list = config
			.plmn_support_list
			.iter()
			.map(|e| e.plmn_id.clone())
			.collect::<Vec<_>>();
		let mut nf_profile = NfProfile1Unchecked {
			nf_instance_id: config.nf_id,
			nf_type: NfType::Amf,
			nf_status: NfStatus::Registered,
			amf_info: Some(amf_info),
			plmn_list,
			nf_services: config.nf_services.clone(),
			..Default::default()
		};
		match &sbi.register_ip {
			std::net::IpAddr::V4(v4) => {
				nf_profile.ipv4_addresses = vec![v4.into()];
			}
			std::net::IpAddr::V6(v6) => {
				nf_profile.ipv6_addresses = vec![v6.into()];
			}		
		}
		trace!("NfProfile 1: {:#?}", nf_profile);
		Ok(nf_profile.try_into()?)
	}
}
