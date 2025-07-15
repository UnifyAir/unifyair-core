use oasbi::{
	common::NfType,
	nrf::types::{AmfInfo, NfProfile1Unchecked, NfStatus},
};
use openapi_nrf::models::NfProfile1;
use tracing::trace;

use crate::{context::app_context::AppContext, builder::sbi::ModelBuildError};

impl AppContext {
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
