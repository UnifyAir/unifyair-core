use std::{cell::UnsafeCell, num::NonZeroU32};

use derive_new::new;
use ngap_models::RrcEstablishmentCause;
use non_empty_string::NonEmptyString;

use crate::utils::models::FiveGSTmsi;

#[derive(new)]
pub struct NasContext {
	pub rrc_establishment_cause: RrcEstablishmentCause,
	pub five_g_s_tmsi: Option<FiveGSTmsi>,
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
