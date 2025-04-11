use std::fmt::Debug;

use nas_models::{message::NasRegistrationRequest, types as nas_types};
use statig::{awaitable::StateMachine };
use derive_new::new;

#[derive(Debug, new)]
pub struct NasContext {
	#[new(default)]
	pub registration_request: Option<NasRegistrationRequest>,
	#[new(default)]
	pub ue_security_capabliity: Option<nas_types::UeSecurityCapability>,
}


pub enum CmState {
	CmIdle,
	CmConnected,
}

pub enum GmmState {
	GmmDeregistered,
	GmmRegistered,
}
