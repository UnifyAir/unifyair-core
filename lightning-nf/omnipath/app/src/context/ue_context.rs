use std::sync::{Arc, atomic::AtomicUsize};

use atomic_handle::AtomicOperation;
use derive_new::new;
use ngap_models::{AmfUeNgapId, RanUeNgapId};

use crate::{
	context::{AtomicGmmState, GnbContext, NasContext},
	ngap::manager::Identifiable,
};

#[derive(new)]
pub struct UeContext {
	pub ran_ue_ngap_id: RanUeNgapId,
	pub amf_ue_ngap_id: AmfUeNgapId,
	pub gnb_context: Arc<GnbContext>,
	pub state: AtomicGmmState,
	pub nas_context: NasContext,
}

pub struct GmmStateField;

impl AtomicOperation<GmmStateField> for UeContext {
	fn get_atomic(&self) -> &AtomicUsize {
		&self.state
	}
}

impl std::fmt::Debug for UeContext {
	fn fmt(
		&self,
		f: &mut std::fmt::Formatter<'_>,
	) -> std::fmt::Result {
		f.debug_struct("UeContext")
			.field("ran_ue_ngap_id", &self.ran_ue_ngap_id)
			.field("amf_ue_ngap_id", &self.amf_ue_ngap_id)
			.field("gmm", &self.state.get())
			.finish()
	}
}

impl Identifiable for UeContext {
	type ID = RanUeNgapId;

	fn id(&self) -> &Self::ID {
		&self.ran_ue_ngap_id
	}
}
