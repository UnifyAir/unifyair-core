use std::sync::Arc;

use counter::CounterU64;
use derive_new::new;
use ngap_models::{FiveGSTmsi, GlobalRanNodeId, PagingDrx, RanUeNgapId};
use nonempty::NonEmpty;
use oasbi::common::{Snssai, Tai};
use scc::hash_map::HashMap as SccHashMap;
use tokio_util::sync::CancellationToken;

use atomic_handle::AtomicHandle;

use crate::{
	context::ue_context::{GmmStateField, UeContext},
	ngap::{manager::ContextManager, network::TnlaAssociation},
};

#[derive(Debug, new)]
pub struct GnbContext {
	pub tnla_association: Arc<TnlaAssociation>,

	#[new(default)]
	pub global_ran_node_id: GlobalRanNodeId,

	#[new(value = "ContextManager::new()")]
	pub ue_context_manager: ContextManager<UeContext>,

	// List of registered ues who might be paged later
	#[new(default)]
	pub idle_ues: SccHashMap<FiveGSTmsi, UeContext>,

	#[new(default)]
	pub ue_states: SccHashMap<RanUeNgapId, AtomicHandle<UeContext, GmmStateField>>,

	#[new(default)]
	pub name: String,

	#[new(default)]
	pub default_paging_drx: PagingDrx,

	pub sctp_loop_cancellation: CancellationToken,

	#[new(default)]
	pub amf_ue_id_generator: CounterU64,
}

#[derive(Debug)]
pub struct SupportedTai {
	pub tai: Tai,
	pub snssais: NonEmpty<Snssai>,
}
