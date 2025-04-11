use std::sync::Arc;

use counter::CounterU64;
use derive_new::new;
use ngap_models::{GlobalRanNodeId, PagingDrx};
use nonempty::NonEmpty;
use oasbi::common::{PlmnId, Snssai, Tai};
use tokio_util::sync::CancellationToken;

use crate::context::ue_context::UeContext;
use crate::ngap::{manager::ContextManager, network::TnlaAssociation};

#[derive(Debug, new)]
pub struct GnbContext {
	pub tnla_association: Arc<TnlaAssociation>,

	#[new(default)]
	pub global_ran_node_id: GlobalRanNodeId,

	#[new(value = "ContextManager::new()")]
	pub ue_context_manager: ContextManager<UeContext>,

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
