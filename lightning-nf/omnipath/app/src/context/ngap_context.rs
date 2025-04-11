use std::{collections::HashMap, sync::Arc};

use ngap_models::{AmfUeNgapId, GlobalRanNodeId, RanUeNgapId};
use rustc_hash::FxBuildHasher;
use scc::hash_map::HashMap as SccHashMap;
use tokio::sync::RwLock;

use crate::{
	context::GnbContext,
	ngap::{
		constants::app::INITIAL_GNB_CAPACITY,
		network::{Network, TnlaAssociation},
	},
};

pub struct NgapContext {
	pub(crate) gnb_contexts: SccHashMap<GlobalRanNodeId, Arc<GnbContext>, FxBuildHasher>,
	pub(crate) network: Arc<Network>,
	// TODO: Inspect if this is needed and clean it up.
	pub(crate) _gnb_associations:
		Arc<RwLock<HashMap<GlobalRanNodeId, Arc<TnlaAssociation>, FxBuildHasher>>>,
	// TODO: Ideally Read heavy, so used better data structure for ue_ids.
	pub(crate) _ue_ids:
		Arc<RwLock<HashMap<AmfUeNgapId, (GlobalRanNodeId, RanUeNgapId), FxBuildHasher>>>,
}

impl NgapContext {
	pub fn new(network: Network) -> Self {
		NgapContext {
			gnb_contexts: SccHashMap::with_capacity_and_hasher(
				INITIAL_GNB_CAPACITY,
				FxBuildHasher::default(),
			),
			network: Arc::new(network),
			_gnb_associations: Arc::new(RwLock::new(HashMap::with_capacity_and_hasher(
				INITIAL_GNB_CAPACITY,
				FxBuildHasher::default(),
			))),
			_ue_ids: Arc::new(RwLock::new(HashMap::with_capacity_and_hasher(
				INITIAL_GNB_CAPACITY,
				FxBuildHasher::default(),
			))),
		}
	}
}
