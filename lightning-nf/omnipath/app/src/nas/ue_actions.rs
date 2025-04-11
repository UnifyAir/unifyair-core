use crate::context::UeContext;

impl UeContext {
	pub async fn handle_nas(
		&mut self,
		nas_pdu: Vec<u8>,
	) {

		// * Need some thought here about how to handle this

		// // Todo: fix this to have a single Bytes for Ngap and Nas
		// let mut bytes = Bytes::from(nas_pdu);

		// let mut gmm = self.gmm.clone();
		// // Safety: unwrap over Arc::get_mut will succeed because
		// // no one will get a mutable reference to the NasContext
		// // and that will only be mutated through the StateMachine
		// // Todo:: make nas_context internal field private by mod __private
		// if let Ok(gmm_message) = GmmMessage::try_from(&mut bytes) {
		// 	Arc::get_mut(&mut gmm).unwrap().handle_with_context(&gmm_message,
		// self); } else {
		// 	trace!("Invalid NAS PDU: {:?}", bytes);
		// }
	}
}
