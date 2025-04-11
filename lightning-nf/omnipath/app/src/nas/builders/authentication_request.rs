use nas_models::message::*;

use crate::nas::{NasContext, NasBuilder, UeContext, NasHandlerError};



impl NasBuilder for NasAuthenticationRequest {

	fn build(
		nas_context: &NasContext,
		ue_context: &UeContext
	) -> Result<Self, NasHandlerError> {

		todo!()
	}
}