use nas_models::message as nas_message;

use crate::nas::{NasContext, NasHandler, UeContext, NasHandlerError};


impl NasHandler for nas_message::NasAuthenticationResponse {

    async fn handle(
        &self,
        nas_context: &mut NasContext,
        ue_context: &mut UeContext,
    ) -> Result<(), NasHandlerError> {
        todo!()

    }
 }
