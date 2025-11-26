use std::{future::Future, sync::Arc};

use crate::context::UeContext;
use nas_context::NasContext;
use error::NasHandlerError;


pub mod nas_context;
mod handlers;
mod error;
mod gmm;
mod builders;
mod ue_actions;


pub trait NasHandler {
    fn handle(
        &self,
        nas_context: &mut NasContext,
        ue_context: &mut UeContext,
    ) -> impl Future<Output = Result<(), NasHandlerError>> + Send;
}


pub trait NasBuilder: Sized {
    fn build(
        nas_context: &NasContext,
        ue_context: &UeContext,
    ) -> Result<Self, NasHandlerError>;
}



