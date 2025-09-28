use thiserror::Error;
use nas_models::TlvError;
use nas_models::message::NasRegistrationRequest;
use super::super::InvalidStateTransition;


#[derive(Error, Debug)]
pub enum RegistrationReqError {
    #[error(transparent)]
    InvalidState(#[from] InvalidStateTransition<NasRegistrationRequest>),
    #[error(transparent)]
    Tlv(#[from] TlvError),

}
