
use thiserror::Error;
use nas_models::types::FiveGmmCause;

#[derive(Error, Debug)]
pub enum NasHandlerError {
    #[error("Invalid NAS PDU: length is less than 2")]
    InvalidNasPdu,
    #[error("Parsing Error: Corrupted message payload, message type not present")]
    UnableToParseNasMessage,
    #[error("Parsing Error: Unknown Nas message type")]
    UnknownNasMessageType,
    #[error("Unknown error occurred")]
    UnknownError,
    #[error("FivegmmCauseError occured")]
    FiveGmmCauseError(FiveGmmCause),
}


