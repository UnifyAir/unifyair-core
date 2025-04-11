use std::{error::Error, fmt::Debug, sync::Arc};

use ngap_models::{InitiatingMessage, NgapPdu};
use tracing::error;

use super::utils::new_semantic_error;
use crate::context::{GnbContext, NgapContext};
use crate::ngap::engine::{
	NgapFailure,
	NgapRequestHandler,
	NgapResponseError,
	// NgapResponseHandler,
	ToPdu,
};

/// Routes an incoming NGAP PDU to the appropriate handler based on its type.
///
/// This function serves as the primary entry point for processing NGAP messages
/// received from a gNB. It uses macros to dispatch the request to specific
/// handlers (`handle_request`, `handle_success_response`,
/// `handle_failure_response`) based on whether the PDU is an
/// `InitiatingMessage`, `SuccessfulOutcome`, or `UnsuccessfulOutcome`.
///
/// Currently, it only explicitly handles `InitiatingMessage::InitialUeMessage`.
/// Other PDU types will result in a generic semantic error response.
///
/// # Arguments
///
/// * `gnb_context` - An `Arc`-wrapped `GnbContext` representing the state of
///   the gNB associated with this message.
/// * `request` - The incoming `NgapPdu` to be processed.
///
/// # Returns
///
/// An `Option<NgapPdu>` containing the response PDU if one is generated, or
/// `None` if the handler does not produce a direct response or an error occurs
/// during conversion.
impl NgapContext {
	pub async fn ngap_route(
		&self,
		gnb_context: Arc<GnbContext>,
		request: NgapPdu,
	) -> Option<NgapPdu> {
		macro_rules! match_ue_pdu {
            ($msg:expr, InitiatingMessage, $($variant:ident),*) => {
                match $msg {
                    $(
                        InitiatingMessage::$variant(pdu) => {
                            let resp = self.handle_request(gnb_context, pdu).await;
                            log_and_convert_to_pdu(resp)
                        },
                    )*
                    _ => new_semantic_error(None, None).to_pdu(),
                }
            };
            ($msg:expr, SuccessfulOutcome, $($variant:ident),*) => {
                match $msg {
                    $(
                        SuccessfulOutcome::$variant(pdu) => {
                            let resp = self.handle_success_response(gnb_context, pdu).await;
                            log_and_convert_to_pdu(resp)
                        },
                    )*
                    _ => new_semantic_error(None, None).to_pdu(),
                }
            };
            ($msg:expr, UnsuccessfulOutcome, $($variant:ident),*) => {
                match $msg {
                    $(
                        UnsuccessfulOutcome::$variant(pdu) => {
                            let resp = self.handle_failure_response(gnb_context, pdu).await;
                            log_and_convert_to_pdu(resp)
                        },
                    )*
                    _ => new_semantic_error(None, None).to_pdu(),
                }
            };
        }

		match request {
			NgapPdu::InitiatingMessage(initiating_message) => {
				match_ue_pdu!(initiating_message, InitiatingMessage, InitialUeMessage)
			}
			_ => new_semantic_error(None, None).to_pdu(),
		}
	}
}

fn log_and_convert_to_pdu<T, F, E>(result: Result<T, NgapResponseError<F, E>>) -> Option<NgapPdu>
where
	T: ToPdu,
	F: ToPdu + Debug,
	E: Error + Debug,
{
	match result {
		Ok(resp) => resp.to_pdu(),
		Err(NgapResponseError { failure, error }) => {
			error!("Error handling InitialUeMessage: {:?}", error);
			match failure {
				NgapFailure::Failure(failure) => failure.to_pdu(),
				NgapFailure::GenericError(error) => error.to_pdu(),
			}
		}
	}
}
