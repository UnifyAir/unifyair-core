use std::sync::Arc;

use asn1_per::{PerCodecError, ThreeGppAsn1PerError};
use ngap_models::{Cause, CauseProtocol, ErrorIndication, InitiatingMessage, NgapPdu, ToNgapPdu};
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, error, info};
use valuable::Valuable;

use super::{
	decode_ngap_pdu,
	interfaces::{NgapRequestHandler, NgapResponseError},
	utils::codec_to_bytes,
};
use crate::{
	context::{GnbContext, NgapContext},
	ngap::{
		constants::app::INITIALIZATION_RETRIES,
		core::ng_setup::NgSetupError,
		network::{NetworkError, TnlaAssociation},
	},
};

impl NgapContext {
	pub async fn run(
		self: Arc<Self>,
		cancel: CancellationToken,
	) -> Result<(), NetworkError> {
		loop {
			tokio::select! {
			biased;

			res = self.network.accept_and_create_tnla(cancel.clone()) => {
				match res {
					Ok(tnla) => {
						let self_clone = self.clone();
						let tnla_clone = tnla.clone();
						tokio::spawn(async move {
							self_clone.start_ngap_processing(tnla_clone).await;
						}.instrument(
							tracing::trace_span!("ngap_connection", id = tnla.id.as_value()),
						));
					}
					Err(e) => error!("Error accepting connection: {:?}", e),
				}
			}

			_ = cancel.cancelled() => {
				info!("Cancellation requested, stopped accepting ran connections");
				break;
			}}
		}

		self.graceful_shutdown().await?;
		Ok(())
	}

	/// Initiates NGAP processing for a new TNLA (Transport Network Layer
	/// Association) connection.
	///
	/// This function performs the following steps:
	/// 1. Attempts to establish an NG setup connection with retries
	/// 2. Creates and stores a new gNB context if setup is successful
	/// 3. Spawns a new task to handle ongoing NGAP message processing
	///
	/// # Arguments
	/// * `self` - Arc reference to NgapContext
	/// * `tnla` - Arc reference to the TNLA connection
	pub async fn start_ngap_processing(
		self: Arc<Self>,
		tnla: Arc<TnlaAssociation>,
	) {
		let sctp_loop_cancellation = CancellationToken::new();

		// Try to establish NG setup request
		let gnb_context = match self
			.try_ng_setup_with_retries(tnla, sctp_loop_cancellation.clone())
			.await
		{
			Some(context) => Arc::new(context),
			None => {
				error!(
					"Failed to establish NG setup after {} retries",
					INITIALIZATION_RETRIES
				);
				return;
			}
		};

		// Safety: We can safely unwrap here because:
		// 1. Duplicate gNB connections are already handled during the NG setup process
		// 2. The SccHashMap insert_async only fails if the key already exists
		// 3. The gNB context's global_ran_node_id uniqueness is validated during setup
		self.gnb_contexts
			.insert_async(gnb_context.global_ran_node_id.clone(), gnb_context.clone())
			.await
			.unwrap();

		info!(
			global_ran_node_id = gnb_context.global_ran_node_id.as_value(),
			diagnostic = "Set up RAN Complete"
		);
		// Spawn NGAP processing loop
		let gnb_context_clone = gnb_context.clone();
		let self_clone = self.clone();
		tokio::spawn(
			async move {
				let res = self_clone.run_ngap_loop(gnb_context.clone()).await;
				let _ = res.map_err(|e| error!(diagnostic = "Error running NGAP loop", error = ?e));
				// TODO: Implement cleanup logic for gNB context and UE contexts
			}
			.instrument(tracing::trace_span!(
				"ngap_request",
				id = gnb_context_clone.global_ran_node_id.as_value()
			)),
		);
	}

	/// Attempts to establish an NG setup connection with multiple retries.
	///
	/// # Arguments
	/// * `tnla` - Arc reference to the TNLA connection
	/// * `cancellation` - Token for cancelling the setup process
	///
	/// # Returns
	/// * `Option<GnbContext>` - Some(context) if setup succeeds, None if all
	///   retries fail
	///
	/// Retries the NG setup process up to INITIALIZATION_RETRIES times before
	/// giving up.
	async fn try_ng_setup_with_retries(
		&self,
		tnla: Arc<TnlaAssociation>,
		cancellation: CancellationToken,
	) -> Option<GnbContext> {
		for attempt in 1..=INITIALIZATION_RETRIES {
			match self.try_ng_setup(tnla.clone(), cancellation.clone()).await {
				Ok(context) => return Some(context),
				Err(e) => {
					error!(
						diagnostic = "NG Setup attempt failed",
						attempt = attempt,
						error = ?e
					);
				}
			}
		}
		None
	}

	/// Performs a single attempt at establishing an NG setup connection.
	///
	/// This function:
	/// 1. Creates a new GnbContext
	/// 2. Reads and decodes the initial NGAP PDU
	/// 3. Handles the NG setup request if received
	/// 4. Sends appropriate response back to the gNB
	///
	/// # Arguments
	/// * `tnla` - Arc reference to the TNLA connection
	/// * `cancellation` - Token for cancelling the setup process
	///
	/// # Returns
	/// * `Result<GnbContext, NgapSetupError>` - Success with context or
	///   detailed error
	///
	/// # Errors
	/// Returns NgapSetupError for various failure scenarios:
	/// - Network communication errors
	/// - PDU encoding/decoding errors
	/// - Invalid or unexpected messages
	/// - NG setup protocol errors
	pub async fn try_ng_setup(
		&self,
		tnla: Arc<TnlaAssociation>,
		cancellation: CancellationToken,
	) -> Result<GnbContext, NgapSetupError> {
		let mut gnb_context = GnbContext::new(tnla.clone(), cancellation);
		let request = gnb_context
			.tnla_association
			.read_data()
			.await
			.map_err(|e| NetworkError::TnlaReadError(tnla.id, e))?;
		let request = match request {
			Some(request) => request,
			None => return Err(NgapSetupError::SocketClosed),
		};
		let request = decode_ngap_pdu(&request);
		let result;
		let response = match request {
			Ok(NgapPdu::InitiatingMessage(InitiatingMessage::NgSetupRequest(ng_setup_request))) => {
				let ngap_resp = self
					.handle_request(&mut gnb_context, ng_setup_request)
					.await;
				match ngap_resp {
					Ok(success) => {
						result = Ok(gnb_context);
						success.to_pdu()
					}
					Err(error) => {
						let NgapResponseError { failure, error } = error;
						result = Err(NgapSetupError::NgSetupError(error));
						failure.to_pdu()
					}
				}
			}
			Err((e, err)) => {
				result = Err(NgapSetupError::PerCodecEncodingError(err));
				e
			}
			Ok(request) => {
				result = Err(NgapSetupError::DidNotReceiveNgSetup(request));
				ErrorIndication {
					cause: Some(Cause::Protocol(
						CauseProtocol::MessageNotCompatibleWithReceiverState,
					)),
					..Default::default()
				}
				.to_pdu()
			}
		};
		encode_and_write_ngap_pdu(tnla.as_ref(), response).await?;
		result
	}

	/// Runs the main NGAP (NG Application Protocol) processing loop for a
	/// specific gNB (gNodeB) connection.
	///
	/// This function handles the continuous processing of NGAP messages from a
	/// connected gNB by:
	/// 1. Reading incoming NGAP messages from the TNLA (Transport Network Layer
	///    Association)
	/// 2. Spawning a new task for each message to handle processing
	///    asynchronously
	/// 3. Decoding the NGAP PDU (Protocol Data Unit)
	/// 4. Routing the message to appropriate handlers and getting a response
	/// 5. Encoding and sending back any response messages
	///
	/// # Arguments
	/// * `self` - Arc reference to NgapContext for shared access
	/// * `gnb_context` - Arc reference to the GnbContext containing the gNB
	///   connection state
	///
	/// # Returns
	/// * `Result<(), NetworkError>` - Ok(()) if loop terminates normally, or
	///   NetworkError on failure
	///
	/// The function continues running until the TNLA connection is closed or
	/// encounters an error. Each message is processed in its own task to allow
	/// concurrent handling of multiple messages.
	pub async fn run_ngap_loop(
		self: Arc<Self>,
		gnb_context: Arc<GnbContext>,
	) -> Result<(), NetworkError> {
		while let Ok(Some(message)) = gnb_context.tnla_association.read_data().await {
			let gnb_context_clone = gnb_context.clone();
			let self_clone = self.clone();
			tokio::spawn(async move {
				let pdu = decode_ngap_pdu(&message);
				let response = match pdu {
					Ok(pdu) => self_clone.ngap_route(gnb_context_clone.clone(), pdu).await,
					Err((pdu, error)) => {
						error!(diagnostic = "Error decoding NGAP PDU", error = ?error);
						Some(pdu)
					}
				};
				if let Some(response) = response {
					let resp = encode_and_write_ngap_pdu(
						&gnb_context_clone.as_ref().tnla_association,
						response,
					)
					.await;
					match resp {
						Ok(_) => (),
						Err(e) => {
							// TODO: Add valuable trait implementation for having structured records
							// of struct for tracing. https://docs.rs/tracing/latest/tracing/field/index.html#using-valuable
							error!(diagnostic = "Ngap write error", error = ?e)
						}
					}
				}
			});
		}
		Ok(())
	}

	// TODO: Implement graceful shutdown for the network
	pub async fn graceful_shutdown(&self) -> Result<(), NetworkError> {
		Ok(())
	}
}

/// Encodes and writes an NGAP PDU to the specified TNLA connection.
///
/// # Arguments
/// * `tnla` - Reference to the TNLA connection
/// * `pdu` - The NGAP PDU to encode and send
///
/// # Returns
/// * `Result<(), NgapWriteError>` - Success or error during encoding/writing
///
/// # Errors
/// - NetworkError: If writing to the TNLA fails
/// - EncodingError: If PDU encoding fails (these are logged but not propagated)
pub async fn encode_and_write_ngap_pdu(
	tnla: &TnlaAssociation,
	pdu: NgapPdu,
) -> Result<(), NgapWriteError> {
	match codec_to_bytes(&pdu) {
		Ok(bytes) => tnla
			.write_data(bytes.into(), None)
			.await
			.map_err(|err| NgapWriteError::NetworkError(NetworkError::TnlaSendError(tnla.id, err))),
		Err(e) => Err(NgapWriteError::EncodingError(e)),
	}
}

#[derive(Debug, Error)]
pub enum NgapWriteError {
	#[error("Network Error")]
	NetworkError(#[from] NetworkError),

	#[error("EncodingError")]
	EncodingError(#[from] ThreeGppAsn1PerError),
}

#[derive(Debug, Error)]
pub enum NgapSetupError {
	#[error("Network Error")]
	NetworkError(#[from] NetworkError),

	#[error("PerCodecEncodingError")]
	PerCodecEncodingError(#[source] PerCodecError),

	#[error("PerCodecDecodingError")]
	PerCodecDecodingError(#[source] PerCodecError),

	#[error("WriteError")]
	WriteError(#[from] NgapWriteError),

	#[error("Did not receive NgSetup Request: {0:?}")]
	DidNotReceiveNgSetup(NgapPdu),

	#[error("NgSetup Error")]
	NgSetupError(#[from] NgSetupError),

	#[error("SocketClosed")]
	SocketClosed,
}
