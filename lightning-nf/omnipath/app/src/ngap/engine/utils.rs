// use asn1_codecs::PerCodecError;
use asn1_per::{CodecDataAllocator, PerCodec, PerCodecError, SerDes, ThreeGppAsn1PerError};
use ngap_models::{
	Cause,
	CauseProtocol,
	CriticalityDiagnostics,
	ErrorIndication,
	NgapPdu,
	ToNgapPdu,
	convert_diagnostics_to_ie,
};

/// Attempts to encode an NGAP PDU payload and returns the encoded bytes.
///
/// # Arguments
/// * `data` - The NGAP PDU to encode
///
/// # Returns
/// * `Ok(Vec<u8>)` - Successfully encoded PDU
/// * `Err(ThreeGppAsn1PerError)` - Error encoding PDU.
pub fn codec_to_bytes<T: PerCodec>(data: &T) -> Result<Vec<u8>, ThreeGppAsn1PerError> {
	let mut d = T::Allocator::new_codec_data();
	data.encode(&mut d)?;
	Ok(d.into_bytes())
}

/// Attempts to decode an NGAP PDU payload and returns either the successfully
/// decoded PDU or an error indication PDU that should be sent back to the
/// sender along with decoding error information.
///
/// # Arguments
/// * `request` - The raw NGAP PDU bytes to decode
///
/// # Returns
/// * `Ok(NgapPdu)` - Successfully decoded PDU
/// * `Err((NgapPdu, PerCodecError))` - Error indication PDU to be sent back
///   along with the decoding error information.
pub fn decode_ngap_pdu(request: &[u8]) -> Result<NgapPdu, (NgapPdu, PerCodecError)> {
	match NgapPdu::from_bytes(request) {
		Ok(pdu) => Ok(pdu),
		Err(e) => {
			let (err, codec_error) = build_criticality_diagnostics(&request, e);
			Err((err.to_pdu(), codec_error))
		}
	}
}

/// Builds an error indication PDU with criticality diagnostics from a decoding
/// error.
///
/// # Arguments
/// * `request` - The raw NGAP PDU bytes to decode
/// * `error` - The decoding error
///
/// # Returns
/// * `(ErrorIndication, PerCodecError)` - Error indication PDU and decoding
///   error information.
pub fn build_criticality_diagnostics(
	request: &[u8],
	error: ThreeGppAsn1PerError,
) -> (ErrorIndication, PerCodecError) {
	let ThreeGppAsn1PerError {
		diagnostics,
		codec_error,
	} = error;
	let i_es_criticality_diagnostics = convert_diagnostics_to_ie(diagnostics);

	let (triggering_message, procedure_code, procedure_criticality) =
		NgapPdu::get_message_info(&request);

	let criticality_diagnostics = CriticalityDiagnostics {
		procedure_code,
		triggering_message,
		procedure_criticality,
		i_es_criticality_diagnostics,
	};

	let err = ErrorIndication {
		cause: Some(Cause::Protocol(
			CauseProtocol::AbstractSyntaxErrorFalselyConstructedMessage,
		)),
		criticality_diagnostics: Some(criticality_diagnostics),
		..Default::default()
	};

	(err, codec_error)
}
