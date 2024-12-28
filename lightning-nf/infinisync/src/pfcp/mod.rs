// use pfcp::{
// 	PfcpHeader,
// 	ie::Cause,
// 	message::{PfcpAssociationSetupRequest, PfcpAssociationSetupResponse},
// };
// use thiserror::Error;
//
// #[derive(Error, Debug)]
// pub enum PfcpHandlerError {}
//
// pub fn association_setup_request_handler(
// 	header: PfcpHeader,
// 	req: PfcpAssociationSetupRequest,
// ) -> Result<(Cause, PfcpAssociationSetupResponse), PfcpHandlerError> {
// 	Ok((
// 		Cause::RequestAccepted,
// 		PfcpAssociationSetupResponse::default(),
// 	))
// }
