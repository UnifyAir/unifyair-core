#![feature(error_generic_member_access)]

use std::{backtrace::Backtrace, net::SocketAddrV4};

use thiserror::Error;

use crate::{config::InfiniSyncConfig, sbi::start_server};

pub async fn run(config: InfiniSyncConfig) -> Result<(), InfiniSyncError> {
	let mut ip_addr = config.configuration.sbi.binding_ip_v4;
	let port = config.configuration.sbi.port;
	let server_addr = SocketAddrV4::new(ip_addr, port);
	start_server(server_addr.into()).await?;
	Ok(())
}

pub mod config;
mod net_gateways;
pub mod pfcp;
pub mod sbi;

#[derive(Error, Debug)]
pub enum InfiniSyncError {
	#[error("Io Error")]
	IoError(#[from] std::io::Error, #[backtrace] Backtrace),
}
