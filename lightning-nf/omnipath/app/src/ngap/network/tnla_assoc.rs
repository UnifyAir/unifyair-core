use std::{
	hash::{Hash, Hasher},
	net::SocketAddr,
};

use bytes::{Bytes, BytesMut};
use counter::CounterUsize;
use tokio_sctp::{SctpStream, SendOptions};

use super::TnlaError;

const READ_BUFFER_SIZE: usize = 1024;
const NGAP_PPID: u32 = 60;
const _NGAP_DTLS_PPID: u32 = 66;

// Add a static atomic counter for generating unique IDs
static TNLA_ASSOCIATION_COUNTER: CounterUsize = CounterUsize::new();

#[derive(Debug)]
pub struct TnlaAssociation {
	pub id: usize, // New field for unique ID
	pub local_addr: SocketAddr,
	pub remote_addr: SocketAddr,
	pub stream: SctpStream,
}

impl Hash for TnlaAssociation {
	fn hash<H: Hasher>(
		&self,
		state: &mut H,
	) {
		self.id.hash(state); // Update to use ID for hashing
	}
}

impl PartialEq for TnlaAssociation {
	fn eq(
		&self,
		other: &Self,
	) -> bool {
		self.id == other.id // Update to compare IDs
	}
}

impl Eq for TnlaAssociation {}

impl TnlaAssociation {
	pub fn new(stream: SctpStream) -> Result<Self, TnlaError> {
		// Get local address
		let local_addr = stream.local_addr().map_err(TnlaError::LocalAddressError)?;

		// Get remote address
		let remote_addr = stream.peer_addr().map_err(TnlaError::RemoteAddressError)?;

		// Generate a unique ID using the atomic counter
		let id = TNLA_ASSOCIATION_COUNTER.increment();

		Ok(Self {
			id,
			local_addr,
			remote_addr,
			stream,
		})
	}

	/// Reads data from the SCTP stream asynchronously.
	/// 
	/// # Returns
	/// - `Ok(Some(Bytes))` - Successfully read data from the stream
	/// - `Ok(None)` - Stream has been closed by the peer (received EOF)
	/// - `Err(TnlaError)` - An error occurred while reading from the stream
	/// 
	/// When this function returns `Ok(None)`, it indicates that the peer has closed their
	/// end of the socket gracefully. The caller should handle this case by closing the
	/// local socket and cleaning up any associated resources.
	pub async fn read_data(&self) -> Result<Option<Bytes>, TnlaError> {
		let mut buf = BytesMut::with_capacity(READ_BUFFER_SIZE);
		let (n, _, _) = self.stream
			.recvmsg_eor_buf(&mut buf)
			.await
			.map_err(TnlaError::ReadError)?;
		if n == 0 {
			Ok(None)
		} else {
			let data = buf.freeze();
			Ok(Some(data))
		}
	}

	pub async fn write_data(
		&self,
		data: Bytes,
		send_options: Option<SendOptions>,
	) -> Result<(), TnlaError> {
		// TODO: Add handling for the stream no. here for load balancing
		let mut send_options = send_options.unwrap_or_default();
		send_options.ppid = NGAP_PPID;
		let _n = self
			.stream
			.sendmsg(data.as_ref(), None, &send_options)
			.await
			.map_err(TnlaError::WriteError)?;
		// TODO: Handle the case where the number of bytes written is not equal to the
		// message size
		Ok(())
	}
}
