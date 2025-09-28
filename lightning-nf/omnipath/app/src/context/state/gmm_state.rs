use std::{
	fmt::{Debug, Display},
};

/// 5G Mobility Management (GMM) State Machine - Top Level States Only
#[repr(u8)]
#[derive(Eq, PartialEq, Hash)]
pub enum GmmState {
	/// UE is not registered with the network
	Deregistered = 0,

	/// Deregistration procedure has been initiated
	DeregistrationInitiated = 1,

	/// Registration procedure has been initiated
	RegistrationInitiated = 2,

	/// UE is in authentication phase
	Unauthenticated = 3,

	/// UE has been successfully authenticated
	Authenticated = 4,

	/// Security mode procedures have been completed
	SecurityModeDone = 5,

	/// UE is fully registered and can access services
	Registered = 6,

	/// Common procedure initiated (service mode, other procedures)
	CommonProcedureInitiated = 7,

	/// An irrecoverable error has occurred, requiring cleanup.
	Irrecoverable = 8,
}

impl GmmState {
	pub const MAX_DISCRIMINANT: u8 = GmmState::Irrecoverable as u8;

	/// Convert to integer value
	pub const fn to_u8(self) -> u8 {
		self as u8
	}

	/// Convert from integer value
	pub const fn from_u8(value: u8) -> Option<Self> {
		match value {
			0 => Some(Self::Deregistered),
			1 => Some(Self::DeregistrationInitiated),
			2 => Some(Self::RegistrationInitiated),
			3 => Some(Self::Unauthenticated),
			4 => Some(Self::Authenticated),
			5 => Some(Self::SecurityModeDone),
			6 => Some(Self::Registered),
			7 => Some(Self::CommonProcedureInitiated),
			8 => Some(Self::Irrecoverable),
			_ => None,
		}
	}

	/// Get a human-readable description of the state
	pub fn description(&self) -> &'static str {
		match self {
			GmmState::Deregistered => "UE is deregistered from the 5G network",
			GmmState::DeregistrationInitiated => "Deregistration procedure initiated",
			GmmState::RegistrationInitiated => "Registration procedure initiated",
			GmmState::Unauthenticated => "UE is undergoing authentication procedures",
			GmmState::Authenticated => "UE has been successfully authenticated",
			GmmState::SecurityModeDone => "Security mode procedures completed",
			GmmState::Registered => "UE is registered and can access 5G services",
			GmmState::CommonProcedureInitiated => "Common procedure (service mode, etc.) initiated",
			GmmState::Irrecoverable => "An irrecoverable error occurred; cleanup required",
		}
	}

	/// Check if the UE can initiate services in this state
	pub fn can_access_services(&self) -> bool {
		matches!(self, GmmState::Registered)
	}

	/// Check if this is a transitional state (temporary during procedures)
	pub fn is_transitional(&self) -> bool {
		matches!(
			self,
			GmmState::DeregistrationInitiated
				| GmmState::RegistrationInitiated
				| GmmState::Unauthenticated
				| GmmState::Authenticated
				| GmmState::SecurityModeDone
				| GmmState::CommonProcedureInitiated
		)
	}

	/// Get the next expected state in the registration flow
	pub fn next_state(&self) -> Option<Self> {
		match self {
			GmmState::Deregistered => Some(GmmState::RegistrationInitiated),
			GmmState::DeregistrationInitiated => Some(GmmState::Deregistered),
			GmmState::RegistrationInitiated => Some(GmmState::Unauthenticated),
			GmmState::Unauthenticated => Some(GmmState::Authenticated),
			GmmState::Authenticated => Some(GmmState::SecurityModeDone),
			GmmState::SecurityModeDone => Some(GmmState::Registered),
			GmmState::Registered => None, // Final state or can go to CommonProcedureInitiated
			GmmState::CommonProcedureInitiated => Some(GmmState::Registered), // Usually returns to Registered */
			GmmState::Irrecoverable => None,
		}
	}

	/// Check if transition to target state is valid
	pub fn can_transition_to(
		&self,
		target: Self,
	) -> bool {
		match (self, target) {
			// Any state can transition to Irrecoverable
			(_, GmmState::Irrecoverable) => true,
			// Cannot transition from Irrecoverable
			(GmmState::Irrecoverable, _) => false,

			// Forward registration transitions
			(GmmState::Deregistered, GmmState::RegistrationInitiated) => true,
			(GmmState::RegistrationInitiated, GmmState::Unauthenticated) => true,
			(GmmState::Unauthenticated, GmmState::Authenticated) => true,
			(GmmState::Authenticated, GmmState::SecurityModeDone) => true,
			(GmmState::SecurityModeDone, GmmState::Registered) => true,

			// Deregistration flow
			(GmmState::Registered, GmmState::DeregistrationInitiated) => true,
			(GmmState::DeregistrationInitiated, GmmState::Deregistered) => true,

			// Common procedure transitions
			(GmmState::Registered, GmmState::CommonProcedureInitiated) => true,
			(GmmState::CommonProcedureInitiated, GmmState::Registered) => true,

			// Failure transitions - can always go back to deregistered
			(_, GmmState::Deregistered) => true,

			// Stay in same state
			(state, target) if state == &target => true,

			// Invalid transitions
			_ => false,
		}
	}
}

impl Default for GmmState {
	fn default() -> Self {
		GmmState::Deregistered
	}
}

impl From<GmmState> for u8 {
	fn from(state: GmmState) -> Self {
		state.to_u8()
	}
}

impl TryFrom<u8> for GmmState {
	type Error = ();

	fn try_from(value: u8) -> Result<Self, Self::Error> {
		Self::from_u8(value).ok_or(())
	}
}

impl Display for GmmState {
	fn fmt(
		&self,
		f: &mut std::fmt::Formatter<'_>,
	) -> std::fmt::Result {
		let name = match self {
			GmmState::Deregistered => "GMM-DEREGISTERED",
			GmmState::DeregistrationInitiated => "GMM-DEREGISTRATION-INITIATED",
			GmmState::RegistrationInitiated => "GMM-REGISTRATION-INITIATED",
			GmmState::Unauthenticated => "GMM-UNAUTHENTICATED",
			GmmState::Authenticated => "GMM-AUTHENTICATED",
			GmmState::SecurityModeDone => "GMM-SECURITY-MODE-DONE",
			GmmState::Registered => "GMM-REGISTERED",
			GmmState::CommonProcedureInitiated => "GMM-COMMON-PROCEDURE-INITIATED",
			GmmState::Irrecoverable => "GMM-IRRECOVERABLE",
		};
		write!(f, "{}", name)
	}
}

impl Debug for GmmState {
	fn fmt(
		&self,
		f: &mut std::fmt::Formatter<'_>,
	) -> std::fmt::Result {
		Display::fmt(self, f)
	}
}
