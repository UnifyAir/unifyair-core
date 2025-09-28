use std::{
	fmt, ops::Deref, sync::atomic::{AtomicUsize, Ordering}
};

use super::GmmState;

/// A custom atomic wrapper for GmmState that performs operations directly on
/// the enum's discriminant to avoid the potential overhead of `match`
/// statements.
///
/// The safety of the `unsafe` transmutation relies on the invariant that this
/// struct only ever stores values that are valid `GmmState` discriminants.
#[derive(Debug)]
pub struct AtomicGmmState {
	state: AtomicUsize,
}

impl AtomicGmmState {
	/// Creates a new AtomicGmmState with the given initial state.
	pub const fn new(initial_state: GmmState) -> Self {
		Self {
			state: AtomicUsize::new(initial_state as usize),
		}
	}

	/// Loads the current state using `std::mem::transmute`.
	#[inline]
	pub fn load(
		&self,
		ordering: Ordering,
	) -> GmmState {
		let discriminant = self.state.load(ordering);
		// This assertion ensures that, in debug builds, we panic if the state
		// ever holds an invalid discriminant, which would be undefined behavior.
		debug_assert!(
			discriminant <= GmmState::MAX_DISCRIMINANT as usize,
			"Invalid GmmState discriminant: {}",
			discriminant
		);
		// Safety: The `debug_assert` and disciplined use of the `store` methods
		// ensure that `state` only contains valid discriminants for `GmmState`.
		// `GmmState` is `#[repr(u8)]`, so transmutation from its discriminant is sound.
		unsafe { std::mem::transmute(discriminant as u8) }
	}

	/// Stores a new state.
	#[inline]
	pub fn store(
		&self,
		new_state: GmmState,
		ordering: Ordering,
	) {
		self.state.store(new_state as usize, ordering);
	}

	/// Atomically swaps the state and returns the previous state.
	#[inline]
	pub fn swap(
		&self,
		new_state: GmmState,
		ordering: Ordering,
	) -> GmmState {
		let old_discriminant = self.state.swap(new_state as usize, ordering);
		debug_assert!(
			old_discriminant <= GmmState::MAX_DISCRIMINANT as usize,
			"Invalid GmmState discriminant: {}",
			old_discriminant
		);
		// Safety: Same justification as `load`.
		unsafe { std::mem::transmute(old_discriminant as u8) }
	}

	/// A helper function to reduce code duplication in `compare_exchange`
	/// methods.
	#[inline]
	fn transmute_result(result: Result<usize, usize>) -> Result<GmmState, GmmState> {
		match result {
			Ok(prev) => {
				debug_assert!(prev <= GmmState::MAX_DISCRIMINANT as usize);
				Ok(unsafe { std::mem::transmute(prev as u8) })
			}
			Err(actual) => {
				debug_assert!(actual <= GmmState::MAX_DISCRIMINANT as usize);
				Err(unsafe { std::mem::transmute(actual as u8) })
			}
		}
	}

	/// Atomically compares the current state with `current` and, if they match,
	/// replaces it with `new`.
	#[inline]
	pub fn compare_exchange(
		&self,
		current: GmmState,
		new: GmmState,
		success: Ordering,
		failure: Ordering,
	) -> Result<GmmState, GmmState> {
		let result = self
			.state
			.compare_exchange(current as usize, new as usize, success, failure);
		Self::transmute_result(result)
	}

	/// Performs a weak compare-and-exchange operation.
	#[inline]
	pub fn compare_exchange_weak(
		&self,
		current: GmmState,
		new: GmmState,
		success: Ordering,
		failure: Ordering,
	) -> Result<GmmState, GmmState> {
		let result =
			self.state
				.compare_exchange_weak(current as usize, new as usize, success, failure);
		Self::transmute_result(result)
	}

	/// Atomically modifies the state with a given function.
	#[inline]
	pub fn fetch_update<F>(
		&self,
		set_order: Ordering,
		fetch_order: Ordering,
		mut f: F,
	) -> Result<GmmState, GmmState>
	where
		F: FnMut(GmmState) -> Option<GmmState>,
	{
		let result = self
			.state
			.fetch_update(set_order, fetch_order, |discriminant| {
				debug_assert!(discriminant <= GmmState::MAX_DISCRIMINANT as usize);
				// Safety: Same justification as `load`.
				let current_state = unsafe { std::mem::transmute(discriminant as u8) };
				f(current_state).map(|new_state| new_state as usize)
			});
		Self::transmute_result(result)
	}

	// --- Convenience Methods ---

	/// Gets the current state using `Acquire` ordering.
	#[inline]
	pub fn get(&self) -> GmmState {
		self.load(Ordering::Acquire)
	}

	/// Sets the current state using `Release` ordering.
	#[inline]
	pub fn set(
		&self,
		state: GmmState,
	) {
		self.store(state, Ordering::Release);
	}

	/// Checks if the current state matches the given state.
	#[inline]
	pub fn is(
		&self,
		expected: GmmState,
	) -> bool {
		self.get() == expected
	}

	/// Checks if the UE can access services in the current state.
	#[inline]
	pub fn can_access_services(&self) -> bool {
		self.get().can_access_services()
	}

	/// Checks if the current state is transitional.
	#[inline]
	pub fn is_transitional(&self) -> bool {
		self.get().is_transitional()
	}

}

impl Default for AtomicGmmState {
	fn default() -> Self {
		Self::new(GmmState::default())
	}
}

impl Deref for AtomicGmmState {
	type Target = AtomicUsize;

	fn deref(&self) -> &Self::Target {
		&self.state	
	}
}

impl Clone for AtomicGmmState {
	/// Clones the `AtomicGmmState` by creating a new atomic variable
	/// initialized with the current state's value.
	fn clone(&self) -> Self {
		Self::new(self.get())
	}
}

impl From<GmmState> for AtomicGmmState {
	fn from(state: GmmState) -> Self {
		Self::new(state)
	}
}

impl fmt::Display for AtomicGmmState {
	fn fmt(
		&self,
		f: &mut fmt::Formatter<'_>,
	) -> fmt::Result {
		// Delegate formatting to the underlying GmmState's Debug or Display impl.
		write!(f, "{:?}", self.get())
	}
}
