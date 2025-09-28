use std::{cell::UnsafeCell, ops::Deref, sync::Arc};

pub struct SeqLock<T> {
	data: UnsafeCell<T>,
}

unsafe impl<T: Send> Send for SeqLock<T> {}
unsafe impl<T: Send> Sync for SeqLock<T> {}

impl<T> SeqLock<T> {
	pub fn new(data: T) -> Self {
		Self {
			data: UnsafeCell::new(data),
		}
	}

	pub unsafe fn get_mut(&self) -> &mut T {
		// SAFETY: Context manager ensures only one future accesses this at a time
		unsafe { &mut *self.data.get() }
	}

	pub unsafe fn get(&self) -> &T {
		// SAFETY: Same as above
		unsafe { &*self.data.get() }
	}

	pub unsafe fn into_inner(self) -> T {
		self.data.into_inner()
	}

}

