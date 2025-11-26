use std::{
	marker::PhantomData, ops::Deref, sync::{
		atomic::{AtomicUsize, Ordering}, Arc
	}
};


/// Trait that types must implement to be used with AtomicHandle.
/// The generic parameter `Field` allows the same type to implement
/// this trait multiple times for different atomic fields.
pub trait AtomicOperation<Field = ()> {
	/// Returns a reference to the atomic field identified by the Field type
	/// parameter
	fn get_atomic(&self) -> &AtomicUsize;
}

/// A handle that provides safe shared access to an AtomicUsize field within an
/// Arc-managed struct.
///
/// The `Field` type parameter is used to distinguish between different atomic
/// fields in the same struct using zero-sized marker types.
///
/// # Type Parameters
/// * `S` - The struct type that contains the atomic field
/// * `Field` - A marker type to identify which atomic field this handle
///   accesses
///
/// # Safety
/// This struct maintains a raw pointer to the atomic field but keeps the
/// original Arc alive, ensuring the memory remains valid for the lifetime of
/// the handle.
pub struct AtomicHandle<S, Field = ()>
where
	S: AtomicOperation<Field> + Send + Sync ,
{
	/// Keeps the original Arc<S> alive to prevent memory deallocation
	_owner: Arc<S>,
	/// Raw pointer to the specific atomic field within the struct
	atomic_ptr: *const AtomicUsize,
	/// Zero-sized marker to track which field this handle represents
	_phantom: PhantomData<Field>,
}

// Safety: AtomicHandle is Send because:
// - Arc<S> is Send when S: Send + Sync
// - The raw pointer points to memory kept alive by the Arc
// - AtomicUsize operations are thread-safe
unsafe impl<S, Field> Send for AtomicHandle<S, Field> where S: AtomicOperation<Field> + Send + Sync {}

// Safety: AtomicHandle is Sync because:
// - Arc<S> is Sync when S: Send + Sync
// - The atomic operations are inherently thread-safe
// - Multiple threads can safely share references to this handle
unsafe impl<S, Field> Sync for AtomicHandle<S, Field> where S: AtomicOperation<Field> + Send + Sync {}

impl<S, Field> AtomicHandle<S, Field>
where
	S: AtomicOperation<Field> + Send + Sync,
{
	/// Creates a new AtomicHandle for the specified field in the given Arc<S>.
	///
	/// # Arguments
	/// * `owner` - The Arc<S> containing the atomic field
	///
	/// # Returns
	/// A new AtomicHandle that provides access to the atomic field
	///
	/// # Example
	/// ```
	/// # use std::sync::{Arc, atomic::AtomicUsize};
	/// # use std::marker::PhantomData;
    /// # use std::ops::Deref;
	/// # pub trait AtomicOperation<Field = ()> {
	/// # 	fn get_atomic(&self) -> &AtomicUsize;
	/// # }
	/// # pub struct AtomicHandle<S, Field = ()> where S: AtomicOperation<Field> + Send + Sync {
	/// # 	_owner: Arc<S>,
	/// # 	atomic_ptr: *const AtomicUsize,
	/// # 	_phantom: PhantomData<Field>,
	/// # }
	/// # impl<S, Field> AtomicHandle<S, Field> where S: AtomicOperation<Field> + Send + Sync {
	/// # 	pub fn new(owner: Arc<S>) -> Self {
	/// # 		let atomic_ptr = owner.get_atomic() as *const AtomicUsize;
	/// # 		Self { _owner: owner, atomic_ptr, _phantom: PhantomData }
	/// # 	}
	/// # }
	/// # struct Counter;
	/// # struct MyStruct { counter: AtomicUsize }
	/// # impl AtomicOperation<Counter> for MyStruct {
	/// #     fn get_atomic(&self) -> &AtomicUsize { &self.counter }
	/// # }
	/// let my_struct = Arc::new(MyStruct { counter: AtomicUsize::new(0) });
	/// let handle: AtomicHandle<MyStruct, Counter> = AtomicHandle::new(my_struct);
	/// ```
	pub fn new(owner: Arc<S>) -> Self {
		let atomic_ptr = owner.get_atomic() as *const AtomicUsize;
		Self {
			_owner: owner,
			atomic_ptr,
			_phantom: PhantomData,
		}
	}

	/// Returns a reference to the underlying AtomicUsize.
	///
	/// This is safe because the Arc is kept alive for the lifetime of this
	/// handle.
	pub fn get(&self) -> &AtomicUsize {
		unsafe { &*self.atomic_ptr }
	}
	
}

impl<S, Field> Deref for AtomicHandle<S, Field> 
where
	S: AtomicOperation<Field> + Send + Sync,
{
	type Target = AtomicUsize;

	fn deref(&self) -> &Self::Target {
		self.get()	
	}
}

// Manual implementation of Clone.
impl<S, Field> Clone for AtomicHandle<S, Field>
where
    S: AtomicOperation<Field> + Send + Sync,
{
    fn clone(&self) -> Self {
        Self {
            _owner: Arc::clone(&self._owner),
            atomic_ptr: self.atomic_ptr,
            _phantom: PhantomData,
        }
    }
}

impl<S, Field> std::fmt::Debug for AtomicHandle<S, Field>
where
	S: AtomicOperation<Field> + Send + Sync,
{
	fn fmt(
		&self,
		f: &mut std::fmt::Formatter<'_>,
	) -> std::fmt::Result {
		f.debug_struct("AtomicHandle")
			.field("current_value", &self.load(Ordering::SeqCst))
			.field("field_type", &std::any::type_name::<Field>())
			.field("struct_type", &std::any::type_name::<S>())
			.finish()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// Type alias for the default (unnamed) atomic field handle
	pub type DefaultAtomicHandle<S> = AtomicHandle<S, ()>;

	// Test marker types
	struct Counter;
	struct Requests;
	struct Errors;

	// Test struct with multiple atomics
	struct TestStruct {
		name: String,
		counter: AtomicUsize,
		requests: AtomicUsize,
		errors: AtomicUsize,
	}

	// Implement AtomicOperation for each field
	impl AtomicOperation<Counter> for TestStruct {
		fn get_atomic(&self) -> &AtomicUsize {
			&self.counter
		}
	}

	impl AtomicOperation<Requests> for TestStruct {
		fn get_atomic(&self) -> &AtomicUsize {
			&self.requests
		}
	}

	impl AtomicOperation<Errors> for TestStruct {
		fn get_atomic(&self) -> &AtomicUsize {
			&self.errors
		}
	}

	// Default implementation (could be any field you choose as default)
	impl AtomicOperation for TestStruct {
		fn get_atomic(&self) -> &AtomicUsize {
			&self.counter // Default to counter field
		}
	}

	type CounterHandle = AtomicHandle<TestStruct, Counter>;
	type RequestsHandle = AtomicHandle<TestStruct, Requests>;
	type ErrorsHandle = AtomicHandle<TestStruct, Errors>;

	#[test]
	fn test_multiple_field_handles() {
		let test_struct = Arc::new(TestStruct {
			name: "test".to_string(),
			counter: AtomicUsize::new(10),
			requests: AtomicUsize::new(20),
			errors: AtomicUsize::new(30),
		});

		let counter_handle: CounterHandle = AtomicHandle::new(Arc::clone(&test_struct));
		let requests_handle: RequestsHandle = AtomicHandle::new(Arc::clone(&test_struct));
		let errors_handle: ErrorsHandle = AtomicHandle::new(Arc::clone(&test_struct));

		// Test initial values
		assert_eq!(counter_handle.load(Ordering::SeqCst), 10);
		assert_eq!(requests_handle.load(Ordering::SeqCst), 20);
		assert_eq!(errors_handle.load(Ordering::SeqCst), 30);

		// Test modifications
		counter_handle.store(100, Ordering::SeqCst);
		requests_handle.fetch_add(5, Ordering::SeqCst);
		errors_handle.fetch_sub(10, Ordering::SeqCst);

		// Verify changes
		assert_eq!(counter_handle.load(Ordering::SeqCst), 100);
		assert_eq!(requests_handle.load(Ordering::SeqCst), 25);
		assert_eq!(errors_handle.load(Ordering::SeqCst), 20);

		// Verify original struct is also modified
		assert_eq!(test_struct.counter.load(Ordering::SeqCst), 100);
		assert_eq!(test_struct.requests.load(Ordering::SeqCst), 25);
		assert_eq!(test_struct.errors.load(Ordering::SeqCst), 20);
	}

	#[test]
	fn test_handle_cloning() {
		let test_struct = Arc::new(TestStruct {
			name: "test".to_string(),
			counter: AtomicUsize::new(0),
			requests: AtomicUsize::new(0),
			errors: AtomicUsize::new(0),
		});

		let handle1: CounterHandle = AtomicHandle::new(test_struct);
		let handle2 = handle1.clone();

		handle1.fetch_add(10, Ordering::SeqCst);
		handle2.fetch_add(5, Ordering::SeqCst);

		assert_eq!(handle1.load(Ordering::SeqCst), 15);
		assert_eq!(handle2.load(Ordering::SeqCst), 15);
	}

	#[test]
	fn test_atomic_address() {
		let test_struct = Arc::new(TestStruct {
			name: "test".to_string(),
			counter: AtomicUsize::new(42),
			requests: AtomicUsize::new(0),
			errors: AtomicUsize::new(0),
		});

		let handle: CounterHandle = AtomicHandle::new(test_struct.clone());
		let counter_ref = &test_struct.counter  as *const AtomicUsize;
		let counter_handle_ref = handle.get() as *const AtomicUsize;

		assert_eq!(counter_ref, counter_handle_ref);
	}
}