use std::{fmt::Debug, future::Future, pin::Pin, sync::Arc};

use rustc_hash::FxBuildHasher;
use scc::hash_map::HashMap as SccHashMap;
use thiserror::Error;
use tokio::sync::OwnedRwLockWriteGuard;

use super::context_queue::ContextQueue;

/// A trait for types that can be identified by a unique ID.
///
/// This trait is used by the `ContextManager` to identify and manage context
/// elements.
pub trait Identifiable {
	/// The type of the ID, which must be clonable, debuggable, equatable, and
	/// hashable.
	type ID: Clone + Debug + Eq + PartialEq + std::hash::Hash + Copy + Send + Sync + 'static;

	/// Returns the ID of the implementor.
	fn id(&self) -> &Self::ID;
}

pub type PinnedSendSyncFuture<T> = Pin<Box<dyn Future<Output = T> + Send + Sync + 'static>>;

/// A manager for context elements that can be identified by a unique ID.
///
/// The `ContextManager` provides thread-safe access to context elements,
/// ensuring that operations on a specific context are properly serialized
/// through a queue system. Each context element is wrapped in a `ContextQueue`
/// which manages exclusive access to the context.
pub struct ContextManager<T: Identifiable> {
	/// A concurrent hash map that stores context queues, keyed by their IDs.
	queues: SccHashMap<T::ID, Arc<ContextQueue<T>>, FxBuildHasher>,
}

impl<T: Identifiable> Debug for ContextManager<T> {
	fn fmt(
		&self,
		f: &mut std::fmt::Formatter<'_>,
	) -> std::fmt::Result {
		f.debug_struct("ContextManager")
			.field("Number of elements", &self.queues.len())
			.finish()
	}
}

impl<T: Identifiable + Send + Sync + 'static> ContextManager<T> {
	/// Creates a new, empty `ContextManager`.
	///
	/// # Returns
	///
	/// A new `ContextManager` instance with no context elements.
	pub fn new() -> Self {
		ContextManager {
			queues: SccHashMap::with_hasher(FxBuildHasher::default()),
		}
	}

	pub fn with_capacity(capacity: usize) -> Self {
		ContextManager {
			queues: SccHashMap::with_capacity_and_hasher(capacity, FxBuildHasher::default()),
		}
	}

	/// Adds a new context element to the manager.
	///
	/// This method creates a new `ContextQueue` for the provided context
	/// element and adds it to the manager, keyed by the element's ID.
	///
	/// # Arguments
	///
	/// * `context` - The context element to add
	///
	/// # Returns
	///
	/// * `Ok(())` if the context was successfully added
	/// * `Err(ContextError::ContextAlreadyExists)` if a context with the same
	///   ID already exists
	pub async fn add_context(
		&self,
		context: T,
	) -> Result<(), ContextError<T>> {
		let id = context.id().to_owned();
		let queue = Arc::new(ContextQueue::new(context));
		self.queues
			.insert_async(id.clone(), queue.clone())
			.await
			.map_err(|(id, queue)| {
				debug_assert_eq!(
					Arc::strong_count(&queue),
					1,
					"Arc should have exactly one strong reference"
				);
				debug_assert_eq!(
					Arc::weak_count(&queue),
					0,
					"Arc should have no weak references"
				);
				// Safety: This is safe because:
				// 1. The queue value comes from a failed insert_async operation, meaning it was
				//    never stored in the map
				// 2. We have the only Arc reference to this queue as it was just created and
				//    clone() was only used for the failed insert
				// 3. No other tasks could have been spawned as the queue never made it into the
				//    manager
				// Therefore we can safely unwrap the Arc and extract the inner value
				let ctx_queue_inner = Arc::into_inner(queue).unwrap();
				let inner = unsafe { ctx_queue_inner.into_inner() }.unwrap();
				ContextError::ContextAlreadyExists(id, inner)
			})
	}

	/// Changes the ID of a context element.
	///
	/// This method removes the context element with the old ID and reinserts it
	/// with the new ID. If the operation fails at any point, it attempts to
	/// restore the original state.
	///
	/// # Arguments
	///
	/// * `old_id` - The current ID of the context element
	/// * `new_id` - The new ID to assign to the context element
	///
	/// # Returns
	///
	/// * `Ok(())` if the ID was successfully changed
	/// * `Err(ContextError::ContextChangeError)` if:
	///   - The element with the old ID was not found
	///     (`ContextChangeError::OldIdNotFound`)
	///   - An element with the new ID already exists
	///     (`ContextChangeError::NewIdAlreadyExists`)
	pub async fn change_id(
		&self,
		old_id: T::ID,
		new_id: T::ID,
	) -> Result<(), ContextError<T>> {
		if let Some((_, element_queue)) = self.queues.remove_async(&old_id).await {
			match self.queues.insert_async(new_id, element_queue).await {
				Ok(()) => Ok(()),
				Err((new_id, element_queue)) => {
					// Attempt to restore the original state if insertion with new ID fails
					let _ = self
						.queues
						.insert_async(old_id.clone(), element_queue)
						.await;
					Err(ContextError::ContextChangeError(
						ContextChangeError::NewIdAlreadyExists,
						old_id,
						new_id,
					))
				}
			}
		} else {
			Err(ContextError::ContextChangeError(
				ContextChangeError::OldIdNotFound,
				old_id,
				new_id,
			))
		}
	}

	pub async fn contains_context(
		&self,
		id: &T::ID,
	) -> bool {
		self.queues.contains_async(id).await
	}

	/// Executes a closure with exclusive access to a context element and
	/// returns its result.
	///
	/// This method schedules the closure to be executed on the context element
	/// with the given ID. The closure is executed with exclusive access to the
	/// context, ensuring that operations are properly serialized through the
	/// context queue.
	///
	/// # Arguments
	///
	/// * `id` - The ID of the context element to operate on
	/// * `closure` - The closure to execute with the context. It takes a
	///   mutable reference to the context and returns a future that resolves to
	///   a value of type `O`.
	///
	/// # Returns
	///
	/// * `Ok(O)` - The result of the closure if the context element exists
	/// * `Err(ContextError::ContextNotFound)` - If the context element with the
	///   given ID doesn't exist
	pub async fn with_context<F, O>(
		&self,
		id: T::ID,
		closure: F,
	) -> Result<O, ContextError<T>>
	where
		F: FnOnce(OwnedRwLockWriteGuard<T>) -> PinnedSendSyncFuture<O>
			+ Send
			+ Sync
			+ 'static,
		O: Send + Sync + 'static,
	{
		let element = self.queues.read_async(&id, |_, queue| queue.clone()).await;
		if let Some(queue) = element {
			Ok(queue.schedule_and_wait(closure).await)
		} else {
			Err(ContextError::ContextNotFound(id))
		}
	}
}

/// Errors that can occur when operating on a `ContextManager`.
#[derive(Debug, Error)]
pub enum ContextError<T: Identifiable> {
	/// Error when attempting to add a context that already exists.
	#[error("ContextAlreadyExists: Context already exists {0:?}")]
	ContextAlreadyExists(T::ID, T),

	/// Error when attempting to access a context that doesn't exist.
	#[error("ContextNotFound: Context not found {0:?}")]
	ContextNotFound(T::ID),

	/// Error when attempting to change the ID of a context.
	#[error("ContextChangeError: Context change error from {1:?} -> {2:?}")]
	ContextChangeError(#[source] ContextChangeError, T::ID, T::ID),
}

/// Specific errors that can occur when changing a context ID.
#[derive(Debug, Error)]
pub enum ContextChangeError {
	/// Error when the old ID doesn't exist in the manager.
	#[error("OldIdNotFound: Old ID not found")]
	OldIdNotFound,

	/// Error when the new ID already exists in the manager.
	#[error("NewIdAlreadyExists: New ID already exists")]
	NewIdAlreadyExists,
}
