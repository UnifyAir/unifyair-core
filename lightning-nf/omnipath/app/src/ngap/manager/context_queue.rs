use std::{
	collections::VecDeque,
	future::Future,
	pin::Pin,
	sync::{
		Arc,
		atomic::{AtomicBool, Ordering},
	},
};

use tokio::sync::{Mutex, oneshot};
use tracing::Instrument;

use super::context_manager::Identifiable;
use crate::utils::SeqLock;

/// `ContextQueue` is designed to manage and execute asynchronous operations on
/// a shared context (`T`) in a sequential manner. It combines an internal,
/// mutable context protected by a `RwLock` with a queue of futures.  Futures
/// added to the queue are executed one at a time, ensuring that access to the
/// shared context is serialized, preventing data races.
///
/// The `ContextQueue` is particularly useful in scenarios where you have a
/// shared resource (the context `T`) that needs to be accessed and modified by
/// multiple asynchronous tasks, but those modifications must happen in a
/// specific order or without concurrent access to prevent race conditions.
/// It's a way to serialize asynchronous operations on a shared resource.
///
/// The queue itself is a `VecDeque` of boxed, pinned futures.  The
/// `processor_active` flag ensures that only one task is processing the queue
/// at any given time, avoiding concurrent modification of the queue itself.
/// When a future is added and the processor is not active, a new task is
/// spawned to process the queue. The processing continues until the queue is
/// empty.

pub(crate) struct ContextQueue<T> {
	inner: Arc<SeqLock<T>>,
	queue: Arc<Mutex<VecDeque<Pin<Box<dyn Future<Output = ()> + Send + 'static>>>>>,
	processor_active: AtomicBool,
}

impl<T> ContextQueue<T> {
	pub fn new(context: T) -> Self {
		ContextQueue {
			inner: Arc::new(SeqLock::new(context)),
			queue: Arc::new(Mutex::new(VecDeque::new())),
			processor_active: AtomicBool::new(false),
		}
	}

	/// Extracts the inner context value, consuming the queue.
	/// This should only be used when you are certain there are no pending
	/// operations.
	pub unsafe fn into_inner(self) -> Option<T> {
		let t = Arc::into_inner(self.inner);
		t.map(|t| unsafe { t.into_inner() })
	}
}

impl<T> ContextQueue<T>
where
	T: Identifiable + Send + Sync + 'static,
{
	/// Pushes a future onto the queue.
	///
	/// This method takes ownership of a `future` and adds it to the internal
	/// queue. The future will be executed when it reaches the front of the
	/// queue. If the queue is currently empty and no processor is active,
	/// a new processor task is spawned to start processing the queue.
	///
	/// # Arguments
	///
	/// * `future` - The future to be added to the queue. It must be a boxed,
	///   pinned future that is `Send`, `Sync` and `'static`.
	async fn push_future(
		self: Arc<Self>,
		future: Pin<Box<dyn Future<Output = ()> + Send + Sync + 'static>>,
	) {
		let mut queue = self.queue.lock().await;
		queue.push_back(future);

		if !self.processor_active.load(Ordering::SeqCst) {
			self.processor_active.store(true, Ordering::SeqCst);
			let self_clone = self.clone();
			tokio::spawn(async move {
				self_clone.process_queue().await;
			});
		}
	}

	/// Processes the queue of futures.
	///
	/// This method is spawned as a separate task and runs until the queue
	/// is empty. It retrieves and awaits each future from the queue in FIFO
	/// order. Once the queue is empty, it sets the `processor_active` flag
	/// to `false`.
	async fn process_queue(&self) {
		loop {
			let mut queue = self.queue.lock().await;
			if queue.is_empty() {
				self.processor_active.store(false, Ordering::SeqCst);
				break;
			}

			// Safety: The check for `queue.is_empty()` is performed above.
			let fut = queue.pop_front().unwrap();
			fut.await;
		}
	}

	/// Enqueues a closure to be executed with exclusive access to the context,
	/// and sends the result of the closure through a oneshot channel.
	///
	/// # Arguments
	///
	/// * `closure`: A closure that takes a mutable reference to the context
	///   (`&mut T`) and returns a future that resolves to a value of type `O`.
	///   The closure is executed with exclusive (write) access to the context.
	/// * `tx`: A oneshot sender used to send the result of the closure back to
	///   the caller.  The caller must await the corresponding receiver to get
	///   the result.
	///
	/// # Returns
	///
	/// A pinned, boxed future that represents the enqueued operation.  This
	/// future's output type is `()`, as the actual result is sent through the
	/// `tx` channel.  The returned future must be awaited to ensure the
	/// operation is executed.  Dropping the future *will not* prevent the
	/// operation from executing once it has been enqueued.
	async fn enqueue_and_get_result<F, O>(
		&self,
		closure: F,
		tx: oneshot::Sender<O>,
	) -> Pin<Box<dyn Future<Output = ()> + Send + Sync + 'static>>
	where
		F: FnOnce(Arc<SeqLock<T>>) -> Pin<Box<dyn Future<Output = O> + Send + Sync + 'static>>
			+ Send
			+ Sync
			+ 'static,
		O: Send + Sync + 'static,
	{
		let context = self.inner.clone();
		Box::pin(async move {
			let context = context;
			// SAFETY: Context Manager Ensures that the future is executed one by one.
			let id = *unsafe { context.get() }.id();

			let future = closure(context).instrument(tracing::info_span!("ContextQueue", id = ?id));
			let output = future.await;
			// The receiver will be waiting for this result, so we ignore the
			// result of send.  If the receiver has been dropped, then the
			// send will fail.  This is fine, as it means that the result is
			// no longer needed.
			let _ = tx.send(output);
		})
	}

	/// Executes a closure with exclusive access to the context and returns its
	/// result, ensuring the operation is properly queued.
	///
	/// This function provides a higher-level abstraction over
	/// `enqueue_and_get_result` and `push_future`. It handles the creation of
	/// the oneshot channel, enqueuing the operation, and waiting for the
	/// result, all in a single call.
	///
	/// The operation follows these steps:
	/// 1. Creates a oneshot channel for receiving the result
	/// 2. Uses `enqueue_and_get_result` to create a future that will execute
	///    the closure with exclusive access to the context and send the result
	///    through the channel
	/// 3. Pushes that future to the queue using `push_future`
	/// 4. Awaits the result from the receiver end of the channel
	///
	/// This function ensures that operations on the shared context are properly
	/// serialized through the queue, preventing race conditions while still
	/// allowing asynchronous execution.
	///
	/// # Arguments
	///
	/// * `closure`: A closure that takes a mutable reference to the context
	///   (`&mut T`) and returns a future that resolves to a value of type `O`.
	///   The closure is executed with exclusive (write) access to the context.
	///
	/// # Returns
	///
	/// The result of type `O` produced by the closure.
	pub async fn schedule_and_wait<F, O>(
		self: Arc<Self>,
		closure: F,
	) -> O
	where
		F: FnOnce(Arc<SeqLock<T>>) -> Pin<Box<dyn Future<Output = O> + Send + Sync + 'static>>
			+ Send
			+ Sync
			+ 'static,
		O: Send + Sync + 'static,
	{
		let (tx, rx) = oneshot::channel::<O>();
		let future = self.enqueue_and_get_result(closure, tx).await;
		self.push_future(future).await;

		// Safety: This unwrap is safe because the oneshot channel's sender (tx) is used
		// inside the future created by enqueue_and_get_result, which is then pushed to
		// the queue via push_future. The queue processor ensures the future is
		// executed, which guarantees that tx.send() is called with the result. The
		// only way this could fail is if the future panics, in which case the entire
		// task would be aborted anyway.
		rx.await.unwrap()
	}
}
