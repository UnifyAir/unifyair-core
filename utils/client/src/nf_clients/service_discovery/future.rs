use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use http::Response as HttpResponse;
use tower::BoxError;
use pin_project_lite::pin_project;
use reqwest::Body;


pin_project! {
    /// Future for the `ServiceDiscovery` service.
    pub struct ResponseFuture<F> {
        #[pin]
        state: State<F>,
    }
}

pin_project! {
    #[project = StateProj]
    enum State<F> {
        // The future returned by the inner service.
        Inner { #[pin] fut: F },
        // An error occurred before the inner service was called.
        // The Option is used to allow moving the error out on the first poll.
        Error { error: Option<BoxError> },
    }
}

impl<F> ResponseFuture<F> {
    /// Creates a new `ResponseFuture` in the `Inner` state.
    pub(crate) fn new(fut: F) -> Self {
        Self {
            state: State::Inner { fut },
        }
    }

    /// Creates a new `ResponseFuture` in the `Error` state.
    pub(crate) fn error(error: BoxError) -> Self {
        Self {
            state: State::Error { error: Some(error) },
        }
    }
}

impl<F, E> Future for ResponseFuture<F>
where
    F: Future<Output = Result<HttpResponse<Body>, E>>,
    E: Into<BoxError>,
{
    type Output = Result<HttpResponse<Body>, BoxError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project().state.project() {
            StateProj::Inner { fut } => {
                // Poll the inner future and map its error type
                fut.poll(cx).map(|res| res.map_err(Into::into))
            }
            StateProj::Error { error } => {
                // The error is ready immediately.
                // We take it from the Option to ensure it's only returned once.
                let e = error.take().expect("ResponseFuture polled after completion");
                Poll::Ready(Err(e))
            }
        }
    }
}