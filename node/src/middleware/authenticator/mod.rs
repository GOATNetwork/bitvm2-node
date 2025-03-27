pub mod musig;

/// An outbound ping failure.
#[derive(Debug)]
pub enum Failure {
    /// The ping timed out, i.e. no response was received within the
    /// configured ping timeout.
    Timeout,
    /// The peer does not support the ping protocol.
    Unsupported,
    /// The ping failed for reasons other than a timeout.
    Other { error: Box<dyn std::error::Error + Send + Sync + 'static> },
}

impl Failure {
    fn other(e: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Other { error: Box::new(e) }
    }
}
