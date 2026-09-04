//! Getting bytes to and from the NCP.
//!
//! The transport is deliberately the thinnest layer in the crate: read bytes,
//! write bytes, and nothing else. All framing lives in [`crate::ash`] and all
//! protocol logic above that, so a transport can be a serial port, a socket, a
//! recorded capture, or a test double, and none of them need to know anything
//! about ASH.

pub mod fake;

#[cfg(feature = "tokio-transport")]
pub mod serial;

/// Why a transport failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TransportError {
    /// The port could not be opened.
    #[error("cannot open {path}: {reason}")]
    Open {
        /// What was being opened.
        path: String,
        /// Why it failed.
        reason: String,
    },
    /// A read or write failed.
    #[error("{operation} failed: {reason}")]
    Io {
        /// Which operation.
        operation: &'static str,
        /// Why it failed.
        reason: String,
    },
    /// The other end went away.
    #[error("the transport closed")]
    Closed,
}

/// A byte pipe to an NCP.
///
/// Chunk-oriented rather than streaming because that is what a serial read
/// gives you: whatever happened to be in the buffer. The ASH decoder is built
/// to accept exactly that, so there is nothing to gain by pretending the
/// boundaries mean anything.
pub trait Transport: Send {
    /// Writes bytes. Returns once they are handed to the port.
    fn write(&mut self, data: &[u8]) -> impl Future<Output = Result<(), TransportError>> + Send;

    /// Reads whatever is available, blocking until at least one byte is.
    fn read(&mut self) -> impl Future<Output = Result<Vec<u8>, TransportError>> + Send;
}
