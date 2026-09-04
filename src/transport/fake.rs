//! A transport backed by scripted bytes, for tests.

//!
//! The point is determinism. Every ASH and EZSP behaviour worth testing --
//! a reset handshake, a retransmission, a callback interleaved with a
//! response, a corrupt frame followed by a good one -- can be expressed as
//! "these bytes arrive in this order", with no hardware, no timing and no
//! flakiness.
//!
//! It also serves as the replay mechanism for captured traces: a real
//! hardware bug becomes a recorded byte string and a test that fails until it
//! is fixed.

use std::collections::VecDeque;

use crate::transport::{Transport, TransportError};

/// A transport that returns queued bytes and records what was written.
#[derive(Debug, Default)]
pub struct FakeTransport {
    /// Chunks still to be handed out, in order.
    to_read: VecDeque<Vec<u8>>,
    /// Everything written, concatenated.
    written: Vec<u8>,
    /// Set to fail the next read.
    fail_next_read: Option<TransportError>,
    /// Whether the other end has gone away.
    ///
    /// Distinct from having nothing queued. A real port with no data pends
    /// until some arrives; only an unplugged device closes. Conflating the two
    /// makes every test that waits for a timeout report a transport failure
    /// instead -- which is exactly what happened before this existed.
    closed: bool,
}

impl FakeTransport {
    /// A transport with nothing queued.
    pub fn new() -> Self {
        Self::default()
    }

    /// A transport that will hand out these chunks, in order.
    ///
    /// Chunk boundaries are meaningful: they model the arbitrary boundaries a
    /// real serial read produces, which is exactly what a frame decoder must
    /// not depend on.
    pub fn with_chunks<I, C>(chunks: I) -> Self
    where
        I: IntoIterator<Item = C>,
        C: Into<Vec<u8>>,
    {
        Self {
            to_read: chunks.into_iter().map(Into::into).collect(),
            written: Vec::new(),
            fail_next_read: None,
            closed: false,
        }
    }

    /// Queues another chunk to be read.
    pub fn push_chunk(&mut self, chunk: impl Into<Vec<u8>>) {
        self.to_read.push_back(chunk.into());
    }

    /// Makes the next read fail.
    pub fn fail_next_read(&mut self, error: TransportError) {
        self.fail_next_read = Some(error);
    }

    /// Models the other end going away.
    ///
    /// Without this, "nothing more to read" and "the device was unplugged"
    /// would be the same thing, and they call for opposite responses: one
    /// waits, the other gives up.
    pub fn close(&mut self) {
        self.closed = true;
    }

    /// Everything written so far.
    pub fn written(&self) -> &[u8] {
        &self.written
    }

    /// Whether every queued chunk has been read.
    pub fn is_drained(&self) -> bool {
        self.to_read.is_empty()
    }
}

// The trait is async; these implementations happen to need no await, which is
// the point of a fake -- it answers immediately and deterministically.
impl Transport for FakeTransport {
    async fn write(&mut self, data: &[u8]) -> Result<(), TransportError> {
        // A real await point, not a formality. An instantly-returning fake
        // never yields, so a caller with an ordering bug -- writing before
        // subscribing, say -- passes against the fake and fails on hardware.
        // Yielding once makes the double behave like a transport.
        std::future::ready(()).await;
        self.written.extend_from_slice(data);
        Ok(())
    }

    async fn read(&mut self) -> Result<Vec<u8>, TransportError> {
        std::future::ready(()).await;
        if let Some(error) = self.fail_next_read.take() {
            return Err(error);
        }
        if let Some(chunk) = self.to_read.pop_front() {
            return Ok(chunk);
        }
        if self.closed {
            return Err(TransportError::Closed);
        }
        // Drained but open: pend, like a real port with nothing to say. The
        // caller's deadline decides what that means. Returning `Closed` here
        // would turn every expected timeout into a transport failure, and
        // returning an empty vec would make a caller spin.
        std::future::pending().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn chunks_come_back_in_order_and_writes_are_recorded() {
        let mut transport = FakeTransport::with_chunks([vec![0x01], vec![0x02, 0x03]]);
        transport.write(&[0xaa]).await.expect("writes");
        assert_eq!(transport.read().await.expect("reads"), vec![0x01]);
        assert_eq!(transport.read().await.expect("reads"), vec![0x02, 0x03]);
        assert_eq!(transport.written(), &[0xaa]);
        assert!(transport.is_drained());
    }

    #[tokio::test]
    async fn a_drained_but_open_transport_pends_rather_than_closing() {
        // A real port with no data waits. Reporting `Closed` here would turn
        // every expected timeout into a transport failure.
        let mut transport = FakeTransport::new();
        let read =
            tokio::time::timeout(std::time::Duration::from_millis(50), transport.read()).await;
        assert!(read.is_err(), "a drained open transport must not resolve");
    }

    #[tokio::test]
    async fn an_explicitly_closed_transport_reports_closed() {
        let mut transport = FakeTransport::new();
        transport.close();
        assert_eq!(transport.read().await, Err(TransportError::Closed));
    }

    #[tokio::test]
    async fn a_scripted_failure_surfaces_once() {
        let mut transport = FakeTransport::with_chunks([vec![0x01]]);
        transport.fail_next_read(TransportError::Io {
            operation: "read",
            reason: "scripted".into(),
        });
        assert!(transport.read().await.is_err());
        assert_eq!(
            transport.read().await.expect("reads"),
            vec![0x01],
            "the failure must not consume the queued chunk"
        );
    }
}
