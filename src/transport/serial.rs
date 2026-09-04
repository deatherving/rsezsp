//! A serial-port transport.
//!
//! # Flow control is not a preference
//!
//! Opening a tty with hardware flow control enabled **blocks in `open(2)`
//! until CTS is asserted**. On a dongle that does not wire RTS/CTS, that is a
//! hang, not a slow start -- and it cannot be interrupted by a timeout,
//! because a blocking syscall is not an await point. A five-second timeout
//! around it was observed to take ten minutes to give up.
//!
//! So [`SerialSettings::rtscts`] defaults to off, and turning it on is an
//! explicit decision for a dongle known to wire those lines. The safe default
//! costs nothing on hardware that does support it; the unsafe one costs the
//! process.
//!
//! Confirmed on a Sonoff ZBDongle-E (EFR32MG21): 115200 baud, no flow control.

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio_serial::{SerialPortBuilderExt as _, SerialStream};

use crate::transport::{Transport, TransportError};

/// How to open the port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SerialSettings {
    /// Baud rate. Ember NCPs use 115200 unless reconfigured.
    pub baud: u32,
    /// Whether the dongle wires RTS/CTS.
    ///
    /// **Leave this off unless you know it does.** See the module docs: a
    /// wrong `true` is an uninterruptible hang.
    pub rtscts: bool,
}

impl Default for SerialSettings {
    fn default() -> Self {
        Self {
            baud: 115_200,
            rtscts: false,
        }
    }
}

/// A transport over a serial port.
#[derive(Debug)]
pub struct SerialTransport {
    stream: SerialStream,
    /// Reused between reads so a read does not allocate per call.
    buffer: Vec<u8>,
}

impl SerialTransport {
    /// Opens `path` with `settings`.
    ///
    /// # Errors
    ///
    /// [`TransportError::Open`] if the port cannot be opened or configured.
    pub fn open(path: &str, settings: SerialSettings) -> Result<Self, TransportError> {
        let mut builder = tokio_serial::new(path, settings.baud);
        builder = builder.flow_control(if settings.rtscts {
            tokio_serial::FlowControl::Hardware
        } else {
            tokio_serial::FlowControl::None
        });
        let stream = builder
            .open_native_async()
            .map_err(|e| TransportError::Open {
                path: path.to_owned(),
                reason: e.to_string(),
            })?;
        Ok(Self {
            stream,
            buffer: vec![0u8; 1024],
        })
    }
}

impl Transport for SerialTransport {
    async fn write(&mut self, data: &[u8]) -> Result<(), TransportError> {
        self.stream
            .write_all(data)
            .await
            .map_err(|e| TransportError::Io {
                operation: "write",
                reason: e.to_string(),
            })?;
        self.stream.flush().await.map_err(|e| TransportError::Io {
            operation: "flush",
            reason: e.to_string(),
        })
    }

    async fn read(&mut self) -> Result<Vec<u8>, TransportError> {
        let read = self
            .stream
            .read(&mut self.buffer)
            .await
            .map_err(|e| TransportError::Io {
                operation: "read",
                reason: e.to_string(),
            })?;
        if read == 0 {
            return Err(TransportError::Closed);
        }
        Ok(self.buffer.get(..read).unwrap_or(&[]).to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_control_defaults_to_off() {
        // Not a style preference. A wrong `true` blocks in open(2) until CTS
        // is asserted, which on a dongle that does not wire it is an
        // uninterruptible hang -- a five-second timeout around it was seen to
        // take ten minutes.
        let settings = SerialSettings::default();
        assert!(!settings.rtscts);
        assert_eq!(settings.baud, 115_200);
    }

    #[test]
    fn a_missing_port_fails_fast_rather_than_hanging() {
        let error = SerialTransport::open("/dev/definitely-not-a-port", SerialSettings::default())
            .expect_err("must fail");
        assert!(matches!(error, TransportError::Open { .. }));
    }
}
