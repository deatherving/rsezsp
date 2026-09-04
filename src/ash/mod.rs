//! ASH: the transport that carries EZSP frames over a serial line.
//!
//! ASH is a small sliding-window protocol with its own framing, checksums,
//! acknowledgements, retransmission and reset handshake. It knows nothing about
//! EZSP beyond "here are some bytes to carry", and this module keeps it that
//! way: no EZSP type appears here, and no ASH concern leaks upwards.
//!
//! The layering matters because the two protocols fail differently. A bad CRC
//! is answered with a NAK and the NCP resends; a malformed EZSP frame is a
//! decoding error with nothing to resend. Mixing them produces a stack that
//! retries unretryable things and gives up on recoverable ones.

pub mod codec;
pub mod error;
pub mod frame;
pub mod state;

pub use codec::{Decoded, Decoder, encode};
pub use error::AshError;
pub use frame::{ASH_VERSION, AshFrame};
pub use state::{Connection, ConnectionState, Outbound};
