//! EZSP: the command protocol spoken to an Ember NCP.
//!
//! Everything here is sans-I/O. A frame is bytes in and a typed value out, or
//! the reverse, with the negotiated protocol version threaded through because
//! it changes what the bytes mean.

pub mod callback;
pub mod codec;
pub mod command;
pub mod correlation;
pub mod error;
pub mod frame;
pub mod version;

pub use codec::{EzspDecode, EzspEncode, Reader, Writer};
pub use command::Command;
pub use error::EzspError;
pub use frame::{Direction, Frame, FrameControl, FrameId, HeaderFormat};
pub use version::ProtocolVersion;
