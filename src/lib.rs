//! `rsezsp` is a hardware-driven Rust implementation of Silicon Labs EZSP for
//! Ember NCP devices.
//!
//! The project intentionally implements EZSP incrementally. Command coverage is
//! based on real hardware and application requirements rather than protocol
//! completeness.
//!
//! # Layering
//!
//! ```text
//! Application / Zigbee runtime
//!         │
//!    typed EZSP API          ezsp::command, ezsp::callback
//!         │
//! EZSP codec + correlation   ezsp::codec, ezsp::frame, ezsp::correlation
//!         │
//!    ASH transport           ash::
//!         │
//!        serial              transport::
//!         │
//!  Silicon Labs Ember NCP
//! ```
//!
//! Each layer is usable on its own and none reaches past its neighbours. This
//! crate owns the host-to-NCP conversation and nothing above it: no ZCL, no
//! ZDO interview logic, no device definitions.
//!
//! # Two properties the design is built around
//!
//! **The protocol version is part of the wire format.** Field widths change
//! between EZSP versions -- a status is one byte below version 14 and four at
//! or above it -- so the negotiated version is threaded through every codec
//! rather than stored once. See [`ezsp::version`].
//!
//! **Parsing is sans-I/O.** Bytes in, typed values out, no runtime involved.
//! That is what makes the parsers deterministic to test, cheap to fuzz, and
//! able to replay a captured wire trace as a regression test.
//!
//! # Protocol references
//!
//! Silicon Labs' EZSP documentation is the authority. Behaviour, command ids,
//! field widths and version boundaries were cross-checked against
//! [`zigbee-herdsman`]'s Ember adapter (MIT, © Koen Kanters and contributors),
//! which is a mature behavioural reference, and against wire traces captured
//! from real hardware. Nothing here is a translation of that source; where the
//! references disagreed, the wire trace decided.
//!
//! [`zigbee-herdsman`]: https://github.com/Koenkk/`zigbee-herdsman`

#![forbid(unsafe_code)]

pub mod ash;
pub mod ezsp;
#[cfg(feature = "tokio-transport")]
pub mod ncp;
pub mod transport;
pub mod types;

#[cfg(feature = "tokio-transport")]
pub use ncp::Ncp;

pub use ash::AshError;
pub use ezsp::{Command, EzspError, FrameId, ProtocolVersion};
pub use types::network::{Eui64, NodeId};
pub use types::status::SlStatus;
