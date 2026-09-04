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
// The usage example drives the runtime, so it only compiles when the runtime
// is enabled. Gated rather than dropped: a crate root with no example of how
// to use the crate is a worse default than one that varies by feature.
#![cfg_attr(feature = "tokio-transport", doc = "# Usage")]
#![cfg_attr(feature = "tokio-transport", doc = "")]
#![cfg_attr(feature = "tokio-transport", doc = "```no_run")]
#![cfg_attr(feature = "tokio-transport", doc = "use rsezsp::Ncp;")]
#![cfg_attr(
    feature = "tokio-transport",
    doc = "use rsezsp::ezsp::command::GetEui64;"
)]
#![cfg_attr(
    feature = "tokio-transport",
    doc = "use rsezsp::transport::serial::{SerialSettings, SerialTransport};"
)]
#![cfg_attr(feature = "tokio-transport", doc = "")]
#![cfg_attr(
    feature = "tokio-transport",
    doc = "# async fn example() -> Result<(), Box<dyn std::error::Error>> {"
)]
#![cfg_attr(
    feature = "tokio-transport",
    doc = "// Opening the port performs no I/O with the NCP; connecting does the ASH"
)]
#![cfg_attr(
    feature = "tokio-transport",
    doc = "// reset handshake and EZSP version negotiation."
)]
#![cfg_attr(
    feature = "tokio-transport",
    doc = "let transport = SerialTransport::open(\"/dev/ttyUSB0\", SerialSettings::default())?;"
)]
#![cfg_attr(
    feature = "tokio-transport",
    doc = "let mut ncp = Ncp::connect(transport).await?;"
)]
#![cfg_attr(feature = "tokio-transport", doc = "")]
#![cfg_attr(
    feature = "tokio-transport",
    doc = "println!(\"EZSP {}, firmware {:#06x}\", ncp.version(), ncp.stack_version());"
)]
#![cfg_attr(feature = "tokio-transport", doc = "")]
#![cfg_attr(
    feature = "tokio-transport",
    doc = "let response = ncp.command(GetEui64).await?;"
)]
#![cfg_attr(
    feature = "tokio-transport",
    doc = "println!(\"coordinator {}\", response.eui64);"
)]
#![cfg_attr(feature = "tokio-transport", doc = "# Ok(())")]
#![cfg_attr(feature = "tokio-transport", doc = "# }")]
#![cfg_attr(feature = "tokio-transport", doc = "```")]
#![cfg_attr(feature = "tokio-transport", doc = "")]
#![cfg_attr(
    feature = "tokio-transport",
    doc = "`examples/startup.rs` is the full version: bringup, opening the network for"
)]
#![cfg_attr(
    feature = "tokio-transport",
    doc = "joining, and sending a command to a device that joined."
)]
#![cfg_attr(feature = "tokio-transport", doc = "")]
//! # Adding a command this crate does not have
//!
//! Coverage grows from real need rather than from working through the
//! specification, so at any moment there are commands nobody has needed yet.
//! That is only a reasonable design if it does not block you, so
//! [`Command`] is an ordinary public trait: you can implement it in **your**
//! crate, for a command this one has never heard of, and send it with
//! [`Ncp::command`] today.
//!
//! ```
//! use rsezsp::ezsp::codec::{EzspDecode, EzspEncode, Reader, Writer};
//! use rsezsp::ezsp::{Command, EzspError, FrameId};
//! use rsezsp::types::status::SlStatus;
//!
//! /// `setRadioPower` — frame id `0x0099`.
//! struct SetRadioPower {
//!     dbm: i8,
//! }
//!
//! impl EzspEncode for SetRadioPower {
//!     fn encode(&self, out: &mut Writer) -> Result<(), EzspError> {
//!         out.u8(self.dbm as u8);
//!         Ok(())
//!     }
//! }
//!
//! struct SetRadioPowerResponse {
//!     status: SlStatus,
//! }
//!
//! impl EzspDecode for SetRadioPowerResponse {
//!     fn decode(input: &mut Reader<'_>) -> Result<Self, EzspError> {
//!         // Applies the version boundary for you: a status is one byte below
//!         // EZSP 14 and four at or above it.
//!         Ok(Self { status: SlStatus::decode(input)? })
//!     }
//! }
//!
//! impl Command for SetRadioPower {
//!     type Response = SetRadioPowerResponse;
//!     const ID: FrameId = FrameId(0x0099);
//! }
//! ```
//!
//! `tests/extending_from_outside.rs` proves this works from a separate crate
//! and drives such a command through the whole runtime. If you write one worth
//! sharing, please send it back -- see `CONTRIBUTING.md`.
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
//! [`zigbee-herdsman`]: https://github.com/Koenkk/zigbee-herdsman

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
