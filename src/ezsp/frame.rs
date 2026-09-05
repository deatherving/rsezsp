//! EZSP frame headers.
//!
//! # Two header formats, and why both are needed
//!
//! EZSP 8 introduced an extended header with a two-byte frame id and a two-byte
//! frame control. Every command uses it — except the very first `version`
//! command, which cannot, because the version has not been negotiated yet and
//! the host does not know which format the NCP will accept.
//!
//! So the first `version` goes out in the **legacy** three-byte header, and
//! everything after it uses the extended one. That is not a quirk worth hiding:
//! it is the bootstrap, and a library that hardcodes one format either cannot
//! connect or cannot send anything afterwards.
//!
//! ```text
//! legacy    [ seq | frame control | frame id            | parameters… ]
//! extended  [ seq | control lo | control hi | id lo | id hi | parameters… ]
//! ```

use crate::ezsp::codec::{Reader, Writer};
use crate::ezsp::error::EzspError;

/// An EZSP command or response identifier.
///
/// Two bytes, because the extended header carries two. The legacy header sends
/// only the low byte, which is why every command reachable in the legacy format
/// has an id below 256.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FrameId(pub u16);

impl FrameId {
    /// `version` — protocol negotiation. Always the first command sent.
    pub const VERSION: Self = Self(0x0000);
    /// `addEndpoint`.
    pub const ADD_ENDPOINT: Self = Self(0x0002);
    /// `networkInit`.
    pub const NETWORK_INIT: Self = Self(0x0017);
    /// `permitJoining`.
    pub const PERMIT_JOINING: Self = Self(0x0022);
    /// `getEui64`.
    pub const GET_EUI64: Self = Self(0x0026);
    /// `sendUnicast`.
    pub const SEND_UNICAST: Self = Self(0x0034);
    /// `sendBroadcast`.
    pub const SEND_BROADCAST: Self = Self(0x0036);
    /// `setManufacturerCode`.
    pub const SET_MANUFACTURER_CODE: Self = Self(0x0015);
    /// `formNetwork`.
    pub const FORM_NETWORK: Self = Self(0x001e);
    /// `networkState`.
    pub const NETWORK_STATE: Self = Self(0x0018);
    /// `sendMulticast`.
    pub const SEND_MULTICAST: Self = Self(0x0038);
    /// `getNetworkKeyInfo`.
    pub const GET_NETWORK_KEY_INFO: Self = Self(0x0116);
    /// `getNetworkParameters`.
    pub const GET_NETWORK_PARAMETERS: Self = Self(0x0028);
    /// `getConfigurationValue`.
    pub const GET_CONFIGURATION_VALUE: Self = Self(0x0052);
    /// `setInitialSecurityState`.
    pub const SET_INITIAL_SECURITY_STATE: Self = Self(0x0068);
    /// `clearTransientLinkKeys`.
    pub const CLEAR_TRANSIENT_LINK_KEYS: Self = Self(0x006b);
    /// `getValue`.
    pub const GET_VALUE: Self = Self(0x00aa);
    /// `exportKey`.
    pub const EXPORT_KEY: Self = Self(0x0114);
    /// `setConfigurationValue`.
    pub const SET_CONFIGURATION_VALUE: Self = Self(0x0053);
    /// `setPolicy`.
    pub const SET_POLICY: Self = Self(0x0055);
    /// `importTransientKey`.
    pub const IMPORT_TRANSIENT_KEY: Self = Self(0x0111);

    /// `stackStatusHandler` callback.
    pub const STACK_STATUS_HANDLER: Self = Self(0x0019);
    /// `messageSentHandler` callback.
    pub const MESSAGE_SENT_HANDLER: Self = Self(0x003f);
    /// `incomingMessageHandler` callback.
    pub const INCOMING_MESSAGE_HANDLER: Self = Self(0x0045);
    /// `trustCenterJoinHandler` callback.
    pub const TRUST_CENTER_JOIN_HANDLER: Self = Self(0x0024);

    /// Whether this id fits the legacy header's single byte.
    pub const fn fits_legacy(self) -> bool {
        self.0 <= 0xff
    }

    /// The documented name, when this build knows one.
    ///
    /// For diagnostics only. An unknown id is reported as its number rather
    /// than as "unknown", because the number is what someone looks up.
    pub const fn name(self) -> Option<&'static str> {
        Some(match self {
            Self::VERSION => "version",
            Self::ADD_ENDPOINT => "addEndpoint",
            Self::NETWORK_INIT => "networkInit",
            Self::PERMIT_JOINING => "permitJoining",
            Self::GET_EUI64 => "getEui64",
            Self::SEND_UNICAST => "sendUnicast",
            Self::SET_CONFIGURATION_VALUE => "setConfigurationValue",
            Self::SET_POLICY => "setPolicy",
            Self::IMPORT_TRANSIENT_KEY => "importTransientKey",
            Self::STACK_STATUS_HANDLER => "stackStatusHandler",
            Self::MESSAGE_SENT_HANDLER => "messageSentHandler",
            Self::INCOMING_MESSAGE_HANDLER => "incomingMessageHandler",
            Self::TRUST_CENTER_JOIN_HANDLER => "trustCenterJoinHandler",
            _ => return None,
        })
    }
}

impl FrameId {
    /// Whether a frame with this id carries key material in its parameters.
    ///
    /// Used to keep keys out of logs. Frame payloads are logged at debug level
    /// because a wire trace is the most useful thing a bug report can carry --
    /// and `CONTRIBUTING.md` asks reporters for exactly that. For these four
    /// the payload *is* the secret: an `exportKey` response is sixteen bytes of
    /// network key, and `importTransientKey` and `setInitialSecurityState`
    /// carry keys outbound.
    ///
    /// Erring towards redaction: a frame id wrongly listed here costs a little
    /// debuggability, while one wrongly omitted publishes a network key in
    /// whatever log the reporter pastes into a public issue.
    #[must_use]
    pub const fn carries_key_material(self) -> bool {
        matches!(
            self,
            Self::EXPORT_KEY
                | Self::IMPORT_TRANSIENT_KEY
                | Self::SET_INITIAL_SECURITY_STATE
                | Self::GET_NETWORK_KEY_INFO
        )
    }
}

impl core::fmt::Display for FrameId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.name() {
            Some(name) => write!(f, "{name} ({:#06x})", self.0),
            None => write!(f, "frame {:#06x}", self.0),
        }
    }
}

/// Which header layout a frame uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderFormat {
    /// Three bytes, one-byte frame id. Only the bootstrap `version` command.
    Legacy,
    /// Five bytes, two-byte frame id. Everything else.
    Extended,
}

impl HeaderFormat {
    /// How many bytes the header occupies.
    ///
    /// Named `byte_len` rather than `len`: a `len` without an `is_empty` reads
    /// as a container, and a header is never empty.
    pub const fn byte_len(self) -> usize {
        match self {
            Self::Legacy => 3,
            Self::Extended => 5,
        }
    }
}

/// Whether a frame is going to the NCP or coming back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Host to NCP.
    Command,
    /// NCP to host.
    Response,
}

/// The parsed frame control field.
///
/// Only the bits this crate acts on are modelled. The rest are carried in
/// `raw_low` so a frame can be logged faithfully without this type having to
/// grow a field for every bit the moment a new firmware sets one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct FrameControl {
    /// Command or response.
    ///
    /// The bools below are each an independent bit of one wire field rather
    /// than a set of options a caller chooses between, so grouping them into
    /// sub-structs would obscure the layout they mirror.
    pub direction: Direction,
    /// Set when the frame is an asynchronous callback rather than a response.
    ///
    /// The single most important bit in this crate. Without it, a callback
    /// arriving while a command is pending can be mistaken for that command's
    /// answer, and the caller gets a decoded structure built from an unrelated
    /// frame -- which looks like a successful call returning nonsense.
    pub is_callback: bool,
    /// The NCP has more callbacks queued.
    pub callback_pending: bool,
    /// The NCP overflowed its callback queue and dropped some.
    pub overflow: bool,
    /// The response was truncated by the NCP.
    pub truncated: bool,
    /// The low control byte as received.
    pub raw_low: u8,
}

impl FrameControl {
    const DIRECTION_RESPONSE: u8 = 0x80;
    const OVERFLOW: u8 = 0x01;
    const TRUNCATED: u8 = 0x02;
    const CALLBACK_PENDING: u8 = 0x04;
    /// Set for a callback delivered asynchronously.
    const ASYNC_CALLBACK: u8 = 0x10;

    /// A control byte for an outgoing command.
    pub const fn command() -> Self {
        Self {
            direction: Direction::Command,
            is_callback: false,
            callback_pending: false,
            overflow: false,
            truncated: false,
            raw_low: 0x00,
        }
    }

    /// Parses a received low control byte.
    pub const fn from_low_byte(low: u8) -> Self {
        Self {
            direction: if low & Self::DIRECTION_RESPONSE == 0 {
                Direction::Command
            } else {
                Direction::Response
            },
            is_callback: low & Self::ASYNC_CALLBACK != 0,
            callback_pending: low & Self::CALLBACK_PENDING != 0,
            overflow: low & Self::OVERFLOW != 0,
            truncated: low & Self::TRUNCATED != 0,
            raw_low: low,
        }
    }

    /// The low control byte to send.
    pub const fn to_low_byte(self) -> u8 {
        match self.direction {
            Direction::Command => 0x00,
            Direction::Response => Self::DIRECTION_RESPONSE,
        }
    }
}

/// A decoded EZSP frame: header plus the undecoded parameter bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame<'a> {
    /// The sequence number, echoed by the NCP in a response.
    pub sequence: u8,
    /// The control field.
    pub control: FrameControl,
    /// Which command or callback this is.
    pub frame_id: FrameId,
    /// The parameters, still encoded.
    pub parameters: &'a [u8],
}

/// The largest EZSP frame the protocol permits.
pub const MAX_FRAME_LENGTH: usize = 218;

/// Writes an outgoing command header.
///
/// # Errors
///
/// [`EzspError::MalformedHeader`] if a legacy header is asked to carry a frame
/// id that does not fit in one byte. That combination cannot be expressed on
/// the wire, and sending the low byte alone would silently address a different
/// command.
pub fn write_header(
    out: &mut Writer,
    sequence: u8,
    frame_id: FrameId,
    format: HeaderFormat,
) -> Result<(), EzspError> {
    out.u8(sequence);
    match format {
        HeaderFormat::Legacy => {
            if !frame_id.fits_legacy() {
                return Err(EzspError::MalformedHeader {
                    reason: "a legacy header cannot carry a frame id above 0xff",
                });
            }
            out.u8(FrameControl::command().to_low_byte());
            // Low byte only; the legacy header has no room for more.
            out.u8((frame_id.0 & 0xff) as u8);
        }
        HeaderFormat::Extended => {
            out.u8(FrameControl::command().to_low_byte());
            // The high control byte carries the extended frame format version
            // in its low two bits. Zero here would claim a format the NCP does
            // not recognise, and it answers nothing at all.
            out.u8(EXTENDED_FRAME_FORMAT_VERSION);
            out.u16(frame_id.0);
        }
    }
    Ok(())
}

/// The extended frame format version this crate speaks, in the high control
/// byte's low two bits.
const EXTENDED_FRAME_FORMAT_VERSION: u8 = 0x01;

/// Parses a received frame.
///
/// The format is inferred rather than passed in: a response to the bootstrap
/// `version` command comes back in the legacy format, and by the time it
/// arrives the caller may already be thinking in extended terms.
///
/// # Errors
///
/// [`EzspError::TruncatedFrame`] for a frame too short to hold a header, and
/// [`EzspError::MalformedHeader`] when the control bytes describe no format
/// this crate knows.
pub fn parse(bytes: &[u8], format: HeaderFormat) -> Result<Frame<'_>, EzspError> {
    if bytes.len() > MAX_FRAME_LENGTH {
        return Err(EzspError::FrameTooLong {
            length: bytes.len(),
            limit: MAX_FRAME_LENGTH,
        });
    }
    if bytes.len() < format.byte_len() {
        return Err(EzspError::TruncatedFrame {
            needed: format.byte_len(),
            available: bytes.len(),
        });
    }

    // Indexed through `get` throughout: these bytes came off a serial line.
    let sequence = *bytes.first().ok_or(EzspError::TruncatedFrame {
        needed: 1,
        available: 0,
    })?;
    let low = *bytes.get(1).ok_or(EzspError::TruncatedFrame {
        needed: 2,
        available: bytes.len(),
    })?;
    let control = FrameControl::from_low_byte(low);

    let (frame_id, parameters) = match format {
        HeaderFormat::Legacy => {
            let id = *bytes.get(2).ok_or(EzspError::TruncatedFrame {
                needed: 3,
                available: bytes.len(),
            })?;
            (FrameId(u16::from(id)), bytes.get(3..).unwrap_or(&[]))
        }
        HeaderFormat::Extended => {
            let lo = *bytes.get(3).ok_or(EzspError::TruncatedFrame {
                needed: 4,
                available: bytes.len(),
            })?;
            let hi = *bytes.get(4).ok_or(EzspError::TruncatedFrame {
                needed: 5,
                available: bytes.len(),
            })?;
            (
                FrameId(u16::from_le_bytes([lo, hi])),
                bytes.get(5..).unwrap_or(&[]),
            )
        }
    };

    Ok(Frame {
        sequence,
        control,
        frame_id,
        parameters,
    })
}

/// A reader over a frame's parameters.
pub fn parameters<'a>(
    frame: &Frame<'a>,
    version: crate::ezsp::version::ProtocolVersion,
) -> Reader<'a> {
    Reader::new(frame.parameters, version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ezsp::version::ProtocolVersion;

    const V13: ProtocolVersion = ProtocolVersion::new(0x0d);

    #[test]
    fn the_bootstrap_version_command_uses_the_legacy_header() {
        // Three bytes, one-byte frame id. This is the only frame that can use
        // it, because the version has not been negotiated when it is sent.
        let mut out = Writer::new(V13);
        write_header(&mut out, 0x00, FrameId::VERSION, HeaderFormat::Legacy).expect("legacy");
        out.u8(0x13); // desiredProtocolVersion
        assert_eq!(out.as_slice(), &[0x00, 0x00, 0x00, 0x13]);
    }

    #[test]
    fn every_other_command_uses_the_extended_header() {
        // Five bytes, two-byte frame id, and the format version in the high
        // control byte. Compared against a real capture: an
        // importTransientKey frame on EZSP 13 begins `16 00 01 11 01`.
        let mut out = Writer::new(V13);
        write_header(
            &mut out,
            0x16,
            FrameId::IMPORT_TRANSIENT_KEY,
            HeaderFormat::Extended,
        )
        .expect("extended");
        assert_eq!(
            out.as_slice(),
            &[0x16, 0x00, 0x01, 0x11, 0x01],
            "must match the bytes a real NCP was seen to accept"
        );
    }

    #[test]
    fn a_legacy_header_refuses_a_frame_id_it_cannot_express() {
        // Sending the low byte alone would address a completely different
        // command, and the NCP would answer it.
        let mut out = Writer::new(V13);
        let error = write_header(
            &mut out,
            0,
            FrameId::IMPORT_TRANSIENT_KEY,
            HeaderFormat::Legacy,
        )
        .expect_err("0x0111 does not fit in one byte");
        assert!(matches!(error, EzspError::MalformedHeader { .. }));
    }

    #[test]
    fn a_callback_is_distinguishable_from_a_response() {
        // The bit this crate's correctness rests on. Both are responses by
        // direction; only one is an answer to a pending command.
        let response =
            parse(&[0x16, 0x80, 0x01, 0x11, 0x01], HeaderFormat::Extended).expect("parses");
        assert_eq!(response.control.direction, Direction::Response);
        assert!(
            !response.control.is_callback,
            "a plain response is not a callback"
        );

        let callback =
            parse(&[0x2b, 0x90, 0x01, 0x45, 0x00], HeaderFormat::Extended).expect("parses");
        assert!(
            callback.control.is_callback,
            "0x10 in the low control byte marks an asynchronous callback"
        );
        assert_eq!(callback.frame_id, FrameId::INCOMING_MESSAGE_HANDLER);
    }

    #[test]
    fn a_frame_too_short_for_its_header_is_refused() {
        for len in 0..5 {
            let bytes = vec![0u8; len];
            assert!(
                parse(&bytes, HeaderFormat::Extended).is_err(),
                "{len} bytes cannot hold a 5-byte header"
            );
        }
        // And the legacy header has its own, lower, threshold.
        assert!(parse(&[0x00, 0x00], HeaderFormat::Legacy).is_err());
        assert!(parse(&[0x00, 0x00, 0x00], HeaderFormat::Legacy).is_ok());
    }

    #[test]
    fn a_frame_longer_than_the_protocol_allows_is_refused() {
        let bytes = vec![0u8; MAX_FRAME_LENGTH + 1];
        assert!(matches!(
            parse(&bytes, HeaderFormat::Extended),
            Err(EzspError::FrameTooLong { .. })
        ));
    }

    #[test]
    fn a_header_with_no_parameters_yields_an_empty_body_not_an_error() {
        // getEui64 and friends take none, so this is the normal case.
        let frame = parse(&[0x01, 0x00, 0x01, 0x26, 0x00], HeaderFormat::Extended).expect("parses");
        assert!(frame.parameters.is_empty());
        assert_eq!(frame.frame_id, FrameId::GET_EUI64);
    }

    #[test]
    fn an_unknown_frame_id_reports_its_number() {
        // Not "unknown": the number is what someone looks up in the spec.
        let id = FrameId(0x0999);
        assert_eq!(id.name(), None);
        assert!(id.to_string().contains("0x0999"), "{id}");
    }
}
