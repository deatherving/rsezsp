//! Typed EZSP commands.
//!
//! # How a command is defined
//!
//! A command is a request type, a response type, a frame id, and the version
//! range it exists in. The [`Command`] trait ties those together so adding one
//! is a small, uniform piece of work and the plumbing cannot drift per command.
//!
//! Every command below carries, in its documentation:
//!
//! * its frame id
//! * the EZSP versions it applies to, where that matters
//! * where the definition came from
//! * whether it has been confirmed against real hardware
//!
//! That last line is the important one. "Implemented" and "seen to work on a
//! device" are different claims, and conflating them is how a library acquires
//! commands nobody has ever successfully sent.

use crate::ezsp::codec::{EzspDecode, EzspEncode, Reader, Writer};
use crate::ezsp::error::EzspError;
use crate::ezsp::frame::FrameId;
use crate::ezsp::version::ProtocolVersion;
use crate::types::aps::{ApsFrame, UnicastType};
use crate::types::network::{ConfigId, Decision, Eui64, NetworkInitBitmask, PolicyId};
use crate::types::security::{SecurityKey, SecurityManFlags};
use crate::types::status::SlStatus;

/// One EZSP command.
pub trait Command: EzspEncode {
    /// The decoded answer.
    type Response: EzspDecode;

    /// The frame id on the wire.
    const ID: FrameId;

    /// Whether the negotiated version has this command.
    ///
    /// Defaults to "any version this crate speaks". Overridden by commands
    /// that came or went at a version boundary, so using one outside its range
    /// is a typed error rather than a frame the NCP silently ignores.
    fn is_available(version: ProtocolVersion) -> bool {
        version.is_supported()
    }
}

/// `version` — negotiate the protocol version. Frame id `0x0000`.
///
/// Always the first command sent, and the only one that may use the legacy
/// header -- the extended format cannot be used before the version it belongs
/// to has been agreed.
///
/// **Only the first one.** A `version` command sent in the legacy format
/// *after* negotiation makes the NCP forget the negotiated version: every
/// extended command afterwards is answered `INVALID_COMMAND` with
/// `ERROR_VERSION_NOT_SET`. Found on hardware, and the reason the header
/// format is chosen by the connection rather than by the command.
///
/// Reference: Silicon Labs UG100; cross-checked against `zigbee-herdsman`.
/// Hardware: confirmed (EZSP 13, `EmberZNet` 7.4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Version {
    /// The version the host would like to speak.
    pub desired: ProtocolVersion,
}

/// What the NCP answered to `version`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionResponse {
    /// The version the NCP will actually speak. Everything after this is
    /// encoded for it, whether or not it is what was asked for.
    pub protocol_version: ProtocolVersion,
    /// Which stack: 2 is `EmberZNet` mesh.
    pub stack_type: u8,
    /// The stack's own version number.
    pub stack_version: u16,
}

impl EzspEncode for Version {
    fn encode(&self, out: &mut Writer) -> Result<(), EzspError> {
        out.u8(self.desired.raw());
        Ok(())
    }
}

impl EzspDecode for VersionResponse {
    fn decode(input: &mut Reader<'_>) -> Result<Self, EzspError> {
        Ok(Self {
            protocol_version: ProtocolVersion::new(input.u8()?),
            stack_type: input.u8()?,
            stack_version: input.u16()?,
        })
    }
}

impl Command for Version {
    type Response = VersionResponse;
    const ID: FrameId = FrameId::VERSION;

    fn is_available(_version: ProtocolVersion) -> bool {
        // Available at every version by definition: it is how the version is
        // discovered, so refusing it on an unsupported version would make an
        // unknown NCP undiagnosable.
        true
    }
}

/// `getEui64` — the NCP's own permanent address. Frame id `0x0026`.
///
/// Reference: UG100; cross-checked against `zigbee-herdsman`.
/// Hardware: confirmed (EZSP 13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetEui64;

/// The NCP's address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetEui64Response {
    /// The address.
    pub eui64: Eui64,
}

impl EzspEncode for GetEui64 {
    fn encode(&self, _out: &mut Writer) -> Result<(), EzspError> {
        Ok(())
    }
}

impl EzspDecode for GetEui64Response {
    fn decode(input: &mut Reader<'_>) -> Result<Self, EzspError> {
        Ok(Self {
            eui64: Eui64::decode(input)?,
        })
    }
}

impl Command for GetEui64 {
    type Response = GetEui64Response;
    const ID: FrameId = FrameId::GET_EUI64;
}

/// `networkInit` — resume a network held in the NCP's tokens. Frame id `0x0017`.
///
/// Not optional at startup, and not merely an optimisation: EZSP reports "no
/// network" from `networkState` until this has run, *even when a network is
/// stored*. A host that reads that and forms a new network destroys the
/// existing one and orphans every joined device.
///
/// Reference: UG100 ("should be called on startup whether or not the node was
/// previously part of a network"); cross-checked against `zigbee-herdsman`.
/// Hardware: confirmed (EZSP 13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkInit {
    /// Initialisation flags.
    pub bitmask: NetworkInitBitmask,
}

/// Whether a stored network was resumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkInitResponse {
    /// `OK` when a network was resumed; a failure status when there was none.
    /// The distinction is the authoritative answer to "does this NCP have a
    /// network", and is more reliable than `networkState`.
    pub status: SlStatus,
}

impl EzspEncode for NetworkInit {
    fn encode(&self, out: &mut Writer) -> Result<(), EzspError> {
        self.bitmask.encode(out)
    }
}

impl EzspDecode for NetworkInitResponse {
    fn decode(input: &mut Reader<'_>) -> Result<Self, EzspError> {
        Ok(Self {
            status: SlStatus::decode(input)?,
        })
    }
}

impl Command for NetworkInit {
    type Response = NetworkInitResponse;
    const ID: FrameId = FrameId::NETWORK_INIT;
}

/// `permitJoining` — open the network for joining. Frame id `0x0022`.
///
/// This opens the MAC association window and nothing more. Whether a device is
/// *admitted*, and whether it is given the network key, is decided by the
/// trust-centre policy — so `permitJoining` alone produces a window in which
/// devices try and are silently refused. A Zigbee 3.0 device additionally
/// needs a transient commissioning key in place; see [`ImportTransientKey`].
///
/// Reference: UG100; cross-checked against `zigbee-herdsman`.
/// Hardware: not yet confirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PermitJoining {
    /// How long to stay open, in seconds.
    ///
    /// Zero closes the window. 255 means *forever* in the protocol, which is a
    /// footgun rather than a feature — a network left permanently open admits
    /// anything that asks — so [`Self::for_seconds`] clamps to 254 and this
    /// field is only 255 if a caller writes it deliberately.
    pub duration: u8,
}

impl PermitJoining {
    /// The largest duration that is not "forever".
    pub const MAX_DURATION: u8 = 254;

    /// Opens the window for `seconds`, clamped away from the forever value.
    ///
    /// A duration longer than the maximum is clamped rather than rejected: the
    /// caller asked for "a long time", and 254 seconds is that answer, where
    /// 255 is a different and far more dangerous one.
    pub const fn for_seconds(seconds: u8) -> Self {
        Self {
            duration: if seconds > Self::MAX_DURATION {
                Self::MAX_DURATION
            } else {
                seconds
            },
        }
    }

    /// Closes the window.
    pub const fn close() -> Self {
        Self { duration: 0 }
    }
}

/// Whether the window changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PermitJoiningResponse {
    /// The NCP's answer.
    pub status: SlStatus,
}

impl EzspEncode for PermitJoining {
    fn encode(&self, out: &mut Writer) -> Result<(), EzspError> {
        out.u8(self.duration);
        Ok(())
    }
}

impl EzspDecode for PermitJoiningResponse {
    fn decode(input: &mut Reader<'_>) -> Result<Self, EzspError> {
        Ok(Self {
            status: SlStatus::decode(input)?,
        })
    }
}

impl Command for PermitJoining {
    type Response = PermitJoiningResponse;
    const ID: FrameId = FrameId::PERMIT_JOINING;
}

/// `setConfigurationValue` — set a stack configuration item. Frame id `0x0053`.
///
/// Must be sent before the network comes up; EZSP refuses afterwards.
///
/// Reference: UG100; cross-checked against `zigbee-herdsman`.
/// Hardware: confirmed (EZSP 13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetConfigurationValue {
    /// Which item.
    pub config_id: ConfigId,
    /// The value.
    pub value: u16,
}

/// Whether the item was set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetConfigurationValueResponse {
    /// The NCP's answer.
    pub status: SlStatus,
}

impl EzspEncode for SetConfigurationValue {
    fn encode(&self, out: &mut Writer) -> Result<(), EzspError> {
        out.u8(self.config_id.0);
        out.u16(self.value);
        Ok(())
    }
}

impl EzspDecode for SetConfigurationValueResponse {
    fn decode(input: &mut Reader<'_>) -> Result<Self, EzspError> {
        Ok(Self {
            status: SlStatus::decode(input)?,
        })
    }
}

impl Command for SetConfigurationValue {
    type Response = SetConfigurationValueResponse;
    const ID: FrameId = FrameId::SET_CONFIGURATION_VALUE;
}

/// `setPolicy` — set a stack decision policy. Frame id `0x0055`.
///
/// The trust-centre policy is the one that decides whether any device can
/// join. See [`Decision`] for why its values are named as individual bits
/// rather than as an enum of composites.
///
/// Reference: UG100; cross-checked against `zigbee-herdsman`.
/// Hardware: confirmed (EZSP 13) — a device joins with the trust-centre policy
/// set to `ALLOW_JOINS | ALLOW_UNSECURED_REJOINS` and does not with zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetPolicy {
    /// Which policy.
    pub policy_id: PolicyId,
    /// The decision.
    pub decision: Decision,
}

/// Whether the policy was set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetPolicyResponse {
    /// The NCP's answer.
    pub status: SlStatus,
}

impl EzspEncode for SetPolicy {
    fn encode(&self, out: &mut Writer) -> Result<(), EzspError> {
        out.u8(self.policy_id.0);
        out.u8(self.decision.0);
        Ok(())
    }
}

impl EzspDecode for SetPolicyResponse {
    fn decode(input: &mut Reader<'_>) -> Result<Self, EzspError> {
        Ok(Self {
            status: SlStatus::decode(input)?,
        })
    }
}

impl Command for SetPolicy {
    type Response = SetPolicyResponse;
    const ID: FrameId = FrameId::SET_POLICY;
}

/// `addEndpoint` — register an application endpoint. Frame id `0x0002`.
///
/// Must happen before the network comes up. Without it the NCP has nowhere to
/// deliver application traffic and answers an active-endpoint request with an
/// empty list, so the coordinator looks like a node with no functionality.
///
/// Reference: UG100; cross-checked against `zigbee-herdsman`.
/// Hardware: confirmed (EZSP 13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddEndpoint {
    /// The endpoint number.
    pub endpoint: u8,
    /// Application profile.
    pub profile_id: u16,
    /// Device id within the profile.
    pub device_id: u16,
    /// Device version.
    pub app_flags: u8,
    /// Clusters this endpoint serves.
    pub input_clusters: Vec<u16>,
    /// Clusters this endpoint uses.
    pub output_clusters: Vec<u16>,
}

/// Whether the endpoint was registered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddEndpointResponse {
    /// The NCP's answer.
    pub status: SlStatus,
}

impl EzspEncode for AddEndpoint {
    fn encode(&self, out: &mut Writer) -> Result<(), EzspError> {
        out.u8(self.endpoint);
        out.u16(self.profile_id);
        out.u16(self.device_id);
        out.u8(self.app_flags);
        // Both counts first, then both lists. Interleaving them -- count,
        // list, count, list -- is the natural guess and produces a frame the
        // NCP rejects.
        let inputs =
            u8::try_from(self.input_clusters.len()).map_err(|_| EzspError::PayloadTooLong {
                length: self.input_clusters.len(),
                limit: usize::from(u8::MAX),
            })?;
        let outputs =
            u8::try_from(self.output_clusters.len()).map_err(|_| EzspError::PayloadTooLong {
                length: self.output_clusters.len(),
                limit: usize::from(u8::MAX),
            })?;
        out.u8(inputs);
        out.u8(outputs);
        for cluster in &self.input_clusters {
            out.u16(*cluster);
        }
        for cluster in &self.output_clusters {
            out.u16(*cluster);
        }
        Ok(())
    }
}

impl EzspDecode for AddEndpointResponse {
    fn decode(input: &mut Reader<'_>) -> Result<Self, EzspError> {
        Ok(Self {
            status: SlStatus::decode(input)?,
        })
    }
}

impl Command for AddEndpoint {
    type Response = AddEndpointResponse;
    const ID: FrameId = FrameId::ADD_ENDPOINT;
}

/// `sendUnicast` — send an APS frame to one device. Frame id `0x0034`.
///
/// The message tag is **one byte below EZSP 14 and two at or above it**. Since
/// the payload follows it, the wrong width shifts every remaining byte and the
/// NCP reads the payload's first byte as part of the tag.
///
/// Reference: UG100; width boundary cross-checked against `zigbee-herdsman`.
/// Hardware: confirmed (EZSP 13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendUnicast {
    /// How the destination is addressed.
    pub unicast_type: UnicastType,
    /// The destination, or an index into a table depending on the type.
    pub index_or_destination: u16,
    /// The APS header.
    pub aps_frame: ApsFrame,
    /// A tag the matching `messageSent` callback will echo.
    pub message_tag: u16,
    /// The application payload.
    pub message: Vec<u8>,
}

/// The NCP's acceptance of a unicast.
///
/// Not delivery: the frame is queued, and whether it arrived is reported later
/// by the `messageSent` callback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendUnicastResponse {
    /// Whether the NCP accepted it.
    pub status: SlStatus,
    /// The APS sequence the NCP assigned.
    pub aps_sequence: u8,
}

impl EzspEncode for SendUnicast {
    fn encode(&self, out: &mut Writer) -> Result<(), EzspError> {
        self.unicast_type.encode(out)?;
        out.u16(self.index_or_destination);
        self.aps_frame.encode(out)?;
        if out.version().has_wide_message_tag() {
            out.u16(self.message_tag);
        } else {
            // Truncated deliberately, not by accident: below EZSP 14 the field
            // is one byte, and a tag that does not fit simply cannot be
            // distinguished by this firmware.
            out.u8((self.message_tag & 0xff) as u8);
        }
        out.length_prefixed(&self.message)
    }
}

impl EzspDecode for SendUnicastResponse {
    fn decode(input: &mut Reader<'_>) -> Result<Self, EzspError> {
        Ok(Self {
            status: SlStatus::decode(input)?,
            aps_sequence: input.u8()?,
        })
    }
}

impl Command for SendUnicast {
    type Response = SendUnicastResponse;
    const ID: FrameId = FrameId::SEND_UNICAST;
}

/// `importTransientKey` — install a short-lived commissioning key. Frame id
/// `0x0111`.
///
/// Needed for Zigbee 3.0 joining: a device without an install code protects the
/// one exchange in which it receives the network key with the well-known
/// trust-centre link key, and the NCP must hold that key while the join window
/// is open.
///
/// The trailing flags byte exists **below EZSP 14 only**. Sending it at 14 or
/// above, or omitting it below, produces a frame the NCP answers `OK` to while
/// installing a key parsed from the wrong bytes — after which a device joins
/// and can never finish commissioning.
///
/// Reference: UG100; width boundary cross-checked against `zigbee-herdsman` and
/// against a wire capture from a working stack (30-byte frame on EZSP 13).
/// Hardware: confirmed (EZSP 13) — a valve commissions with this and rejoins
/// indefinitely without it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportTransientKey {
    /// Which device the key is for. [`Eui64::WILDCARD`] for any.
    pub eui64: Eui64,
    /// The key.
    pub key: SecurityKey,
    /// Flags. Only sent below EZSP 14.
    pub flags: SecurityManFlags,
}

/// Whether the key was installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportTransientKeyResponse {
    /// The NCP's answer. Always four bytes for this command, at every version.
    pub status: SlStatus,
}

impl EzspEncode for ImportTransientKey {
    fn encode(&self, out: &mut Writer) -> Result<(), EzspError> {
        self.eui64.encode(out)?;
        self.key.encode(out)?;
        if out.version().has_transient_key_flags() {
            out.u8(self.flags.0);
        }
        Ok(())
    }
}

impl EzspDecode for ImportTransientKeyResponse {
    fn decode(input: &mut Reader<'_>) -> Result<Self, EzspError> {
        // Four bytes regardless of version: this is a security-manager command
        // and returns an `sl_status_t` even on firmware where other commands
        // return a one-byte `EmberStatus`.
        Ok(Self {
            status: SlStatus(input.u32()?),
        })
    }
}

impl Command for ImportTransientKey {
    type Response = ImportTransientKeyResponse;
    const ID: FrameId = FrameId::IMPORT_TRANSIENT_KEY;
}

#[cfg(test)]
mod tests {
    use super::*;

    const V13: ProtocolVersion = ProtocolVersion::new(0x0d);
    const V14: ProtocolVersion = ProtocolVersion::new(0x0e);

    fn encoded<C: Command>(command: &C, version: ProtocolVersion) -> Vec<u8> {
        let mut out = Writer::new(version);
        command.encode(&mut out).expect("encodes");
        out.into_vec()
    }

    #[test]
    fn version_is_available_even_on_a_version_we_cannot_speak() {
        // It is how the version is discovered. Refusing it on an unsupported
        // NCP would make an unknown device undiagnosable.
        assert!(Version::is_available(ProtocolVersion::new(0x04)));
        assert!(!GetEui64::is_available(ProtocolVersion::new(0x04)));
    }

    #[test]
    fn the_transient_key_flags_byte_appears_only_below_ezsp_fourteen() {
        // The exact bug this crate was built after. Below 14 the frame is
        // 8 + 16 + 1 = 25 bytes; at 14 and above it is 24.
        let command = ImportTransientKey {
            eui64: Eui64::WILDCARD,
            key: SecurityKey::ZIGBEE_ALLIANCE_09,
            flags: SecurityManFlags::NONE,
        };

        let v13 = encoded(&command, V13);
        assert_eq!(v13.len(), 25, "v13 carries the flags byte");
        assert_eq!(
            &v13[..8],
            &[0xff; 8],
            "the wildcard address comes first, little-endian"
        );
        assert_eq!(&v13[8..24], b"ZigBeeAlliance09");
        assert_eq!(v13.get(24), Some(&0x00), "then the flags byte");

        let v14 = encoded(&command, V14);
        assert_eq!(v14.len(), 24, "v14 dropped the flags byte");
        assert_eq!(&v14[..8], &[0xff; 8]);
        assert_eq!(&v14[8..], b"ZigBeeAlliance09");
    }

    #[test]
    fn the_unicast_message_tag_widens_at_ezsp_fourteen() {
        // The payload follows the tag, so the wrong width shifts every
        // remaining byte and the NCP reads the payload's first byte as tag.
        let command = SendUnicast {
            unicast_type: UnicastType::Direct,
            index_or_destination: 0x1234,
            aps_frame: ApsFrame::default(),
            message_tag: 0x00ab,
            message: vec![0xde, 0xad],
        };

        let v13 = encoded(&command, V13);
        let v14 = encoded(&command, V14);
        assert_eq!(
            v14.len(),
            v13.len() + 1,
            "the only difference is one byte of tag"
        );

        // 1 type + 2 destination + 11 aps = 14 bytes before the tag.
        assert_eq!(v13.get(14), Some(&0xab), "v13: one tag byte");
        assert_eq!(v13.get(15), Some(&0x02), "then the payload length");
        assert_eq!(v14.get(14..16), Some(&[0xab, 0x00][..]), "v14: two, LE");
        assert_eq!(v14.get(16), Some(&0x02));
    }

    #[test]
    fn add_endpoint_sends_both_counts_before_either_list() {
        // The natural guess -- count, list, count, list -- produces a frame
        // the NCP rejects, and the rejection does not say why.
        let command = AddEndpoint {
            endpoint: 1,
            profile_id: 0x0104,
            device_id: 0x0065,
            app_flags: 0,
            input_clusters: vec![0x0000, 0x0006],
            output_clusters: vec![0x0019],
        };
        let bytes = encoded(&command, V13);
        assert_eq!(
            bytes,
            vec![
                0x01, // endpoint
                0x04, 0x01, // profile, LE
                0x65, 0x00, // device id, LE
                0x00, // app flags
                0x02, // input count
                0x01, // output count
                0x00, 0x00, 0x06, 0x00, // inputs
                0x19, 0x00, // outputs
            ]
        );
    }

    #[test]
    fn permit_joining_clamps_away_from_the_forever_value() {
        // 255 means "open forever" in the protocol. A network left permanently
        // open admits anything that asks, so a caller asking for a long window
        // gets the longest bounded one rather than an unbounded one.
        assert_eq!(PermitJoining::for_seconds(60).duration, 60);
        assert_eq!(PermitJoining::for_seconds(254).duration, 254);
        assert_eq!(
            PermitJoining::for_seconds(255).duration,
            254,
            "255 must not be reachable by asking for a long time"
        );
        assert_eq!(PermitJoining::close().duration, 0);

        // But it is still expressible deliberately, because refusing to encode
        // a protocol-legal value would be this crate deciding policy.
        let forever = PermitJoining { duration: 255 };
        assert_eq!(encoded(&forever, V13), vec![0xff]);
    }

    #[test]
    fn permit_joining_encodes_one_byte_and_reads_a_versioned_status() {
        let command = PermitJoining::for_seconds(240);
        assert_eq!(encoded(&command, V13), vec![0xf0]);

        // One byte of status on v13, four on v14: a response decoded at the
        // wrong width either leaves bytes over or reads past the end.
        let mut v13 = Reader::new(&[0x00], V13);
        assert!(
            PermitJoiningResponse::decode(&mut v13)
                .expect("v13")
                .status
                .is_ok()
        );
        let mut v14 = Reader::new(&[0x00], V14);
        assert!(
            PermitJoiningResponse::decode(&mut v14).is_err(),
            "one byte cannot hold a v14 status, and that must be an error"
        );
    }

    #[test]
    fn a_status_response_reads_the_right_width_for_its_version() {
        // The same four bytes decode to different values, and on v13 three
        // bytes are left for the fields that follow.
        let bytes = [0x00, 0x27, 0x00, 0x00];

        let mut v13 = Reader::new(&bytes, V13);
        let response = SendUnicastResponse::decode(&mut v13).expect("v13");
        assert_eq!(response.status, SlStatus::OK);
        assert_eq!(
            response.aps_sequence, 0x27,
            "on v13 the sequence is the byte after a one-byte status"
        );

        let mut v14 = Reader::new(&bytes, V14);
        let response = SendUnicastResponse::decode(&mut v14);
        assert!(
            response.is_err(),
            "on v14 the status eats all four bytes, leaving no sequence -- and \
             that must be an error rather than a fabricated value"
        );
    }

    #[test]
    fn a_version_response_decodes_the_negotiated_version() {
        // Captured shape: protocol 13, stack type 2 (mesh), stack version.
        let bytes = [0x0d, 0x02, 0x44, 0x74];
        let mut reader = Reader::new(&bytes, ProtocolVersion::new(0x04));
        let response = VersionResponse::decode(&mut reader).expect("decodes");
        assert_eq!(response.protocol_version, V13);
        assert_eq!(response.stack_type, 2);
        assert_eq!(response.stack_version, 0x7444);
    }

    #[test]
    fn a_truncated_response_is_an_error_not_a_default() {
        for len in 0..4 {
            let bytes = vec![0u8; len];
            let mut reader = Reader::new(&bytes, ProtocolVersion::new(0x04));
            assert!(
                VersionResponse::decode(&mut reader).is_err(),
                "{len} bytes must not decode into a version"
            );
        }
    }

    #[test]
    fn an_endpoint_with_too_many_clusters_is_refused_not_truncated() {
        let command = AddEndpoint {
            endpoint: 1,
            profile_id: 0x0104,
            device_id: 0x0065,
            app_flags: 0,
            input_clusters: vec![0x0000; 300],
            output_clusters: vec![],
        };
        let mut out = Writer::new(V13);
        assert!(matches!(
            command.encode(&mut out),
            Err(EzspError::PayloadTooLong { .. })
        ));
    }
}
