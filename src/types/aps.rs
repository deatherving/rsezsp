//! The APS frame carried by `sendUnicast` and friends.

use crate::ezsp::codec::{EzspDecode, EzspEncode, Reader, Writer};
use crate::ezsp::error::EzspError;

/// APS transmission options.
///
/// A bitmask, and the bits are not interchangeable across destination kinds.
/// `RETRY` asks for an acknowledgement, which a multicast or broadcast can
/// never produce -- there is no single recipient to send one -- so setting it
/// there makes every send wait out a timeout and then report a delivery failure
/// that did not happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ApsOptions(pub u16);

impl ApsOptions {
    /// No options.
    pub const NONE: Self = Self(0x0000);
    /// Encrypt at the APS layer.
    pub const ENCRYPTION: Self = Self(0x0020);
    /// Retry until acknowledged. Unicast only.
    pub const RETRY: Self = Self(0x0040);
    /// Discover a route if none is known. Unicast only.
    pub const ENABLE_ROUTE_DISCOVERY: Self = Self(0x0100);
    /// Force a fresh route discovery.
    pub const FORCE_ROUTE_DISCOVERY: Self = Self(0x0200);
    /// Include our own EUI64.
    pub const SOURCE_EUI64: Self = Self(0x0400);
    /// Include the destination's EUI64.
    pub const DESTINATION_EUI64: Self = Self(0x0800);
    /// Discover the destination's short address if unknown.
    pub const ENABLE_ADDRESS_DISCOVERY: Self = Self(0x1000);

    /// Combines two option sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Whether an option is present.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// The options a working stack sets for a unicast.
    ///
    /// Without retry a single lost frame reads as an unreachable device;
    /// without route discovery the first message to a device behind a router
    /// fails.
    pub const fn unicast_defaults() -> Self {
        Self(Self::RETRY.0 | Self::ENABLE_ROUTE_DISCOVERY.0)
    }
}

/// An APS frame header.
///
/// Eleven bytes on the wire. Note there is no radius field: `EmberZNet` takes it
/// as a separate argument to the send command rather than inside the frame, and
/// including one here would shift every following field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ApsFrame {
    /// Application profile, e.g. `0x0104` for Home Automation.
    pub profile_id: u16,
    /// Cluster.
    pub cluster_id: u16,
    /// Our endpoint.
    pub source_endpoint: u8,
    /// Their endpoint.
    pub destination_endpoint: u8,
    /// Transmission options.
    pub options: ApsOptions,
    /// Group, for multicast. Zero otherwise.
    ///
    /// A multicast's destination lives *here*, not in the send command's
    /// arguments: `sendMulticast` takes no address and reads the group from the
    /// frame, so a multicast built without it addresses group zero -- which
    /// sends successfully and reaches nobody.
    pub group_id: u16,
    /// APS sequence, assigned by the NCP when sending.
    pub sequence: u8,
}

/// How many bytes an APS frame occupies.
pub const APS_FRAME_LEN: usize = 11;

impl EzspEncode for ApsFrame {
    fn encode(&self, out: &mut Writer) -> Result<(), EzspError> {
        out.u16(self.profile_id);
        out.u16(self.cluster_id);
        out.u8(self.source_endpoint);
        out.u8(self.destination_endpoint);
        out.u16(self.options.0);
        out.u16(self.group_id);
        out.u8(self.sequence);
        Ok(())
    }
}

impl EzspDecode for ApsFrame {
    fn decode(input: &mut Reader<'_>) -> Result<Self, EzspError> {
        Ok(Self {
            profile_id: input.u16()?,
            cluster_id: input.u16()?,
            source_endpoint: input.u8()?,
            destination_endpoint: input.u8()?,
            options: ApsOptions(input.u16()?),
            group_id: input.u16()?,
            sequence: input.u8()?,
        })
    }
}

/// How a unicast is addressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnicastType {
    /// Straight to a short address.
    Direct,
    /// Via an address table entry.
    ViaAddressTable,
    /// Via a binding table entry.
    ViaBinding,
    /// A multicast, addressed by the frame's group.
    Multicast,
    /// A broadcast.
    Broadcast,
}

impl UnicastType {
    /// The wire value.
    pub const fn raw(self) -> u8 {
        match self {
            Self::Direct => 0x00,
            Self::ViaAddressTable => 0x01,
            Self::ViaBinding => 0x02,
            Self::Multicast => 0x03,
            Self::Broadcast => 0x04,
        }
    }
}

impl EzspEncode for UnicastType {
    fn encode(&self, out: &mut Writer) -> Result<(), EzspError> {
        out.u8(self.raw());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ezsp::version::ProtocolVersion;

    const V13: ProtocolVersion = ProtocolVersion::new(0x0d);

    #[test]
    fn an_aps_frame_is_eleven_bytes_and_has_no_radius() {
        // The length is the check that matters: a radius field added here
        // would shift every byte after it, and the NCP would read the payload
        // as part of the header.
        let frame = ApsFrame {
            profile_id: 0x0104,
            cluster_id: 0x0006,
            source_endpoint: 1,
            destination_endpoint: 1,
            options: ApsOptions::unicast_defaults(),
            group_id: 0,
            sequence: 0,
        };
        let mut out = Writer::new(V13);
        frame.encode(&mut out).expect("encodes");
        assert_eq!(out.len(), APS_FRAME_LEN);
        assert_eq!(
            out.as_slice(),
            &[
                0x04, 0x01, 0x06, 0x00, 0x01, 0x01, 0x40, 0x01, 0x00, 0x00, 0x00
            ]
        );
    }

    #[test]
    fn an_aps_frame_round_trips() {
        let frame = ApsFrame {
            profile_id: 0x0000,
            cluster_id: 0x8004,
            source_endpoint: 0,
            destination_endpoint: 0,
            options: ApsOptions(0x0140),
            group_id: 0x1234,
            sequence: 0x27,
        };
        let mut out = Writer::new(V13);
        frame.encode(&mut out).expect("encodes");
        let bytes = out.into_vec();
        let mut reader = Reader::new(&bytes, V13);
        assert_eq!(ApsFrame::decode(&mut reader).expect("decodes"), frame);
        assert!(reader.is_empty(), "decoding must consume exactly the frame");
    }

    #[test]
    fn a_truncated_aps_frame_is_refused_at_every_length() {
        // Ten bytes is a plausible-looking header that is one short.
        for len in 0..APS_FRAME_LEN {
            let bytes = vec![0u8; len];
            let mut reader = Reader::new(&bytes, V13);
            assert!(
                ApsFrame::decode(&mut reader).is_err(),
                "{len} bytes must not decode as an 11-byte frame"
            );
        }
    }

    #[test]
    fn unicast_defaults_carry_retry_and_route_discovery() {
        let options = ApsOptions::unicast_defaults();
        assert!(options.contains(ApsOptions::RETRY));
        assert!(options.contains(ApsOptions::ENABLE_ROUTE_DISCOVERY));
        // And nothing else: an option set here is a decision, not a default
        // to be widened by accident.
        assert_eq!(options.0, 0x0140);
    }
}
