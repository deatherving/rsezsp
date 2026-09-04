//! Network-layer types.

use crate::ezsp::codec::{EzspDecode, EzspEncode, Reader, Writer};
use crate::ezsp::error::EzspError;

/// A 64-bit IEEE address (EUI64).
///
/// Stored big-endian as people write it, and transmitted little-endian as EZSP
/// sends it. Keeping both straight in one place is deliberate: the two forms
/// look identical in a debugger and a mix-up produces an address that is valid,
/// wrong, and byte-reversed -- which reads as a completely different device.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Eui64(u64);

impl Eui64 {
    /// The wildcard address, used where a command means "any device".
    pub const WILDCARD: Self = Self(u64::MAX);

    /// From a `u64` written the way the address is printed.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// The value, in print order.
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// The bytes as EZSP carries them: least significant first.
    pub const fn to_wire(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }

    /// From the bytes as EZSP carries them.
    pub const fn from_wire(bytes: [u8; 8]) -> Self {
        Self(u64::from_le_bytes(bytes))
    }
}

impl core::fmt::Display for Eui64 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:#018x}", self.0)
    }
}

impl core::fmt::Debug for Eui64 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Same as `Display`, not the derived form. A derived `Debug` prints the
        // inner `u64` in decimal, and a Zigbee address in decimal is unusable:
        // it cannot be compared against a label, a log line from another
        // implementation, or a datasheet. Noticed when a real join callback
        // reported `Eui64(11871831752037302271)`.
        write!(f, "{self}")
    }
}

impl EzspEncode for Eui64 {
    fn encode(&self, out: &mut Writer) -> Result<(), EzspError> {
        out.bytes(&self.to_wire());
        Ok(())
    }
}

impl EzspDecode for Eui64 {
    fn decode(input: &mut Reader<'_>) -> Result<Self, EzspError> {
        Ok(Self::from_wire(input.array::<8>()?))
    }
}

/// A 16-bit network (short) address.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct NodeId(pub u16);

impl NodeId {
    /// The coordinator is always zero.
    pub const COORDINATOR: Self = Self(0x0000);
    /// Broadcast to every device.
    pub const BROADCAST_ALL: Self = Self(0xffff);
    /// Broadcast to devices whose radio is on when idle.
    pub const BROADCAST_RX_ON_WHEN_IDLE: Self = Self(0xfffd);
    /// Broadcast to routers and the coordinator.
    pub const BROADCAST_ROUTERS: Self = Self(0xfffc);
}

impl core::fmt::Debug for NodeId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Hex for the same reason: short addresses are written and discussed in
        // hex everywhere, and `0x3a41` is recognisable where `14913` is not.
        write!(f, "{:#06x}", self.0)
    }
}

impl core::fmt::Display for NodeId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:#06x}", self.0)
    }
}

impl EzspEncode for NodeId {
    fn encode(&self, out: &mut Writer) -> Result<(), EzspError> {
        out.u16(self.0);
        Ok(())
    }
}

impl EzspDecode for NodeId {
    fn decode(input: &mut Reader<'_>) -> Result<Self, EzspError> {
        Ok(Self(input.u16()?))
    }
}

/// Flags for `networkInit`.
///
/// A bitmask rather than an enum: the values combine, and the one that matters
/// in practice is `PARENT_INFO_IN_TOKEN`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NetworkInitBitmask(pub u16);

impl NetworkInitBitmask {
    /// No flags.
    pub const NONE: Self = Self(0x0000);
    /// Restore an end device's parent from persistent storage.
    pub const PARENT_INFO_IN_TOKEN: Self = Self(0x0001);
    /// Rejoin as an end device on failure.
    pub const END_DEVICE_REJOIN_ON_REBOOT: Self = Self(0x0002);

    /// Both flags set.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl EzspEncode for NetworkInitBitmask {
    fn encode(&self, out: &mut Writer) -> Result<(), EzspError> {
        out.u16(self.0);
        Ok(())
    }
}

/// A configuration item settable with `setConfigurationValue`.
///
/// Only the items with a known effect are named. The type carries the raw id so
/// an unnamed one can still be set, because the alternative is that a caller
/// with a datasheet cannot use this crate until someone adds a constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConfigId(pub u8);

impl ConfigId {
    /// `EZSP_CONFIG_STACK_PROFILE`. Must be 2 for `ZigBee` Pro, and it is
    /// advertised in every beacon: a device scanning for a network reads it and
    /// will not attempt to join if it is wrong.
    pub const STACK_PROFILE: Self = Self(0x0c);
    /// `EZSP_CONFIG_SECURITY_LEVEL`. Standard security is 5, also advertised
    /// in beacons.
    pub const SECURITY_LEVEL: Self = Self(0x0d);
    /// `EZSP_CONFIG_MAX_HOPS`.
    pub const MAX_HOPS: Self = Self(0x10);
    /// `EZSP_CONFIG_MAX_END_DEVICE_CHILDREN`. The end-device capacity a
    /// joining device reads out of the beacon.
    pub const MAX_END_DEVICE_CHILDREN: Self = Self(0x11);
    /// `EZSP_CONFIG_INDIRECT_TRANSMISSION_TIMEOUT`, in milliseconds.
    pub const INDIRECT_TRANSMISSION_TIMEOUT: Self = Self(0x12);
    /// `EZSP_CONFIG_END_DEVICE_POLL_TIMEOUT`.
    pub const END_DEVICE_POLL_TIMEOUT: Self = Self(0x13);
    /// `EZSP_CONFIG_TRUST_CENTER_ADDRESS_CACHE_SIZE`.
    pub const TRUST_CENTER_ADDRESS_CACHE_SIZE: Self = Self(0x19);
    /// `EZSP_CONFIG_KEY_TABLE_SIZE`.
    pub const KEY_TABLE_SIZE: Self = Self(0x1e);
    /// `EZSP_CONFIG_APS_UNICAST_MESSAGE_COUNT`.
    pub const APS_UNICAST_MESSAGE_COUNT: Self = Self(0x03);
}

/// A policy settable with `setPolicy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyId(pub u8);

impl PolicyId {
    /// Whether and how a device is admitted to the network.
    pub const TRUST_CENTER: Self = Self(0x00);
    /// Whether a remote device may change our binding table.
    pub const BINDING_MODIFICATION: Self = Self(0x01);
    /// Whether the host supplies replies to unicasts.
    pub const UNICAST_REPLIES: Self = Self(0x02);
    /// Whether message contents come back in the sent callback.
    pub const MESSAGE_CONTENTS_IN_CALLBACK: Self = Self(0x04);
    /// How to answer a device asking for the trust-centre link key.
    pub const TC_KEY_REQUEST: Self = Self(0x05);
    /// How to answer a device asking for an application link key.
    pub const APP_KEY_REQUEST: Self = Self(0x06);
}

/// A decision value for [`PolicyId`].
///
/// Deliberately **not** an enum of named constants for the trust-centre policy.
/// On `EmberZNet` 7.x that field is an `EmberDecisionBitmask` whose bits combine,
/// while the pre-EZSP-8 `EzspDecisionId` gave the same numbers unrelated
/// meanings -- `ALLOW_JOINS` was `0x00`, which modern firmware reads as
/// "default configuration", meaning deny. A library offering that name for that
/// value sets the policy to deny while its own log line says allow. So the
/// bitmask bits are named individually and combined explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Decision(pub u8);

impl Decision {
    /// Trust-centre bitmask: admit a joining device with no link key yet.
    pub const ALLOW_JOINS: Self = Self(0x01);
    /// Trust-centre bitmask: admit an unsecured rejoin.
    ///
    /// A sleepy device that lost its parent -- a battery change, or a wake
    /// outside its poll timeout -- comes back this way. Without the bit it
    /// never returns, which reads as a device that paired once and then died.
    pub const ALLOW_UNSECURED_REJOINS: Self = Self(0x02);
    /// Trust-centre bitmask: send the network key in the clear.
    pub const SEND_KEY_IN_CLEAR: Self = Self(0x04);
    /// Trust-centre bitmask: joins must use an install code.
    pub const JOINS_USE_INSTALL_CODE_KEY: Self = Self(0x10);

    /// `TC_KEY_REQUEST`: answer with the current link key.
    pub const ALLOW_TC_KEY_REQUEST_SAME_KEY: Self = Self(0x51);
    /// `TC_KEY_REQUEST`: refuse.
    pub const DENY_TC_KEY_REQUESTS: Self = Self(0x50);
    /// `APP_KEY_REQUEST`: refuse.
    pub const DENY_APP_KEY_REQUESTS: Self = Self(0x60);
    /// `BINDING_MODIFICATION`: allow only for valid endpoints and clusters.
    pub const CHECK_BINDING_MODIFICATIONS: Self = Self(0x12);

    /// Combines two bitmask bits.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ezsp::version::ProtocolVersion;

    const V13: ProtocolVersion = ProtocolVersion::new(0x0d);

    #[test]
    fn an_ieee_address_goes_out_little_endian() {
        // The mix-up that produces a valid, wrong, byte-reversed address --
        // which reads as a completely different device. Checked against the
        // bytes, not just round-tripped.
        let address = Eui64::new(0x94a0_81ff_fed9_6e5c);
        assert_eq!(
            address.to_wire(),
            [0x5c, 0x6e, 0xd9, 0xfe, 0xff, 0x81, 0xa0, 0x94]
        );
        assert_eq!(Eui64::from_wire(address.to_wire()), address);
        assert_eq!(address.to_string(), "0x94a081fffed96e5c");
    }

    #[test]
    fn addresses_print_in_hex_in_both_forms() {
        // A derived `Debug` prints the inner integer in decimal, and an
        // address in decimal cannot be compared against a device label, a log
        // line from another implementation, or a datasheet. Noticed when a
        // real join callback reported `Eui64(11871831752037302271)`.
        let address = Eui64::new(0xa4c1_3814_2d62_ffff);
        assert_eq!(format!("{address}"), "0xa4c138142d62ffff");
        assert_eq!(format!("{address:?}"), "0xa4c138142d62ffff");

        let node = NodeId(14913);
        assert_eq!(format!("{node:?}"), "0x3a41");
        assert_eq!(format!("{node}"), "0x3a41");
    }

    #[test]
    fn the_wildcard_address_is_all_ones() {
        assert_eq!(Eui64::WILDCARD.to_wire(), [0xff; 8]);
    }

    #[test]
    fn an_ieee_address_round_trips_through_the_codec() {
        let address = Eui64::new(0xa4c1_3814_2d62_ffff);
        let mut out = Writer::new(V13);
        address.encode(&mut out).expect("encodes");
        let bytes = out.into_vec();
        assert_eq!(bytes.len(), 8);
        let mut reader = Reader::new(&bytes, V13);
        assert_eq!(Eui64::decode(&mut reader).expect("decodes"), address);
    }

    #[test]
    fn a_truncated_ieee_address_is_refused() {
        let mut reader = Reader::new(&[0x01, 0x02, 0x03], V13);
        assert!(Eui64::decode(&mut reader).is_err());
    }

    #[test]
    fn trust_centre_bits_combine_to_the_value_a_working_stack_sends() {
        // 3 = ALLOW_JOINS | ALLOW_UNSECURED_REJOINS, which is what a reference
        // implementation was observed to send and what a device actually joins
        // against. The historical trap is that a legacy enum called 0x00
        // "AllowJoins", and 0x00 on modern firmware means deny.
        let decision = Decision::ALLOW_JOINS.union(Decision::ALLOW_UNSECURED_REJOINS);
        assert_eq!(decision.0, 3);
        assert_ne!(decision.0, 0, "zero would deny every join");
    }
}
