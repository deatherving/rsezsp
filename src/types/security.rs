//! Key material.

use crate::ezsp::codec::{EzspDecode, EzspEncode, Reader, Writer};
use crate::ezsp::error::EzspError;
use crate::types::network::Eui64;

/// A 128-bit key.
///
/// A newtype whose `Debug` redacts, because a key is the credential for a whole
/// network and `[u8; 16]` prints itself in full anywhere a struct containing it
/// is logged, traced, or put in an error. That is a leak no amount of care at
/// the call sites prevents, so the type prevents it.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SecurityKey([u8; 16]);

impl SecurityKey {
    /// The well-known Zigbee 3.0 default trust-centre link key.
    ///
    /// `ZigBeeAlliance09` in ASCII. Public by design and specified: a Zigbee
    /// 3.0 device that ships without an install code uses it to protect the one
    /// exchange in which it is given the real network key. It is not a secret,
    /// and the security it provides is that the window in which it is accepted
    /// is short and operator-initiated.
    pub const ZIGBEE_ALLIANCE_09: Self = Self(*b"ZigBeeAlliance09");

    /// Wraps raw key bytes.
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The key material.
    ///
    /// Named `expose` so every place a key can escape is findable in review.
    pub const fn expose(&self) -> &[u8; 16] {
        &self.0
    }
}

impl core::fmt::Debug for SecurityKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecurityKey(redacted)")
    }
}

impl core::fmt::Display for SecurityKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("<redacted>")
    }
}

impl EzspEncode for SecurityKey {
    fn encode(&self, out: &mut Writer) -> Result<(), EzspError> {
        out.bytes(&self.0);
        Ok(())
    }
}

/// Flags for a security-manager call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SecurityManFlags(pub u8);

impl SecurityManFlags {
    /// No flags.
    pub const NONE: Self = Self(0x00);
    /// The `key_index` field is meaningful.
    pub const KEY_INDEX_IS_VALID: Self = Self(0x01);
    /// The `eui64` field is meaningful.
    pub const EUI_IS_VALID: Self = Self(0x02);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ezsp::version::ProtocolVersion;

    #[test]
    fn the_well_known_key_is_the_specified_ascii() {
        assert_eq!(
            SecurityKey::ZIGBEE_ALLIANCE_09.expose(),
            b"ZigBeeAlliance09"
        );
        assert_eq!(SecurityKey::ZIGBEE_ALLIANCE_09.expose().len(), 16);
    }

    #[test]
    fn a_key_never_prints_itself() {
        // The reason this is a newtype. A stored or logged structure holding a
        // key must not carry it into a log line.
        let key = SecurityKey::new([0xab; 16]);
        let debug = format!("{key:?}");
        assert!(debug.contains("redacted"), "{debug}");
        assert!(!debug.contains("171") && !debug.contains("ab"), "{debug}");
        assert_eq!(format!("{key}"), "<redacted>");
    }

    #[test]
    fn a_key_encodes_as_sixteen_raw_bytes() {
        let mut out = Writer::new(ProtocolVersion::new(0x0d));
        SecurityKey::ZIGBEE_ALLIANCE_09
            .encode(&mut out)
            .expect("encodes");
        assert_eq!(out.as_slice(), b"ZigBeeAlliance09");
    }
}

impl EzspDecode for SecurityKey {
    fn decode(input: &mut Reader<'_>) -> Result<Self, EzspError> {
        Ok(Self::new(input.array::<16>()?))
    }
}

/// Which key the security manager should act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecurityKeyType(pub u8);

impl SecurityKeyType {
    /// The current network key.
    pub const NETWORK: Self = Self(0x01);
    /// The trust centre link key.
    pub const TC_LINK: Self = Self(0x02);
}

/// Which key to export, and any qualifiers on it.
///
/// The wire layout is fixed even though most fields are unused for any given
/// key type -- `psa_key_alg_permission` in particular is four bytes that a
/// caller reading the network key has no reason to think about, but omitting
/// them shifts the status that follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityManContext {
    /// Which key.
    pub core_key_type: SecurityKeyType,
    /// Index into a key table, when the type uses one.
    pub key_index: u8,
    /// Derived key type. `0` for none.
    pub derived_type: u8,
    /// The device the key belongs to, where that applies.
    pub eui64: Eui64,
    /// Which network, on a multi-network build. `0` otherwise.
    pub multi_network_index: u8,
    /// Which of the fields above are meaningful.
    pub flags: SecurityManFlags,
    /// PSA algorithm permissions. `0` unless you have a reason.
    pub psa_key_alg_permission: u32,
}

impl SecurityManContext {
    /// A context that reads the current network key.
    #[must_use]
    pub const fn network_key() -> Self {
        Self {
            core_key_type: SecurityKeyType::NETWORK,
            key_index: 0,
            derived_type: 0,
            eui64: Eui64::new(0),
            multi_network_index: 0,
            flags: SecurityManFlags::NONE,
            psa_key_alg_permission: 0,
        }
    }
}

impl EzspEncode for SecurityManContext {
    fn encode(&self, out: &mut Writer) -> Result<(), EzspError> {
        out.u8(self.core_key_type.0);
        out.u8(self.key_index);
        out.u8(self.derived_type);
        self.eui64.encode(out)?;
        out.u8(self.multi_network_index);
        out.u8(self.flags.0);
        out.u32(self.psa_key_alg_permission);
        Ok(())
    }
}

impl EzspDecode for SecurityManContext {
    fn decode(input: &mut Reader<'_>) -> Result<Self, EzspError> {
        Ok(Self {
            core_key_type: SecurityKeyType(input.u8()?),
            key_index: input.u8()?,
            derived_type: input.u8()?,
            eui64: Eui64::decode(input)?,
            multi_network_index: input.u8()?,
            flags: SecurityManFlags(input.u8()?),
            psa_key_alg_permission: input.u32()?,
        })
    }
}

/// Flags for `setInitialSecurityState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitialSecurityBitmask(pub u16);

impl InitialSecurityBitmask {
    /// A trust centre global link key is in use.
    pub const TRUST_CENTER_GLOBAL_LINK_KEY: Self = Self(0x0004);
    /// The trust centre uses a hashed link key.
    ///
    /// Note this is `0x0084`, not a single bit: it implies the flags below it.
    /// Writing `0x0080` here, on the assumption that every entry in a bitmask
    /// is one bit, silently drops part of the configuration.
    pub const TRUST_CENTER_USES_HASHED_LINK_KEY: Self = Self(0x0084);
    /// The preconfigured key is a network key, not a link key.
    pub const PRECONFIGURED_NETWORK_KEY_MODE: Self = Self(0x0008);
    /// `preconfigured_key` is set.
    pub const HAVE_PRECONFIGURED_KEY: Self = Self(0x0100);
    /// `network_key` is set.
    pub const HAVE_NETWORK_KEY: Self = Self(0x0200);
    /// Ask for a link key when joining.
    pub const GET_LINK_KEY_WHEN_JOINING: Self = Self(0x0400);
    /// Require the network key to arrive encrypted.
    pub const REQUIRE_ENCRYPTED_KEY: Self = Self(0x0800);
    /// Do not reset frame counters.
    ///
    /// Set this when restoring a network rather than creating one. Resetting
    /// the counters on a network that already has joined devices makes every
    /// one of them reject the coordinator's frames as replays.
    pub const NO_FRAME_COUNTER_RESET: Self = Self(0x1000);

    /// Combines two bitmasks.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Whether every bit in `other` is set.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

/// The security configuration a coordinator forms a network with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitialSecurityState {
    /// Which of the fields below are meaningful, and how the stack behaves.
    pub bitmask: InitialSecurityBitmask,
    /// The preconfigured link key.
    pub preconfigured_key: SecurityKey,
    /// The network key.
    pub network_key: SecurityKey,
    /// The network key's sequence number.
    pub network_key_sequence_number: u8,
    /// The trust centre's address, when one is preconfigured.
    pub preconfigured_trust_center_eui64: Eui64,
}

impl EzspEncode for InitialSecurityState {
    fn encode(&self, out: &mut Writer) -> Result<(), EzspError> {
        out.u16(self.bitmask.0);
        self.preconfigured_key.encode(out)?;
        self.network_key.encode(out)?;
        out.u8(self.network_key_sequence_number);
        self.preconfigured_trust_center_eui64.encode(out)
    }
}

#[cfg(test)]
mod redaction_tests {
    use super::*;
    use crate::ezsp::frame::FrameId;

    #[test]
    fn a_key_never_renders_its_bytes() {
        // A structure containing a key ends up in a log line eventually. Both
        // formatters have to redact, because `{:?}` and `{}` are both reached
        // by ordinary tracing macros.
        let key = SecurityKey::new([0xab; 16]);
        for rendered in [format!("{key:?}"), format!("{key}")] {
            assert!(!rendered.contains("ab"), "key bytes leaked: {rendered}");
            assert!(rendered.contains("redacted"), "{rendered}");
        }
    }

    #[test]
    fn a_struct_containing_a_key_redacts_it_too() {
        // The realistic path: nobody logs a bare key, they log the thing that
        // holds one.
        let state = InitialSecurityState {
            bitmask: InitialSecurityBitmask::HAVE_NETWORK_KEY,
            preconfigured_key: SecurityKey::new([0x11; 16]),
            network_key: SecurityKey::new([0x22; 16]),
            network_key_sequence_number: 0,
            preconfigured_trust_center_eui64: Eui64::new(0),
        };
        let rendered = format!("{state:?}");
        assert!(!rendered.contains("11"), "leaked: {rendered}");
        assert!(!rendered.contains("22"), "leaked: {rendered}");
    }

    #[test]
    fn every_frame_carrying_a_key_is_marked_for_redaction() {
        // Frame payloads are logged at debug level, and CONTRIBUTING asks bug
        // reporters to attach that output. For these the payload *is* the
        // secret, so a miss here publishes a network key in a public issue.
        for frame_id in [
            FrameId::EXPORT_KEY,
            FrameId::IMPORT_TRANSIENT_KEY,
            FrameId::SET_INITIAL_SECURITY_STATE,
            FrameId::GET_NETWORK_KEY_INFO,
        ] {
            assert!(
                frame_id.carries_key_material(),
                "{frame_id} carries key material and must be redacted in logs"
            );
        }

        // And the ordinary ones are not redacted, because a wire trace that
        // hides everything is no use in a bug report.
        for frame_id in [
            FrameId::VERSION,
            FrameId::GET_EUI64,
            FrameId::SEND_UNICAST,
            FrameId::NETWORK_INIT,
        ] {
            assert!(!frame_id.carries_key_material(), "{frame_id}");
        }
    }
}
