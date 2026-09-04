//! Key material.

use crate::ezsp::codec::{EzspEncode, Writer};
use crate::ezsp::error::EzspError;

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
