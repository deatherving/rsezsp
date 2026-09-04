//! The negotiated EZSP protocol version, and what it changes.
//!
//! This module is the reason the crate exists. EZSP is not one wire format: the
//! same command is encoded differently depending on the version the host and
//! NCP agreed on, and a library with fixed per-command layouts can only ever be
//! correct for the one version its author tested against.
//!
//! Concretely, at the EZSP 14 boundary:
//!
//! | | below 14 | 14 and above |
//! |---|---|---|
//! | a status value | `u8` (`EmberStatus`) | `u32` (`sl_status_t`) |
//! | `sendUnicast` message tag | `u8` | `u16` |
//! | `importTransientKey` flags | present | absent |
//!
//! Those are not obscure corners. A status is in almost every response, and
//! `sendUnicast` is the most-used command there is. Getting the width wrong
//! shifts every following field, so the frame still parses and every value
//! after the mistake is plausible and wrong.
//!
//! So [`ProtocolVersion`] is threaded through every encoder and decoder rather
//! than stored once and hoped about, and the boundaries are named predicates
//! instead of `if version < 0x0e` scattered across the codebase.

/// A negotiated EZSP protocol version.
///
/// A newtype rather than a bare `u8` because it is not an ordinary number: two
/// versions differing by one can have different wire formats, and the point of
/// the type is that the comparison is always made through a named predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolVersion(u8);

impl ProtocolVersion {
    /// The lowest version this crate will speak.
    ///
    /// EZSP 13, matching what current `EmberZNet` firmware negotiates. Older
    /// NCPs used a different frame format for *every* command, not just some
    /// fields, and claiming support without a device to test against would be
    /// a guess presented as a feature.
    pub const MIN_SUPPORTED: Self = Self(0x0d);

    /// The highest version this crate knows the differences for.
    pub const MAX_SUPPORTED: Self = Self(0x13);

    /// The version a host asks for first.
    ///
    /// The NCP answers with its own, which may be lower; that answer is what
    /// everything afterwards is encoded for.
    pub const PREFERRED: Self = Self::MAX_SUPPORTED;

    /// The version at which several field widths changed.
    ///
    /// Named because it appears in more than one place and `0x0e` at a call
    /// site says nothing about why it matters.
    pub const WIDER_STATUS: Self = Self(0x0e);

    /// Wraps a raw version number.
    pub const fn new(raw: u8) -> Self {
        Self(raw)
    }

    /// The raw number, for the wire.
    pub const fn raw(self) -> u8 {
        self.0
    }

    /// Whether this crate knows how to speak it.
    pub const fn is_supported(self) -> bool {
        self.0 >= Self::MIN_SUPPORTED.0 && self.0 <= Self::MAX_SUPPORTED.0
    }

    /// Whether a status field is four bytes rather than one.
    ///
    /// Below EZSP 14 a status is a one-byte `EmberStatus`; at 14 and above it
    /// is a four-byte `sl_status_t`. Since a status is the first field of most
    /// responses, getting this wrong misaligns everything after it.
    pub const fn has_wide_status(self) -> bool {
        self.0 >= Self::WIDER_STATUS.0
    }

    /// Whether `sendUnicast` takes a two-byte message tag.
    pub const fn has_wide_message_tag(self) -> bool {
        self.0 >= Self::WIDER_STATUS.0
    }

    /// Whether `importTransientKey` carries a trailing flags byte.
    ///
    /// Present below EZSP 14 and gone at 14 and above. This is the field whose
    /// absence, in another implementation, silently installed a key spliced out
    /// of the wrong bytes -- the NCP answered `OK` and a joining device could
    /// never finish commissioning.
    pub const fn has_transient_key_flags(self) -> bool {
        self.0 < Self::WIDER_STATUS.0
    }
}

impl core::fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "v{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_boundary_is_at_fourteen_and_is_exclusive_below() {
        // Every one of these was read off a working reference implementation
        // and confirmed against a real dongle's wire trace. 13 is what current
        // EmberZNet negotiates, which puts real deployments one step below the
        // boundary -- the most fragile place to be, and the reason these are
        // predicates rather than inline comparisons.
        let thirteen = ProtocolVersion::new(0x0d);
        let fourteen = ProtocolVersion::new(0x0e);

        assert!(!thirteen.has_wide_status(), "v13 status is one byte");
        assert!(fourteen.has_wide_status(), "v14 status is four bytes");

        assert!(!thirteen.has_wide_message_tag());
        assert!(fourteen.has_wide_message_tag());

        assert!(
            thirteen.has_transient_key_flags(),
            "v13 carries the flags byte"
        );
        assert!(
            !fourteen.has_transient_key_flags(),
            "v14 dropped the flags byte"
        );
    }

    #[test]
    fn support_is_bounded_at_both_ends() {
        assert!(ProtocolVersion::MIN_SUPPORTED.is_supported());
        assert!(ProtocolVersion::MAX_SUPPORTED.is_supported());
        // Below: older NCPs framed every command differently, and claiming
        // support with no device to test against would be a guess.
        assert!(!ProtocolVersion::new(0x0c).is_supported());
        // Above: a version whose differences are not known yet. Refusing is
        // honest; guessing would produce frames that are wrong in ways nobody
        // has characterised.
        assert!(!ProtocolVersion::new(0x14).is_supported());
    }

    #[test]
    fn the_preferred_version_is_one_we_can_actually_speak() {
        // A stale `PREFERRED` would ask the NCP for a version this crate then
        // refuses, which fails at the first command with a confusing error.
        assert!(ProtocolVersion::PREFERRED.is_supported());
    }
}
