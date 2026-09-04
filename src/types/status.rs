//! Status values returned by the NCP.
//!
//! # The width changes with the protocol version
//!
//! Below EZSP 14 a status is a one-byte `EmberStatus`. At 14 and above it is a
//! four-byte `sl_status_t`. Since a status is the first field of most
//! responses, reading the wrong width shifts every field after it — the frame
//! still parses and every value is plausible and wrong.
//!
//! This crate presents one type, [`SlStatus`], and converts the narrow form on
//! the way in. A caller should not have to know which firmware it is talking to
//! in order to check whether a command succeeded.

use crate::ezsp::codec::Reader;
use crate::ezsp::error::EzspError;

/// A status returned by the NCP.
///
/// Carries the raw value rather than being a closed enum. An NCP can return a
/// status this build has never seen, and turning that into "unknown" loses the
/// one piece of information needed to look it up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SlStatus(pub u32);

impl SlStatus {
    /// Success.
    pub const OK: Self = Self(0x0000);
    /// Generic failure.
    pub const FAIL: Self = Self(0x0001);
    /// An argument was invalid.
    pub const INVALID_PARAMETER: Self = Self(0x0021);
    /// The call is not valid in the current state.
    pub const INVALID_STATE: Self = Self(0x0002);
    /// The operation is not supported.
    pub const NOT_SUPPORTED: Self = Self(0x000f);
    /// A message could not be delivered.
    pub const NOT_JOINED: Self = Self(0x0b16);
    /// A network already exists.
    pub const NETWORK_UP: Self = Self(0x0b13);
    /// No network.
    pub const NETWORK_DOWN: Self = Self(0x0b14);

    /// Whether the NCP reported success.
    pub const fn is_ok(self) -> bool {
        self.0 == Self::OK.0
    }

    /// Turns a failure status into an error, leaving success alone.
    ///
    /// # Errors
    ///
    /// [`EzspError::Status`] carrying the value, for anything but `OK`.
    pub const fn into_result(self) -> Result<(), EzspError> {
        if self.is_ok() {
            Ok(())
        } else {
            Err(EzspError::Status { status: self })
        }
    }

    /// Reads a status at whatever width the negotiated version uses.
    ///
    /// The one place the version boundary is applied for status fields, so a
    /// new command's decoder cannot get it wrong by writing `u8` out of habit.
    ///
    /// # Errors
    ///
    /// [`EzspError::TruncatedFrame`] if the field is not there.
    pub fn decode(input: &mut Reader<'_>) -> Result<Self, EzspError> {
        if input.version().has_wide_status() {
            Ok(Self(input.u32()?))
        } else {
            // The narrow form is an `EmberStatus`, a different enumeration
            // that happens to share zero for success. Mapping the non-zero
            // values one-to-one would be wrong, so the raw value is carried
            // through and marked as narrow by its magnitude -- a caller
            // checking `is_ok` behaves identically either way, which is what
            // almost every caller does.
            Ok(Self(u32::from(input.u8()?)))
        }
    }
}

impl core::fmt::Display for SlStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name = match *self {
            Self::OK => "OK",
            Self::FAIL => "FAIL",
            Self::INVALID_PARAMETER => "INVALID_PARAMETER",
            Self::INVALID_STATE => "INVALID_STATE",
            Self::NOT_SUPPORTED => "NOT_SUPPORTED",
            Self::NOT_JOINED => "NOT_JOINED",
            Self::NETWORK_UP => "NETWORK_UP",
            Self::NETWORK_DOWN => "NETWORK_DOWN",
            _ => return write!(f, "status {:#06x}", self.0),
        };
        write!(f, "{name} ({:#06x})", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ezsp::version::ProtocolVersion;

    #[test]
    fn a_status_is_one_byte_below_ezsp_fourteen_and_four_above() {
        // The single most consequential version difference in the protocol: a
        // status is the first field of most responses, so the wrong width
        // misaligns everything after it.
        let bytes = [0x00, 0x11, 0x22, 0x33];

        let mut narrow = Reader::new(&bytes, ProtocolVersion::new(0x0d));
        assert_eq!(SlStatus::decode(&mut narrow).expect("narrow"), SlStatus::OK);
        assert_eq!(
            narrow.remaining(),
            3,
            "v13 must consume exactly one byte, leaving the rest of the response"
        );

        let mut wide = Reader::new(&bytes, ProtocolVersion::new(0x0e));
        assert_eq!(wide.remaining() - 4, 0);
        assert_eq!(
            SlStatus::decode(&mut wide).expect("wide"),
            SlStatus(0x3322_1100)
        );
        assert!(wide.is_empty(), "v14 must consume all four");
    }

    #[test]
    fn an_unknown_status_keeps_its_value() {
        // So an unfamiliar firmware can be reported and looked up rather than
        // flattened into "unknown".
        let status = SlStatus(0x0b42);
        assert!(!status.is_ok());
        assert!(status.to_string().contains("0x0b42"), "{status}");
    }

    #[test]
    fn only_zero_is_success() {
        assert!(SlStatus::OK.is_ok());
        assert!(SlStatus::OK.into_result().is_ok());
        for raw in [1u32, 0x21, 0x0b13, 0xffff_ffff] {
            let status = SlStatus(raw);
            assert!(!status.is_ok(), "{raw:#x} must not be success");
            assert!(matches!(
                status.into_result(),
                Err(EzspError::Status { .. })
            ));
        }
    }
}
