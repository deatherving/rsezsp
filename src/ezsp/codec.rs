//! Byte-level reading and writing, sans-I/O.
//!
//! Every byte read here arrived over a serial line from a device this crate
//! does not control, so the reader is written on the assumption that its input
//! is hostile: no slice indexing, no arithmetic that can wrap, and a typed
//! error for every way a frame can be wrong.
//!
//! # Why not `std::io::Read` and `Write`
//!
//! They would work, and the temptation is real because the traits already
//! exist. Two reasons against:
//!
//! * `io::Error` cannot say *why* a frame was rejected. "Unexpected end of
//!   file" is not the same information as "a length byte claimed 40 more bytes
//!   than the frame contains", and the second is what a person debugging a new
//!   dongle needs.
//! * Encoding an EZSP field depends on the negotiated protocol version, so the
//!   codec has to carry it. Threading a version through `io::Write` means
//!   putting it somewhere else, and "somewhere else" is where it gets out of
//!   step with the frame being written.

use crate::ezsp::error::EzspError;
use crate::ezsp::version::ProtocolVersion;

/// A cursor over a frame's bytes.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
    version: ProtocolVersion,
}

impl<'a> Reader<'a> {
    /// A reader over `bytes`, decoding for `version`.
    pub const fn new(bytes: &'a [u8], version: ProtocolVersion) -> Self {
        Self {
            bytes,
            position: 0,
            version,
        }
    }

    /// The protocol version this frame is being decoded for.
    ///
    /// Available to every decoder because field widths depend on it: a status
    /// is one byte below EZSP 14 and four bytes at or above it.
    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }

    /// How many bytes are left.
    pub const fn remaining(&self) -> usize {
        // Saturating rather than a subtraction: `position` never exceeds
        // `len`, but an underflow here would be a panic on a data path.
        self.bytes.len().saturating_sub(self.position)
    }

    /// Whether everything has been consumed.
    pub const fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// The bytes not yet read, without consuming them.
    pub fn peek_rest(&self) -> &'a [u8] {
        self.bytes.get(self.position..).unwrap_or(&[])
    }

    /// Takes `n` bytes.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], EzspError> {
        let end = self
            .position
            .checked_add(n)
            .ok_or(EzspError::TruncatedFrame {
                needed: n,
                available: self.remaining(),
            })?;
        let slice = self
            .bytes
            .get(self.position..end)
            .ok_or(EzspError::TruncatedFrame {
                needed: n,
                available: self.remaining(),
            })?;
        self.position = end;
        Ok(slice)
    }

    /// Takes everything left.
    pub fn take_rest(&mut self) -> &'a [u8] {
        let rest = self.peek_rest();
        self.position = self.bytes.len();
        rest
    }

    /// One byte.
    pub fn u8(&mut self) -> Result<u8, EzspError> {
        Ok(*self.take(1)?.first().ok_or(EzspError::TruncatedFrame {
            needed: 1,
            available: 0,
        })?)
    }

    /// A little-endian `u16`. EZSP is little-endian throughout.
    pub fn u16(&mut self) -> Result<u16, EzspError> {
        let bytes = self.take(2)?;
        let [a, b] = bytes else {
            return Err(EzspError::TruncatedFrame {
                needed: 2,
                available: bytes.len(),
            });
        };
        Ok(u16::from_le_bytes([*a, *b]))
    }

    /// A little-endian `u32`.
    pub fn u32(&mut self) -> Result<u32, EzspError> {
        let bytes = self.take(4)?;
        let [a, b, c, d] = bytes else {
            return Err(EzspError::TruncatedFrame {
                needed: 4,
                available: bytes.len(),
            });
        };
        Ok(u32::from_le_bytes([*a, *b, *c, *d]))
    }

    /// A fixed-size array.
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], EzspError> {
        let bytes = self.take(N)?;
        bytes.try_into().map_err(|_| EzspError::TruncatedFrame {
            needed: N,
            available: bytes.len(),
        })
    }

    /// A `u8` length followed by that many bytes.
    ///
    /// The shape most likely to be malformed, deliberately or otherwise: the
    /// length comes from the frame and is not to be trusted.
    pub fn length_prefixed(&mut self) -> Result<&'a [u8], EzspError> {
        let len = self.u8()? as usize;
        self.take(len)
    }
}

/// A growable buffer for building a frame.
#[derive(Debug, Clone)]
pub struct Writer {
    bytes: Vec<u8>,
    version: ProtocolVersion,
}

impl Writer {
    /// A writer that encodes for `version`.
    pub const fn new(version: ProtocolVersion) -> Self {
        Self {
            bytes: Vec::new(),
            version,
        }
    }

    /// The protocol version being encoded for.
    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }

    /// How much has been written.
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether nothing has been written.
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// One byte.
    pub fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    /// A little-endian `u16`.
    pub fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    /// A little-endian `u32`.
    pub fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    /// Raw bytes, with no length prefix.
    pub fn bytes(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    /// A `u8` length followed by the bytes.
    ///
    /// # Errors
    ///
    /// [`EzspError::PayloadTooLong`] if the slice cannot be described by a
    /// single length byte. Truncating instead would send a frame the NCP reads
    /// as valid and shorter than intended, which is worse than refusing.
    pub fn length_prefixed(&mut self, value: &[u8]) -> Result<(), EzspError> {
        let len = u8::try_from(value.len()).map_err(|_| EzspError::PayloadTooLong {
            length: value.len(),
            limit: usize::from(u8::MAX),
        })?;
        self.u8(len);
        self.bytes(value);
        Ok(())
    }

    /// The finished bytes.
    pub fn into_vec(self) -> Vec<u8> {
        self.bytes
    }

    /// The bytes written so far.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

/// Something that can be written into an EZSP frame.
///
/// The version is a parameter rather than crate state because it changes what
/// the bytes are. `sendUnicast`'s message tag is one byte below EZSP 14 and two
/// at or above it, so a type that encoded itself without knowing the version
/// could only ever be right for one of them -- which is precisely the failure
/// this crate exists to avoid.
pub trait EzspEncode {
    /// Appends this value's bytes.
    fn encode(&self, out: &mut Writer) -> Result<(), EzspError>;
}

/// Something that can be read out of an EZSP frame.
pub trait EzspDecode: Sized {
    /// Reads one value, consuming exactly its bytes.
    fn decode(input: &mut Reader<'_>) -> Result<Self, EzspError>;
}

impl EzspEncode for u8 {
    fn encode(&self, out: &mut Writer) -> Result<(), EzspError> {
        out.u8(*self);
        Ok(())
    }
}

impl EzspDecode for u8 {
    fn decode(input: &mut Reader<'_>) -> Result<Self, EzspError> {
        input.u8()
    }
}

impl EzspEncode for u16 {
    fn encode(&self, out: &mut Writer) -> Result<(), EzspError> {
        out.u16(*self);
        Ok(())
    }
}

impl EzspDecode for u16 {
    fn decode(input: &mut Reader<'_>) -> Result<Self, EzspError> {
        input.u16()
    }
}

impl EzspEncode for () {
    fn encode(&self, _out: &mut Writer) -> Result<(), EzspError> {
        Ok(())
    }
}

impl EzspDecode for () {
    fn decode(_input: &mut Reader<'_>) -> Result<Self, EzspError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const V13: ProtocolVersion = ProtocolVersion::new(0x0d);

    #[test]
    fn integers_round_trip_little_endian() {
        let mut writer = Writer::new(V13);
        writer.u8(0x12);
        writer.u16(0x3456);
        writer.u32(0x89ab_cdef);
        // Asserted as bytes, not just round-tripped: a codec that read back
        // its own wrong byte order would pass a round-trip test and fail
        // against every real device.
        assert_eq!(
            writer.as_slice(),
            &[0x12, 0x56, 0x34, 0xef, 0xcd, 0xab, 0x89]
        );

        let bytes = writer.into_vec();
        let mut reader = Reader::new(&bytes, V13);
        assert_eq!(reader.u8().expect("u8"), 0x12);
        assert_eq!(reader.u16().expect("u16"), 0x3456);
        assert_eq!(reader.u32().expect("u32"), 0x89ab_cdef);
        assert!(reader.is_empty());
    }

    #[test]
    fn a_truncated_read_says_what_was_missing() {
        let mut reader = Reader::new(&[0x01], V13);
        let error = reader.u32().expect_err("four bytes are not there");
        match error {
            EzspError::TruncatedFrame { needed, available } => {
                assert_eq!(needed, 4);
                assert_eq!(available, 1, "the error must say what was actually there");
            }
            other => panic!("expected a truncation, got {other:?}"),
        }
    }

    #[test]
    fn a_failed_read_does_not_advance_the_cursor() {
        // Otherwise a decoder that recovers from one bad field reads the next
        // one from the middle of the previous, and every field after it is
        // garbage that looks plausible.
        let mut reader = Reader::new(&[0xaa, 0xbb], V13);
        assert!(reader.u32().is_err());
        assert_eq!(reader.remaining(), 2, "a failed read must consume nothing");
        assert_eq!(reader.u16().expect("still readable"), 0xbbaa);
    }

    #[test]
    fn a_length_prefix_longer_than_the_frame_is_refused() {
        // The shape most likely to be malformed: the length is data, and
        // trusting it is how a parser reads past the end of a buffer.
        let mut reader = Reader::new(&[0x40, 0x01, 0x02], V13);
        assert!(
            matches!(
                reader.length_prefixed(),
                Err(EzspError::TruncatedFrame { needed: 0x40, .. })
            ),
            "a length claiming 64 bytes of a 2-byte body must be refused"
        );
    }

    #[test]
    fn a_length_prefix_of_zero_is_valid_and_empty() {
        // Not an error: plenty of EZSP payloads are legitimately empty, and
        // rejecting them would break commands that work.
        let mut reader = Reader::new(&[0x00], V13);
        assert_eq!(reader.length_prefixed().expect("zero length is fine"), &[]);
    }

    #[test]
    fn a_payload_too_long_to_describe_is_refused_not_truncated() {
        let mut writer = Writer::new(V13);
        let long = vec![0u8; 300];
        let error = writer
            .length_prefixed(&long)
            .expect_err("300 bytes cannot be described by one length byte");
        assert!(matches!(
            error,
            EzspError::PayloadTooLong { length: 300, .. }
        ));
    }

    #[test]
    fn take_cannot_be_tricked_into_overflowing() {
        // `position + n` on a large `n`. An overflow here would wrap to a
        // small number and hand out a slice from the wrong place.
        let mut reader = Reader::new(&[0x01, 0x02], V13);
        assert!(reader.take(usize::MAX).is_err());
        assert_eq!(reader.remaining(), 2);
    }
}
