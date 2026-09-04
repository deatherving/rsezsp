//! Turning ASH frames into bytes and back, sans-I/O.
//!
//! Four transformations sit between a frame and the wire, and all four have to
//! be applied in the right order or nothing works:
//!
//! ```text
//! encode:  frame -> randomise data -> append CRC -> byte-stuff -> FLAG
//! decode:  FLAG-delimited -> unstuff -> verify CRC -> de-randomise data
//! ```
//!
//! The randomisation is the step most easily missed, because a frame without it
//! is still well-formed: correct CRC, correct length, and a payload the NCP
//! reads as garbage. It exists so a payload full of one repeated reserved byte
//! does not double in size through escaping.

use crate::ash::error::AshError;
use crate::ash::frame::AshFrame;

/// Frame delimiter.
pub const FLAG: u8 = 0x7e;
/// Escape prefix for a reserved byte.
pub const ESCAPE: u8 = 0x7d;
/// The NCP is abandoning the frame in progress.
pub const CANCEL: u8 = 0x1a;
/// The frame in progress was corrupted in transit.
pub const SUBSTITUTE: u8 = 0x18;
/// Flow control, ignored when the port uses RTS/CTS.
pub const XON: u8 = 0x11;
/// Flow control, ignored when the port uses RTS/CTS.
pub const XOFF: u8 = 0x13;
/// `XORed` into an escaped byte.
const FLIP: u8 = 0x20;

/// Seed for the data-randomising LFSR.
const LFSR_SEED: u8 = 0x42;
/// Feedback polynomial for the data-randomising LFSR.
const LFSR_POLY: u8 = 0xb8;

/// The largest complete frame, control and CRC included, before stuffing.
const MAX_FRAME_WITH_CRC: usize = 133;
/// The shortest: a control byte and a CRC.
const MIN_FRAME_WITH_CRC: usize = 3;

/// Whether a byte must be escaped when sent.
const fn is_reserved(byte: u8) -> bool {
    matches!(byte, FLAG | ESCAPE | XON | XOFF | SUBSTITUTE | CANCEL)
}

/// CRC-16/CCITT-FALSE: poly `0x1021`, initial value `0xffff`, no reflection.
///
/// Written as the plain bitwise algorithm rather than a table or the
/// equivalent bit-twiddling found in reference implementations, because this
/// version can be checked against the published test vector for the algorithm
/// -- which is a stronger guarantee than agreeing with another implementation.
pub fn crc16(seed: u16, byte: u8) -> u16 {
    let mut crc = seed ^ (u16::from(byte) << 8);
    let mut bit = 0;
    while bit < 8 {
        crc = if crc & 0x8000 == 0 {
            crc << 1
        } else {
            (crc << 1) ^ 0x1021
        };
        bit += 1;
    }
    crc
}

/// The CRC over a whole byte string.
pub fn crc16_all(bytes: &[u8]) -> u16 {
    bytes.iter().fold(0xffff, |crc, byte| crc16(crc, *byte))
}

/// XORs a data field with the ASH pseudo-random sequence.
///
/// Its own inverse, so the same function serves both directions.
pub fn randomise(data: &mut [u8]) {
    let mut seed = LFSR_SEED;
    for byte in data {
        *byte ^= seed;
        seed = if seed & 1 == 0 {
            seed >> 1
        } else {
            (seed >> 1) ^ LFSR_POLY
        };
    }
}

/// Encodes one frame, ready to write to the port.
///
/// # Errors
///
/// [`AshError::TooLong`] if the frame's data field exceeds what ASH permits.
pub fn encode(frame: &AshFrame) -> Result<Vec<u8>, AshError> {
    let mut unstuffed = Vec::with_capacity(MAX_FRAME_WITH_CRC);
    unstuffed.push(frame.control());

    // Randomised before the CRC, because the CRC covers what goes on the wire.
    let mut body = frame.body();
    if matches!(frame, AshFrame::Data { .. }) {
        randomise(&mut body);
    }
    unstuffed.extend_from_slice(&body);

    if unstuffed.len() + 2 > MAX_FRAME_WITH_CRC {
        return Err(AshError::TooLong {
            length: unstuffed.len() + 2,
            maximum: MAX_FRAME_WITH_CRC,
        });
    }

    let crc = crc16_all(&unstuffed);
    // High byte first: ASH sends the CRC big-endian even though every other
    // multi-byte field in EZSP is little-endian.
    unstuffed.extend_from_slice(&crc.to_be_bytes());

    let mut out = Vec::with_capacity(unstuffed.len() + 8);
    for byte in unstuffed {
        if is_reserved(byte) {
            out.push(ESCAPE);
            out.push(byte ^ FLIP);
        } else {
            out.push(byte);
        }
    }
    out.push(FLAG);
    Ok(out)
}

/// What the decoder produced from a chunk of bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decoded {
    /// A complete, verified frame.
    Frame(AshFrame),
    /// A frame arrived and was rejected. The reason says whether to NAK.
    Rejected(AshError),
}

/// Reassembles frames from a byte stream.
///
/// Incremental because a serial read returns whatever happened to be in the
/// buffer: half a frame, three frames, or one byte. The decoder holds the
/// partial frame between calls and never assumes a read boundary is a frame
/// boundary.
#[derive(Debug, Default)]
pub struct Decoder {
    /// Bytes of the frame in progress, unstuffed.
    partial: Vec<u8>,
    /// Set when the previous byte was an escape.
    escaped: bool,
    /// Set when the frame in progress is already known to be unusable.
    ///
    /// Kept separate from discarding the bytes so the frame is still consumed
    /// up to its delimiter -- otherwise its remainder is read as the start of
    /// the next one, and a single corrupt frame desynchronises the stream.
    dropping: Option<AshError>,
}

impl Decoder {
    /// A decoder with nothing buffered.
    pub fn new() -> Self {
        Self::default()
    }

    /// Discards any partial frame.
    ///
    /// Used after a reset, where anything buffered belongs to the connection
    /// that just went away.
    pub fn reset(&mut self) {
        self.partial.clear();
        self.escaped = false;
        self.dropping = None;
    }

    /// Feeds bytes in, and returns whatever completed.
    ///
    /// Never fails as a whole: a bad frame is one `Decoded::Rejected` in the
    /// returned list, and the frames around it still decode. One corrupt frame
    /// must not cost the ones that arrived in the same read.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<Decoded> {
        let mut out = Vec::new();
        for byte in bytes {
            if let Some(decoded) = self.push(*byte) {
                out.push(decoded);
            }
        }
        out
    }

    /// Handles one byte.
    fn push(&mut self, byte: u8) -> Option<Decoded> {
        match byte {
            // Flow control from the NCP. Ignored: the port uses RTS/CTS, and
            // acting on these would stall a link that is not blocked.
            XON | XOFF => None,
            CANCEL => {
                // Normal during startup, when the NCP abandons partial output
                // as it resets. The frame in progress is gone, not corrupt.
                self.reset();
                None
            }
            SUBSTITUTE => {
                // The frame is known bad, but must still be consumed to its
                // delimiter or its tail becomes the next frame's head.
                self.dropping = Some(AshError::Substituted);
                None
            }
            ESCAPE => {
                self.escaped = true;
                None
            }
            FLAG => {
                let result = self.finish();
                self.reset();
                result
            }
            _ => {
                let byte = if self.escaped {
                    self.escaped = false;
                    byte ^ FLIP
                } else {
                    byte
                };
                // Bounded: a stream with no delimiter must not grow a buffer
                // without limit. Marked and consumed rather than truncated.
                if self.partial.len() >= MAX_FRAME_WITH_CRC {
                    self.dropping = Some(AshError::TooLong {
                        length: self.partial.len() + 1,
                        maximum: MAX_FRAME_WITH_CRC,
                    });
                    return None;
                }
                self.partial.push(byte);
                None
            }
        }
    }

    /// Completes the frame at a delimiter.
    fn finish(&mut self) -> Option<Decoded> {
        if let Some(error) = self.dropping.clone() {
            return Some(Decoded::Rejected(error));
        }
        // Two flags in a row, or a flag after a cancel. Not an error: the NCP
        // sends a flag to delimit, and an empty gap between two is nothing.
        if self.partial.is_empty() {
            return None;
        }
        if self.partial.len() < MIN_FRAME_WITH_CRC {
            return Some(Decoded::Rejected(AshError::TooShort {
                length: self.partial.len(),
                minimum: MIN_FRAME_WITH_CRC,
            }));
        }

        let split = self.partial.len().saturating_sub(2);
        let (covered, carried) = self.partial.split_at(split);
        let [hi, lo] = carried else {
            return Some(Decoded::Rejected(AshError::TooShort {
                length: self.partial.len(),
                minimum: MIN_FRAME_WITH_CRC,
            }));
        };
        let carried = u16::from_be_bytes([*hi, *lo]);
        let computed = crc16_all(covered);
        if computed != carried {
            return Some(Decoded::Rejected(AshError::BadCrc { computed, carried }));
        }

        let (control, body) = covered.split_first()?;
        let mut body = body.to_vec();
        // De-randomised only for data frames, and only after the CRC has been
        // verified over the bytes as they arrived.
        if control & 0x80 == 0 {
            randomise(&mut body);
        }
        match AshFrame::from_parts(*control, &body) {
            Ok(frame) => Some(Decoded::Frame(frame)),
            Err(error) => Some(Decoded::Rejected(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_crc_matches_the_published_check_value() {
        // CRC-16/CCITT-FALSE over "123456789" is 0x29b1. Checking against the
        // algorithm's own published vector is stronger than agreeing with
        // another implementation, which could be wrong in the same way.
        assert_eq!(crc16_all(b"123456789"), 0x29b1);
    }

    #[test]
    fn randomising_is_its_own_inverse() {
        let original = b"\x00\x00\x01\x02\x03\xff\xff\x7e\x7d".to_vec();
        let mut data = original.clone();
        randomise(&mut data);
        assert_ne!(data, original, "randomising must actually change the bytes");
        randomise(&mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn the_lfsr_produces_the_specified_sequence() {
        // Seeded 0x42, and each step is `(seed>>1) ^ 0xb8` when the low bit is
        // set. Applied to zeroes, the output *is* the sequence, which is the
        // clearest way to pin it.
        let mut data = [0u8; 6];
        randomise(&mut data);
        assert_eq!(data, [0x42, 0x21, 0xa8, 0x54, 0x2a, 0x15]);
    }

    #[test]
    fn a_frame_round_trips_through_the_wire_form() {
        let frame = AshFrame::Data {
            frame_num: 1,
            ack_num: 0,
            retransmit: false,
            payload: vec![0x00, 0x00, 0x00, 0x13],
        };
        let bytes = encode(&frame).expect("encodes");
        assert_eq!(bytes.last(), Some(&FLAG), "a frame ends with the delimiter");

        let mut decoder = Decoder::new();
        let frames = decoder.feed(&bytes);
        assert_eq!(frames, vec![Decoded::Frame(frame)]);
    }

    #[test]
    fn reserved_bytes_are_escaped_and_survive_the_round_trip() {
        // A payload made entirely of bytes that must be escaped. If stuffing
        // and unstuffing disagree, this is where it shows.
        let frame = AshFrame::Data {
            frame_num: 0,
            ack_num: 0,
            retransmit: false,
            payload: vec![FLAG, ESCAPE, XON, XOFF, SUBSTITUTE, CANCEL],
        };
        let bytes = encode(&frame).expect("encodes");
        // Exactly one delimiter, at the end: any reserved byte left unescaped
        // would end the frame early.
        let delimiters = bytes
            .iter()
            .fold(0_usize, |n, b| n + usize::from(*b == FLAG));
        assert_eq!(delimiters, 1);

        let mut decoder = Decoder::new();
        assert_eq!(decoder.feed(&bytes), vec![Decoded::Frame(frame)]);
    }

    #[test]
    fn a_frame_split_across_reads_still_decodes() {
        // A serial read returns whatever was in the buffer, so a frame
        // boundary and a read boundary have nothing to do with each other.
        let frame = AshFrame::Data {
            frame_num: 3,
            ack_num: 2,
            retransmit: false,
            payload: vec![0xaa; 20],
        };
        let bytes = encode(&frame).expect("encodes");
        let mut decoder = Decoder::new();
        let mut produced = Vec::new();
        for byte in &bytes {
            produced.extend(decoder.feed(&[*byte]));
        }
        assert_eq!(produced, vec![Decoded::Frame(frame)]);
    }

    #[test]
    fn several_frames_in_one_read_all_decode() {
        let a = AshFrame::Ack {
            ack_num: 1,
            not_ready: false,
        };
        let b = AshFrame::Data {
            frame_num: 0,
            ack_num: 1,
            retransmit: false,
            payload: vec![0x01, 0x02],
        };
        let mut bytes = encode(&a).expect("a");
        bytes.extend(encode(&b).expect("b"));

        let mut decoder = Decoder::new();
        assert_eq!(
            decoder.feed(&bytes),
            vec![Decoded::Frame(a), Decoded::Frame(b)]
        );
    }

    #[test]
    fn a_corrupted_frame_does_not_cost_the_next_one() {
        // The property that matters for recovery: one bad frame must be
        // reported and skipped, not desynchronise the stream.
        let good = AshFrame::Ack {
            ack_num: 4,
            not_ready: false,
        };
        let mut bytes = encode(&good).expect("encodes");
        // Corrupt the control byte of a copy, leaving its CRC stale.
        let mut broken = encode(&good).expect("encodes");
        if let Some(first) = broken.first_mut() {
            *first ^= 0x01;
        }
        let mut stream = broken;
        stream.append(&mut bytes);

        let mut decoder = Decoder::new();
        let frames = decoder.feed(&stream);
        assert_eq!(frames.len(), 2, "both frames must be accounted for");
        assert!(
            matches!(
                frames.first(),
                Some(Decoded::Rejected(AshError::BadCrc { .. }))
            ),
            "got {:?}",
            frames.first()
        );
        assert_eq!(
            frames.get(1),
            Some(&Decoded::Frame(good)),
            "the frame after a corrupt one must still decode"
        );
    }

    #[test]
    fn a_bad_crc_is_recoverable_by_nak_and_a_protocol_error_is_not() {
        // The distinction drives recovery: NAK a bad CRC so the NCP resends,
        // but NAKing a protocol violation would loop forever.
        assert!(
            AshError::BadCrc {
                computed: 1,
                carried: 2
            }
            .is_recoverable_by_nak()
        );
        assert!(
            !AshError::InvalidControl {
                control: 0xff,
                length: 0
            }
            .is_recoverable_by_nak()
        );
    }

    #[test]
    fn a_cancel_discards_the_partial_frame_without_an_error() {
        // The NCP cancels partial output when it resets, which is normal and
        // must not be reported as corruption.
        let mut decoder = Decoder::new();
        assert!(decoder.feed(&[0x25, 0xaa, 0xbb]).is_empty());
        assert!(decoder.feed(&[CANCEL]).is_empty());

        let frame = AshFrame::Rst;
        let bytes = encode(&frame).expect("encodes");
        assert_eq!(decoder.feed(&bytes), vec![Decoded::Frame(frame)]);
    }

    #[test]
    fn a_substitute_marks_the_frame_bad_but_still_consumes_it() {
        // If the remainder were not consumed to the delimiter, its tail would
        // be read as the head of the next frame.
        let mut decoder = Decoder::new();
        decoder.feed(&[0x25, 0xaa]);
        assert!(decoder.feed(&[SUBSTITUTE, 0xbb, 0xcc]).is_empty());
        let frames = decoder.feed(&[FLAG]);
        assert_eq!(frames, vec![Decoded::Rejected(AshError::Substituted)]);

        // And the stream is usable again immediately.
        let frame = AshFrame::Ack {
            ack_num: 0,
            not_ready: false,
        };
        assert_eq!(
            decoder.feed(&encode(&frame).expect("encodes")),
            vec![Decoded::Frame(frame)]
        );
    }

    #[test]
    fn flow_control_bytes_are_ignored_mid_frame() {
        // The NCP can interleave XON/XOFF anywhere. Treating one as data would
        // corrupt the frame it landed in.
        let frame = AshFrame::Ack {
            ack_num: 2,
            not_ready: false,
        };
        let bytes = encode(&frame).expect("encodes");
        let mut stream = Vec::new();
        for (index, byte) in bytes.iter().enumerate() {
            if index == 1 {
                stream.push(XON);
            }
            stream.push(*byte);
        }
        let mut decoder = Decoder::new();
        assert_eq!(decoder.feed(&stream), vec![Decoded::Frame(frame)]);
    }

    #[test]
    fn repeated_delimiters_produce_nothing_rather_than_errors() {
        // The NCP delimits with flags; a gap between two is not a frame.
        let mut decoder = Decoder::new();
        assert!(decoder.feed(&[FLAG, FLAG, FLAG]).is_empty());
    }

    #[test]
    fn a_frame_too_short_to_hold_a_crc_is_refused() {
        let mut decoder = Decoder::new();
        let frames = decoder.feed(&[0x25, 0xaa, FLAG]);
        assert!(matches!(
            frames.first(),
            Some(Decoded::Rejected(AshError::TooShort { .. }))
        ));
    }

    #[test]
    fn a_stream_with_no_delimiter_does_not_grow_without_bound() {
        // Hostile input: bytes forever and never a flag. The buffer must stay
        // bounded and the frame must be reported once it is delimited.
        let mut decoder = Decoder::new();
        decoder.feed(&vec![0xaa; 10_000]);
        let frames = decoder.feed(&[FLAG]);
        assert!(
            matches!(
                frames.first(),
                Some(Decoded::Rejected(AshError::TooLong { .. }))
            ),
            "got {frames:?}"
        );
    }

    #[test]
    fn an_escape_at_the_end_of_a_read_carries_into_the_next() {
        // Escape state has to survive a read boundary, or a stuffed byte split
        // across two reads decodes as its unescaped self.
        // The payload is randomised *before* stuffing, so the byte that
        // forces an escape is not the reserved byte itself: the first LFSR
        // output is 0x42, so 0x3c ^ 0x42 == 0x7e, the delimiter.
        let frame = AshFrame::Data {
            frame_num: 0,
            ack_num: 0,
            retransmit: false,
            payload: vec![FLAG ^ 0x42],
        };
        let bytes = encode(&frame).expect("encodes");
        let escape_at = bytes
            .iter()
            .position(|b| *b == ESCAPE)
            .expect("a randomised payload byte of 0x7e must be escaped");

        let mut decoder = Decoder::new();
        let (head, tail) = bytes.split_at(escape_at + 1);
        assert!(decoder.feed(head).is_empty());
        assert_eq!(decoder.feed(tail), vec![Decoded::Frame(frame)]);
    }
}
