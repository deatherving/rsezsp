//! ASH frame types and the control byte.
//!
//! Every ASH frame is `[control, payload…, crc_hi, crc_lo, FLAG]`, and the
//! control byte alone says which of six kinds it is and how long the rest must
//! be. Modelling that as an enum rather than a struct of booleans means an
//! impossible combination -- a `RST` carrying an ack number, say -- cannot be
//! constructed.
//!
//! ```text
//! DATA    0b0FFF_RAAA   FFF = frame number, R = retransmit, AAA = ack number
//! ACK     0b1000_NAAA   N   = not-ready
//! NAK     0b1010_NAAA
//! RST     0b1100_0000
//! `RSTACK`  0b1100_0001   payload: [ash version, reset code]
//! ERROR   0b1100_0010   payload: [ash version, error code]
//! ```

use crate::ash::error::AshError;

/// The ASH protocol version this crate speaks.
pub const ASH_VERSION: u8 = 2;

/// The largest data field an ASH frame may carry.
pub const MAX_DATA_FIELD_LEN: usize = 128;

/// Frame numbers and ack numbers are three bits wide, so they wrap at 8.
pub const SEQUENCE_MODULUS: u8 = 8;

const CONTROL_DATA_MASK: u8 = 0x80;
const CONTROL_SHORT_MASK: u8 = 0xe0;
const ACK_NUM_MASK: u8 = 0x07;
const FRAME_NUM_MASK: u8 = 0x70;
const FRAME_NUM_SHIFT: u8 = 4;
const RETRANSMIT_MASK: u8 = 0x08;
const NOT_READY_MASK: u8 = 0x08;

const CONTROL_ACK: u8 = 0x80;
const CONTROL_NAK: u8 = 0xa0;
const CONTROL_RST: u8 = 0xc0;
const CONTROL_RSTACK: u8 = 0xc1;
const CONTROL_ERROR: u8 = 0xc2;

/// One ASH frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AshFrame {
    /// Carries an EZSP frame.
    Data {
        /// This frame's number, 0..8.
        frame_num: u8,
        /// The number of the next frame we expect from the NCP.
        ack_num: u8,
        /// Set when this is a resend of a frame already sent.
        ///
        /// The NCP uses it to tell a genuine duplicate from a new frame that
        /// happens to reuse a number after a wrap.
        retransmit: bool,
        /// The EZSP frame, already de-randomised on receive.
        payload: Vec<u8>,
    },
    /// Acknowledges frames up to `ack_num`.
    Ack {
        /// The next frame number expected.
        ack_num: u8,
        /// The sender cannot accept more data yet.
        not_ready: bool,
    },
    /// Rejects a frame and asks for a resend from `ack_num`.
    Nak {
        /// The next frame number expected.
        ack_num: u8,
        /// The sender cannot accept more data yet.
        not_ready: bool,
    },
    /// Host asks the NCP to reset.
    Rst,
    /// The NCP has reset and is ready.
    RstAck {
        /// ASH version the NCP speaks.
        version: u8,
        /// Why it reset.
        reset_code: u8,
    },
    /// The NCP hit an error and needs resetting.
    Error {
        /// ASH version the NCP speaks.
        version: u8,
        /// What went wrong.
        error_code: u8,
    },
}

impl AshFrame {
    /// The control byte for this frame.
    pub const fn control(&self) -> u8 {
        match self {
            Self::Data {
                frame_num,
                ack_num,
                retransmit,
                ..
            } => {
                ((*frame_num % SEQUENCE_MODULUS) << FRAME_NUM_SHIFT)
                    | (if *retransmit { RETRANSMIT_MASK } else { 0 })
                    | (*ack_num % SEQUENCE_MODULUS)
            }
            Self::Ack { ack_num, not_ready } => {
                CONTROL_ACK
                    | (if *not_ready { NOT_READY_MASK } else { 0 })
                    | (*ack_num % SEQUENCE_MODULUS)
            }
            Self::Nak { ack_num, not_ready } => {
                CONTROL_NAK
                    | (if *not_ready { NOT_READY_MASK } else { 0 })
                    | (*ack_num % SEQUENCE_MODULUS)
            }
            Self::Rst => CONTROL_RST,
            Self::RstAck { .. } => CONTROL_RSTACK,
            Self::Error { .. } => CONTROL_ERROR,
        }
    }

    /// The bytes after the control byte, before the CRC.
    ///
    /// Owned rather than borrowed because `RSTACK` and `ERROR` carry two bytes
    /// that are fields of the enum rather than a stored slice. Returning a
    /// borrow forced them to be empty, which silently made those two frames
    /// unable to round-trip -- they encoded without their version and code.
    /// One allocation per frame is nothing at 115200 baud.
    pub fn body(&self) -> Vec<u8> {
        match self {
            Self::Data { payload, .. } => payload.clone(),
            Self::RstAck {
                version,
                reset_code,
            } => vec![*version, *reset_code],
            Self::Error {
                version,
                error_code,
            } => vec![*version, *error_code],
            Self::Ack { .. } | Self::Nak { .. } | Self::Rst => Vec::new(),
        }
    }

    /// Whether this frame acknowledges data, and up to what number.
    pub const fn acknowledges(&self) -> Option<u8> {
        match self {
            Self::Data { ack_num, .. } | Self::Ack { ack_num, .. } | Self::Nak { ack_num, .. } => {
                Some(*ack_num)
            }
            _ => None,
        }
    }

    /// Parses a control byte and body into a frame.
    ///
    /// The length is checked against the type, because a control byte alone
    /// cannot be trusted: `RSTACK` with no body is not a short `RSTACK`, it is
    /// a corrupted frame that would otherwise be read as a successful reset.
    ///
    /// # Errors
    ///
    /// [`AshError::InvalidControl`] when the control byte and length disagree,
    /// and [`AshError::TooLong`] for an oversized data field.
    pub fn from_parts(control: u8, body: &[u8]) -> Result<Self, AshError> {
        let invalid = || AshError::InvalidControl {
            control,
            length: body.len(),
        };

        // A data frame is the only kind with the top bit clear, and the only
        // kind with a variable-length body.
        if control & CONTROL_DATA_MASK == 0 {
            if body.len() > MAX_DATA_FIELD_LEN {
                return Err(AshError::TooLong {
                    length: body.len(),
                    maximum: MAX_DATA_FIELD_LEN,
                });
            }
            return Ok(Self::Data {
                frame_num: (control & FRAME_NUM_MASK) >> FRAME_NUM_SHIFT,
                ack_num: control & ACK_NUM_MASK,
                retransmit: control & RETRANSMIT_MASK != 0,
                payload: body.to_vec(),
            });
        }

        // The three fixed control bytes are matched before the masked ones,
        // because 0xc0..0xc2 would otherwise fall into the ACK/NAK pattern.
        match control {
            CONTROL_RST => {
                if body.is_empty() {
                    Ok(Self::Rst)
                } else {
                    Err(invalid())
                }
            }
            CONTROL_RSTACK => {
                let [version, reset_code] = body else {
                    return Err(invalid());
                };
                Ok(Self::RstAck {
                    version: *version,
                    reset_code: *reset_code,
                })
            }
            CONTROL_ERROR => {
                let [version, error_code] = body else {
                    return Err(invalid());
                };
                Ok(Self::Error {
                    version: *version,
                    error_code: *error_code,
                })
            }
            _ => {
                if !body.is_empty() {
                    return Err(invalid());
                }
                let ack_num = control & ACK_NUM_MASK;
                let not_ready = control & NOT_READY_MASK != 0;
                match control & CONTROL_SHORT_MASK {
                    CONTROL_ACK => Ok(Self::Ack { ack_num, not_ready }),
                    CONTROL_NAK => Ok(Self::Nak { ack_num, not_ready }),
                    _ => Err(invalid()),
                }
            }
        }
    }
}

/// The next sequence number after `n`, wrapping at 8.
///
/// Its own function because the wrap is where sequence bugs live: three bits
/// means 7 is followed by 0, and an implementation that increments freely
/// works for exactly seven frames.
pub const fn next_sequence(n: u8) -> u8 {
    (n + 1) % SEQUENCE_MODULUS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_data_control_byte_packs_the_three_fields() {
        let frame = AshFrame::Data {
            frame_num: 2,
            ack_num: 5,
            retransmit: false,
            payload: vec![],
        };
        // 0b0_010_0_101
        assert_eq!(frame.control(), 0x25);

        let retransmitted = AshFrame::Data {
            frame_num: 2,
            ack_num: 5,
            retransmit: true,
            payload: vec![],
        };
        assert_eq!(retransmitted.control(), 0x2d, "the retransmit bit is 0x08");
    }

    #[test]
    fn control_bytes_round_trip_for_every_kind() {
        let frames = [
            AshFrame::Data {
                frame_num: 7,
                ack_num: 3,
                retransmit: true,
                payload: vec![0xaa, 0xbb],
            },
            AshFrame::Ack {
                ack_num: 1,
                not_ready: false,
            },
            AshFrame::Ack {
                ack_num: 6,
                not_ready: true,
            },
            AshFrame::Nak {
                ack_num: 2,
                not_ready: false,
            },
            AshFrame::Rst,
            AshFrame::RstAck {
                version: ASH_VERSION,
                reset_code: 0x0b,
            },
            AshFrame::Error {
                version: ASH_VERSION,
                error_code: 0x51,
            },
        ];
        for frame in frames {
            let parsed = AshFrame::from_parts(frame.control(), &frame.body())
                .unwrap_or_else(|e| panic!("{frame:?} must round-trip, got {e}"));
            assert_eq!(parsed, frame);
        }
    }

    #[test]
    fn the_fixed_control_bytes_are_not_read_as_ack_or_nak() {
        // 0xc0..0xc2 fall inside the ACK/NAK bit pattern, so matching the
        // masked forms first would turn a reset into an acknowledgement --
        // and the handshake would appear to succeed while the NCP is resetting.
        assert_eq!(AshFrame::from_parts(0xc0, &[]).expect("RST"), AshFrame::Rst);
        assert!(matches!(
            AshFrame::from_parts(0xc1, &[2, 0x0b]).expect("RSTACK"),
            AshFrame::RstAck { .. }
        ));
        assert!(matches!(
            AshFrame::from_parts(0xc2, &[2, 0x51]).expect("ERROR"),
            AshFrame::Error { .. }
        ));
    }

    #[test]
    fn a_short_rstack_is_refused_rather_than_read_as_a_reset() {
        // The dangerous case: a corrupted RSTACK with a missing body would
        // otherwise report a successful reset that never happened.
        for body in [&[][..], &[2][..], &[2, 0x0b, 0x00][..]] {
            assert!(
                AshFrame::from_parts(0xc1, body).is_err(),
                "RSTACK must carry exactly two body bytes, got {body:?}"
            );
        }
    }

    #[test]
    fn an_ack_carrying_a_body_is_refused() {
        // ACK and NAK have no body. One that arrives with bytes is a framing
        // error, not an ACK with extra information.
        assert!(AshFrame::from_parts(0x81, &[0xff]).is_err());
        assert!(AshFrame::from_parts(0xa1, &[0xff]).is_err());
    }

    #[test]
    fn an_oversized_data_field_is_refused() {
        let body = vec![0u8; MAX_DATA_FIELD_LEN + 1];
        assert!(matches!(
            AshFrame::from_parts(0x00, &body),
            Err(AshError::TooLong { .. })
        ));
    }

    #[test]
    fn sequence_numbers_wrap_at_eight() {
        // Three bits. An implementation that increments freely works for
        // exactly seven frames and then addresses frame 8, which does not
        // exist.
        assert_eq!(next_sequence(0), 1);
        assert_eq!(next_sequence(6), 7);
        assert_eq!(next_sequence(7), 0, "7 wraps to 0, not to 8");
        // And the control byte cannot express an out-of-range number.
        let frame = AshFrame::Data {
            frame_num: 9,
            ack_num: 11,
            retransmit: false,
            payload: vec![],
        };
        let parsed = AshFrame::from_parts(frame.control(), &[]).expect("parses");
        assert_eq!(
            parsed,
            AshFrame::Data {
                frame_num: 1,
                ack_num: 3,
                retransmit: false,
                payload: vec![]
            },
            "out-of-range numbers must be reduced, never truncated into another field"
        );
    }
}
