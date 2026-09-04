//! Asynchronous callbacks from the NCP.
//!
//! Only the callbacks this project has actually observed on hardware are
//! decoded. The rest are carried through as [`Callback::Unknown`] with their
//! bytes intact, which is deliberate: a callback nobody has captured cannot be
//! decoded reliably from a datasheet alone, and guessing its layout produces a
//! typed value that is confidently wrong.
//!
//! Every variant below records where its layout came from and whether it has
//! been seen on a device.

use crate::ezsp::codec::{EzspDecode, Reader};
use crate::ezsp::error::EzspError;
use crate::ezsp::frame::FrameId;
use crate::ezsp::version::ProtocolVersion;
use crate::types::aps::ApsFrame;
use crate::types::network::{Eui64, NodeId};
use crate::types::status::SlStatus;

/// A decoded callback.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Callback {
    /// The stack's status changed. Frame id `0x0019`.
    ///
    /// `0x90` is network-up and `0x9c` is network-opened; both were observed
    /// during a real join.
    ///
    /// Hardware: confirmed (EZSP 13).
    StackStatus {
        /// The new status.
        status: SlStatus,
    },

    /// A device joined, rejoined or left. Frame id `0x0024`.
    ///
    /// The one callback that reports a join, and the reason a coordinator
    /// notices a device at all. Note that a *departure* arrives through this
    /// same callback, distinguished only by `device_update`: treating every
    /// one as an arrival resurrects devices that just left.
    ///
    /// Hardware: confirmed (EZSP 13) — a valve joining produced
    /// `device_update = 0` (standard security, unsecured join).
    TrustCenterJoin {
        /// The joining device's short address.
        node_id: NodeId,
        /// Its permanent address.
        eui64: Eui64,
        /// What happened: arrival, rejoin, or departure.
        device_update: u8,
        /// What the trust centre decided.
        decision: u8,
        /// The parent it joined through.
        parent_node_id: NodeId,
    },

    /// An application frame arrived. Frame id `0x0045`.
    ///
    /// Hardware: confirmed (EZSP 13).
    IncomingMessage {
        /// Unicast, broadcast or multicast.
        message_type: u8,
        /// The APS header.
        aps_frame: ApsFrame,
        /// The application payload.
        payload: Vec<u8>,
    },

    /// A sent message was delivered, or was not. Frame id `0x003f`.
    ///
    /// Hardware: confirmed (EZSP 13) — including `status = 102`
    /// (delivery failed) for a frame sent to a sleepy device that was not
    /// polling.
    MessageSent {
        /// The tag the send command carried.
        message_tag: u16,
        /// Whether it was delivered.
        status: SlStatus,
    },

    /// A callback this build does not decode.
    ///
    /// Carried rather than dropped so an unfamiliar firmware can be captured
    /// and reported. The bytes are exactly what arrived.
    Unknown {
        /// Which callback.
        frame_id: FrameId,
        /// Its undecoded parameters.
        parameters: Vec<u8>,
    },
}

impl Callback {
    /// Decodes a callback from its frame id and parameters.
    ///
    /// Never fails on an unrecognised id: that is an `Unknown`, not an error.
    /// It *does* fail when a callback this build claims to understand does not
    /// match its expected layout, because that means the layout is wrong for
    /// this firmware and silently accepting it would produce a typed value
    /// built from the wrong bytes.
    pub fn decode(
        frame_id: FrameId,
        parameters: &[u8],
        version: ProtocolVersion,
    ) -> Result<Self, EzspError> {
        let mut input = Reader::new(parameters, version);
        match frame_id {
            FrameId::STACK_STATUS_HANDLER => Ok(Self::StackStatus {
                status: SlStatus::decode(&mut input)?,
            }),
            FrameId::TRUST_CENTER_JOIN_HANDLER => Ok(Self::TrustCenterJoin {
                node_id: NodeId::decode(&mut input)?,
                eui64: Eui64::decode(&mut input)?,
                device_update: input.u8()?,
                decision: input.u8()?,
                parent_node_id: NodeId::decode(&mut input)?,
            }),
            FrameId::MESSAGE_SENT_HANDLER => {
                // The tag width follows the same boundary as the send command
                // that set it: one byte below EZSP 14, two at or above.
                let message_tag = if version.has_wide_message_tag() {
                    input.u16()?
                } else {
                    u16::from(input.u8()?)
                };
                Ok(Self::MessageSent {
                    message_tag,
                    status: SlStatus::decode(&mut input)?,
                })
            }
            FrameId::INCOMING_MESSAGE_HANDLER => Ok(Self::IncomingMessage {
                message_type: input.u8()?,
                aps_frame: ApsFrame::decode(&mut input)?,
                // Everything after the header. Length-prefixed forms differ
                // between firmware builds, so the remainder is taken whole
                // rather than trusting a length this build might read at the
                // wrong offset.
                payload: input.take_rest().to_vec(),
            }),
            _ => Ok(Self::Unknown {
                frame_id,
                parameters: parameters.to_vec(),
            }),
        }
    }

    /// Which callback this is.
    pub const fn frame_id(&self) -> FrameId {
        match self {
            Self::StackStatus { .. } => FrameId::STACK_STATUS_HANDLER,
            Self::TrustCenterJoin { .. } => FrameId::TRUST_CENTER_JOIN_HANDLER,
            Self::IncomingMessage { .. } => FrameId::INCOMING_MESSAGE_HANDLER,
            Self::MessageSent { .. } => FrameId::MESSAGE_SENT_HANDLER,
            Self::Unknown { frame_id, .. } => *frame_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const V13: ProtocolVersion = ProtocolVersion::new(0x0d);

    #[test]
    fn a_stack_status_callback_decodes_the_observed_values() {
        // 0x90 network-up and 0x9c network-opened, both seen during a real
        // join sequence.
        for raw in [0x90u8, 0x9c] {
            let callback =
                Callback::decode(FrameId::STACK_STATUS_HANDLER, &[raw], V13).expect("decodes");
            assert_eq!(
                callback,
                Callback::StackStatus {
                    status: SlStatus(u32::from(raw))
                }
            );
        }
    }

    #[test]
    fn a_trust_centre_join_decodes_a_real_capture() {
        // Taken from a valve joining a real coordinator: node 25287, address
        // 0xa4c138142d62ffff, update 0 (standard security unsecured join),
        // parent 0 (the coordinator).
        let mut parameters = Vec::new();
        parameters.extend_from_slice(&25287u16.to_le_bytes());
        parameters.extend_from_slice(&Eui64::new(0xa4c1_3814_2d62_ffff).to_wire());
        parameters.push(0x00);
        parameters.push(0x00);
        parameters.extend_from_slice(&0u16.to_le_bytes());

        let callback = Callback::decode(FrameId::TRUST_CENTER_JOIN_HANDLER, &parameters, V13)
            .expect("decodes");
        assert_eq!(
            callback,
            Callback::TrustCenterJoin {
                node_id: NodeId(25287),
                eui64: Eui64::new(0xa4c1_3814_2d62_ffff),
                device_update: 0,
                decision: 0,
                parent_node_id: NodeId::COORDINATOR,
            }
        );
    }

    #[test]
    fn a_message_sent_tag_follows_the_version_boundary() {
        // The tag width must match the send command that set it, or the status
        // is read from the tag's second byte.
        let narrow = [0x02, 0x66];
        let decoded =
            Callback::decode(FrameId::MESSAGE_SENT_HANDLER, &narrow, V13).expect("v13 decodes");
        assert_eq!(
            decoded,
            Callback::MessageSent {
                message_tag: 0x02,
                // 102: delivery failed, as observed for a frame sent to a
                // sleepy device that was not polling.
                status: SlStatus(102),
            }
        );

        let wide = [0x02, 0x00, 0x66, 0x00, 0x00, 0x00];
        let decoded = Callback::decode(
            FrameId::MESSAGE_SENT_HANDLER,
            &wide,
            ProtocolVersion::new(0x0e),
        )
        .expect("v14 decodes");
        assert_eq!(
            decoded,
            Callback::MessageSent {
                message_tag: 0x0002,
                status: SlStatus(0x66),
            }
        );
    }

    #[test]
    fn an_unknown_callback_keeps_its_bytes_rather_than_failing() {
        // So an unfamiliar firmware can be captured and reported instead of
        // taking the connection down.
        let callback = Callback::decode(FrameId(0x0999), &[0xde, 0xad], V13).expect("decodes");
        assert_eq!(
            callback,
            Callback::Unknown {
                frame_id: FrameId(0x0999),
                parameters: vec![0xde, 0xad],
            }
        );
    }

    #[test]
    fn a_truncated_known_callback_is_an_error_not_a_guess() {
        // A layout that does not fit means the layout is wrong for this
        // firmware. Accepting it would produce a typed value from the wrong
        // bytes -- which is worse than an error, because it looks like data.
        for len in 0..14 {
            let parameters = vec![0u8; len];
            assert!(
                Callback::decode(FrameId::TRUST_CENTER_JOIN_HANDLER, &parameters, V13).is_err(),
                "{len} bytes must not decode as a trust-centre join"
            );
        }
    }

    #[test]
    fn an_incoming_message_takes_its_payload_whole() {
        let mut parameters = vec![0x00];
        parameters.extend_from_slice(&[
            0x00, 0x00, 0x04, 0x80, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x27,
        ]);
        parameters.extend_from_slice(&[0x01, 0x02, 0x03]);

        let callback =
            Callback::decode(FrameId::INCOMING_MESSAGE_HANDLER, &parameters, V13).expect("decodes");
        match callback {
            Callback::IncomingMessage {
                aps_frame, payload, ..
            } => {
                assert_eq!(aps_frame.cluster_id, 0x8004);
                assert_eq!(payload, vec![0x01, 0x02, 0x03]);
            }
            other => panic!("expected an incoming message, got {other:?}"),
        }
    }
}
