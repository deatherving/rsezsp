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
        /// Link quality reported by the node that last relayed the message.
        last_hop_lqi: u8,
        /// Signal strength in dBm, and genuinely signed -- a healthy link is
        /// a negative number.
        last_hop_rssi: i8,
        /// Who sent it.
        sender: NodeId,
        /// Index into the binding table, or `0xff` for none.
        binding_index: u8,
        /// Index into the address table, or `0xff` for none.
        address_index: u8,
        /// The application payload.
        payload: Vec<u8>,
    },

    /// A sent message was delivered, or was not. Frame id `0x003f`.
    ///
    /// Hardware: confirmed (EZSP 13) — including `status = 102`
    /// (delivery failed) for a frame sent to a sleepy device that was not
    /// polling.
    MessageSent {
        /// Unicast, broadcast or multicast.
        message_type: u8,
        /// The destination for a direct unicast, or a table index otherwise.
        /// Unspecified for multicasts and broadcasts.
        index_or_destination: u16,
        /// The APS header the message was sent with.
        aps_frame: ApsFrame,
        /// The tag the send command carried, which is how a caller matches
        /// this report to the message it sent.
        message_tag: u16,
        /// Whether it was delivered.
        status: SlStatus,
        /// The message as sent.
        payload: Vec<u8>,
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
                let message_type = input.u8()?;
                let index_or_destination = input.u16()?;
                let aps_frame = ApsFrame::decode(&mut input)?;
                // The tag width follows the same boundary as the send command
                // that set it: one byte below EZSP 14, two at or above.
                let message_tag = if version.has_wide_message_tag() {
                    input.u16()?
                } else {
                    u16::from(input.u8()?)
                };
                Ok(Self::MessageSent {
                    message_type,
                    index_or_destination,
                    aps_frame,
                    message_tag,
                    status: SlStatus::decode(&mut input)?,
                    payload: input.length_prefixed()?.to_vec(),
                })
            }
            FrameId::INCOMING_MESSAGE_HANDLER => Ok(Self::IncomingMessage {
                message_type: input.u8()?,
                aps_frame: ApsFrame::decode(&mut input)?,
                last_hop_lqi: input.u8()?,
                #[allow(clippy::cast_possible_wrap)]
                last_hop_rssi: input.u8()? as i8,
                sender: NodeId::decode(&mut input)?,
                binding_index: input.u8()?,
                address_index: input.u8()?,
                // Length-prefixed, and the prefix is load-bearing: some
                // firmware appends a source-route-overhead byte after the
                // payload. Taking the rest of the frame instead would fold
                // that byte into the application message.
                payload: input.length_prefixed()?.to_vec(),
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
    use crate::types::aps::ApsOptions;

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
    fn a_message_sent_report_is_read_from_the_right_offsets() {
        // This frame reports the send of a genOnOff command to 0x3a41 with
        // tag 1. An earlier decoder started at the message tag, so it read the
        // message *type* as the tag and the low byte of the destination
        // address as the status -- reporting "not delivered: 0x41" for a
        // message whose real status was never looked at. Both wrong values
        // were entirely plausible, which is why this asserts on offsets rather
        // than on a round trip.
        let bytes = [
            0x00, // direct unicast
            0x41, 0x3a, // destination 0x3a41
            0x04, 0x01, 0x06, 0x00, 0x01, 0x01, 0x40, 0x01, 0x00, 0x00, 0xda, // APS
            0x01, // message tag, as supplied to sendUnicast
            0x00, // status
            0x03, 0x01, 0x42, 0x01, // the ZCL bytes that were sent
        ];

        let decoded =
            Callback::decode(FrameId::MESSAGE_SENT_HANDLER, &bytes, V13).expect("v13 decodes");
        assert_eq!(
            decoded,
            Callback::MessageSent {
                message_type: 0,
                index_or_destination: 0x3a41,
                aps_frame: ApsFrame {
                    profile_id: 0x0104,
                    cluster_id: 0x0006,
                    source_endpoint: 1,
                    destination_endpoint: 1,
                    options: ApsOptions(0x0140),
                    group_id: 0,
                    sequence: 0xda,
                },
                message_tag: 1,
                status: SlStatus::OK,
                payload: vec![0x01, 0x42, 0x01],
            }
        );
    }

    #[test]
    fn a_message_sent_tag_and_status_widen_together_at_ezsp_fourteen() {
        // Both fields cross the same boundary, and they are adjacent: getting
        // one right and the other wrong misaligns everything after them.
        let mut wide = vec![0x00, 0x41, 0x3a];
        wide.extend_from_slice(&[
            0x04, 0x01, 0x06, 0x00, 0x01, 0x01, 0x40, 0x01, 0x00, 0x00, 0xda,
        ]);
        wide.extend_from_slice(&[0x01, 0x00]); // two-byte tag
        wide.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // four-byte status
        wide.extend_from_slice(&[0x00]); // empty payload

        let decoded = Callback::decode(
            FrameId::MESSAGE_SENT_HANDLER,
            &wide,
            ProtocolVersion::new(0x0e),
        )
        .expect("v14 decodes");
        let Callback::MessageSent {
            message_tag,
            status,
            payload,
            ..
        } = decoded
        else {
            panic!("expected a message-sent report, got {decoded:?}");
        };
        assert_eq!((message_tag, status), (1, SlStatus::OK));
        assert!(payload.is_empty());
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
    fn an_incoming_message_decodes_a_real_capture() {
        // Captured from the valve on a Sonoff ZBDongle-E at EZSP 13. The seven
        // bytes between the APS frame and the payload are why this test
        // exists: an earlier decoder took everything after the APS header as
        // the payload, so LQI, RSSI, the sender, two table indices and the
        // length prefix were all silently prepended to the ZCL message.
        let bytes = [
            0x00, // unicast
            0x04, 0x01, 0x11, 0xfc, 0x01, 0x01, 0x40, 0x01, 0x00, 0x00, 0x28, // APS
            0xff, // LQI
            0xe2, // RSSI, -30 dBm
            0x41, 0x3a, // sender 0x3a41
            0xff, 0xff, // no binding, no address table entry
            0x1e, // 30 bytes follow
            0x18, 0xd6, 0x0a, 0x1f, 0x50, 0x48, 0x20, 0x15, 0x00, 0x02, 0x00, 0x01, 0x00, 0x32,
            0x2d, 0xc3, 0xf1, 0x32, 0x2d, 0xc6, 0x49, 0x32, 0x2d, 0xc4, 0x0b, 0x01, 0x00, 0x00,
            0x00, 0x00,
        ];

        let decoded =
            Callback::decode(FrameId::INCOMING_MESSAGE_HANDLER, &bytes, V13).expect("decodes");
        let Callback::IncomingMessage {
            aps_frame,
            last_hop_lqi,
            last_hop_rssi,
            sender,
            binding_index,
            address_index,
            payload,
            ..
        } = decoded
        else {
            panic!("expected an incoming message, got {decoded:?}");
        };

        assert_eq!(sender, NodeId(0x3a41));
        assert_eq!(aps_frame.cluster_id, 0xfc11, "the Sonoff custom cluster");
        assert_eq!(last_hop_lqi, 0xff);
        assert_eq!(last_hop_rssi, -30, "RSSI is signed; read as u8 this is 226");
        assert_eq!((binding_index, address_index), (0xff, 0xff));
        assert_eq!(payload.len(), 30);
        assert_eq!(
            payload.first().copied(),
            Some(0x18),
            "the payload must start at the ZCL frame control byte, not at the LQI"
        );
    }
}
