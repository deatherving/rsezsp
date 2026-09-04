//! The ASH connection state machine.
//!
//! ASH state is small but every piece of it is load-bearing: two sequence
//! counters, a retransmit queue, and a connection phase. Held as separate
//! booleans it becomes possible to be half-connected, or to acknowledge a frame
//! that was never received, so the phase is an enum and the counters live
//! behind methods that maintain their own invariants.
//!
//! # Sans-I/O
//!
//! This type performs no I/O and owns no timer. It is fed received frames and
//! asked what to send; the caller does the writing and the waiting. That is
//! what makes a reset handshake, a retransmission and a sequence rollover all
//! testable without a serial port or a clock.

use crate::ash::error::AshError;
use crate::ash::frame::{AshFrame, next_sequence};

/// How many times a reset is attempted before giving up.
pub const MAX_RESET_ATTEMPTS: u8 = 5;

/// How many times a data frame is resent before the link is declared dead.
pub const MAX_RETRANSMITS: u8 = 3;

/// How many frames may be unacknowledged at once.
///
/// Seven, one short of the eight-value sequence space, and the shortfall is
/// the point. With all eight outstanding, an `ack_num` of 0 means both "none
/// acknowledged" and "all eight acknowledged" -- the counter has wrapped onto
/// itself and there is nothing in the frame to distinguish the two. Bounding
/// the window one below the modulus makes that state unreachable.
pub const MAX_WINDOW: usize = 7;

/// Where the connection is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Nothing has been sent; no NCP known to be there.
    Disconnected,
    /// A reset has been sent and `RSTACK` is awaited.
    Resetting {
        /// How many resets have been sent.
        attempts: u8,
    },
    /// The NCP answered and frames may flow.
    Connected,
    /// The link failed in a way a reset will not fix.
    Failed,
}

/// Something the caller should send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outbound {
    /// Write this frame to the port.
    Send(AshFrame),
    /// Nothing to do.
    Nothing,
}

/// An in-flight data frame awaiting acknowledgement.
#[derive(Debug, Clone)]
struct InFlight {
    frame_num: u8,
    payload: Vec<u8>,
    sends: u8,
}

/// The ASH half of a connection.
#[derive(Debug)]
pub struct Connection {
    state: ConnectionState,
    /// The number the next data frame we send will carry.
    next_tx_frame: u8,
    /// The number of the next data frame we expect to receive.
    next_rx_frame: u8,
    /// Frames sent and not yet acknowledged, oldest first.
    in_flight: Vec<InFlight>,
    /// Set when a received frame needs acknowledging.
    ack_pending: bool,
    /// Set when a received frame was bad and the NCP should resend.
    nak_pending: bool,
}

impl Default for Connection {
    fn default() -> Self {
        Self::new()
    }
}

impl Connection {
    /// A fresh, disconnected connection.
    pub const fn new() -> Self {
        Self {
            state: ConnectionState::Disconnected,
            next_tx_frame: 0,
            next_rx_frame: 0,
            in_flight: Vec::new(),
            ack_pending: false,
            nak_pending: false,
        }
    }

    /// Where the connection is.
    pub const fn state(&self) -> ConnectionState {
        self.state
    }

    /// Whether data may be sent.
    pub const fn is_connected(&self) -> bool {
        matches!(self.state, ConnectionState::Connected)
    }

    /// How many frames are awaiting acknowledgement.
    pub fn in_flight(&self) -> usize {
        self.in_flight.len()
    }

    /// Begins the reset handshake.
    ///
    /// Counters go back to zero here rather than on `RSTACK`: after a reset the
    /// NCP starts from frame zero, and a host that kept its old numbering
    /// would send a frame the NCP rejects as out of sequence.
    pub fn begin_reset(&mut self) -> Outbound {
        let attempts = match self.state {
            ConnectionState::Resetting { attempts } => attempts,
            _ => 0,
        };
        if attempts >= MAX_RESET_ATTEMPTS {
            self.state = ConnectionState::Failed;
            return Outbound::Nothing;
        }
        self.state = ConnectionState::Resetting {
            attempts: attempts.saturating_add(1),
        };
        self.next_tx_frame = 0;
        self.next_rx_frame = 0;
        self.in_flight.clear();
        self.ack_pending = false;
        self.nak_pending = false;
        Outbound::Send(AshFrame::Rst)
    }

    /// Queues a payload and returns the data frame to send.
    ///
    /// # Errors
    ///
    /// [`AshError::NotConnected`] before the handshake completes -- sending
    /// data to an NCP that has not answered a reset produces no reply and no
    /// diagnosis, so refusing says which step was skipped -- and
    /// [`AshError::WindowFull`] when seven frames are already outstanding.
    pub fn send_data(&mut self, payload: Vec<u8>) -> Result<AshFrame, AshError> {
        if !self.is_connected() {
            return Err(AshError::NotConnected);
        }
        if self.in_flight.len() >= MAX_WINDOW {
            return Err(AshError::WindowFull {
                outstanding: self.in_flight.len(),
                limit: MAX_WINDOW,
            });
        }
        let frame_num = self.next_tx_frame;
        self.next_tx_frame = next_sequence(frame_num);
        self.in_flight.push(InFlight {
            frame_num,
            payload: payload.clone(),
            sends: 1,
        });
        self.ack_pending = false;
        Ok(AshFrame::Data {
            frame_num,
            ack_num: self.next_rx_frame,
            retransmit: false,
            payload,
        })
    }

    /// What a received frame means, and what to send back.
    ///
    /// Returns the payload of a data frame when one arrived, alongside whatever
    /// the caller should write. Both, because a data frame simultaneously
    /// delivers a payload and obliges an acknowledgement, and returning only
    /// one of those invites forgetting the other.
    pub fn on_frame(&mut self, frame: &AshFrame) -> (Option<Vec<u8>>, Outbound) {
        match frame {
            AshFrame::RstAck { version, .. } => {
                // The handshake completing. Accepted from any state: an NCP
                // that resets on its own sends this unprompted, and treating
                // it as unexpected would leave the host talking to a device
                // that has forgotten the conversation.
                self.state = ConnectionState::Connected;
                self.next_tx_frame = 0;
                self.next_rx_frame = 0;
                self.in_flight.clear();
                self.ack_pending = false;
                self.nak_pending = false;
                tracing::debug!(ash_version = version, "NCP reset and ready");
                (None, Outbound::Nothing)
            }
            AshFrame::Error { .. } => {
                // Not recoverable by retrying: the NCP is telling us it needs
                // a reset before it will do anything else.
                self.state = ConnectionState::Failed;
                self.in_flight.clear();
                (None, Outbound::Nothing)
            }
            AshFrame::Ack { ack_num, .. } => {
                self.retire_acknowledged(*ack_num);
                (None, Outbound::Nothing)
            }
            AshFrame::Nak { ack_num, .. } => {
                self.retire_acknowledged(*ack_num);
                (None, self.retransmit_oldest())
            }
            AshFrame::Rst => {
                // The host sends these; an NCP does not. Ignored rather than
                // treated as an error, because a loopback or an echoing
                // adapter can produce one and it means nothing.
                (None, Outbound::Nothing)
            }
            AshFrame::Data {
                frame_num,
                ack_num,
                payload,
                ..
            } => {
                self.retire_acknowledged(*ack_num);

                if *frame_num == self.next_rx_frame {
                    self.next_rx_frame = next_sequence(*frame_num);
                    self.nak_pending = false;
                    let ack = AshFrame::Ack {
                        ack_num: self.next_rx_frame,
                        not_ready: false,
                    };
                    (Some(payload.clone()), Outbound::Send(ack))
                } else {
                    // Either a duplicate the NCP resent because our ack was
                    // lost, or a genuine gap. Both are answered by
                    // re-acknowledging what we do have: a duplicate must not
                    // be delivered twice, and a gap must not be filled by
                    // accepting a frame out of order.
                    tracing::debug!(
                        received = frame_num,
                        expected = self.next_rx_frame,
                        "out-of-sequence ASH data frame"
                    );
                    let ack = AshFrame::Ack {
                        ack_num: self.next_rx_frame,
                        not_ready: false,
                    };
                    (None, Outbound::Send(ack))
                }
            }
        }
    }

    /// What to send when a received frame failed to decode.
    ///
    /// A NAK for the recoverable cases, so the NCP resends. Anything else is
    /// left alone: `NAKing` a protocol violation asks for the same bad frame
    /// again.
    pub fn on_decode_failure(&mut self, error: &AshError) -> Outbound {
        if error.is_recoverable_by_nak() {
            self.nak_pending = true;
            Outbound::Send(AshFrame::Nak {
                ack_num: self.next_rx_frame,
                not_ready: false,
            })
        } else {
            Outbound::Nothing
        }
    }

    /// Resends the oldest unacknowledged frame, if there is one.
    ///
    /// Called on a NAK and on a timeout. The retransmit bit is set so the NCP
    /// can tell a genuine resend from a new frame that reuses the number after
    /// a wrap.
    pub fn retransmit_oldest(&mut self) -> Outbound {
        let ack_num = self.next_rx_frame;
        let Some(oldest) = self.in_flight.first_mut() else {
            return Outbound::Nothing;
        };
        if oldest.sends >= MAX_RETRANSMITS {
            self.state = ConnectionState::Failed;
            return Outbound::Nothing;
        }
        oldest.sends = oldest.sends.saturating_add(1);
        Outbound::Send(AshFrame::Data {
            frame_num: oldest.frame_num,
            ack_num,
            retransmit: true,
            payload: oldest.payload.clone(),
        })
    }

    /// Drops frames the NCP has acknowledged.
    ///
    /// `ack_num` is the next frame the NCP expects, so every frame before it is
    /// acknowledged.
    ///
    /// Done positionally rather than with modular arithmetic. The queue is
    /// ordered oldest-first, so "everything before `ack_num`" is "everything
    /// ahead of the entry numbered `ack_num`" -- which needs no reasoning about
    /// the wrap and cannot be off by a window. A comparison on the numbers
    /// themselves has to decide whether `ack_num` 0 is before or after frame 7,
    /// and both answers are right in different situations.
    ///
    /// `ack_num` not being present means every outstanding frame is behind it,
    /// so the queue drains.
    fn retire_acknowledged(&mut self, ack_num: u8) {
        let cut = self
            .in_flight
            .iter()
            .position(|frame| frame.frame_num == ack_num)
            .unwrap_or(self.in_flight.len());
        self.in_flight.drain(..cut);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A connection that has completed the handshake.
    fn connected() -> Connection {
        let mut connection = Connection::new();
        assert_eq!(connection.begin_reset(), Outbound::Send(AshFrame::Rst));
        connection.on_frame(&AshFrame::RstAck {
            version: 2,
            reset_code: 0x0b,
        });
        assert!(connection.is_connected());
        connection
    }

    #[test]
    fn data_is_refused_before_the_handshake_completes() {
        // Sending data to an NCP that has not answered a reset produces no
        // reply and no diagnosis. Refusing names the step that was skipped.
        let mut connection = Connection::new();
        assert!(matches!(
            connection.send_data(vec![0x00]),
            Err(AshError::NotConnected)
        ));

        connection.begin_reset();
        assert!(
            connection.send_data(vec![0x00]).is_err(),
            "a reset that has not been answered is not a connection"
        );
    }

    #[test]
    fn the_handshake_resets_both_counters() {
        // After a reset the NCP starts from frame zero. A host that kept its
        // old numbering sends a frame the NCP rejects as out of sequence, and
        // the link appears to connect and then go silent.
        let mut connection = connected();
        connection.send_data(vec![0x01]).expect("sends");
        connection.send_data(vec![0x02]).expect("sends");
        assert_eq!(connection.next_tx_frame, 2);

        connection.on_frame(&AshFrame::RstAck {
            version: 2,
            reset_code: 0x0b,
        });
        assert_eq!(connection.next_tx_frame, 0);
        assert_eq!(connection.next_rx_frame, 0);
        assert_eq!(
            connection.in_flight(),
            0,
            "frames in flight belong to the connection that just went away"
        );
    }

    #[test]
    fn an_unprompted_rstack_reconnects_rather_than_erroring() {
        // An NCP that resets on its own sends this unasked. Treating it as
        // unexpected leaves the host talking to a device that has forgotten
        // the conversation.
        let mut connection = Connection::new();
        connection.on_frame(&AshFrame::RstAck {
            version: 2,
            reset_code: 0x02,
        });
        assert!(connection.is_connected());
    }

    #[test]
    fn a_data_frame_is_delivered_and_acknowledged_together() {
        let mut connection = connected();
        let (payload, outbound) = connection.on_frame(&AshFrame::Data {
            frame_num: 0,
            ack_num: 0,
            retransmit: false,
            payload: vec![0xaa],
        });
        assert_eq!(payload, Some(vec![0xaa]));
        assert_eq!(
            outbound,
            Outbound::Send(AshFrame::Ack {
                ack_num: 1,
                not_ready: false
            }),
            "the ack names the next frame expected, not the one received"
        );
    }

    #[test]
    fn a_duplicate_frame_is_acknowledged_but_not_delivered_twice() {
        // The NCP resends when our ack is lost. Delivering the payload again
        // would double every command's effect.
        let mut connection = connected();
        let first = AshFrame::Data {
            frame_num: 0,
            ack_num: 0,
            retransmit: false,
            payload: vec![0xaa],
        };
        assert_eq!(connection.on_frame(&first).0, Some(vec![0xaa]));

        let duplicate = AshFrame::Data {
            frame_num: 0,
            ack_num: 0,
            retransmit: true,
            payload: vec![0xaa],
        };
        let (payload, outbound) = connection.on_frame(&duplicate);
        assert_eq!(payload, None, "a duplicate must not be delivered again");
        assert!(
            matches!(outbound, Outbound::Send(AshFrame::Ack { ack_num: 1, .. })),
            "but it must still be acknowledged, or the NCP keeps resending"
        );
    }

    #[test]
    fn an_out_of_sequence_frame_is_not_accepted_out_of_order() {
        let mut connection = connected();
        let (payload, outbound) = connection.on_frame(&AshFrame::Data {
            frame_num: 3,
            ack_num: 0,
            retransmit: false,
            payload: vec![0xbb],
        });
        assert_eq!(payload, None, "a gap must not be filled by guessing");
        assert!(matches!(
            outbound,
            Outbound::Send(AshFrame::Ack { ack_num: 0, .. })
        ));
    }

    #[test]
    fn a_nak_resends_the_oldest_frame_with_the_retransmit_bit_set() {
        let mut connection = connected();
        connection.send_data(vec![0x11]).expect("sends");
        let (_, outbound) = connection.on_frame(&AshFrame::Nak {
            ack_num: 0,
            not_ready: false,
        });
        match outbound {
            Outbound::Send(AshFrame::Data {
                frame_num,
                retransmit,
                payload,
                ..
            }) => {
                assert_eq!(frame_num, 0);
                assert_eq!(payload, vec![0x11]);
                assert!(
                    retransmit,
                    "the bit is how the NCP tells a resend from a wrapped number"
                );
            }
            other => panic!("expected a resend, got {other:?}"),
        }
    }

    #[test]
    fn an_ack_retires_frames_across_the_sequence_wrap() {
        // Three bits, so frame 6 acknowledged by ack_num 7 and frame 7 by
        // ack_num 0 are both normal. A plain `<` comparison gets the second
        // wrong -- the frame is never retired, the window fills, and the link
        // stalls after exactly eight frames.
        let mut connection = connected();
        for n in 0..u8::try_from(MAX_WINDOW).unwrap_or(u8::MAX) {
            connection.send_data(vec![n]).expect("sends");
        }
        assert_eq!(connection.in_flight(), MAX_WINDOW);

        // Frames 0..6 are outstanding, so "next expected 7" acknowledges all
        // of them.
        connection.on_frame(&AshFrame::Ack {
            ack_num: 7,
            not_ready: false,
        });
        assert_eq!(connection.in_flight(), 0);

        // Now push the numbering across the wrap: 7, 0, 1.
        for n in 0..3u8 {
            connection.send_data(vec![0x10 + n]).expect("sends");
        }
        // A partial ack: the NCP expects 0, so only frame 7 is acknowledged.
        connection.on_frame(&AshFrame::Ack {
            ack_num: 0,
            not_ready: false,
        });
        assert_eq!(
            connection.in_flight(),
            2,
            "an ack at the wrap point must retire exactly what it covers"
        );

        // And the rest.
        connection.on_frame(&AshFrame::Ack {
            ack_num: 2,
            not_ready: false,
        });
        assert_eq!(connection.in_flight(), 0);
    }

    #[test]
    fn the_send_window_stops_one_short_of_the_sequence_space() {
        // Not an arbitrary limit. With all eight outstanding, an ack_num of 0
        // means both "none acknowledged" and "all eight acknowledged" -- the
        // counter has wrapped onto itself. Bounding the window at seven makes
        // that ambiguity unreachable rather than something to disambiguate.
        let mut connection = connected();
        for n in 0..u8::try_from(MAX_WINDOW).unwrap_or(u8::MAX) {
            connection.send_data(vec![n]).expect("sends");
        }
        assert!(matches!(
            connection.send_data(vec![0xff]),
            Err(AshError::WindowFull { .. })
        ));

        // And it reopens as frames are acknowledged.
        connection.on_frame(&AshFrame::Ack {
            ack_num: 3,
            not_ready: false,
        });
        assert!(connection.send_data(vec![0xff]).is_ok());
    }

    #[test]
    fn an_ack_retires_only_what_it_covers() {
        let mut connection = connected();
        connection.send_data(vec![0]).expect("sends");
        connection.send_data(vec![1]).expect("sends");
        connection.send_data(vec![2]).expect("sends");

        // Next expected is 2, so frames 0 and 1 are acknowledged and 2 is not.
        connection.on_frame(&AshFrame::Ack {
            ack_num: 2,
            not_ready: false,
        });
        assert_eq!(connection.in_flight(), 1);
    }

    #[test]
    fn the_link_fails_after_too_many_resends_rather_than_looping() {
        let mut connection = connected();
        connection.send_data(vec![0x11]).expect("sends");
        for _ in 0..MAX_RETRANSMITS {
            connection.retransmit_oldest();
        }
        assert_eq!(connection.state(), ConnectionState::Failed);
        assert_eq!(
            connection.retransmit_oldest(),
            Outbound::Nothing,
            "a failed link must stop resending"
        );
    }

    #[test]
    fn reset_gives_up_after_a_bounded_number_of_attempts() {
        // A dongle that is not there, or is wedged, must produce a failure
        // rather than an infinite handshake.
        let mut connection = Connection::new();
        for _ in 0..MAX_RESET_ATTEMPTS {
            assert_eq!(connection.begin_reset(), Outbound::Send(AshFrame::Rst));
        }
        assert_eq!(connection.begin_reset(), Outbound::Nothing);
        assert_eq!(connection.state(), ConnectionState::Failed);
    }

    #[test]
    fn an_ncp_error_frame_fails_the_link_without_retrying() {
        // The NCP is saying it needs a reset before it will do anything. A
        // retry would be answered with the same error.
        let mut connection = connected();
        connection.send_data(vec![0x11]).expect("sends");
        connection.on_frame(&AshFrame::Error {
            version: 2,
            error_code: 0x51,
        });
        assert_eq!(connection.state(), ConnectionState::Failed);
        assert_eq!(connection.in_flight(), 0);
    }

    #[test]
    fn a_bad_crc_produces_a_nak_and_a_protocol_error_does_not() {
        let mut connection = connected();
        let nak = connection.on_decode_failure(&AshError::BadCrc {
            computed: 1,
            carried: 2,
        });
        assert!(matches!(nak, Outbound::Send(AshFrame::Nak { .. })));

        let nothing = connection.on_decode_failure(&AshError::InvalidControl {
            control: 0xff,
            length: 0,
        });
        assert_eq!(
            nothing,
            Outbound::Nothing,
            "NAKing a protocol violation asks for the same bad frame again"
        );
    }
}
