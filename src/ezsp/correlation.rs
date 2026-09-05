//! Matching responses to the commands that asked for them.
//!
//! This is the module the crate exists for.
//!
//! # Why it is not obvious
//!
//! The naive model is "send a command, the next frame is its answer". That is
//! wrong on an Ember NCP, because callbacks arrive whenever the stack has
//! something to say — a device joined, a message was delivered, a frame came
//! in — and they interleave freely with responses:
//!
//! ```text
//! send command A
//!   callback X arrives      <- not A's answer
//!   response A arrives      <- A's answer
//!   callback Y arrives      <- not anything's answer
//! ```
//!
//! A correlator that takes the next frame hands the caller a decoded structure
//! built from an unrelated frame. That does not fail: it succeeds, with values
//! that look plausible.
//!
//! # The guard
//!
//! A frame is this command's answer only when **all three** hold:
//!
//! 1. it is not flagged as an asynchronous callback,
//! 2. its sequence number matches the pending command's, and
//! 3. its frame id matches the pending command's.
//!
//! All three, because each alone is insufficient. The callback flag can be
//! absent from a frame that is still not ours; sequence numbers are one byte
//! and wrap every 256 commands; and a frame id alone says nothing about which
//! of two identical commands answered.
//!
//! That triple is not theoretical. A sibling project matched ZCL responses on
//! `(cluster, sequence)` and accepted the coordinator's own echoed request as
//! the answer to its own read — resolving in 27ms with an empty result, which
//! read as a device that answered instantly with nothing.

use crate::ezsp::error::EzspError;
use crate::ezsp::frame::{Direction, Frame, FrameId};

/// A command awaiting its answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pending {
    /// The sequence number sent.
    pub sequence: u8,
    /// The command sent.
    pub frame_id: FrameId,
}

/// What an inbound frame turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Classified<'a> {
    /// The answer to the pending command.
    Response {
        /// The parameter bytes, still encoded.
        parameters: &'a [u8],
    },
    /// An asynchronous callback, for the caller to dispatch.
    Callback {
        /// Which callback.
        frame_id: FrameId,
        /// The parameter bytes, still encoded.
        parameters: &'a [u8],
    },
    /// A frame that belongs to nothing currently outstanding.
    ///
    /// Not an error. A response to a command that already timed out arrives
    /// here, and dropping it is correct -- but it is reported so a caller can
    /// count them, because a rising count means the timeout is too short.
    Stale {
        /// Which frame.
        frame_id: FrameId,
        /// Its sequence number.
        sequence: u8,
    },
}

/// Tracks one outstanding command and classifies what arrives.
///
/// One at a time, deliberately. EZSP over ASH has a small window and the NCP
/// answers in order, so a pipeline would add a queue whose only purpose is to
/// make correlation harder to reason about. The caller serialises commands; the
/// correlator's job is to be certain about which frame is the answer.
#[derive(Debug, Default)]
pub struct Correlator {
    pending: Option<Pending>,
    next_sequence: u8,
    /// Frames that matched nothing, counted rather than dropped silently.
    stale_frames: u64,
}

impl Correlator {
    /// A correlator with nothing outstanding.
    pub const fn new() -> Self {
        Self {
            pending: None,
            next_sequence: 0,
            stale_frames: 0,
        }
    }

    /// The sequence number the next command should carry.
    ///
    /// Wraps at 256, which is why the sequence alone cannot identify a
    /// response: after 256 commands the numbers repeat.
    pub const fn peek_sequence(&self) -> u8 {
        self.next_sequence
    }

    /// Whether a command is outstanding.
    pub const fn is_busy(&self) -> bool {
        self.pending.is_some()
    }

    /// What is outstanding, if anything.
    pub const fn pending(&self) -> Option<Pending> {
        self.pending
    }

    /// How many frames matched nothing outstanding.
    pub const fn stale_frames(&self) -> u64 {
        self.stale_frames
    }

    /// The command currently awaiting a response, if any.
    ///
    /// Exposed so a caller can decide how to log an inbound frame *before*
    /// parsing it -- which matters for responses carrying key material, where
    /// the unparsed bytes are the secret.
    #[must_use]
    pub const fn pending_frame_id(&self) -> Option<FrameId> {
        match &self.pending {
            Some(pending) => Some(pending.frame_id),
            None => None,
        }
    }

    /// Registers a command as outstanding and returns its sequence number.
    ///
    /// # Errors
    ///
    /// [`EzspError::NotConnected`] is not used here; a second concurrent
    /// command is refused with [`EzspError::SequenceMismatch`] naming the
    /// sequence still outstanding, because issuing one would make two
    /// commands indistinguishable if the NCP answered out of order.
    pub fn begin(&mut self, frame_id: FrameId) -> Result<u8, EzspError> {
        if let Some(pending) = self.pending {
            return Err(EzspError::SequenceMismatch {
                sequence: pending.sequence,
            });
        }
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        self.pending = Some(Pending { sequence, frame_id });
        Ok(sequence)
    }

    /// Classifies a received frame.
    ///
    /// Clears the pending command when the frame is its answer, so a duplicate
    /// arriving afterwards is classified stale rather than answering the *next*
    /// command to be issued.
    pub fn classify<'a>(&mut self, frame: &Frame<'a>) -> Classified<'a> {
        // A callback is never a response, whatever else matches. Checked first
        // because a callback can legitimately carry a sequence number equal to
        // a pending command's -- the NCP numbers them from its own counter.
        if frame.control.is_callback {
            return Classified::Callback {
                frame_id: frame.frame_id,
                parameters: frame.parameters,
            };
        }

        // A command echoed back is not an answer. An adapter or a loopback can
        // produce one, and accepting it resolves the caller's request with its
        // own arguments.
        if frame.control.direction != Direction::Response {
            self.stale_frames = self.stale_frames.saturating_add(1);
            return Classified::Stale {
                frame_id: frame.frame_id,
                sequence: frame.sequence,
            };
        }

        match self.pending {
            Some(pending)
                if pending.sequence == frame.sequence && pending.frame_id == frame.frame_id =>
            {
                self.pending = None;
                Classified::Response {
                    parameters: frame.parameters,
                }
            }
            _ => {
                self.stale_frames = self.stale_frames.saturating_add(1);
                Classified::Stale {
                    frame_id: frame.frame_id,
                    sequence: frame.sequence,
                }
            }
        }
    }

    /// Abandons the outstanding command because it timed out.
    ///
    /// # Errors
    ///
    /// [`EzspError::Timeout`] naming the command, so the caller reports which
    /// one rather than "a command".
    pub fn time_out(&mut self) -> Result<(), EzspError> {
        match self.pending.take() {
            Some(pending) => Err(EzspError::Timeout {
                frame_id: pending.frame_id,
            }),
            None => Ok(()),
        }
    }

    /// Abandons everything because the NCP reset.
    ///
    /// Distinct from a timeout: the sequence counter goes back to zero, because
    /// the NCP's did. Keeping the old counter would make the next command carry
    /// a number the NCP does not expect.
    ///
    /// # Errors
    ///
    /// [`EzspError::NcpReset`] when a command was in flight, so the caller
    /// learns it was lost rather than waiting out its timeout.
    pub fn on_ncp_reset(&mut self) -> Result<(), EzspError> {
        self.next_sequence = 0;
        match self.pending.take() {
            Some(pending) => Err(EzspError::NcpReset {
                frame_id: pending.frame_id,
            }),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ezsp::frame::{HeaderFormat, parse};

    /// A response frame, as the NCP would send one.
    fn response(sequence: u8, frame_id: FrameId, parameters: &[u8]) -> Vec<u8> {
        let mut bytes = vec![sequence, 0x80, 0x01];
        bytes.extend_from_slice(&frame_id.0.to_le_bytes());
        bytes.extend_from_slice(parameters);
        bytes
    }

    /// A callback frame: the response direction plus the async-callback bit.
    fn callback(sequence: u8, frame_id: FrameId, parameters: &[u8]) -> Vec<u8> {
        let mut bytes = vec![sequence, 0x90, 0x01];
        bytes.extend_from_slice(&frame_id.0.to_le_bytes());
        bytes.extend_from_slice(parameters);
        bytes
    }

    fn frame_of(bytes: &[u8]) -> Frame<'_> {
        parse(bytes, HeaderFormat::Extended).expect("parses")
    }

    #[test]
    fn a_callback_between_send_and_response_does_not_answer_the_command() {
        // The interleaving that motivates the whole module.
        let mut correlator = Correlator::new();
        let sequence = correlator.begin(FrameId::GET_EUI64).expect("begins");

        let x = callback(0x40, FrameId::INCOMING_MESSAGE_HANDLER, &[0x01]);
        assert!(matches!(
            correlator.classify(&frame_of(&x)),
            Classified::Callback {
                frame_id: FrameId::INCOMING_MESSAGE_HANDLER,
                ..
            }
        ));
        assert!(
            correlator.is_busy(),
            "a callback must not resolve the pending command"
        );

        let answer = response(sequence, FrameId::GET_EUI64, &[0xaa; 8]);
        assert!(matches!(
            correlator.classify(&frame_of(&answer)),
            Classified::Response { parameters } if parameters.len() == 8
        ));
        assert!(!correlator.is_busy());

        let y = callback(0x41, FrameId::MESSAGE_SENT_HANDLER, &[]);
        assert!(matches!(
            correlator.classify(&frame_of(&y)),
            Classified::Callback { .. }
        ));
    }

    #[test]
    fn a_callback_sharing_the_pending_sequence_is_still_a_callback() {
        // The NCP numbers callbacks from its own counter, so a collision is
        // routine rather than exotic. Matching on sequence alone would hand
        // the caller a callback's payload as its command's answer.
        let mut correlator = Correlator::new();
        let sequence = correlator.begin(FrameId::GET_EUI64).expect("begins");

        let colliding = callback(sequence, FrameId::INCOMING_MESSAGE_HANDLER, &[0xff]);
        assert!(
            matches!(
                correlator.classify(&frame_of(&colliding)),
                Classified::Callback { .. }
            ),
            "the callback flag outranks a matching sequence"
        );
        assert!(correlator.is_busy());
    }

    #[test]
    fn a_response_with_the_wrong_frame_id_is_not_accepted() {
        // Right sequence, wrong command. Accepting it decodes one command's
        // parameters as another's, which produces plausible nonsense.
        let mut correlator = Correlator::new();
        let sequence = correlator.begin(FrameId::GET_EUI64).expect("begins");

        let wrong = response(sequence, FrameId::VERSION, &[0x0d, 0x02, 0x44, 0x74]);
        assert!(matches!(
            correlator.classify(&frame_of(&wrong)),
            Classified::Stale { .. }
        ));
        assert!(correlator.is_busy(), "the command is still outstanding");

        let right = response(sequence, FrameId::GET_EUI64, &[0x11; 8]);
        assert!(matches!(
            correlator.classify(&frame_of(&right)),
            Classified::Response { .. }
        ));
    }

    #[test]
    fn a_response_with_the_wrong_sequence_is_not_accepted() {
        let mut correlator = Correlator::new();
        let sequence = correlator.begin(FrameId::GET_EUI64).expect("begins");

        let wrong = response(sequence.wrapping_add(7), FrameId::GET_EUI64, &[0x22; 8]);
        assert!(matches!(
            correlator.classify(&frame_of(&wrong)),
            Classified::Stale { .. }
        ));
        assert!(correlator.is_busy());
    }

    #[test]
    fn an_unexpected_sequence_then_the_right_one_resolves_correctly() {
        // The second scenario the design has to survive.
        let mut correlator = Correlator::new();
        let sequence = correlator.begin(FrameId::SET_POLICY).expect("begins");

        correlator.classify(&frame_of(&response(0xfe, FrameId::SET_POLICY, &[0x00])));
        correlator.classify(&frame_of(&callback(
            0x02,
            FrameId::STACK_STATUS_HANDLER,
            &[0x90],
        )));
        assert!(correlator.is_busy());

        let answer = response(sequence, FrameId::SET_POLICY, &[0x00]);
        assert!(matches!(
            correlator.classify(&frame_of(&answer)),
            Classified::Response { .. }
        ));
        assert_eq!(
            correlator.stale_frames(),
            1,
            "the misaddressed response is counted, so a rising count can be seen"
        );
    }

    #[test]
    fn our_own_command_echoed_back_is_not_its_own_answer() {
        // A loopback or an echoing adapter produces this. Accepting it
        // resolves the caller's request with its own arguments -- which is
        // exactly the shape of a bug found on real hardware in a sibling
        // project.
        let mut correlator = Correlator::new();
        let sequence = correlator.begin(FrameId::GET_EUI64).expect("begins");

        let mut echo = vec![sequence, 0x00, 0x01];
        echo.extend_from_slice(&FrameId::GET_EUI64.0.to_le_bytes());
        assert!(matches!(
            correlator.classify(&frame_of(&echo)),
            Classified::Stale { .. }
        ));
        assert!(correlator.is_busy());
    }

    #[test]
    fn a_duplicate_response_does_not_answer_the_next_command() {
        // The pending slot is cleared on the first answer, so a retransmitted
        // duplicate cannot resolve whatever is issued next.
        let mut correlator = Correlator::new();
        let first = correlator.begin(FrameId::GET_EUI64).expect("begins");
        let answer = response(first, FrameId::GET_EUI64, &[0x33; 8]);
        correlator.classify(&frame_of(&answer));

        let second = correlator.begin(FrameId::SET_POLICY).expect("begins");
        assert_ne!(first, second);
        assert!(
            matches!(
                correlator.classify(&frame_of(&answer)),
                Classified::Stale { .. }
            ),
            "a duplicate of the previous answer must not resolve the new command"
        );
        assert!(correlator.is_busy());
    }

    #[test]
    fn a_second_concurrent_command_is_refused() {
        let mut correlator = Correlator::new();
        correlator.begin(FrameId::GET_EUI64).expect("begins");
        assert!(matches!(
            correlator.begin(FrameId::SET_POLICY),
            Err(EzspError::SequenceMismatch { .. })
        ));
    }

    #[test]
    fn a_timeout_names_the_command_that_was_waiting() {
        let mut correlator = Correlator::new();
        correlator.begin(FrameId::NETWORK_INIT).expect("begins");
        match correlator.time_out() {
            Err(EzspError::Timeout { frame_id }) => {
                assert_eq!(frame_id, FrameId::NETWORK_INIT);
            }
            other => panic!("expected a named timeout, got {other:?}"),
        }
        assert!(!correlator.is_busy());
        assert!(
            correlator.time_out().is_ok(),
            "a timeout with nothing pending is not an error"
        );
    }

    #[test]
    fn a_reset_while_pending_reports_the_loss_and_rewinds_the_sequence() {
        // The NCP's own counter goes to zero, so ours must too -- otherwise
        // the next command carries a number the NCP does not expect and the
        // link appears to hang.
        let mut correlator = Correlator::new();
        correlator.begin(FrameId::GET_EUI64).expect("begins");
        correlator.begin(FrameId::GET_EUI64).ok();
        let _ = correlator.classify(&frame_of(&response(0, FrameId::GET_EUI64, &[0x44; 8])));
        correlator.begin(FrameId::SET_POLICY).expect("begins");

        match correlator.on_ncp_reset() {
            Err(EzspError::NcpReset { frame_id }) => assert_eq!(frame_id, FrameId::SET_POLICY),
            other => panic!("expected a reset error, got {other:?}"),
        }
        assert_eq!(
            correlator.peek_sequence(),
            0,
            "the sequence must restart with the NCP's"
        );
        assert!(!correlator.is_busy());
    }

    #[test]
    fn the_sequence_wraps_and_is_therefore_not_an_identifier_on_its_own() {
        // 256 commands and the numbers repeat. This is why the frame id is
        // part of the guard.
        let mut correlator = Correlator::new();
        for _ in 0..256 {
            let sequence = correlator.begin(FrameId::GET_EUI64).expect("begins");
            correlator.classify(&frame_of(&response(sequence, FrameId::GET_EUI64, &[0; 8])));
        }
        assert_eq!(
            correlator.peek_sequence(),
            0,
            "after 256 commands the counter is back where it started"
        );
    }
}
