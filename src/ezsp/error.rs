//! What can go wrong, named precisely.
//!
//! Every variant here answers a different question for whoever is debugging.
//! "The frame was bad" is not actionable; "a length byte claimed 64 bytes and
//! the frame had 2" tells you whether to look at the device, the cable, or the
//! codec.
//!
//! Deliberately no `Other(String)` variant. One would absorb every case nobody
//! wanted to think about, and the cases nobody wanted to think about are the
//! ones that turn up on unfamiliar hardware.

use crate::ezsp::frame::FrameId;
use crate::ezsp::version::ProtocolVersion;
use crate::types::status::SlStatus;

/// A failure in the EZSP layer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EzspError {
    /// A frame ended before a field it promised.
    #[error("frame ended early: needed {needed} more bytes, {available} available")]
    TruncatedFrame {
        /// How many bytes the decoder asked for.
        needed: usize,
        /// How many were left.
        available: usize,
    },

    /// A frame was longer than EZSP permits.
    #[error("frame is {length} bytes; EZSP permits at most {limit}")]
    FrameTooLong {
        /// The length seen.
        length: usize,
        /// The protocol limit.
        limit: usize,
    },

    /// A payload could not be described by its length prefix.
    #[error("payload is {length} bytes; a length prefix holds at most {limit}")]
    PayloadTooLong {
        /// The payload length.
        length: usize,
        /// The largest describable length.
        limit: usize,
    },

    /// A frame's header did not parse.
    #[error("malformed frame header: {reason}")]
    MalformedHeader {
        /// What specifically was wrong.
        reason: &'static str,
    },

    /// Bytes were left over after decoding.
    ///
    /// Worth an error rather than a shrug: it usually means a field width was
    /// wrong for this protocol version, which is the failure mode this crate
    /// was built to catch. Everything decoded so far will have looked
    /// plausible.
    #[error("{extra} bytes left after decoding the response to {frame_id}")]
    TrailingBytes {
        /// The command whose response it was.
        frame_id: FrameId,
        /// How many bytes were not consumed.
        extra: usize,
    },

    /// The NCP negotiated a version this crate cannot speak.
    #[error("the NCP speaks EZSP {negotiated}, which this build does not support")]
    UnsupportedVersion {
        /// What the NCP answered with.
        negotiated: ProtocolVersion,
    },

    /// A command was used that the negotiated version does not have.
    #[error("{frame_id} is not available in EZSP {version}")]
    UnsupportedCommand {
        /// The command.
        frame_id: FrameId,
        /// The version in use.
        version: ProtocolVersion,
    },

    /// A response arrived whose frame id is not the one that was asked for.
    ///
    /// Distinct from a sequence mismatch: this is the right conversation with
    /// the wrong content.
    #[error("expected a response to {expected}, got {actual}")]
    UnexpectedResponse {
        /// The pending command.
        expected: FrameId,
        /// What arrived.
        actual: FrameId,
    },

    /// A response arrived carrying a sequence number nothing is waiting on.
    #[error("no command is waiting on sequence {sequence}")]
    SequenceMismatch {
        /// The sequence that arrived.
        sequence: u8,
    },

    /// An enum field held a value this build does not know.
    ///
    /// Carries the value so an unfamiliar firmware can be reported rather than
    /// guessed at.
    #[error("{name} has no variant for {value:#04x}")]
    UnknownEnum {
        /// Which enum.
        name: &'static str,
        /// The value seen.
        value: u32,
    },

    /// The NCP answered with a failure status.
    ///
    /// Not an error in this crate: the exchange worked and the NCP said no.
    #[error("the NCP returned {status}")]
    Status {
        /// What it returned.
        status: SlStatus,
    },

    /// No response arrived in time.
    #[error("{frame_id} timed out")]
    Timeout {
        /// The command that was waiting.
        frame_id: FrameId,
    },

    /// The NCP reset while a command was in flight.
    ///
    /// Separate from a timeout because the recovery differs: a reset means
    /// every pending command is lost and the connection must be re-established
    /// from the handshake, not merely retried.
    #[error("the NCP reset while {frame_id} was pending")]
    NcpReset {
        /// The command that was lost.
        frame_id: FrameId,
    },

    /// The connection is not up.
    #[error("not connected to an NCP")]
    NotConnected,

    /// The transport failed.
    #[error("transport failure: {reason}")]
    Transport {
        /// What the transport reported.
        reason: String,
    },

    /// A failure in the ASH layer underneath.
    #[error("ASH: {0}")]
    Ash(#[from] crate::ash::AshError),
}

impl EzspError {
    /// Whether retrying the same command could plausibly succeed.
    ///
    /// A malformed frame is not transient -- the same bytes will fail the same
    /// way -- but a timeout or a dropped ASH frame is.
    pub const fn is_transient(&self) -> bool {
        matches!(
            self,
            Self::Timeout { .. } | Self::NcpReset { .. } | Self::Transport { .. } | Self::Ash(_)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_say_enough_to_act_on() {
        // The whole reason these are structured. A person reading a log needs
        // to know whether to suspect the device, the cable, or this crate.
        let truncated = EzspError::TruncatedFrame {
            needed: 4,
            available: 1,
        };
        let text = truncated.to_string();
        assert!(text.contains('4') && text.contains('1'), "{text}");

        let trailing = EzspError::TrailingBytes {
            frame_id: FrameId::VERSION,
            extra: 3,
        };
        assert!(
            trailing.to_string().contains('3'),
            "trailing bytes usually mean a wrong field width for this version, \
             so the count matters"
        );
    }

    #[test]
    fn only_the_recoverable_failures_are_transient() {
        assert!(
            EzspError::Timeout {
                frame_id: FrameId::VERSION
            }
            .is_transient()
        );
        assert!(
            EzspError::NcpReset {
                frame_id: FrameId::VERSION
            }
            .is_transient()
        );
        // A malformed frame will fail identically on retry, so calling it
        // transient would turn one bad frame into an infinite loop.
        assert!(
            !EzspError::TruncatedFrame {
                needed: 1,
                available: 0
            }
            .is_transient()
        );
        // And an NCP that said no is not a failure to retry either.
        assert!(
            !EzspError::Status {
                status: SlStatus::FAIL
            }
            .is_transient()
        );
    }
}
