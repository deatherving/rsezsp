//! ASH-layer failures.

/// What can go wrong framing or unframing ASH.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AshError {
    /// The frame's CRC did not match its contents.
    ///
    /// Almost always line noise or a baud-rate mismatch rather than a protocol
    /// error, which is why it is distinguished from a malformed frame: the
    /// recovery is to NAK and let the NCP resend, not to give up.
    #[error("ASH CRC mismatch: computed {computed:#06x}, frame carried {carried:#06x}")]
    BadCrc {
        /// What the receiver computed.
        computed: u16,
        /// What the frame claimed.
        carried: u16,
    },

    /// The frame was shorter than its type permits.
    #[error("ASH frame is {length} bytes, shorter than the minimum {minimum}")]
    TooShort {
        /// The length seen.
        length: usize,
        /// The minimum for this frame type.
        minimum: usize,
    },

    /// The frame was longer than ASH permits.
    #[error("ASH frame is {length} bytes, longer than the maximum {maximum}")]
    TooLong {
        /// The length seen.
        length: usize,
        /// The protocol maximum.
        maximum: usize,
    },

    /// The control byte matched no frame type, or matched one whose fixed
    /// length disagrees with the frame.
    #[error("ASH control byte {control:#04x} is not a valid frame of {length} bytes")]
    InvalidControl {
        /// The control byte.
        control: u8,
        /// The frame length it arrived with.
        length: usize,
    },

    /// The NCP sent `CANCEL`, abandoning the frame in progress.
    ///
    /// Normal during startup: the NCP cancels partial output when it resets.
    #[error("the NCP cancelled the frame in progress")]
    Cancelled,

    /// The NCP sent `SUBSTITUTE`, marking the frame as corrupt in transit.
    #[error("the NCP reported a corrupted frame")]
    Substituted,

    /// The NCP reported an error condition and needs a reset.
    #[error("the NCP reported error code {code:#04x} (ASH version {version})")]
    NcpError {
        /// ASH protocol version the NCP reported.
        version: u8,
        /// The error code.
        code: u8,
    },

    /// The NCP reset. Every pending command is lost.
    #[error("the NCP reset with code {code:#04x} (ASH version {version})")]
    NcpReset {
        /// ASH protocol version the NCP reported.
        version: u8,
        /// The reset code.
        code: u8,
    },

    /// The reset handshake did not complete.
    #[error("the NCP did not answer a reset within the allowed attempts")]
    ResetFailed,

    /// A data frame arrived with a frame number that is not the next expected.
    ///
    /// Reported rather than silently accepted: out-of-order delivery means a
    /// frame was lost, and the NCP must be `NAKed` so it resends.
    #[error("ASH frame number {received} arrived while expecting {expected}")]
    OutOfSequence {
        /// The number that arrived.
        received: u8,
        /// The number expected.
        expected: u8,
    },

    /// The host is not connected to an NCP.
    #[error("ASH is not connected")]
    NotConnected,

    /// No frame arrived within the timeout.
    #[error("ASH timed out waiting for the NCP")]
    Timeout,

    /// The send window is full; wait for an acknowledgement.
    ///
    /// The window is bounded at seven, one short of the sequence space,
    /// because with all eight outstanding an acknowledgement is ambiguous: a
    /// three-bit `ack_num` of 0 would mean both "none acknowledged" and "all
    /// eight acknowledged", and there is no way to tell which.
    #[error("the ASH send window is full ({outstanding} of {limit} frames unacknowledged)")]
    WindowFull {
        /// How many frames are awaiting acknowledgement.
        outstanding: usize,
        /// The window size.
        limit: usize,
    },
}

impl AshError {
    /// Whether the right response is to ask the NCP to resend.
    ///
    /// A bad CRC or a corrupted frame is recoverable by NAK. A protocol
    /// violation is not, and `NAKing` one would loop.
    pub const fn is_recoverable_by_nak(&self) -> bool {
        matches!(self, Self::BadCrc { .. } | Self::Substituted)
    }
}
