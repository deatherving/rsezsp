//! The runtime: one NCP conversation, driven over a transport.
//!
//! This is the only module that does I/O, and it contains no parsing. It owns
//! the ASH connection, the frame decoder, the correlator and the transport, and
//! its job is to move bytes between them in the right order. Everything it
//! decides is delegated: what a frame means is [`crate::ash`]'s answer, whether
//! a frame is a response is [`crate::ezsp::correlation`]'s.
//!
//! # One command at a time
//!
//! Deliberate. EZSP over ASH has a seven-frame window and the NCP answers in
//! order, so pipelining would buy little and cost the one property worth having
//! here: certainty about which frame answers which command. A caller that wants
//! concurrency can hold the [`Ncp`] behind a lock; a caller that wants
//! correctness gets it by default.
//!
//! # Callbacks are queued, not dropped
//!
//! A callback can arrive at any moment, including in the middle of waiting for
//! a response. They are collected and handed to the caller by
//! [`Ncp::take_callbacks`] rather than being discarded, because a join
//! notification that arrives while some unrelated command is in flight is still
//! a join.

use std::time::Duration;

use crate::ash::{self, AshFrame, Connection, Decoded, Decoder, Outbound};
use crate::ezsp::callback::Callback;
use crate::ezsp::codec::{EzspDecode, Writer};
use crate::ezsp::command::{Command, Version, VersionResponse};
use crate::ezsp::correlation::{Classified, Correlator};
use crate::ezsp::error::EzspError;
use crate::ezsp::frame::{self, FrameId, HeaderFormat};
use crate::ezsp::version::ProtocolVersion;
use crate::transport::{Transport, TransportError};

/// The stack type an `EmberZNet` mesh NCP reports.
///
/// Checked during negotiation: another stack type answers the same commands
/// with different meanings, so continuing would decode its replies as if they
/// were mesh ones.
const STACK_TYPE_MESH: u8 = 0x02;

/// How long to wait for a command's answer.
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);

/// How long to wait for the NCP to answer a reset.
///
/// Longer than a command: the NCP is rebooting its stack, and the first attempt
/// after plugging in a dongle is the slowest.
pub const RESET_TIMEOUT: Duration = Duration::from_secs(5);

/// A connected NCP.
#[derive(Debug)]
pub struct Ncp<T: Transport> {
    transport: T,
    ash: Connection,
    decoder: Decoder,
    correlator: Correlator,
    version: ProtocolVersion,
    /// The NCP firmware's own version number, as reported during negotiation.
    ///
    /// Kept because it identifies the firmware build, and firmware builds are
    /// what differ. Every hardware report this project acts on starts with
    /// which one was running; leaving it in a debug log means a caller has to
    /// reproduce the connection to answer that.
    stack_version: u16,
    callbacks: Vec<Callback>,
    /// The pending command's response parameters, once they arrive.
    ///
    /// Parked here rather than returned from the read loop because the loop
    /// also handles callbacks and acknowledgements, and threading one
    /// optional result out of it would make every other case carry a `None`.
    response: Option<Vec<u8>>,
    /// Whether the bootstrap `version` command has been sent.
    ///
    /// The legacy header may be used exactly once, for the first `version`.
    /// After that the NCP expects extended frames, and a legacy one makes it
    /// forget the negotiated version -- every extended command afterwards is
    /// answered `INVALID_COMMAND` with `ERROR_VERSION_NOT_SET`. Found on
    /// hardware: a second `version` sent in the legacy format broke `getEui64`
    /// and everything after it.
    initial_version_sent: bool,
    /// The format the pending command's response will arrive in, if one is
    /// pending.
    ///
    /// Needed because the answer to the bootstrap `version` command comes back
    /// in the legacy format, and by then the caller is already thinking in
    /// extended terms.
    ///
    /// `None` when nothing is outstanding, which is not the same as "extended"
    /// even though that is what it resolves to: keeping them distinct means a
    /// callback arriving while a *legacy* command is pending is not silently
    /// parsed with the legacy header. Only the bootstrap `version` is ever
    /// legacy, and callbacks cannot arrive before negotiation -- but encoding
    /// that as an invariant rather than a coincidence costs nothing.
    pending_format: Option<HeaderFormat>,
}

impl<T: Transport> Ncp<T> {
    /// Brings up a connection: ASH reset, then EZSP version negotiation.
    ///
    /// # Errors
    ///
    /// [`EzspError::Ash`] if the NCP never answers a reset, and
    /// [`EzspError::UnsupportedVersion`] if it negotiates a version this build
    /// does not know the wire format for -- which is refused rather than
    /// guessed, because a wrong field width produces plausible wrong values
    /// rather than an error.
    pub async fn connect(transport: T) -> Result<Self, EzspError> {
        let mut ncp = Self {
            transport,
            ash: Connection::new(),
            decoder: Decoder::new(),
            correlator: Correlator::new(),
            // Whatever we ask for; replaced by what the NCP answers. Until
            // then only the bootstrap `version` command is encodable, and it
            // has no version-dependent fields.
            version: ProtocolVersion::PREFERRED,
            stack_version: 0,
            callbacks: Vec::new(),
            initial_version_sent: false,
            response: None,
            pending_format: None,
        };

        ncp.reset().await?;

        let negotiated = ncp.negotiate().await?;
        ncp.version = negotiated.protocol_version;
        ncp.stack_version = negotiated.stack_version;
        tracing::info!(
            version = %ncp.version,
            stack_version = format_args!("{:#06x}", ncp.stack_version),
            "EZSP negotiated"
        );
        Ok(ncp)
    }

    /// Performs EZSP version negotiation, which takes **two** exchanges when
    /// the NCP does not speak the version the host asked for.
    ///
    /// The host offers a version; the NCP answers with the one it runs. If
    /// those differ, the host must send `version` **again, carrying the NCP's
    /// version**, and only then is negotiation complete. Until it is, the NCP
    /// answers every other command with `INVALID_COMMAND` and
    /// `ERROR_VERSION_NOT_SET`.
    ///
    /// Found on hardware. A single exchange looks like it worked -- the NCP
    /// replies with its version and nothing reports an error -- and then
    /// `getEui64`, the very next command, is rejected. The first exchange is
    /// an offer, not an agreement.
    ///
    /// # Errors
    ///
    /// [`EzspError::UnsupportedVersion`] when the NCP runs a version this
    /// build does not know the wire format for. Refused rather than attempted:
    /// a wrong field width yields plausible wrong values, not an error.
    async fn negotiate(&mut self) -> Result<VersionResponse, EzspError> {
        let offered = ProtocolVersion::PREFERRED;
        let first = self.command(Version { desired: offered }).await?;

        // The stack type is checked before anything else is trusted: a
        // non-mesh stack answers these commands with a different meaning.
        if first.stack_type != STACK_TYPE_MESH {
            return Err(EzspError::UnsupportedVersion {
                negotiated: first.protocol_version,
            });
        }
        if !first.protocol_version.is_supported() {
            return Err(EzspError::UnsupportedVersion {
                negotiated: first.protocol_version,
            });
        }

        if first.protocol_version == offered {
            tracing::debug!(version = %offered, "NCP runs the offered version");
            return Ok(first);
        }

        // The second exchange, which is what actually completes negotiation.
        // Sent extended, because the bootstrap legacy frame has been used.
        let agreed = first.protocol_version;
        let second = self.command(Version { desired: agreed }).await?;
        if second.protocol_version != agreed {
            // The NCP changed its mind. Nothing sensible follows from that.
            return Err(EzspError::UnsupportedVersion {
                negotiated: second.protocol_version,
            });
        }
        tracing::debug!(
            offered = %offered,
            agreed = %agreed,
            stack_version = format_args!("{:#06x}", second.stack_version),
            "NCP runs an older version; switched"
        );
        Ok(second)
    }

    /// The EZSP version in use. Every field width follows from it.
    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }

    /// The NCP firmware's own version number, from the negotiation exchange.
    ///
    /// Distinct from [`Self::version`], which is the *protocol* version. This
    /// one identifies the firmware build -- `0x7440` for `EmberZNet` 7.4.4 --
    /// and is the first thing a hardware report should quote, because firmware
    /// builds are what differ.
    pub const fn stack_version(&self) -> u16 {
        self.stack_version
    }

    /// Callbacks received so far, taken and cleared.
    pub fn take_callbacks(&mut self) -> Vec<Callback> {
        std::mem::take(&mut self.callbacks)
    }

    /// Performs the ASH reset handshake.
    ///
    /// # Errors
    ///
    /// [`ash::AshError::ResetFailed`] once the attempts are exhausted.
    pub async fn reset(&mut self) -> Result<(), EzspError> {
        for _ in 0..ash::state::MAX_RESET_ATTEMPTS {
            self.decoder.reset();
            let Outbound::Send(rst) = self.ash.begin_reset() else {
                break;
            };
            self.write_frame(&rst).await?;

            // The NCP cancels partial output as it resets, so junk before the
            // RSTACK is expected rather than a fault.
            match self
                .pump_until(RESET_TIMEOUT, |ncp| ncp.ash.is_connected())
                .await
            {
                Ok(()) if self.ash.is_connected() => {
                    self.correlator = Correlator::new();
                    // The NCP has forgotten the negotiated version, so the
                    // next `version` must go out legacy again.
                    self.initial_version_sent = false;
                    return Ok(());
                }
                Ok(()) | Err(_) => {
                    tracing::debug!("no RSTACK yet; retrying the reset");
                }
            }
        }
        Err(ash::AshError::ResetFailed.into())
    }

    /// Sends a command and waits for its answer.
    ///
    /// # Errors
    ///
    /// [`EzspError::UnsupportedCommand`] when the negotiated version does not
    /// have it, [`EzspError::Timeout`] naming the command, and
    /// [`EzspError::NcpReset`] if the NCP resets while it is in flight.
    pub async fn command<C: Command>(&mut self, command: C) -> Result<C::Response, EzspError> {
        if !C::is_available(self.version) {
            return Err(EzspError::UnsupportedCommand {
                frame_id: C::ID,
                version: self.version,
            });
        }

        // The header format belongs to the connection, not the command. Only
        // the first `version` may go out legacy; see `initial_version_sent`.
        let format = if C::ID == FrameId::VERSION && !self.initial_version_sent {
            HeaderFormat::Legacy
        } else {
            HeaderFormat::Extended
        };
        let sequence = self.correlator.begin(C::ID)?;
        self.pending_format = Some(format);

        let mut out = Writer::new(self.version);
        frame::write_header(&mut out, sequence, C::ID, format)?;
        command.encode(&mut out)?;
        let bytes = out.into_vec();
        if bytes.len() > frame::MAX_FRAME_LENGTH {
            return Err(EzspError::FrameTooLong {
                length: bytes.len(),
                limit: frame::MAX_FRAME_LENGTH,
            });
        }

        if C::ID.carries_key_material() {
            // The parameters are the secret. Logged by length so the exchange
            // is still visible in a trace without the key being in it.
            tracing::debug!(
                frame_id = %C::ID,
                format = ?format,
                len = bytes.len(),
                "sending EZSP frame (parameters redacted: carries key material)"
            );
        } else {
            tracing::debug!(
                frame_id = %C::ID,
                format = ?format,
                bytes = ?bytes,
                "sending EZSP frame"
            );
        }
        if matches!(format, HeaderFormat::Legacy) {
            self.initial_version_sent = true;
        }
        let data = self.ash.send_data(bytes)?;
        self.write_frame(&data).await?;

        // Pumped until the correlator says the answer arrived. Callbacks and
        // stale frames are absorbed on the way, which is the whole point.
        let mut response: Option<Vec<u8>> = None;
        let outcome = self
            .pump_until(COMMAND_TIMEOUT, |ncp| {
                response = ncp.take_response();
                response.is_some() || !ncp.ash.is_connected()
            })
            .await;

        if let Some(parameters) = response {
            let mut reader = crate::ezsp::codec::Reader::new(&parameters, self.version);
            let decoded = C::Response::decode(&mut reader)?;
            if !reader.is_empty() {
                // Almost always a field width wrong for this version.
                // Reported rather than ignored, because everything decoded
                // so far will have looked plausible.
                return Err(EzspError::TrailingBytes {
                    frame_id: C::ID,
                    extra: reader.remaining(),
                });
            }
            return Ok(decoded);
        }

        // No answer. Which failure it was matters: a reset means the command
        // was lost and the link must be re-established, where a timeout means
        // only that this command went unanswered.
        if !self.ash.is_connected() {
            self.correlator.on_ncp_reset()?;
        }
        outcome?;
        self.correlator.time_out()?;
        Err(EzspError::Timeout { frame_id: C::ID })
    }

    /// Reads for up to `timeout`, returning any callbacks that arrived.
    ///
    /// Returns as soon as the first callback arrives, or empty at the deadline.
    ///
    /// This exists because callbacks are the only way the NCP reports anything
    /// it was not asked about -- a device joining, a message being delivered, a
    /// frame arriving -- and without it they could only be collected as a side
    /// effect of sending some unrelated command. Waiting for a join by polling
    /// `getEui64` in a loop works and is obviously the wrong shape.
    ///
    /// # Errors
    ///
    /// [`EzspError::Transport`] if the transport fails. A deadline with nothing
    /// received is `Ok(vec![])`, not an error: nothing happening is a normal
    /// outcome and the caller decides whether it matters.
    pub async fn poll(&mut self, timeout: Duration) -> Result<Vec<Callback>, EzspError> {
        self.pump_until(timeout, |ncp| !ncp.callbacks.is_empty())
            .await?;
        Ok(self.take_callbacks())
    }

    /// The pending response's parameters, if it has arrived.
    fn take_response(&mut self) -> Option<Vec<u8>> {
        self.response.take()
    }

    /// Writes one ASH frame.
    async fn write_frame(&mut self, frame: &AshFrame) -> Result<(), EzspError> {
        let bytes = ash::encode(frame)?;
        self.transport
            .write(&bytes)
            .await
            .map_err(|e| map_transport(&e))
    }

    /// Reads and processes frames until `done` or the deadline.
    async fn pump_until(
        &mut self,
        timeout: Duration,
        mut done: impl FnMut(&mut Self) -> bool,
    ) -> Result<(), EzspError> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if done(self) {
                return Ok(());
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Ok(());
            }
            let read = tokio::time::timeout(remaining, self.transport.read()).await;
            match read {
                Ok(Ok(bytes)) => self.consume(&bytes).await?,
                Ok(Err(e)) => return Err(map_transport(&e)),
                // Not an error here: the caller decides what a deadline means,
                // because a reset that times out is retried and a command that
                // times out is reported.
                Err(_) => return Ok(()),
            }
        }
    }

    /// Feeds bytes through ASH and dispatches whatever comes out.
    async fn consume(&mut self, bytes: &[u8]) -> Result<(), EzspError> {
        for decoded in self.decoder.feed(bytes) {
            match decoded {
                Decoded::Frame(frame) => {
                    let (payload, outbound) = self.ash.on_frame(&frame);
                    if let Outbound::Send(reply) = outbound {
                        self.write_frame(&reply).await?;
                    }
                    if let Some(payload) = payload {
                        self.dispatch(&payload);
                    }
                }
                Decoded::Rejected(error) => {
                    tracing::debug!(%error, "rejected ASH frame");
                    let outbound = self.ash.on_decode_failure(&error);
                    if let Outbound::Send(reply) = outbound {
                        self.write_frame(&reply).await?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Classifies one EZSP frame and files it.
    fn dispatch(&mut self, payload: &[u8]) {
        // With nothing pending, anything arriving is a callback, and those
        // are extended once negotiation is done.
        let format = self.pending_format.unwrap_or(HeaderFormat::Extended);

        // Redaction is decided from the *pending command*, not from the parsed
        // frame: the frame has not been parsed yet, and a response that fails
        // to parse would otherwise be logged in full -- which is precisely the
        // case where the bytes get pasted into a bug report.
        if self
            .correlator
            .pending_frame_id()
            .is_some_and(FrameId::carries_key_material)
        {
            tracing::debug!(
                len = payload.len(),
                "received EZSP frame (redacted: answers a command carrying key material)"
            );
        } else {
            tracing::debug!(bytes = ?payload, "received EZSP frame");
        }
        let parsed = frame::parse(payload, format);
        let Ok(parsed) = parsed else {
            tracing::debug!("undecodable EZSP frame");
            return;
        };
        match self.correlator.classify(&parsed) {
            Classified::Response { parameters } => {
                self.response = Some(parameters.to_vec());
                // Nothing is outstanding now, so a frame arriving next is a
                // callback and must not be parsed as this command's format.
                self.pending_format = None;
            }
            Classified::Callback {
                frame_id,
                parameters,
            } => match Callback::decode(frame_id, parameters, self.version) {
                Ok(callback) => self.callbacks.push(callback),
                Err(error) => {
                    // A callback this build claims to understand but could not
                    // decode. Logged rather than fatal: the connection is fine
                    // and the next frame may be the one that matters.
                    tracing::warn!(%frame_id, %error, "undecodable callback");
                }
            },
            Classified::Stale { frame_id, sequence } => {
                tracing::debug!(%frame_id, sequence, "stale EZSP frame");
            }
        }
    }
}

/// Maps a transport failure into the EZSP error type.
fn map_transport(error: &TransportError) -> EzspError {
    EzspError::Transport {
        reason: error.to_string(),
    }
}
