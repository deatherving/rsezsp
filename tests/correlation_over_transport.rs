//! Correlation and callback delivery over a scripted transport.
//!
//! These exercise the whole stack below the typed API -- ASH framing, the
//! decoder, the correlator, the runtime loop -- with no hardware and no
//! timing. Every interleaving worth worrying about is expressible as "these
//! bytes arrive in this order", which is the reason the codecs are sans-I/O.

// The helpers below are free functions rather than bodies of `#[test]` fns, so
// clippy's in-tests allowance does not reach them. Asserting on
// `encode(..).expect(..)` is how these tests state that a frame they built is
// well-formed; a `Result` threaded through every helper would obscure that.
#![allow(clippy::expect_used)]
// The runtime is what is being tested here, so this file needs the feature
// that provides it. Without the gate, the sans-I/O build -- which CI runs to
// prove the codecs carry no runtime -- fails to compile its own test suite.
#![cfg(feature = "tokio-transport")]

use std::time::Duration;

use rsezsp::ash::{AshFrame, encode};
use rsezsp::ezsp::callback::Callback;
use rsezsp::ezsp::command::{GetEui64, Version};
use rsezsp::ezsp::{FrameId, ProtocolVersion};
use rsezsp::transport::fake::FakeTransport;
use rsezsp::{Eui64, Ncp};

/// An ASH data frame carrying an EZSP frame, with the given ASH numbering.
fn ash_data(frame_num: u8, ack_num: u8, ezsp: Vec<u8>) -> Vec<u8> {
    encode(&AshFrame::Data {
        frame_num,
        ack_num,
        retransmit: false,
        payload: ezsp,
    })
    .expect("encodes")
}

/// The NCP's `RSTACK`, which ends the reset handshake.
fn rstack() -> Vec<u8> {
    encode(&AshFrame::RstAck {
        version: 2,
        reset_code: 0x0b,
    })
    .expect("encodes")
}

/// A legacy-header `version` response: v13, mesh, stack 0x7440.
fn version_legacy(sequence: u8) -> Vec<u8> {
    vec![sequence, 0x80, 0x00, 0x0d, 0x02, 0x40, 0x74]
}

/// An extended-header `version` response.
fn version_extended(sequence: u8) -> Vec<u8> {
    vec![sequence, 0x80, 0x01, 0x00, 0x00, 0x0d, 0x02, 0x40, 0x74]
}

/// An extended-header `getEui64` response.
fn eui64_response(sequence: u8, address: Eui64) -> Vec<u8> {
    let mut bytes = vec![sequence, 0x80, 0x01, 0x26, 0x00];
    bytes.extend_from_slice(&address.to_wire());
    bytes
}

/// A `stackStatusHandler` callback. Note the 0x90 low control byte: the
/// response direction *plus* the asynchronous-callback bit.
fn stack_status(sequence: u8, status: u8) -> Vec<u8> {
    vec![sequence, 0x90, 0x01, 0x19, 0x00, status]
}

/// The bytes for a completed handshake and negotiation, which every test needs
/// before it can do anything interesting.
///
/// Two `version` exchanges, because that is what negotiation takes when the
/// NCP runs a different version from the one offered.
fn connected_prelude() -> Vec<Vec<u8>> {
    vec![
        rstack(),
        ash_data(0, 1, version_legacy(0)),
        ash_data(1, 2, version_extended(1)),
    ]
}

const DEVICE: Eui64 = Eui64::new(0xa4c1_3814_2d62_ffff);

#[tokio::test]
async fn a_command_response_is_correlated_over_the_full_stack() {
    let mut chunks = connected_prelude();
    chunks.push(ash_data(2, 3, eui64_response(2, DEVICE)));
    let transport = FakeTransport::with_chunks(chunks);

    let mut ncp = Ncp::connect(transport).await.expect("connects");
    assert_eq!(ncp.version(), ProtocolVersion::new(0x0d));

    let response = ncp.command(GetEui64).await.expect("getEui64");
    assert_eq!(response.eui64, DEVICE);
}

#[tokio::test]
async fn a_callback_before_the_response_does_not_answer_the_command() {
    // The interleaving the correlator exists for. The callback arrives first,
    // in its own ASH frame, while getEui64 is outstanding.
    let mut chunks = connected_prelude();
    chunks.push(ash_data(2, 3, stack_status(0x40, 0x90)));
    chunks.push(ash_data(3, 3, eui64_response(2, DEVICE)));
    let transport = FakeTransport::with_chunks(chunks);

    let mut ncp = Ncp::connect(transport).await.expect("connects");
    let response = ncp.command(GetEui64).await.expect("getEui64");
    assert_eq!(
        response.eui64, DEVICE,
        "the command must be answered by its own response, not by the callback"
    );

    let callbacks = ncp.take_callbacks();
    assert_eq!(callbacks.len(), 1, "and the callback must not be lost");
    assert!(matches!(
        callbacks.first(),
        Some(Callback::StackStatus { .. })
    ));
}

#[tokio::test]
async fn a_callback_after_the_response_is_still_delivered() {
    let mut chunks = connected_prelude();
    chunks.push(ash_data(2, 3, eui64_response(2, DEVICE)));
    chunks.push(ash_data(3, 3, stack_status(0x41, 0x9c)));
    let transport = FakeTransport::with_chunks(chunks);

    let mut ncp = Ncp::connect(transport).await.expect("connects");
    ncp.command(GetEui64).await.expect("getEui64");

    // Arrived after the command returned, so it is read by `poll` rather than
    // as a side effect of the command.
    let callbacks = ncp.poll(Duration::from_millis(200)).await.expect("polls");
    assert_eq!(
        callbacks,
        vec![Callback::StackStatus {
            status: rsezsp::SlStatus(0x9c)
        }]
    );
}

#[tokio::test]
async fn a_wrong_sequence_then_the_right_one_resolves_correctly() {
    // A response for a sequence nothing is waiting on, then a callback, then
    // the real answer. All three arrive while one command is outstanding.
    let mut chunks = connected_prelude();
    chunks.push(ash_data(2, 3, eui64_response(0xfe, Eui64::new(0xdead))));
    chunks.push(ash_data(3, 3, stack_status(0x42, 0x90)));
    chunks.push(ash_data(4, 3, eui64_response(2, DEVICE)));
    let transport = FakeTransport::with_chunks(chunks);

    let mut ncp = Ncp::connect(transport).await.expect("connects");
    let response = ncp.command(GetEui64).await.expect("getEui64");
    assert_eq!(
        response.eui64, DEVICE,
        "a misaddressed response must not resolve the command"
    );
}

#[tokio::test]
async fn a_response_for_the_wrong_command_does_not_resolve_this_one() {
    // Right sequence, wrong frame id. Accepting it would decode a `version`
    // response as an address -- four bytes read as eight, or worse, succeeding
    // with garbage.
    let mut chunks = connected_prelude();
    chunks.push(ash_data(2, 3, version_extended(2)));
    let transport = FakeTransport::with_chunks(chunks);

    let mut ncp = Ncp::connect(transport).await.expect("connects");
    let error = ncp
        .command(GetEui64)
        .await
        .expect_err("a version response must not answer getEui64");
    assert!(
        error.to_string().contains("timed out"),
        "the command should go unanswered rather than take the wrong frame: {error}"
    );
}

#[tokio::test]
async fn poll_returns_empty_at_the_deadline_rather_than_failing() {
    // Nothing happening is a normal outcome. An error here would make every
    // quiet interval look like a fault.
    let mut chunks = connected_prelude();
    chunks.push(ash_data(2, 3, eui64_response(2, DEVICE)));
    let transport = FakeTransport::with_chunks(chunks);

    let mut ncp = Ncp::connect(transport).await.expect("connects");
    ncp.command(GetEui64).await.expect("getEui64");

    let callbacks = ncp.poll(Duration::from_millis(50)).await.expect("polls");
    assert!(callbacks.is_empty());
}

#[tokio::test]
async fn an_unanswered_command_times_out_naming_itself() {
    let transport = FakeTransport::with_chunks(connected_prelude());
    let mut ncp = Ncp::connect(transport).await.expect("connects");

    let error = ncp.command(GetEui64).await.expect_err("nothing answers");
    let text = error.to_string();
    assert!(
        text.contains("getEui64"),
        "the error must name the command that was waiting, got {text}"
    );
}

#[tokio::test]
async fn negotiation_requires_the_second_exchange() {
    // Only the first `version` response is scripted, so the second exchange
    // goes unanswered. Connecting must fail rather than proceed with a version
    // the NCP has not agreed to -- which is exactly the state that produced
    // ERROR_VERSION_NOT_SET on real hardware.
    let transport = FakeTransport::with_chunks(vec![rstack(), ash_data(0, 1, version_legacy(0))]);
    assert!(
        Ncp::connect(transport).await.is_err(),
        "an incomplete negotiation must not be reported as connected"
    );
}

#[tokio::test]
async fn a_frame_split_across_reads_is_still_correlated() {
    // A read boundary and a frame boundary have nothing to do with each other.
    // Every byte of the prelude and the response arrives in its own chunk.
    let mut bytes = Vec::new();
    for chunk in connected_prelude() {
        bytes.extend(chunk);
    }
    bytes.extend(ash_data(2, 3, eui64_response(2, DEVICE)));

    let transport = FakeTransport::with_chunks(bytes.into_iter().map(|b| vec![b]));
    let mut ncp = Ncp::connect(transport).await.expect("connects");
    let response = ncp.command(GetEui64).await.expect("getEui64");
    assert_eq!(response.eui64, DEVICE);
}

#[tokio::test]
async fn a_command_is_refused_when_the_negotiated_version_lacks_it() {
    // `Version` claims availability at every version by definition; a command
    // that did not would be refused here rather than sent and ignored.
    let transport = FakeTransport::with_chunks(connected_prelude());
    let mut ncp = Ncp::connect(transport).await.expect("connects");
    // The control: version is always available, so this is a timeout rather
    // than an availability refusal.
    let error = ncp
        .command(Version {
            desired: ProtocolVersion::PREFERRED,
        })
        .await
        .expect_err("nothing answers");
    assert!(!error.to_string().contains("not available"), "{error}");
    assert_eq!(FrameId::VERSION.0, 0x0000);
}
