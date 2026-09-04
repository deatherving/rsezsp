//! Regression tests built from captured hardware behaviour.
//!
//! Every test here exists because a real dongle behaved in a way the code did
//! not expect. The rule for this file: when hardware exposes a protocol bug,
//! save a minimised capture, add the test, fix the implementation, verify on
//! hardware, and keep the capture permanently. A fixed bug with no test is a
//! bug waiting for the next refactor.
//!
//! Hardware: Sonoff ZBDongle-E (EFR32MG21), `EmberZNet` 7.4.4, EZSP 13,
//! stack version 0x7440.

use rsezsp::Eui64;
use rsezsp::ash::{AshFrame, Decoded, Decoder, encode};
use rsezsp::ezsp::callback::Callback;
use rsezsp::ezsp::codec::{EzspDecode, Reader};
use rsezsp::ezsp::command::{GetEui64Response, NetworkInitResponse, VersionResponse};
use rsezsp::ezsp::frame::{HeaderFormat, parse};
use rsezsp::ezsp::{Direction, FrameId, ProtocolVersion};
use rsezsp::types::network::NodeId;
use rsezsp::types::status::SlStatus;

const V13: ProtocolVersion = ProtocolVersion::new(0x0d);

/// The coordinator this was captured from.
const COORDINATOR: Eui64 = Eui64::new(0x94a0_81ff_fed9_6e5c);

#[test]
fn the_bootstrap_version_exchange_decodes_as_captured() {
    // Sent:     [0, 0, 0, 19]                    legacy header, desired 0x13
    // Received: [0, 128, 0, 13, 2, 64, 116]      legacy header, v13 mesh
    let received = [0x00, 0x80, 0x00, 0x0d, 0x02, 0x40, 0x74];
    let frame = parse(&received, HeaderFormat::Legacy).expect("parses");

    assert_eq!(frame.sequence, 0);
    assert_eq!(frame.control.direction, Direction::Response);
    assert!(!frame.control.is_callback);
    assert_eq!(frame.frame_id, FrameId::VERSION);

    let mut reader = Reader::new(frame.parameters, V13);
    let response = VersionResponse::decode(&mut reader).expect("decodes");
    assert_eq!(response.protocol_version, V13);
    assert_eq!(response.stack_type, 2, "2 is EmberZNet mesh");
    assert_eq!(response.stack_version, 0x7440);
}

#[test]
fn version_negotiation_takes_two_exchanges_when_the_ncp_runs_an_older_version() {
    // The finding that cost the most to diagnose. The host offered 0x13 and
    // the NCP answered 0x0d. A single exchange *looks* successful -- the NCP
    // replies with its version and nothing errors -- but negotiation is not
    // complete, and the very next command comes back as:
    //
    //   [2, 128, 1, 88, 0, 48]
    //    seq  resp  fmt  id=0x0058       status 0x30
    //                    INVALID_COMMAND ERROR_VERSION_NOT_SET
    //
    // The second exchange, carrying the NCP's own version, is what completes
    // it. This test pins the shape of the rejection so the symptom is
    // recognisable if it ever returns.
    let rejection = [0x02, 0x80, 0x01, 0x58, 0x00, 0x30];
    let frame = parse(&rejection, HeaderFormat::Extended).expect("parses");

    assert_eq!(
        frame.frame_id,
        FrameId(0x0058),
        "0x0058 is INVALID_COMMAND, the NCP's way of saying it did not accept the frame"
    );
    assert!(
        !frame.control.is_callback,
        "it is a response to our command, not an unsolicited event"
    );
    assert_eq!(
        frame.parameters,
        [0x30],
        "0x30 is ERROR_VERSION_NOT_SET: negotiation was never completed"
    );
}

#[test]
fn the_second_version_exchange_uses_the_extended_header() {
    // Captured: [1, 0, 1, 0, 0, 13] going out, [1, 128, 1, 0, 0, 13, 2, 64, 116]
    // coming back. The legacy header may be used exactly once, for the
    // bootstrap; the follow-up that completes negotiation is extended.
    let received = [0x01, 0x80, 0x01, 0x00, 0x00, 0x0d, 0x02, 0x40, 0x74];
    let frame = parse(&received, HeaderFormat::Extended).expect("parses");
    assert_eq!(frame.frame_id, FrameId::VERSION);

    let mut reader = Reader::new(frame.parameters, V13);
    let response = VersionResponse::decode(&mut reader).expect("decodes");
    assert_eq!(response.protocol_version, V13);
}

#[test]
fn get_eui64_decodes_the_coordinator_address_from_the_capture() {
    // [2, 128, 1, 38, 0, 92, 110, 217, 254, 255, 129, 160, 148]
    // The address is little-endian on the wire and reads back as
    // 0x94a081fffed96e5c -- the same value an independent implementation
    // reports for this dongle, which is what makes it a check rather than a
    // restatement.
    let received = [
        0x02, 0x80, 0x01, 0x26, 0x00, 0x5c, 0x6e, 0xd9, 0xfe, 0xff, 0x81, 0xa0, 0x94,
    ];
    let frame = parse(&received, HeaderFormat::Extended).expect("parses");
    assert_eq!(frame.frame_id, FrameId::GET_EUI64);

    let mut reader = Reader::new(frame.parameters, V13);
    let response = GetEui64Response::decode(&mut reader).expect("decodes");
    assert_eq!(response.eui64, COORDINATOR);
    assert!(
        reader.is_empty(),
        "an EUI64 is exactly eight bytes; anything left over means a wrong width"
    );
}

#[test]
fn network_init_reports_not_joined_when_the_stack_profile_is_unset() {
    // The second hardware finding. `networkInit` returned 0x93
    // (EMBER_NOT_JOINED) on a dongle that demonstrably *had* a stored
    // network: an independent implementation resumed the same dongle seconds
    // later. The difference was ordering -- it had set STACK_PROFILE first,
    // and this NCP defaults that to 0, so the stack will not adopt a stored
    // ZigBee Pro network.
    //
    // Kept as a test because the failure is indistinguishable from "there is
    // no network" unless you know to look.
    let received = [0x03, 0x80, 0x01, 0x17, 0x00, 0x93];
    let frame = parse(&received, HeaderFormat::Extended).expect("parses");
    assert_eq!(frame.frame_id, FrameId::NETWORK_INIT);

    let mut reader = Reader::new(frame.parameters, V13);
    let response = NetworkInitResponse::decode(&mut reader).expect("decodes");
    assert_eq!(
        response.status,
        SlStatus(0x93),
        "one byte on EZSP 13: a four-byte read here would consume the frame \
         and report success"
    );
    assert!(!response.status.is_ok());
}

#[test]
fn network_init_reports_success_once_the_stack_profile_is_set() {
    // The same command after `setConfigurationValue(STACK_PROFILE, 2)`.
    let received = [0x04, 0x80, 0x01, 0x17, 0x00, 0x00];
    let frame = parse(&received, HeaderFormat::Extended).expect("parses");
    let mut reader = Reader::new(frame.parameters, V13);
    let response = NetworkInitResponse::decode(&mut reader).expect("decodes");
    assert!(response.status.is_ok());
}

#[test]
fn the_stack_status_callback_from_a_resumed_network_decodes_as_a_callback() {
    // Captured during startup: the stack coming up emits this unsolicited,
    // while a command may well be in flight. Status 144 is 0x90, network-up.
    //
    // The assertion that matters is the callback bit: without it this frame
    // would be offered to the correlator as a response and could resolve
    // whatever command was pending with a stack status.
    let received = [0x05, 0x90, 0x01, 0x19, 0x00, 0x90];
    let frame = parse(&received, HeaderFormat::Extended).expect("parses");

    assert!(
        frame.control.is_callback,
        "0x10 in the low control byte is what keeps this out of the response path"
    );
    assert_eq!(frame.frame_id, FrameId::STACK_STATUS_HANDLER);

    let callback = Callback::decode(frame.frame_id, frame.parameters, V13).expect("decodes");
    assert_eq!(
        callback,
        Callback::StackStatus {
            status: SlStatus(0x90)
        }
    );
}

#[test]
fn a_full_ash_round_trip_carries_a_captured_ezsp_frame() {
    // End to end through the layer that actually touches the wire: the EZSP
    // frame for the bootstrap `version`, wrapped in ASH, unwrapped again.
    // Covers randomisation, CRC and stuffing together, which is where a
    // subtly wrong constant hides -- each step is individually plausible.
    let ezsp = vec![0x00, 0x00, 0x00, 0x13];
    let frame = AshFrame::Data {
        frame_num: 0,
        ack_num: 0,
        retransmit: false,
        payload: ezsp.clone(),
    };
    let wire = encode(&frame).expect("encodes");

    let mut decoder = Decoder::new();
    let frames = decoder.feed(&wire);
    assert_eq!(frames.len(), 1);
    match frames.first() {
        Some(Decoded::Frame(AshFrame::Data { payload, .. })) => {
            assert_eq!(*payload, ezsp, "the payload must survive randomisation");
        }
        other => panic!("expected a data frame, got {other:?}"),
    }
}

#[test]
fn the_rstack_that_ends_the_reset_handshake_decodes() {
    // What the NCP sends after a RST. A short or corrupted one must not be
    // read as a successful reset, which is checked in the frame module; here
    // the well-formed case is pinned.
    let frame = AshFrame::RstAck {
        version: 2,
        reset_code: 0x0b,
    };
    let wire = encode(&frame).expect("encodes");
    let mut decoder = Decoder::new();
    assert_eq!(decoder.feed(&wire), vec![Decoded::Frame(frame)]);
}

#[test]
fn an_incoming_message_from_the_valve_keeps_its_payload_separate_from_the_radio_metadata() {
    // The valve reporting on the Sonoff manufacturer cluster, captured while
    // the coordinator was idle.
    //
    // The bug: the decoder took everything after the APS header as the
    // application payload. Seven bytes of radio metadata sit between them --
    // LQI, RSSI, the sender, two table indices and a length prefix -- and all
    // seven were being handed to the caller as the start of the ZCL message.
    // Nothing failed: the frame parsed, the payload was non-empty, and the
    // first byte was a plausible ZCL frame control value.
    let parameters = [
        0x00, // unicast
        0x04, 0x01, 0x11, 0xfc, 0x01, 0x01, 0x40, 0x01, 0x00, 0x00, 0x28, // APS
        0xff, 0xe2, // LQI 255, RSSI -30 dBm
        0x41, 0x3a, // sender 0x3a41
        0xff, 0xff, // no binding, no address table entry
        0x1e, // 30 bytes of payload follow
        0x18, 0xd6, 0x0a, 0x1f, 0x50, 0x48, 0x20, 0x15, 0x00, 0x02, 0x00, 0x01, 0x00, 0x32, 0x2d,
        0xc3, 0xf1, 0x32, 0x2d, 0xc6, 0x49, 0x32, 0x2d, 0xc4, 0x0b, 0x01, 0x00, 0x00, 0x00, 0x00,
    ];

    let callback = Callback::decode(FrameId::INCOMING_MESSAGE_HANDLER, &parameters, V13)
        .expect("the capture must decode");
    let Callback::IncomingMessage {
        sender,
        last_hop_rssi,
        payload,
        ..
    } = callback
    else {
        panic!("expected an incoming message, got {callback:?}");
    };

    assert_eq!(sender, NodeId(0x3a41), "the valve");
    assert_eq!(last_hop_rssi, -30, "signed; as u8 this reads 226");
    assert_eq!(payload.len(), 30, "exactly what the length prefix promised");
    assert_eq!(
        payload.first().copied(),
        Some(0x18),
        "a ZCL frame control byte, not the LQI that used to be here"
    );
}

#[test]
fn the_message_sent_report_for_a_delivered_unicast_decodes_as_captured() {
    // The confirmation for a genOnOff command that physically actuated the
    // valve. Every field is cross-checkable against the send that produced it,
    // which is what makes this capture worth keeping: destination 0x3a41, the
    // APS sequence the send command returned, and the tag the host supplied.
    //
    // The bug: the decoder started at the message tag, eleven bytes early. It
    // read the message type as the tag and the low byte of the destination
    // address as the status -- and 0x3a41 has a low byte of 0x41, so a
    // successful delivery was reported as failure status 0x41.
    let parameters = [
        0x00, // direct unicast
        0x41, 0x3a, // destination 0x3a41
        0x04, 0x01, 0x06, 0x00, 0x01, 0x01, 0x40, 0x01, 0x00, 0x00, 0x9b, // APS, sequence 155
        0x01, // the tag the host supplied
        0x00, // delivered
        0x00, // no payload echoed back
    ];

    let callback = Callback::decode(FrameId::MESSAGE_SENT_HANDLER, &parameters, V13)
        .expect("the capture must decode");
    let Callback::MessageSent {
        index_or_destination,
        aps_frame,
        message_tag,
        status,
        ..
    } = callback
    else {
        panic!("expected a message-sent report, got {callback:?}");
    };

    assert_eq!(index_or_destination, 0x3a41);
    assert_eq!(aps_frame.sequence, 155, "as returned by sendUnicast");
    assert_eq!(message_tag, 1, "read as 0 when the offsets were wrong");
    assert!(status.is_ok(), "read as 0x41 when the offsets were wrong");
}
