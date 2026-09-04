//! Proof that a command this crate does not implement can be added from
//! outside it.
//!
//! Command coverage here grows from real need rather than from working through
//! the specification, which is only a reasonable design if it does not block
//! anyone. A user who needs a command nobody has needed yet must be able to
//! write it in their own crate, today, without forking this one and without
//! waiting for a release.
//!
//! This test lives in `tests/` on purpose: an integration test is a separate
//! crate, so it can only reach what a real dependent can reach. If the public
//! API were missing a piece -- a sealed trait, a private codec, an
//! unconstructible frame id -- this file would fail to compile.
//!
//! It is also worked example. `getChildData` below is a real unimplemented
//! command, written the way the contributing guide asks for.

#![cfg(feature = "tokio-transport")]
#![allow(clippy::expect_used)]

use rsezsp::ezsp::codec::{EzspDecode, EzspEncode, Reader, Writer};
use rsezsp::ezsp::{Command, EzspError, FrameId, ProtocolVersion};
use rsezsp::transport::fake::FakeTransport;
use rsezsp::types::network::{Eui64, NodeId};
use rsezsp::types::status::SlStatus;
use rsezsp::{Ncp, ash};

/// `getChildData` — read one entry from the NCP's child table. Frame id
/// `0x004a`.
///
/// Not implemented by `rsezsp` at the time of writing, which is the point:
/// everything below is written from outside the crate, using only its public
/// API.
struct GetChildData {
    /// Which entry. Callers walk upward until the NCP reports no more.
    index: u8,
}

/// What the NCP answers with.
#[derive(Debug)]
struct GetChildDataResponse {
    status: SlStatus,
    eui64: Eui64,
    node_id: NodeId,
    device_type: u8,
}

impl EzspEncode for GetChildData {
    fn encode(&self, out: &mut Writer) -> Result<(), EzspError> {
        out.u8(self.index);
        Ok(())
    }
}

impl EzspDecode for GetChildDataResponse {
    fn decode(input: &mut Reader<'_>) -> Result<Self, EzspError> {
        // `SlStatus::decode` applies the version boundary itself, so a command
        // written outside the crate gets the one-byte/four-byte split right
        // without having to know the rule.
        let status = SlStatus::decode(input)?;
        Ok(Self {
            status,
            eui64: Eui64::decode(input)?,
            node_id: NodeId::decode(input)?,
            device_type: input.u8()?,
        })
    }
}

impl Command for GetChildData {
    type Response = GetChildDataResponse;
    const ID: FrameId = FrameId(0x004a);
}

/// An ASH data frame carrying an EZSP frame.
fn ash_data(frame_num: u8, ack_num: u8, ezsp: Vec<u8>) -> Vec<u8> {
    ash::encode(&ash::AshFrame::Data {
        frame_num,
        ack_num,
        retransmit: false,
        payload: ezsp,
    })
    .expect("the frame is well under the ASH size limit")
}

/// An extended-header response frame carrying `parameters`.
fn ncp_response(sequence: u8, frame_id: FrameId, parameters: &[u8]) -> Vec<u8> {
    let [id_lo, id_hi] = frame_id.0.to_le_bytes();
    let mut ezsp = vec![
        sequence, 0x80, // a response
        0x01, // extended format
        id_lo, id_hi,
    ];
    ezsp.extend_from_slice(parameters);
    ezsp
}

/// A completed reset handshake and version negotiation.
///
/// Two `version` exchanges, because the host offers the newest version it
/// knows and this NCP runs 13. The first exchange is an offer, not an
/// agreement -- getting that wrong is one of the bugs recorded in
/// `tests/hardware_regression.rs`.
fn connected_prelude() -> Vec<Vec<u8>> {
    vec![
        ash::encode(&ash::AshFrame::RstAck {
            version: 2,
            reset_code: 0x0b,
        })
        .expect("encodes"),
        ash_data(0, 1, vec![0x00, 0x80, 0x00, 0x0d, 0x02, 0x40, 0x74]),
        ash_data(
            1,
            2,
            vec![0x01, 0x80, 0x01, 0x00, 0x00, 0x0d, 0x02, 0x40, 0x74],
        ),
    ]
}

#[tokio::test]
async fn a_command_defined_outside_this_crate_round_trips_through_the_runtime() {
    let mut chunks = connected_prelude();
    // v13 means a one-byte status, and the sequence continues from
    // negotiation.
    chunks.push(ash_data(
        2,
        3,
        ncp_response(
            2,
            GetChildData::ID,
            &[
                0x00, // status: success
                0xff, 0xff, 0x62, 0x2d, 0x14, 0x38, 0xc1, 0xa4, // eui64, little endian
                0x41, 0x3a, // node id 0x3a41
                0x02, // sleepy end device
            ],
        ),
    ));

    let mut ncp = Ncp::connect(FakeTransport::with_chunks(chunks))
        .await
        .expect("connects");
    assert_eq!(ncp.version(), ProtocolVersion::new(0x0d));
    assert_eq!(ncp.stack_version(), 0x7440);

    let response = ncp
        .command(GetChildData { index: 0 })
        .await
        .expect("a command defined outside the crate must be sendable");

    assert!(response.status.is_ok());
    assert_eq!(response.eui64, Eui64::new(0xa4c1_3814_2d62_ffff));
    assert_eq!(response.node_id, NodeId(0x3a41));
    assert_eq!(response.device_type, 0x02);
}

#[tokio::test]
async fn an_externally_defined_command_can_restrict_itself_to_a_version_range() {
    // The mechanism that stops a command being sent to firmware that has no
    // such command -- a typed error rather than a frame the NCP ignores.
    struct OnlyOnNewFirmware;

    impl EzspEncode for OnlyOnNewFirmware {
        fn encode(&self, _out: &mut Writer) -> Result<(), EzspError> {
            Ok(())
        }
    }

    impl Command for OnlyOnNewFirmware {
        type Response = ();
        const ID: FrameId = FrameId(0x0123);

        fn is_available(version: ProtocolVersion) -> bool {
            version.has_wide_status()
        }
    }

    let mut ncp = Ncp::connect(FakeTransport::with_chunks(connected_prelude()))
        .await
        .expect("connects");
    let error = ncp
        .command(OnlyOnNewFirmware)
        .await
        .expect_err("v13 does not have this command");
    assert!(
        matches!(error, EzspError::UnsupportedCommand { .. }),
        "expected an unsupported-command error, got {error:?}"
    );
}
