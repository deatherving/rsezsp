//! Protocol types, at both sides of the version boundary.
//!
//! Every type is decoded twice, once for a version with narrow fields and once
//! for a version with wide ones. A decoder that ignores the version passes the
//! first and reads past the end on the second.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rsezsp::ezsp::{EzspDecode, ProtocolVersion, Reader};
use rsezsp::types::aps::ApsFrame;
use rsezsp::types::network::{Eui64, NodeId};
use rsezsp::types::status::SlStatus;

fuzz_target!(|data: &[u8]| {
    for version in [ProtocolVersion::new(0x0d), ProtocolVersion::new(0x0e)] {
        let mut reader = Reader::new(data, version);
        let _ = SlStatus::decode(&mut reader);

        let mut reader = Reader::new(data, version);
        let _ = ApsFrame::decode(&mut reader);

        let mut reader = Reader::new(data, version);
        let _ = Eui64::decode(&mut reader);

        let mut reader = Reader::new(data, version);
        let _ = NodeId::decode(&mut reader);

        // The length-prefixed reader, which is the shape most likely to be
        // hostile: the length is data.
        let mut reader = Reader::new(data, version);
        let _ = reader.length_prefixed();
    }
});
