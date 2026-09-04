//! Callback decoding, across frame ids and versions.
//!
//! A callback's payload is entirely device-controlled and arrives unsolicited,
//! so it is the least constrained input in the crate: nothing asked for it and
//! nothing knows what it should look like.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rsezsp::ezsp::callback::Callback;
use rsezsp::ezsp::{FrameId, ProtocolVersion};

fuzz_target!(|data: &[u8]| {
    // The first byte selects which callback to try, so the fuzzer can steer
    // itself between them instead of only ever exercising one.
    let (selector, payload) = data.split_first().unwrap_or((&0, &[]));
    let frame_id = match selector % 5 {
        0 => FrameId::STACK_STATUS_HANDLER,
        1 => FrameId::TRUST_CENTER_JOIN_HANDLER,
        2 => FrameId::INCOMING_MESSAGE_HANDLER,
        3 => FrameId::MESSAGE_SENT_HANDLER,
        // An id this build does not decode, which must be carried rather than
        // rejected.
        _ => FrameId(u16::from(*selector) << 8),
    };
    for version in [ProtocolVersion::new(0x0d), ProtocolVersion::new(0x0e)] {
        let _ = Callback::decode(frame_id, payload, version);
    }
});
