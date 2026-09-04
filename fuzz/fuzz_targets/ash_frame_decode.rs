//! The ASH decoder, fed arbitrary bytes.
//!
//! This is the parser closest to the wire, so it sees whatever the line
//! produces: noise, half frames, a device speaking a different protocol. It
//! must never panic and must never grow a buffer without bound, which is why
//! the target feeds one long stream rather than one frame -- an unbounded
//! buffer only shows up when the delimiter never arrives.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rsezsp::ash::Decoder;

fuzz_target!(|data: &[u8]| {
    // One decoder across the whole input: state must survive malformed frames
    // without corrupting the frames after them.
    let mut decoder = Decoder::new();
    for chunk in data.chunks(7) {
        let _ = decoder.feed(chunk);
    }

    // And again in one go, because the chunking above is itself a variable a
    // decoder must not depend on.
    let mut whole = Decoder::new();
    let _ = whole.feed(data);
});
