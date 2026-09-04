//! EZSP header parsing, both formats.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rsezsp::ezsp::frame::{HeaderFormat, parse};

fuzz_target!(|data: &[u8]| {
    // Both formats on the same bytes. The legacy header is three bytes and the
    // extended one five, so the same input exercises different boundaries.
    let _ = parse(data, HeaderFormat::Legacy);
    let _ = parse(data, HeaderFormat::Extended);
});
