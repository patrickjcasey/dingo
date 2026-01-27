#![no_main]

use dingo_proto::Header;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test header parsing in isolation.
    // The parser should never panic, regardless of input.
    let _ = Header::parse(data);
});
