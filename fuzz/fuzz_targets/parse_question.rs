#![no_main]

use dingo_proto::Question;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test question parsing in isolation.
    // Assumes the packet data is the full packet context for name decompression.
    // Parses question starting at offset 12 (after header) if data is long enough.
    if data.len() >= 12 {
        let _ = Question::parse(data, 12);
    }
});
