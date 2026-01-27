#![no_main]

use dingo_proto::ResourceRecord;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test resource record parsing in isolation.
    // Assumes the packet data is the full packet context for name decompression.
    // Parses RR starting at offset 12 (after header) if data is long enough.
    if data.len() >= 12 {
        let _ = ResourceRecord::parse(data, 12);
    }
});
