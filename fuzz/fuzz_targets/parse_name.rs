#![no_main]

use dingo_proto::Name;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test domain name parsing with compression pointer handling.
    // This is the most critical target for finding compression pointer vulnerabilities.
    // Try parsing names at various offsets to exercise different code paths.

    // Parse from the beginning
    let _ = Name::parse(data, 0);

    // Parse from offset 12 (typical question section start)
    if data.len() > 12 {
        let _ = Name::parse(data, 12);
    }

    // Parse from a random-ish offset based on data length
    if data.len() > 20 {
        let offset = (data.len() / 3).min(100);
        let _ = Name::parse(data, offset);
    }
});
