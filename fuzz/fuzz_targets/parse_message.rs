#![no_main]

use dingo_proto::Message;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The parser should never panic, regardless of input.
    // It may return Ok or Err, but must not crash.
    let _ = Message::parse(data);
});
