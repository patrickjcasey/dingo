# dingo-proto &emsp; [![crates.io][crates-badge]][crates] [![docs.rs][docs-badge]][docs] [![License: MIT][license-badge]][license]

[crates-badge]: https://img.shields.io/crates/v/dingo-proto.svg
[crates]: https://crates.io/crates/dingo-proto
[docs-badge]: https://docs.rs/dingo-proto/badge.svg
[docs]: https://docs.rs/dingo-proto
[license-badge]: https://img.shields.io/badge/License-MIT-yellow.svg
[license]: https://opensource.org/licenses/MIT

**A high-performance, safe DNS packet parser focused on speed and safety.**

## Features

- Zero unsafe code (`#![forbid(unsafe_code)]`)
- Fast, zero-copy parsing where possible
- `no_std` compatible (requires `alloc`)
- Robust handling of malformed packets
- Comprehensive test suite with real-world packet captures
- Fuzz-tested to check for possible crashes

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
dingo-proto = "0.2"
```

Parse a DNS message:

```rust
use dingo_proto::Message;

let packet = [
    // Header
    0x12, 0x34,             // ID = 0x1234
    0x01, 0x00,             // Flags: RD=1 (standard query with recursion desired)
    0x00, 0x01,             // QDCOUNT = 1
    0x00, 0x00,             // ANCOUNT = 0
    0x00, 0x00,             // NSCOUNT = 0
    0x00, 0x00,             // ARCOUNT = 0
    // Question section
    0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
    0x03, b'c', b'o', b'm',
    0x00,
    0x00, 0x01,             // QTYPE = A (1)
    0x00, 0x01,             // QCLASS = IN (1)
];
let message = Message::parse(&packet).unwrap();
```

## Features flags

- `std` — adds a `std::error::Error` implementation for `ParseError`.

## Security

This parser is designed to safely handle malformed input. The test suite includes
checks for known DNS parsing vulnerabilities:

- **Compression pointer loops** (CVE-2018-20994, CVE-2017-14339)
- **Compression pointer out-of-bounds** (NAME:WRECK)
- **Label/name length overflow** (RFC 9267)
- **RDLENGTH validation** (RFC 9267)
- **Record count validation** (RFC 9267)

## Relevant RFCs

- [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035) — Domain Names - Implementation and Specification
- [RFC 9267](https://datatracker.ietf.org/doc/html/rfc9267) — Common Implementation Anti-Patterns

## License

Licensed under the [MIT license](https://opensource.org/licenses/MIT).

This crate is part of the [Dingo](https://github.com/patrickjcasey/dingo) workspace.
