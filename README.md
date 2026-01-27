# Dingo

A high-performance DNS toolkit for Rust, focused on speed and ease of use.

## Workspace Structure

This is a Cargo workspace containing the following crates:

| Crate | Description |
|-------|-------------|
| [`dingo-proto`](crates/dingo-proto) | DNS packet parser (`no_std` compatible) |

## Features

- Fast, zero-copy parsing where possible
- `no_std` compatible (with `alloc`)
- Robust handling of malformed packets
- Protection against known DNS parsing vulnerabilities
- Comprehensive test suite with real-world packet captures

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
dingo-proto = "0.1"
```

Example:

```rust
use dingo_proto::Message;

fn main() {
    let packet: &[u8] = [/* DNS packet bytes */];
    match Message::parse(packet) {
        Ok(message) => {
            println!("Query ID: {}", message.header.id);

            for question in &message.questions {
                println!("Question: {} {:?}", question.name, question.qtype);
            }

            for answer in &message.answers {
                println!("Answer: {} -> {:?}", answer.name, answer.rdata);
            }
        }
        Err(e) => eprintln!("Parse error: {}", e),
    }
}
```

## Building

```bash
cargo build
```

## Testing

### Unit Tests

```bash
cargo test
```

### Test Data Setup

This project uses git submodules for external test data. Initialize them with:

```bash
git submodule update --init --recursive
```

To download additional test samples from the Wireshark wiki:

```bash
./scripts/download-testdata.sh
```

### Running All Tests

```bash
# Run all workspace tests
cargo test --workspace

# Run tests including those that require test data
cargo test --workspace --all-features
```

## Fuzzing

This project uses [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) for fuzzing.

### Setup

```bash
# Install cargo-fuzz (requires nightly)
cargo install cargo-fuzz
```

### Running Fuzzers

```bash
# Fuzz the main message parser
cargo +nightly fuzz run parse_message

# Fuzz domain name parsing (compression pointer handling)
cargo +nightly fuzz run parse_name

# Fuzz with multiple parallel jobs
cargo +nightly fuzz run parse_message --jobs 4
```

### Seeding the Corpus

Copy test data to the fuzzing corpus:

```bash
# Copy CZ-NIC fuzzing seeds
mkdir -p fuzz/corpus/parse_message
cp testdata/dns-fuzzing/packet/*.pkt fuzz/corpus/parse_message/

# Extract DNS payloads from pcap files (requires tshark)
./scripts/extract-dns-payloads.sh fuzz/corpus/parse_message testdata/samples/*.pcap
```

### Fuzz Targets

| Target | Description |
|--------|-------------|
| `parse_message` | Complete DNS message parsing |
| `parse_header` | DNS header parsing only |
| `parse_question` | Question section parsing |
| `parse_rr` | Resource record parsing |
| `parse_name` | Domain name with compression pointer handling |

## Updating Test Data

This project uses git submodules for external test data sources.

### Submodules

| Directory | Source | Description |
|-----------|--------|-------------|
| `testdata/dns-fuzzing` | [CZ-NIC/dns-fuzzing](https://github.com/CZ-NIC/dns-fuzzing) | AFL fuzzing seeds |
| `testdata/wireshark` | [Wireshark](https://gitlab.com/wireshark/wireshark) | Test captures (sparse checkout) |

### Update CZ-NIC Fuzzing Corpus

```bash
git -C testdata/dns-fuzzing fetch origin
git -C testdata/dns-fuzzing checkout origin/master
git add testdata/dns-fuzzing
git commit -m "chore: update CZ-NIC fuzzing corpus"
```

### Update Wireshark Test Captures

```bash
git -C testdata/wireshark fetch origin
git -C testdata/wireshark checkout origin/master
git add testdata/wireshark
git commit -m "chore: update Wireshark test captures"
```

### Manual Downloads

Some test files must be downloaded separately:

```bash
./scripts/download-testdata.sh
```

This downloads from the [Wireshark Wiki SampleCaptures](https://wiki.wireshark.org/SampleCaptures):
- `dns.cap` - Various DNS lookups
- `dns-remoteshell.pcap` - DNS anomaly sample
- `zlip-1.pcap` - Self-referential pointer decompression flaw
- `zlip-2.pcap` - Cross-referencing pointer decompression flaw
- `zlip-3.pcap` - Domain length explosion via decompression

## Security

This parser is designed to safely handle malformed input. The test suite includes
checks for known DNS parsing vulnerabilities:

- **Compression pointer loops** (CVE-2018-20994, CVE-2017-14339)
- **Compression pointer out-of-bounds** (NAME:WRECK)
- **Label/name length overflow** (RFC 9267)
- **RDLENGTH validation** (RFC 9267)
- **Record count validation** (RFC 9267)

See [RFC 9267](https://www.rfc-editor.org/rfc/rfc9267.html) for details on common
DNS implementation anti-patterns.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
