# TODO: dingo-proto 0.1.0 Release

This document tracks what needs to be done before publishing `dingo-proto` to crates.io.

## Phase 1: Core Implementation

These are the foundational components that must be implemented first.

### 1. Implement `Name` parsing (`src/name.rs`)

Parse DNS domain names with RFC 1035 compression pointer support.

**Requirements:**
- [ ] Handle label sequences (length-prefixed segments)
- [ ] Handle compression pointers (0xC0 prefix followed by 14-bit offset)
- [ ] Detect and reject pointer loops (self-reference, mutual loops)
- [ ] Detect and reject out-of-bounds pointers
- [ ] Detect and reject forward pointers (pointer to data not yet parsed)
- [ ] Enforce max label length (63 octets)
- [ ] Enforce max name length (255 octets after decompression)
- [ ] Track recursion depth to prevent stack overflow
- [ ] Implement `to_string()` for display (dot-separated labels with trailing dot)

**Security notes:**
- This is the most security-critical component
- Compression pointer vulnerabilities are the source of many DNS CVEs
- See: CVE-2018-20994, CVE-2017-14339, NAME:WRECK

### 2. Implement `Question` parsing (`src/question.rs`)

Parse the question section of DNS messages.

**Requirements:**
- [ ] Parse domain name using `Name::parse()`
- [ ] Read QTYPE (2 bytes, big-endian)
- [ ] Read QCLASS (2 bytes, big-endian)
- [ ] Validate bounds before reading QTYPE/QCLASS
- [ ] Return parsed Question and next offset

### 3. Implement `ResourceRecord` parsing (`src/rr.rs`)

Parse resource records (answers, authorities, additionals).

**Requirements:**
- [ ] Parse domain name using `Name::parse()`
- [ ] Read TYPE, CLASS, TTL, RDLENGTH (big-endian)
- [ ] Validate RDLENGTH doesn't exceed remaining packet (`RdataOverflow`)
- [ ] For A records, validate RDLENGTH == 4 (`InvalidRdataLength`)
- [ ] For AAAA records, validate RDLENGTH == 16 (`InvalidRdataLength`)
- [ ] Read RDLENGTH bytes as RDATA
- [ ] Return parsed ResourceRecord and next offset

### 4. Implement `Message` parsing (`src/message.rs`)

The main entry point for parsing complete DNS packets.

**Requirements:**
- [ ] Parse header using `Header::parse()`
- [ ] Parse QDCOUNT questions
- [ ] Parse ANCOUNT answer records
- [ ] Parse NSCOUNT authority records
- [ ] Parse ARCOUNT additional records
- [ ] Validate counts match actual parsed records (`InvalidRecordCount`)
- [ ] Handle truncated messages gracefully

---

## Phase 2: Testing & Validation

### 5. Get vulnerability tests passing

All tests in `crates/dingo-proto/tests/vulnerability.rs` must pass.

**Compression Pointer Tests:**
- [ ] `test_compression_pointer_self_reference()` - CVE-2018-20994 pattern
- [ ] `test_compression_pointer_mutual_loop()` - zlip-2 pattern
- [ ] `test_compression_pointer_out_of_bounds()` - NAME:WRECK
- [ ] `test_compression_pointer_forward()` - Forward pointer detection
- [ ] `test_compression_pointer_deep_chain()` - Deep recursion limits

**Label/Name Tests:**
- [ ] `test_label_length_overflow()` - Label > 63 octets
- [ ] `test_name_length_overflow()` - zlip-3 pattern (> 255 octets)

**RDLENGTH Tests:**
- [ ] `test_rdlength_overflow()` - RDLENGTH exceeds packet
- [ ] `test_rdlength_mismatch_a_record()` - Invalid A record length

**Record Count Tests:**
- [ ] `test_inflated_qdcount()` - QDCOUNT > actual questions
- [ ] `test_inflated_ancount()` - ANCOUNT > actual answers

**CVE Regression Tests:**
- [ ] `test_cve_2018_20994_trust_dns()`
- [ ] `test_cve_2017_14339_yadifa()`

### 6. Get conformance tests passing

All tests in `crates/dingo-proto/tests/conformance.rs` must pass.

- [ ] `test_cz_nic_fuzzing_corpus()` - Parse 9,774 CZ-NIC packets without panic
- [ ] `test_valid_minimal_query()` - Parse minimal DNS query
- [ ] `test_valid_response_with_a_record()` - Parse response with compression
- [ ] `test_valid_response_multiple_records()` - Multiple record types
- [ ] `test_valid_edns_opt_record()` - EDNS OPT record support

### 7. Get fuzzing targets running

The fuzz targets in `fuzz/fuzz_targets/` must compile and run.

- [ ] `parse_message` - Complete DNS message parsing
- [ ] `parse_header` - Header parsing (already works)
- [ ] `parse_question` - Question section parsing
- [ ] `parse_rr` - Resource record parsing
- [ ] `parse_name` - Domain name with compression pointers

**Fuzzing tasks:**
- [ ] Verify all fuzz targets compile
- [ ] Run each target with CZ-NIC corpus as seed
- [ ] Run extended fuzzing sessions (hours/overnight)
- [ ] Add any crash inputs to regression tests

### 8. Research DNS CVEs and add regression tests

Research known CVEs in other DNS parsers and add tests.

**Already covered:**
- CVE-2018-20994 (trust-dns) - Compression pointer infinite loop
- CVE-2017-14339 (YADIFA) - Compression pointer loop

**To research:**
- [ ] CVE-2024-24788 (Go DNS) - Malformed response freeze
- [ ] CVE-2020-25684/85/86 (dnsmasq) - Various parsing issues
- [ ] Recent CVEs in: BIND, Unbound, PowerDNS, c-ares, musl libc resolver
- [ ] Review RFC 9267 (DNS Implementation Anti-Patterns)

### 9. Add unit tests for public API

Comprehensive unit tests for all public types.

**Header tests:**
- [ ] All accessor methods (id, qr, opcode, flags, counts)
- [ ] Edge cases (all flags set, max counts)

**Name tests:**
- [ ] Simple single-label names
- [ ] Multi-label names
- [ ] Root domain (empty name)
- [ ] Max length labels (63 bytes)
- [ ] Max length names (255 bytes)

**Question/ResourceRecord tests:**
- [ ] Various QTYPE/TYPE values
- [ ] Various CLASS values
- [ ] Common record types (A, AAAA, CNAME, MX, TXT, NS, SOA)

**Message tests:**
- [ ] Query with single question
- [ ] Response with single/multiple answers
- [ ] Truncated message (TC flag)

---

## Phase 3: Performance

### 10. Benchmark against other DNS parsers

Compare performance against other Rust DNS parsers.

**Parsers to compare:**
- [ ] `trust-dns` (hickory-dns)
- [ ] `dns-parser`
- [ ] `domain` (NLnet Labs)
- [ ] `simple-dns`

**Benchmark scenarios:**
- [ ] Minimal query parsing
- [ ] Response with compression pointer
- [ ] Large response with many records
- [ ] Complex compression pointer chains
- [ ] Header-only parsing

**Implementation:**
- [ ] Use criterion.rs for statistical benchmarks
- [ ] Document results

### 11. Apply performance optimizations

Based on benchmark results, optimize hot paths.

**Potential optimizations:**
- [ ] Zero-copy parsing where possible
- [ ] Compression pointer cache
- [ ] Inline critical functions
- [ ] Avoid allocations (SmallVec for no_std)
- [ ] Profile with `perf` or `samply`

---

## Phase 4: Pre-publish Checklist

### 12. Final checklist before crates.io publish

**Cargo.toml:**
- [ ] Version set to 0.1.0
- [ ] Description filled in
- [ ] License specified (MIT/Apache-2.0)
- [ ] Repository URL set
- [ ] Documentation URL set
- [ ] Keywords added (dns, parser, no_std)
- [ ] Categories added
- [ ] Exclude unnecessary files (testdata/, fuzz/)

**Documentation:**
- [ ] README.md with usage examples
- [ ] All public items have doc comments
- [ ] `cargo doc` builds without warnings
- [ ] Examples compile and run

**Quality:**
- [ ] `cargo clippy` passes with no warnings
- [ ] `cargo fmt --check` passes
- [ ] All tests pass (`cargo test --all`)
- [ ] No_std build works (`cargo build --no-default-features`)
- [ ] MSRV documented and tested

**Security:**
- [ ] No unsafe code (or documented why needed)
- [ ] All CVE regression tests pass
- [ ] Fuzzing has been run extensively
- [ ] CHANGELOG.md documents security properties

**Final:**
- [ ] `cargo publish --dry-run` succeeds
- [ ] Review public API one final time

---

## File Overview

| File | Status | Description |
|------|--------|-------------|
| `src/lib.rs` | ✅ Done | Public API exports |
| `src/error.rs` | ✅ Done | ParseError enum with all variants |
| `src/decoder.rs` | ⚠️ Legacy | DnsRequest::parse (may be removed) |
| `src/name.rs` | 🔴 TODO | Domain name parsing |
| `src/question.rs` | 🔴 TODO | Question section parsing |
| `src/rr.rs` | 🔴 TODO | Resource record parsing |
| `src/message.rs` | 🔴 TODO | Complete message parsing |

---

## References

- [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035) - Domain Names - Implementation and Specification
- [RFC 9267](https://datatracker.ietf.org/doc/html/rfc9267) - Common Implementation Anti-Patterns
- [NAME:WRECK](https://www.forescout.com/research-labs/namewreck/) - DNS vulnerabilities research
- [CZ-NIC dns-fuzzing](https://github.com/CZ-NIC/dns-fuzzing) - Fuzzing corpus
