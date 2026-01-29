# TODO: dingo-proto 0.1.0 Release

This document tracks what needs to be done before publishing `dingo-proto` to crates.io.

## Phase 1: Core Implementation ✅ COMPLETE

These are the foundational components that must be implemented first.

### 1. Implement `Name` parsing (`src/name.rs`) ✅

Parse DNS domain names with RFC 1035 compression pointer support.

**Requirements:**
- [x] Handle label sequences (length-prefixed segments)
- [x] Handle compression pointers (0xC0 prefix followed by 14-bit offset)
- [x] Detect and reject pointer loops (self-reference, mutual loops)
- [x] Detect and reject out-of-bounds pointers
- [x] Detect and reject forward pointers (pointer to data not yet parsed)
- [x] Enforce max label length (63 octets)
- [x] Enforce max name length (255 octets after decompression)
- [x] Track visited positions to prevent loops (fixed-size array, no allocation)
- [x] Implement `to_string()` for display (dot-separated labels with trailing dot)
- [x] Zero-copy `Name<'a>` borrowed type
- [x] `NameOwned` owned type with `into_owned()` conversion
- [x] `LabelIter<'a>` for iterating over labels

**Security notes:**
- This is the most security-critical component
- Compression pointer vulnerabilities are the source of many DNS CVEs
- See: CVE-2018-20994, CVE-2017-14339, NAME:WRECK

### 2. Implement `Question` parsing (`src/question.rs`) ✅

Parse the question section of DNS messages.

**Requirements:**
- [x] Parse domain name using `Name::parse()`
- [x] Read QTYPE (2 bytes, big-endian)
- [x] Read QCLASS (2 bytes, big-endian)
- [x] Validate bounds before reading QTYPE/QCLASS
- [x] Return parsed Question and next offset
- [x] Zero-copy `Question<'a>` borrowed type
- [x] `QuestionOwned` owned type with `into_owned()` conversion

### 3. Implement `ResourceRecord` parsing (`src/rr.rs`) ✅

Parse resource records (answers, authorities, additionals).

**Requirements:**
- [x] Parse domain name using `Name::parse()`
- [x] Read TYPE, CLASS, TTL, RDLENGTH (big-endian)
- [x] Validate RDLENGTH doesn't exceed remaining packet (`RdataOverflow`)
- [x] For A records, validate RDLENGTH == 4 (`InvalidRdataLength`)
- [x] For AAAA records, validate RDLENGTH == 16 (`InvalidRdataLength`)
- [x] Read RDLENGTH bytes as RDATA (zero-copy slice)
- [x] Return parsed ResourceRecord and next offset
- [x] Zero-copy `ResourceRecord<'a>` borrowed type
- [x] `ResourceRecordOwned` owned type with `into_owned()` conversion
- [x] Helper methods: `is_a()`, `is_aaaa()`, `is_cname()`, `as_ipv4()`, `as_ipv6()`

### 4. Implement `Message` parsing (`src/message.rs`) ✅

The main entry point for parsing complete DNS packets.

**Requirements:**
- [x] Parse header using `Header::parse()`
- [x] Validate all sections upfront during `Message::parse()`
- [x] Parse QDCOUNT questions
- [x] Parse ANCOUNT answer records
- [x] Parse NSCOUNT authority records
- [x] Parse ARCOUNT additional records
- [x] Return errors immediately for malformed packets
- [x] Zero-copy `Message<'a>` with lazy iteration via `questions()`, `answers()`, etc.
- [x] `MessageOwned` owned type with `into_owned()` conversion
- [x] `QuestionIter<'a>` and `ResourceRecordIter<'a>` iterators

---

## Phase 2: Testing & Validation ✅ COMPLETE

### 5. Get vulnerability tests passing ✅

All tests in `crates/dingo-proto/tests/vulnerability.rs` pass.

**Compression Pointer Tests:**
- [x] `test_compression_pointer_self_reference()` - CVE-2018-20994 pattern
- [x] `test_compression_pointer_mutual_loop()` - zlip-2 pattern
- [x] `test_compression_pointer_out_of_bounds()` - NAME:WRECK
- [x] `test_compression_pointer_forward()` - Forward pointer detection
- [x] `test_compression_pointer_deep_chain()` - Deep recursion limits

**Label/Name Tests:**
- [x] `test_label_length_overflow()` - Label > 63 octets
- [x] `test_name_length_overflow()` - zlip-3 pattern (> 255 octets)

**RDLENGTH Tests:**
- [x] `test_rdlength_overflow()` - RDLENGTH exceeds packet
- [x] `test_rdlength_mismatch_a_record()` - Invalid A record length

**Record Count Tests:**
- [x] `test_inflated_qdcount()` - QDCOUNT > actual questions
- [x] `test_inflated_ancount()` - ANCOUNT > actual answers

**CVE Regression Tests:**
- [x] `test_cve_2018_20994_trust_dns()`
- [x] `test_cve_2017_14339_yadifa()`
- [x] `test_cve_2024_24788_go_dns()`

### 6. Get conformance tests passing ✅

All tests in `crates/dingo-proto/tests/conformance.rs` pass.

- [x] `test_cz_nic_fuzzing_corpus()` - Parse CZ-NIC packets without panic
- [x] `test_valid_minimal_query()` - Parse minimal DNS query
- [x] `test_valid_response_with_a_record()` - Parse response with compression
- [ ] `test_valid_response_multiple_records()` - Multiple record types (TODO: implement)
- [ ] `test_valid_edns_opt_record()` - EDNS OPT record support (TODO: implement)

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

### 8. Research DNS CVEs and add regression tests ✅

Research known CVEs in other DNS parsers and add tests.

**Already covered:**
- [x] CVE-2018-20994 (trust-dns) - Compression pointer infinite loop
- [x] CVE-2017-14339 (YADIFA) - Compression pointer loop
- [x] CVE-2024-24788 (Go DNS) - Malformed response freeze
- [x] DNSpooq (CVE-2020-25684/85/86) - Documented as out-of-scope (cache poisoning, not parser)
- [x] RFC 9267 (DNS Implementation Anti-Patterns) - Reviewed and tested

### 9. Add unit tests for public API ✅

Comprehensive unit tests for all public types (101 tests passing).

**Header tests:**
- [x] All accessor methods (id, qr, opcode, flags, counts)
- [x] Edge cases (all flags set, max counts)

**Name tests:**
- [x] Simple single-label names
- [x] Multi-label names
- [x] Root domain (empty name)
- [x] Max length labels (63 bytes)
- [x] Max length names (255 bytes)
- [x] Compression pointer tests

**Question/ResourceRecord tests:**
- [x] Various QTYPE/TYPE values
- [x] Various CLASS values
- [x] Common record types (A, AAAA, CNAME, MX, TXT, NS, SOA, OPT)

**Message tests:**
- [x] Query with single question
- [x] Response with single/multiple answers
- [x] Truncated message (TC flag)
- [x] All sections (question, answer, authority, additional)

---

## Phase 3: Performance ✅ COMPLETE

### 10. Benchmark against other DNS parsers ✅

Compare performance against other Rust DNS parsers.

**Parsers compared:**
- [x] `hickory-proto` (formerly trust-dns)
- [x] `domain` (NLnet Labs)

**Benchmark scenarios:**
- [x] Minimal query parsing
- [x] Response with compression pointer
- [x] Response with multiple answers

**Implementation:**
- [x] Using criterion.rs with benchmark groups for comparison
- [x] HTML reports enabled (`target/criterion/report/index.html`)
- [x] Throughput metrics (bytes/sec)

### 11. Apply performance optimizations ✅

**Implemented optimizations:**
- [x] Zero-copy parsing - `Name<'a>`, `Question<'a>`, `ResourceRecord<'a>`, `Message<'a>` reference packet data
- [x] No allocations during parsing (borrowed types)
- [x] Fixed-size array for compression pointer loop detection (no heap allocation)
- [x] Lazy iteration - sections parsed on-demand via iterators
- [x] Inline critical functions

---

## Phase 4: Pre-publish Checklist

### 12. Documentation

**README and examples:**
- [ ] Add usage examples to README.md
- [ ] Document MSRV (Minimum Supported Rust Version) policy
- [ ] Add examples directory with runnable examples

**API documentation:**
- [x] All public items have doc comments
- [ ] `cargo doc` builds without warnings
- [ ] Doctests compile and run

### 13. Final checklist before crates.io publish

**Cargo.toml:**
- [x] Description filled in
- [ ] Version set to 0.1.0
- [ ] License specified (MIT/Apache-2.0)
- [ ] Repository URL set
- [ ] Documentation URL set
- [x] Keywords added (dns, parser, no_std)
- [x] Categories added
- [ ] Exclude unnecessary files (testdata/, fuzz/)

**Quality:**
- [ ] `cargo clippy` passes with no warnings
- [ ] `cargo fmt --check` passes
- [x] All tests pass (`cargo test --all`) - 131 tests passing
- [ ] No_std build works (`cargo build --no-default-features`)
- [ ] MSRV documented and tested

**Security:**
- [x] No unsafe code
- [x] All CVE regression tests pass
- [ ] Fuzzing has been run extensively
- [ ] CHANGELOG.md documents security properties

**Final:**
- [ ] `cargo publish --dry-run` succeeds
- [ ] Review public API one final time

---

## New Tasks

### 14. Add usage examples

Create examples demonstrating how to use `dingo-proto`.

**Examples to add:**
- [ ] `examples/parse_query.rs` - Parse a DNS query and print questions
- [ ] `examples/parse_response.rs` - Parse a DNS response and print answers
- [ ] `examples/owned_vs_borrowed.rs` - Demonstrate zero-copy vs owned types
- [ ] `examples/error_handling.rs` - Show how to handle parse errors

### 15. Write MSRV policy in README

Document the Minimum Supported Rust Version policy.

- [ ] Determine MSRV (test with older Rust versions)
- [ ] Add MSRV badge to README
- [ ] Document MSRV policy (e.g., "supports last 3 stable releases")
- [ ] Add CI job to test MSRV

### 16. Add DNS message construction API

Add support for building DNS messages, not just parsing them.

**Builder API design:**
- [ ] `MessageBuilder` - Construct complete DNS messages
- [ ] `QuestionBuilder` - Build question records
- [ ] `ResourceRecordBuilder` - Build resource records
- [ ] Fluent API with method chaining (e.g., `MessageBuilder::new().id(0x1234).question(...).build()`)

**Core functionality:**
- [ ] Set header fields (ID, flags, opcode, etc.)
- [ ] Add questions with name, qtype, qclass
- [ ] Add resource records (answers, authorities, additionals)
- [ ] Serialize to `Vec<u8>` or write to `&mut [u8]`

**Name compression (optional, may defer to future release):**
- [ ] Implement compression pointer generation for repeated names
- [ ] Track name offsets during serialization
- [ ] Option to disable compression for simplicity

**Considerations:**
- Should work in no_std with alloc (use `Vec` for output)
- Consider a no-alloc variant that writes to a provided buffer
- Validate constraints during building (label length, name length, etc.)
- Return `Result` for operations that can fail

**Example API sketch:**
```rust
let packet = MessageBuilder::new()
    .id(0x1234)
    .recursion_desired(true)
    .question("example.com", QType::A, QClass::IN)
    .build()?;

let response = MessageBuilder::response_to(&query)
    .answer("example.com", Type::A, Class::IN, 300, &[93, 184, 216, 34])
    .build()?;
```

### 17 Setup CI
[ ] configure `cargo test`
[ ] configure `cargo miri`
[ ] configure `cargo fmt --check`
[ ] configure publishing when git tag applied to `main`

### 18 Setup CI
[ ] rewrite git history, squash down to 1 commit
[ ] swap email to `patrickcaseyoss@gmail.com` in git history and Cargo.toml

---

## File Overview

| File              | Status | Description                             |
| ----------------- | ------ | --------------------------------------- |
| `src/lib.rs`      | ✅ Done | Public API exports, Header type         |
| `src/error.rs`    | ✅ Done | ParseError enum with all variants       |
| `src/name.rs`     | ✅ Done | Name<'a>, NameOwned, LabelIter          |
| `src/question.rs` | ✅ Done | Question<'a>, QuestionOwned             |
| `src/rr.rs`       | ✅ Done | ResourceRecord<'a>, ResourceRecordOwned |
| `src/message.rs`  | ✅ Done | Message<'a>, MessageOwned, iterators    |

---

## References

- [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035) - Domain Names - Implementation and Specification
- [RFC 9267](https://datatracker.ietf.org/doc/html/rfc9267) - Common Implementation Anti-Patterns
- [NAME:WRECK](https://www.forescout.com/research-labs/namewreck/) - DNS vulnerabilities research
- [CZ-NIC dns-fuzzing](https://github.com/CZ-NIC/dns-fuzzing) - Fuzzing corpus
