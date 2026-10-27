# Changelog

All notable changes to `dingo-proto` are documented in this file. Releases
before 0.3.0 predate the changelog.

## [0.3.0] - 2026-10-27

### Breaking changes

- `Header::parse` no longer rejects unassigned OPCODE values, RCODE values, or
  the Z bit; it only checks length. OPCODE 6-15 (including DSO, RFC 8490),
  RCODE 11-15, and headers with the Z bit set now parse, matching `hickory-proto`
  and `domain`.
- `ParseError::ReservedHeaderBit`, `ParseError::InvalidOpcode`, and
  `ParseError::InvalidResponseCode` have been removed.
- `ResponseCode` gains `YXDomain`, `YXRRSet`, `NXRRSet`, `NotAuth`, and `NotZone`
  for RCODE 6-10 (RFC 2136). `ResponseCode::Reserved` now covers only 11-15.
- `ParseError::LabelLengthTooLong` is replaced by `ParseError::UnsupportedLabelType`.
  A length octet above 63 always uses a reserved label type (`01` or `10` prefix),
  so both cases are reported with the new variant.
- New `ParseError::TooManyCompressionPointers`, returned when a name follows more
  than 128 compression pointers. `ParseError::CompressionPointerLoop` is now only
  returned for a pointer that points to itself.
- `ResourceRecordOwned::as_ipv4` and `as_ipv6` return `Ipv4Addr` and `Ipv6Addr`
  instead of `[u8; 4]` and `[u8; 16]`, matching `ResourceRecord`.
- `Message` equality and hashing compare the header and parsed sections instead of
  raw packet bytes, so messages that differ only in name case or compression are
  equal.
- `Message::parse` returns `ParseError::InvalidRecordCount` when a section count
  is larger than the number of records in the packet, instead of `BufferTooShort`.
  A record that is cut short is still reported as `BufferTooShort`.

### Added

- `Hash` for `QuestionOwned`, `ResourceRecordOwned`, and `MessageOwned`.

### Fixed

- `Name::is_root` follows compression pointers, so a pointer to a root label is
  reported as root.
- The RDLENGTH bounds check can no longer overflow on 16-bit targets.

[0.3.0]: https://github.com/patrickjcasey/dingo/compare/dingo-proto-v0.2.0...dingo-proto-v0.3.0
