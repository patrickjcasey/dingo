//! Benchmarks for DNS parsing performance.
//!
//! Run with: cargo bench

#![feature(test)]

extern crate test;

use dingo_proto::Message;
use test::Bencher;

/// Minimal DNS query packet for "example.com" A record
#[rustfmt::skip]
const MINIMAL_QUERY: &[u8] = &[
    // Header
    0x12, 0x34,             // ID
    0x01, 0x00,             // Flags: RD=1
    0x00, 0x01,             // QDCOUNT = 1
    0x00, 0x00,             // ANCOUNT = 0
    0x00, 0x00,             // NSCOUNT = 0
    0x00, 0x00,             // ARCOUNT = 0
    // Question
    0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
    0x03, b'c', b'o', b'm',
    0x00,
    0x00, 0x01,             // QTYPE = A
    0x00, 0x01,             // QCLASS = IN
];

/// DNS response with A record using compression pointer
#[rustfmt::skip]
const RESPONSE_WITH_COMPRESSION: &[u8] = &[
    // Header
    0x12, 0x34,
    0x81, 0x80,             // QR=1, RD=1, RA=1
    0x00, 0x01,             // QDCOUNT = 1
    0x00, 0x01,             // ANCOUNT = 1
    0x00, 0x00,
    0x00, 0x00,
    // Question
    0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
    0x03, b'c', b'o', b'm',
    0x00,
    0x00, 0x01,
    0x00, 0x01,
    // Answer (with compression pointer)
    0xC0, 0x0C,             // Pointer to offset 12
    0x00, 0x01,             // TYPE = A
    0x00, 0x01,             // CLASS = IN
    0x00, 0x00, 0x00, 0x3C, // TTL = 60
    0x00, 0x04,             // RDLENGTH = 4
    0x5D, 0xB8, 0xD8, 0x22, // IP address
];

#[bench]
fn bench_parse_minimal_query(b: &mut Bencher) {
    b.iter(|| test::black_box(Message::parse(MINIMAL_QUERY)));
}

#[bench]
fn bench_parse_response_with_compression(b: &mut Bencher) {
    b.iter(|| test::black_box(Message::parse(RESPONSE_WITH_COMPRESSION)));
}

#[bench]
fn bench_parse_header_only(b: &mut Bencher) {
    use dingo_proto::Header;
    b.iter(|| test::black_box(Header::parse(MINIMAL_QUERY)));
}
