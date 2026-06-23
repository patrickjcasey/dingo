use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use domain::base::Message as DomainMessage;
use hickory_proto::op::Message as HickoryMessage;
use std::hint::black_box;

/// Minimal DNS query packet for "example.com" A record (29 bytes)
#[rustfmt::skip]
const MINIMAL_QUERY: &[u8] = &[
    // Header (12 bytes)
    0x12, 0x34,             // ID
    0x01, 0x00,             // Flags: RD=1
    0x00, 0x01,             // QDCOUNT = 1
    0x00, 0x00,             // ANCOUNT = 0
    0x00, 0x00,             // NSCOUNT = 0
    0x00, 0x00,             // ARCOUNT = 0
    // Question (17 bytes)
    0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
    0x03, b'c', b'o', b'm',
    0x00,
    0x00, 0x01,             // QTYPE = A
    0x00, 0x01,             // QCLASS = IN
];

/// DNS response with A record using compression pointer (45 bytes)
#[rustfmt::skip]
const RESPONSE_WITH_ANSWER: &[u8] = &[
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
    0x5D, 0xB8, 0xD8, 0x22, // 93.184.216.34
];

/// DNS response with multiple answers (for throughput testing)
#[rustfmt::skip]
const RESPONSE_MULTIPLE_ANSWERS: &[u8] = &[
    // Header
    0x12, 0x34,
    0x81, 0x80,
    0x00, 0x01,             // QDCOUNT = 1
    0x00, 0x04,             // ANCOUNT = 4
    0x00, 0x00,
    0x00, 0x00,
    // Question: www.example.com
    0x03, b'w', b'w', b'w',
    0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
    0x03, b'c', b'o', b'm',
    0x00,
    0x00, 0x01, 0x00, 0x01,
    // Answer 1
    0xC0, 0x0C,
    0x00, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x3C,
    0x00, 0x04,
    0x01, 0x02, 0x03, 0x04,
    // Answer 2
    0xC0, 0x0C,
    0x00, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x3C,
    0x00, 0x04,
    0x05, 0x06, 0x07, 0x08,
    // Answer 3
    0xC0, 0x0C,
    0x00, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x3C,
    0x00, 0x04,
    0x09, 0x0A, 0x0B, 0x0C,
    // Answer 4
    0xC0, 0x0C,
    0x00, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x3C,
    0x00, 0x04,
    0x0D, 0x0E, 0x0F, 0x10,
];

/// DNS response with heavy compression - NS delegation with glue records
/// This tests chained compression pointers and multiple pointer references
///
/// Offset map:
///   0-11: Header (12 bytes)
///  12-24: Question name "example.com" (13 bytes)
///     12: label "example" (8 bytes)
///     20: label "com" (4 bytes)
///     24: null terminator
///  25-28: QTYPE + QCLASS (4 bytes)
///  29+: Authority and Additional sections
#[rustfmt::skip]
const RESPONSE_HEAVY_COMPRESSION: &[u8] = &[
    // Header (offset 0-11)
    0x12, 0x34,             // ID
    0x85, 0x00,             // QR=1, AA=1, RD=1
    0x00, 0x01,             // QDCOUNT = 1
    0x00, 0x00,             // ANCOUNT = 0
    0x00, 0x02,             // NSCOUNT = 2
    0x00, 0x02,             // ARCOUNT = 2

    // Question: example.com (offset 12)
    0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',  // offset 12-19
    0x03, b'c', b'o', b'm',                          // offset 20-23
    0x00,                                             // offset 24
    0x00, 0x02,             // QTYPE = NS (offset 25-26)
    0x00, 0x01,             // QCLASS = IN (offset 27-28)

    // Authority 1: example.com NS ns1.example.com (offset 29)
    0xC0, 0x0C,             // Pointer to offset 12 "example.com"
    0x00, 0x02,             // TYPE = NS
    0x00, 0x01,             // CLASS = IN
    0x00, 0x01, 0x51, 0x80, // TTL = 86400
    0x00, 0x06,             // RDLENGTH = 6
    0x03, b'n', b's', b'1', // "ns1" (offset 41-44)
    0xC0, 0x0C,             // Pointer to "example.com" (offset 45-46)
    // Total: 18 bytes, ends at offset 47

    // Authority 2: example.com NS ns2.example.com (offset 47)
    0xC0, 0x0C,             // Pointer to "example.com"
    0x00, 0x02,             // TYPE = NS
    0x00, 0x01,             // CLASS = IN
    0x00, 0x01, 0x51, 0x80, // TTL = 86400
    0x00, 0x06,             // RDLENGTH = 6
    0x03, b'n', b's', b'2', // "ns2" (offset 59-62)
    0xC0, 0x0C,             // Pointer to "example.com" (offset 63-64)
    // Total: 18 bytes, ends at offset 65

    // Additional 1: ns1.example.com A (offset 65)
    0xC0, 0x29,             // Pointer to offset 41 "ns1.example.com"
    0x00, 0x01,             // TYPE = A
    0x00, 0x01,             // CLASS = IN
    0x00, 0x01, 0x51, 0x80, // TTL = 86400
    0x00, 0x04,             // RDLENGTH = 4
    192, 0, 2, 1,           // 192.0.2.1
    // Total: 16 bytes, ends at offset 81

    // Additional 2: ns2.example.com A (offset 81)
    0xC0, 0x3B,             // Pointer to offset 59 "ns2.example.com"
    0x00, 0x01,             // TYPE = A
    0x00, 0x01,             // CLASS = IN
    0x00, 0x01, 0x51, 0x80, // TTL = 86400
    0x00, 0x04,             // RDLENGTH = 4
    192, 0, 2, 2,           // 192.0.2.2
    // Total: 16 bytes, ends at offset 97
];

fn bench_minimal_query(c: &mut Criterion) {
    let mut group = c.benchmark_group("minimal_query");
    group.throughput(Throughput::Bytes(MINIMAL_QUERY.len() as u64));

    group.bench_function(BenchmarkId::new("parse", "dingo"), |b| {
        b.iter(|| {
            let msg = dingo_proto::Message::parse(black_box(MINIMAL_QUERY)).unwrap();
            for q in msg.questions() {
                let _ = black_box(q);
            }
        })
    });
    group.bench_function(BenchmarkId::new("parse", "hickory"), |b| {
        b.iter(|| HickoryMessage::from_vec(black_box(MINIMAL_QUERY)))
    });
    group.bench_function(BenchmarkId::new("parse", "domain"), |b| {
        b.iter(|| {
            let msg = DomainMessage::from_slice(black_box(MINIMAL_QUERY)).unwrap();
            // Force parsing by iterating over questions
            for q in msg.question() {
                let _ = black_box(q);
            }
        })
    });

    group.finish();
}

fn bench_response_with_answer(c: &mut Criterion) {
    let mut group = c.benchmark_group("response_with_answer");
    group.throughput(Throughput::Bytes(RESPONSE_WITH_ANSWER.len() as u64));

    group.bench_function(BenchmarkId::new("parse", "dingo"), |b| {
        b.iter(|| {
            let msg = dingo_proto::Message::parse(black_box(RESPONSE_WITH_ANSWER)).unwrap();
            for q in msg.questions() {
                let _ = black_box(q);
            }
            for a in msg.answers() {
                let _ = black_box(a);
            }
        })
    });
    group.bench_function(BenchmarkId::new("parse", "hickory"), |b| {
        b.iter(|| HickoryMessage::from_vec(black_box(RESPONSE_WITH_ANSWER)))
    });
    group.bench_function(BenchmarkId::new("parse", "domain"), |b| {
        b.iter(|| {
            let msg = DomainMessage::from_slice(black_box(RESPONSE_WITH_ANSWER)).unwrap();
            for q in msg.question() {
                let _ = black_box(q);
            }
            for a in msg.answer().unwrap() {
                let _ = black_box(a);
            }
        })
    });

    group.finish();
}

fn bench_response_multiple_answers(c: &mut Criterion) {
    let mut group = c.benchmark_group("response_multiple_answers");
    group.throughput(Throughput::Bytes(RESPONSE_MULTIPLE_ANSWERS.len() as u64));

    group.bench_function(BenchmarkId::new("parse", "dingo"), |b| {
        b.iter(|| {
            let msg = dingo_proto::Message::parse(black_box(RESPONSE_MULTIPLE_ANSWERS)).unwrap();
            for q in msg.questions() {
                let _ = black_box(q);
            }
            for a in msg.answers() {
                let _ = black_box(a);
            }
        })
    });
    group.bench_function(BenchmarkId::new("parse", "hickory"), |b| {
        b.iter(|| HickoryMessage::from_vec(black_box(RESPONSE_MULTIPLE_ANSWERS)))
    });
    group.bench_function(BenchmarkId::new("parse", "domain"), |b| {
        b.iter(|| {
            let msg = DomainMessage::from_slice(black_box(RESPONSE_MULTIPLE_ANSWERS)).unwrap();
            for q in msg.question() {
                let _ = black_box(q);
            }
            for a in msg.answer().unwrap() {
                let _ = black_box(a);
            }
        })
    });

    group.finish();
}

fn bench_heavy_compression(c: &mut Criterion) {
    let mut group = c.benchmark_group("heavy_compression");
    group.throughput(Throughput::Bytes(RESPONSE_HEAVY_COMPRESSION.len() as u64));

    group.bench_function(BenchmarkId::new("parse", "dingo"), |b| {
        b.iter(|| {
            let msg = dingo_proto::Message::parse(black_box(RESPONSE_HEAVY_COMPRESSION)).unwrap();
            for q in msg.questions() {
                let _ = black_box(q);
            }
            for ns in msg.authorities() {
                let _ = black_box(ns);
            }
            for ar in msg.additionals() {
                let _ = black_box(ar);
            }
        })
    });
    group.bench_function(BenchmarkId::new("parse", "hickory"), |b| {
        b.iter(|| HickoryMessage::from_vec(black_box(RESPONSE_HEAVY_COMPRESSION)))
    });
    group.bench_function(BenchmarkId::new("parse", "domain"), |b| {
        b.iter(|| {
            let msg = DomainMessage::from_slice(black_box(RESPONSE_HEAVY_COMPRESSION)).unwrap();
            for q in msg.question() {
                let _ = black_box(q);
            }
            // No answers in this response
            for ns in msg.authority().unwrap() {
                let _ = black_box(ns);
            }
            for ar in msg.additional().unwrap() {
                let _ = black_box(ar);
            }
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_minimal_query,
    bench_response_with_answer,
    bench_response_multiple_answers,
    bench_heavy_compression,
);
criterion_main!(benches);
