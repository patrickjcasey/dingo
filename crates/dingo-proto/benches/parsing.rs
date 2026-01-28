//! Benchmarks comparing dingo-proto against hickory-proto and domain crates.
//!
//! Run with: cargo bench -p dingo-proto

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

// ============================================================================
// Test packets
// ============================================================================

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

// ============================================================================
// dingo-proto benchmarks
// ============================================================================

fn bench_dingo(c: &mut Criterion) {
    let mut group = c.benchmark_group("dingo-proto");

    group.throughput(Throughput::Bytes(MINIMAL_QUERY.len() as u64));
    group.bench_function("minimal_query", |b| {
        b.iter(|| dingo_proto::Message::parse(black_box(MINIMAL_QUERY)))
    });

    group.throughput(Throughput::Bytes(RESPONSE_WITH_ANSWER.len() as u64));
    group.bench_function("response_with_answer", |b| {
        b.iter(|| dingo_proto::Message::parse(black_box(RESPONSE_WITH_ANSWER)))
    });

    group.throughput(Throughput::Bytes(RESPONSE_MULTIPLE_ANSWERS.len() as u64));
    group.bench_function("response_multiple_answers", |b| {
        b.iter(|| dingo_proto::Message::parse(black_box(RESPONSE_MULTIPLE_ANSWERS)))
    });

    group.finish();
}

// ============================================================================
// hickory-proto benchmarks
// ============================================================================

fn bench_hickory(c: &mut Criterion) {
    use hickory_proto::op::Message as HickoryMessage;

    let mut group = c.benchmark_group("hickory-proto");

    group.throughput(Throughput::Bytes(MINIMAL_QUERY.len() as u64));
    group.bench_function("minimal_query", |b| {
        b.iter(|| HickoryMessage::from_vec(black_box(MINIMAL_QUERY)))
    });

    group.throughput(Throughput::Bytes(RESPONSE_WITH_ANSWER.len() as u64));
    group.bench_function("response_with_answer", |b| {
        b.iter(|| HickoryMessage::from_vec(black_box(RESPONSE_WITH_ANSWER)))
    });

    group.throughput(Throughput::Bytes(RESPONSE_MULTIPLE_ANSWERS.len() as u64));
    group.bench_function("response_multiple_answers", |b| {
        b.iter(|| HickoryMessage::from_vec(black_box(RESPONSE_MULTIPLE_ANSWERS)))
    });

    group.finish();
}

// ============================================================================
// domain benchmarks
// ============================================================================

fn bench_domain(c: &mut Criterion) {
    use domain::base::Message as DomainMessage;

    let mut group = c.benchmark_group("domain");

    // Note: domain uses lazy/zero-copy parsing. from_slice() just validates
    // the header and returns a view. We need to iterate over records to force
    // actual parsing for a fair comparison.

    group.throughput(Throughput::Bytes(MINIMAL_QUERY.len() as u64));
    group.bench_function("minimal_query", |b| {
        b.iter(|| {
            let msg = DomainMessage::from_slice(black_box(MINIMAL_QUERY)).unwrap();
            // Force parsing by iterating over questions
            for q in msg.question() {
                let _ = black_box(q);
            }
        })
    });

    group.throughput(Throughput::Bytes(RESPONSE_WITH_ANSWER.len() as u64));
    group.bench_function("response_with_answer", |b| {
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

    group.throughput(Throughput::Bytes(RESPONSE_MULTIPLE_ANSWERS.len() as u64));
    group.bench_function("response_multiple_answers", |b| {
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

// ============================================================================
// Comparison benchmarks (side-by-side)
// ============================================================================

fn bench_comparison(c: &mut Criterion) {
    use domain::base::Message as DomainMessage;
    use hickory_proto::op::Message as HickoryMessage;

    // Minimal query comparison
    let mut group = c.benchmark_group("comparison/minimal_query");
    group.throughput(Throughput::Bytes(MINIMAL_QUERY.len() as u64));

    group.bench_function("dingo-proto", |b| {
        b.iter(|| dingo_proto::Message::parse(black_box(MINIMAL_QUERY)))
    });
    group.bench_function("hickory-proto", |b| {
        b.iter(|| HickoryMessage::from_vec(black_box(MINIMAL_QUERY)))
    });
    group.bench_function("domain", |b| {
        b.iter(|| {
            let msg = DomainMessage::from_slice(black_box(MINIMAL_QUERY)).unwrap();
            for q in msg.question() {
                let _ = black_box(q);
            }
        })
    });

    group.finish();

    // Response with answer comparison
    let mut group = c.benchmark_group("comparison/response_with_answer");
    group.throughput(Throughput::Bytes(RESPONSE_WITH_ANSWER.len() as u64));

    group.bench_function("dingo-proto", |b| {
        b.iter(|| dingo_proto::Message::parse(black_box(RESPONSE_WITH_ANSWER)))
    });
    group.bench_function("hickory-proto", |b| {
        b.iter(|| HickoryMessage::from_vec(black_box(RESPONSE_WITH_ANSWER)))
    });
    group.bench_function("domain", |b| {
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

criterion_group!(
    benches,
    bench_dingo,
    bench_hickory,
    bench_domain,
    bench_comparison
);
criterion_main!(benches);
