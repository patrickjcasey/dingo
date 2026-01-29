//! Conformance tests using real packet captures.
//!
//! These tests verify that the parser correctly handles real-world DNS packets
//! from various sources including Wireshark captures and the CZ-NIC fuzzing corpus.

use dingo_proto::Message;
use std::path::{Path, PathBuf};

/// Get the workspace root directory.
/// Tests are run from the workspace root, so we can use relative paths.
fn workspace_root() -> PathBuf {
    // When running `cargo test` from workspace root, CWD is the workspace root
    // When running from crate dir, we need to go up
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Helper to load a raw DNS packet from a file
fn load_packet(path: &Path) -> Vec<u8> {
    std::fs::read(path).expect("Failed to read packet file")
}

/// Helper to iterate over all .pkt files in a directory
fn iter_pkt_files(dir: &Path) -> impl Iterator<Item = std::path::PathBuf> {
    std::fs::read_dir(dir)
        .expect("Failed to read directory")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map_or(false, |ext| ext == "pkt"))
}

// =============================================================================
// CZ-NIC Fuzzing Corpus Tests
// =============================================================================

/// Test parsing against the CZ-NIC dns-fuzzing corpus.
///
/// These are raw DNS packets used for fuzzing Knot DNS.
/// The parser should not panic on any of these inputs.
#[test]
fn test_cz_nic_fuzzing_corpus() {
    let corpus_dir = workspace_root().join("testdata/dns-fuzzing/packet");

    if !corpus_dir.exists() {
        eprintln!(
            "Skipping CZ-NIC corpus test: {} not found. Run: git submodule update --init",
            corpus_dir.display()
        );
        return;
    }

    let mut tested = 0;
    let mut parsed_ok = 0;
    let mut parsed_err = 0;

    for path in iter_pkt_files(&corpus_dir) {
        let data = load_packet(&path);
        tested += 1;

        // The parser must not panic, but may return Ok or Err
        match Message::parse(&data) {
            Ok(_) => parsed_ok += 1,
            Err(_) => parsed_err += 1,
        }
    }

    println!(
        "CZ-NIC corpus: {} packets tested, {} parsed OK, {} returned errors",
        tested, parsed_ok, parsed_err
    );

    assert!(
        tested > 0,
        "No packets found in CZ-NIC corpus at {}",
        corpus_dir.display()
    );
}

// =============================================================================
// Wireshark Sample Capture Tests
// =============================================================================

/// Test parsing DNS packets from Wireshark test captures.
///
/// Note: These are PCAP files, so we need pcap-parser to extract DNS payloads.
/// For now, this is a placeholder that documents the expected test structure.
#[test]
fn test_wireshark_dns_mdns_capture() {
    let pcap_path = workspace_root().join("testdata/wireshark/test/captures/dns-mdns.pcap");

    if !pcap_path.exists() {
        eprintln!(
            "Skipping Wireshark capture test: {} not found. Run: git submodule update --init",
            pcap_path.display()
        );
        return;
    }

    // TODO: Extract DNS payloads from PCAP and test parsing
    // This requires pcap-parser to extract UDP payloads from port 53/5353
    //
    // Example structure:
    // let pcap_data = std::fs::read(pcap_path).unwrap();
    // for dns_payload in extract_dns_from_pcap(&pcap_data) {
    //     let _ = Message::parse(&dns_payload);
    // }

    println!("Wireshark dns-mdns.pcap exists, PCAP parsing not yet implemented");
}

// =============================================================================
// Manual Sample Tests (downloaded via script)
// =============================================================================

/// Test against Wireshark wiki sample: dns.cap
#[test]
fn test_wireshark_wiki_dns_cap() {
    let pcap_path = workspace_root().join("testdata/samples/dns.cap");

    if !pcap_path.exists() {
        eprintln!(
            "Skipping dns.cap test: {} not found. Run: ./scripts/download-testdata.sh",
            pcap_path.display()
        );
        return;
    }

    // TODO: Extract DNS payloads from PCAP
    println!("dns.cap exists, PCAP parsing not yet implemented");
}

/// Test against Wireshark wiki sample: zlip-1.pcap (self-referential pointer)
///
/// This capture contains a DNS packet with an endless self-referential
/// compression pointer, designed to test decompression flaw handling.
#[test]
fn test_wireshark_wiki_zlip1() {
    let pcap_path = workspace_root().join("testdata/samples/zlip-1.pcap");

    if !pcap_path.exists() {
        eprintln!(
            "Skipping zlip-1.pcap test: {} not found. Run: ./scripts/download-testdata.sh",
            pcap_path.display()
        );
        return;
    }

    // TODO: Extract DNS payload and verify it returns CompressionPointerLoop error
    println!("zlip-1.pcap exists, PCAP parsing not yet implemented");
}

/// Test against Wireshark wiki sample: zlip-2.pcap (cross-referencing pointers)
///
/// This capture contains DNS packets with endless cross-referencing
/// compression pointers.
#[test]
fn test_wireshark_wiki_zlip2() {
    let pcap_path = workspace_root().join("testdata/samples/zlip-2.pcap");

    if !pcap_path.exists() {
        eprintln!(
            "Skipping zlip-2.pcap test: {} not found. Run: ./scripts/download-testdata.sh",
            pcap_path.display()
        );
        return;
    }

    // TODO: Extract DNS payload and verify it returns CompressionPointerLoop error
    println!("zlip-2.pcap exists, PCAP parsing not yet implemented");
}

/// Test against Wireshark wiki sample: zlip-3.pcap (domain length explosion)
///
/// This capture creates a very long domain name through multiple
/// decompression of the same hostname.
#[test]
fn test_wireshark_wiki_zlip3() {
    let pcap_path = workspace_root().join("testdata/samples/zlip-3.pcap");

    if !pcap_path.exists() {
        eprintln!(
            "Skipping zlip-3.pcap test: {} not found. Run: ./scripts/download-testdata.sh",
            pcap_path.display()
        );
        return;
    }

    // TODO: Extract DNS payload and verify it returns NameTooLong error
    println!("zlip-3.pcap exists, PCAP parsing not yet implemented");
}

/// Test against Wireshark wiki sample: dns-remoteshell.pcap
///
/// This capture contains DNS anomaly caused by remoteshell riding on DNS port.
#[test]
fn test_wireshark_wiki_dns_remoteshell() {
    let pcap_path = workspace_root().join("testdata/samples/dns-remoteshell.pcap");

    if !pcap_path.exists() {
        eprintln!(
            "Skipping dns-remoteshell.pcap test: {} not found. Run: ./scripts/download-testdata.sh",
            pcap_path.display()
        );
        return;
    }

    // TODO: Extract DNS payloads and test parsing
    // Some packets in this capture may not be valid DNS
    println!("dns-remoteshell.pcap exists, PCAP parsing not yet implemented");
}

// =============================================================================
// Known Good Packet Tests
// =============================================================================

/// Test parsing a minimal valid DNS query
#[test]
fn test_valid_minimal_query() {
    // Minimal DNS query for "example.com" A record
    #[rustfmt::skip]
    let packet = [
        // Header
        0x12, 0x34,             // ID = 0x1234
        0x01, 0x00,             // Flags: RD=1 (standard query with recursion desired)
        0x00, 0x01,             // QDCOUNT = 1
        0x00, 0x00,             // ANCOUNT = 0
        0x00, 0x00,             // NSCOUNT = 0
        0x00, 0x00,             // ARCOUNT = 0
        // Question section
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',  // "example"
        0x03, b'c', b'o', b'm',                          // "com"
        0x00,                                             // null terminator
        0x00, 0x01,             // QTYPE = A (1)
        0x00, 0x01,             // QCLASS = IN (1)
    ];

    let result = Message::parse(&packet);
    assert!(result.is_ok(), "Failed to parse valid query: {:?}", result);

    let msg = result.unwrap();
    assert!(msg.is_query());
    assert_eq!(msg.id(), 0x1234);
    assert_eq!(msg.header.qdcount(), 1);

    let questions: Vec<_> = msg.questions().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(questions.len(), 1);
    assert_eq!(questions[0].name.to_string(), "example.com.");
    assert_eq!(questions[0].qtype, 1); // A
    assert_eq!(questions[0].qclass, 1); // IN
}

/// Test parsing a valid DNS response with A record
#[test]
fn test_valid_response_with_a_record() {
    #[rustfmt::skip]
    let packet = [
        // Header
        0x12, 0x34,             // ID = 0x1234
        0x81, 0x80,             // Flags: QR=1, RD=1, RA=1 (response)
        0x00, 0x01,             // QDCOUNT = 1
        0x00, 0x01,             // ANCOUNT = 1
        0x00, 0x00,             // NSCOUNT = 0
        0x00, 0x00,             // ARCOUNT = 0
        // Question section
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x03, b'c', b'o', b'm',
        0x00,
        0x00, 0x01,             // QTYPE = A
        0x00, 0x01,             // QCLASS = IN
        // Answer section
        0xC0, 0x0C,             // Name: compression pointer to offset 12 (example.com)
        0x00, 0x01,             // TYPE = A
        0x00, 0x01,             // CLASS = IN
        0x00, 0x00, 0x00, 0x3C, // TTL = 60 seconds
        0x00, 0x04,             // RDLENGTH = 4
        0x5D, 0xB8, 0xD8, 0x22, // RDATA = 93.184.216.34
    ];

    let result = Message::parse(&packet);
    assert!(
        result.is_ok(),
        "Failed to parse valid response: {:?}",
        result
    );

    let msg = result.unwrap();
    assert!(msg.is_response());
    let answers: Vec<_> = msg.answers().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(answers.len(), 1);
}

/// Test parsing a response with multiple record types
#[test]
fn test_valid_response_multiple_records() {
    // TODO: Construct a packet with A, AAAA, CNAME, MX records
    // and verify all are parsed correctly
}

/// Test parsing EDNS (OPT) record
#[test]
fn test_valid_edns_opt_record() {
    // TODO: Construct a packet with EDNS OPT record
    // and verify it's handled correctly
}
