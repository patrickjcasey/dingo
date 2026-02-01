use dingo_proto::{Header, Message, ParseError};
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{LegacyPcapReader, PcapBlockOwned, PcapError};
use std::fs::File;
use std::net::{Ipv4Addr, Ipv6Addr};
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
        .filter(|p| p.extension().is_some_and(|ext| ext == "pkt"))
}

/// Extract DNS payloads from a PCAP file.
///
/// This extracts UDP payloads from packets on port 53 or 5353 (mDNS).
/// Returns a vector of raw DNS message bytes.
fn extract_dns_from_pcap(path: &Path) -> Vec<Vec<u8>> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to open {}: {}", path.display(), e);
            return vec![];
        }
    };

    let mut reader = match LegacyPcapReader::new(65536, file) {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "Failed to create PCAP reader for {}: {:?}",
                path.display(),
                e
            );
            return vec![];
        }
    };

    let mut dns_payloads = Vec::new();

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::Legacy(packet) => {
                        // Try to extract DNS payload from the packet
                        if let Some(dns_data) = extract_dns_from_ethernet(packet.data) {
                            dns_payloads.push(dns_data);
                        }
                    }
                    PcapBlockOwned::LegacyHeader(_) => {
                        // Skip header blocks
                    }
                    _ => {}
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                reader.refill().unwrap();
            }
            Err(e) => {
                eprintln!("Error reading PCAP: {:?}", e);
                break;
            }
        }
    }

    dns_payloads
}

/// Extract DNS payload from an Ethernet frame.
/// Returns None if not a DNS packet (UDP port 53 or 5353).
fn extract_dns_from_ethernet(data: &[u8]) -> Option<Vec<u8>> {
    // Minimum: 14 (Ethernet) + 20 (IP) + 8 (UDP) + 12 (DNS header) = 54 bytes
    if data.len() < 54 {
        return None;
    }

    // Check EtherType (bytes 12-13)
    let ethertype = u16::from_be_bytes([data[12], data[13]]);

    let ip_start = match ethertype {
        0x0800 => 14, // IPv4
        0x86DD => 14, // IPv6
        _ => return None,
    };

    // For IPv4, check protocol and extract header length
    if ethertype == 0x0800 {
        if data.len() < ip_start + 20 {
            return None;
        }

        let version_ihl = data[ip_start];
        let ihl = (version_ihl & 0x0F) as usize * 4;
        let protocol = data[ip_start + 9];

        // Check for UDP (protocol 17)
        if protocol != 17 {
            return None;
        }

        let udp_start = ip_start + ihl;
        if data.len() < udp_start + 8 {
            return None;
        }

        // Extract UDP ports
        let src_port = u16::from_be_bytes([data[udp_start], data[udp_start + 1]]);
        let dst_port = u16::from_be_bytes([data[udp_start + 2], data[udp_start + 3]]);

        // Check for DNS (port 53) or mDNS (port 5353)
        if src_port != 53 && dst_port != 53 && src_port != 5353 && dst_port != 5353 {
            return None;
        }

        // Extract UDP payload (DNS data)
        let dns_start = udp_start + 8;
        if dns_start >= data.len() {
            return None;
        }

        Some(data[dns_start..].to_vec())
    } else {
        // IPv6 handling (simplified - doesn't handle extension headers)
        if data.len() < ip_start + 40 {
            return None;
        }

        let next_header = data[ip_start + 6];

        // Check for UDP (next header 17)
        if next_header != 17 {
            return None;
        }

        let udp_start = ip_start + 40;
        if data.len() < udp_start + 8 {
            return None;
        }

        let src_port = u16::from_be_bytes([data[udp_start], data[udp_start + 1]]);
        let dst_port = u16::from_be_bytes([data[udp_start + 2], data[udp_start + 3]]);

        if src_port != 53 && dst_port != 53 && src_port != 5353 && dst_port != 5353 {
            return None;
        }

        let dns_start = udp_start + 8;
        if dns_start >= data.len() {
            return None;
        }

        Some(data[dns_start..].to_vec())
    }
}

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
        "CZ-NIC corpus: {tested} packets tested, {parsed_ok} parsed OK, {parsed_err} returned errors"
    );

    assert!(
        tested > 0,
        "No packets found in CZ-NIC corpus at {}",
        corpus_dir.display()
    );
}

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

    let dns_payloads = extract_dns_from_pcap(&pcap_path);

    assert!(
        !dns_payloads.is_empty(),
        "Should extract DNS payloads from dns-mdns.pcap"
    );

    let mut parsed_ok = 0;
    let mut parsed_err = 0;

    for payload in &dns_payloads {
        match Message::parse(payload) {
            Ok(_) => parsed_ok += 1,
            Err(_) => parsed_err += 1,
        }
    }

    println!(
        "dns-mdns.pcap: {} packets, {} parsed OK, {} errors",
        dns_payloads.len(),
        parsed_ok,
        parsed_err
    );

    // Most packets should parse successfully
    assert!(
        parsed_ok > 0,
        "At least some DNS packets should parse successfully"
    );
}

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

    let dns_payloads = extract_dns_from_pcap(&pcap_path);

    assert!(
        !dns_payloads.is_empty(),
        "Should extract DNS payloads from dns.cap"
    );

    let mut parsed_ok = 0;

    for payload in &dns_payloads {
        if Message::parse(payload).is_ok() {
            parsed_ok += 1;
        }
    }

    println!(
        "dns.cap: {} packets extracted, {} parsed successfully",
        dns_payloads.len(),
        parsed_ok
    );

    // All standard DNS packets should parse
    assert_eq!(
        parsed_ok,
        dns_payloads.len(),
        "All DNS packets in dns.cap should parse successfully"
    );
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

    let dns_payloads = extract_dns_from_pcap(&pcap_path);

    // zlip files may have malformed packets that don't extract as normal UDP
    // The important thing is we don't panic and handle errors gracefully
    for payload in &dns_payloads {
        let result = Message::parse(payload);
        // Should return an error for malformed compression pointers
        if let Err(e) = result {
            assert!(
                matches!(
                    e,
                    ParseError::CompressionPointerLoop
                        | ParseError::CompressionPointerOutOfBounds
                        | ParseError::CompressionPointerForward
                        | ParseError::BufferTooShort
                        | ParseError::NameTooLong
                ),
                "Expected compression-related error, got {e:?}"
            );
        }
    }

    println!(
        "zlip-1.pcap: handled {} packets without panic",
        dns_payloads.len()
    );
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

    let dns_payloads = extract_dns_from_pcap(&pcap_path);

    for payload in &dns_payloads {
        let result = Message::parse(payload);
        if let Err(e) = result {
            assert!(
                matches!(
                    e,
                    ParseError::CompressionPointerLoop
                        | ParseError::CompressionPointerOutOfBounds
                        | ParseError::CompressionPointerForward
                        | ParseError::BufferTooShort
                        | ParseError::NameTooLong
                ),
                "Expected compression-related error, got {e:?}"
            );
        }
    }

    println!(
        "zlip-2.pcap: handled {} packets without panic",
        dns_payloads.len()
    );
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

    let dns_payloads = extract_dns_from_pcap(&pcap_path);

    for payload in &dns_payloads {
        let result = Message::parse(payload);
        if let Err(e) = result {
            // zlip-3 specifically tests name length explosion
            assert!(
                matches!(
                    e,
                    ParseError::NameTooLong
                        | ParseError::CompressionPointerLoop
                        | ParseError::CompressionPointerOutOfBounds
                        | ParseError::CompressionPointerForward
                        | ParseError::BufferTooShort
                ),
                "Expected name length or compression error, got {e:?}"
            );
        }
    }

    println!(
        "zlip-3.pcap: handled {} packets without panic",
        dns_payloads.len()
    );
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

    let dns_payloads = extract_dns_from_pcap(&pcap_path);

    // Some packets in this capture may not be valid DNS (it's anomaly traffic)
    // The parser should not panic on any of them
    let mut parsed_ok = 0;
    let mut parsed_err = 0;

    for payload in &dns_payloads {
        match Message::parse(payload) {
            Ok(_) => parsed_ok += 1,
            Err(_) => parsed_err += 1,
        }
    }

    println!(
        "dns-remoteshell.pcap: {} packets, {} parsed OK, {} errors (expected for anomaly traffic)",
        dns_payloads.len(),
        parsed_ok,
        parsed_err
    );
}

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
    assert!(result.is_ok(), "Failed to parse valid query: {result:?}");

    let msg = result.unwrap();
    assert!(msg.is_query());
    assert_eq!(msg.id(), 0x1234);
    assert_eq!(msg.header.qdcount(), 1);

    let questions: Vec<_> = msg.questions().collect::<Vec<_>>();
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
    assert!(result.is_ok(), "Failed to parse valid response: {result:?}");

    let msg = result.unwrap();
    assert!(msg.is_response());
    let answers: Vec<_> = msg.answers().collect::<Vec<_>>();
    assert_eq!(answers.len(), 1);
}

/// Test parsing a response with multiple record types (A, AAAA, CNAME)
#[test]
fn test_valid_response_multiple_records() {
    #[rustfmt::skip]
    let packet = [
        // Header
        0x12, 0x34,             // ID
        0x81, 0x80,             // Flags: QR=1, RD=1, RA=1
        0x00, 0x01,             // QDCOUNT = 1
        0x00, 0x03,             // ANCOUNT = 3 (CNAME + A + AAAA)
        0x00, 0x00,             // NSCOUNT = 0
        0x00, 0x00,             // ARCOUNT = 0

        // Question: www.example.com A
        0x03, b'w', b'w', b'w',
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x03, b'c', b'o', b'm',
        0x00,
        0x00, 0x01,             // QTYPE = A
        0x00, 0x01,             // QCLASS = IN

        // Answer 1: CNAME www.example.com -> example.com
        0xC0, 0x0C,             // Name: pointer to www.example.com (offset 12)
        0x00, 0x05,             // TYPE = CNAME (5)
        0x00, 0x01,             // CLASS = IN
        0x00, 0x00, 0x0E, 0x10, // TTL = 3600
        0x00, 0x02,             // RDLENGTH = 2 (pointer)
        0xC0, 0x10,             // RDATA: pointer to example.com (offset 16)

        // Answer 2: A record for example.com
        0xC0, 0x10,             // Name: pointer to example.com
        0x00, 0x01,             // TYPE = A
        0x00, 0x01,             // CLASS = IN
        0x00, 0x00, 0x00, 0x3C, // TTL = 60
        0x00, 0x04,             // RDLENGTH = 4
        0x5D, 0xB8, 0xD8, 0x22, // RDATA = 93.184.216.34

        // Answer 3: AAAA record for example.com
        0xC0, 0x10,             // Name: pointer to example.com
        0x00, 0x1C,             // TYPE = AAAA (28)
        0x00, 0x01,             // CLASS = IN
        0x00, 0x00, 0x00, 0x3C, // TTL = 60
        0x00, 0x10,             // RDLENGTH = 16
        0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0x00, 0x01,
        0x02, 0x48, 0x18, 0x93, 0x25, 0xc8, 0x19, 0x46,
    ];

    let result = Message::parse(&packet);
    assert!(result.is_ok(), "Failed to parse response: {result:?}");

    let msg = result.unwrap();
    assert!(msg.is_response());
    assert_eq!(msg.header.ancount(), 3);

    let answers: Vec<_> = msg.answers().collect::<Vec<_>>();
    assert_eq!(answers.len(), 3);

    // Verify record types
    assert_eq!(answers[0].rtype, 5); // CNAME
    assert_eq!(answers[1].rtype, 1); // A
    assert_eq!(answers[2].rtype, 28); // AAAA

    // Verify A record data
    assert_eq!(answers[1].as_ipv4(), Some(Ipv4Addr::new(93, 184, 216, 34)));

    // Verify AAAA record data
    assert_eq!(
        answers[2].as_ipv6(),
        Some(Ipv6Addr::from_bits(u128::from_be_bytes([
            0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0x00, 0x01, 0x02, 0x48, 0x18, 0x93, 0x25, 0xc8,
            0x19, 0x46,
        ])))
    );
}

/// Test parsing EDNS (OPT) record in additional section
#[test]
fn test_valid_edns_opt_record() {
    #[rustfmt::skip]
    let packet = [
        // Header
        0x12, 0x34,             // ID
        0x01, 0x00,             // Flags: RD=1 (query)
        0x00, 0x01,             // QDCOUNT = 1
        0x00, 0x00,             // ANCOUNT = 0
        0x00, 0x00,             // NSCOUNT = 0
        0x00, 0x01,             // ARCOUNT = 1 (OPT record)

        // Question: example.com A
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x03, b'c', b'o', b'm',
        0x00,
        0x00, 0x01,             // QTYPE = A
        0x00, 0x01,             // QCLASS = IN

        // Additional: OPT record (EDNS)
        0x00,                   // Name: root (required for OPT)
        0x00, 0x29,             // TYPE = OPT (41)
        0x10, 0x00,             // CLASS = UDP payload size (4096)
        0x00, 0x00, 0x00, 0x00, // TTL = extended RCODE (0) + version (0) + flags (0)
        0x00, 0x00,             // RDLENGTH = 0 (no options)
    ];

    let result = Message::parse(&packet);
    assert!(result.is_ok(), "Failed to parse EDNS query: {result:?}");

    let msg = result.unwrap();
    assert_eq!(msg.header.arcount(), 1);

    let additionals: Vec<_> = msg.additionals().collect::<Vec<_>>();
    assert_eq!(additionals.len(), 1);

    let opt = &additionals[0];
    assert!(opt.is_opt());
    assert_eq!(opt.rtype, 41);
    assert_eq!(opt.rclass, 4096); // UDP payload size
    assert_eq!(opt.rdlength, 0);
}

/// Test parsing EDNS with options (e.g., EDNS Client Subnet)
#[test]
fn test_valid_edns_with_options() {
    #[rustfmt::skip]
    let packet = [
        // Header
        0x12, 0x34,             // ID
        0x01, 0x00,             // Flags: RD=1
        0x00, 0x01,             // QDCOUNT = 1
        0x00, 0x00,             // ANCOUNT = 0
        0x00, 0x00,             // NSCOUNT = 0
        0x00, 0x01,             // ARCOUNT = 1

        // Question
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x03, b'c', b'o', b'm',
        0x00,
        0x00, 0x01,             // QTYPE = A
        0x00, 0x01,             // QCLASS = IN

        // OPT record with EDNS Client Subnet option
        0x00,                   // Name: root
        0x00, 0x29,             // TYPE = OPT
        0x10, 0x00,             // CLASS = 4096
        0x00, 0x00, 0x80, 0x00, // TTL: extended RCODE=0, version=0, DO=1
        0x00, 0x08,             // RDLENGTH = 8

        // EDNS Client Subnet option
        0x00, 0x08,             // Option code: Client Subnet
        0x00, 0x04,             // Option length: 4
        0x00, 0x01,             // Family: IPv4
        0x18,                   // Source prefix length: 24
        0x00,                   // Scope prefix length: 0
        0xC0,                   // Address: 192.x.x.x (first octet)
    ];

    let result = Message::parse(&packet);
    assert!(
        result.is_ok(),
        "Failed to parse EDNS with options: {result:?}"
    );

    let msg = result.unwrap();
    let additionals: Vec<_> = msg.additionals().collect::<Vec<_>>();
    assert_eq!(additionals.len(), 1);

    let opt = &additionals[0];
    assert!(opt.is_opt());
    assert_eq!(opt.rdlength, 8);
    assert_eq!(opt.rdata.len(), 8);
}

// The parser uses strict validation for headers per RFC 1035:
// - Reserved Z bit (bit 9) must be zero (AD/CD bits 10-11 are allowed per RFC 4035)
// - OPCODE must be in known range (0-5)
// - RCODE must be in known range (0-10)
/// Test that headers with reserved Z bit set are rejected
#[test]
fn test_header_reserved_z_bit_rejected() {
    #[rustfmt::skip]
    let packet = [
        // Header
        0x12, 0x34,             // ID = 0x1234
        0x01, 0x00,             // Flags: RD=1
        0x00, 0x00,             // QDCOUNT = 0
        0x00, 0x00,             // ANCOUNT = 0
        0x00, 0x00,             // NSCOUNT = 0
        0x00, 0x00,             // ARCOUNT = 0
    ];

    // First verify normal header parses
    let (header, _) = Header::parse(&packet).expect("normal header should parse");
    assert_eq!(header.id(), 0x1234);

    // Set only the reserved Z bit (bit 9, 0x40 in byte 3)
    let mut packet_with_reserved_z = packet;
    packet_with_reserved_z[3] |= 0x40;

    let result = Header::parse(&packet_with_reserved_z);
    assert_eq!(
        result,
        Err(ParseError::ReservedHeaderBit),
        "Header with reserved Z bit should be rejected"
    );
}

/// Test that DNSSEC AD/CD bits are allowed (they're not the reserved bit)
#[test]
fn test_header_dnssec_bits_allowed() {
    #[rustfmt::skip]
    let mut packet = [
        // Header
        0x12, 0x34,             // ID = 0x1234
        0x80, 0x00,             // Flags: QR=1 (response)
        0x00, 0x00,             // QDCOUNT = 0
        0x00, 0x00,             // ANCOUNT = 0
        0x00, 0x00,             // NSCOUNT = 0
        0x00, 0x00,             // ARCOUNT = 0
    ];

    // Set AD bit (0x20) and CD bit (0x10) - these are DNSSEC flags, not reserved
    packet[3] |= 0x30; // AD + CD

    let result = Header::parse(&packet);
    assert!(
        result.is_ok(),
        "Header with DNSSEC AD/CD bits should be allowed"
    );
}

/// Test that headers with reserved opcodes are rejected
#[test]
fn test_header_reserved_opcode_rejected() {
    #[rustfmt::skip]
    let mut packet = [
        // Header
        0x12, 0x34,             // ID
        0x00, 0x00,             // Flags (will modify opcode)
        0x00, 0x00,             // QDCOUNT = 0
        0x00, 0x00,             // ANCOUNT = 0
        0x00, 0x00,             // NSCOUNT = 0
        0x00, 0x00,             // ARCOUNT = 0
    ];

    // Opcode is bits 3-6 of byte 2 (0x78 mask, shifted right by 3)
    // Set opcode to 6 (first reserved value, 6-15 are reserved)
    packet[2] = 0x30; // opcode = 6

    let result = Header::parse(&packet);
    assert_eq!(
        result,
        Err(ParseError::InvalidOpcode),
        "Header with reserved opcode 6 should be rejected"
    );

    // Also test opcode 15
    packet[2] = 0x78; // opcode = 15
    let result = Header::parse(&packet);
    assert_eq!(
        result,
        Err(ParseError::InvalidOpcode),
        "Header with reserved opcode 15 should be rejected"
    );
}

/// Test that valid opcodes are accepted (0-5)
#[test]
fn test_header_valid_opcodes_accepted() {
    for opcode in 0..=5u8 {
        #[rustfmt::skip]
        let mut packet = [
            0x12, 0x34,             // ID
            0x00, 0x00,             // Flags
            0x00, 0x00,             // QDCOUNT
            0x00, 0x00,             // ANCOUNT
            0x00, 0x00,             // NSCOUNT
            0x00, 0x00,             // ARCOUNT
        ];

        packet[2] = opcode << 3;

        let result = Header::parse(&packet);
        assert!(result.is_ok(), "Opcode {opcode} should be accepted");

        let (header, _) = result.unwrap();
        assert_eq!(header.opcode(), opcode);
    }
}

/// Test that headers with reserved RCODE values are rejected
#[test]
fn test_header_reserved_rcode_rejected() {
    #[rustfmt::skip]
    let mut packet = [
        // Header
        0x12, 0x34,             // ID
        0x80, 0x00,             // Flags: QR=1 (response)
        0x00, 0x00,             // QDCOUNT = 0
        0x00, 0x00,             // ANCOUNT = 0
        0x00, 0x00,             // NSCOUNT = 0
        0x00, 0x00,             // ARCOUNT = 0
    ];

    // RCODE is bits 0-3 of byte 3 (0x0F mask)
    // Set RCODE to 11 (first reserved value, 11-15 are reserved)
    packet[3] = 0x0B;

    let result = Header::parse(&packet);
    assert_eq!(
        result,
        Err(ParseError::InvalidResponseCode),
        "Header with reserved RCODE 11 should be rejected"
    );

    // Also test RCODE 15
    packet[3] = 0x0F;
    let result = Header::parse(&packet);
    assert_eq!(
        result,
        Err(ParseError::InvalidResponseCode),
        "Header with reserved RCODE 15 should be rejected"
    );
}

/// Test that valid RCODEs are accepted (0-10)
#[test]
fn test_header_valid_rcodes_accepted() {
    for rcode in 0..=10u8 {
        #[rustfmt::skip]
        let mut packet = [
            0x12, 0x34,             // ID
            0x80, 0x00,             // Flags: QR=1 (response)
            0x00, 0x00,             // QDCOUNT
            0x00, 0x00,             // ANCOUNT
            0x00, 0x00,             // NSCOUNT
            0x00, 0x00,             // ARCOUNT
        ];

        packet[3] = rcode;

        let result = Header::parse(&packet);
        assert!(result.is_ok(), "RCODE {rcode} should be accepted");
    }
}

/// Test that headers with all valid flags set works
#[test]
fn test_header_all_valid_flags() {
    #[rustfmt::skip]
    let packet = [
        // Header with valid flags
        0xFF, 0xFF,             // ID = 0xFFFF
        0x2F,                   // QR=0, Opcode=5 (UPDATE), AA=1, TC=1, RD=1
        0xB0,                   // RA=1, Z=0, AD=1, CD=1, RCODE=0
        0xFF, 0xFF,             // QDCOUNT = 65535
        0xFF, 0xFF,             // ANCOUNT = 65535
        0xFF, 0xFF,             // NSCOUNT = 65535
        0xFF, 0xFF,             // ARCOUNT = 65535
    ];

    let result = Header::parse(&packet);
    assert!(
        result.is_ok(),
        "Header with all valid flags should be accepted"
    );

    let (header, _) = result.unwrap();
    assert_eq!(header.id(), 0xFFFF);
    assert_eq!(header.opcode(), 5);
    assert!(header.authoritative_answer());
    assert!(header.truncated());
    assert!(header.recursion_desired());
    assert!(header.recursion_available());
    assert_eq!(header.qdcount(), 65535);
    assert_eq!(header.ancount(), 65535);
    assert_eq!(header.nscount(), 65535);
    assert_eq!(header.arcount(), 65535);
}

/// Test header parsing with minimum valid input (exactly 12 bytes)
#[test]
fn test_header_exact_size() {
    let packet = [0u8; 12];

    let result = Header::parse(&packet);
    assert!(result.is_ok(), "12-byte buffer should parse as header");

    let (header, remainder) = result.unwrap();
    assert_eq!(header.id(), 0);
    assert!(remainder.is_empty());
}

/// Test header parsing fails with insufficient bytes
#[test]
fn test_header_too_short() {
    let packet = [0u8; 11]; // One byte short

    let result = Header::parse(&packet);
    assert!(result.is_err(), "11-byte buffer should fail to parse");
}

/// Test header parsing returns correct remainder
#[test]
fn test_header_returns_remainder() {
    let mut packet = [0u8; 20];
    packet[12..20].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);

    let (_, remainder) = Header::parse(&packet).unwrap();
    assert_eq!(remainder, &[1, 2, 3, 4, 5, 6, 7, 8]);
}
