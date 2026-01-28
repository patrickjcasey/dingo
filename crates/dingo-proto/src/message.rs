//! DNS message parsing.
//!
//! This module provides the main entry point for parsing DNS messages as
//! specified in RFC 1035 Section 4.

use alloc::vec::Vec;

use crate::question::Question;
use crate::rr::ResourceRecord;
use crate::{Header, ParseError, QR};

/// A parsed DNS message.
///
/// DNS messages consist of a header followed by four sections:
/// - Question section: what is being asked
/// - Answer section: resource records answering the question
/// - Authority section: resource records pointing to authoritative name servers
/// - Additional section: resource records with additional information
///
/// # Example
///
/// ```ignore
/// use dingo_proto::Message;
///
/// let packet = [/* ... DNS packet bytes ... */];
/// let message = Message::parse(&packet)?;
///
/// if message.is_query() {
///     println!("Query for: {:?}", message.questions);
/// } else {
///     println!("Response with {} answers", message.answers.len());
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// The DNS header containing flags and section counts.
    pub header: Header,
    /// The question section.
    ///
    /// Typically contains one question, but the protocol allows multiple.
    pub questions: Vec<Question>,
    /// The answer section.
    ///
    /// Contains resource records that answer the question(s).
    pub answers: Vec<ResourceRecord>,
    /// The authority section.
    ///
    /// Contains resource records pointing to authoritative name servers.
    pub authorities: Vec<ResourceRecord>,
    /// The additional section.
    ///
    /// Contains resource records with additional helpful information,
    /// such as A records for name servers listed in the authority section.
    pub additionals: Vec<ResourceRecord>,
}

impl Message {
    /// Parse a DNS message from raw packet data.
    ///
    /// This is the main entry point for parsing DNS packets.
    ///
    /// # Arguments
    ///
    /// * `data` - The raw DNS packet bytes
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The packet is too short for a valid header ([`ParseError::BufferTooShort`])
    /// - Any domain name is malformed (compression pointer issues, length issues)
    /// - Record counts don't match actual records ([`ParseError::InvalidRecordCount`])
    /// - RDATA length issues ([`ParseError::RdataOverflow`], [`ParseError::InvalidRdataLength`])
    ///
    /// # Example
    ///
    /// ```
    /// use dingo_proto::Message;
    ///
    /// // Minimal DNS query for example.com A
    /// let packet = [
    ///     0x12, 0x34, // ID
    ///     0x01, 0x00, // Flags: standard query, RD=1
    ///     0x00, 0x01, // QDCOUNT = 1
    ///     0x00, 0x00, // ANCOUNT = 0
    ///     0x00, 0x00, // NSCOUNT = 0
    ///     0x00, 0x00, // ARCOUNT = 0
    ///     0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
    ///     0x03, b'c', b'o', b'm',
    ///     0x00,
    ///     0x00, 0x01, // QTYPE = A
    ///     0x00, 0x01, // QCLASS = IN
    /// ];
    ///
    /// let msg = Message::parse(&packet).unwrap();
    /// assert!(msg.is_query());
    /// assert_eq!(msg.questions.len(), 1);
    /// ```
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        // 1. Parse the header
        let (header, _remainder) = Header::parse(data)?;

        // 2. Get the counts from the header
        let qdcount = header.qdcount() as usize;
        let ancount = header.ancount() as usize;
        let nscount = header.nscount() as usize;
        let arcount = header.arcount() as usize;

        // 3. Start parsing after the header (offset 12)
        let mut offset = Header::SIZE;

        // 3a. Parse questions
        let mut questions = Vec::with_capacity(qdcount);
        for _ in 0..qdcount {
            let (question, next_offset) = Question::parse(data, offset)?;
            questions.push(question);
            offset = next_offset;
        }

        // 3b. Parse answers
        let mut answers = Vec::with_capacity(ancount);
        for _ in 0..ancount {
            let (rr, next_offset) = ResourceRecord::parse(data, offset)?;
            answers.push(rr);
            offset = next_offset;
        }

        // 3c. Parse authorities
        let mut authorities = Vec::with_capacity(nscount);
        for _ in 0..nscount {
            let (rr, next_offset) = ResourceRecord::parse(data, offset)?;
            authorities.push(rr);
            offset = next_offset;
        }

        // 3d. Parse additionals
        let mut additionals = Vec::with_capacity(arcount);
        for _ in 0..arcount {
            let (rr, next_offset) = ResourceRecord::parse(data, offset)?;
            additionals.push(rr);
            offset = next_offset;
        }

        Ok(Self {
            header,
            questions,
            answers,
            authorities,
            additionals,
        })
    }

    /// Returns true if this message is a query (QR=0).
    #[inline]
    pub fn is_query(&self) -> bool {
        self.header.qr() == QR::Query
    }

    /// Returns true if this message is a response (QR=1).
    #[inline]
    pub fn is_response(&self) -> bool {
        self.header.qr() == QR::Response
    }

    /// Returns the message ID.
    #[inline]
    pub fn id(&self) -> u16 {
        self.header.id()
    }

    /// Returns true if this response indicates an error.
    #[inline]
    pub fn is_error(&self) -> bool {
        use crate::ResponseCode;
        !matches!(self.header.response_code(), ResponseCode::NoErrorCondition)
    }

    /// Returns true if recursion was desired in the query.
    #[inline]
    pub fn recursion_desired(&self) -> bool {
        self.header.recursion_desired()
    }

    /// Returns true if recursion is available (set in responses).
    #[inline]
    pub fn recursion_available(&self) -> bool {
        self.header.recursion_available()
    }

    /// Returns true if this message was truncated.
    ///
    /// When true, the client should retry the query using TCP.
    #[inline]
    pub fn truncated(&self) -> bool {
        self.header.truncated()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Basic Query Parsing Tests
    // =========================================================================

    #[test]
    fn test_parse_minimal_query() {
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
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,
            0x00, 0x01,             // QTYPE = A (1)
            0x00, 0x01,             // QCLASS = IN (1)
        ];

        let msg = Message::parse(&packet).unwrap();

        assert!(msg.is_query());
        assert!(!msg.is_response());
        assert_eq!(msg.id(), 0x1234);
        assert!(msg.recursion_desired());
        assert!(!msg.truncated());
        assert_eq!(msg.questions.len(), 1);
        assert_eq!(msg.answers.len(), 0);
        assert_eq!(msg.authorities.len(), 0);
        assert_eq!(msg.additionals.len(), 0);

        let q = &msg.questions[0];
        assert_eq!(q.name.to_string(), "example.com.");
        assert_eq!(q.qtype, 1); // A
        assert_eq!(q.qclass, 1); // IN
    }

    #[test]
    fn test_parse_query_multiple_questions() {
        // Query with 2 questions (unusual but valid)
        #[rustfmt::skip]
        let packet = [
            0x00, 0x01,             // ID
            0x00, 0x00,             // Flags
            0x00, 0x02,             // QDCOUNT = 2
            0x00, 0x00,             // ANCOUNT
            0x00, 0x00,             // NSCOUNT
            0x00, 0x00,             // ARCOUNT
            // Question 1: "a.com" A
            0x01, b'a', 0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x01, 0x00, 0x01,
            // Question 2: "b.com" AAAA
            0x01, b'b', 0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x1C, 0x00, 0x01,
        ];

        let msg = Message::parse(&packet).unwrap();

        assert_eq!(msg.questions.len(), 2);
        assert_eq!(msg.questions[0].name.to_string(), "a.com.");
        assert_eq!(msg.questions[0].qtype, 1); // A
        assert_eq!(msg.questions[1].name.to_string(), "b.com.");
        assert_eq!(msg.questions[1].qtype, 28); // AAAA
    }

    #[test]
    fn test_parse_query_root_ns() {
        // Query for root nameservers (. NS IN)
        #[rustfmt::skip]
        let packet = [
            0xAB, 0xCD,             // ID
            0x00, 0x00,             // Flags
            0x00, 0x01,             // QDCOUNT = 1
            0x00, 0x00,             // ANCOUNT
            0x00, 0x00,             // NSCOUNT
            0x00, 0x00,             // ARCOUNT
            0x00,                   // root name
            0x00, 0x02,             // QTYPE = NS
            0x00, 0x01,             // QCLASS = IN
        ];

        let msg = Message::parse(&packet).unwrap();

        assert_eq!(msg.questions[0].name.to_string(), ".");
        assert!(msg.questions[0].name.is_root());
        assert_eq!(msg.questions[0].qtype, 2);
    }

    // =========================================================================
    // Response Parsing Tests
    // =========================================================================

    #[test]
    fn test_parse_response_with_single_answer() {
        // Response to "example.com" A query with one answer
        #[rustfmt::skip]
        let packet = [
            // Header
            0x12, 0x34,             // ID
            0x81, 0x80,             // Flags: QR=1, RD=1, RA=1
            0x00, 0x01,             // QDCOUNT = 1
            0x00, 0x01,             // ANCOUNT = 1
            0x00, 0x00,             // NSCOUNT = 0
            0x00, 0x00,             // ARCOUNT = 0
            // Question
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,
            0x00, 0x01,             // QTYPE = A
            0x00, 0x01,             // QCLASS = IN
            // Answer (using compression pointer)
            0xC0, 0x0C,             // Name: pointer to offset 12
            0x00, 0x01,             // TYPE = A
            0x00, 0x01,             // CLASS = IN
            0x00, 0x00, 0x00, 0x3C, // TTL = 60
            0x00, 0x04,             // RDLENGTH = 4
            0x5D, 0xB8, 0xD8, 0x22, // RDATA = 93.184.216.34
        ];

        let msg = Message::parse(&packet).unwrap();

        assert!(msg.is_response());
        assert!(!msg.is_query());
        assert!(msg.recursion_available());
        assert!(!msg.is_error());

        assert_eq!(msg.questions.len(), 1);
        assert_eq!(msg.answers.len(), 1);

        let ans = &msg.answers[0];
        assert_eq!(ans.name.to_string(), "example.com.");
        assert!(ans.is_a());
        assert_eq!(ans.ttl, 60);
        assert_eq!(ans.as_ipv4(), Some([93, 184, 216, 34]));
    }

    #[test]
    fn test_parse_response_multiple_answers() {
        // Response with multiple A records (round-robin DNS)
        #[rustfmt::skip]
        let packet = [
            0x00, 0x01,             // ID
            0x81, 0x80,             // Flags: response
            0x00, 0x01,             // QDCOUNT = 1
            0x00, 0x02,             // ANCOUNT = 2
            0x00, 0x00,             // NSCOUNT
            0x00, 0x00,             // ARCOUNT
            // Question
            0x03, b'w', b'w', b'w', 0x00,
            0x00, 0x01, 0x00, 0x01,
            // Answer 1
            0xC0, 0x0C,             // pointer to "www."
            0x00, 0x01, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x3C,
            0x00, 0x04,
            0x01, 0x01, 0x01, 0x01, // 1.1.1.1
            // Answer 2
            0xC0, 0x0C,             // pointer to "www."
            0x00, 0x01, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x3C,
            0x00, 0x04,
            0x08, 0x08, 0x08, 0x08, // 8.8.8.8
        ];

        let msg = Message::parse(&packet).unwrap();

        assert_eq!(msg.answers.len(), 2);
        assert_eq!(msg.answers[0].as_ipv4(), Some([1, 1, 1, 1]));
        assert_eq!(msg.answers[1].as_ipv4(), Some([8, 8, 8, 8]));
    }

    #[test]
    fn test_parse_response_with_authority_section() {
        // Response with authority section (NS records)
        #[rustfmt::skip]
        let packet = [
            0x00, 0x01,             // ID
            0x81, 0x80,             // Flags
            0x00, 0x01,             // QDCOUNT = 1
            0x00, 0x00,             // ANCOUNT = 0
            0x00, 0x01,             // NSCOUNT = 1
            0x00, 0x00,             // ARCOUNT = 0
            // Question
            0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x02, 0x00, 0x01, // NS IN
            // Authority
            0xC0, 0x0C,             // com.
            0x00, 0x02,             // TYPE = NS
            0x00, 0x01,             // CLASS = IN
            0x00, 0x00, 0x0E, 0x10, // TTL = 3600
            0x00, 0x04,             // RDLENGTH = 4 (label len + "ns" + null)
            0x02, b'n', b's', 0x00, // "ns."
        ];

        let msg = Message::parse(&packet).unwrap();

        assert_eq!(msg.questions.len(), 1);
        assert_eq!(msg.answers.len(), 0);
        assert_eq!(msg.authorities.len(), 1);
        assert_eq!(msg.authorities[0].rtype, 2); // NS
    }

    #[test]
    fn test_parse_response_with_additional_section() {
        // Response with additional section (glue records)
        #[rustfmt::skip]
        let packet = [
            0x00, 0x01,             // ID
            0x81, 0x80,             // Flags
            0x00, 0x01,             // QDCOUNT = 1
            0x00, 0x00,             // ANCOUNT = 0
            0x00, 0x00,             // NSCOUNT = 0
            0x00, 0x01,             // ARCOUNT = 1
            // Question
            0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x01, 0x00, 0x01,
            // Additional (OPT record for EDNS)
            0x00,                   // root name
            0x00, 0x29,             // TYPE = OPT
            0x10, 0x00,             // CLASS = UDP payload size (4096)
            0x00, 0x00, 0x00, 0x00, // TTL = extended RCODE
            0x00, 0x00,             // RDLENGTH = 0
        ];

        let msg = Message::parse(&packet).unwrap();

        assert_eq!(msg.additionals.len(), 1);
        assert!(msg.additionals[0].is_opt());
    }

    #[test]
    fn test_parse_full_response_all_sections() {
        // Response with question, answer, authority, and additional
        #[rustfmt::skip]
        let packet = [
            0x00, 0x01,             // ID
            0x81, 0x80,             // Flags
            0x00, 0x01,             // QDCOUNT = 1
            0x00, 0x01,             // ANCOUNT = 1
            0x00, 0x01,             // NSCOUNT = 1
            0x00, 0x01,             // ARCOUNT = 1
            // Question: example.com A
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x01, 0x00, 0x01,
            // Answer: A record
            0xC0, 0x0C,
            0x00, 0x01, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x3C,
            0x00, 0x04,
            0x01, 0x02, 0x03, 0x04,
            // Authority: NS record
            0xC0, 0x0C,
            0x00, 0x02, 0x00, 0x01,
            0x00, 0x00, 0x0E, 0x10,
            0x00, 0x04,             // RDLENGTH = 4 (label len + "ns" + null)
            0x02, b'n', b's', 0x00,
            // Additional: OPT
            0x00,
            0x00, 0x29,
            0x10, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];

        let msg = Message::parse(&packet).unwrap();

        assert_eq!(msg.questions.len(), 1);
        assert_eq!(msg.answers.len(), 1);
        assert_eq!(msg.authorities.len(), 1);
        assert_eq!(msg.additionals.len(), 1);
    }

    // =========================================================================
    // Response Code Tests
    // =========================================================================

    #[test]
    fn test_parse_nxdomain_response() {
        // NXDOMAIN response (name does not exist)
        #[rustfmt::skip]
        let packet = [
            0x00, 0x01,             // ID
            0x81, 0x83,             // Flags: QR=1, RD=1, RA=1, RCODE=3 (NXDOMAIN)
            0x00, 0x01,             // QDCOUNT = 1
            0x00, 0x00,             // ANCOUNT = 0
            0x00, 0x00,             // NSCOUNT = 0
            0x00, 0x00,             // ARCOUNT = 0
            0x07, b'i', b'n', b'v', b'a', b'l', b'i', b'd', 0x00,
            0x00, 0x01, 0x00, 0x01,
        ];

        let msg = Message::parse(&packet).unwrap();

        assert!(msg.is_response());
        assert!(msg.is_error());
    }

    #[test]
    fn test_parse_servfail_response() {
        // SERVFAIL response
        #[rustfmt::skip]
        let packet = [
            0x00, 0x01,
            0x81, 0x82,             // RCODE=2 (SERVFAIL)
            0x00, 0x01,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,
            0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x01, 0x00, 0x01,
        ];

        let msg = Message::parse(&packet).unwrap();

        assert!(msg.is_error());
    }

    // =========================================================================
    // Header Flag Tests
    // =========================================================================

    #[test]
    fn test_parse_truncated_response() {
        // Response with TC (truncated) flag set
        #[rustfmt::skip]
        let packet = [
            0x00, 0x01,
            0x82, 0x00,             // Flags: QR=1, TC=1
            0x00, 0x01,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,
            0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x01, 0x00, 0x01,
        ];

        let msg = Message::parse(&packet).unwrap();

        assert!(msg.truncated());
    }

    // =========================================================================
    // Empty Sections Tests
    // =========================================================================

    #[test]
    fn test_parse_header_only_all_zeros() {
        // Header with all counts = 0
        #[rustfmt::skip]
        let packet = [
            0x00, 0x00,             // ID
            0x00, 0x00,             // Flags
            0x00, 0x00,             // QDCOUNT = 0
            0x00, 0x00,             // ANCOUNT = 0
            0x00, 0x00,             // NSCOUNT = 0
            0x00, 0x00,             // ARCOUNT = 0
        ];

        let msg = Message::parse(&packet).unwrap();

        assert!(msg.questions.is_empty());
        assert!(msg.answers.is_empty());
        assert!(msg.authorities.is_empty());
        assert!(msg.additionals.is_empty());
    }

    #[test]
    fn test_parse_response_only_answers() {
        // Response with answers but no question (unusual but possible)
        #[rustfmt::skip]
        let packet = [
            0x00, 0x01,
            0x80, 0x00,             // QR=1
            0x00, 0x00,             // QDCOUNT = 0
            0x00, 0x01,             // ANCOUNT = 1
            0x00, 0x00,             // NSCOUNT
            0x00, 0x00,             // ARCOUNT
            // Answer
            0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x01, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x3C,
            0x00, 0x04,
            0x01, 0x02, 0x03, 0x04,
        ];

        let msg = Message::parse(&packet).unwrap();

        assert!(msg.questions.is_empty());
        assert_eq!(msg.answers.len(), 1);
    }

    // =========================================================================
    // Buffer Boundary Error Tests
    // =========================================================================

    #[test]
    fn test_empty_packet() {
        let result = Message::parse(&[]);
        assert!(
            matches!(result, Err(ParseError::BufferTooShort)),
            "Expected BufferTooShort, got {:?}",
            result
        );
    }

    #[test]
    fn test_truncated_header() {
        // Only 8 bytes, header needs 12
        let result = Message::parse(&[0; 8]);
        assert!(
            matches!(result, Err(ParseError::BufferTooShort)),
            "Expected BufferTooShort, got {:?}",
            result
        );
    }

    #[test]
    fn test_truncated_header_11_bytes() {
        let result = Message::parse(&[0; 11]);
        assert!(
            matches!(result, Err(ParseError::BufferTooShort)),
            "Expected BufferTooShort, got {:?}",
            result
        );
    }

    // =========================================================================
    // Record Count Mismatch Tests
    // =========================================================================

    #[test]
    fn test_qdcount_exceeds_data() {
        // QDCOUNT=5 but only 1 question present
        #[rustfmt::skip]
        let packet = [
            0x00, 0x01,
            0x00, 0x00,
            0x00, 0x05,             // QDCOUNT = 5
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,
            // Only 1 question
            0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x01, 0x00, 0x01,
        ];

        let result = Message::parse(&packet);
        assert!(
            matches!(
                result,
                Err(ParseError::BufferTooShort | ParseError::InvalidRecordCount)
            ),
            "Expected BufferTooShort or InvalidRecordCount, got {:?}",
            result
        );
    }

    #[test]
    fn test_ancount_exceeds_data() {
        // ANCOUNT=3 but only 1 answer present
        #[rustfmt::skip]
        let packet = [
            0x00, 0x01,
            0x80, 0x00,
            0x00, 0x00,
            0x00, 0x03,             // ANCOUNT = 3
            0x00, 0x00,
            0x00, 0x00,
            // Only 1 answer
            0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x01, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x3C,
            0x00, 0x04,
            0x01, 0x02, 0x03, 0x04,
        ];

        let result = Message::parse(&packet);
        assert!(
            matches!(
                result,
                Err(ParseError::BufferTooShort | ParseError::InvalidRecordCount)
            ),
            "Expected BufferTooShort or InvalidRecordCount, got {:?}",
            result
        );
    }

    #[test]
    fn test_header_with_qdcount_but_no_questions() {
        // QDCOUNT=1 but no question section
        #[rustfmt::skip]
        let packet = [
            0x00, 0x01,
            0x00, 0x00,
            0x00, 0x01,             // QDCOUNT = 1
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,
            // No question follows
        ];

        let result = Message::parse(&packet);
        assert!(
            matches!(
                result,
                Err(ParseError::BufferTooShort | ParseError::InvalidRecordCount)
            ),
            "Expected BufferTooShort or InvalidRecordCount, got {:?}",
            result
        );
    }

    // =========================================================================
    // Compression Pointer Tests
    // =========================================================================

    #[test]
    fn test_response_with_compression_pointers() {
        // Multiple records using compression pointers to the same name
        #[rustfmt::skip]
        let packet = [
            0x00, 0x01,
            0x81, 0x80,
            0x00, 0x01,             // QDCOUNT = 1
            0x00, 0x02,             // ANCOUNT = 2
            0x00, 0x00,
            0x00, 0x00,
            // Question: example.com at offset 12
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x01, 0x00, 0x01,
            // Answer 1: uses pointer to offset 12
            0xC0, 0x0C,
            0x00, 0x01, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x3C,
            0x00, 0x04,
            0x01, 0x01, 0x01, 0x01,
            // Answer 2: also uses pointer to offset 12
            0xC0, 0x0C,
            0x00, 0x01, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x3C,
            0x00, 0x04,
            0x02, 0x02, 0x02, 0x02,
        ];

        let msg = Message::parse(&packet).unwrap();

        assert_eq!(msg.answers.len(), 2);
        assert_eq!(msg.answers[0].name.to_string(), "example.com.");
        assert_eq!(msg.answers[1].name.to_string(), "example.com.");
    }

    // =========================================================================
    // Name Error Propagation Tests
    // =========================================================================

    #[test]
    fn test_compression_pointer_loop_in_question() {
        // Question with self-referential compression pointer
        #[rustfmt::skip]
        let packet = [
            0x00, 0x01,
            0x00, 0x00,
            0x00, 0x01,             // QDCOUNT = 1
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,
            0xC0, 0x0C,             // Self-referential pointer
            0x00, 0x01, 0x00, 0x01,
        ];

        let result = Message::parse(&packet);
        assert!(
            matches!(result, Err(ParseError::CompressionPointerLoop)),
            "Expected CompressionPointerLoop, got {:?}",
            result
        );
    }

    #[test]
    fn test_compression_pointer_loop_in_answer() {
        // Valid question, but answer has compression pointer loop
        #[rustfmt::skip]
        let packet = [
            0x00, 0x01,
            0x80, 0x00,
            0x00, 0x01,
            0x00, 0x01,             // ANCOUNT = 1
            0x00, 0x00,
            0x00, 0x00,
            // Valid question
            0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x01, 0x00, 0x01,
            // Answer with self-referential name
            0xC0, 0x15,             // Points to itself (offset 21)
            0x00, 0x01, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x3C,
            0x00, 0x04,
            0x01, 0x02, 0x03, 0x04,
        ];

        let result = Message::parse(&packet);
        assert!(
            matches!(
                result,
                Err(ParseError::CompressionPointerLoop | ParseError::CompressionPointerForward)
            ),
            "Expected compression pointer error, got {:?}",
            result
        );
    }

    // =========================================================================
    // RDLENGTH Error Propagation Tests
    // =========================================================================

    #[test]
    fn test_rdlength_overflow_in_answer() {
        // Answer with RDLENGTH that exceeds remaining packet
        #[rustfmt::skip]
        let packet = [
            0x00, 0x01,
            0x80, 0x00,
            0x00, 0x00,
            0x00, 0x01,             // ANCOUNT = 1
            0x00, 0x00,
            0x00, 0x00,
            // Answer with huge RDLENGTH
            0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x01, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x3C,
            0x00, 0xFF,             // RDLENGTH = 255
            0x01, 0x02, 0x03, 0x04, // Only 4 bytes
        ];

        let result = Message::parse(&packet);
        assert!(
            matches!(result, Err(ParseError::RdataOverflow)),
            "Expected RdataOverflow, got {:?}",
            result
        );
    }

    #[test]
    fn test_invalid_a_record_length_in_answer() {
        // A record with wrong RDLENGTH
        #[rustfmt::skip]
        let packet = [
            0x00, 0x01,
            0x80, 0x00,
            0x00, 0x00,
            0x00, 0x01,
            0x00, 0x00,
            0x00, 0x00,
            // A record with RDLENGTH = 3
            0x00,
            0x00, 0x01, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x3C,
            0x00, 0x03,
            0x01, 0x02, 0x03,
        ];

        let result = Message::parse(&packet);
        assert!(
            matches!(result, Err(ParseError::InvalidRdataLength)),
            "Expected InvalidRdataLength, got {:?}",
            result
        );
    }

    // =========================================================================
    // Extra Data Tests
    // =========================================================================

    #[test]
    fn test_extra_data_after_message() {
        // Valid message followed by extra garbage bytes
        // Parser should succeed (DNS allows trailing data in some contexts)
        #[rustfmt::skip]
        let packet = [
            0x00, 0x01,
            0x00, 0x00,
            0x00, 0x01,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,
            0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x01, 0x00, 0x01,
            // Extra garbage
            0xDE, 0xAD, 0xBE, 0xEF,
        ];

        // Parser may succeed or fail depending on implementation choice
        // Either is acceptable, but it must not panic
        let _ = Message::parse(&packet);
    }
}
