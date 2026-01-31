use alloc::vec::Vec;

use crate::question::{Question, QuestionOwned};
use crate::rr::{ResourceRecord, ResourceRecordOwned};
use crate::{Header, ParseError, QR};

/// A zero-copy DNS message with lazy parsing.
///
/// DNS messages consist of a header followed by four sections:
/// - Question section: what is being asked
/// - Answer section: resource records answering the question
/// - Authority section: resource records pointing to authoritative name servers
/// - Additional section: resource records with additional information
///
/// This type only parses the header on construction. The sections are parsed
/// lazily when you iterate over them, yielding `Result` items to handle
/// per-record parsing errors.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Message<'a> {
    /// The DNS header containing flags and section counts.
    pub header: Header,
    /// The complete packet data.
    packet: &'a [u8],
}

impl<'a> Message<'a> {
    /// Parse and validate a DNS message from raw bytes
    ///
    /// This validates the entire packet including all sections (questions,
    /// answers, authorities, additionals). If validation succeeds, the
    /// iterators are guaranteed to yield valid records.
    pub fn parse(packet: &'a [u8]) -> Result<Self, ParseError> {
        let (header, _remainder) = Header::parse(packet)?;

        let mut offset = Header::SIZE;
        for _ in 0..header.qdcount() {
            let (_, next_offset) = Question::parse(packet, offset)?;
            offset = next_offset;
        }

        for _ in 0..header.ancount() {
            let (_, next_offset) = ResourceRecord::parse(packet, offset)?;
            offset = next_offset;
        }

        for _ in 0..header.nscount() {
            let (_, next_offset) = ResourceRecord::parse(packet, offset)?;
            offset = next_offset;
        }

        for _ in 0..header.arcount() {
            let (_, next_offset) = ResourceRecord::parse(packet, offset)?;
            offset = next_offset;
        }

        Ok(Self { header, packet })
    }

    /// Returns an iterator over the questions in this message.
    ///
    /// Each item is a `Result<Question<'a>, ParseError>` to handle parsing errors
    /// that may occur during iteration.
    pub fn questions(&self) -> QuestionIter<'a> {
        QuestionIter {
            packet: self.packet,
            offset: Header::SIZE,
            remaining: self.header.qdcount(),
            failed: false,
        }
    }

    /// Returns an iterator over the answers in this message.
    ///
    /// Each item is a `Result<ResourceRecord<'a>, ParseError>`.
    ///
    /// **Note:** This skips over the question section first. If the questions
    /// are malformed, this iterator will yield errors.
    pub fn answers(&self) -> ResourceRecordIter<'a> {
        // Skip past questions to find where answers start
        let mut offset = Header::SIZE;
        let mut questions_remaining = self.header.qdcount();

        // Skip questions
        while questions_remaining > 0 {
            match Question::parse(self.packet, offset) {
                Ok((_, next_offset)) => {
                    offset = next_offset;
                    questions_remaining -= 1;
                }
                Err(_) => {
                    // Questions failed to parse; iterator will return error on first call
                    return ResourceRecordIter {
                        packet: self.packet,
                        offset,
                        remaining: self.header.ancount(),
                        failed: true,
                    };
                }
            }
        }

        ResourceRecordIter {
            packet: self.packet,
            offset,
            remaining: self.header.ancount(),
            failed: false,
        }
    }

    /// Returns an iterator over the authority records in this message.
    ///
    /// Each item is a `Result<ResourceRecord<'a>, ParseError>`.
    ///
    /// **Note:** This skips over the question and answer sections first.
    pub fn authorities(&self) -> ResourceRecordIter<'a> {
        // Skip past questions and answers
        let mut offset = Header::SIZE;

        // Skip questions
        for _ in 0..self.header.qdcount() {
            match Question::parse(self.packet, offset) {
                Ok((_, next_offset)) => offset = next_offset,
                Err(_) => {
                    return ResourceRecordIter {
                        packet: self.packet,
                        offset,
                        remaining: self.header.nscount(),
                        failed: true,
                    };
                }
            }
        }

        // Skip answers
        for _ in 0..self.header.ancount() {
            match ResourceRecord::parse(self.packet, offset) {
                Ok((_, next_offset)) => offset = next_offset,
                Err(_) => {
                    return ResourceRecordIter {
                        packet: self.packet,
                        offset,
                        remaining: self.header.nscount(),
                        failed: true,
                    };
                }
            }
        }

        ResourceRecordIter {
            packet: self.packet,
            offset,
            remaining: self.header.nscount(),
            failed: false,
        }
    }

    /// Returns an iterator over the additional records in this message.
    ///
    /// Each item is a `Result<ResourceRecord<'a>, ParseError>`.
    ///
    /// **Note:** This skips over the question, answer, and authority sections first.
    pub fn additionals(&self) -> ResourceRecordIter<'a> {
        // Skip past questions, answers, and authorities
        let mut offset = Header::SIZE;

        // Skip questions
        for _ in 0..self.header.qdcount() {
            match Question::parse(self.packet, offset) {
                Ok((_, next_offset)) => offset = next_offset,
                Err(_) => {
                    return ResourceRecordIter {
                        packet: self.packet,
                        offset,
                        remaining: self.header.arcount(),
                        failed: true,
                    };
                }
            }
        }

        // Skip answers
        for _ in 0..self.header.ancount() {
            match ResourceRecord::parse(self.packet, offset) {
                Ok((_, next_offset)) => offset = next_offset,
                Err(_) => {
                    return ResourceRecordIter {
                        packet: self.packet,
                        offset,
                        remaining: self.header.arcount(),
                        failed: true,
                    };
                }
            }
        }

        // Skip authorities
        for _ in 0..self.header.nscount() {
            match ResourceRecord::parse(self.packet, offset) {
                Ok((_, next_offset)) => offset = next_offset,
                Err(_) => {
                    return ResourceRecordIter {
                        packet: self.packet,
                        offset,
                        remaining: self.header.arcount(),
                        failed: true,
                    };
                }
            }
        }

        ResourceRecordIter {
            packet: self.packet,
            offset,
            remaining: self.header.arcount(),
            failed: false,
        }
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

    /// Returns the raw packet data.
    #[inline]
    pub fn packet(&self) -> &'a [u8] {
        self.packet
    }
}

impl<'a> Message<'a> {
    /// Converts this borrowed message to an owned [`MessageOwned`].
    ///
    /// This parses and allocates memory for all sections. Since `Message::parse`
    /// validates the entire packet upfront, this should not fail for a validly
    /// parsed message.
    pub fn into_owned(self) -> Result<MessageOwned, ParseError> {
        let questions: Result<Vec<_>, _> = self
            .questions()
            .map(|r| r.map(|q| q.into_owned()))
            .collect();
        let answers: Result<Vec<_>, _> = self
            .answers()
            .map(|r| r.map(|rr| rr.into_owned()))
            .collect();
        let authorities: Result<Vec<_>, _> = self
            .authorities()
            .map(|r| r.map(|rr| rr.into_owned()))
            .collect();
        let additionals: Result<Vec<_>, _> = self
            .additionals()
            .map(|r| r.map(|rr| rr.into_owned()))
            .collect();

        Ok(MessageOwned {
            header: self.header,
            questions: questions?,
            answers: answers?,
            authorities: authorities?,
            additionals: additionals?,
        })
    }
}

/// Iterator over the questions in a DNS message.
///
/// Each item is a `Result<Question<'a>, ParseError>` to handle parsing errors.
#[derive(Debug, Clone)]
pub struct QuestionIter<'a> {
    packet: &'a [u8],
    offset: usize,
    remaining: u16,
    failed: bool,
}

impl<'a> Iterator for QuestionIter<'a> {
    type Item = Result<Question<'a>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 || self.failed {
            return None;
        }

        match Question::parse(self.packet, self.offset) {
            Ok((question, next_offset)) => {
                self.offset = next_offset;
                self.remaining -= 1;
                Some(Ok(question))
            }
            Err(e) => {
                self.failed = true;
                self.remaining = 0;
                Some(Err(e))
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.remaining as usize;
        (0, Some(remaining))
    }
}

/// Iterator over resource records in a DNS message section.
///
/// Each item is a `Result<ResourceRecord<'a>, ParseError>` to handle parsing errors.
#[derive(Debug, Clone)]
pub struct ResourceRecordIter<'a> {
    packet: &'a [u8],
    offset: usize,
    remaining: u16,
    failed: bool,
}

impl<'a> Iterator for ResourceRecordIter<'a> {
    type Item = Result<ResourceRecord<'a>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }

        // If we failed during skipping, report error immediately
        if self.failed {
            self.remaining = 0;
            return Some(Err(ParseError::BufferTooShort));
        }

        match ResourceRecord::parse(self.packet, self.offset) {
            Ok((rr, next_offset)) => {
                self.offset = next_offset;
                self.remaining -= 1;
                Some(Ok(rr))
            }
            Err(e) => {
                self.failed = true;
                self.remaining = 0;
                Some(Err(e))
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.remaining as usize;
        (0, Some(remaining))
    }
}

/// An owned DNS message with all sections parsed.
///
/// DNS messages consist of a header followed by four sections:
/// - Question section: what is being asked
/// - Answer section: resource records answering the question
/// - Authority section: resource records pointing to authoritative name servers
/// - Additional section: resource records with additional information
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageOwned {
    /// The DNS header containing flags and section counts.
    pub header: Header,
    /// The question section.
    ///
    /// Typically contains one question, but the protocol allows multiple.
    pub questions: Vec<QuestionOwned>,
    /// The answer section.
    ///
    /// Contains resource records that answer the question(s).
    pub answers: Vec<ResourceRecordOwned>,
    /// The authority section.
    ///
    /// Contains resource records pointing to authoritative name servers.
    pub authorities: Vec<ResourceRecordOwned>,
    /// The additional section.
    ///
    /// Contains resource records with additional helpful information,
    /// such as A records for name servers listed in the authority section.
    pub additionals: Vec<ResourceRecordOwned>,
}

impl MessageOwned {
    /// Parse a DNS message from raw packet data.
    ///
    /// This eagerly parses all sections, allocating memory for each record.
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        let msg = Message::parse(data)?;
        msg.into_owned()
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

        // Test lazy iteration
        let questions: Vec<_> = msg.questions().collect();
        assert_eq!(questions.len(), 1);
        let q = questions[0].as_ref().unwrap();
        assert_eq!(q.name.to_string(), "example.com.");
        assert_eq!(q.qtype, 1); // A
        assert_eq!(q.qclass, 1); // IN

        assert_eq!(msg.answers().count(), 0);
        assert_eq!(msg.authorities().count(), 0);
        assert_eq!(msg.additionals().count(), 0);
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

        let questions: Vec<_> = msg.questions().collect();
        assert_eq!(questions.len(), 2);
        assert_eq!(questions[0].as_ref().unwrap().name.to_string(), "a.com.");
        assert_eq!(questions[0].as_ref().unwrap().qtype, 1); // A
        assert_eq!(questions[1].as_ref().unwrap().name.to_string(), "b.com.");
        assert_eq!(questions[1].as_ref().unwrap().qtype, 28); // AAAA
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

        let q = msg.questions().next().unwrap().unwrap();
        assert_eq!(q.name.to_string(), ".");
        assert!(q.name.is_root());
        assert_eq!(q.qtype, 2);
    }

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

        assert_eq!(msg.questions().count(), 1);

        let answers: Vec<_> = msg.answers().collect();
        assert_eq!(answers.len(), 1);

        let ans = answers[0].as_ref().unwrap();
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

        let answers: Vec<_> = msg.answers().collect();
        assert_eq!(answers.len(), 2);
        assert_eq!(answers[0].as_ref().unwrap().as_ipv4(), Some([1, 1, 1, 1]));
        assert_eq!(answers[1].as_ref().unwrap().as_ipv4(), Some([8, 8, 8, 8]));
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

        assert_eq!(msg.questions().count(), 1);
        assert_eq!(msg.answers().count(), 0);

        let authorities: Vec<_> = msg.authorities().collect();
        assert_eq!(authorities.len(), 1);
        assert_eq!(authorities[0].as_ref().unwrap().rtype, 2); // NS
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

        let additionals: Vec<_> = msg.additionals().collect();
        assert_eq!(additionals.len(), 1);
        assert!(additionals[0].as_ref().unwrap().is_opt());
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

        assert_eq!(msg.questions().count(), 1);
        assert_eq!(msg.answers().count(), 1);
        assert_eq!(msg.authorities().count(), 1);
        assert_eq!(msg.additionals().count(), 1);
    }

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

        assert_eq!(msg.questions().count(), 0);
        assert_eq!(msg.answers().count(), 0);
        assert_eq!(msg.authorities().count(), 0);
        assert_eq!(msg.additionals().count(), 0);
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

        assert_eq!(msg.questions().count(), 0);
        assert_eq!(msg.answers().count(), 1);
    }

    #[test]
    fn test_empty_packet() {
        let result = Message::parse(&[]);
        assert!(
            matches!(result, Err(ParseError::BufferTooShort)),
            "Expected BufferTooShort, got {result:?}"
        );
    }

    #[test]
    fn test_truncated_header() {
        // Only 8 bytes, header needs 12
        let result = Message::parse(&[0; 8]);
        assert!(
            matches!(result, Err(ParseError::BufferTooShort)),
            "Expected BufferTooShort, got {result:?}"
        );
    }

    #[test]
    fn test_truncated_header_11_bytes() {
        let result = Message::parse(&[0; 11]);
        assert!(
            matches!(result, Err(ParseError::BufferTooShort)),
            "Expected BufferTooShort, got {result:?}"
        );
    }

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

        // Parse validates everything upfront, should fail
        let result = Message::parse(&packet);
        assert!(result.is_err(), "Expected error for QDCOUNT mismatch");
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

        // Parse validates everything upfront, should fail
        let result = Message::parse(&packet);
        assert!(result.is_err(), "Expected error for missing questions");
    }

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

        let answers: Vec<_> = msg.answers().collect();
        assert_eq!(answers.len(), 2);
        assert_eq!(
            answers[0].as_ref().unwrap().name.to_string(),
            "example.com."
        );
        assert_eq!(
            answers[1].as_ref().unwrap().name.to_string(),
            "example.com."
        );
    }

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

        // Parse validates everything upfront, should detect compression pointer loop
        let result = Message::parse(&packet);
        assert!(matches!(result, Err(ParseError::CompressionPointerLoop)));
    }

    #[test]
    fn test_message_into_owned() {
        #[rustfmt::skip]
        let packet = [
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
            // Answer
            0xC0, 0x0C,
            0x00, 0x01, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x3C,
            0x00, 0x04,
            0x5D, 0xB8, 0xD8, 0x22,
        ];

        let msg = Message::parse(&packet).unwrap();
        let owned = msg.into_owned().unwrap();

        assert!(owned.is_response());
        assert_eq!(owned.id(), 0x1234);
        assert_eq!(owned.questions.len(), 1);
        assert_eq!(owned.questions[0].name.to_string(), "example.com.");
        assert_eq!(owned.answers.len(), 1);
        assert_eq!(owned.answers[0].as_ipv4(), Some([93, 184, 216, 34]));
    }

    #[test]
    fn test_message_owned_parse() {
        #[rustfmt::skip]
        let packet = [
            0x12, 0x34,
            0x01, 0x00,
            0x00, 0x01,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,
            0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x01, 0x00, 0x01,
        ];

        let msg = MessageOwned::parse(&packet).unwrap();

        assert!(msg.is_query());
        assert_eq!(msg.questions.len(), 1);
        assert_eq!(msg.questions[0].name.to_string(), "com.");
    }

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
