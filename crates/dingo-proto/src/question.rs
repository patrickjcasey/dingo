use crate::ParseError;
use crate::name::{Name, NameOwned};
#[allow(unused, reason = "make supporting no_std easier")]
use alloc::string::ToString;

/// A zero-copy DNS question entry.
///
/// The question section contains the domain name being queried, the query type,
/// and the query class. This borrowed variant references the original packet data.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Question<'a> {
    /// The domain name being queried (zero-copy reference to packet).
    pub name: Name<'a>,
    /// The query type (QTYPE).
    ///
    /// Common values:
    /// - 1 = A (IPv4 address)
    /// - 2 = NS (name server)
    /// - 5 = CNAME (canonical name)
    /// - 15 = MX (mail exchange)
    /// - 16 = TXT (text)
    /// - 28 = AAAA (IPv6 address)
    /// - 255 = ANY (all records)
    pub qtype: u16,
    /// The query class (QCLASS).
    ///
    /// Common values:
    /// - 1 = IN (Internet)
    /// - 255 = ANY (any class)
    pub qclass: u16,
}

impl<'a> Question<'a> {
    /// Parse a question from the packet data starting at the given offset.
    ///
    /// Returns the parsed question and the offset immediately after the question.
    pub fn parse(packet: &'a [u8], offset: usize) -> Result<(Self, usize), ParseError> {
        let (name, pos) = Name::parse(packet, offset)?;

        // QTYPE and QCLASS form a fixed 4-byte block; one bounds check covers both.
        if pos + 4 > packet.len() {
            return Err(ParseError::BufferTooShort);
        }
        let qtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        let qclass = u16::from_be_bytes([packet[pos + 2], packet[pos + 3]]);

        let question = Self {
            name,
            qtype,
            qclass,
        };
        Ok((question, pos + 4))
    }

    /// Returns true if this is a query for any record type (QTYPE=255).
    #[inline]
    pub fn is_any_type(&self) -> bool {
        self.qtype == 255
    }

    /// Returns true if this is a query for any class (QCLASS=255).
    #[inline]
    pub fn is_any_class(&self) -> bool {
        self.qclass == 255
    }

    /// Converts this borrowed question to an owned [`QuestionOwned`].
    pub fn into_owned(self) -> QuestionOwned {
        self.into()
    }
}

impl<'a> From<Question<'a>> for QuestionOwned {
    fn from(q: Question<'a>) -> Self {
        QuestionOwned {
            name: q.name.into_owned(),
            qtype: q.qtype,
            qclass: q.qclass,
        }
    }
}

/// An owned DNS question entry.
///
/// The question section contains the domain name being queried, the query type,
/// and the query class. This owned variant stores the name in allocated memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuestionOwned {
    /// The domain name being queried.
    pub name: NameOwned,
    /// The query type (QTYPE).
    ///
    /// Common values:
    /// - 1 = A (IPv4 address)
    /// - 2 = NS (name server)
    /// - 5 = CNAME (canonical name)
    /// - 15 = MX (mail exchange)
    /// - 16 = TXT (text)
    /// - 28 = AAAA (IPv6 address)
    /// - 255 = ANY (all records)
    pub qtype: u16,
    /// The query class (QCLASS).
    ///
    /// Common values:
    /// - 1 = IN (Internet)
    /// - 255 = ANY (any class)
    pub qclass: u16,
}

impl QuestionOwned {
    /// Parse a question from the packet data starting at the given offset.
    ///
    /// Returns the parsed question and the offset immediately after the question.
    /// This immediately converts to owned, allocating memory for the name.
    pub fn parse(packet: &[u8], offset: usize) -> Result<(Self, usize), ParseError> {
        let (question, end) = Question::parse(packet, offset)?;
        Ok((question.into(), end))
    }

    /// Returns true if this is a query for any record type (QTYPE=255).
    #[inline]
    pub fn is_any_type(&self) -> bool {
        self.qtype == 255
    }

    /// Returns true if this is a query for any class (QCLASS=255).
    #[inline]
    pub fn is_any_class(&self) -> bool {
        self.qclass == 255
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn test_parse_a_record_question() {
        // Question for "example.com" A record, class IN
        #[rustfmt::skip]
        let data = [
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,       // end of name
            0x00, 0x01, // QTYPE = A (1)
            0x00, 0x01, // QCLASS = IN (1)
        ];

        let (question, end_offset) = Question::parse(&data, 0).unwrap();

        assert_eq!(question.name.to_string(), "example.com.");
        assert_eq!(question.qtype, 1); // A
        assert_eq!(question.qclass, 1); // IN
        assert_eq!(end_offset, data.len()); // 13 (name) + 2 (qtype) + 2 (qclass) = 17
    }

    #[test]
    fn test_parse_aaaa_record_question() {
        // Question for "ipv6.example.com" AAAA record
        #[rustfmt::skip]
        let data = [
            0x04, b'i', b'p', b'v', b'6',
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,
            0x00, 0x1C, // QTYPE = AAAA (28)
            0x00, 0x01, // QCLASS = IN (1)
        ];

        let (question, end_offset) = Question::parse(&data, 0).unwrap();

        assert_eq!(question.qtype, 28); // AAAA
        assert_eq!(question.qclass, 1);
        assert_eq!(end_offset, data.len());
    }

    #[test]
    fn test_parse_mx_record_question() {
        // Question for MX record
        #[rustfmt::skip]
        let data = [
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,
            0x00, 0x0F, // QTYPE = MX (15)
            0x00, 0x01, // QCLASS = IN
        ];

        let (question, end_offset) = Question::parse(&data, 0).unwrap();

        assert_eq!(question.qtype, 15); // MX
        assert_eq!(end_offset, data.len());
    }

    #[test]
    fn test_parse_any_type_question() {
        // Question with QTYPE=ANY (255)
        #[rustfmt::skip]
        let data = [
            0x03, b'c', b'o', b'm',
            0x00,
            0x00, 0xFF, // QTYPE = ANY (255)
            0x00, 0x01, // QCLASS = IN
        ];

        let (question, end_offset) = Question::parse(&data, 0).unwrap();

        assert_eq!(question.qtype, 255);
        assert!(question.is_any_type());
        assert_eq!(end_offset, data.len());
    }

    #[test]
    fn test_parse_any_class_question() {
        // Question with QCLASS=ANY (255)
        #[rustfmt::skip]
        let data = [
            0x03, b'c', b'o', b'm',
            0x00,
            0x00, 0x01, // QTYPE = A
            0x00, 0xFF, // QCLASS = ANY (255)
        ];

        let (question, end_offset) = Question::parse(&data, 0).unwrap();

        assert_eq!(question.qclass, 255);
        assert!(question.is_any_class());
        assert_eq!(end_offset, data.len());
    }

    #[test]
    fn test_parse_root_domain_question() {
        // Question for the root domain "."
        #[rustfmt::skip]
        let data = [
            0x00,       // root domain (empty name)
            0x00, 0x02, // QTYPE = NS
            0x00, 0x01, // QCLASS = IN
        ];

        let (question, end_offset) = Question::parse(&data, 0).unwrap();

        assert_eq!(question.name.to_string(), ".");
        assert!(question.name.is_root());
        assert_eq!(question.qtype, 2); // NS
        assert_eq!(end_offset, data.len());
    }

    #[test]
    fn test_parse_question_at_offset() {
        // Question section typically starts at offset 12 (after header)
        #[rustfmt::skip]
        let data = [
            // Fake header (12 bytes)
            0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // Question at offset 12
            0x03, b'w', b'w', b'w',
            0x00,
            0x00, 0x01, // QTYPE = A
            0x00, 0x01, // QCLASS = IN
        ];

        let (question, end_offset) = Question::parse(&data, 12).unwrap();

        assert_eq!(question.name.to_string(), "www.");
        assert_eq!(end_offset, data.len()); // 12 (header) + 5 (name) + 4 (qtype+qclass) = 21
    }

    #[test]
    fn test_parse_question_with_compression_pointer() {
        // Question using a compression pointer to an earlier name
        #[rustfmt::skip]
        let data = [
            // "example.com." at offset 0
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,
            // Question at offset 13 using pointer
            0xC0, 0x00, // pointer to offset 0
            0x00, 0x01, // QTYPE = A
            0x00, 0x01, // QCLASS = IN
        ];

        // With the offset-based API, pass the full packet and the offset
        let (question, end_offset) = Question::parse(&data, 13).unwrap();

        assert_eq!(question.name.to_string(), "example.com.");
        assert_eq!(end_offset, data.len()); // 13 + 2 (pointer) + 4 (qtype+qclass) = 19
    }

    #[test]
    fn test_parse_question_with_partial_compression() {
        // Question for "www.example.com." using partial compression
        #[rustfmt::skip]
        let data = [
            // "example.com." at offset 0
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,
            // Question at offset 13: "www" + pointer to example.com
            0x03, b'w', b'w', b'w',
            0xC0, 0x00, // pointer to offset 0
            0x00, 0x01, // QTYPE = A
            0x00, 0x01, // QCLASS = IN
        ];

        // With the offset-based API, pass the full packet and the offset
        let (question, end_offset) = Question::parse(&data, 13).unwrap();

        assert_eq!(question.name.to_string(), "www.example.com.");
        assert_eq!(end_offset, data.len()); // 13 + 4 (www) + 2 (pointer) + 4 (qtype+qclass) = 23
    }

    #[test]
    fn test_parse_truncated_before_qtype() {
        // Buffer ends before QTYPE can be read
        let data = [0x03, b'c', b'o', b'm', 0x00]; // name only, no qtype/qclass

        let result = Question::parse(&data, 0);
        assert!(
            matches!(result, Err(ParseError::BufferTooShort)),
            "Expected BufferTooShort, got {result:?}"
        );
    }

    #[test]
    fn test_parse_truncated_before_qclass() {
        // Buffer ends after QTYPE but before QCLASS
        #[rustfmt::skip]
        let data = [
            0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x01, // QTYPE only
        ];

        let result = Question::parse(&data, 0);
        assert!(
            matches!(result, Err(ParseError::BufferTooShort)),
            "Expected BufferTooShort, got {result:?}"
        );
    }

    #[test]
    fn test_parse_truncated_qclass() {
        // QCLASS is only 1 byte instead of 2
        #[rustfmt::skip]
        let data = [
            0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x01, // QTYPE
            0x00,       // partial QCLASS
        ];

        let result = Question::parse(&data, 0);
        assert!(
            matches!(result, Err(ParseError::BufferTooShort)),
            "Expected BufferTooShort, got {result:?}"
        );
    }

    #[test]
    fn test_parse_question_empty_buffer() {
        let result = Question::parse(&[], 0);
        assert!(
            matches!(result, Err(ParseError::BufferTooShort)),
            "Expected BufferTooShort, got {result:?}"
        );
    }

    #[test]
    fn test_parse_question_invalid_name_propagates_error() {
        // If the name parsing fails, the error should propagate
        let data = [
            0xC0, 0x00, // Self-referential pointer (invalid)
            0x00, 0x01, // QTYPE
            0x00, 0x01, // QCLASS
        ];

        let result = Question::parse(&data, 0);
        assert!(
            matches!(result, Err(ParseError::CompressionPointerLoop)),
            "Expected CompressionPointerLoop to propagate, got {result:?}"
        );
    }

    #[test]
    fn test_parse_txt_question() {
        #[rustfmt::skip]
        let data = [
            0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x10, // QTYPE = TXT (16)
            0x00, 0x01,
        ];

        let (question, end_offset) = Question::parse(&data, 0).unwrap();
        assert_eq!(question.qtype, 16);
        assert_eq!(end_offset, data.len());
    }

    #[test]
    fn test_parse_ns_question() {
        #[rustfmt::skip]
        let data = [
            0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x02, // QTYPE = NS (2)
            0x00, 0x01,
        ];

        let (question, end_offset) = Question::parse(&data, 0).unwrap();
        assert_eq!(question.qtype, 2);
        assert_eq!(end_offset, data.len());
    }

    #[test]
    fn test_parse_soa_question() {
        #[rustfmt::skip]
        let data = [
            0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x06, // QTYPE = SOA (6)
            0x00, 0x01,
        ];

        let (question, end_offset) = Question::parse(&data, 0).unwrap();
        assert_eq!(question.qtype, 6);
        assert_eq!(end_offset, data.len());
    }

    #[test]
    fn test_parse_ptr_question() {
        // PTR record question (used for reverse DNS)
        #[rustfmt::skip]
        let data = [
            0x01, b'1', 0x01, b'0', 0x03, b'1', b'6', b'8', 0x03, b'1', b'9', b'2',
            0x07, b'i', b'n', b'-', b'a', b'd', b'd', b'r',
            0x04, b'a', b'r', b'p', b'a',
            0x00,
            0x00, 0x0C, // QTYPE = PTR (12)
            0x00, 0x01,
        ];

        let (question, end_offset) = Question::parse(&data, 0).unwrap();
        assert_eq!(question.qtype, 12);
        assert_eq!(end_offset, data.len());
        // This would be "1.0.168.192.in-addr.arpa."
    }

    #[test]
    fn test_parse_cname_question() {
        #[rustfmt::skip]
        let data = [
            0x03, b'w', b'w', b'w', 0x00,
            0x00, 0x05, // QTYPE = CNAME (5)
            0x00, 0x01,
        ];

        let (question, end_offset) = Question::parse(&data, 0).unwrap();
        assert_eq!(question.qtype, 5);
        assert_eq!(end_offset, data.len());
    }

    #[test]
    fn test_parse_chaos_class_question() {
        // CH (Chaos) class is used for version.bind queries
        #[rustfmt::skip]
        let data = [
            0x07, b'v', b'e', b'r', b's', b'i', b'o', b'n',
            0x04, b'b', b'i', b'n', b'd',
            0x00,
            0x00, 0x10, // QTYPE = TXT
            0x00, 0x03, // QCLASS = CH (3)
        ];

        let (question, end_offset) = Question::parse(&data, 0).unwrap();
        assert_eq!(question.qclass, 3);
        assert_eq!(end_offset, data.len());
    }

    #[test]
    fn test_question_into_owned() {
        #[rustfmt::skip]
        let data = [
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,
            0x00, 0x01, // QTYPE = A
            0x00, 0x01, // QCLASS = IN
        ];

        let (question, _) = Question::parse(&data, 0).unwrap();
        let owned: QuestionOwned = question.into();

        assert_eq!(owned.name.to_string(), "example.com.");
        assert_eq!(owned.qtype, 1);
        assert_eq!(owned.qclass, 1);
    }

    #[test]
    fn test_question_owned_parse() {
        #[rustfmt::skip]
        let data = [
            0x03, b'c', b'o', b'm',
            0x00,
            0x00, 0x01, // QTYPE = A
            0x00, 0x01, // QCLASS = IN
        ];

        let (question, end_offset) = QuestionOwned::parse(&data, 0).unwrap();

        assert_eq!(question.name.to_string(), "com.");
        assert_eq!(question.qtype, 1);
        assert_eq!(question.qclass, 1);
        assert_eq!(end_offset, data.len());
    }
}
