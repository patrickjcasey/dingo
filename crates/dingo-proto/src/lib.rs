#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
extern crate core;

mod error;
mod message;
mod name;
mod question;
mod rr;

pub use error::ParseError;
pub use message::{Message, MessageOwned, QuestionIter, ResourceRecordIter};
pub use name::{LabelIter, Name, NameOwned};
pub use question::{Question, QuestionOwned};
pub use rr::{ResourceRecord, ResourceRecordOwned};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum QR {
    Query = 0,
    Response = 1,
}

/// From section 3.2.2 of RFC 1035
///
/// TYPE fields are used in resource records. Note that these types are a subset of QTYPES
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Type {
    /// a host address
    A = 1,
    /// an authoritative name server
    NS,
    /// a mail destination (Obsolete - use MX)
    MD,
    /// a mail forwarder (Obsolete - use MX)
    MF,
    /// the canonical name for an alias
    CNAME,
    /// marks the start of a zone authority
    SOA,
    /// a mailbox domain name (EXPERIMENTAL)
    MB,
    /// a mail group member (EXPERIMENTAL)
    MG,
    /// a mail rename domain name (EXPERIMENTAL)
    MR,
    /// a null RR (EXPERIMENTAL)
    NULL,
    /// a well known service description
    WKS,
    /// a domain name pointer
    PTR,
    /// host information
    HINFO,
    /// mailbox or mail list information
    MINFO,
    /// mail exchange
    MX,
    /// text strings
    TXT,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ResponseCode {
    NoErrorCondition = 0,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused,
    /// Extended RCODE values (6-10) or reserved values.
    ///
    /// Values 6-10 are used by DNS UPDATE (RFC 2136) and other extensions:
    /// - 6 = YXDomain (name exists when it should not)
    /// - 7 = YXRRSet (RR set exists when it should not)
    /// - 8 = NXRRSet (RR set does not exist when it should)
    /// - 9 = NotAuth (server not authoritative / not authorized)
    /// - 10 = NotZone (name not in zone)
    Reserved = 11,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Header([u8; Self::SIZE]);

impl Header {
    /// number of bytes needed to construct a `Header` within a DNS Request
    const SIZE: usize = 12;

    /// The reserved Z bit mask (bit 9, 0x40 in byte 3).
    /// Bits 10-11 (AD/CD) are used by DNSSEC and are allowed.
    const RESERVED_Z_BIT: u8 = 0x40;

    /// Maximum valid OPCODE (0-5 are assigned, 6-15 are reserved).
    const MAX_VALID_OPCODE: u8 = 5;

    /// Maximum valid RCODE (0-10 are assigned, 11-15 are reserved).
    const MAX_VALID_RCODE: u8 = 10;

    #[inline]
    pub fn parse(bytes: &[u8]) -> Result<(Self, &[u8]), ParseError> {
        let (header, remainder) = bytes
            .split_at_checked(Self::SIZE)
            .ok_or(ParseError::BufferTooShort)?;
        let header = <[u8; 12]>::try_from(header).unwrap();

        // Validate reserved Z bit (bit 9) is zero.
        // Note: Bits 10-11 (AD/CD) are used by DNSSEC (RFC 4035) and are allowed.
        if header[3] & Self::RESERVED_Z_BIT != 0 {
            return Err(ParseError::ReservedHeaderBit);
        }

        // Validate OPCODE is in known range (0-5).
        let opcode = (header[2] >> 3) & 0x0F;
        if opcode > Self::MAX_VALID_OPCODE {
            return Err(ParseError::InvalidOpcode);
        }

        // Validate RCODE is in known range (0-10).
        let rcode = header[3] & 0x0F;
        if rcode > Self::MAX_VALID_RCODE {
            return Err(ParseError::InvalidResponseCode);
        }

        Ok((Self(header), remainder))
    }

    /// Returns the 16-bit identifier assigned by the program that generated the query.
    /// This identifier is copied to the corresponding reply and can be used to match
    /// responses to outstanding queries.
    #[inline]
    pub fn id(&self) -> u16 {
        u16::from_be_bytes([self.0[0], self.0[1]])
    }

    /// Returns whether this message is a query (0) or a response (1).
    #[inline]
    pub fn qr(&self) -> QR {
        if self.0[2] & 0x80 != 0 {
            QR::Response
        } else {
            QR::Query
        }
    }

    /// Returns a 4-bit field specifying the kind of query:
    /// - 0 = standard query (QUERY)
    /// - 1 = inverse query (IQUERY, obsolete per RFC 3425)
    /// - 2 = server status request (STATUS)
    /// - 3 = reserved
    /// - 4 = notify (NOTIFY, RFC 1996)
    /// - 5 = update (UPDATE, RFC 2136)
    /// - 6-15 = reserved for future use
    #[inline]
    pub fn opcode(&self) -> u8 {
        (self.0[2] >> 3) & 0x0F
    }

    /// Authoritative Answer - valid in responses, specifies that the responding
    /// name server is an authority for the domain name in the question section.
    #[inline]
    pub fn authoritative_answer(&self) -> bool {
        self.0[2] & 0b100 != 0
    }

    /// TrunCation - specifies that this message was truncated due to length
    /// greater than that permitted on the transmission channel.
    #[inline]
    pub fn truncated(&self) -> bool {
        self.0[2] & 0b10 != 0
    }

    /// Recursion Desired - directs the name server to pursue the query recursively.
    #[inline]
    pub fn recursion_desired(&self) -> bool {
        self.0[2] & 0b1 != 0
    }

    /// Recursion Available - set in a response, denotes whether recursive
    /// query support is available in the name server.
    #[inline]
    pub fn recursion_available(&self) -> bool {
        self.0[3] & 0x80 != 0
    }

    /// Response code - 4-bit field set as part of responses.
    #[inline]
    pub fn response_code(&self) -> ResponseCode {
        match self.0[3] & 0x0F {
            0 => ResponseCode::NoErrorCondition,
            1 => ResponseCode::FormatError,
            2 => ResponseCode::ServerFailure,
            3 => ResponseCode::NameError,
            4 => ResponseCode::NotImplemented,
            5 => ResponseCode::Refused,
            _ => ResponseCode::Reserved,
        }
    }

    /// Returns the number of entries in the question section.
    #[inline]
    pub fn qdcount(&self) -> u16 {
        u16::from_be_bytes([self.0[4], self.0[5]])
    }

    /// Returns the number of resource records in the answer section.
    #[inline]
    pub fn ancount(&self) -> u16 {
        u16::from_be_bytes([self.0[6], self.0[7]])
    }

    /// Returns the number of name server resource records in the authority section.
    #[inline]
    pub fn nscount(&self) -> u16 {
        u16::from_be_bytes([self.0[8], self.0[9]])
    }

    /// Returns the number of resource records in the additional records section.
    #[inline]
    pub fn arcount(&self) -> u16 {
        u16::from_be_bytes([self.0[10], self.0[11]])
    }
}
