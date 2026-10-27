//! A high-performance, no_std-compatible DNS packet parser focused on speed and safety.
//!
//! # Example
//! ```
//! use dingo_proto::Message;
//!
//! let packet = [
//!      // Header
//!      0x12, 0x34,             // ID = 0x1234
//!      0x01, 0x00,             // Flags: RD=1 (standard query with recursion desired)
//!      0x00, 0x01,             // QDCOUNT = 1
//!      0x00, 0x00,             // ANCOUNT = 0
//!      0x00, 0x00,             // NSCOUNT = 0
//!      0x00, 0x00,             // ARCOUNT = 0
//!      // Question section
//!      0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
//!      0x03, b'c', b'o', b'm',
//!      0x00,
//!      0x00, 0x01,             // QTYPE = A (1)
//!      0x00, 0x01,             // QCLASS = IN (1)
//! ];
//! Message::parse(&packet).unwrap();
//! ```

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
    /// Name exists when it should not (RFC 2136)
    YXDomain,
    /// RR set exists when it should not (RFC 2136)
    YXRRSet,
    /// RR set that should exist does not (RFC 2136)
    NXRRSet,
    /// Server not authoritative for zone / not authorized (RFC 2136, RFC 8945)
    NotAuth,
    /// Name not contained in zone (RFC 2136)
    NotZone,
    /// Unassigned RCODE values (11-15)
    Reserved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Header([u8; Self::SIZE]);

impl Header {
    /// number of bytes needed to construct a `Header` within a DNS Request
    const SIZE: usize = 12;

    /// Parses a header from the start of `bytes`.
    ///
    /// The OPCODE, RCODE, and Z bit are not validated: unassigned values are
    /// left for the caller to interpret (e.g. a server answering an unknown
    /// OPCODE with NOTIMP, per RFC 1035 section 4.1.1).
    #[inline]
    pub fn parse(bytes: &[u8]) -> Result<(Self, &[u8]), ParseError> {
        let (header, remainder) = bytes
            .split_at_checked(Self::SIZE)
            .ok_or(ParseError::BufferTooShort)?;
        let header = <[u8; 12]>::try_from(header).unwrap();

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
    /// - 6 = DNS stateful operations (DSO, RFC 8490)
    /// - 7-15 = unassigned
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
            6 => ResponseCode::YXDomain,
            7 => ResponseCode::YXRRSet,
            8 => ResponseCode::NXRRSet,
            9 => ResponseCode::NotAuth,
            10 => ResponseCode::NotZone,
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
