//! `dingo-proto` - A high-performance DNS packet parser
//!
//! This crate provides a fast and safe DNS message parser with a focus on
//! correctness and resistance to malformed input.
//!
//! # Example
//! ```
//! use dingo_proto::{Message, ParseError};
//!
//! let packet = [
//!     0x12, 0x34, // ID
//!     0x01, 0x00, // Flags: standard query
//!     0x00, 0x01, // QDCOUNT = 1
//!     0x00, 0x00, // ANCOUNT = 0
//!     0x00, 0x00, // NSCOUNT = 0
//!     0x00, 0x00, // ARCOUNT = 0
//!     // Question: example.com A IN
//!     0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
//!     0x03, b'c', b'o', b'm',
//!     0x00,
//!     0x00, 0x01, // QTYPE = A
//!     0x00, 0x01, // QCLASS = IN
//! ];
//!
//! let message = Message::parse(&packet).unwrap();
//! assert!(message.is_query());
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
pub use message::Message;
pub use name::Name;
pub use question::Question;
pub use rr::ResourceRecord;

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
    /// Reserved for future use (values 6-15)
    Reserved,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header([u8; Self::SIZE]);

impl Header {
    /// number of bytes needed to construct a `Header` within a DNS Request
    const SIZE: usize = 12;

    #[inline]
    pub fn parse(bytes: &[u8]) -> Result<(Self, &[u8]), ParseError> {
        if bytes.len() < Self::SIZE {
            return Err(ParseError::BufferTooShort);
        }
        let (header, remainder) = bytes.split_at(Self::SIZE);
        // TODO: validate all of the fields are valid
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
    /// 0 = standard query (QUERY)
    /// 1 = inverse query (IQUERY)
    /// 2 = server status request (STATUS)
    /// 3-15 = reserved for future use
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
