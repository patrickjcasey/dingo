//! DNS resource record parsing.
//!
//! This module handles parsing of resource records (RRs) as specified in
//! RFC 1035 Section 4.1.3. Resource records appear in the answer, authority,
//! and additional sections of DNS messages.
//!
//! # Type Variants
//!
//! - [`ResourceRecord`] - Zero-copy borrowed type that references packet data
//! - [`ResourceRecordOwned`] - Owned type that stores data in allocated vectors

use alloc::vec::Vec;

use crate::name::{Name, NameOwned};
use crate::ParseError;

/// A zero-copy DNS resource record.
///
/// Resource records contain the actual DNS data such as IP addresses,
/// name server information, mail exchange records, etc. This borrowed variant
/// references the original packet data without allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceRecord<'a> {
    /// The domain name to which this record pertains.
    pub name: Name<'a>,

    /// The record type (TYPE).
    ///
    /// Common values:
    /// - 1 = A (IPv4 address)
    /// - 2 = NS (name server)
    /// - 5 = CNAME (canonical name)
    /// - 6 = SOA (start of authority)
    /// - 15 = MX (mail exchange)
    /// - 16 = TXT (text)
    /// - 28 = AAAA (IPv6 address)
    /// - 41 = OPT (EDNS)
    pub rtype: u16,

    /// The record class (CLASS).
    ///
    /// Common values:
    /// - 1 = IN (Internet)
    pub rclass: u16,

    /// Time to live in seconds.
    ///
    /// Specifies how long the record may be cached.
    pub ttl: u32,

    /// The length of the RDATA field.
    pub rdlength: u16,

    /// The raw record data as a slice into the packet.
    ///
    /// The format depends on the record type:
    /// - A: 4 bytes (IPv4 address)
    /// - AAAA: 16 bytes (IPv6 address)
    /// - CNAME/NS/PTR: compressed domain name
    /// - MX: 2-byte preference + domain name
    /// - TXT: length-prefixed strings
    /// - SOA: complex structure with names and integers
    pub rdata: &'a [u8],

    /// The complete packet (for parsing names in RDATA).
    packet: &'a [u8],
}

impl<'a> ResourceRecord<'a> {
    /// Parse a resource record from the packet data starting at the given offset.
    ///
    /// Returns the parsed record and the offset immediately after the record.
    ///
    /// # Arguments
    ///
    /// * `packet` - The complete DNS packet data (needed for name decompression)
    /// * `offset` - The offset within `packet` where the record starts
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The buffer is too short
    /// - The domain name is invalid (see [`Name::parse`])
    /// - RDLENGTH exceeds remaining packet data ([`ParseError::RdataOverflow`])
    /// - RDLENGTH is invalid for the record type ([`ParseError::InvalidRdataLength`])
    ///
    /// # Example
    ///
    /// ```ignore
    /// // A record for "www" pointing to 1.2.3.4
    /// let data = [
    ///     0x03, b'w', b'w', b'w', 0x00, // name: www.
    ///     0x00, 0x01,                   // TYPE = A
    ///     0x00, 0x01,                   // CLASS = IN
    ///     0x00, 0x00, 0x00, 0x3C,       // TTL = 60
    ///     0x00, 0x04,                   // RDLENGTH = 4
    ///     0x01, 0x02, 0x03, 0x04,       // RDATA = 1.2.3.4
    /// ];
    /// let (rr, next_offset) = ResourceRecord::parse(&data, 0)?;
    /// assert_eq!(rr.rtype, 1);
    /// assert_eq!(rr.rdata, [1, 2, 3, 4]);
    /// ```
    pub fn parse(packet: &'a [u8], offset: usize) -> Result<(Self, usize), ParseError> {
        // 1. Parse the domain name using Name::parse
        let (name, mut pos) = Name::parse(packet, offset)?;

        // 2. Read TYPE (2 bytes, big-endian)
        if pos + 2 > packet.len() {
            return Err(ParseError::BufferTooShort);
        }
        let rtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        pos += 2;

        // 3. Read CLASS (2 bytes, big-endian)
        if pos + 2 > packet.len() {
            return Err(ParseError::BufferTooShort);
        }
        let rclass = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        pos += 2;

        // 4. Read TTL (4 bytes, big-endian)
        if pos + 4 > packet.len() {
            return Err(ParseError::BufferTooShort);
        }
        let ttl = u32::from_be_bytes([
            packet[pos],
            packet[pos + 1],
            packet[pos + 2],
            packet[pos + 3],
        ]);
        pos += 4;

        // 5. Read RDLENGTH (2 bytes, big-endian)
        if pos + 2 > packet.len() {
            return Err(ParseError::BufferTooShort);
        }
        let rdlength = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        pos += 2;

        // 6. Validate that RDLENGTH bytes are available in the remaining data
        let rdlength_usize = rdlength as usize;
        if pos + rdlength_usize > packet.len() {
            return Err(ParseError::RdataOverflow);
        }

        // 7. For known types (A, AAAA), validate RDLENGTH matches expected size
        match rtype {
            1 => {
                // A record must have exactly 4 bytes
                if rdlength != 4 {
                    return Err(ParseError::InvalidRdataLength);
                }
            }
            28 => {
                // AAAA record must have exactly 16 bytes
                if rdlength != 16 {
                    return Err(ParseError::InvalidRdataLength);
                }
            }
            _ => {
                // Other record types: accept any RDLENGTH
            }
        }

        // 8. Get RDATA slice (zero-copy)
        let rdata = &packet[pos..pos + rdlength_usize];
        pos += rdlength_usize;

        // 9. Return the ResourceRecord and offset after RDATA
        let rr = Self {
            name,
            rtype,
            rclass,
            ttl,
            rdlength,
            rdata,
            packet,
        };
        Ok((rr, pos))
    }

    /// Returns true if this is an A record (IPv4 address).
    #[inline]
    pub fn is_a(&self) -> bool {
        self.rtype == 1
    }

    /// Returns true if this is an AAAA record (IPv6 address).
    #[inline]
    pub fn is_aaaa(&self) -> bool {
        self.rtype == 28
    }

    /// Returns true if this is an OPT record (EDNS).
    #[inline]
    pub fn is_opt(&self) -> bool {
        self.rtype == 41
    }

    /// For A records, returns the IPv4 address as a 4-byte array.
    ///
    /// Returns `None` if this is not an A record or RDATA is malformed.
    #[inline]
    pub fn as_ipv4(&self) -> Option<[u8; 4]> {
        if self.rtype == 1 && self.rdata.len() == 4 {
            Some([self.rdata[0], self.rdata[1], self.rdata[2], self.rdata[3]])
        } else {
            None
        }
    }

    /// For AAAA records, returns the IPv6 address as a 16-byte array.
    ///
    /// Returns `None` if this is not an AAAA record or RDATA is malformed.
    #[inline]
    pub fn as_ipv6(&self) -> Option<[u8; 16]> {
        if self.rtype == 28 && self.rdata.len() == 16 {
            self.rdata.try_into().ok()
        } else {
            None
        }
    }

    /// Returns the complete packet this record references.
    ///
    /// This is useful for parsing names within RDATA (e.g., CNAME, MX).
    #[inline]
    pub fn packet(&self) -> &'a [u8] {
        self.packet
    }

    /// Converts this borrowed record to an owned [`ResourceRecordOwned`].
    ///
    /// This allocates memory to store the name and RDATA.
    pub fn into_owned(self) -> ResourceRecordOwned {
        ResourceRecordOwned {
            name: self.name.into_owned(),
            rtype: self.rtype,
            rclass: self.rclass,
            ttl: self.ttl,
            rdlength: self.rdlength,
            rdata: self.rdata.to_vec(),
        }
    }
}

impl<'a> From<ResourceRecord<'a>> for ResourceRecordOwned {
    fn from(rr: ResourceRecord<'a>) -> Self {
        rr.into_owned()
    }
}

/// An owned DNS resource record.
///
/// Resource records contain the actual DNS data such as IP addresses,
/// name server information, mail exchange records, etc. This owned variant
/// stores the name and RDATA in allocated memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRecordOwned {
    /// The domain name to which this record pertains.
    pub name: NameOwned,

    /// The record type (TYPE).
    ///
    /// Common values:
    /// - 1 = A (IPv4 address)
    /// - 2 = NS (name server)
    /// - 5 = CNAME (canonical name)
    /// - 6 = SOA (start of authority)
    /// - 15 = MX (mail exchange)
    /// - 16 = TXT (text)
    /// - 28 = AAAA (IPv6 address)
    /// - 41 = OPT (EDNS)
    pub rtype: u16,

    /// The record class (CLASS).
    ///
    /// Common values:
    /// - 1 = IN (Internet)
    pub rclass: u16,

    /// Time to live in seconds.
    ///
    /// Specifies how long the record may be cached.
    pub ttl: u32,

    /// The length of the RDATA field.
    pub rdlength: u16,

    /// The raw record data.
    ///
    /// The format depends on the record type:
    /// - A: 4 bytes (IPv4 address)
    /// - AAAA: 16 bytes (IPv6 address)
    /// - CNAME/NS/PTR: compressed domain name
    /// - MX: 2-byte preference + domain name
    /// - TXT: length-prefixed strings
    /// - SOA: complex structure with names and integers
    pub rdata: Vec<u8>,
}

impl ResourceRecordOwned {
    /// Parse a resource record from the packet data starting at the given offset.
    ///
    /// Returns the parsed record and the offset immediately after the record.
    /// This immediately converts to owned, allocating memory for the name and RDATA.
    ///
    /// # Arguments
    ///
    /// * `packet` - The complete DNS packet data (needed for name decompression)
    /// * `offset` - The offset within `packet` where the record starts
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The buffer is too short
    /// - The domain name is invalid (see [`Name::parse`])
    /// - RDLENGTH exceeds remaining packet data ([`ParseError::RdataOverflow`])
    /// - RDLENGTH is invalid for the record type ([`ParseError::InvalidRdataLength`])
    pub fn parse(packet: &[u8], offset: usize) -> Result<(Self, usize), ParseError> {
        let (rr, end) = ResourceRecord::parse(packet, offset)?;
        Ok((rr.into_owned(), end))
    }

    /// Returns true if this is an A record (IPv4 address).
    #[inline]
    pub fn is_a(&self) -> bool {
        self.rtype == 1
    }

    /// Returns true if this is an AAAA record (IPv6 address).
    #[inline]
    pub fn is_aaaa(&self) -> bool {
        self.rtype == 28
    }

    /// Returns true if this is an OPT record (EDNS).
    #[inline]
    pub fn is_opt(&self) -> bool {
        self.rtype == 41
    }

    /// For A records, returns the IPv4 address as a 4-byte array.
    ///
    /// Returns `None` if this is not an A record or RDATA is malformed.
    #[inline]
    pub fn as_ipv4(&self) -> Option<[u8; 4]> {
        if self.rtype == 1 && self.rdata.len() == 4 {
            Some([self.rdata[0], self.rdata[1], self.rdata[2], self.rdata[3]])
        } else {
            None
        }
    }

    /// For AAAA records, returns the IPv6 address as a 16-byte array.
    ///
    /// Returns `None` if this is not an AAAA record or RDATA is malformed.
    #[inline]
    pub fn as_ipv6(&self) -> Option<[u8; 16]> {
        if self.rtype == 28 && self.rdata.len() == 16 {
            self.rdata.as_slice().try_into().ok()
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // A Record Tests
    // =========================================================================

    #[test]
    fn test_parse_a_record() {
        // A record for "www." pointing to 192.168.1.1
        #[rustfmt::skip]
        let data = [
            0x03, b'w', b'w', b'w', 0x00, // name: www.
            0x00, 0x01,                   // TYPE = A (1)
            0x00, 0x01,                   // CLASS = IN (1)
            0x00, 0x00, 0x00, 0x3C,       // TTL = 60 seconds
            0x00, 0x04,                   // RDLENGTH = 4
            0xC0, 0xA8, 0x01, 0x01,       // RDATA = 192.168.1.1
        ];

        let (rr, end_offset) = ResourceRecord::parse(&data, 0).unwrap();

        assert_eq!(rr.name.to_string(), "www.");
        assert_eq!(rr.rtype, 1); // A
        assert_eq!(rr.rclass, 1); // IN
        assert_eq!(rr.ttl, 60);
        assert_eq!(rr.rdlength, 4);
        assert_eq!(rr.rdata, [192, 168, 1, 1]);
        assert!(rr.is_a());
        assert_eq!(rr.as_ipv4(), Some([192, 168, 1, 1]));
        assert_eq!(end_offset, data.len()); // 5 (name) + 10 (fixed fields) + 4 (rdata) = 19
    }

    #[test]
    fn test_parse_a_record_all_zeros() {
        // A record pointing to 0.0.0.0
        #[rustfmt::skip]
        let data = [
            0x00,                         // root name
            0x00, 0x01,                   // TYPE = A
            0x00, 0x01,                   // CLASS = IN
            0x00, 0x00, 0x00, 0x00,       // TTL = 0
            0x00, 0x04,                   // RDLENGTH = 4
            0x00, 0x00, 0x00, 0x00,       // RDATA = 0.0.0.0
        ];

        let (rr, end_offset) = ResourceRecord::parse(&data, 0).unwrap();

        assert_eq!(rr.as_ipv4(), Some([0, 0, 0, 0]));
        assert_eq!(end_offset, data.len());
    }

    #[test]
    fn test_parse_a_record_max_ttl() {
        // A record with maximum TTL (2^31 - 1)
        #[rustfmt::skip]
        let data = [
            0x00,                         // root name
            0x00, 0x01,                   // TYPE = A
            0x00, 0x01,                   // CLASS = IN
            0x7F, 0xFF, 0xFF, 0xFF,       // TTL = 2147483647
            0x00, 0x04,                   // RDLENGTH = 4
            0x08, 0x08, 0x08, 0x08,       // RDATA = 8.8.8.8
        ];

        let (rr, end_offset) = ResourceRecord::parse(&data, 0).unwrap();

        assert_eq!(rr.ttl, 2147483647);
        assert_eq!(end_offset, data.len());
    }

    // =========================================================================
    // AAAA Record Tests
    // =========================================================================

    #[test]
    fn test_parse_aaaa_record() {
        // AAAA record pointing to 2001:db8::1
        #[rustfmt::skip]
        let data = [
            0x03, b'w', b'w', b'w', 0x00, // name: www.
            0x00, 0x1C,                   // TYPE = AAAA (28)
            0x00, 0x01,                   // CLASS = IN
            0x00, 0x00, 0x01, 0x2C,       // TTL = 300
            0x00, 0x10,                   // RDLENGTH = 16
            // RDATA = 2001:0db8:0000:0000:0000:0000:0000:0001
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];

        let (rr, end_offset) = ResourceRecord::parse(&data, 0).unwrap();

        assert_eq!(rr.rtype, 28); // AAAA
        assert_eq!(rr.rdlength, 16);
        assert!(rr.is_aaaa());
        assert!(rr.as_ipv6().is_some());
        assert_eq!(end_offset, data.len()); // 5 + 10 + 16 = 31
    }

    #[test]
    fn test_parse_aaaa_record_loopback() {
        // AAAA record pointing to ::1
        #[rustfmt::skip]
        let data = [
            0x00,                         // root name
            0x00, 0x1C,                   // TYPE = AAAA
            0x00, 0x01,                   // CLASS = IN
            0x00, 0x00, 0x00, 0x3C,       // TTL = 60
            0x00, 0x10,                   // RDLENGTH = 16
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];

        let (rr, end_offset) = ResourceRecord::parse(&data, 0).unwrap();

        let ipv6 = rr.as_ipv6().unwrap();
        assert_eq!(ipv6[15], 1);
        assert_eq!(&ipv6[0..15], &[0u8; 15]);
        assert_eq!(end_offset, data.len());
    }

    // =========================================================================
    // CNAME Record Tests
    // =========================================================================

    #[test]
    fn test_parse_cname_record() {
        // CNAME record: www.example.com -> example.com
        #[rustfmt::skip]
        let data = [
            0x03, b'w', b'w', b'w', 0x00, // name: www.
            0x00, 0x05,                   // TYPE = CNAME (5)
            0x00, 0x01,                   // CLASS = IN
            0x00, 0x00, 0x0E, 0x10,       // TTL = 3600
            0x00, 0x0D,                   // RDLENGTH = 13
            // RDATA = "example.com."
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm', 0x00,
        ];

        let (rr, end_offset) = ResourceRecord::parse(&data, 0).unwrap();

        assert_eq!(rr.rtype, 5); // CNAME
        assert_eq!(rr.rdlength, 13);
        assert_eq!(end_offset, data.len());
    }

    // =========================================================================
    // NS Record Tests
    // =========================================================================

    #[test]
    fn test_parse_ns_record() {
        #[rustfmt::skip]
        let data = [
            0x03, b'c', b'o', b'm', 0x00, // name: com.
            0x00, 0x02,                   // TYPE = NS (2)
            0x00, 0x01,                   // CLASS = IN
            0x00, 0x01, 0x51, 0x80,       // TTL = 86400
            0x00, 0x14,                   // RDLENGTH = 20
            // RDATA = "a.gtld-servers.net."
            0x01, b'a', 0x0C, b'g', b't', b'l', b'd', b'-', b's', b'e', b'r', b'v', b'e', b'r', b's',
            0x03, b'n', b'e', b't', 0x00,
        ];

        let (rr, end_offset) = ResourceRecord::parse(&data, 0).unwrap();

        assert_eq!(rr.rtype, 2); // NS
        assert_eq!(end_offset, data.len());
    }

    // =========================================================================
    // MX Record Tests
    // =========================================================================

    #[test]
    fn test_parse_mx_record() {
        // MX record with preference 10
        #[rustfmt::skip]
        let data = [
            0x03, b'c', b'o', b'm', 0x00, // name: com.
            0x00, 0x0F,                   // TYPE = MX (15)
            0x00, 0x01,                   // CLASS = IN
            0x00, 0x00, 0x0E, 0x10,       // TTL = 3600
            0x00, 0x08,                   // RDLENGTH = 8 (preference=2 + name=6)
            // RDATA = preference (2 bytes) + mail exchanger name
            0x00, 0x0A,                   // preference = 10
            0x04, b'm', b'a', b'i', b'l', 0x00, // "mail."
        ];

        let (rr, end_offset) = ResourceRecord::parse(&data, 0).unwrap();

        assert_eq!(rr.rtype, 15); // MX
        // First two bytes of rdata should be preference
        assert_eq!(u16::from_be_bytes([rr.rdata[0], rr.rdata[1]]), 10);
        assert_eq!(end_offset, data.len());
    }

    // =========================================================================
    // TXT Record Tests
    // =========================================================================

    #[test]
    fn test_parse_txt_record() {
        // TXT record with "hello"
        #[rustfmt::skip]
        let data = [
            0x00,                         // root name
            0x00, 0x10,                   // TYPE = TXT (16)
            0x00, 0x01,                   // CLASS = IN
            0x00, 0x00, 0x00, 0x3C,       // TTL = 60
            0x00, 0x06,                   // RDLENGTH = 6
            // RDATA = length-prefixed string "hello"
            0x05, b'h', b'e', b'l', b'l', b'o',
        ];

        let (rr, end_offset) = ResourceRecord::parse(&data, 0).unwrap();

        assert_eq!(rr.rtype, 16); // TXT
        assert_eq!(rr.rdata[0], 5); // string length
        assert_eq!(&rr.rdata[1..6], b"hello");
        assert_eq!(end_offset, data.len());
    }

    // =========================================================================
    // OPT Record Tests (EDNS)
    // =========================================================================

    #[test]
    fn test_parse_opt_record() {
        // OPT pseudo-record (EDNS)
        #[rustfmt::skip]
        let data = [
            0x00,                         // root name (required for OPT)
            0x00, 0x29,                   // TYPE = OPT (41)
            0x10, 0x00,                   // CLASS = requestor's UDP payload size (4096)
            0x00, 0x00, 0x00, 0x00,       // TTL = extended RCODE and flags
            0x00, 0x00,                   // RDLENGTH = 0 (no options)
        ];

        let (rr, end_offset) = ResourceRecord::parse(&data, 0).unwrap();

        assert_eq!(rr.rtype, 41); // OPT
        assert!(rr.is_opt());
        assert_eq!(rr.rclass, 4096); // UDP payload size
        assert_eq!(end_offset, data.len());
    }

    // =========================================================================
    // Compression Pointer Tests
    // =========================================================================

    #[test]
    fn test_parse_rr_with_compression_pointer() {
        // RR name uses compression pointer to earlier name
        // Note: With the slice-based API, compression pointers need full packet context.
        #[rustfmt::skip]
        let data = [
            // "example.com." at offset 0
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm', 0x00,
            // A record at offset 13 with pointer to offset 0
            0xC0, 0x00,                   // name: pointer to offset 0
            0x00, 0x01,                   // TYPE = A
            0x00, 0x01,                   // CLASS = IN
            0x00, 0x00, 0x00, 0x3C,       // TTL = 60
            0x00, 0x04,                   // RDLENGTH = 4
            0x01, 0x02, 0x03, 0x04,       // RDATA = 1.2.3.4
        ];

        // With slice-based API, we slice from offset 13
        let (rr, end_offset) = ResourceRecord::parse(&data, 13).unwrap();

        assert_eq!(rr.rdata, [1, 2, 3, 4]);
        assert_eq!(end_offset, data.len()); // 2 (pointer) + 10 (fixed) + 4 (rdata) = 16
    }

    #[test]
    fn test_parse_rr_with_partial_compression() {
        // RR name: "www" + pointer to "example.com."
        // Note: With the slice-based API, compression pointers need full packet context.
        #[rustfmt::skip]
        let data = [
            // "example.com." at offset 0
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm', 0x00,
            // A record at offset 13 for "www.example.com."
            0x03, b'w', b'w', b'w', 0xC0, 0x00, // name: www + pointer
            0x00, 0x01,                   // TYPE = A
            0x00, 0x01,                   // CLASS = IN
            0x00, 0x00, 0x00, 0x3C,       // TTL = 60
            0x00, 0x04,                   // RDLENGTH = 4
            0x01, 0x02, 0x03, 0x04,       // RDATA = 1.2.3.4
        ];

        // With slice-based API, we slice from offset 13
        let (rr, end_offset) = ResourceRecord::parse(&data, 13).unwrap();

        assert_eq!(rr.rdata, [1, 2, 3, 4]);
        assert_eq!(end_offset, data.len());
    }

    // =========================================================================
    // RDLENGTH Validation Tests
    // =========================================================================

    #[test]
    fn test_rdlength_overflow() {
        // RDLENGTH claims more bytes than available
        #[rustfmt::skip]
        let data = [
            0x00,                         // root name
            0x00, 0x01,                   // TYPE = A
            0x00, 0x01,                   // CLASS = IN
            0x00, 0x00, 0x00, 0x3C,       // TTL = 60
            0x00, 0xFF,                   // RDLENGTH = 255 (but only 4 bytes follow)
            0x01, 0x02, 0x03, 0x04,       // truncated RDATA
        ];

        let result = ResourceRecord::parse(&data, 0);
        assert!(
            matches!(result, Err(ParseError::RdataOverflow)),
            "Expected RdataOverflow, got {:?}",
            result
        );
    }

    #[test]
    fn test_rdlength_exactly_remaining() {
        // RDLENGTH exactly matches remaining bytes (should succeed)
        #[rustfmt::skip]
        let data = [
            0x00,                         // root name
            0x00, 0x10,                   // TYPE = TXT
            0x00, 0x01,                   // CLASS = IN
            0x00, 0x00, 0x00, 0x3C,       // TTL = 60
            0x00, 0x04,                   // RDLENGTH = 4
            0x03, b'a', b'b', b'c',       // RDATA = exactly 4 bytes
        ];

        let result = ResourceRecord::parse(&data, 0);
        assert!(result.is_ok(), "Expected success, got {:?}", result);
    }

    #[test]
    fn test_invalid_a_record_length_too_short() {
        // A record with RDLENGTH = 3 (should be 4)
        #[rustfmt::skip]
        let data = [
            0x00,                         // root name
            0x00, 0x01,                   // TYPE = A
            0x00, 0x01,                   // CLASS = IN
            0x00, 0x00, 0x00, 0x3C,       // TTL = 60
            0x00, 0x03,                   // RDLENGTH = 3 (invalid for A)
            0x01, 0x02, 0x03,             // truncated IP
        ];

        let result = ResourceRecord::parse(&data, 0);
        assert!(
            matches!(result, Err(ParseError::InvalidRdataLength)),
            "Expected InvalidRdataLength for short A record, got {:?}",
            result
        );
    }

    #[test]
    fn test_invalid_a_record_length_too_long() {
        // A record with RDLENGTH = 5 (should be 4)
        #[rustfmt::skip]
        let data = [
            0x00,                         // root name
            0x00, 0x01,                   // TYPE = A
            0x00, 0x01,                   // CLASS = IN
            0x00, 0x00, 0x00, 0x3C,       // TTL = 60
            0x00, 0x05,                   // RDLENGTH = 5 (invalid for A)
            0x01, 0x02, 0x03, 0x04, 0x05, // too many bytes
        ];

        let result = ResourceRecord::parse(&data, 0);
        assert!(
            matches!(result, Err(ParseError::InvalidRdataLength)),
            "Expected InvalidRdataLength for long A record, got {:?}",
            result
        );
    }

    #[test]
    fn test_invalid_aaaa_record_length() {
        // AAAA record with RDLENGTH = 15 (should be 16)
        #[rustfmt::skip]
        let data = [
            0x00,                         // root name
            0x00, 0x1C,                   // TYPE = AAAA
            0x00, 0x01,                   // CLASS = IN
            0x00, 0x00, 0x00, 0x3C,       // TTL = 60
            0x00, 0x0F,                   // RDLENGTH = 15 (invalid for AAAA)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];

        let result = ResourceRecord::parse(&data, 0);
        assert!(
            matches!(result, Err(ParseError::InvalidRdataLength)),
            "Expected InvalidRdataLength for short AAAA record, got {:?}",
            result
        );
    }

    // =========================================================================
    // Buffer Boundary Tests
    // =========================================================================

    #[test]
    fn test_parse_rr_empty_buffer() {
        let result = ResourceRecord::parse(&[], 0);
        assert!(
            matches!(result, Err(ParseError::BufferTooShort)),
            "Expected BufferTooShort, got {:?}",
            result
        );
    }

    #[test]
    fn test_parse_rr_truncated_type() {
        // Only name, no TYPE/CLASS/TTL/RDLENGTH
        let data = [0x03, b'c', b'o', b'm', 0x00];

        let result = ResourceRecord::parse(&data, 0);
        assert!(
            matches!(result, Err(ParseError::BufferTooShort)),
            "Expected BufferTooShort, got {:?}",
            result
        );
    }

    #[test]
    fn test_parse_rr_truncated_ttl() {
        // NAME + TYPE + CLASS but no TTL
        #[rustfmt::skip]
        let data = [
            0x00,       // name
            0x00, 0x01, // TYPE
            0x00, 0x01, // CLASS
        ];

        let result = ResourceRecord::parse(&data, 0);
        assert!(
            matches!(result, Err(ParseError::BufferTooShort)),
            "Expected BufferTooShort, got {:?}",
            result
        );
    }

    #[test]
    fn test_parse_rr_truncated_rdlength() {
        // NAME + TYPE + CLASS + TTL but no RDLENGTH
        #[rustfmt::skip]
        let data = [
            0x00,                   // name
            0x00, 0x01,             // TYPE
            0x00, 0x01,             // CLASS
            0x00, 0x00, 0x00, 0x3C, // TTL
        ];

        let result = ResourceRecord::parse(&data, 0);
        assert!(
            matches!(result, Err(ParseError::BufferTooShort)),
            "Expected BufferTooShort, got {:?}",
            result
        );
    }

    // =========================================================================
    // Helper Method Tests
    // =========================================================================

    #[test]
    fn test_as_ipv4_wrong_type() {
        // AAAA record should return None for as_ipv4()
        #[rustfmt::skip]
        let data = [
            0x00,
            0x00, 0x1C,                   // TYPE = AAAA
            0x00, 0x01,
            0x00, 0x00, 0x00, 0x3C,
            0x00, 0x10,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];

        let (rr, end_offset) = ResourceRecord::parse(&data, 0).unwrap();
        assert_eq!(rr.as_ipv4(), None);
        assert_eq!(end_offset, data.len());
    }

    #[test]
    fn test_as_ipv6_wrong_type() {
        // A record should return None for as_ipv6()
        #[rustfmt::skip]
        let data = [
            0x00,
            0x00, 0x01,                   // TYPE = A
            0x00, 0x01,
            0x00, 0x00, 0x00, 0x3C,
            0x00, 0x04,
            0x01, 0x02, 0x03, 0x04,
        ];

        let (rr, end_offset) = ResourceRecord::parse(&data, 0).unwrap();
        assert_eq!(rr.as_ipv6(), None);
        assert_eq!(end_offset, data.len());
    }

    #[test]
    fn test_is_type_helpers() {
        #[rustfmt::skip]
        let a_record = [
            0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04,
            0x01, 0x02, 0x03, 0x04,
        ];
        let (rr, end_offset) = ResourceRecord::parse(&a_record, 0).unwrap();
        assert!(rr.is_a());
        assert!(!rr.is_aaaa());
        assert!(!rr.is_opt());
        assert_eq!(end_offset, a_record.len());
    }

    // =========================================================================
    // Zero-length RDATA Tests
    // =========================================================================

    #[test]
    fn test_parse_rr_zero_rdlength() {
        // Some record types can have zero-length RDATA
        #[rustfmt::skip]
        let data = [
            0x00,                         // root name
            0x00, 0x29,                   // TYPE = OPT (commonly has 0 RDLENGTH)
            0x10, 0x00,                   // CLASS
            0x00, 0x00, 0x00, 0x00,       // TTL
            0x00, 0x00,                   // RDLENGTH = 0
        ];

        let (rr, end_offset) = ResourceRecord::parse(&data, 0).unwrap();

        assert_eq!(rr.rdlength, 0);
        assert!(rr.rdata.is_empty());
        assert_eq!(end_offset, data.len());
    }

    // =========================================================================
    // Owned type tests
    // =========================================================================

    #[test]
    fn test_resource_record_into_owned() {
        #[rustfmt::skip]
        let data = [
            0x03, b'w', b'w', b'w', 0x00, // name: www.
            0x00, 0x01,                   // TYPE = A
            0x00, 0x01,                   // CLASS = IN
            0x00, 0x00, 0x00, 0x3C,       // TTL = 60
            0x00, 0x04,                   // RDLENGTH = 4
            0x01, 0x02, 0x03, 0x04,       // RDATA = 1.2.3.4
        ];

        let (rr, _) = ResourceRecord::parse(&data, 0).unwrap();
        let owned: ResourceRecordOwned = rr.into_owned();

        assert_eq!(owned.name.to_string(), "www.");
        assert_eq!(owned.rtype, 1);
        assert_eq!(owned.rclass, 1);
        assert_eq!(owned.ttl, 60);
        assert_eq!(owned.rdata, [1, 2, 3, 4]);
        assert!(owned.is_a());
        assert_eq!(owned.as_ipv4(), Some([1, 2, 3, 4]));
    }

    #[test]
    fn test_resource_record_owned_parse() {
        #[rustfmt::skip]
        let data = [
            0x00,                         // root name
            0x00, 0x01,                   // TYPE = A
            0x00, 0x01,                   // CLASS = IN
            0x00, 0x00, 0x00, 0x3C,       // TTL = 60
            0x00, 0x04,                   // RDLENGTH = 4
            0x08, 0x08, 0x08, 0x08,       // RDATA = 8.8.8.8
        ];

        let (rr, end_offset) = ResourceRecordOwned::parse(&data, 0).unwrap();

        assert_eq!(rr.name.to_string(), ".");
        assert_eq!(rr.rtype, 1);
        assert_eq!(rr.as_ipv4(), Some([8, 8, 8, 8]));
        assert_eq!(end_offset, data.len());
    }
}
