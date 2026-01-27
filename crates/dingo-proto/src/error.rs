use core::fmt::{Display, write};

/// Possible errors that may occur when parsing a DNS packet
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ParseError {
    /// Input buffer is too short to contain required data.
    BufferTooShort,
    /// Compression pointer creates a loop (self-reference or mutual reference).
    ///
    /// This prevents infinite loops when decompressing domain names.
    /// See: CVE-2018-20994, CVE-2017-14339
    CompressionPointerLoop,
    /// Compression pointer points beyond the packet boundary.
    ///
    /// See: NAME:WRECK vulnerabilities
    CompressionPointerOutOfBounds,
    /// Compression pointer points forward to data not yet parsed.
    ///
    /// RFC 1035 only allows pointers to previously occurring names.
    CompressionPointerForward,
    /// Label length exceeds the maximum of 63 octets.
    LabelLengthTooLong,
    /// Domain name exceeds the maximum of 255 octets after decompression.
    ///
    /// See: zlip-3 vulnerability pattern
    NameTooLong,
    /// RDLENGTH exceeds the remaining packet data.
    RdataOverflow,
    /// RDLENGTH doesn't match the expected length for the record type.
    ///
    /// For example, A records must have RDLENGTH of exactly 4.
    InvalidRdataLength,
    /// Record count in header doesn't match actual records in packet.
    InvalidRecordCount,
}

impl Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ParseError::BufferTooShort => write!(f, "buffer too short"),
            ParseError::CompressionPointerLoop => write!(f, "compression pointer loop detected"),
            ParseError::CompressionPointerOutOfBounds => {
                write!(f, "compression pointer out of bounds")
            }
            ParseError::CompressionPointerForward => {
                write!(f, "compression pointer points forward")
            }
            ParseError::LabelLengthTooLong => write!(f, "label length exceeds 63 octets"),
            ParseError::NameTooLong => write!(f, "domain name exceeds 255 octets"),
            ParseError::RdataOverflow => write!(f, "RDLENGTH exceeds remaining packet"),
            ParseError::InvalidRdataLength => write!(f, "RDLENGTH invalid for record type"),
            ParseError::InvalidRecordCount => write!(f, "record count mismatch"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError {}
