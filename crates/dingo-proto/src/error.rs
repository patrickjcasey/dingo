use core::fmt::Display;

/// Possible errors that may occur when parsing a DNS packet
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ParseError {
    /// Input buffer is too short to contain required data.
    BufferTooShort,
    /// Compression pointer creates a loop (self-reference or mutual reference).
    CompressionPointerLoop,
    /// Compression pointer points beyond the packet boundary.
    CompressionPointerOutOfBounds,
    /// Compression pointer points forward to data not yet parsed.
    CompressionPointerForward,
    /// Label uses a reserved or unsupported label type (first two bits `01` or
    /// `10`, e.g. RFC 6891 extended labels).
    ///
    /// A length octet above 63 falls in this range, so labels longer than 63
    /// octets are also reported with this error.
    UnsupportedLabelType,
    /// Domain name exceeds the maximum of 255 octets after decompression.
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
            ParseError::UnsupportedLabelType => {
                write!(f, "unsupported label type or label exceeds 63 octets")
            }
            ParseError::NameTooLong => write!(f, "domain name exceeds 255 octets"),
            ParseError::RdataOverflow => write!(f, "RDLENGTH exceeds remaining packet"),
            ParseError::InvalidRdataLength => write!(f, "RDLENGTH invalid for record type"),
            ParseError::InvalidRecordCount => write!(f, "record count mismatch"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError {}
