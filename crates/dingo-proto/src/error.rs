use core::fmt::Display;

/// Possible errors that may occur when parsing a DNS packet
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ParseError {
    /// Input buffer is too short to contain required data.
    BufferTooShort,
    /// Compression pointer points to itself.
    CompressionPointerLoop,
    /// A name followed more than 128 compression pointers.
    ///
    /// The limit bounds the work done per name. It is hit by excessively long
    /// (but otherwise valid) pointer chains, and by loops that pass through a
    /// label before returning to an earlier pointer.
    TooManyCompressionPointers,
    /// Compression pointer points beyond the packet boundary.
    CompressionPointerOutOfBounds,
    /// Compression pointer points forward to data not yet parsed.
    CompressionPointerForward,
    /// Label length exceeds the maximum of 63 octets.
    LabelLengthTooLong,
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
            ParseError::TooManyCompressionPointers => {
                write!(f, "too many compression pointers in name")
            }
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
