use alloc::string::String;
#[allow(unused, reason = "make supporting no_std easier")]
use alloc::string::ToString;
#[allow(unused, reason = "make supporting no_std easier")]
use alloc::vec;
use alloc::vec::Vec;

use crate::ParseError;

/// Maximum length of a single label (63 octets per RFC 1035).
pub const MAX_LABEL_LENGTH: usize = 63;

/// Maximum length of a domain name (255 octets per RFC 1035).
pub const MAX_NAME_LENGTH: usize = 255;

/// Maximum compression pointer chain depth to prevent stack overflow.
pub const MAX_POINTER_CHAIN: usize = 128;

/// A zero-copy borrowed DNS domain name.
///
/// This type references the original packet data without allocation.
/// Domain names in DNS are represented as a sequence of labels, where each label
/// is a length-prefixed string. Names can use compression pointers to refer to
/// previously occurring names in the message.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Name<'a> {
    /// The complete DNS packet data (needed for compression pointers).
    packet: &'a [u8],
    /// Offset where this name starts in the packet.
    start: usize,
    /// Offset immediately after the name in the original stream (not following pointers).
    end: usize,
}

impl<'a> Name<'a> {
    /// Parse a domain name from the packet data starting at the given offset.
    ///
    /// Returns the parsed name and the offset immediately after the name in the
    /// original data (not following compression pointers).
    ///
    /// This method only validates that the name structure is valid; it does not
    /// decompress the name. Use [`labels()`](Self::labels) to iterate over the
    /// decompressed labels.
    pub fn parse(packet: &'a [u8], offset: usize) -> Result<(Self, usize), ParseError> {
        // Validate the name structure and find the end position
        let end = Self::validate_and_find_end(packet, offset)?;
        let name = Self {
            packet,
            start: offset,
            end,
        };
        Ok((name, end))
    }

    /// Validates the name structure and returns the end position.
    ///
    /// This performs all security checks (loop detection, bounds checking, etc.)
    /// without allocating memory.
    fn validate_and_find_end(packet: &[u8], offset: usize) -> Result<usize, ParseError> {
        let mut pos = offset;
        let mut end_pos: Option<usize> = None;
        let mut total_len: usize = 0;

        // We only need to track positions we've visited to detect loops
        let mut visited = [0u16; MAX_POINTER_CHAIN];
        let mut visited_count = 0;

        loop {
            // Check for loops
            let pos_u16 = pos as u16;

            if visited[..visited_count].contains(&pos_u16) {
                return Err(ParseError::CompressionPointerLoop);
            }
            if visited_count >= MAX_POINTER_CHAIN {
                return Err(ParseError::CompressionPointerLoop);
            }

            visited[visited_count] = pos_u16;
            visited_count += 1;

            if pos >= packet.len() {
                return Err(ParseError::BufferTooShort);
            }

            let length = packet[pos];
            match length & 0xC0 {
                0x00 => {
                    if length == 0 {
                        // Root label - end of name
                        if end_pos.is_none() {
                            end_pos = Some(pos + 1);
                        }
                        break;
                    }

                    let label_len = length as usize;

                    if label_len > MAX_LABEL_LENGTH {
                        return Err(ParseError::LabelLengthTooLong);
                    }

                    total_len += label_len + 1;
                    if total_len > MAX_NAME_LENGTH {
                        return Err(ParseError::NameTooLong);
                    }

                    let label_end = pos + 1 + label_len;
                    if label_end > packet.len() {
                        return Err(ParseError::BufferTooShort);
                    }

                    pos = label_end;
                }
                // Compression pointer
                0xC0 => {
                    if pos + 1 >= packet.len() {
                        return Err(ParseError::BufferTooShort);
                    }

                    let ptr_offset = (((length & 0x3F) as usize) << 8) | (packet[pos + 1] as usize);

                    if ptr_offset >= packet.len() {
                        return Err(ParseError::CompressionPointerOutOfBounds);
                    }

                    if ptr_offset > pos {
                        return Err(ParseError::CompressionPointerForward);
                    }

                    if end_pos.is_none() {
                        end_pos = Some(pos + 2);
                    }
                    pos = ptr_offset;
                }
                _ => {
                    // 0x40-0x7F and 0x80-0xBF are reserved
                    return Err(ParseError::LabelLengthTooLong);
                }
            }
        }

        total_len += 1; // Account for root label
        if total_len > MAX_NAME_LENGTH {
            return Err(ParseError::NameTooLong);
        }

        Ok(end_pos.unwrap_or(pos))
    }

    /// Returns an iterator over the labels of this domain name.
    ///
    /// Each item is a `Result<&'a [u8], ParseError>` to handle any parsing
    /// errors that occur during iteration (though errors are unlikely if
    /// `parse()` succeeded).
    #[inline]
    pub fn labels(&self) -> LabelIter<'a> {
        LabelIter::new(self.packet, self.start)
    }

    /// Returns true if this is the root domain (empty name).
    #[inline]
    pub fn is_root(&self) -> bool {
        self.start < self.packet.len() && self.packet[self.start] == 0
    }

    /// Returns the total length of this name when encoded (without compression).
    ///
    /// This is the sum of: 1 byte per label for length + label bytes + 1 byte for root.
    pub fn encoded_len(&self) -> usize {
        let mut len = 1; // Root label
        for label in self.labels().flatten() {
            len += 1 + label.len();
        }
        len
    }

    /// Returns the packet data this name references.
    #[inline]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.packet
    }

    /// Returns the start offset of this name in the packet.
    #[inline]
    pub fn start(&self) -> usize {
        self.start
    }

    /// Returns the end offset (where parsing should continue after this name).
    #[inline]
    pub fn end(&self) -> usize {
        self.end
    }

    /// Converts this borrowed name to an owned [`NameOwned`].
    ///
    /// This allocates memory to store all the labels.
    pub fn into_owned(self) -> NameOwned {
        self.into()
    }
}

impl core::fmt::Display for Name<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut has_labels = false;
        for label in self.labels().flatten() {
            write!(f, "{}.", String::from_utf8_lossy(label))?;
            has_labels = true;
        }
        if !has_labels {
            write!(f, ".")?;
        }
        Ok(())
    }
}

impl<'a> From<Name<'a>> for NameOwned {
    fn from(name: Name<'a>) -> Self {
        let labels = name
            .labels()
            .filter_map(|r| r.ok())
            .map(|l| l.to_vec())
            .collect();
        NameOwned { labels }
    }
}

/// Iterator over the labels of a DNS domain name.
///
/// This iterator follows compression pointers and yields each label as a byte slice.
/// Errors are returned for malformed names (though this is unlikely if the name
/// was successfully parsed).
#[derive(Debug, Clone)]
pub struct LabelIter<'a> {
    packet: &'a [u8],
    pos: usize,
    visited: [u16; MAX_POINTER_CHAIN],
    visited_count: usize,
    done: bool,
}

impl<'a> LabelIter<'a> {
    fn new(packet: &'a [u8], start: usize) -> Self {
        Self {
            packet,
            pos: start,
            visited: [0u16; MAX_POINTER_CHAIN],
            visited_count: 0,
            done: false,
        }
    }
}

impl<'a> Iterator for LabelIter<'a> {
    type Item = Result<&'a [u8], ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        loop {
            // Check for loops
            let pos_u16 = self.pos as u16;
            for i in 0..self.visited_count {
                if self.visited[i] == pos_u16 {
                    self.done = true;
                    return Some(Err(ParseError::CompressionPointerLoop));
                }
            }

            if self.visited_count >= MAX_POINTER_CHAIN {
                self.done = true;
                return Some(Err(ParseError::CompressionPointerLoop));
            }
            self.visited[self.visited_count] = pos_u16;
            self.visited_count += 1;

            if self.pos >= self.packet.len() {
                self.done = true;
                return Some(Err(ParseError::BufferTooShort));
            }

            let length = self.packet[self.pos];
            match length & 0xC0 {
                0x00 => {
                    if length == 0 {
                        // Root label - done
                        self.done = true;
                        return None;
                    }

                    let label_len = length as usize;
                    let label_start = self.pos + 1;
                    let label_end = label_start + label_len;

                    if label_end > self.packet.len() {
                        self.done = true;
                        return Some(Err(ParseError::BufferTooShort));
                    }

                    self.pos = label_end;
                    return Some(Ok(&self.packet[label_start..label_end]));
                }
                0xC0 => {
                    if self.pos + 1 >= self.packet.len() {
                        self.done = true;
                        return Some(Err(ParseError::BufferTooShort));
                    }

                    let ptr_offset =
                        (((length & 0x3F) as usize) << 8) | (self.packet[self.pos + 1] as usize);

                    if ptr_offset >= self.packet.len() {
                        self.done = true;
                        return Some(Err(ParseError::CompressionPointerOutOfBounds));
                    }

                    self.pos = ptr_offset;
                    // Continue the loop to follow the pointer
                }
                _ => {
                    self.done = true;
                    return Some(Err(ParseError::LabelLengthTooLong));
                }
            }
        }
    }
}

/// An owned DNS domain name.
///
/// Domain names in DNS are represented as a sequence of labels, where each label
/// is a length-prefixed string. This owned variant stores labels in allocated vectors,
/// suitable for long-term storage or modification.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NameOwned {
    /// The labels that make up this domain name.
    ///
    /// For "example.com.", this would be ["example", "com"].
    /// The root label (empty string) is implicit and not stored.
    labels: Vec<Vec<u8>>,
}

impl NameOwned {
    /// Parse a domain name from the packet data starting at the given offset.
    ///
    /// Returns the parsed name and the offset immediately after the name in the
    /// original data (not following compression pointers).
    ///
    /// # Arguments
    ///
    /// * `data` - The complete DNS packet data (needed for compression pointers)
    /// * `offset` - The offset within `data` where the name starts
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The buffer is too short
    /// - A compression pointer creates a loop
    /// - A compression pointer points out of bounds
    /// - A compression pointer points forward
    /// - A label exceeds 63 octets
    /// - The decompressed name exceeds 255 octets
    pub fn parse(packet: &[u8], offset: usize) -> Result<(Self, usize), ParseError> {
        let (name, end) = Name::parse(packet, offset)?;
        Ok((name.into_owned(), end))
    }

    /// Returns the labels that make up this domain name.
    #[inline]
    pub fn labels(&self) -> &[Vec<u8>] {
        &self.labels
    }

    /// Returns true if this is the root domain (empty name).
    #[inline]
    pub fn is_root(&self) -> bool {
        self.labels.is_empty()
    }

    /// Returns the total length of this name when encoded (without compression).
    ///
    /// This is the sum of: 1 byte per label for length + label bytes + 1 byte for root.
    #[inline]
    pub fn encoded_len(&self) -> usize {
        self.labels.iter().fold(0usize, |acc, x| acc + 1 + x.len()) + 1
    }
}

impl core::fmt::Display for NameOwned {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.is_root() {
            write!(f, ".")?;
        } else {
            for label in self.labels.iter() {
                write!(f, "{}.", String::from_utf8_lossy(label))?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;

    #[test]
    fn test_parse_simple_single_label() {
        // "com."
        let data = [0x03, b'c', b'o', b'm', 0x00];
        let (name, next_offset) = Name::parse(&data, 0).unwrap();

        assert_eq!(name.to_string(), "com.");
        assert_eq!(name.labels().count(), 1);
        assert_eq!(name.labels().next().unwrap().unwrap(), b"com");
        assert_eq!(next_offset, data.len());
    }

    #[test]
    fn test_parse_two_label_name() {
        // "example.com."
        let data = [
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
        ];
        let (name, next_offset) = Name::parse(&data, 0).unwrap();

        assert_eq!(name.to_string(), "example.com.");
        let labels: Vec<_> = name.labels().collect();
        assert_eq!(labels.len(), 2);
        assert_eq!(labels[0].as_ref().unwrap(), b"example");
        assert_eq!(labels[1].as_ref().unwrap(), b"com");
        assert_eq!(next_offset, data.len());
    }

    #[test]
    fn test_parse_three_label_name() {
        // "www.example.com."
        let data = [
            0x03, b'w', b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c',
            b'o', b'm', 0x00,
        ];
        let (name, next_offset) = Name::parse(&data, 0).unwrap();

        assert_eq!(name.to_string(), "www.example.com.");
        assert_eq!(name.labels().count(), 3);
        assert_eq!(next_offset, data.len());
    }

    #[test]
    fn test_parse_root_name() {
        // Root domain is just a null byte
        let data = [0x00];
        let (name, next_offset) = Name::parse(&data, 0).unwrap();

        assert!(name.is_root());
        assert_eq!(name.to_string(), ".");
        assert_eq!(name.labels().count(), 0);
        assert_eq!(next_offset, data.len());
    }

    #[test]
    fn test_parse_name_with_trailing_data() {
        // Name followed by extra data (like QTYPE/QCLASS)
        let data = [
            0x03, b'c', b'o', b'm', 0x00, // "com."
            0x00, 0x01, 0x00, 0x01, // trailing data
        ];
        let (name, next_offset) = Name::parse(&data, 0).unwrap();

        assert_eq!(name.to_string(), "com.");
        assert_eq!(next_offset, 5); // After "com." but before trailing data
    }

    #[test]
    fn test_compression_pointer_self_reference() {
        // A pointer that points to itself should be detected as a loop
        let data = [
            0xC0, 0x00, // Pointer to offset 0 (itself)
        ];

        let result = Name::parse(&data, 0);
        assert!(
            matches!(result, Err(ParseError::CompressionPointerLoop)),
            "Expected CompressionPointerLoop, got {result:?}"
        );
    }

    #[test]
    fn test_compression_pointer_mutual_loop() {
        // Two pointers pointing to each other - but the first one is actually forward!
        // A pointer at offset 0 pointing to offset 2 is a forward pointer.
        // This tests that forward pointers are rejected before loop detection.
        let data = [
            0xC0, 0x02, // Pointer at offset 0 -> offset 2 (forward!)
            0xC0, 0x00, // Pointer at offset 2 -> offset 0 (backward)
        ];

        let result = Name::parse(&data, 0);
        // The first pointer points forward, so we get ForwardPointer, not Loop
        assert!(
            matches!(result, Err(ParseError::CompressionPointerForward)),
            "Expected CompressionPointerForward (first pointer is forward), got {result:?}"
        );
    }

    #[test]
    fn test_compression_pointer_out_of_bounds() {
        // Pointer pointing beyond packet boundary
        let data = [
            0xC0, 0xFF, // Pointer to offset 255 (way beyond packet)
        ];

        let result = Name::parse(&data, 0);
        assert!(
            matches!(result, Err(ParseError::CompressionPointerOutOfBounds)),
            "Expected CompressionPointerOutOfBounds, got {result:?}"
        );
    }

    #[test]
    fn test_compression_pointer_forward() {
        // Pointer pointing forward to data not yet parsed
        let data = [
            0xC0, 0x02, // Pointer at offset 0 -> offset 2 (forward)
            0x03, b'c', b'o', b'm', 0x00, // "com." at offset 2
        ];

        let result = Name::parse(&data, 0);
        assert!(
            matches!(result, Err(ParseError::CompressionPointerForward)),
            "Expected CompressionPointerForward, got {result:?}"
        );
    }

    #[test]
    fn test_label_max_valid_length() {
        // 63 bytes is the maximum valid label length
        let mut data = vec![63]; // length byte
        data.extend([b'a'; 63]); // 63 'a's
        data.push(0x00); // null terminator

        let (name, _) = Name::parse(&data, 0).unwrap();
        assert_eq!(name.labels().next().unwrap().unwrap().len(), 63);
    }

    #[test]
    fn test_label_length_overflow() {
        // 64 bytes exceeds the maximum (uses bits that could be pointer flags)
        let mut data = vec![64]; // length byte = 64 (invalid)
        data.extend([b'a'; 64]);
        data.push(0x00);

        let result = Name::parse(&data, 0);
        assert!(
            matches!(result, Err(ParseError::LabelLengthTooLong)),
            "Expected InvalidLabelLength, got {result:?}"
        );
    }

    #[test]
    fn test_label_length_uses_reserved_bits() {
        // Length byte 0x40-0x7F uses reserved bits (not pointer, not valid length)
        let data = [0x7F, b'a']; // 0x7F = 127, uses reserved bits

        let result = Name::parse(&data, 0);
        assert!(
            matches!(result, Err(ParseError::LabelLengthTooLong)),
            "Expected InvalidLabelLength for reserved bits, got {result:?}"
        );
    }

    #[test]
    fn test_name_max_valid_length() {
        // Maximum name is 255 bytes: 63 + 1 + 63 + 1 + 63 + 1 + 61 + 1 + 1 = 255
        // That's: label(63).label(63).label(63).label(61). + null
        let mut data = Vec::new();

        // Three 63-byte labels
        for _ in 0..3 {
            data.push(63);
            data.extend(core::iter::repeat_n(b'a', 63));
        }
        // One 61-byte label (to reach exactly 255)
        data.push(61);
        data.extend(core::iter::repeat_n(b'a', 61));
        // Null terminator
        data.push(0x00);

        let result = Name::parse(&data, 0);
        assert!(result.is_ok(), "255-byte name should be valid: {result:?}");
    }

    #[test]
    fn test_name_too_long_direct() {
        // Name exceeds 255 bytes without using compression
        let mut data = Vec::new();

        // Four 63-byte labels = 4 * (1 + 63) + 1 = 257 bytes
        for _ in 0..4 {
            data.push(63);
            data.extend(core::iter::repeat_n(b'a', 63));
        }
        data.push(0x00);

        let result = Name::parse(&data, 0);
        assert!(
            matches!(result, Err(ParseError::NameTooLong)),
            "Expected NameTooLong, got {result:?}"
        );
    }

    #[test]
    fn test_empty_buffer() {
        let data: [u8; 0] = [];
        let result = Name::parse(&data, 0);
        assert!(
            matches!(result, Err(ParseError::BufferTooShort)),
            "Expected BufferTooShort for empty buffer, got {result:?}"
        );
    }

    #[test]
    fn test_label_extends_beyond_buffer() {
        // Label length says 10 bytes, but only 3 bytes remain
        let data = [0x0A, b'a', b'b', b'c']; // length=10, only 3 bytes of data

        let result = Name::parse(&data, 0);
        assert!(
            matches!(result, Err(ParseError::BufferTooShort)),
            "Expected BufferTooShort for truncated label, got {result:?}"
        );
    }

    #[test]
    fn test_missing_null_terminator() {
        // Name without null terminator (runs off end of buffer)
        let data = [0x03, b'c', b'o', b'm']; // no null terminator

        let result = Name::parse(&data, 0);
        assert!(
            matches!(result, Err(ParseError::BufferTooShort)),
            "Expected BufferTooShort for missing terminator, got {result:?}"
        );
    }

    #[test]
    fn test_compression_pointer_truncated() {
        // Compression pointer with only first byte (missing offset byte)
        let data = [0xC0]; // pointer prefix but no offset byte

        let result = Name::parse(&data, 0);
        assert!(
            matches!(result, Err(ParseError::BufferTooShort)),
            "Expected BufferTooShort for truncated pointer, got {result:?}"
        );
    }

    #[test]
    fn test_to_string_trailing_dot() {
        let data = [0x03, b'c', b'o', b'm', 0x00];
        let (name, _) = Name::parse(&data, 0).unwrap();

        // DNS names should have trailing dot to indicate FQDN
        assert!(name.to_string().ends_with('.'));
    }

    #[test]
    fn test_encoded_len_simple() {
        let data = [0x03, b'c', b'o', b'm', 0x00];
        let (name, _) = Name::parse(&data, 0).unwrap();

        // "com." = 1 (length) + 3 (label) + 1 (null) = 5
        assert_eq!(name.encoded_len(), 5);
    }

    #[test]
    fn test_encoded_len_multi_label() {
        let data = [
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
        ];
        let (name, _) = Name::parse(&data, 0).unwrap();

        // "example.com." = 1+7 + 1+3 + 1 = 13
        assert_eq!(name.encoded_len(), 13);
    }

    #[test]
    fn test_encoded_len_root() {
        let data = [0x00];
        let (name, _) = Name::parse(&data, 0).unwrap();

        // Root = just null byte = 1
        assert_eq!(name.encoded_len(), 1);
    }

    #[test]
    fn test_name_owned_parse() {
        let data = [0x03, b'c', b'o', b'm', 0x00];
        let (name, next_offset) = NameOwned::parse(&data, 0).unwrap();

        assert_eq!(name.to_string(), "com.");
        assert_eq!(name.labels().len(), 1);
        assert_eq!(name.labels()[0], b"com");
        assert_eq!(next_offset, data.len());
    }

    #[test]
    fn test_name_into_owned() {
        let data = [
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
        ];
        let (borrowed, _) = Name::parse(&data, 0).unwrap();
        let owned: NameOwned = borrowed.into_owned();

        assert_eq!(owned.to_string(), "example.com.");
        assert_eq!(owned.labels().len(), 2);
        assert_eq!(owned.labels()[0], b"example");
        assert_eq!(owned.labels()[1], b"com");
    }

    #[test]
    fn test_name_owned_is_root() {
        let data = [0x00];
        let (name, _) = NameOwned::parse(&data, 0).unwrap();

        assert!(name.is_root());
        assert_eq!(name.to_string(), ".");
    }

    #[test]
    fn test_name_owned_encoded_len() {
        let data = [
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
        ];
        let (name, _) = NameOwned::parse(&data, 0).unwrap();

        // "example.com." = 1+7 + 1+3 + 1 = 13
        assert_eq!(name.encoded_len(), 13);
    }

    #[test]
    fn test_compression_pointer_valid() {
        // "example.com." at offset 0, then a pointer to it
        #[rustfmt::skip]
        let data = [
            // "example.com." at offset 0
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,
            // Pointer at offset 13
            0xC0, 0x00, // pointer to offset 0
        ];

        let (name, end_offset) = Name::parse(&data, 13).unwrap();
        assert_eq!(name.to_string(), "example.com.");
        assert_eq!(end_offset, 15); // 13 + 2 bytes for pointer
    }

    #[test]
    fn test_compression_pointer_partial() {
        // "www" + pointer to "example.com."
        #[rustfmt::skip]
        let data = [
            // "example.com." at offset 0
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,
            // "www" + pointer at offset 13
            0x03, b'w', b'w', b'w',
            0xC0, 0x00, // pointer to offset 0
        ];

        let (name, end_offset) = Name::parse(&data, 13).unwrap();
        assert_eq!(name.to_string(), "www.example.com.");
        assert_eq!(end_offset, 19); // 13 + 4 (www) + 2 (pointer)
    }
}
