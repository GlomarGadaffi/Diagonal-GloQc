//! Outer container framing — spec/diag-protocol.md §5.
//!
//! Distinct from `hdlc` (§4): this is the length-prefixed, multi-message
//! wrapper a single device read (or a single write) carries, *around*
//! individually HDLC-framed messages — not itself HDLC. Wire layout,
//! little-endian throughout:
//!
//!   data_type:    u32
//!   num_messages: u32
//!   messages[num_messages]:
//!     len:  u32
//!     data: [u8; len]     (still HDLC-framed; §4 unwraps each of these)

/// data_type value meaning "userspace" — the only kind this project acts on.
pub const DATA_TYPE_USER_SPACE: u32 = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Container {
    pub data_type: u32,
    /// Each entry is one still-HDLC-framed message blob, verbatim.
    pub messages: Vec<Vec<u8>>,
}

impl Container {
    pub fn is_user_space(&self) -> bool {
        self.data_type == DATA_TYPE_USER_SPACE
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    /// Fewer than 8 bytes — not enough for even the data_type + num_messages header.
    TooShortForHeader,
    /// A message's declared `len` runs past the end of the buffer.
    TruncatedMessage { message_index: usize, declared_len: u32, remaining: usize },
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnvelopeError::TooShortForHeader => {
                write!(f, "buffer shorter than the 8-byte container header")
            }
            EnvelopeError::TruncatedMessage { message_index, declared_len, remaining } => write!(
                f,
                "message {message_index} declares {declared_len} bytes but only {remaining} remain"
            ),
        }
    }
}

impl std::error::Error for EnvelopeError {}

/// Parses one read-buffer's worth of bytes into a [`Container`]. Does not
/// interpret message contents — each blob in the result is still
/// HDLC-framed (see `hdlc::decapsulate_one`).
pub fn parse_container(raw: &[u8]) -> Result<Container, EnvelopeError> {
    if raw.len() < 8 {
        return Err(EnvelopeError::TooShortForHeader);
    }
    let data_type = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let num_messages = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);

    let mut messages = Vec::with_capacity(num_messages as usize);
    let mut offset = 8usize;
    for i in 0..num_messages {
        if offset + 4 > raw.len() {
            return Err(EnvelopeError::TruncatedMessage {
                message_index: i as usize,
                declared_len: 0,
                remaining: raw.len().saturating_sub(offset),
            });
        }
        let len =
            u32::from_le_bytes([raw[offset], raw[offset + 1], raw[offset + 2], raw[offset + 3]]);
        offset += 4;

        let end = offset + len as usize;
        if end > raw.len() {
            return Err(EnvelopeError::TruncatedMessage {
                message_index: i as usize,
                declared_len: len,
                remaining: raw.len().saturating_sub(offset),
            });
        }
        messages.push(raw[offset..end].to_vec());
        offset = end;
    }

    Ok(Container { data_type, messages })
}

/// Builds the write-side container wrapping one already HDLC-framed
/// request. `mdm_field` mirrors the "use_mdm" quirk in spec §5's source
/// device behavior: present (as a signed i32) only when the target needs
/// it, absent otherwise — omitted here entirely when `None`.
pub fn build_request_container_bytes(hdlc_framed_request: &[u8], mdm_field: Option<i32>) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + hdlc_framed_request.len());
    out.extend_from_slice(&DATA_TYPE_USER_SPACE.to_le_bytes());
    if let Some(mdm) = mdm_field {
        out.extend_from_slice(&mdm.to_le_bytes());
    }
    out.extend_from_slice(hdlc_framed_request);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(data_type: u32, num_messages: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&data_type.to_le_bytes());
        v.extend_from_slice(&num_messages.to_le_bytes());
        v
    }

    fn with_len_prefix(blob: &[u8]) -> Vec<u8> {
        let mut v = (blob.len() as u32).to_le_bytes().to_vec();
        v.extend_from_slice(blob);
        v
    }

    #[test]
    fn parses_zero_message_container() {
        let raw = header(DATA_TYPE_USER_SPACE, 0);
        let container = parse_container(&raw).unwrap();
        assert_eq!(container.data_type, DATA_TYPE_USER_SPACE);
        assert!(container.messages.is_empty());
        assert!(container.is_user_space());
    }

    #[test]
    fn parses_multiple_length_prefixed_messages() {
        let mut raw = header(DATA_TYPE_USER_SPACE, 2);
        raw.extend(with_len_prefix(b"first blob"));
        raw.extend(with_len_prefix(b"second, longer blob"));

        let container = parse_container(&raw).unwrap();
        assert_eq!(container.messages, vec![b"first blob".to_vec(), b"second, longer blob".to_vec()]);
    }

    #[test]
    fn non_user_space_data_type_is_preserved_not_rejected() {
        // parsing shouldn't filter by data_type — that's a policy decision
        // for the caller (matches spec: capture coverage stays independent
        // of interpretation).
        let raw = header(999, 0);
        let container = parse_container(&raw).unwrap();
        assert_eq!(container.data_type, 999);
        assert!(!container.is_user_space());
    }

    #[test]
    fn rejects_buffer_shorter_than_header() {
        assert_eq!(parse_container(&[1, 2, 3]), Err(EnvelopeError::TooShortForHeader));
    }

    #[test]
    fn rejects_message_len_running_past_buffer_end() {
        let mut raw = header(DATA_TYPE_USER_SPACE, 1);
        raw.extend_from_slice(&100u32.to_le_bytes()); // claims 100 bytes
        raw.extend_from_slice(b"only a few"); // far fewer actually present

        match parse_container(&raw) {
            Err(EnvelopeError::TruncatedMessage { message_index: 0, declared_len: 100, .. }) => {}
            other => panic!("expected TruncatedMessage, got {other:?}"),
        }
    }

    #[test]
    fn request_container_bytes_with_and_without_mdm_field() {
        let hdlc_bytes = [0x7E, 0xAA, 0xBB, 0x7E];

        let without_mdm = build_request_container_bytes(&hdlc_bytes, None);
        assert_eq!(without_mdm.len(), 4 + hdlc_bytes.len());
        assert_eq!(&without_mdm[0..4], &DATA_TYPE_USER_SPACE.to_le_bytes());
        assert_eq!(&without_mdm[4..], &hdlc_bytes);

        let with_mdm = build_request_container_bytes(&hdlc_bytes, Some(-1));
        assert_eq!(with_mdm.len(), 8 + hdlc_bytes.len());
        assert_eq!(&with_mdm[4..8], &(-1i32).to_le_bytes());
        assert_eq!(&with_mdm[8..], &hdlc_bytes);
    }

    #[test]
    fn round_trips_through_parse_after_build_when_wrapped_as_a_full_container() {
        // build_request_container_bytes produces the write-side shape (no
        // num_messages field — the device doesn't need one for a
        // single-request write). Confirm parse_container still handles a
        // *read*-shaped container (with num_messages) built the same way,
        // for symmetry of the two message blobs it wraps.
        let hdlc_a = [0x7E, 1, 2, 0x7E];
        let hdlc_b = [0x7E, 3, 4, 5, 0x7E];
        let mut raw = header(DATA_TYPE_USER_SPACE, 2);
        raw.extend(with_len_prefix(&hdlc_a));
        raw.extend(with_len_prefix(&hdlc_b));

        let container = parse_container(&raw).unwrap();
        assert_eq!(container.messages, vec![hdlc_a.to_vec(), hdlc_b.to_vec()]);
    }
}
