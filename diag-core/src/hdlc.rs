//! Frame transport — spec/diag-protocol.md §4.
//!
//! Wire format: `escaped(payload ++ crc16_x25(payload).to_le_bytes()) | FLAG`
//! — content, then exactly one *trailing* FLAG. No leading FLAG: frames
//! are delimited by what follows them, not enclosed by a pair. Consecutive
//! frames are simply concatenated (`content,FLAG,content,FLAG,...`), so a
//! missing trailing FLAG on a given span specifically signals that the
//! frame is incomplete, not an equally-valid alternate framing — that
//! distinction matters and is enforced below, not glossed over (see the
//! doc comment on `decapsulate_one`, and how it was caught).
//!
//! FLAG = 0x7E, ESC = 0x7D, escaped bytes are XORed with 0x20 (standard
//! HDLC bit-6 stuffing, ISO/IEC 13239 — generic, not protocol-specific).
//!
//! CRC is CRC-16/X-25 (poly=0x1021, init=0xFFFF, refin/refout=true,
//! xorout=0xFFFF): the standard reflected-CCITT FCS used across the
//! HDLC/PPP/X.25 family (RFC 1662 Appendix C uses this exact bit-serial
//! form with the 0x8408 reflected-poly constant). Verified below against
//! the CRC's own published standard check value, not against any other
//! project's output.

pub const FLAG: u8 = 0x7E;
pub const ESC: u8 = 0x7D;
const ESC_XOR: u8 = 0x20;

/// CRC-16/X-25 over `data`. Reflected input/output, init 0xFFFF, xorout 0xFFFF.
pub fn crc16_x25(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= byte as u16;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x8408
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn push_escaped(out: &mut Vec<u8>, byte: u8) {
    if byte == FLAG || byte == ESC {
        out.push(ESC);
        out.push(byte ^ ESC_XOR);
    } else {
        out.push(byte);
    }
}

/// Frames `payload` for the wire: appends its CRC, escapes, appends a
/// single trailing FLAG. No leading FLAG (see module docs).
pub fn encode(payload: &[u8]) -> Vec<u8> {
    let crc = crc16_x25(payload).to_le_bytes();
    let mut framed = Vec::with_capacity(payload.len() + 3);
    for &byte in payload.iter().chain(crc.iter()) {
        push_escaped(&mut framed, byte);
    }
    framed.push(FLAG);
    framed
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Input didn't end in a FLAG — signals a truncated/incomplete frame,
    /// not an alternate valid framing (module docs).
    MissingTrailingFlag,
    /// An escape byte was the last byte before the closing FLAG.
    TrailingEscape,
    /// De-escaped content was shorter than the 2-byte CRC trailer.
    TooShort,
    CrcMismatch { expected: u16, computed: u16 },
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::MissingTrailingFlag => {
                write!(f, "no trailing FLAG — frame is truncated or incomplete")
            }
            DecodeError::TrailingEscape => write!(f, "frame ended mid-escape-sequence"),
            DecodeError::TooShort => write!(f, "frame shorter than the 2-byte CRC trailer"),
            DecodeError::CrcMismatch { expected, computed } => {
                write!(f, "CRC mismatch: expected {expected:#06x}, computed {computed:#06x}")
            }
        }
    }
}

impl std::error::Error for DecodeError {}

/// Decapsulates a single frame that's already been isolated from its
/// stream (e.g. by a `read_until(FLAG, ..)`-style read, or a split on
/// FLAG bytes) rather than fed through a [`FrameExtractor`]. Requires
/// exactly the real wire contract: content ending in one trailing FLAG,
/// no leading FLAG expected or stripped.
///
/// An earlier version of this function also tolerated a *missing*
/// trailing FLAG (treating it the same as "caller already stripped it").
/// That was wrong: a `read_until`-style caller handing over a span with
/// no trailing FLAG means the frame was cut off mid-read (truncated), not
/// that framing was done. Caught by `lib`'s own truncation test suite
/// (`qmdl::test::test_truncation`) once this function was wired in to
/// replace the vendored decapsulate call — real behavioral coverage,
/// not just this crate's own unit tests, catching a genuine bug.
pub fn decapsulate_one(data: &[u8]) -> Result<Vec<u8>, DecodeError> {
    let data = data.strip_suffix(&[FLAG]).ok_or(DecodeError::MissingTrailingFlag)?;
    unescape_and_verify(data)
}

fn unescape_and_verify(raw: &[u8]) -> Result<Vec<u8>, DecodeError> {
    let mut out = Vec::with_capacity(raw.len());
    let mut escaped = false;
    for &byte in raw {
        if escaped {
            out.push(byte ^ ESC_XOR);
            escaped = false;
        } else if byte == ESC {
            escaped = true;
        } else {
            out.push(byte);
        }
    }
    if escaped {
        return Err(DecodeError::TrailingEscape);
    }
    if out.len() < 2 {
        return Err(DecodeError::TooShort);
    }
    let split = out.len() - 2;
    let (payload, crc_bytes) = out.split_at(split);
    let expected = u16::from_le_bytes([crc_bytes[0], crc_bytes[1]]);
    let computed = crc16_x25(payload);
    if expected != computed {
        return Err(DecodeError::CrcMismatch { expected, computed });
    }
    Ok(payload.to_vec())
}

/// Extracts complete frames from a byte stream fed incrementally.
///
/// Device reads don't align to frame boundaries (spec §3): a read can
/// return a partial frame, several frames, or land mid-frame. Any bytes
/// after the last complete FLAG stay buffered across calls.
#[derive(Default)]
pub struct FrameExtractor {
    buf: Vec<u8>,
}

impl FrameExtractor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Pops the next complete frame, if one is fully buffered.
    ///
    /// `None` means "not enough bytes yet," not an error. `Some(Err(_))`
    /// means a complete FLAG-terminated frame was found but failed
    /// unescaping or CRC verification — the caller decides whether to log
    /// and continue; this method has already advanced past it, so the
    /// next call resumes scanning after the corrupt frame rather than
    /// getting stuck on it.
    pub fn next_frame(&mut self) -> Option<Result<Vec<u8>, DecodeError>> {
        loop {
            let flag_pos = self.buf.iter().position(|&b| b == FLAG)?;
            let raw = self.buf[..flag_pos].to_vec();
            self.buf.drain(..=flag_pos); // content plus the FLAG itself

            if raw.is_empty() {
                // Back-to-back FLAGs (e.g. idle-fill) — nothing between
                // them, keep scanning.
                continue;
            }

            return Some(unescape_and_verify(&raw));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc16_x25_matches_published_standard_check_value() {
        // The CRC-16/X-25 catalog check value for ASCII "123456789" is
        // 0x906E. This is the standard's own test vector — independent
        // verification, unrelated to any DIAG tool's output.
        assert_eq!(crc16_x25(b"123456789"), 0x906E);
    }

    #[test]
    fn round_trip_simple_payload() {
        let payload = b"hello diag";
        let framed = encode(payload);
        assert_eq!(framed.last(), Some(&FLAG));
        assert_ne!(framed.first(), Some(&FLAG), "no leading FLAG should be emitted");

        let mut ex = FrameExtractor::new();
        ex.push(&framed);
        assert_eq!(ex.next_frame().unwrap().unwrap(), payload);
    }

    #[test]
    fn round_trip_payload_containing_flag_and_escape_bytes() {
        let payload = [0x00, FLAG, 0xAA, ESC, 0xFF, FLAG, ESC];
        let framed = encode(&payload);
        // confirm escaping actually happened: the only raw FLAG byte is
        // the single trailing delimiter.
        assert_eq!(framed.iter().filter(|&&b| b == FLAG).count(), 1);

        let mut ex = FrameExtractor::new();
        ex.push(&framed);
        assert_eq!(ex.next_frame().unwrap().unwrap(), payload.to_vec());
    }

    #[test]
    fn corrupt_crc_is_reported_not_silently_accepted() {
        let mut framed = encode(b"payload");
        // flip a bit inside the escaped payload+crc region, away from the
        // trailing FLAG
        let mid = framed.len() / 2;
        framed[mid] ^= 0x01;

        let mut ex = FrameExtractor::new();
        ex.push(&framed);
        match ex.next_frame() {
            Some(Err(DecodeError::CrcMismatch { .. })) | Some(Err(DecodeError::TrailingEscape)) => {}
            other => panic!("expected a decode error, got {other:?}"),
        }
    }

    #[test]
    fn incomplete_frame_yields_none_until_the_rest_arrives() {
        let framed = encode(b"streamed");
        let (first_half, second_half) = framed.split_at(framed.len() / 2);

        let mut ex = FrameExtractor::new();
        ex.push(first_half);
        assert!(ex.next_frame().is_none());

        ex.push(second_half);
        assert_eq!(ex.next_frame().unwrap().unwrap(), b"streamed".to_vec());
    }

    #[test]
    fn back_to_back_frames_extract_in_order() {
        let mut stream = encode(b"first");
        stream.extend(encode(b"second"));

        let mut ex = FrameExtractor::new();
        ex.push(&stream);
        assert_eq!(ex.next_frame().unwrap().unwrap(), b"first".to_vec());
        assert_eq!(ex.next_frame().unwrap().unwrap(), b"second".to_vec());
        assert!(ex.next_frame().is_none());
    }

    #[test]
    fn empty_payload_round_trips() {
        let framed = encode(&[]);
        let mut ex = FrameExtractor::new();
        ex.push(&framed);
        // an all-CRC, zero-payload frame is 2 bytes of content — still
        // valid, just no payload bytes ahead of the trailer.
        assert_eq!(ex.next_frame().unwrap().unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn decapsulate_one_matches_frame_extractor_on_a_well_formed_frame() {
        let framed = encode(b"single frame");
        assert_eq!(decapsulate_one(&framed).unwrap(), b"single frame");
    }

    #[test]
    fn decapsulate_one_rejects_a_span_missing_its_trailing_flag() {
        // This is the case that matters: a read_until(FLAG, ..)-style read
        // that hit EOF before finding a delimiter (truncated mid-frame)
        // must be a hard, distinguishable error — not silently accepted.
        let framed = encode(b"single frame");
        let truncated = &framed[..framed.len() - 2]; // drop the FLAG and a byte before it
        assert_eq!(
            decapsulate_one(truncated),
            Err(DecodeError::MissingTrailingFlag)
        );
    }

    #[test]
    fn decapsulate_one_rejects_an_unexpected_leading_flag_via_crc_not_a_silent_strip() {
        // No leading FLAG is ever produced on the wire (module docs). If
        // one somehow appears, it must NOT be silently stripped — it's
        // just an extra content byte, so it flows into the escape/CRC
        // check like any other unexpected byte and fails loudly.
        let mut framed = encode(b"x");
        framed.insert(0, FLAG);
        assert!(decapsulate_one(&framed).is_err());
    }
}
