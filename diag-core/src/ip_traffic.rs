//! User IP traffic log record decode (log_type `0x11EB`) — spec §7.
//!
//! **Uncertain, flagged plainly rather than presented with false
//! confidence.** Every source this project cross-checked itself against
//! for other log types treats this one specifically as unverified — the
//! layout used here (skip a fixed 8-byte prefix, the rest is the raw IP
//! packet) traces back to a single QCSuper source comment that itself
//! reads "is this right??" rather than a confirmed spec. Not wired into
//! `dispatch` with the same confidence as `rrc`/`nas`/`legacy_signalling`
//! — available for a caller who wants to try it, not presented as
//! settled.

/// Skips a fixed prefix and returns the rest of the body as a guessed
/// raw IP packet. No structure to validate beyond length, so this can't
/// meaningfully fail except by being short — returns `None` rather than
/// a typed error since there's nothing more specific to report.
pub fn decode(body: &[u8]) -> Option<Vec<u8>> {
    const GUESSED_PREFIX_LEN: usize = 8;
    if body.len() < GUESSED_PREFIX_LEN {
        return None;
    }
    Some(body[GUESSED_PREFIX_LEN..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_the_guessed_prefix() {
        let mut body = vec![0u8; 8];
        body.extend_from_slice(&[0x45, 0x00, 0x01, 0x02]); // pretend IP header start
        assert_eq!(decode(&body).unwrap(), vec![0x45, 0x00, 0x01, 0x02]);
    }

    #[test]
    fn returns_none_for_a_body_shorter_than_the_guessed_prefix() {
        assert_eq!(decode(&[0u8; 4]), None);
    }

    #[test]
    fn empty_remainder_after_the_prefix_is_valid() {
        assert_eq!(decode(&[0u8; 8]), Some(Vec::new()));
    }
}
