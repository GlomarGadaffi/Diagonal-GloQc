//! Mask configuration — spec/diag-protocol.md §6.
//!
//! Request builders, plus just enough response parsing to complete the
//! config handshake (status + range sizes) — not the full Log/Response
//! message dispatch or LogBody decode, which stays out of scope (spec
//! §7, ongoing, a much larger and separately-phased surface). The
//! distinction: this module needs to know "did SetMask succeed" and
//! "what ranges exist," not "decode every possible response payload."
//!
//! Response envelope (spec §5's message layer, narrowed to what LogConfig
//! responses need): 4-byte LE command code, 4-byte LE sub-op code, 4-byte
//! LE status, then an op-specific payload. A leading byte of 16 instead
//! marks a Log message, not a Response — checked and rejected here rather
//! than misread as a malformed response.

const LOG_CONFIG_CMD: u32 = 115;
const RETRIEVE_ID_RANGES_OP: u32 = 1;
const SET_MASK_OP: u32 = 3;
const LOG_MESSAGE_DISCRIMINANT: u8 = 16;

/// Request body asking the modem which log-code ranges exist per
/// equipment ID. Response carries 16 `u32` range sizes, one per
/// equipment ID slot — interpreting that response is out of scope here.
pub fn retrieve_id_ranges_request_bytes() -> Vec<u8> {
    let mut out = Vec::with_capacity(8);
    out.extend_from_slice(&LOG_CONFIG_CMD.to_le_bytes());
    out.extend_from_slice(&RETRIEVE_ID_RANGES_OP.to_le_bytes());
    out
}

/// Request body enabling *every* log code in `[0, log_mask_bitsize)` for
/// `log_type` — maximal capture, as opposed to enabling a curated
/// allowlist. Behavioral choice only (spec §6): same SetMask operation,
/// different bit pattern.
pub fn set_all_bits_mask_request_bytes(log_type: u32, log_mask_bitsize: u32) -> Vec<u8> {
    let num_bytes = ((log_mask_bitsize + 7) / 8) as usize;
    let mut mask = vec![0xFFu8; num_bytes];
    if let Some(last) = mask.last_mut() {
        let used_bits_in_last_byte = log_mask_bitsize as usize - (num_bytes - 1) * 8;
        if used_bits_in_last_byte < 8 {
            *last &= (1u8 << used_bits_in_last_byte) - 1;
        }
    }

    let mut out = Vec::with_capacity(20 + mask.len());
    out.extend_from_slice(&LOG_CONFIG_CMD.to_le_bytes());
    out.extend_from_slice(&SET_MASK_OP.to_le_bytes());
    out.extend_from_slice(&log_type.to_le_bytes());
    out.extend_from_slice(&log_mask_bitsize.to_le_bytes());
    out.extend_from_slice(&mask);
    out
}

/// True if a decapsulated message's leading byte marks it as a Log
/// message rather than a Response. Log message bodies aren't parsed
/// here — capture just archives them raw (spec §7).
pub fn is_log_message(payload: &[u8]) -> bool {
    payload.first() == Some(&LOG_MESSAGE_DISCRIMINANT)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetrieveIdRangesResponse {
    pub status: u32,
    pub log_mask_sizes: [u32; 16],
}

/// Parses a decapsulated message as a RetrieveIdRanges response. `None`
/// if it isn't one (wrong command/sub-op, a Log message, or too short) —
/// callers scanning a stream of responses treat that as "keep looking,"
/// not an error, since interleaved Log messages during config are routine.
pub fn parse_retrieve_id_ranges_response(payload: &[u8]) -> Option<RetrieveIdRangesResponse> {
    const RANGES_LEN: usize = 16 * 4;
    if is_log_message(payload) || payload.len() < 12 + RANGES_LEN {
        return None;
    }
    if u32::from_le_bytes(payload[0..4].try_into().ok()?) != LOG_CONFIG_CMD {
        return None;
    }
    if u32::from_le_bytes(payload[4..8].try_into().ok()?) != RETRIEVE_ID_RANGES_OP {
        return None;
    }
    let status = u32::from_le_bytes(payload[8..12].try_into().ok()?);

    let mut log_mask_sizes = [0u32; 16];
    for (i, slot) in log_mask_sizes.iter_mut().enumerate() {
        let off = 12 + i * 4;
        *slot = u32::from_le_bytes(payload[off..off + 4].try_into().ok()?);
    }
    Some(RetrieveIdRangesResponse { status, log_mask_sizes })
}

/// Parses a decapsulated message as a SetMask response, returning its
/// status (0 = success). `None` under the same "keep looking" conditions
/// as [`parse_retrieve_id_ranges_response`].
pub fn parse_set_mask_response(payload: &[u8]) -> Option<u32> {
    if is_log_message(payload) || payload.len() < 12 {
        return None;
    }
    if u32::from_le_bytes(payload[0..4].try_into().ok()?) != LOG_CONFIG_CMD {
        return None;
    }
    if u32::from_le_bytes(payload[4..8].try_into().ok()?) != SET_MASK_OP {
        return None;
    }
    Some(u32::from_le_bytes(payload[8..12].try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retrieve_id_ranges_is_cmd_115_op_1() {
        assert_eq!(
            retrieve_id_ranges_request_bytes(),
            vec![115, 0, 0, 0, 1, 0, 0, 0]
        );
    }

    #[test]
    fn set_mask_header_fields_are_correct() {
        let bytes = set_all_bits_mask_request_bytes(4, 8);
        assert_eq!(&bytes[0..4], &115u32.to_le_bytes()); // LogConfig
        assert_eq!(&bytes[4..8], &3u32.to_le_bytes()); // SetMask op
        assert_eq!(&bytes[8..12], &4u32.to_le_bytes()); // log_type
        assert_eq!(&bytes[12..16], &8u32.to_le_bytes()); // bitsize
    }

    #[test]
    fn full_byte_bitsize_sets_every_bit() {
        let bytes = set_all_bits_mask_request_bytes(0, 16);
        let mask = &bytes[16..];
        assert_eq!(mask, &[0xFF, 0xFF]);
    }

    #[test]
    fn partial_final_byte_only_sets_valid_bits_not_padding() {
        // 17 bits -> 3 bytes, last byte should only have bit 0 set (the
        // 17th bit, index 16), not the 7 padding bits above it.
        let bytes = set_all_bits_mask_request_bytes(0, 17);
        let mask = &bytes[16..];
        assert_eq!(mask, &[0xFF, 0xFF, 0b0000_0001]);
    }

    #[test]
    fn zero_bitsize_produces_empty_mask_without_panicking() {
        let bytes = set_all_bits_mask_request_bytes(0, 0);
        assert_eq!(&bytes[16..], &[] as &[u8]);
    }

    #[test]
    fn total_length_matches_header_plus_mask_bytes() {
        let bytes = set_all_bits_mask_request_bytes(2, 20);
        // 16 header bytes (cmd, op, log_type, bitsize) + ceil(20/8)=3 mask bytes
        assert_eq!(bytes.len(), 16 + 3);
    }

    fn build_response(cmd: u32, subopcode: u32, status: u32, rest: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&cmd.to_le_bytes());
        out.extend_from_slice(&subopcode.to_le_bytes());
        out.extend_from_slice(&status.to_le_bytes());
        out.extend_from_slice(rest);
        out
    }

    #[test]
    fn is_log_message_checks_only_the_leading_byte() {
        assert!(is_log_message(&[16, 0, 0, 0]));
        assert!(!is_log_message(&[115, 0, 0, 0]));
        assert!(!is_log_message(&[]));
    }

    #[test]
    fn parses_a_well_formed_retrieve_id_ranges_response() {
        let mut ranges = [0u8; 64];
        for (i, chunk) in ranges.chunks_mut(4).enumerate() {
            chunk.copy_from_slice(&(i as u32 * 10).to_le_bytes());
        }
        let payload = build_response(LOG_CONFIG_CMD, RETRIEVE_ID_RANGES_OP, 0, &ranges);

        let parsed = parse_retrieve_id_ranges_response(&payload).unwrap();
        assert_eq!(parsed.status, 0);
        assert_eq!(parsed.log_mask_sizes[3], 30);
        assert_eq!(parsed.log_mask_sizes[15], 150);
    }

    #[test]
    fn retrieve_id_ranges_response_rejects_wrong_command_or_subopcode() {
        let ranges = [0u8; 64];
        let wrong_cmd = build_response(999, RETRIEVE_ID_RANGES_OP, 0, &ranges);
        assert!(parse_retrieve_id_ranges_response(&wrong_cmd).is_none());

        let wrong_op = build_response(LOG_CONFIG_CMD, SET_MASK_OP, 0, &ranges);
        assert!(parse_retrieve_id_ranges_response(&wrong_op).is_none());
    }

    #[test]
    fn retrieve_id_ranges_response_rejects_a_log_message_instead_of_misparsing_it() {
        let log_shaped = build_response(16, RETRIEVE_ID_RANGES_OP, 0, &[0u8; 64]);
        assert!(parse_retrieve_id_ranges_response(&log_shaped).is_none());
    }

    #[test]
    fn retrieve_id_ranges_response_rejects_a_truncated_ranges_section() {
        let short = build_response(LOG_CONFIG_CMD, RETRIEVE_ID_RANGES_OP, 0, &[0u8; 10]);
        assert!(parse_retrieve_id_ranges_response(&short).is_none());
    }

    #[test]
    fn parses_a_well_formed_set_mask_response() {
        let success = build_response(LOG_CONFIG_CMD, SET_MASK_OP, 0, &[]);
        assert_eq!(parse_set_mask_response(&success), Some(0));

        let failure = build_response(LOG_CONFIG_CMD, SET_MASK_OP, 7, &[]);
        assert_eq!(parse_set_mask_response(&failure), Some(7));
    }

    #[test]
    fn set_mask_response_rejects_wrong_command_or_subopcode_or_log_messages() {
        assert!(parse_set_mask_response(&build_response(999, SET_MASK_OP, 0, &[])).is_none());
        assert!(
            parse_set_mask_response(&build_response(LOG_CONFIG_CMD, RETRIEVE_ID_RANGES_OP, 0, &[]))
                .is_none()
        );
        assert!(parse_set_mask_response(&build_response(16, SET_MASK_OP, 0, &[])).is_none());
    }
}
