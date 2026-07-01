//! Legacy 2G/3G signalling log records — spec §7. Three log types sharing
//! one shape (a channel/bearer byte, a secondary-id byte, a
//! length-prefixed raw message), differing only in the length field's
//! width:
//!
//! - WCDMA Signalling (`0x412F`): length is 2 bytes
//! - GSM RR Signalling (`0x512F`): length is 1 byte
//! - GPRS MAC Signalling (`0x5226`): length is 1 byte

pub const WCDMA_SIGNALLING: u16 = 0x412F;
pub const GSM_RR_SIGNALLING: u16 = 0x512F;
pub const GPRS_MAC_SIGNALLING: u16 = 0x5226;

pub fn is_legacy_signalling_log_type(log_type: u16) -> bool {
    matches!(log_type, WCDMA_SIGNALLING | GSM_RR_SIGNALLING | GPRS_MAC_SIGNALLING)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    pub channel_type: u8,
    /// "radio_bearer" for WCDMA, "message_type" for GSM RR / GPRS MAC —
    /// same byte position, different name depending on log type. Kept
    /// generic rather than picking a label that's wrong two-thirds of
    /// the time.
    pub secondary_id: u8,
    pub msg: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    NotALegacySignallingLogType(u16),
    TooShort,
    LengthExceedsAvailableData { declared: usize, available: usize },
}

pub fn decode(log_type: u16, body: &[u8]) -> Result<Decoded, DecodeError> {
    if !is_legacy_signalling_log_type(log_type) {
        return Err(DecodeError::NotALegacySignallingLogType(log_type));
    }
    if body.len() < 2 {
        return Err(DecodeError::TooShort);
    }
    let channel_type = body[0];
    let secondary_id = body[1];

    let (length, header_len) = if log_type == WCDMA_SIGNALLING {
        if body.len() < 4 {
            return Err(DecodeError::TooShort);
        }
        (u16::from_le_bytes([body[2], body[3]]) as usize, 4)
    } else {
        (body[2] as usize, 3)
    };

    if header_len + length > body.len() {
        return Err(DecodeError::LengthExceedsAvailableData {
            declared: length,
            available: body.len() - header_len,
        });
    }

    Ok(Decoded {
        channel_type,
        secondary_id,
        msg: body[header_len..header_len + length].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_wcdma_with_16_bit_length() {
        let mut body = vec![0x01, 0x02];
        body.extend_from_slice(&3u16.to_le_bytes());
        body.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        let decoded = decode(WCDMA_SIGNALLING, &body).unwrap();
        assert_eq!(decoded.channel_type, 0x01);
        assert_eq!(decoded.secondary_id, 0x02);
        assert_eq!(decoded.msg, vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn decodes_gsm_rr_with_8_bit_length() {
        let body = vec![0x05, 0x06, 2, 0xDE, 0xAD];
        let decoded = decode(GSM_RR_SIGNALLING, &body).unwrap();
        assert_eq!(decoded.msg, vec![0xDE, 0xAD]);
    }

    #[test]
    fn decodes_gprs_mac_with_8_bit_length() {
        let body = vec![0x07, 0x08, 1, 0xFF];
        let decoded = decode(GPRS_MAC_SIGNALLING, &body).unwrap();
        assert_eq!(decoded.msg, vec![0xFF]);
    }

    #[test]
    fn rejects_unrelated_log_type() {
        assert_eq!(
            decode(0xB0C0, &[0, 0, 0]),
            Err(DecodeError::NotALegacySignallingLogType(0xB0C0))
        );
    }

    #[test]
    fn rejects_length_running_past_available_data() {
        let body = vec![0x01, 0x02, 200, 0xAA]; // claims 200 bytes, only 1 present
        assert!(matches!(
            decode(GSM_RR_SIGNALLING, &body),
            Err(DecodeError::LengthExceedsAvailableData { .. })
        ));
    }

    #[test]
    fn rejects_body_too_short_for_even_the_header() {
        assert_eq!(decode(GSM_RR_SIGNALLING, &[0x01]), Err(DecodeError::TooShort));
    }

    #[test]
    fn is_legacy_signalling_log_type_recognizes_all_three_and_rejects_others() {
        for code in [WCDMA_SIGNALLING, GSM_RR_SIGNALLING, GPRS_MAC_SIGNALLING] {
            assert!(is_legacy_signalling_log_type(code));
        }
        assert!(!is_legacy_signalling_log_type(0xB0C0));
    }
}
