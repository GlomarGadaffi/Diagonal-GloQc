//! Plain (non-secure) NAS OTA log record decode — spec §7.
//!
//! LTE (`decode`): four log_types, ESM/EMM each in/out
//! (`0xB0E2`/`0xB0E3`/`0xB0EC`/`0xB0ED`). Simple shape: a fixed 4-byte
//! version header, then the raw NAS PDU runs to the end of the body — no
//! embedded length field of its own, no per-firmware-version layout
//! differences (contrast with RRC OTA, see [`crate::rrc`]).
//!
//! UMTS (`decode_umts`, log_type `0x713A`): a different, older shape —
//! a 1-byte uplink flag then an explicit 4-byte length, rather than
//! "everything else in the body." Kept in this module because it's the
//! same layer (NAS), not because the wire shape matches LTE's.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Downlink,
    Uplink,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    pub direction: Direction,
    pub ext_header_version: u8,
    pub pdu: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    NotANasLogType(u16),
    TooShort,
}

pub fn is_nas_log_type(log_type: u16) -> bool {
    matches!(log_type, 0xB0E2 | 0xB0E3 | 0xB0EC | 0xB0ED)
}

/// Decodes a NAS OTA log record body. `body` must already be exactly the
/// record's body bytes (e.g. from [`crate::log::parse`]) — direction
/// comes from `log_type`, not from the body itself.
pub fn decode(log_type: u16, body: &[u8]) -> Result<Decoded, DecodeError> {
    let direction = match log_type {
        0xB0E2 | 0xB0EC => Direction::Downlink,
        0xB0E3 | 0xB0ED => Direction::Uplink,
        other => return Err(DecodeError::NotANasLogType(other)),
    };
    if body.len() < 4 {
        return Err(DecodeError::TooShort);
    }
    let ext_header_version = body[0];
    // bytes 1..4 are rrc_rel / rrc_version_minor / rrc_version_major —
    // not exposed as separate fields yet, no current consumer needs them.
    Ok(Decoded {
        direction,
        ext_header_version,
        pdu: body[4..].to_vec(),
    })
}

pub const UMTS_NAS_OTA: u16 = 0x713A;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UmtsDecoded {
    pub uplink: bool,
    pub pdu: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum UmtsDecodeError {
    TooShort,
    LengthExceedsAvailableData { declared: usize, available: usize },
}

pub fn decode_umts(body: &[u8]) -> Result<UmtsDecoded, UmtsDecodeError> {
    const HEADER_LEN: usize = 5; // 1 uplink flag + 4-byte LE length
    if body.len() < HEADER_LEN {
        return Err(UmtsDecodeError::TooShort);
    }
    let uplink = body[0] != 0;
    let length = u32::from_le_bytes(body[1..5].try_into().unwrap()) as usize;
    if HEADER_LEN + length > body.len() {
        return Err(UmtsDecodeError::LengthExceedsAvailableData {
            declared: length,
            available: body.len() - HEADER_LEN,
        });
    }
    Ok(UmtsDecoded {
        uplink,
        pdu: body[HEADER_LEN..HEADER_LEN + length].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(ext_header_version: u8, pdu: &[u8]) -> Vec<u8> {
        let mut b = vec![ext_header_version, 0, 0, 0]; // rrc_rel, minor, major unused here
        b.extend_from_slice(pdu);
        b
    }

    #[test]
    fn decodes_downlink_esm() {
        let pdu = [0x01, 0x02, 0x03];
        let body = build(9, &pdu);
        let decoded = decode(0xB0E2, &body).unwrap();
        assert_eq!(decoded.direction, Direction::Downlink);
        assert_eq!(decoded.ext_header_version, 9);
        assert_eq!(decoded.pdu, pdu.to_vec());
    }

    #[test]
    fn decodes_uplink_esm() {
        let body = build(9, &[0xAA]);
        assert_eq!(decode(0xB0E3, &body).unwrap().direction, Direction::Uplink);
    }

    #[test]
    fn decodes_downlink_and_uplink_emm() {
        let body = build(9, &[0xBB]);
        assert_eq!(decode(0xB0EC, &body).unwrap().direction, Direction::Downlink);
        assert_eq!(decode(0xB0ED, &body).unwrap().direction, Direction::Uplink);
    }

    #[test]
    fn rejects_non_nas_log_type() {
        assert_eq!(
            decode(0xB0C0, &build(9, &[0])),
            Err(DecodeError::NotANasLogType(0xB0C0))
        );
    }

    #[test]
    fn rejects_body_shorter_than_the_fixed_header() {
        assert_eq!(decode(0xB0E2, &[1, 2]), Err(DecodeError::TooShort));
    }

    #[test]
    fn empty_pdu_after_header_is_valid_not_an_error() {
        let decoded = decode(0xB0E2, &build(9, &[])).unwrap();
        assert_eq!(decoded.pdu, Vec::<u8>::new());
    }

    #[test]
    fn is_nas_log_type_recognizes_all_four_codes_and_rejects_others() {
        for code in [0xB0E2, 0xB0E3, 0xB0EC, 0xB0ED] {
            assert!(is_nas_log_type(code));
        }
        assert!(!is_nas_log_type(0xB0C0));
    }

    fn build_umts(uplink: bool, pdu: &[u8]) -> Vec<u8> {
        let mut b = vec![uplink as u8];
        b.extend_from_slice(&(pdu.len() as u32).to_le_bytes());
        b.extend_from_slice(pdu);
        b
    }

    #[test]
    fn decodes_umts_downlink_and_uplink() {
        let dl = decode_umts(&build_umts(false, &[0x11, 0x22])).unwrap();
        assert!(!dl.uplink);
        assert_eq!(dl.pdu, vec![0x11, 0x22]);

        let ul = decode_umts(&build_umts(true, &[0x33])).unwrap();
        assert!(ul.uplink);
        assert_eq!(ul.pdu, vec![0x33]);
    }

    #[test]
    fn umts_rejects_length_running_past_available_data() {
        let mut body = build_umts(false, &[0xAA]);
        // overwrite the 4-byte length field to claim more than is present
        body[1..5].copy_from_slice(&100u32.to_le_bytes());
        assert!(matches!(
            decode_umts(&body),
            Err(UmtsDecodeError::LengthExceedsAvailableData { .. })
        ));
    }

    #[test]
    fn umts_rejects_body_shorter_than_the_fixed_header() {
        assert_eq!(decode_umts(&[0, 0, 0]), Err(UmtsDecodeError::TooShort));
    }

    #[test]
    fn umts_empty_pdu_is_valid_not_an_error() {
        let decoded = decode_umts(&build_umts(false, &[])).unwrap();
        assert_eq!(decoded.pdu, Vec::<u8>::new());
    }
}
