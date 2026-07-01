//! NAS Information Element parsing (3GPP TS 24.301 / TS 24.008), built on
//! top of [`crate::nas::decode`]'s raw PDU extraction — interprets
//! specific message types' content instead of just passing bytes
//! through. NAS is a hand-parseable format (fixed mandatory IEs by
//! message type at known positions, then tagged optional IEs), not
//! ASN.1 — tractable in a way RRC content isn't (see `crate::rrc`'s and
//! ROADMAP.md's notes on why RRC-content heuristics are scoped
//! separately).
//!
//! **Confidence varies by function — read each one's doc comment.** The
//! message envelope (protocol discriminator + message type) and the
//! Mobile Identity BCD encoding are standard, simple, well-documented
//! formats with high confidence. Exact optional-IE tag values (e.g.
//! which byte marks "this TLV is a GUTI") are lower confidence and
//! flagged as such — no real EMM/ESM traffic has been captured from the
//! target device yet to verify against (same gap noted for RRC/NAS in
//! ARCHITECTURE.md).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolDiscriminator {
    Esm,
    Emm,
    Other(u8),
}

/// Byte 0 of any NAS message: security header type (high nibble) +
/// protocol discriminator (low nibble) — TS 24.007 §11.2.3.1.1, the
/// standard NAS message envelope, true regardless of which Qualcomm log
/// type (ESM-in/out or EMM-in/out) delivered the bytes.
pub fn protocol_discriminator(pdu: &[u8]) -> Option<ProtocolDiscriminator> {
    let byte = *pdu.first()?;
    Some(match byte & 0x0F {
        0x2 => ProtocolDiscriminator::Esm,
        0x7 => ProtocolDiscriminator::Emm,
        other => ProtocolDiscriminator::Other(other),
    })
}

/// Byte 1: the message type (TS 24.301 Table 9.8.1 for EMM, 9.9.2 for ESM).
pub fn message_type(pdu: &[u8]) -> Option<u8> {
    pdu.get(1).copied()
}

/// Well-known EMM message type codes (TS 24.301 Table 9.8.1).
pub mod emm_message_type {
    pub const ATTACH_ACCEPT: u8 = 0x42;
    pub const IDENTITY_REQUEST: u8 = 0x55;
    pub const IDENTITY_RESPONSE: u8 = 0x56;
    pub const SECURITY_MODE_COMMAND: u8 = 0x5D;
    pub const GUTI_REALLOCATION_COMMAND: u8 = 0x50;
    pub const TRACKING_AREA_UPDATE_ACCEPT: u8 = 0x49;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityType {
    Imsi,
    Imei,
    Imeisv,
    Tmsi,
    Other(u8),
}

/// Identity Request's requested identity type — TS 24.301 §9.9.3.24
/// "Identity type 2", the low 3 bits of the byte right after
/// `message_type`. Fixed position (Identity Request has exactly one
/// mandatory IE), high confidence.
pub fn identity_request_type(pdu: &[u8]) -> Option<IdentityType> {
    if message_type(pdu) != Some(emm_message_type::IDENTITY_REQUEST) {
        return None;
    }
    let byte = *pdu.get(2)?;
    Some(match byte & 0x07 {
        1 => IdentityType::Imsi,
        2 => IdentityType::Imei,
        3 => IdentityType::Imeisv,
        4 => IdentityType::Tmsi,
        other => IdentityType::Other(other),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityAlgorithms {
    /// EPS encryption algorithm ID. 0 = EEA0 (null cipher).
    pub ciphering: u8,
    /// EPS integrity algorithm ID. 0 = EIA0 (null integrity).
    pub integrity: u8,
}

impl SecurityAlgorithms {
    pub fn is_null_cipher(&self) -> bool {
        self.ciphering == 0
    }
    pub fn is_null_integrity(&self) -> bool {
        self.integrity == 0
    }
}

/// Security Mode Command's selected algorithms — TS 24.301 §9.9.3.32
/// "NAS security algorithms": one octet, upper nibble ciphering, lower
/// nibble integrity, algorithm ID 0 meaning null in both (TS 33.401).
/// Fixed position (first mandatory IE after message_type), high
/// confidence in the encoding; the exact byte offset for this specific
/// message (whether anything precedes it) isn't verified against a real
/// captured sample.
pub fn security_mode_command_algorithms(pdu: &[u8]) -> Option<SecurityAlgorithms> {
    if message_type(pdu) != Some(emm_message_type::SECURITY_MODE_COMMAND) {
        return None;
    }
    let byte = *pdu.get(2)?;
    Some(SecurityAlgorithms {
        ciphering: (byte >> 4) & 0x0F,
        integrity: byte & 0x0F,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MobileIdentity {
    Imsi(String),
    Imei(String),
    Imeisv(String),
    Tmsi(u32),
    Guti { mmegi: u16, mmec: u8, m_tmsi: u32 },
    Unknown { type_code: u8, raw: Vec<u8> },
}

/// Decodes a Mobile Identity IE's *value* bytes (TS 24.008 §10.5.1.4) —
/// the BCD-digit format used to carry IMSI/IMEI/IMEISV/TMSI/GUTI.
/// Standard, simple, well-documented encoding: low 3 bits of the first
/// byte give the identity type, bit 3 gives odd/even digit count for the
/// BCD forms, remaining nibbles are digits (0xF is a filler on odd-length
/// values). High confidence in the general format; TMSI/GUTI's specific
/// sub-field bit-widths (mmegi/mmec split) are the part worth treating as
/// a first cut, not a verified-against-real-traffic one.
pub fn decode_mobile_identity(value: &[u8]) -> Option<MobileIdentity> {
    let first = *value.first()?;
    let type_code = first & 0x07;
    // Bit 3 ("odd/even indicator") is redundant with the 0xF filler
    // convention below for decoding purposes — a filler nibble only
    // ever appears when the count is even, and the loop already detects
    // it directly, so there's nothing left for this flag to gate. Not
    // read here; the wire bit still exists, just isn't needed twice.

    match type_code {
        1 | 2 | 3 => {
            // IMSI / IMEI / IMEISV: BCD digits, first digit in the high
            // nibble of byte 0, then two digits per subsequent byte
            // (low nibble first, then high nibble unless it's the 0xF
            // filler that pads an even-length value to a whole byte).
            let mut digits = String::new();
            digits.push(bcd_digit_char(first >> 4));
            for &byte in &value[1..] {
                digits.push(bcd_digit_char(byte & 0x0F));
                let high = byte >> 4;
                if high != 0x0F {
                    digits.push(bcd_digit_char(high));
                }
            }
            Some(match type_code {
                1 => MobileIdentity::Imsi(digits),
                2 => MobileIdentity::Imei(digits),
                _ => MobileIdentity::Imeisv(digits),
            })
        }
        4 => {
            // TMSI: 4 raw bytes following the first byte, big-endian.
            if value.len() < 5 {
                return None;
            }
            Some(MobileIdentity::Tmsi(u32::from_be_bytes(
                value[1..5].try_into().ok()?,
            )))
        }
        6 => {
            // GUTI: MCC/MNC (3 BCD bytes) + MME group ID (2 bytes) + MME
            // code (1 byte) + M-TMSI (4 bytes). Sub-field widths here are
            // a first cut from the general GUTI structure in TS
            // 24.301 §9.9.3.12, not verified against a captured sample.
            if value.len() < 11 {
                return None;
            }
            let mmegi = u16::from_be_bytes(value[4..6].try_into().ok()?);
            let mmec = value[6];
            let m_tmsi = u32::from_be_bytes(value[7..11].try_into().ok()?);
            Some(MobileIdentity::Guti { mmegi, mmec, m_tmsi })
        }
        other => Some(MobileIdentity::Unknown {
            type_code: other,
            raw: value.to_vec(),
        }),
    }
}

fn bcd_digit_char(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        _ => '?',
    }
}

/// Identity Response's Mobile Identity IE — TS 24.301 §8.2.22, a single
/// mandatory LV IE right after `message_type`: one length byte, then the
/// Mobile Identity value (see [`decode_mobile_identity`]).
pub fn identity_response_identity(pdu: &[u8]) -> Option<MobileIdentity> {
    if message_type(pdu) != Some(emm_message_type::IDENTITY_RESPONSE) {
        return None;
    }
    let len = *pdu.get(2)? as usize;
    let value = pdu.get(3..3 + len)?;
    decode_mobile_identity(value)
}

/// **Best-effort, not verified.** Scans an Attach Accept or GUTI
/// Reallocation Command's optional TLV IEs for a GUTI, using `0x50` as
/// the assumed "EPS mobile identity" IEI — a value that recurs across
/// several NAS optional-IE catalogs for this purpose, but hasn't been
/// confirmed against this specific message type's real IE table or a
/// captured sample. Returns the first plausible match; may return `None`
/// on a real message that does carry a GUTI if the tag assumption is
/// wrong, or (much less likely) misidentify an unrelated TLV that
/// happens to share the tag byte.
pub fn scan_for_guti(pdu: &[u8]) -> Option<MobileIdentity> {
    const ASSUMED_GUTI_IEI: u8 = 0x50;
    let mut offset = 3; // skip envelope byte + message_type + first mandatory IE byte
    while offset + 1 < pdu.len() {
        let tag = pdu[offset];
        let len = *pdu.get(offset + 1)? as usize;
        let value = pdu.get(offset + 2..offset + 2 + len)?;
        if tag == ASSUMED_GUTI_IEI {
            if let Some(identity @ MobileIdentity::Guti { .. }) = decode_mobile_identity(value) {
                return Some(identity);
            }
        }
        offset += 2 + len;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_discriminator_recognizes_esm_and_emm() {
        assert_eq!(protocol_discriminator(&[0x02]), Some(ProtocolDiscriminator::Esm));
        assert_eq!(protocol_discriminator(&[0x07]), Some(ProtocolDiscriminator::Emm));
        assert_eq!(protocol_discriminator(&[0x09]), Some(ProtocolDiscriminator::Other(9)));
    }

    #[test]
    fn identity_request_extracts_requested_type() {
        let pdu = [0x07, emm_message_type::IDENTITY_REQUEST, 0x01]; // requesting IMSI
        assert_eq!(identity_request_type(&pdu), Some(IdentityType::Imsi));
    }

    #[test]
    fn identity_request_type_returns_none_for_a_different_message() {
        let pdu = [0x07, emm_message_type::ATTACH_ACCEPT, 0x01];
        assert_eq!(identity_request_type(&pdu), None);
    }

    #[test]
    fn security_mode_command_detects_null_cipher_and_null_integrity() {
        let pdu = [0x07, emm_message_type::SECURITY_MODE_COMMAND, 0x00];
        let algos = security_mode_command_algorithms(&pdu).unwrap();
        assert!(algos.is_null_cipher());
        assert!(algos.is_null_integrity());
    }

    #[test]
    fn security_mode_command_detects_real_algorithms_as_not_null() {
        // ciphering=2 (EEA2/AES), integrity=2 (EIA2/AES)
        let pdu = [0x07, emm_message_type::SECURITY_MODE_COMMAND, 0x22];
        let algos = security_mode_command_algorithms(&pdu).unwrap();
        assert!(!algos.is_null_cipher());
        assert!(!algos.is_null_integrity());
        assert_eq!(algos.ciphering, 2);
        assert_eq!(algos.integrity, 2);
    }

    #[test]
    fn decodes_imsi_with_odd_digit_count_no_filler() {
        // Encodes "12345": byte0 = digit1(high nibble)=1 | odd-bit=1 | type=1,
        // byte1 = digit3<<4 | digit2, byte2 = digit5<<4 | digit4.
        let value = [0x19, 0x32, 0x54];
        assert_eq!(
            decode_mobile_identity(&value),
            Some(MobileIdentity::Imsi("12345".to_string()))
        );
    }

    #[test]
    fn decodes_imsi_with_even_digit_count_and_filler_nibble() {
        // Encodes "1234": byte0 = digit1=1 | odd-bit=0 | type=1 -> 0x11,
        // byte1 = digit3<<4 | digit2 -> 0x32, byte2 = filler(0xF)<<4 | digit4 -> 0xF4.
        let value = [0x11, 0x32, 0xF4];
        assert_eq!(
            decode_mobile_identity(&value),
            Some(MobileIdentity::Imsi("1234".to_string()))
        );
    }

    #[test]
    fn decodes_tmsi_as_four_raw_bytes() {
        let value = [0x04, 0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(
            decode_mobile_identity(&value),
            Some(MobileIdentity::Tmsi(0xDEADBEEF))
        );
    }

    #[test]
    fn identity_response_extracts_mobile_identity() {
        let mut pdu = vec![0x07, emm_message_type::IDENTITY_RESPONSE];
        let identity_value = [0x04u8, 0xAA, 0xBB, 0xCC, 0xDD]; // TMSI
        pdu.push(identity_value.len() as u8);
        pdu.extend_from_slice(&identity_value);
        assert_eq!(
            identity_response_identity(&pdu),
            Some(MobileIdentity::Tmsi(0xAABBCCDD))
        );
    }

    #[test]
    fn scan_for_guti_finds_a_tagged_guti_ie() {
        let mut pdu = vec![0x07, emm_message_type::ATTACH_ACCEPT, 0x00]; // dummy first mandatory IE byte
        // unrelated TLV first, to prove scanning skips it correctly
        pdu.extend_from_slice(&[0x99, 0x02, 0xAA, 0xBB]);
        // GUTI TLV: tag 0x50, then an 11-byte GUTI value
        let mut guti_value = vec![0x06u8]; // type=6 (GUTI), odd bit unused here
        guti_value.extend_from_slice(&[0x00, 0x00, 0x00]); // MCC/MNC (unused by decoder beyond skipping)
        guti_value.extend_from_slice(&0x1234u16.to_be_bytes()); // mmegi
        guti_value.push(0x56); // mmec
        guti_value.extend_from_slice(&0xAABBCCDDu32.to_be_bytes()); // m_tmsi
        pdu.push(0x50);
        pdu.push(guti_value.len() as u8);
        pdu.extend_from_slice(&guti_value);

        assert_eq!(
            scan_for_guti(&pdu),
            Some(MobileIdentity::Guti { mmegi: 0x1234, mmec: 0x56, m_tmsi: 0xAABBCCDD })
        );
    }

    #[test]
    fn scan_for_guti_returns_none_when_absent() {
        let pdu = vec![0x07, emm_message_type::ATTACH_ACCEPT, 0x00, 0x99, 0x02, 0xAA, 0xBB];
        assert_eq!(scan_for_guti(&pdu), None);
    }
}
