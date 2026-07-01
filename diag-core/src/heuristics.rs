//! IMSI-catcher detection heuristics operating on decoded NAS content.
//!
//! **NAS-layer only.** LTE has two independent security contexts — NAS
//! (this module can check it: `nas_null_cipher`) and AS/RRC (a separate
//! Security Mode Command carried in RRC, which needs real ASN.1 decode
//! this project doesn't have yet — see ROADMAP.md for `null_cipher` and
//! the other RRC-dependent heuristics, deliberately not attempted here
//! rather than faked).

use crate::{log, nas, nas_ie};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    pub heuristic: &'static str,
    pub severity: Severity,
    pub description: String,
}

/// Runs every NAS-layer heuristic against one decoded LOG message.
/// Returns whatever fired — usually zero or one, but not mutually
/// exclusive by design. Silently returns nothing for non-NAS messages or
/// anything that fails to decode (this is a detector, not a validator —
/// a message it can't parse isn't itself a finding).
pub fn analyze(header: &log::Header, body: &[u8]) -> Vec<Detection> {
    let pdu = match extract_nas_pdu(header, body) {
        Some(pdu) => pdu,
        None => return Vec::new(),
    };

    [check_imsi_requested(&pdu), check_nas_null_cipher(&pdu)]
        .into_iter()
        .flatten()
        .collect()
}

fn extract_nas_pdu(header: &log::Header, body: &[u8]) -> Option<Vec<u8>> {
    if nas::is_nas_log_type(header.log_type) {
        nas::decode(header.log_type, body).ok().map(|d| d.pdu)
    } else if header.log_type == nas::UMTS_NAS_OTA {
        nas::decode_umts(body).ok().map(|d| d.pdu)
    } else {
        None
    }
}

fn check_imsi_requested(pdu: &[u8]) -> Option<Detection> {
    match nas_ie::identity_request_type(pdu) {
        Some(nas_ie::IdentityType::Imsi) => Some(Detection {
            heuristic: "imsi_requested",
            severity: Severity::High,
            description:
                "Network sent an Identity Request asking for IMSI specifically. Legitimate \
                 networks rarely need the raw IMSI once a device already has a GUTI — a \
                 well-known IMSI-catcher signature."
                    .to_string(),
        }),
        _ => None,
    }
}

fn check_nas_null_cipher(pdu: &[u8]) -> Option<Detection> {
    let algos = nas_ie::security_mode_command_algorithms(pdu)?;
    if !algos.is_null_cipher() {
        return None;
    }
    Some(Detection {
        heuristic: "nas_null_cipher",
        severity: Severity::High,
        description: format!(
            "NAS Security Mode Command selected EEA0 (null ciphering). Legitimate only for \
             emergency-call sessions; otherwise a strong signal of a null-cipher downgrade. \
             NAS integrity algorithm: {}.",
            if algos.is_null_integrity() {
                "also null (EIA0)"
            } else {
                "non-null"
            }
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_imsi_requested() {
        let pdu = [0x07, 0x55, 0x01]; // Identity Request, type=IMSI
        let header = test_header(0xB0EC);
        let detections = analyze(&header, &wrap_nas_body(&pdu));
        assert!(detections.iter().any(|d| d.heuristic == "imsi_requested"));
    }

    #[test]
    fn does_not_flag_identity_request_for_imei() {
        let pdu = [0x07, 0x55, 0x02]; // Identity Request, type=IMEI
        let header = test_header(0xB0EC);
        let detections = analyze(&header, &wrap_nas_body(&pdu));
        assert!(!detections.iter().any(|d| d.heuristic == "imsi_requested"));
    }

    #[test]
    fn detects_nas_null_cipher() {
        let pdu = [0x07, 0x5D, 0x00]; // Security Mode Command, EEA0/EIA0
        let header = test_header(0xB0EC);
        let detections = analyze(&header, &wrap_nas_body(&pdu));
        assert!(detections.iter().any(|d| d.heuristic == "nas_null_cipher"));
    }

    #[test]
    fn does_not_flag_real_ciphering() {
        let pdu = [0x07, 0x5D, 0x22]; // Security Mode Command, EEA2/EIA2
        let header = test_header(0xB0EC);
        let detections = analyze(&header, &wrap_nas_body(&pdu));
        assert!(detections.is_empty());
    }

    #[test]
    fn ignores_non_nas_log_types() {
        let header = test_header(0xB0C0); // RRC, not NAS
        let detections = analyze(&header, &[0u8; 20]);
        assert!(detections.is_empty());
    }

    #[test]
    fn does_not_panic_on_garbage_body() {
        let header = test_header(0xB0EC);
        let detections = analyze(&header, &[0xFFu8; 2]); // too short to be a real NAS PDU
        assert!(detections.is_empty());
    }

    fn test_header(log_type: u16) -> log::Header {
        log::Header {
            pending_msgs: 0,
            outer_length: 0,
            inner_length: 0,
            log_type,
            timestamp_raw: 0,
        }
    }

    /// nas::decode expects the vendored-envelope shape (ext_header_version
    /// + rrc_rel + rrc_version_minor + rrc_version_major, then the plain
    /// NAS PDU) — wraps a bare NAS PDU with that 4-byte prefix for tests.
    fn wrap_nas_body(nas_pdu: &[u8]) -> Vec<u8> {
        let mut body = vec![9u8, 0, 0, 0];
        body.extend_from_slice(nas_pdu);
        body
    }
}
