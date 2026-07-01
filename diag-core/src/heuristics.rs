//! IMSI-catcher detection heuristics operating on decoded NAS and RRC
//! content.
//!
//! NAS-layer checks (`imsi_requested`, `nas_null_cipher`) work directly
//! off raw PDU extraction. RRC-layer checks
//! (`connection_redirect_2g_downgrade`, `lte_sib6_and_7_downgrade`,
//! `incomplete_sib`) need real ASN.1 content decode — see
//! `crate::rrc_content` for that, and its module docs for the honesty
//! caveat on `channel_hint`-dependent dispatch reliability.
//!
//! **Not implemented**: AS/RRC-layer `null_cipher` (a *different*
//! Security Mode Command than the NAS one — LTE has two independent
//! security contexts). The RRC decoder now exists and could support this;
//! it just hasn't been written yet. Not the same as the deliberate
//! Event/F3-mask deferral elsewhere in this project — this one's just
//! not done, not "can't verify the format."

use crate::{log, nas, nas_ie, rrc, rrc_content};

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

/// Runs every heuristic applicable to one decoded LOG message — NAS or
/// RRC, whichever `header.log_type` indicates. Returns whatever fired;
/// usually zero or one, not mutually exclusive by design. Anything that
/// fails to decode or doesn't match a known message shape yields no
/// detections (this is a detector, not a validator).
pub fn analyze(header: &log::Header, body: &[u8]) -> Vec<Detection> {
    if nas::is_nas_log_type(header.log_type) || header.log_type == nas::UMTS_NAS_OTA {
        return analyze_nas(header, body);
    }
    if header.log_type == 0xB0C0 {
        return analyze_rrc(body);
    }
    Vec::new()
}

fn analyze_nas(header: &log::Header, body: &[u8]) -> Vec<Detection> {
    let Some(pdu) = extract_nas_pdu(header, body) else {
        return Vec::new();
    };
    [check_imsi_requested(&pdu), check_nas_null_cipher(&pdu)]
        .into_iter()
        .flatten()
        .collect()
}

fn analyze_rrc(body: &[u8]) -> Vec<Detection> {
    let Ok(decoded) = rrc::decode(body) else {
        return Vec::new();
    };
    match decoded.header.channel_hint() {
        rrc::ChannelHint::DlDcch => rrc_content::check_connection_redirect(&decoded.pdu)
            .into_iter()
            .collect(),
        rrc::ChannelHint::BcchDlSch => [
            rrc_content::check_sib_downgrade_broadcast(&decoded.pdu),
            rrc_content::check_incomplete_sib(&decoded.pdu),
        ]
        .into_iter()
        .flatten()
        .collect(),
        _ => Vec::new(),
    }
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
    fn rrc_log_type_with_unclassifiable_channel_yields_no_detections() {
        // channel_hint() falls back to Unknown for pdu_num values outside
        // 1-8 (see rrc.rs) - an all-zero body decodes cleanly (pdu_num=0)
        // but isn't routed to either RRC check, so this should be empty
        // without erroring, not "ignored" the way a genuinely unhandled
        // log_type would be.
        let header = test_header(0xB0C0);
        let detections = analyze(&header, &[0u8; 20]);
        assert!(detections.is_empty());
    }

    #[test]
    fn unrelated_log_type_yields_no_detections() {
        let header = test_header(0x18A7); // an internal-plane type, not NAS or RRC
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
