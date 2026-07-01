//! Real RRC content decode via the generated `lte-rrc-asn1` UPER codec —
//! the RRC-content heuristics (`connection_redirect_2g_downgrade`,
//! `lte_sib6_and_7_downgrade`, `incomplete_sib`) that raw PDU extraction
//! alone can't support, since they need to inspect specific IE values
//! inside the message, not just pass the bytes through.
//!
//! **Dispatch depends on `rrc::Header::channel_hint`, which is itself
//! explicitly best-effort** (see `crate::rrc` module docs) — a wrong
//! channel classification means attempting to decode against the wrong
//! top-level ASN.1 message type. UPER's structure usually (not always)
//! turns that into a clean decode error rather than silently producing
//! plausible-looking garbage, since tag/length/choice-index encoding
//! doesn't coincide by chance across unrelated message types — but
//! "usually" is doing real work in that sentence. Treat a successful
//! decode here as probable, not certain, until validated against real
//! captured traffic (none of this project's own hardware testing has
//! captured RRC signalling yet — see ARCHITECTURE.md).

use asn1_codecs::PerCodecData;
use asn1_codecs::uper::UperCodec;
use lte_rrc_asn1::lte_rrc::*;

use crate::heuristics::{Detection, Severity};

/// Attempts to decode a DL-DCCH PDU and check for a 2G/3G redirect in an
/// RRC Connection Release — a classic downgrade-attack signature. Call
/// this when `rrc::Header::channel_hint()` returned `DlDcch`.
pub fn check_connection_redirect(pdu: &[u8]) -> Option<Detection> {
    let mut data = PerCodecData::from_slice_uper(pdu);
    let msg = DL_DCCH_Message::uper_decode(&mut data).ok()?;

    let DL_DCCH_MessageType::C1(c1) = msg.message else {
        return None;
    };
    let DL_DCCH_MessageType_c1::RrcConnectionRelease(release) = c1 else {
        return None;
    };
    let RRCConnectionReleaseCriticalExtensions::C1(c1ext) = release.critical_extensions else {
        return None;
    };
    let RRCConnectionReleaseCriticalExtensions_c1::RrcConnectionRelease_r8(ies) = c1ext else {
        return None;
    };
    let redirect = ies.redirected_carrier_info?;

    let target = match redirect {
        RedirectedCarrierInfo::Geran(_) => "GERAN (2G)",
        RedirectedCarrierInfo::Utra_FDD(_) | RedirectedCarrierInfo::Utra_TDD(_) => "UTRA (3G)",
        RedirectedCarrierInfo::Utra_TDD_r10(_) => "UTRA (3G, r10)",
        _ => return None, // EUTRA / NR / CDMA2000 redirects aren't a downgrade
    };

    Some(Detection {
        heuristic: "connection_redirect_2g_downgrade",
        severity: Severity::High,
        description: format!(
            "RRC Connection Release redirected the device to {target} — forcing a downgrade \
             to weaker-security radio access is a well-known IMSI-catcher technique."
        ),
    })
}

/// Checks a BCCH-DL-SCH PDU (broadcast System Information) for SIB6/7 —
/// the SIBs carrying UTRA/GERAN reselection parameters. Their mere
/// presence isn't inherently malicious — legitimate networks broadcast
/// these for real inter-RAT reselection — so this is flagged
/// informational: a signal worth correlating with other findings, not a
/// standalone alarm. Call this when `channel_hint()` returned `BcchDlSch`.
pub fn check_sib_downgrade_broadcast(pdu: &[u8]) -> Option<Detection> {
    let mut data = PerCodecData::from_slice_uper(pdu);
    let msg = BCCH_DL_SCH_Message::uper_decode(&mut data).ok()?;

    let BCCH_DL_SCH_MessageType::C1(c1) = msg.message else {
        return None;
    };
    let BCCH_DL_SCH_MessageType_c1::SystemInformation(si) = c1 else {
        return None;
    };
    let SystemInformationCriticalExtensions::SystemInformation_r8(ies) = si.critical_extensions
    else {
        return None;
    };

    let has_sib6 = ies
        .sib_type_and_info
        .0
        .iter()
        .any(|e| matches!(e, SystemInformation_r8_IEsSib_TypeAndInfo_Entry::Sib6(_)));
    let has_sib7 = ies
        .sib_type_and_info
        .0
        .iter()
        .any(|e| matches!(e, SystemInformation_r8_IEsSib_TypeAndInfo_Entry::Sib7(_)));

    if !has_sib6 && !has_sib7 {
        return None;
    }

    let which = match (has_sib6, has_sib7) {
        (true, true) => "SIB6 and SIB7",
        (true, false) => "SIB6",
        _ => "SIB7",
    };
    Some(Detection {
        heuristic: "lte_sib6_and_7_downgrade",
        severity: Severity::Low,
        description: format!(
            "Cell is broadcasting {which} — carries UTRA/GERAN reselection parameters. Not \
             inherently malicious on its own; worth correlating with other findings."
        ),
    })
}

/// Flags a BCCH-DL-SCH PDU that fails to decode as valid RRC content —
/// a malformed/truncated broadcast can indicate a non-compliant (possibly
/// fake) base station. **Only call this when the caller already knows,
/// from `channel_hint()`, that this PDU claims to be a BCCH/SIB-bearing
/// channel** — calling it on an arbitrary/misclassified PDU would count
/// ordinary channel-hint misclassification as a false "incomplete SIB",
/// since decode failure is the expected outcome of decoding the wrong
/// message type on purpose, not evidence of malformation.
pub fn check_incomplete_sib(pdu: &[u8]) -> Option<Detection> {
    let mut data = PerCodecData::from_slice_uper(pdu);
    match BCCH_DL_SCH_Message::uper_decode(&mut data) {
        Ok(_) => None,
        Err(_) => Some(Detection {
            heuristic: "incomplete_sib",
            severity: Severity::Medium,
            description: "A broadcast claiming to be System Information failed to decode as \
                valid RRC content. Could indicate a malformed broadcast from a non-compliant \
                base station, or a channel misclassification artifact — see this function's \
                own doc comment on the precondition for calling it."
                .to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests exercise the *dispatch and pattern-matching plumbing*
    // with garbage/empty input, not real decoded content - there's no
    // real captured RRC sample to build a genuine positive-case fixture
    // from (see module docs). They confirm the functions don't panic and
    // correctly return None on non-matching content; they do not confirm
    // the positive-detection path against a known-good encoded message.

    #[test]
    fn connection_redirect_returns_none_on_empty_input() {
        assert_eq!(check_connection_redirect(&[]), None);
    }

    #[test]
    fn connection_redirect_returns_none_on_garbage() {
        assert_eq!(check_connection_redirect(&[0xFF; 20]), None);
    }

    #[test]
    fn sib_downgrade_returns_none_on_empty_input() {
        assert_eq!(check_sib_downgrade_broadcast(&[]), None);
    }

    #[test]
    fn incomplete_sib_flags_undecodable_content() {
        // Empty input can't possibly be a valid SIB - should flag, not panic.
        let detection = check_incomplete_sib(&[]);
        assert!(detection.is_some());
        assert_eq!(detection.unwrap().heuristic, "incomplete_sib");
    }
}
