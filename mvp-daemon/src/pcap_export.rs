//! Converts an archived raw capture to a pcap file: walks the archive's
//! concatenated Log messages, decodes RRC OTA and plain NAS bodies (the
//! same scope the pre-clean-room daemon's pcap export had — nothing
//! broader), wraps each as GSMTAP, and writes a classic pcap file.
//! Everything else is skipped, not decoded here (spec §7 — internal-plane
//! log types need their own, separately-scoped decoders).

use diag_core::{gsmtap, log, nas, pcap, rrc};

fn channel_hint_to_gsmtap_subtype(hint: rrc::ChannelHint) -> u8 {
    match hint {
        rrc::ChannelHint::BcchBch => gsmtap::LTE_RRC_SUBTYPE_BCCH_BCH,
        rrc::ChannelHint::BcchDlSch => gsmtap::LTE_RRC_SUBTYPE_BCCH_DL_SCH,
        rrc::ChannelHint::Mcch => gsmtap::LTE_RRC_SUBTYPE_MCCH,
        rrc::ChannelHint::Pcch => gsmtap::LTE_RRC_SUBTYPE_PCCH,
        rrc::ChannelHint::DlCcch => gsmtap::LTE_RRC_SUBTYPE_DL_CCCH,
        rrc::ChannelHint::DlDcch => gsmtap::LTE_RRC_SUBTYPE_DL_DCCH,
        rrc::ChannelHint::UlCcch => gsmtap::LTE_RRC_SUBTYPE_UL_CCCH,
        rrc::ChannelHint::UlDcch => gsmtap::LTE_RRC_SUBTYPE_UL_DCCH,
        rrc::ChannelHint::Unknown => gsmtap::LTE_RRC_SUBTYPE_UNKNOWN,
    }
}

fn channel_hint_is_uplink(hint: rrc::ChannelHint) -> bool {
    matches!(hint, rrc::ChannelHint::UlCcch | rrc::ChannelHint::UlDcch)
}

fn rrc_gsmtap_payload(body: &[u8]) -> Option<Vec<u8>> {
    let decoded = rrc::decode(body).ok()?;
    let hint = decoded.header.channel_hint();
    let header = gsmtap::lte_rrc_header(
        channel_hint_to_gsmtap_subtype(hint),
        channel_hint_is_uplink(hint),
        decoded.header.earfcn as u16,
        decoded.header.sfn,
        decoded.header.subfn,
    );
    let mut payload = header.to_vec();
    payload.extend_from_slice(&decoded.pdu);
    Some(payload)
}

fn nas_gsmtap_payload(log_type: u16, body: &[u8]) -> Option<Vec<u8>> {
    let decoded = nas::decode(log_type, body).ok()?;
    let header = gsmtap::lte_nas_header(decoded.direction == nas::Direction::Uplink);
    let mut payload = header.to_vec();
    payload.extend_from_slice(&decoded.pdu);
    Some(payload)
}

/// Converts `raw` (a decompressed archive: concatenated decapsulated Log
/// messages, no delimiter) into a complete pcap file's bytes.
pub fn convert(raw: &[u8]) -> Vec<u8> {
    let mut out = pcap::global_header().to_vec();
    let mut identification: u16 = 0;

    for (header, body) in log::walk(raw) {
        let gsmtap_payload = if header.log_type == 0xB0C0 {
            rrc_gsmtap_payload(body)
        } else if nas::is_nas_log_type(header.log_type) {
            nas_gsmtap_payload(header.log_type, body)
        } else {
            None
        };

        let Some(payload) = gsmtap_payload else {
            continue;
        };
        let unix_millis = log::to_unix_millis(header.timestamp_raw);
        out.extend_from_slice(&pcap::packet_record(&payload, unix_millis, identification));
        identification = identification.wrapping_add(1);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_log_message(log_type: u16, timestamp_raw: u64, body: &[u8]) -> Vec<u8> {
        let inner_length = (12 + body.len()) as u16;
        let mut v = vec![log::LOG_DISCRIMINANT, 0];
        v.extend_from_slice(&inner_length.to_le_bytes()); // outer_length
        v.extend_from_slice(&inner_length.to_le_bytes()); // inner_length
        v.extend_from_slice(&log_type.to_le_bytes());
        v.extend_from_slice(&timestamp_raw.to_le_bytes());
        v.extend_from_slice(body);
        v
    }

    fn build_rrc_body(pdu: &[u8]) -> Vec<u8> {
        let mut b = vec![2u8, 0, 0]; // ext_header_version=2 (v0 layout), rel_maj, rel_min
        b.push(0); // bearer_id
        b.extend_from_slice(&0u16.to_le_bytes()); // phy_cell_id
        b.extend_from_slice(&0u16.to_le_bytes()); // earfcn
        b.extend_from_slice(&0u16.to_le_bytes()); // sfn_subfn
        b.push(6); // pdu_num -> DlCcch
        b.extend_from_slice(&(pdu.len() as u16).to_le_bytes());
        b.extend_from_slice(pdu);
        b
    }

    fn build_nas_body(pdu: &[u8]) -> Vec<u8> {
        let mut b = vec![9u8, 0, 0, 0]; // ext_header_version, rrc_rel, minor, major
        b.extend_from_slice(pdu);
        b
    }

    #[test]
    fn converts_rrc_and_nas_messages_into_pcap_records_and_skips_everything_else() {
        let mut raw = Vec::new();
        raw.extend(build_log_message(0xB0C0, 1, &build_rrc_body(&[0xAA, 0xBB])));
        raw.extend(build_log_message(0xB0E2, 2, &build_nas_body(&[0xCC])));
        raw.extend(build_log_message(0x18A7, 3, &[0x00; 20])); // internal-plane, not exported

        let pcap_bytes = convert(&raw);

        // global header (24) + 2 packet records, each: 16 (pcap hdr) + 20
        // (ip) + 8 (udp) + 16 (gsmtap) + pdu
        let expected_len = 24
            + (16 + 20 + 8 + 16 + 2) // rrc record, 2-byte pdu
            + (16 + 20 + 8 + 16 + 1); // nas record, 1-byte pdu
        assert_eq!(pcap_bytes.len(), expected_len);
        assert_eq!(&pcap_bytes[0..4], &0xA1B2C3D4u32.to_le_bytes());
    }

    #[test]
    fn empty_input_produces_just_the_global_header() {
        let pcap_bytes = convert(&[]);
        assert_eq!(pcap_bytes.len(), 24);
    }

    #[test]
    fn a_message_with_undecodable_rrc_body_is_skipped_not_a_panic() {
        let mut raw = Vec::new();
        raw.extend(build_log_message(0xB0C0, 1, &[])); // empty body, decode() will reject it
        let pcap_bytes = convert(&raw);
        assert_eq!(pcap_bytes.len(), 24); // just the global header, message skipped
    }
}
