//! LTE RRC OTA log record decode (log_type `0xB0C0`) — spec §7.
//!
//! Header layout is versioned (a leading `ext_header_version` byte selects
//! one of four field layouts, widening over time as firmware added
//! fields — wider EARFCN, an SIB mask, then NR release fields for
//! dual-connectivity). All four are simple fixed-position fields; decoded
//! with high confidence directly from the wire, not guessed.
//!
//! The one genuinely uncertain part: `pdu_num` selects an RRC channel
//! type (BCCH/PCCH/CCCH/DCCH, up/down), and the real mapping is
//! empirically reverse-engineered per firmware-version range across
//! several *different* lookup tables — not something safely
//! reconstructable from general protocol knowledge without real risk of
//! a silent transcription error. Rather than guess across that whole
//! matrix, this uses one reasonable default table and says so plainly:
//! [`Header::channel_hint`] is a best-effort classification, not a
//! verified one. The raw PDU bytes are always extracted correctly
//! regardless — worst case from a wrong hint is a mislabeled channel in
//! Wireshark, not lost or corrupted data.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub ext_header_version: u8,
    pub bearer_id: u8,
    pub phy_cell_id: u16,
    pub earfcn: u32,
    pub sfn: u32,
    pub subfn: u8,
    pub pdu_num: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    pub header: Header,
    pub pdu: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    TooShort,
    UnknownExtHeaderVersion(u8),
    PduLengthExceedsAvailableData { declared: usize, available: usize },
}

/// RRC channel type, for GSMTAP's subtype field. Coarse on purpose — see
/// module docs on why this is a hint, not a verified classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelHint {
    BcchBch,
    BcchDlSch,
    Mcch,
    Pcch,
    DlCcch,
    DlDcch,
    UlCcch,
    UlDcch,
    Unknown,
}

impl Header {
    /// Best-effort `pdu_num` -> channel mapping (see module docs).
    pub fn channel_hint(&self) -> ChannelHint {
        match self.pdu_num {
            1 => ChannelHint::BcchBch,
            2 => ChannelHint::BcchDlSch,
            3 => ChannelHint::Mcch,
            4 => ChannelHint::Pcch,
            5 => ChannelHint::DlCcch,
            6 => ChannelHint::DlDcch,
            7 => ChannelHint::UlCcch,
            8 => ChannelHint::UlDcch,
            _ => ChannelHint::Unknown,
        }
    }
}

fn u16le(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

fn u32le(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// Decodes an RRC OTA log record body (the bytes after the outer LOG
/// envelope header — i.e. starting with `ext_header_version`).
pub fn decode(body: &[u8]) -> Result<Decoded, DecodeError> {
    if body.is_empty() {
        return Err(DecodeError::TooShort);
    }
    let v = body[0];
    let rest = &body[1..];

    // Field widths grew across firmware versions: EARFCN widens at v>=8,
    // an SIB mask appears at v>=5, NR release fields appear at v>=25.
    let wide_earfcn = v >= 8;
    let has_sib_mask = v >= 5;
    let has_nr = v >= 25;

    let fixed_len = 2 // rrc_rel_maj, rrc_rel_min
        + if has_nr { 2 } else { 0 } // nr_rrc_rel_maj, nr_rrc_rel_min
        + 1 // bearer_id
        + 2 // phy_cell_id
        + if wide_earfcn { 4 } else { 2 } // earfcn
        + 2 // sfn_subfn
        + 1 // pdu_num
        + if has_sib_mask { 4 } else { 0 } // sib_mask
        + 2; // len
    if rest.len() < fixed_len {
        return Err(DecodeError::TooShort);
    }

    let mut off = 2; // skip rrc_rel_maj, rrc_rel_min
    if has_nr {
        off += 2; // nr_rrc_rel_maj, nr_rrc_rel_min
    }
    let bearer_id = rest[off];
    off += 1;
    let phy_cell_id = u16le(rest, off);
    off += 2;
    let earfcn = if wide_earfcn {
        let e = u32le(rest, off);
        off += 4;
        e
    } else {
        let e = u16le(rest, off) as u32;
        off += 2;
        e
    };
    let sfn_subfn = u16le(rest, off);
    off += 2;
    let pdu_num = rest[off];
    off += 1;
    if has_sib_mask {
        off += 4; // sib_mask — positional only, not exposed as a field yet
    }
    let len = u16le(rest, off) as usize;
    off += 2;

    if off + len > rest.len() {
        return Err(DecodeError::PduLengthExceedsAvailableData {
            declared: len,
            available: rest.len() - off,
        });
    }

    Ok(Decoded {
        header: Header {
            ext_header_version: v,
            bearer_id,
            phy_cell_id,
            earfcn,
            sfn: (sfn_subfn as u32) >> 4,
            subfn: (sfn_subfn & 0xf) as u8,
            pdu_num,
        },
        pdu: rest[off..off + len].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_v0(bearer_id: u8, phy_cell_id: u16, earfcn: u16, sfn_subfn: u16, pdu_num: u8, pdu: &[u8]) -> Vec<u8> {
        let mut b = vec![2u8]; // ext_header_version = 2 (falls in 0..=4)
        b.push(0); // rrc_rel_maj
        b.push(0); // rrc_rel_min
        b.push(bearer_id);
        b.extend_from_slice(&phy_cell_id.to_le_bytes());
        b.extend_from_slice(&earfcn.to_le_bytes());
        b.extend_from_slice(&sfn_subfn.to_le_bytes());
        b.push(pdu_num);
        b.extend_from_slice(&(pdu.len() as u16).to_le_bytes());
        b.extend_from_slice(pdu);
        b
    }

    fn build_v8(bearer_id: u8, phy_cell_id: u16, earfcn: u32, sfn_subfn: u16, pdu_num: u8, sib_mask: u32, pdu: &[u8]) -> Vec<u8> {
        let mut b = vec![10u8]; // falls in 8..=24
        b.push(0);
        b.push(0);
        b.push(bearer_id);
        b.extend_from_slice(&phy_cell_id.to_le_bytes());
        b.extend_from_slice(&earfcn.to_le_bytes());
        b.extend_from_slice(&sfn_subfn.to_le_bytes());
        b.push(pdu_num);
        b.extend_from_slice(&sib_mask.to_le_bytes());
        b.extend_from_slice(&(pdu.len() as u16).to_le_bytes());
        b.extend_from_slice(pdu);
        b
    }

    #[test]
    fn decodes_v0_layout_narrow_earfcn_no_sib_mask() {
        let pdu = [0xAA, 0xBB, 0xCC];
        let body = build_v0(5, 0x1234, 0x2710, 0x00A5, 6, &pdu);
        let decoded = decode(&body).unwrap();
        assert_eq!(decoded.header.ext_header_version, 2);
        assert_eq!(decoded.header.bearer_id, 5);
        assert_eq!(decoded.header.phy_cell_id, 0x1234);
        assert_eq!(decoded.header.earfcn, 0x2710);
        assert_eq!(decoded.header.pdu_num, 6);
        assert_eq!(decoded.pdu, pdu.to_vec());
    }

    #[test]
    fn decodes_v8_layout_wide_earfcn_with_sib_mask() {
        let pdu = [0x01, 0x02, 0x03, 0x04, 0x05];
        let body = build_v8(3, 0x5678, 0x00012345, 0x1234, 2, 0xDEADBEEF, &pdu);
        let decoded = decode(&body).unwrap();
        assert_eq!(decoded.header.ext_header_version, 10);
        assert_eq!(decoded.header.earfcn, 0x00012345);
        assert_eq!(decoded.header.pdu_num, 2);
        assert_eq!(decoded.pdu, pdu.to_vec());
    }

    #[test]
    fn sfn_and_subfn_split_correctly_from_combined_field() {
        // sfn_subfn packs sfn in the upper 12 bits, subfn in the lower 4
        let pdu = [0u8];
        let body = build_v0(0, 0, 0, 0b1010_1010_1010_0111, 1, &pdu);
        let decoded = decode(&body).unwrap();
        assert_eq!(decoded.header.subfn, 0b0111);
        assert_eq!(decoded.header.sfn, 0b1010_1010_1010);
    }

    #[test]
    fn rejects_empty_body() {
        assert_eq!(decode(&[]), Err(DecodeError::TooShort));
    }

    #[test]
    fn rejects_truncated_header() {
        assert_eq!(decode(&[2, 0, 0]), Err(DecodeError::TooShort));
    }

    #[test]
    fn rejects_pdu_length_running_past_available_data() {
        let mut body = build_v0(0, 0, 0, 0, 1, &[0xAA, 0xBB]);
        // overwrite the declared length (last two bytes before the PDU) to
        // claim more than is actually present
        let len_offset = body.len() - 2 - 2;
        body[len_offset..len_offset + 2].copy_from_slice(&100u16.to_le_bytes());
        assert!(matches!(
            decode(&body),
            Err(DecodeError::PduLengthExceedsAvailableData { .. })
        ));
    }

    #[test]
    fn channel_hint_maps_known_pdu_nums_and_falls_back_to_unknown() {
        let mut header = Header {
            ext_header_version: 2,
            bearer_id: 0,
            phy_cell_id: 0,
            earfcn: 0,
            sfn: 0,
            subfn: 0,
            pdu_num: 1,
        };
        assert_eq!(header.channel_hint(), ChannelHint::BcchBch);
        header.pdu_num = 8;
        assert_eq!(header.channel_hint(), ChannelHint::UlDcch);
        header.pdu_num = 200;
        assert_eq!(header.channel_hint(), ChannelHint::Unknown);
    }
}
