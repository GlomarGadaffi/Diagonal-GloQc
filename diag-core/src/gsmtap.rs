//! GSMTAP header construction — a public osmocom format
//! (<https://github.com/osmocom/libosmocore/blob/master/include/osmocom/core/gsmtap.h>),
//! not anything original to this project or to Rayhunter. Independent
//! implementation of a standard: this is the same relationship
//! `diag-core` has to CRC-16/X-25 or the pcap file format, not a
//! DIAG-protocol clean-room concern.

pub const PORT: u16 = 4729;

pub const TYPE_LTE_RRC: u8 = 0x0d;
pub const TYPE_LTE_NAS: u8 = 0x12;

pub const LTE_RRC_SUBTYPE_BCCH_BCH: u8 = 4;
pub const LTE_RRC_SUBTYPE_BCCH_DL_SCH: u8 = 5;
pub const LTE_RRC_SUBTYPE_MCCH: u8 = 7;
pub const LTE_RRC_SUBTYPE_PCCH: u8 = 6;
pub const LTE_RRC_SUBTYPE_DL_CCCH: u8 = 0;
pub const LTE_RRC_SUBTYPE_DL_DCCH: u8 = 1;
pub const LTE_RRC_SUBTYPE_UL_CCCH: u8 = 2;
pub const LTE_RRC_SUBTYPE_UL_DCCH: u8 = 3;
pub const LTE_RRC_SUBTYPE_UNKNOWN: u8 = 0; // falls back to DL-CCCH's slot; Wireshark just may mis-dissect

pub const LTE_NAS_SUBTYPE_PLAIN: u8 = 0;

/// Builds the 16-byte GSMTAP header (version 2, header_len 4 words),
/// big-endian per the spec.
#[allow(clippy::too_many_arguments)]
pub fn header(
    packet_type: u8,
    subtype: u8,
    uplink: bool,
    arfcn: u16,
    frame_number: u32,
    subslot: u8,
) -> [u8; 16] {
    let mut h = [0u8; 16];
    h[0] = 2; // version
    h[1] = 4; // header_len, in 4-byte words
    h[2] = packet_type;
    h[3] = 0; // timeslot
              // byte 4-5: 1 bit pcs_band_indicator, 1 bit uplink, 14 bits arfcn (big-endian bitfield)
    let arfcn14 = arfcn & 0x3FFF;
    let bits: u16 = ((uplink as u16) << 14) | arfcn14;
    h[4..6].copy_from_slice(&bits.to_be_bytes());
    h[6] = 0; // signal_dbm
    h[7] = 0; // signal_noise_ratio_db
    h[8..12].copy_from_slice(&frame_number.to_be_bytes());
    h[12] = subtype;
    h[13] = 0; // antenna_number
    h[14] = subslot;
    h[15] = 0; // reserved
    h
}

pub fn lte_rrc_header(subtype: u8, uplink: bool, arfcn: u16, frame_number: u32, subslot: u8) -> [u8; 16] {
    header(TYPE_LTE_RRC, subtype, uplink, arfcn, frame_number, subslot)
}

pub fn lte_nas_header(uplink: bool) -> [u8; 16] {
    header(TYPE_LTE_NAS, LTE_NAS_SUBTYPE_PLAIN, uplink, 0, 0, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_is_16_bytes_version_2_len_4() {
        let h = header(TYPE_LTE_RRC, LTE_RRC_SUBTYPE_DL_DCCH, false, 100, 42, 3);
        assert_eq!(h.len(), 16);
        assert_eq!(h[0], 2);
        assert_eq!(h[1], 4);
    }

    #[test]
    fn packet_type_and_subtype_land_in_the_right_bytes() {
        let h = header(TYPE_LTE_NAS, LTE_NAS_SUBTYPE_PLAIN, false, 0, 0, 0);
        assert_eq!(h[2], TYPE_LTE_NAS);
        assert_eq!(h[12], LTE_NAS_SUBTYPE_PLAIN);
    }

    #[test]
    fn uplink_bit_and_arfcn_pack_correctly_into_the_shared_field() {
        let downlink = header(TYPE_LTE_RRC, 0, false, 0x3FFF, 0, 0);
        assert_eq!(u16::from_be_bytes([downlink[4], downlink[5]]), 0x3FFF);

        let uplink = header(TYPE_LTE_RRC, 0, true, 0x3FFF, 0, 0);
        let bits = u16::from_be_bytes([uplink[4], uplink[5]]);
        assert_eq!(bits & 0x3FFF, 0x3FFF); // arfcn preserved
        assert_ne!(bits & 0x4000, 0); // uplink bit set
    }

    #[test]
    fn arfcn_wider_than_14_bits_is_truncated_not_panicking() {
        let h = header(TYPE_LTE_RRC, 0, false, 0xFFFF, 0, 0);
        let bits = u16::from_be_bytes([h[4], h[5]]);
        assert_eq!(bits, 0x3FFF); // masked to 14 bits
    }

    #[test]
    fn frame_number_is_big_endian_in_the_right_position() {
        let h = header(TYPE_LTE_RRC, 0, false, 0, 0x0102_0304, 0);
        assert_eq!(&h[8..12], &[0x01, 0x02, 0x03, 0x04]);
    }
}
