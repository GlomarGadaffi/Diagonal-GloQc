//! Classic pcap file writer, wrapping GSMTAP-framed payloads in synthetic
//! loopback IPv4/UDP headers so Wireshark's GSMTAP dissector picks them
//! up automatically (GSMTAP's registered port is 4729 — spec §gsmtap).
//! Everything here is public, standard wire format (RFC 791, RFC 768, the
//! classic libpcap file format) with conventional values (loopback
//! addresses, DF-set/no-fragmentation, unchecked checksums) — there's no
//! DIAG-specific or Rayhunter-specific expression in this file at all,
//! same relationship to "clean room" as `archive.rs`'s use of gzip.
//!
//! Classic pcap (not pcapng) by choice: simpler to hand-roll, equally
//! readable by Wireshark, and this project doesn't need pcapng's
//! per-interface/per-packet-comment features for an MVP.

const LINKTYPE_IPV4: u32 = 228;
const GSMTAP_PORT: u16 = 4729;
const SRC_UDP_PORT: u16 = 13337;

/// Writes the 24-byte classic pcap global header.
pub fn global_header() -> [u8; 24] {
    let mut h = [0u8; 24];
    h[0..4].copy_from_slice(&0xA1B2C3D4u32.to_le_bytes()); // magic (native byte order marker)
    h[4..6].copy_from_slice(&2u16.to_le_bytes()); // version_major
    h[6..8].copy_from_slice(&4u16.to_le_bytes()); // version_minor
    // bytes 8..16 (thiszone, sigfigs) stay zero
    h[16..20].copy_from_slice(&65535u32.to_le_bytes()); // snaplen
    h[20..24].copy_from_slice(&LINKTYPE_IPV4.to_le_bytes());
    h
}

fn ipv4_header(total_len: u16, identification: u16) -> [u8; 20] {
    let mut h = [0u8; 20];
    h[0] = 0x45; // version 4, IHL 5 (no options)
    h[1] = 0x00; // DSCP/ECN
    h[2..4].copy_from_slice(&total_len.to_be_bytes());
    h[4..6].copy_from_slice(&identification.to_be_bytes());
    h[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF set, no fragmentation
    h[8] = 64; // TTL
    h[9] = 17; // protocol = UDP
    // bytes 10..12 (header checksum) left as 0 - unchecked, Wireshark
    // doesn't validate IP checksums by default
    h[12..16].copy_from_slice(&[127, 0, 0, 1]); // src
    h[16..20].copy_from_slice(&[127, 0, 0, 1]); // dst
    h
}

fn udp_header(payload_len: u16) -> [u8; 8] {
    let mut h = [0u8; 8];
    h[0..2].copy_from_slice(&SRC_UDP_PORT.to_be_bytes());
    h[2..4].copy_from_slice(&GSMTAP_PORT.to_be_bytes());
    h[4..6].copy_from_slice(&(8 + payload_len).to_be_bytes());
    // checksum left as 0 - valid per RFC 768, means "not computed" for IPv4 UDP
    h
}

/// Wraps `gsmtap_payload` (a 16-byte GSMTAP header plus its PDU) in
/// synthetic IPv4/UDP headers, then a pcap per-packet record. `unix_millis`
/// becomes the packet's capture timestamp.
pub fn packet_record(gsmtap_payload: &[u8], unix_millis: i64, identification: u16) -> Vec<u8> {
    let total_len = (20 + 8 + gsmtap_payload.len()) as u16;
    let mut data = Vec::with_capacity(total_len as usize);
    data.extend_from_slice(&ipv4_header(total_len, identification));
    data.extend_from_slice(&udp_header(gsmtap_payload.len() as u16));
    data.extend_from_slice(gsmtap_payload);

    let ts_sec = (unix_millis.max(0) / 1000) as u32;
    let ts_usec = ((unix_millis.max(0) % 1000) * 1000) as u32;

    let mut record = Vec::with_capacity(16 + data.len());
    record.extend_from_slice(&ts_sec.to_le_bytes());
    record.extend_from_slice(&ts_usec.to_le_bytes());
    record.extend_from_slice(&(data.len() as u32).to_le_bytes()); // incl_len
    record.extend_from_slice(&(data.len() as u32).to_le_bytes()); // orig_len (never truncated here)
    record.extend_from_slice(&data);
    record
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_header_has_correct_magic_and_linktype() {
        let h = global_header();
        assert_eq!(u32::from_le_bytes(h[0..4].try_into().unwrap()), 0xA1B2C3D4);
        assert_eq!(u32::from_le_bytes(h[20..24].try_into().unwrap()), LINKTYPE_IPV4);
        assert_eq!(h.len(), 24);
    }

    #[test]
    fn packet_record_length_fields_match_actual_wrapped_size() {
        let gsmtap_payload = vec![0xAB; 30]; // pretend 16-byte header + 14-byte PDU
        let record = packet_record(&gsmtap_payload, 1_700_000_000_000, 5);
        let incl_len = u32::from_le_bytes(record[8..12].try_into().unwrap());
        let orig_len = u32::from_le_bytes(record[12..16].try_into().unwrap());
        assert_eq!(incl_len, orig_len);
        assert_eq!(incl_len as usize, 20 + 8 + gsmtap_payload.len());
        assert_eq!(record.len(), 16 + incl_len as usize);
    }

    #[test]
    fn packet_record_ip_and_udp_headers_carry_the_gsmtap_port_and_payload() {
        let gsmtap_payload = vec![0x11, 0x22, 0x33];
        let record = packet_record(&gsmtap_payload, 0, 1);
        let ip_start = 16;
        let udp_start = ip_start + 20;
        let payload_start = udp_start + 8;
        assert_eq!(record[ip_start], 0x45); // version+IHL
        assert_eq!(
            u16::from_be_bytes([record[udp_start + 2], record[udp_start + 3]]),
            GSMTAP_PORT
        );
        assert_eq!(&record[payload_start..], &gsmtap_payload[..]);
    }

    #[test]
    fn timestamp_splits_into_seconds_and_microseconds_correctly() {
        let record = packet_record(&[0u8; 1], 1_234_567, 0); // 1234.567 seconds
        let ts_sec = u32::from_le_bytes(record[0..4].try_into().unwrap());
        let ts_usec = u32::from_le_bytes(record[4..8].try_into().unwrap());
        assert_eq!(ts_sec, 1234);
        assert_eq!(ts_usec, 567_000);
    }

    #[test]
    fn identification_field_is_carried_through_to_the_ip_header() {
        let record_a = packet_record(&[0u8; 1], 0, 0xAAAA);
        let record_b = packet_record(&[0u8; 1], 0, 0xBBBB);
        let id_offset = 16 + 4; // pcap record header (16) + ip header up to identification
        assert_ne!(
            &record_a[id_offset..id_offset + 2],
            &record_b[id_offset..id_offset + 2]
        );
    }
}
