//! End-to-end smoke test for the diag-core rewrite: proves the modules
//! compose into a working pipeline, not just that each passes in
//! isolation. Uses synthetic data standing in for real device I/O —
//! device bringup itself (spec §3) stays on the vendored hardware layer
//! and isn't reachable from this host (see spec/diag-protocol.md, and
//! ARCHITECTURE.md's verification approach).

use diag_core::{archive, dispatch, envelope, hdlc, mask};

/// Builds one synthetic "device read buffer": an envelope container
/// wrapping several independently-HDLC-framed message blobs — the exact
/// shape `DiagDevice::get_next_messages_container` hands off after a raw
/// `read()` call.
fn synthetic_read_buffer(payloads: &[&[u8]]) -> Vec<u8> {
    let mut container = envelope::DATA_TYPE_USER_SPACE.to_le_bytes().to_vec();
    container.extend_from_slice(&(payloads.len() as u32).to_le_bytes());
    for payload in payloads {
        let framed = hdlc::encode(payload);
        container.extend_from_slice(&(framed.len() as u32).to_le_bytes());
        container.extend_from_slice(&framed);
    }
    container
}

#[test]
fn read_path_parses_container_decapsulates_each_message_and_dispatches() {
    let messages: [&[u8]; 3] = [
        &[0x00, 0x01, 0xAA, 0xBB], // pretend log_type 0x0001
        &[0x02, 0x00, FLAG_BYTE, ESC_BYTE], // contains bytes needing escaping
        &[0x99, 0x99, 0xFF],
    ];
    const FLAG_BYTE: u8 = 0x7E;
    const ESC_BYTE: u8 = 0x7D;

    let raw = synthetic_read_buffer(&messages);

    let container = envelope::parse_container(&raw).expect("container should parse");
    assert!(container.is_user_space());
    assert_eq!(container.messages.len(), messages.len());

    let mut registry = dispatch::Registry::new();
    registry.register(0x0001, |payload| {
        dispatch::DecodedBody::Decoded(format!("known type, {} bytes", payload.len()))
    });

    let mut decapsulated = Vec::new();
    for (blob, expected_payload) in container.messages.iter().zip(messages.iter()) {
        let payload = hdlc::decapsulate_one(blob).expect("frame should decapsulate cleanly");
        assert_eq!(&payload, expected_payload);
        decapsulated.push(payload);
    }

    // exercise dispatch on the pipeline's own output, not synthetic
    // standalone bytes: first message's first two bytes stand in for a
    // log_type the registry knows about, the rest don't.
    let log_type = u16::from_be_bytes([decapsulated[0][0], decapsulated[0][1]]);
    match registry.decode(log_type, &decapsulated[0]) {
        dispatch::DecodedBody::Decoded(s) => assert!(s.contains("known type")),
        other => panic!("expected the registered decoder to fire, got {other:?}"),
    }
    for payload in &decapsulated[1..] {
        assert_eq!(
            registry.decode(0xFFFF, payload),
            dispatch::DecodedBody::Raw(payload.clone()),
            "unregistered codes must fall back to raw, never drop data"
        );
    }
}

#[test]
fn decapsulated_messages_archive_losslessly_across_multiple_containers() {
    let container_a = synthetic_read_buffer(&[&[1, 2, 3], &[4, 5, 6, 7]]);
    let container_b = synthetic_read_buffer(&[&[8, 9]]);

    let mut expected_raw = Vec::new();
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut writer = archive::ArchiveWriter::new(&mut buf);
        for raw_container in [&container_a, &container_b] {
            let parsed = envelope::parse_container(raw_container).unwrap();
            for blob in &parsed.messages {
                let payload = hdlc::decapsulate_one(blob).unwrap();
                writer.write_raw(&payload).unwrap();
                expected_raw.extend_from_slice(&payload);
            }
        }
        writer.close().unwrap();
    }

    buf.set_position(0);
    let mut reader = archive::ArchiveReader::new(buf);
    assert_eq!(reader.read_all().unwrap(), expected_raw);
}

#[test]
fn write_path_request_round_trips_through_the_same_envelope_parser_as_the_read_path() {
    // Builds a request the way DiagDevice's write path will: mask request
    // body -> HDLC frame -> container wrapper. Then confirms it parses
    // back out with parse_container + decapsulate_one exactly like a
    // response read off the device would, proving both directions agree
    // on the same wire format rather than each half being tested only
    // against itself.
    let request_body = mask::retrieve_id_ranges_request_bytes();
    let framed = hdlc::encode(&request_body);
    let container_bytes = envelope::build_request_container_bytes(&framed, Some(-1));

    // build_request_container_bytes omits num_messages (the device
    // doesn't need one for a single-request write); reconstruct a
    // read-shaped container around the same bytes to confirm
    // parse_container agrees on the framing underneath.
    let mdm_field_len = 4; // Some(-1) => 4 bytes written
    let hdlc_bytes = &container_bytes[4 + mdm_field_len..];
    let mut read_shaped = envelope::DATA_TYPE_USER_SPACE.to_le_bytes().to_vec();
    read_shaped.extend_from_slice(&1u32.to_le_bytes());
    read_shaped.extend_from_slice(&(hdlc_bytes.len() as u32).to_le_bytes());
    read_shaped.extend_from_slice(hdlc_bytes);

    let container = envelope::parse_container(&read_shaped).unwrap();
    let payload = hdlc::decapsulate_one(&container.messages[0]).unwrap();
    assert_eq!(payload, request_body);
}
