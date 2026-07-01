# Architecture

## Capture: `/dev/diag`

`mvp-daemon/src/device.rs`'s `DiagDevice` owns the device — it's the one
piece of this project that's inherently hardware/OS-specific (raw ioctl
calls, Unix file I/O), scoped to the Orbic RC400L specifically rather than a
general multi-device abstraction. On open it issues the `MEMORY_DEVICE_MODE`
ioctl (falling back to a struct-argument form some driver versions expect);
reads come back as raw buffers, retried past the short reads some devices
return right after the mode switch.

Everything downstream of "raw bytes off the wire" is portable and lives in
`diag-core`, independent of any specific device.

## Frame and container parsing: `diag-core::hdlc` / `diag-core::envelope`

Two framing layers, handled separately:

- `hdlc` (spec §4): per-message HDLC framing — escape/unescape, CRC-16/X-25.
  Wire format is `content, then a single trailing FLAG` — no leading flag,
  consecutive messages just concatenate. `FrameExtractor` handles a growing
  buffer fed incrementally; `decapsulate_one` handles a single
  already-isolated span (e.g. from a `read_until`-style split) and
  specifically treats a *missing* trailing FLAG as truncation, not an
  alternate valid framing — a real bug caught by testing against real
  captured data, not just synthetic vectors.
- `envelope` (spec §5): the outer container a device read returns — a
  `data_type` + a length-prefixed list of still-HDLC-framed message blobs.
  Also builds the same shape for the write side (outgoing requests).

## Mask configuration: `diag-core::mask`

Logging is gated by a per-equipment-ID bitmask; nothing is captured by
default. `retrieve_id_ranges_request_bytes` asks the modem which log-type
ranges exist; `set_all_bits_mask_request_bytes` enables *every* code in a
range — maximal capture by construction, not a curated allowlist. Response
parsing (`parse_retrieve_id_ranges_response`, `parse_set_mask_response`) is
just enough to complete the config handshake — not full protocol message
dispatch, which is a separate concern (see Decode, below).

Event mask (`DIAG_EVENT_REPORT_F`) and F3/debug-message mask
(`DIAG_EXT_MSG_CONFIG_F`) are not configured — deliberately. Unlike
everything else here, neither has a reference implementation anywhere in
this codebase to verify wire format against before sending bytes to live
hardware; see ROADMAP.md.

## Archive: `diag-core::archive`

Append-only, gzip-compressed store of raw de-escaped message bytes — no
parsing, no filtering. Whatever the mask captures lands here losslessly,
independent of whether a decoder exists for it yet; re-decoding later only
requires re-reading this file. Tolerates being read while still being
written to (no finalizing gzip trailer yet) — returns what decompressed
cleanly instead of erroring, since that's the normal state of a live
in-progress recording.

## Decode: `diag-core::log` / `rrc` / `nas` / `dispatch`

`log::parse` splits a decapsulated message into its LOG header
(pending_msgs, outer/inner length, log_type, hardware timestamp) and body;
`log::walk` steps through an archive's concatenated messages (no delimiter
between them — boundaries only come from each header's own length field).

Per-log-type body decoders: `rrc` (LTE RRC OTA, all four
firmware-version-gated header layouts) and `nas` (plain ESM/EMM NAS OTA).
Both just extract metadata and the raw PDU — no ASN.1 needed, since GSMTAP
(below) carries raw PDU bytes for Wireshark's own dissectors to decode.
`dispatch` is an open registry for everything else: log types without a
registered decoder are preserved raw, never dropped — capture coverage and
decode coverage are independent by design (most log types, including the
high-frequency internal-plane ones this project exists to surface, don't
have a decoder yet).

**Known limitation:** RRC's `pdu_num` → channel-type classification uses one
reasonable default mapping, not a verified one — the real mapping is
empirically reverse-engineered per firmware-version range across several
different tables, and reconstructing all of them from general knowledge
without a way to verify wasn't safe to do with confidence. The raw PDU bytes
are always extracted correctly regardless; a wrong classification just means
a mislabeled channel in Wireshark, not lost data.

## Egress: `diag-core::gsmtap` / `pcap`, `mvp-daemon::pcap_export`

`gsmtap` builds the 16-byte GSMTAP header (a public osmocom format,
independent of anything DIAG-specific). `pcap` writes a classic pcap file,
wrapping GSMTAP payloads in synthetic loopback IPv4/UDP headers addressed to
GSMTAP's registered port (4729) — standard, conventional values throughout,
the same approach any DIAG-to-pcap tool uses. `mvp-daemon::pcap_export` ties
it together: walks an archive, decodes RRC OTA and plain NAS bodies, skips
everything else (matching the scope of pcap export before this project's
license pivot — nothing broader).

Export is pull/request-driven — each request re-walks the archive from the
start, not a live stream. A general-purpose live sink (decoded or raw-hex
records, fanned out in-process as containers arrive) is planned but not
implemented; see ROADMAP.md.

## Web UI / API

`mvp-daemon/src/main.rs` defines an axum HTTP API (recording control,
status, capture list, raw/pcap download, log-type distribution) and serves
a hand-written HTML/JS single page embedded as a string constant — no
frontend build step, no framework. The page polls the API on a timer;
there's no push channel from daemon to browser.
