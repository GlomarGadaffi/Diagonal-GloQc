# Architecture

## Capture: `/dev/diag`

`mvp-daemon/src/device.rs`'s `DiagDevice` owns the device: it's the one
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

- `hdlc` (spec §4): per-message HDLC framing, escape/unescape, CRC-16/X-25.
  Wire format is `content, then a single trailing FLAG`, no leading flag;
  consecutive messages just concatenate. `FrameExtractor` handles a growing
  buffer fed incrementally; `decapsulate_one` handles a single
  already-isolated span (e.g. from a `read_until`-style split) and
  specifically treats a *missing* trailing FLAG as truncation, not an
  alternate valid framing: a real bug caught by testing against real
  captured data, not just synthetic vectors.
- `envelope` (spec §5): the outer container a device read returns, a
  `data_type` plus a length-prefixed list of still-HDLC-framed message
  blobs. Also builds the same shape for the write side (outgoing requests).

## Mask configuration: `diag-core::mask`

Logging is gated by a per-equipment-ID bitmask; nothing is captured by
default. `retrieve_id_ranges_request_bytes` asks the modem which log-type
ranges exist; `set_all_bits_mask_request_bytes` enables *every* code in a
range: maximal capture by construction, not a curated allowlist. Response
parsing (`parse_retrieve_id_ranges_response`, `parse_set_mask_response`) is
just enough to complete the config handshake, not full protocol message
dispatch, which is a separate concern (see Decode, below).

Event mask (`DIAG_EVENT_REPORT_F`) and F3/debug-message mask
(`DIAG_EXT_MSG_CONFIG_F`) are not configured, deliberately. Unlike
everything else here, neither has a reference implementation anywhere in
this codebase to verify wire format against before sending bytes to live
hardware; see ROADMAP.md.

## Archive: `diag-core::archive`

Append-only, gzip-compressed store of raw de-escaped message bytes: no
parsing, no filtering. Whatever the mask captures lands here losslessly,
independent of whether a decoder exists for it yet; re-decoding later only
requires re-reading this file. Tolerates being read while still being
written to (no finalizing gzip trailer yet), returning what decompressed
cleanly instead of erroring, since that's the normal state of a live
in-progress recording.

## Decode: `diag-core::log` / `rrc` / `nas` / `nas_ie` / `legacy_signalling` / `ip_traffic` / `dispatch`

`log::parse` splits a decapsulated message into its LOG header
(pending_msgs, outer/inner length, log_type, hardware timestamp) and body;
`log::walk` steps through an archive's concatenated messages (no delimiter
between them; boundaries only come from each header's own length field).

Per-log-type body decoders, in decreasing order of confidence:

- `rrc`: LTE RRC OTA (`0xB0C0`, all four firmware-version-gated header
  layouts) and NR RRC OTA (`0xB821`, no header at all, the whole body is
  the raw PDU). Extracts metadata and the raw PDU; doesn't need ASN.1 for
  that part, since GSMTAP (below) carries raw PDU bytes for Wireshark's
  own dissectors to decode.
- `nas`: plain ESM/EMM LTE NAS OTA (`0xB0E2`/`0xB0E3`/`0xB0EC`/`0xB0ED`)
  and UMTS NAS OTA (`0x713A`, a different, older shape: explicit
  uplink-flag plus 4-byte length rather than "rest of the body").
- `legacy_signalling`: WCDMA (`0x412F`), GSM RR (`0x512F`), GPRS MAC
  (`0x5226`) signalling. One shared shape (channel byte, secondary-id
  byte, length-prefixed message), differing only in length-field width.
- `ip_traffic` (`0x11EB`): **explicitly uncertain**, not presented with
  the same confidence as the above. The layout used (skip a fixed 8-byte
  prefix) traces to a single external comment that itself reads "is this
  right??" rather than a confirmed spec: kept and clearly flagged rather
  than either fabricating confidence or silently omitting it.

`dispatch` is an open registry for everything else: log types without a
registered decoder are preserved raw, never dropped. Capture coverage and
decode coverage are independent by design. Real captured data from the
target device shows this gap concretely: its dominant log type by far (one
internal-plane code was >97% of messages in one capture window) has no
decoder yet, none of the above cover it. Highest priority for what comes
next; see ROADMAP.md.

**Known limitation:** RRC's `pdu_num` to channel-type classification uses
one reasonable default mapping, not a verified one. The real mapping is
empirically reverse-engineered per firmware-version range across several
different tables, and reconstructing all of them from general knowledge
without a way to verify wasn't safe to do with confidence. The raw PDU bytes
are always extracted correctly regardless; a wrong classification just means
a mislabeled channel in Wireshark, not lost data. `diag-core::rrc_content`
and `heuristics` (below) both depend on this classification for dispatch,
so this same caveat propagates into their reliability too.

`nas_ie` goes one level deeper than `nas`: instead of just extracting the
raw NAS PDU, it decodes specific message content per TS 24.301, since NAS
is a hand-parseable TLV format rather than ASN.1. Message envelope
(protocol discriminator, message type), Identity Request/Response,
Security Mode Command algorithms, and Mobile Identity BCD decoding
(IMSI/IMEI/TMSI/GUTI) are all in scope here. Confidence again varies by
function: fixed-position mandatory IEs are high confidence, the optional
GUTI TLV tag scan in Attach Accept is flagged best-effort (see that
module's own doc comments).

## Real RRC content decode: `asn1-specs` / `diag-core::rrc_content`

`rrc` and `nas` above extract metadata and hand back the raw PDU; that's
enough for pcap export (Wireshark's own dissectors do the rest) but not
enough to inspect specific IE values inside an RRC message, which some
detection heuristics need. `asn1-specs/` closes that gap: a generated LTE
RRC UPER codec, compiled independently from 3GPP's own public ASN.1 spec
text via the third-party `hampi` compiler (unrelated project, Apache-2.0 OR
MIT; see `asn1-specs/README.md` for full provenance). `rrc_content` uses
the generated types to decode specific message shapes (RRC Connection
Release, System Information) and pull out the fields the heuristics below
check.

Dispatch to the right top-level ASN.1 message type depends on `rrc`'s
`channel_hint`, which carries the classification-confidence caveat noted
above. A wrong channel classification usually (not always) surfaces as a
clean UPER decode error rather than a silently wrong result, since PER's
tag/length/choice-index structure doesn't coincide by chance across
unrelated message types, but "usually" is doing real work in that sentence.
None of this has been validated against real captured RRC signalling yet.

## Detection heuristics: `diag-core::heuristics`

Runs against every captured message live, dispatched by log type:

- NAS-layer, via `nas_ie` (raw PDU extraction is enough, no ASN.1 needed):
  `imsi_requested` (an Identity Request asking for IMSI specifically, not
  just any identity type) and `nas_null_cipher` (Security Mode Command
  selecting EEA0/EIA0).
- RRC-layer, via `rrc_content` (needs real content decode):
  `connection_redirect_2g_downgrade` (RRC Connection Release redirecting to
  GERAN/UTRA), `lte_sib6_and_7_downgrade` (broadcast of the SIBs carrying
  UTRA/GERAN reselection parameters, informational rather than a standalone
  alarm since legitimate networks broadcast these too), and
  `incomplete_sib` (a broadcast claiming to be System Information that
  fails to decode, only meaningful when `channel_hint` already identified
  the channel as BCCH-DL-SCH, otherwise a channel misclassification would
  look identical to a real malformed broadcast).

Not implemented: the AS/RRC-layer sibling to `nas_null_cipher` (LTE has two
independent security contexts, NAS and AS/RRC, each with their own Security
Mode Command). The decoder needed for it now exists; it just hasn't been
written yet.

## Egress: `diag-core::gsmtap` / `pcap`, `mvp-daemon::pcap_export`

`gsmtap` builds the 16-byte GSMTAP header (a public osmocom format,
independent of anything DIAG-specific). `pcap` writes a classic pcap file,
wrapping GSMTAP payloads in synthetic loopback IPv4/UDP headers addressed to
GSMTAP's registered port (4729): standard, conventional values throughout,
the same approach any DIAG-to-pcap tool uses. `mvp-daemon::pcap_export` ties
it together: walks an archive, decodes RRC OTA and plain NAS bodies, skips
everything else (matching the scope of pcap export before this project's
license pivot, nothing broader; the legacy-signalling/UMTS/NR decoders and
the ASN.1-based RRC content decode both exist now but aren't wired into
pcap export specifically).

Export is pull/request-driven: each request re-walks the archive from the
start, not a live stream. A general-purpose live sink (decoded or raw-hex
records, fanned out in-process as containers arrive) is planned but not
implemented; see ROADMAP.md.

## Web UI / API

`mvp-daemon/src/main.rs` defines an axum HTTP API (recording control,
status, capture list, raw/pcap download, log-type distribution, live
detections, live identity extractions) and serves a hand-written HTML/JS
single page embedded as a string constant: no frontend build step, no
framework. The page polls the API on a timer; there's no push channel from
daemon to browser. Detections and identities are held in bounded
in-memory history (oldest evicted first) inside `CaptureState`, independent
of whether a recording is currently active, same pattern as the log-type
distribution counter.
