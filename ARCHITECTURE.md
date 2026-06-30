# Architecture

## Capture: `/dev/diag`

`lib/src/diag_device.rs` owns the device. On open it issues the
`MEMORY_DEVICE_MODE` ioctl (`enable_frame_readwrite`) and determines whether
the modem is reached directly or via an MDM proxy (`determine_use_mdm`).
Reads come back as `MessagesContainer`s (`lib/src/diag/mod.rs`) — HDLC framed,
CRC-CCITT checked, one or more `Message::Log` / `Message::Response` entries
per container. `as_stream()` exposes this as an async stream; the daemon's
diag thread (`daemon/src/diag.rs`) consumes it in a loop.

Logging is gated by a per-equipment-ID bitmask. `retrieve_id_ranges()` asks
the modem which log-type ranges exist and how wide each is; `config_logs()`
then issues a `SetMask` request per range. What's actually captured is
exactly, and only, whatever bits are set in that mask — nothing reaches the
qmdl that wasn't asked for.

`build_log_mask_request` (`lib/src/diag/mod.rs`) builds the mask from an
explicit accept-list of log codes (`lib/src/log_codes.rs`). The accept-list
approach is what historically limited capture to the OTA/NAS signalling
plane (RRC, NAS, L3 signalling) and excluded the internal plane (ML1, MAC,
RLC, serving-cell RSRP/RSRQ/TA, scheduling/BSR) — those codes were simply
never in the list. Widening capture means widening this mask (see
ROADMAP.md), and separately, adding the event-report and F3/debug-message
mask paths, which are distinct DIAG commands not modeled at all yet — the
current `Request` enum has exactly one variant, `LogConfig`.

## Archive: qmdl

`lib/src/qmdl.rs`'s `QmdlWriter` writes the raw HDLC bytes from each
container straight to a gzip-compressed file — no parsing, no filtering.
This is the full-fidelity record: whatever the mask captured lands here
losslessly, independent of whether a decoder for it exists yet. Re-decoding
later (with better/updated decoders) only requires re-reading this file.

## Decode

`lib/src/diag/diaglog/mod.rs` defines `LogBody`, a deku-derived enum
dispatched on the diag log-type field. Each known log type gets a struct;
unknown types fail to parse (and are skipped, not lost — they're still in
the qmdl). Today this covers LTE RRC OTA and NAS-plain (non-ciphered)
messages; the internal-plane log types have no decoder yet.

`lib/src/gsmtap/parser.rs` converts a decoded `LogBody` into a GSMTAP
message for pcap export and for the analysis heuristics
(`lib/src/analysis/`). This conversion is also narrow by construction: it
maps exactly `LteRrcOtaMessage` and `Nas4GMessage`, and returns `None` for
everything else. Capturing more log types is necessary but not sufficient —
each new type also needs a `LogBody` variant and, if it should reach
analysis/export, a GSMTAP mapping or a separate sink path.

## Egress

Two paths exist today:

- **pcap**, via `daemon/src/pcap.rs`: a pull/request-driven conversion of
  the qmdl recorded so far. Not a live stream — each request re-walks the
  qmdl from the start.
- **NDJSON analysis report**, via `daemon/src/analysis.rs`'s
  `AnalysisWriter`: written incrementally, one JSON line per analyzed
  container, flushed immediately. This is the actual live tap point today
  — `DiagTask::process_container` (`daemon/src/diag.rs`) calls
  `analyze_container` on every container as it arrives.

A general-purpose live sink — decoded or raw-hex records, fanned out
in-process as containers arrive, independent of qmdl recording — is planned
but not implemented (see ROADMAP.md). The intended seam is the same point
in `process_container`, behind a small trait so the concrete destination is
swappable without touching capture or decode.

## Web UI / API

`daemon/src/server.rs` + `daemon/src/main.rs` define an axum HTTP API
(recording control, config, manifest/stats, pcap/qmdl download) and serve a
SvelteKit single-page app (`daemon/web/`) built ahead of time and embedded
into the binary via `include_bytes!`. The frontend polls the API on a
timer; there's no push channel from daemon to browser.

## Device bringup

`lib/src/lib.rs`'s `Device` enum and the per-device modules under
`daemon/src/battery/` and `daemon/src/display/` encapsulate the differences
between supported hardware (ioctl quirks, battery sysfs paths, display
framebuffer access). `rootshell/` is a minimal helper for devices that need
an elevated shell to install or manage the daemon. Which device(s) this
project targets, and how a fresh device gets the daemon onto it, are open
(see ROADMAP.md) — the `Device` enum currently carries all previously
supported hardware unchanged.
