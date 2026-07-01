# DIAG Capture Core — Functional Spec

## 1. Purpose

This document specifies the behavior of the DIAG capture core — device bringup,
frame-level transport, message envelope, mask configuration, log dispatch, and raw
archival — as the basis for an independent Rust implementation intended to replace the
currently-vendored GPLv3 `lib/` in this repo ahead of public release.

The goal is a rewrite grounded in protocol *behavior*, described here, rather than one
derived by reading and restructuring the vendored source. Implementation should be done
against this spec's functional requirements and the external references in §2, not
against `lib/src/diag_device.rs` et al.

## 2. Provenance and an honest limit on that claim

The Qualcomm DIAG protocol is documented across several independent, mutually
corroborating open-source projects and published research that predate and stand apart
from the code currently vendored in this repo:

- **QCSuper** (P1sec) — Python DIAG capture tool
- **SCAT** (fgsect) — Python DIAG/QMDL capture and analysis tool
- **MobileInsight** (academic, published MobiSys/SIGCOMM work) — independent
  implementation with its own published protocol documentation
- Osmocom wiki and various baseband security research publications

Even the vendored code's own source comments attribute its log-code table to QCSuper
and its framing approach to SCAT — the vendored code is itself several hops downstream
of primary protocol documentation, not the origin of it. Command codes, ioctl behavior,
and wire layout described below are protocol facts corroborated across that ecosystem,
not creative expression original to any one project.

**The honest limit:** this spec is written by someone (and reviewed by an assistant)
who has already read the vendored source in this repo at length this session. That
rules out a genuine blinded two-team clean room. The discipline this document commits
to instead — and that the implementation must follow — is: describe behavior and wire
format, verified against the independent sources above, not the vendored code's
specific types, names, or module shape. That's a good-faith independent reimplementation,
not a blind clean room, and should be represented as such if this ever matters.

## 3. Device bringup — functional requirements

- Opens a fixed character device path exposing the modem's diagnostic interface.
- The device does not carry DIAG protocol traffic in its default mode. An ioctl-driven
  mode switch (to "memory device" / callback mode) is required before reads/writes
  carry protocol frames. The specific ioctl request number and argument layout are
  kernel/MSM-version-family dependent — every DIAG tool in the ecosystem branches on
  this, it is not a detail original to any one of them.
- Bringup must retry with backoff: the device node may not exist yet immediately after
  modem boot/reset, or may be transiently busy.
- A single read may return multiple frames, a partial frame, or a frame boundary that
  doesn't align with the read call — the read loop must buffer and incrementally
  extract complete frames, not assume one frame per read.
- Writes may report a short or zero byte count on success on some kernel/driver
  versions. This is a documented quirk of the diagnostic char device across the
  ecosystem (not standard file-write semantics) and must not be treated as failure by
  itself.

## 4. Frame transport (HDLC)

- Traffic is HDLC-framed: frame delimiter `0x7E`, escape byte `0x7D` with the standard
  HDLC bit-6 XOR unescape rule (byte `XOR 0x20` following an escape byte) for any
  in-payload occurrence of `0x7E`/`0x7D`.
- A 2-byte CRC trailer (CRC-CCITT family) covers the un-escaped payload, appended
  before HDLC encoding on the wire. **Exact parameter set (init value, reflection) is
  not asserted here from memory — verify against known-good captures before shipping,
  rather than trusting recollection.**
- This layer is standard/generic HDLC framing (ISO/IEC 13239) with a standard CRC
  family — not Qualcomm- or protocol-specific in its mechanics. Only what's *inside*
  the frame is DIAG-specific.

## 5. Message envelope

- A de-escaped HDLC payload carries one or more DIAG messages back-to-back — no
  length prefix at the frame layer; message boundaries come from parsing each
  message's own internal structure.
- First byte of a message is a command code that determines how the remainder parses.
- Two command codes matter for the capture core:
  - **LOG (0x10 / 16)** — a captured log packet: length, log-code/type, timestamp,
    then a type-specific payload.
  - **LOG_CONFIG (0x73 / 115)** — carries both configuration requests (set mask,
    retrieve ID ranges) and their responses; an operation sub-code distinguishes which.
- A single device read typically yields a container of zero or more complete
  messages. The capture loop's unit of work is "container in, parsed messages out,"
  not "one message per read."

## 6. Mask configuration protocol

- Nothing is captured by default. Capture of a given log-code is gated by a
  per-equipment-ID bitmask that must be explicitly enabled.
- Two-step exchange per equipment ID:
  1. **Retrieve ID ranges** — ask which log-code ranges exist for a given equipment
     ID. This varies by modem/firmware family; range boundaries cannot be hardcoded.
  2. **Set mask** — send a bitmask sized to the returned range, one bit per log code,
     enabling capture for the codes wanted.
- "Maximal capture" = set every bit in every returned range, rather than a curated
  subset. This is a *behavioral* choice (which bit pattern to generate), not a
  structural one — same operation, different input.
- Two structurally-adjacent configuration surfaces exist and should be modeled as
  siblings to the log mask, not bolted onto it:
  - **Event reporting** — separate enable/mask mechanism gating a stream of discrete
    event records, independent of the log-code mask.
  - **Extended/debug message masking** — separate per-subsystem-ID mask gating
    verbose/debug string output ("F3" traffic in ecosystem terminology; terse/QSR-
    encoded on newer firmware, resolving against a firmware-specific hash database
    that may not be available — capture raw regardless of resolvability).

## 7. Log record dispatch

- Each LOG message's log-code selects how its payload is interpreted. The mapping
  from code to payload layout is a large, sparse, firmware-family-dependent table —
  there's no algorithmic derivation, each code's layout is independently documented.
- Dispatch should be an open/extensible registry (code → decoder), not a closed enum
  — this project's entire point is to keep adding codes over time, particularly the
  internal/physical-layer codes that signalling-focused tools in the ecosystem
  typically don't bother decoding.
- A log-code with no registered decoder must still be preserved (raw bytes + code +
  timestamp), never dropped. Decode coverage and capture coverage are independent
  concerns.
- Source of truth for payload layouts: independently re-derive from the ecosystem
  sources in §2, cross-checked against real captures from the target device — not
  transcribed from the vendored code's struct definitions.

## 8. Raw archive format

- The archive container format itself is a pre-existing convention in the broader
  DIAG-tooling ecosystem (it's what Qualcomm's own first-party tooling reads/writes),
  not something original to any GPL project in this lineage.
- Functional requirement: append-only, lossless store of raw de-escaped message bytes
  (post-frame-unwrap, pre-decode), so any capture can be fully re-decoded later even
  if today's decoder registry doesn't cover everything in it yet.
- Compression is an implementation choice (ubiquity of tooling on the decode side),
  not a format requirement.
- Lowest legal sensitivity of any component here — fundamentally "append bytes to a
  file," consuming a third-party container convention rather than authoring one.

## 9. Explicit non-goals for the rewrite

- Do not mirror the vendored module boundary
  (`diag_device.rs`/`diag/mod.rs`/`qmdl.rs`/`log_codes.rs`/`diag/diaglog/mod.rs`) —
  organize by the protocol concerns in §3–§8 however that naturally falls out in Rust.
- Do not carry over specific type/field names, error enum variants, or function
  signatures from the currently-vendored code.
- Arriving at a similar mechanism independently because it's a genuinely good fit
  (e.g., a derive-macro-driven declarative byte layout) is fine. Starting from the
  vendored code's existing macro invocations and translating field-by-field is not.
- Where the vendored code's own comments cite external prior art, treat that as a
  pointer to go verify against the primary source — not as permission to copy the
  vendored table as-is.

## 10. Relationship to the currently-vendored code

- The vendored `lib/` stays in place as the running system until each rewritten
  module lands and passes equivalent verification (cross-compile + hardware capture
  parity, per `ARCHITECTURE.md`). Not deleted preemptively.
- Replace incrementally, one section of this spec at a time; delete the vendored file
  a rewritten module replaces in the same change, not dual-maintained.
- Suggested order: §4 (HDLC) first — most self-contained, pure byte-stream transform,
  synthetic test vectors, zero device dependency, lowest legal stakes (generic
  standard, not DIAG-specific) — then §5 (envelope), §6 (mask config), §8 (archive),
  §7 (dispatch/decoders) last since it's the largest surface.
