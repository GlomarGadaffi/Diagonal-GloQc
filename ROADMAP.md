# Roadmap

Status: scaffold complete (capture/decode/web-UI/build tooling vendored and
building, against a curated log mask). Everything below is not yet done.

## 1. Widen the log mask to all bits

`build_log_mask_request` (`lib/src/diag/mod.rs`) currently sets a bit only
for codes in an explicit accept-list. Add a builder that sets every bit for
each equipment-ID range `retrieve_id_ranges()` reports, and wire
`config_logs()` to use it behind a config toggle (full vs. curated), so a
device that destabilizes under a full mask can fall back without a code
change. This alone gets internal-plane bytes into the qmdl, before any
decoder for them exists.

## 2. Live sink seam

Add a small `Sink` trait and tee it into `process_container`
(`daemon/src/diag.rs`), alongside the existing `analyze_container` call.
Records carry either a decoded struct or a raw-hex fallback, so nothing is
invisible downstream before its decoder lands. Ship a stdout/no-op
implementation first to prove the seam; the qmdl write must never block on
it (bounded queue, spill-to-disk on overflow). The concrete destination
(HEC-style push, local socket, batch upload, something else) is an open
decision — the trait boundary exists so that decision doesn't touch capture
or decode.

## 3. Inline decoders, by value

Extend `LogBody` (`lib/src/diag/diaglog/mod.rs`) with internal-plane log
types, highest-value first: serving-cell measurements (RSRP/RSRQ/TA), then
MAC/scheduling (BSR), then the rest. Each new decoder becomes a typed
record on the sink. Validate decoded values against a known-good reference
(engineering screen / field-test app) on at least one target device before
trusting them.

## 4. Event mask + F3/debug-message mask

Two more DIAG command families, neither modeled yet:

- **Event mask** — a different request/response pair than `LogConfig`;
  needs new `Request`/`Message` variants and its own decoders.
- **F3/debug messages** — same, plus a caveat: terse/QSR-encoded F3 strings
  need a firmware-specific hash database to resolve into readable text.
  Capture raw regardless; resolve opportunistically if/when that database
  is available for a given firmware.

## 5. Active polling

A periodic task issuing read-only request/response commands — version,
NV reads, EFS reads, subsystem/cell-info queries — and feeding responses
into the same pipeline. Read-only only; never a write path. Needs a
per-device allowlist and rate limits before enabling broadly; this is the
highest-risk item for modem stability and should land last.

## Open decisions

- **Target device(s).** The `Device` enum still carries every previously
  supported device. Narrowing to an actual target determines how much of
  the per-device ioctl/display/battery surface is real work versus dead
  weight, and what device bringup (rooting, initial daemon install) looks
  like — there's no automated installer in this repo currently.
- **Sink destination.** See item 2 — trait exists, implementation doesn't.
- **NV/EFS allowlist.** Which items are useful, and confirmed safe to read,
  per modem family — needed before item 5 can enable anything by default.

## Stability note

Full log mask + event mask + F3 + active polling, all at once, is a
firehose against a 10MB `/dev/diag` read buffer, and some modems wedge or
reset under a fully-enabled mask. Bring capture up incrementally per
device (mask groups one at a time, watching for wedge/reset) rather than
enabling everything from item 1 through item 5 in one step on a new
device.
