# Roadmap

Status: capture, RRC/NAS decode, raw + pcap export, and basic observability
are built and verified live on real hardware (a connected Orbic RC400L).
Everything below is what's left.

## Done

- **Maximal log mask.** `diag-core::mask` enables every log code the modem
  reports as available — not a curated subset. No config-gated fallback to
  a narrower mask exists yet (see Stability note below).
- **RRC OTA + plain NAS decode, pcap export.** `diag-core::rrc` / `nas` /
  `gsmtap` / `pcap`, tied together in `mvp-daemon::pcap_export`. Channel-type
  classification for RRC is a best-effort default, not verified — see
  ARCHITECTURE.md.
- **Raw archive export + basic observability.** Download a capture as-is,
  or converted to pcap; a running log-type distribution count, independent
  of recording state.

## 1. Internal-plane decoders, by value

The actual point of this project: log types outside the OTA/NAS signalling
plane, highest-value first. Real capture data already shows one
high-frequency internal-plane type (`0x18a7`, >97% of messages in an idle
capture window) with no decoder at all — serving-cell measurements
(RSRP/RSRQ/TA) are the natural first target, then MAC/scheduling (BSR),
then the rest. Each new decoder is a new module registered against
`diag-core::dispatch`, same shape as `rrc`/`nas`. Validate decoded values
against a known-good reference (engineering screen / field-test app) before
trusting them — unlike RRC/NAS, there's no vendored struct definition
anywhere to ground a first attempt against, so this needs real
device-side verification from the start, not just unit tests.

## 2. Event mask + F3/debug-message mask

Deliberately not attempted yet, and not guessed at: unlike everything
above, neither `DIAG_EVENT_REPORT_F` (event mask) nor
`DIAG_EXT_MSG_CONFIG_F` (F3/debug messages) has a reference implementation
anywhere in this codebase's history to verify wire format against — the
original vendored project this was forked from never implemented them
either. Sending unverified command bytes to live hardware on recall alone
isn't a risk worth taking casually. Needs either real protocol
documentation research or careful, monitored empirical trial before
landing. F3 has an additional caveat once it does land: terse/QSR-encoded
strings need a firmware-specific hash database to resolve into readable
text — capture raw regardless, resolve opportunistically.

## 3. Active polling

A periodic task issuing read-only request/response commands — version, NV
reads, EFS reads, subsystem/cell-info queries — feeding responses into the
same pipeline. Read-only only, never a write path. Needs a target-device
NV/EFS allowlist (which items are useful and confirmed safe to read
repeatedly) before enabling broadly. Same "no reference to verify against"
caveat as item 2 applies to some of these commands — check before
implementing, don't assume.

## 4. Live sink

Export today is pull/request-driven — each request re-walks the archive
from the start. A live tee (decoded or raw-hex records, fanned out
in-process as containers arrive, independent of archive recording) would
let downstream tools consume in real time instead of polling a file. Not
started; the natural seam is inside `mvp-daemon`'s capture loop, behind a
small trait so the concrete destination is swappable without touching
capture or decode.

## Open decisions

- **Sink destination**, once item 4 exists — HEC-style push, local socket,
  batch upload, something else.
- **NV/EFS allowlist** for item 3.
- **Multi-device support.** This project currently targets the Orbic
  RC400L specifically, not a device abstraction layer. Whether to broaden
  that is open, and would mean adding a real device abstraction to
  `mvp-daemon::device` where today there's just one hardcoded ioctl path.

## Stability note

A fully-enabled log mask, plus event mask, plus F3, plus active polling,
all at once, is a firehose against a 10MB `/dev/diag` read buffer — some
modems wedge or reset under that. Bring capture up incrementally per
device (mask groups one at a time, watching for wedge/reset) rather than
enabling everything in one step on a new device.
