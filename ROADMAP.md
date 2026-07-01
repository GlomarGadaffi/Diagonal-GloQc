# Roadmap

Status: capture, RRC/NAS decode, live detection heuristics, identity
extraction, raw + pcap export, and basic observability are built and
verified live on real hardware (a connected Orbic RC400L). Everything
below is what's left.

## Done

- **Maximal log mask.** `diag-core::mask` enables every log code the modem
  reports as available, not a curated subset. No config-gated fallback to
  a narrower mask exists yet (see Stability note below).
- **RRC OTA + plain NAS decode, pcap export.** `diag-core::rrc` / `nas` /
  `gsmtap` / `pcap`, tied together in `mvp-daemon::pcap_export`. Channel-type
  classification for RRC is a best-effort default, not verified: see
  ARCHITECTURE.md.
- **Raw archive export + basic observability.** Download a capture as-is,
  or converted to pcap; a running log-type distribution count (with a
  per-type "is a decoder registered" flag), independent of recording state.
- **Legacy 2G/3G signalling + UMTS NAS + NR RRC decode.**
  `diag-core::legacy_signalling` (WCDMA/GSM-RR/GPRS-MAC), `nas::decode_umts`,
  `rrc::decode_nr`. Extends decode breadth beyond the original pcap-export
  scope, though not yet wired into pcap export itself (that's still
  deliberately LTE RRC + plain NAS only, matching the pre-clean-room
  daemon). `ip_traffic` also exists but is explicitly flagged uncertain,
  not presented with the same confidence as the others: see
  ARCHITECTURE.md.
- **NAS information elements + device identity extraction.**
  `diag-core::nas_ie` decodes the NAS message envelope, Identity
  Request/Response, Security Mode Command algorithms, and Mobile Identity
  BCD encoding (IMSI/IMEI/TMSI/GUTI). Confidence is fixed-position-IE-high,
  optional-TLV-scan-lower (see that module's doc comments per function).
  This is the device's own identifiers as they appear in its own NAS
  traffic, not other users': DIAG has no path to that, see README.md.
- **Real RRC content decode.** `asn1-specs/` is a generated LTE RRC UPER
  codec, compiled independently from 3GPP's own public ASN.1 spec text via
  the third-party `hampi` compiler (see that directory's README for
  provenance). `diag-core::rrc_content` uses it for actual IE-level RRC
  message inspection, not just raw-PDU passthrough.
- **Detection heuristics.** `diag-core::heuristics` runs live against every
  captured message: `imsi_requested`, `nas_null_cipher` (NAS-layer),
  `connection_redirect_2g_downgrade`, `lte_sib6_and_7_downgrade`,
  `incomplete_sib` (RRC-layer, via `rrc_content`). Wired into
  `mvp-daemon`'s capture loop with capped in-memory history, surfaced via
  `/api/detections` and `/api/identities` plus UI panels. Reliability
  inherits `channel_hint`'s best-effort caveat for the RRC-layer checks:
  see `rrc_content`'s module docs.

## Not done

### AS/RRC-layer `null_cipher`

A different Security Mode Command than the NAS one already covered
(`nas_null_cipher`): LTE runs two independent security contexts, NAS and
AS/RRC. The RRC decoder now exists and could support this; it just hasn't
been written yet. Straightforward follow-on to the existing RRC-content
heuristics, not blocked on anything.

### 1. Internal-plane decoders, by value

The actual point of this project: log types outside the OTA/NAS signalling
plane, highest-value first. Real capture data already shows one
high-frequency internal-plane type (`0x18a7`, >97% of messages in an idle
capture window) with no decoder at all. Serving-cell measurements
(RSRP/RSRQ/TA) are the natural first target, then MAC/scheduling (BSR),
then the rest. Each new decoder is a new module registered against
`diag-core::dispatch`, same shape as `rrc`/`nas`. Validate decoded values
against a known-good reference (engineering screen / field-test app) before
trusting them: unlike RRC/NAS, there's no vendored struct definition
anywhere to ground a first attempt against, so this needs real
device-side verification from the start, not just unit tests.

### 2. Event mask + F3/debug-message mask

Deliberately not attempted yet, and not guessed at: unlike everything
above, neither `DIAG_EVENT_REPORT_F` (event mask) nor
`DIAG_EXT_MSG_CONFIG_F` (F3/debug messages) has a reference implementation
anywhere in this codebase's history to verify wire format against. The
original vendored project this was forked from never implemented them
either. Sending unverified command bytes to live hardware on recall alone
isn't a risk worth taking casually. Needs either real protocol
documentation research or careful, monitored empirical trial before
landing. F3 has an additional caveat once it does land: terse/QSR-encoded
strings need a firmware-specific hash database to resolve into readable
text, so capture raw regardless and resolve opportunistically.

### 3. Active polling

A periodic task issuing read-only request/response commands (version, NV
reads, EFS reads, subsystem/cell-info queries) feeding responses into the
same pipeline. Read-only only, never a write path. Needs a target-device
NV/EFS allowlist (which items are useful and confirmed safe to read
repeatedly) before enabling broadly. Same "no reference to verify against"
caveat as item 2 applies to some of these commands: check before
implementing, don't assume.

### 4. Live sink

Export today is pull/request-driven: each request re-walks the archive
from the start. A live tee (decoded or raw-hex records, fanned out
in-process as containers arrive, independent of archive recording) would
let downstream tools consume in real time instead of polling a file. Not
started; the natural seam is inside `mvp-daemon`'s capture loop, behind a
small trait so the concrete destination is swappable without touching
capture or decode.

### 5. Multi sensor fusion

Correlating a detection with other context, rather than judging a capture
stream in isolation. GPS position is the obvious first fusion input (a
fake tower that only ever appears at one location is a much stronger
signal than the same tower profile seen everywhere); other RF context is
a plausible second. Depends on item 4 (a live sink is the natural point to
fan detections out to something that also has a position feed) and hasn't
been designed yet beyond that dependency.

## Open decisions

- **Sink destination**, once item 4 exists: HEC-style push, local socket,
  batch upload, something else.
- **NV/EFS allowlist** for item 3.
- **Fusion input sources and correlation design**, once item 5 is picked up.
- **Multi-device support.** This project currently targets the Orbic
  RC400L specifically, not a device abstraction layer. Whether to broaden
  that is open, and would mean adding a real device abstraction to
  `mvp-daemon::device` where today there's just one hardcoded ioctl path.

## Stability note

A fully-enabled log mask, plus event mask, plus F3, plus active polling,
all at once, is a firehose against a 10MB `/dev/diag` read buffer: some
modems wedge or reset under that. Bring capture up incrementally per
device (mask groups one at a time, watching for wedge/reset) rather than
enabling everything in one step on a new device.
