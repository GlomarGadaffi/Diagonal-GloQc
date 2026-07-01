# Diagonal-GloQc

A capture daemon for Qualcomm baseband modems, built around the `/dev/diag`
diagnostic interface. It opens the diag device, enables maximal logging (every
log code the modem reports as available, not a curated subset), and records
the raw diagnostic stream to disk.

The goal is maximal extraction: not just the OTA signalling plane (RRC/NAS),
but the internal/physical-layer plane (ML1, MAC, serving-cell measurements)
that a narrow log mask would otherwise leave uncaptured.

On top of raw capture, it decodes message content live and runs a set of
IMSI-catcher detection heuristics as data streams in: IMSI-specific identity
requests, null-cipher downgrades (both NAS and, now that real RRC content
decode exists, on the RRC side), forced redirects to 2G/3G, and suspicious
SIB6/7 broadcasts. Detections and any device identifiers seen (TMSI/GUTI/IMSI in the device's
own NAS traffic, not other users': DIAG doesn't expose that, see the note
below) show up live in the status UI.

Everything here is an independent, from-scratch implementation: see
[spec/diag-protocol.md](spec/diag-protocol.md) for the protocol spec this is
built from and its provenance notes, and [ARCHITECTURE.md](ARCHITECTURE.md) /
[ROADMAP.md](ROADMAP.md) for how it's structured and what's built versus
planned.

**On "can it see other users' traffic":** no. DIAG only ever exposes what
the device's own modem decoded for itself. Blind PDCCH/DCI/RNTI decoding
for other users on the cell is an SDR technique (see LTESniffer, FALCON)
that needs dedicated radio hardware and a full software LTE stack, not a
phone's baseband chip. The two are different architectures, not the same
capability with a setting turned off.

## Layout

- `diag-core/`: protocol logic as a portable library. HDLC framing
  (`hdlc`), the outer container envelope (`envelope`), mask configuration
  (`mask`), the LOG message header and RRC OTA / plain NAS body decoders
  (`log`, `rrc`, `nas`), legacy 2G/3G signalling and IP traffic decoders
  (`legacy_signalling`, `ip_traffic`), NAS information elements and mobile
  identity decoding (`nas_ie`), real RRC message content via generated
  ASN.1 (`rrc_content`), detection heuristics (`heuristics`), GSMTAP header
  construction (`gsmtap`), a pcap file writer (`pcap`), the raw archive
  format (`archive`), and an open decoder registry for log types without a
  dedicated decoder yet (`dispatch`).
- `asn1-specs/`: a generated LTE RRC UPER codec, compiled fresh from
  3GPP's own public ASN.1 spec text (see that directory's README for
  provenance and regeneration instructions).
- `mvp-daemon/`: the on-device binary. `/dev/diag` bringup, the capture
  loop with live detection and identity extraction, and a minimal HTTP
  status/control UI (hand-written HTML/JS, no frontend build step) with
  raw and pcap export.
- `rootshell/`: a minimal root-shell helper for the deployment flow.

## Building

```
cargo build-mvp-daemon-firmware-devel   # fast-building, ARMv7 musl target
cargo build-mvp-daemon-firmware         # size-optimized firmware profile
```

Cross-compiling requires the `armv7-unknown-linux-musleabihf` Rust target
(`rustup target add armv7-unknown-linux-musleabihf`); no external C
cross-compiler needed, `rust-lld` handles it (see `.cargo/config.toml`).

Deploying a built binary to a device is access-method-specific; `dist/`
has an example payload manifest for the `orbic-toolkit`-style install flow.

## License

MIT (see `LICENSE`). Every crate here is MIT-licensed independently, too.

## Acknowledgements

The Qualcomm DIAG protocol this project extracts from was documented and
reverse-engineered across several independent projects this codebase
doesn't include but was informed by, cross-checking against real captured
data along the way: [QCSuper](https://github.com/P1sec/QCSuper),
[SCAT](https://github.com/fgsect/scat), and
[MobileInsight](https://github.com/mobile-insight/mobileinsight-core).

Full credit as well to the [EFF's Rayhunter
project](https://github.com/EFForg/rayhunter) for pioneering IMSI-catcher
detection built on this same interface, part of what pointed at the DIAG
protocol's potential in the first place. This project is an independent
reimplementation, though: no Rayhunter source is copied here, and its own
protocol knowledge is itself downstream of QCSuper and SCAT rather than
original to it.

RRC message content decode uses [hampi](https://github.com/ystero-dev/hampi/)
(the `asn1-compiler` / `asn1-codecs` crates), an independent ASN.1-to-Rust
compiler and codec runtime, run against 3GPP's own public ASN.1 spec text.
Not a dependency this project's clean-room boundary needed to route around:
a third-party tool consuming a public standard, same category as any other
crates.io dependency. See `asn1-specs/README.md` for the specifics.

## What's next

Next up: correlating detections with other sensor data (GPS position, other
RF context) instead of treating each capture stream in isolation. Multi
sensor fusion is on the roadmap; see [ROADMAP.md](ROADMAP.md) for where
this and everything else currently stands.
