# Diagonal-GloQc

A capture daemon for Qualcomm baseband modems, built around the `/dev/diag`
diagnostic interface. It opens the diag device, enables maximal logging (every
log code the modem reports as available, not a curated subset), and records
the raw diagnostic stream to disk.

The goal is maximal extraction: not just the OTA signalling plane (RRC/NAS),
but the internal/physical-layer plane (ML1, MAC, serving-cell measurements)
that a narrow log mask would otherwise leave uncaptured.

Everything here is an independent, from-scratch implementation — see
[spec/diag-protocol.md](spec/diag-protocol.md) for the protocol spec this is
built from and its provenance notes, and [ARCHITECTURE.md](ARCHITECTURE.md) /
[ROADMAP.md](ROADMAP.md) for how it's structured and what's built versus
planned.

## Layout

- `diag-core/` — protocol logic as a portable library: HDLC framing
  (`hdlc`), the outer container envelope (`envelope`), mask configuration
  (`mask`), the LOG message header and RRC OTA / plain NAS body decoders
  (`log`, `rrc`, `nas`), GSMTAP header construction (`gsmtap`), a pcap file
  writer (`pcap`), the raw archive format (`archive`), and an open decoder
  registry for log types without a dedicated decoder yet (`dispatch`).
- `mvp-daemon/` — the on-device binary: `/dev/diag` bringup, the capture
  loop, and a minimal HTTP status/control UI (hand-written HTML/JS, no
  frontend build step) with raw and pcap export.

## Building

```
cargo build-mvp-daemon-firmware-devel   # fast-building, ARMv7 musl target
cargo build-mvp-daemon-firmware         # size-optimized firmware profile
```

Cross-compiling requires the `armv7-unknown-linux-musleabihf` Rust target
(`rustup target add armv7-unknown-linux-musleabihf`) — no external C
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
detection built on this same interface — it's part of what pointed at the
DIAG protocol's potential in the first place. This project is an independent
reimplementation, though: no Rayhunter source is copied here, and its own
protocol knowledge is itself downstream of QCSuper and SCAT rather than
original to it.
