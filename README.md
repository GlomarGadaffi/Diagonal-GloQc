# Diagonal-GloQc

A capture daemon for Qualcomm baseband modems, built around the `/dev/diag`
diagnostic interface. It opens the diag device, sets logging masks, and
records the raw diagnostic stream to disk for offline or live analysis.

The goal is maximal extraction: not just the OTA signalling plane (RRC/NAS),
but the internal/physical-layer plane (ML1, MAC, serving-cell measurements)
that a narrow log mask would otherwise leave uncaptured. See
[ARCHITECTURE.md](ARCHITECTURE.md) for how capture, decode, and egress are
structured, and [ROADMAP.md](ROADMAP.md) for what's built versus planned.

Internal tool. Not distributed.

## Layout

- `lib/` — the `/dev/diag` I/O layer, HDLC framing, diag message parsing,
  the qmdl archive format, GSMTAP conversion, and analysis heuristics.
- `daemon/` — the on-device service: recording lifecycle, config, web UI
  (`daemon/web/`, SvelteKit), HTTP API (axum).
- `rootshell/` — a minimal root-shell helper for devices that need it.
- `telcom-parser/` — ASN.1-derived LTE RRC message decoding used by the
  analysis heuristics.

## Building

```
./scripts/build-dev.sh        # frontend + daemon + rootshell, ARMv7 musl target
./scripts/build-dev.sh check  # just verify toolchain prerequisites
```

Cross-compiling the daemon requires the `armv7-unknown-linux-musleabihf`
Rust target (the script installs it via rustup if missing). See
`.cargo/config.toml` for the build aliases and target-specific linker flags,
and `dist/` for the on-device config template and init script.

Deploying a built binary to a device is device- and access-method-specific
(see `make.sh` for an `adb`-based example); there's no automated installer
in this repo.

## License

GPLv3 (see `LICENSE`). This carries forward licensing terms from code this
project builds on; see the license text for what that means for any future
distribution.
