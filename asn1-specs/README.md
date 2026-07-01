# lte-rrc-asn1

A generated LTE RRC UPER codec — real ASN.1 decode of RRC message content
(not just raw-PDU passthrough like `diag-core::rrc`), needed for
RRC-content-dependent detection heuristics (redirect-to-2G/3G, SIB6/7
downgrade broadcasts).

## Provenance

- **Spec source**: `specs/*.asn` are 3GPP TS 36.331's own published ASN.1
  module text (`EUTRA-RRC-Definitions`, `EUTRA-InterNodeDefinitions`,
  `EUTRA-Sidelink-Preconf`, `EUTRA-UE-Variables`, `PC5-RRC-Definitions`) —
  a public telecommunications standard, not proprietary source, and not
  original creative work of any project this codebase is descended from.
  Extracted via [Objective Systems'](https://obj-sys.com) published copy
  of the same public spec text — a standard, common source for these
  files across the telecom tooling ecosystem.
- **Compiler**: [`hampi`](https://github.com/ystero-dev/hampi/)
  (`asn1-compiler` / `rs-asn1c`, Apache-2.0 OR MIT, "Ystero Project
  Developers" — an independent project, unrelated to this codebase's
  history). `src/lte_rrc.rs` is generated fresh by running this compiler
  against the spec files above, not copied from anywhere.

## Regenerating

```
cargo install asn1-compiler --locked
rs-asn1c --codec uper --module src/lte_rrc.rs -- specs/EUTRA* specs/PC5-RRC-Definitions.asn
```

## Known limitations

- ~6800 build warnings — mostly non-upper-camel-case generated type names
  (the compiler doesn't rename ASN.1 identifiers that don't match Rust
  convention) and some unreachable-pattern warnings in generated enum
  match arms. Cosmetic; doesn't affect correctness.
- Compiling the full module produced several `"Fields for some sequence
  additions may not be generated!"` warnings during generation — likely
  affects some later-release (`r15`/`r16`) optional extension fields on
  a subset of message types. The core message types needed for this
  project's heuristics (`RRCConnectionRelease`, `SystemInformationBlockType6`,
  `SystemInformationBlockType7`, `RedirectedCarrierInfo`) generated and
  compiled successfully; not every message in the full R16 spec has been
  individually verified.
