//! Clean-room reimplementation of the DIAG capture core.
//!
//! Built module-by-module from `spec/diag-protocol.md`, not from this
//! repo's vendored `lib/`. See that spec's §2 for provenance and an
//! honest statement of what "clean room" does and doesn't mean here.
//!
//! Each module here corresponds to one spec section and stands alone
//! until enough of the stack exists to replace the vendored equivalent
//! (spec §10).

pub mod archive;
pub mod dispatch;
pub mod envelope;
pub mod gsmtap;
pub mod hdlc;
pub mod heuristics;
pub mod ip_traffic;
pub mod legacy_signalling;
pub mod log;
pub mod mask;
pub mod nas;
pub mod nas_ie;
pub mod pcap;
pub mod rrc;
