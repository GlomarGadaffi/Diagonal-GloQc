//! Log record dispatch — spec/diag-protocol.md §7.
//!
//! An open registry, not a closed enum (spec §7): decoder coverage grows
//! incrementally and independently of capture coverage. Anything without
//! a registered decoder is preserved raw, never dropped.
//!
//! No production decoders live here yet — payload-layout knowledge for
//! individual log codes has to be independently re-derived per spec §2's
//! provenance discipline (the ecosystem sources, cross-checked against
//! real captures), not asserted from memory. Shipping a "decoder" without
//! that verification would be worse than no decoder: silently wrong
//! structured output instead of honest raw bytes. So: registry mechanics
//! only, proven with a synthetic test-only decoder.

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedBody {
    /// No decoder registered for this log-code — original bytes, untouched.
    Raw(Vec<u8>),
    /// A registered decoder produced a description of the payload.
    /// Deliberately a loose shape for now (spec §7 decoders arrive
    /// incrementally); replaced by typed variants as real decoders land.
    Decoded(String),
}

pub type Decoder = fn(&[u8]) -> DecodedBody;

#[derive(Default)]
pub struct Registry {
    decoders: HashMap<u16, Decoder>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a decoder for `log_type`. Overwrites any prior
    /// registration for the same code, matching how the vendored decoder
    /// table is inherently addressed by a single log-type key.
    pub fn register(&mut self, log_type: u16, decoder: Decoder) {
        self.decoders.insert(log_type, decoder);
    }

    /// Decodes `payload` if `log_type` has a registered decoder;
    /// otherwise preserves it raw. Never errors: an unregistered code is
    /// an expected, routine case, not a failure (spec §7).
    pub fn decode(&self, log_type: u16, payload: &[u8]) -> DecodedBody {
        match self.decoders.get(&log_type) {
            Some(decoder) => decoder(payload),
            None => DecodedBody::Raw(payload.to_vec()),
        }
    }

    pub fn is_registered(&self, log_type: u16) -> bool {
        self.decoders.contains_key(&log_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_decoder(payload: &[u8]) -> DecodedBody {
        DecodedBody::Decoded(format!("{} bytes: {payload:02x?}", payload.len()))
    }

    #[test]
    fn unregistered_code_falls_back_to_raw_not_dropped() {
        let registry = Registry::new();
        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(
            registry.decode(0xB1C0, &payload),
            DecodedBody::Raw(payload)
        );
    }

    #[test]
    fn registered_code_dispatches_to_its_decoder() {
        let mut registry = Registry::new();
        registry.register(0x1234, test_decoder);

        match registry.decode(0x1234, &[1, 2, 3]) {
            DecodedBody::Decoded(s) => assert!(s.contains("3 bytes")),
            other => panic!("expected Decoded, got {other:?}"),
        }
    }

    #[test]
    fn other_codes_stay_unaffected_by_an_unrelated_registration() {
        let mut registry = Registry::new();
        registry.register(0x1234, test_decoder);

        assert_eq!(
            registry.decode(0x9999, &[1, 2, 3]),
            DecodedBody::Raw(vec![1, 2, 3])
        );
    }

    #[test]
    fn re_registering_a_code_replaces_the_previous_decoder() {
        fn other_decoder(_: &[u8]) -> DecodedBody {
            DecodedBody::Decoded("replaced".to_string())
        }

        let mut registry = Registry::new();
        registry.register(0x1234, test_decoder);
        registry.register(0x1234, other_decoder);

        assert_eq!(
            registry.decode(0x1234, &[]),
            DecodedBody::Decoded("replaced".to_string())
        );
    }

    #[test]
    fn is_registered_reflects_registry_state() {
        let mut registry = Registry::new();
        assert!(!registry.is_registered(0x1234));
        registry.register(0x1234, test_decoder);
        assert!(registry.is_registered(0x1234));
    }
}
