//! Hybrid KEM suite selection for the storage data/control plane.
//!
//! This module keeps a *thin, `&'static`* description of the hybrid KEM suite
//! used by the LUKS provisioning path, and bridges it to the algorithm-agile,
//! owned [`hyper_qrse::combiner::KemSuite`] that the QRSE control plane actually
//! threads through [`hyper_qrse::combiner::hybrid_combine`]. Nothing here invents
//! crypto: it only selects suite identifiers and builds the binding context.

use hyper_qrse::combiner::{CombinerContext, KemSuite};

/// A thin, statically-known description of a hybrid classical+PQC KEM suite.
///
/// Mirrors [`hyper_qrse::combiner::KemSuite`] but with `&'static str` fields so
/// it can live in `const`s like [`DEFAULT_TRANSITION_SUITE`]. Convert to the
/// owned, serde-friendly `KemSuite` via [`From`] / [`HybridKemSuite::to_kem_suite`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HybridKemSuite {
    pub classical: &'static str,
    pub pqc: &'static str,
    pub combiner: &'static str,
}

/// The default commercial transition profile (PAD §3.2): X25519 + ML-KEM-768,
/// combined with HKDF-SHA384. Kept consistent with
/// [`hyper_qrse::combiner::KemSuite::transition_768`].
pub const DEFAULT_TRANSITION_SUITE: HybridKemSuite = HybridKemSuite {
    classical: "x25519",
    pqc: "ml-kem-768",
    combiner: "hkdf-sha384",
};

/// The CNSA-leaning high-assurance profile: X25519 + ML-KEM-1024.
/// Kept consistent with [`hyper_qrse::combiner::KemSuite::high_assurance_1024`].
pub const HIGH_ASSURANCE_SUITE: HybridKemSuite = HybridKemSuite {
    classical: "x25519",
    pqc: "ml-kem-1024",
    combiner: "hkdf-sha384",
};

impl HybridKemSuite {
    /// Convert to the owned, algorithm-agile control-plane suite.
    pub fn to_kem_suite(&self) -> KemSuite {
        KemSuite {
            classical: self.classical.to_string(),
            pqc: self.pqc.to_string(),
            combiner: self.combiner.to_string(),
        }
    }

    /// Canonical, unambiguous wire form (matches `KemSuite::canonical`).
    pub fn canonical(&self) -> String {
        format!("{}+{}+{}", self.classical, self.pqc, self.combiner)
    }
}

impl From<HybridKemSuite> for KemSuite {
    fn from(s: HybridKemSuite) -> Self {
        s.to_kem_suite()
    }
}

impl From<&HybridKemSuite> for KemSuite {
    fn from(s: &HybridKemSuite) -> Self {
        s.to_kem_suite()
    }
}

/// Legacy string form of the combiner context (kept for compatibility).
///
/// Prefer [`build_combiner_context`], which produces the structured,
/// length-prefixed [`CombinerContext`] the QRSE combiner actually binds.
pub fn combiner_context(volume_id: &str, device_id: &str, policy_version: u64) -> String {
    format!("chainnew-hyper-slate:v1:{volume_id}:{device_id}:{policy_version}")
}

/// Build the structured [`CombinerContext`] bound into every hybrid KEK
/// derivation (PAD §9.4). The suite is carried through unchanged so a suite
/// downgrade necessarily changes the derived KEK.
#[allow(clippy::too_many_arguments)]
pub fn build_combiner_context(
    volume_id: impl Into<String>,
    device_id: impl Into<String>,
    policy_id: impl Into<String>,
    policy_version: u64,
    suite: &HybridKemSuite,
    boot_measurement: impl Into<String>,
) -> CombinerContext {
    CombinerContext {
        volume_id: volume_id.into(),
        device_id: device_id.into(),
        policy_id: policy_id.into(),
        policy_version,
        algorithm_suite: suite.to_kem_suite(),
        boot_measurement: boot_measurement.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_suite_matches_qrse_transition_768() {
        let bridged: KemSuite = DEFAULT_TRANSITION_SUITE.into();
        assert_eq!(bridged, KemSuite::transition_768());
        assert_eq!(bridged.canonical(), DEFAULT_TRANSITION_SUITE.canonical());
    }

    #[test]
    fn high_assurance_suite_matches_qrse_1024() {
        let bridged: KemSuite = (&HIGH_ASSURANCE_SUITE).into();
        assert_eq!(bridged, KemSuite::high_assurance_1024());
    }

    #[test]
    fn ref_and_owned_from_agree() {
        let owned: KemSuite = DEFAULT_TRANSITION_SUITE.into();
        let by_ref: KemSuite = (&DEFAULT_TRANSITION_SUITE).into();
        assert_eq!(owned, by_ref);
        assert_eq!(owned, DEFAULT_TRANSITION_SUITE.to_kem_suite());
    }

    #[test]
    fn combiner_context_binds_suite_and_inputs() {
        let ctx = build_combiner_context(
            "vol-1",
            "pn52-lab-001",
            "policy-prod-v4",
            42,
            &DEFAULT_TRANSITION_SUITE,
            "sha384:bootmeas",
        );
        assert_eq!(ctx.algorithm_suite, KemSuite::transition_768());
        assert_eq!(ctx.policy_version, 42);
        // Length-prefixed encoding includes the canonical suite string.
        let bytes = ctx.to_bytes();
        let needle = DEFAULT_TRANSITION_SUITE.canonical();
        assert!(bytes
            .windows(needle.len())
            .any(|w| w == needle.as_bytes()));
    }

    #[test]
    fn legacy_string_context_still_works() {
        assert_eq!(
            combiner_context("vol-1", "dev-1", 7),
            "chainnew-hyper-slate:v1:vol-1:dev-1:7"
        );
    }
}
