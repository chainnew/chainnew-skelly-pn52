//! Downgrade protection (PAD-QRSE-001 §9.3 / §16.2).
//!
//! Two downgrade families are defended here, on top of an already
//! post-quantum-verified manifest ([`crate::manifest::VerifiedManifest`]):
//!
//! 1. **Version rollback** — replaying an older, signed manifest. Rejected when
//!    the manifest's `minimum_boot_manifest_version` is below the tenant floor
//!    *or* below the device's monotonic counter (a previously seen version).
//! 2. **Suite / algorithm downgrade** — stripping the PQC leg. Rejected when
//!    policy requires PQC but the manifest is classical-only, or when a hybrid
//!    keyslot has had its post-quantum leg removed.
//!
//! Hard rule (PAD §16.2): once a volume policy marks hybrid as required, a
//! downgrade from hybrid to classical-only MUST be rejected.

use crate::combiner::KemSuite;
use crate::manifest::VerifiedManifest;

/// Tenant-level downgrade floor / policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionFloor {
    /// The lowest acceptable `minimum_boot_manifest_version`.
    pub tenant_min_manifest_version: u64,
    /// Whether a post-quantum unlock path (hybrid keyslot) is required.
    pub require_pqc_signature: bool,
    /// Whether a fully classical-only manifest is tolerated despite the above.
    pub allow_classical_only: bool,
}

impl VersionFloor {
    /// A strict floor: no classical-only, PQC required, at `min` version.
    pub fn strict(min: u64) -> Self {
        VersionFloor {
            tenant_min_manifest_version: min,
            require_pqc_signature: true,
            allow_classical_only: false,
        }
    }
}

/// Verdict of a downgrade check. Only [`DowngradeVerdict::Ok`] permits unlock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DowngradeVerdict {
    /// No downgrade detected.
    Ok,
    /// The manifest version is below the tenant floor or the monotonic counter.
    RejectedStaleVersion { found: u64, floor: u64 },
    /// PQC is required but the manifest offers no post-quantum unlock path.
    RejectedClassicalOnly,
    /// A hybrid keyslot's post-quantum leg has been stripped (suite downgrade).
    RejectedSuiteDowngrade { from: String, to: String },
}

impl DowngradeVerdict {
    /// Whether the verdict permits unlock.
    pub fn is_ok(&self) -> bool {
        matches!(self, DowngradeVerdict::Ok)
    }
}

/// Check a verified manifest for downgrade against `floor` and the device's
/// `monotonic_counter` (the highest version previously accepted). Fail-closed:
/// returns the first violating verdict.
pub fn check(
    manifest: &VerifiedManifest,
    floor: &VersionFloor,
    monotonic_counter: u64,
) -> DowngradeVerdict {
    let found = manifest.min_boot_manifest_version();

    // 1. Version rollback vs tenant floor.
    if found < floor.tenant_min_manifest_version {
        return DowngradeVerdict::RejectedStaleVersion {
            found,
            floor: floor.tenant_min_manifest_version,
        };
    }
    // 1b. Version rollback vs device monotonic counter (replay of old metadata).
    if found < monotonic_counter {
        return DowngradeVerdict::RejectedStaleVersion {
            found,
            floor: monotonic_counter,
        };
    }

    // 2. Suite / classical-only downgrade.
    if floor.require_pqc_signature && !floor.allow_classical_only {
        // A hybrid slot with its PQC leg stripped is a suite downgrade.
        for slot in manifest.keyslots() {
            if slot.is_hybrid() && slot.classical_only() {
                let to = slot
                    .kem_suite()
                    .map(KemSuite::canonical)
                    .unwrap_or_default();
                let from = slot
                    .kem_suite()
                    .map(|s| format!("{}+<pqc-required>+{}", s.classical, s.combiner))
                    .unwrap_or_else(|| "hybrid".to_string());
                return DowngradeVerdict::RejectedSuiteDowngrade { from, to };
            }
        }
        // No hybrid (PQC) unlock path at all -> classical-only manifest.
        if !manifest.keyslots().iter().any(|s| s.is_hybrid()) {
            return DowngradeVerdict::RejectedClassicalOnly;
        }
    }

    DowngradeVerdict::Ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::combiner::KemSuite;
    use crate::crypto::DeterministicSigner;
    use crate::keyslot::{Keyslot, KeyslotKind, KeyslotStatus, KmsAttestation};
    use crate::manifest::test_support::sample_manifest;
    use crate::manifest::QrsdManifest;

    fn verify(m: &QrsdManifest, signer: &DeterministicSigner) -> VerifiedManifest {
        let v = signer.verifier();
        m.verify(&[&v]).expect("pq verified")
    }

    fn signed(m: &mut QrsdManifest) -> DeterministicSigner {
        let signer = DeterministicSigner::ml_dsa_65("disk-pq", b"seed");
        m.sign(&signer, "disk-manifest");
        signer
    }

    #[test]
    fn ok_when_version_and_suite_satisfy() {
        let mut m = sample_manifest(true);
        let signer = signed(&mut m);
        let vm = verify(&m, &signer);
        let floor = VersionFloor::strict(7);
        assert_eq!(check(&vm, &floor, 5), DowngradeVerdict::Ok);
    }

    #[test]
    fn rejects_stale_version_vs_floor() {
        let mut m = sample_manifest(true);
        m.boot_policy.minimum_boot_manifest_version = 4;
        let signer = signed(&mut m);
        let vm = verify(&m, &signer);
        let floor = VersionFloor::strict(7);
        assert_eq!(
            check(&vm, &floor, 0),
            DowngradeVerdict::RejectedStaleVersion { found: 4, floor: 7 }
        );
    }

    #[test]
    fn rejects_stale_version_vs_monotonic_counter() {
        let mut m = sample_manifest(true);
        m.boot_policy.minimum_boot_manifest_version = 7;
        let signer = signed(&mut m);
        let vm = verify(&m, &signer);
        let floor = VersionFloor::strict(7);
        // Device has previously accepted version 9; replaying 7 is a rollback.
        assert_eq!(
            check(&vm, &floor, 9),
            DowngradeVerdict::RejectedStaleVersion { found: 7, floor: 9 }
        );
    }

    #[test]
    fn rejects_classical_only_when_pqc_required() {
        // No hybrid keyslot, but still PQ-signed so a VerifiedManifest exists.
        let mut m = sample_manifest(false);
        let signer = signed(&mut m);
        let vm = verify(&m, &signer);
        let floor = VersionFloor::strict(7);
        assert_eq!(check(&vm, &floor, 0), DowngradeVerdict::RejectedClassicalOnly);
    }

    #[test]
    fn classical_only_allowed_when_policy_permits() {
        let mut m = sample_manifest(false);
        let signer = signed(&mut m);
        let vm = verify(&m, &signer);
        let floor = VersionFloor {
            tenant_min_manifest_version: 7,
            require_pqc_signature: true,
            allow_classical_only: true,
        };
        assert_eq!(check(&vm, &floor, 0), DowngradeVerdict::Ok);
    }

    #[test]
    fn rejects_suite_downgrade_when_pqc_leg_stripped() {
        let mut m = sample_manifest(false);
        // Add a hybrid slot whose PQC leg has been stripped.
        m.key_hierarchy.keyslots.push(Keyslot::new(
            2,
            KeyslotStatus::Active,
            KeyslotKind::HybridRemoteKms {
                kem: KemSuite {
                    classical: "x25519".into(),
                    pqc: "".into(),
                    combiner: "hkdf-sha384".into(),
                },
                attestation: KmsAttestation {
                    required: true,
                    accepted_tee: vec!["amd-sev-snp".into()],
                    measurement_policy_ref: "pol".into(),
                },
            },
        ));
        let signer = signed(&mut m);
        let vm = verify(&m, &signer);
        let floor = VersionFloor::strict(7);
        match check(&vm, &floor, 0) {
            DowngradeVerdict::RejectedSuiteDowngrade { to, .. } => {
                assert!(to.contains("x25519"));
            }
            other => panic!("expected suite downgrade, got {other:?}"),
        }
    }
}
