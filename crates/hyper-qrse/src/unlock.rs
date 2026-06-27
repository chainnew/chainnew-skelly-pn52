//! Attested hybrid unlock flow (PAD-QRSE-001 §13.1, Phase 3+4).
//!
//! [`attested_hybrid_unlock`] is the gated path from a signed manifest to a live
//! KEK. Every gate fails closed; the order is fixed and security-relevant:
//!
//! 1. **Manifest verification** — require a valid post-quantum signature.
//! 2. **Downgrade check** — reject version rollback and suite downgrade.
//! 3. **Attested KMS decision** — release the remote leg only if measured-boot
//!    attestation (PCRs / boot policy / capsule / hypervisor version) passes.
//! 4. **Decapsulate both KEM legs** — classical and post-quantum.
//! 5. **Build the combiner context** from the manifest + measurement + suite.
//! 6. **Hybrid combine** the two shared secrets into a KEK (fail-closed if
//!    either leg is dead).
//! 7. **Append a `key_release` receipt** to the audit spine.
//!
//! All denials are also recorded on the [`ReceiptChain`] so the audit spine
//! stays complete and tamper-evident on the deny path too.

use hyper_attest::{
    BootMeasurement, KeyReleaseDecision, KeyReleaseRequest, KmsSimulator,
};
use hyper_receipts::{ReceiptChain, ReceiptEvent};

use crate::combiner::{hybrid_combine, CombinerContext, Kek, KemSuite};
use crate::crypto::{CryptoError, DecapKey, Kem, KemCiphertext, Verifier};
use crate::downgrade::{self, DowngradeVerdict, VersionFloor};
use crate::manifest::{ManifestError, QrsdManifest};

/// Policy id stamped onto QRSE unlock receipts.
pub const QRSE_UNLOCK_POLICY_ID: &str = "pol-qrse-attested-hybrid-unlock";

/// Default KEK length in bytes (AES-256-XTS wraps via a 32-byte KEK here).
pub const KEK_LEN: usize = 32;

/// Inputs to an attested hybrid unlock.
#[derive(Debug, Clone)]
pub struct UnlockRequest {
    pub manifest: QrsdManifest,
    pub boot_measurement: BootMeasurement,
    pub device_id: String,
    pub hypervisor_version: u64,
}

/// Why an unlock failed. Every variant means **no KEK was produced**.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UnlockError {
    #[error("manifest verification failed: {0}")]
    ManifestVerification(#[from] ManifestError),
    #[error("downgrade rejected: {0:?}")]
    Downgrade(DowngradeVerdict),
    #[error("attestation denied: {0}")]
    AttestationDenied(String),
    #[error("no active hybrid keyslot to derive a suite from")]
    NoHybridKeyslot,
    #[error("crypto failure: {0}")]
    Crypto(#[from] CryptoError),
}

/// The decapsulation material for one KEM leg.
#[derive(Debug, Clone)]
pub struct KemLeg<'a> {
    pub dk: &'a DecapKey,
    pub ct: &'a KemCiphertext,
}

/// Run the full attested hybrid unlock. Returns a [`Kek`] on success; on any
/// gate failure returns an [`UnlockError`] (and a deny receipt is recorded).
#[allow(clippy::too_many_arguments)]
pub fn attested_hybrid_unlock(
    req: &UnlockRequest,
    verifiers: &[&dyn Verifier],
    floor: &VersionFloor,
    monotonic_counter: u64,
    classical_kem: &dyn Kem,
    pqc_kem: &dyn Kem,
    classical_leg: KemLeg<'_>,
    pqc_leg: KemLeg<'_>,
    kms: &KmsSimulator,
    chain: &mut ReceiptChain,
) -> Result<Kek, UnlockError> {
    let manifest = &req.manifest;
    let inputs_hash = hyper_receipts::sha384_hex(&manifest.signing_bytes());

    // 1. Verify manifest signatures (post-quantum required).
    let verified = match manifest.verify(verifiers) {
        Ok(v) => v,
        Err(e) => {
            record_deny(chain, manifest, &inputs_hash, "manifest_verification");
            return Err(UnlockError::ManifestVerification(e));
        }
    };

    // 2. Downgrade check.
    let verdict = downgrade::check(&verified, floor, monotonic_counter);
    if !verdict.is_ok() {
        record_deny(chain, manifest, &inputs_hash, "downgrade");
        return Err(UnlockError::Downgrade(verdict));
    }

    // Determine the hybrid suite from an active hybrid keyslot (needed for the
    // combiner context). Absent one, there is no PQC unlock path.
    let suite: KemSuite = match verified
        .keyslots()
        .iter()
        .find(|s| s.is_active() && s.is_hybrid() && !s.classical_only())
        .and_then(|s| s.kem_suite().cloned())
    {
        Some(s) => s,
        None => {
            record_deny(chain, manifest, &inputs_hash, "no_hybrid_keyslot");
            return Err(UnlockError::NoHybridKeyslot);
        }
    };

    // 3. Attested KMS decision (this records its own key_release receipt).
    let bm = &req.boot_measurement;
    let kms_req = KeyReleaseRequest {
        request_type: "key_release".to_string(),
        device_id: req.device_id.clone(),
        vm_id: manifest.volume_id.clone(),
        capsule_hash: bm.capsule_manifest_hash.clone(),
        boot_policy_hash: bm.boot_policy_hash.clone(),
        pcrs: bm.pcrs.clone(),
        hypervisor_version: req.hypervisor_version,
        nonce: format!(
            "{}:{}",
            manifest.volume_id, manifest.boot_policy.minimum_boot_manifest_version
        ),
    };
    match kms.evaluate(&kms_req, chain) {
        KeyReleaseDecision::Allow { .. } => {}
        KeyReleaseDecision::Deny { reason } => {
            return Err(UnlockError::AttestationDenied(reason));
        }
    }

    // 4. Decapsulate both legs.
    let ss_classical = classical_kem.decapsulate(classical_leg.dk, classical_leg.ct)?;
    let ss_pqc = pqc_kem.decapsulate(pqc_leg.dk, pqc_leg.ct)?;

    // 5. Build the combiner context from manifest + measurement + suite.
    let context = CombinerContext {
        volume_id: manifest.volume_id.clone(),
        device_id: req.device_id.clone(),
        policy_id: manifest.boot_policy.policy_id.clone(),
        policy_version: manifest.boot_policy.minimum_boot_manifest_version,
        algorithm_suite: suite,
        boot_measurement: bm.boot_policy_hash.clone(),
    };

    // 6. Hybrid combine (transcript binds the entire signed manifest body).
    let transcript = manifest.signing_bytes();
    let kek = hybrid_combine(&ss_classical, &ss_pqc, &transcript, &context, KEK_LEN)?;

    // 7. Append the final unlock receipt to the audit spine.
    chain.append(
        ReceiptEvent::KeyRelease,
        manifest.volume_id.clone(),
        "allow",
        QRSE_UNLOCK_POLICY_ID,
        inputs_hash,
    );

    Ok(kek)
}

/// Record a fail-closed deny on the audit spine.
fn record_deny(chain: &mut ReceiptChain, manifest: &QrsdManifest, inputs_hash: &str, stage: &str) {
    chain.append(
        ReceiptEvent::KeyRelease,
        manifest.volume_id.clone(),
        format!("deny:{stage}"),
        QRSE_UNLOCK_POLICY_ID,
        inputs_hash.to_string(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{DeterministicKem, DeterministicSigner};
    use crate::manifest::test_support::sample_manifest;
    use hyper_attest::{BootMeasurement, KmsPolicy, PcrBank, PCR0, PCR11, PCR7};

    struct Fixture {
        req: UnlockRequest,
        signer: DeterministicSigner,
        classical_kem: DeterministicKem,
        pqc_kem: DeterministicKem,
        classical_dk: DecapKey,
        classical_ct: KemCiphertext,
        pqc_dk: DecapKey,
        pqc_ct: KemCiphertext,
        kms: KmsSimulator,
    }

    fn pcrs() -> PcrBank {
        let mut p = PcrBank::new();
        p.set(PCR0, "sha384:fw").set(PCR7, "sha384:sb").set(PCR11, "sha384:kern");
        p
    }

    fn boot_measurement() -> BootMeasurement {
        BootMeasurement::new(
            "sha384:uefi",
            "sha384:kernel",
            "sha384:bootpol",
            "sha384:capsule",
            pcrs(),
        )
    }

    fn make_fixture() -> Fixture {
        let mut manifest = sample_manifest(true);
        let signer = DeterministicSigner::ml_dsa_65("disk-pq", b"seed");
        manifest.sign(&signer, "disk-manifest");

        let bm = boot_measurement();
        let req = UnlockRequest {
            manifest,
            boot_measurement: bm.clone(),
            device_id: "pn52-lab-001".into(),
            hypervisor_version: 9,
        };

        // Set up matching KEM legs.
        let classical_kem = DeterministicKem::x25519();
        let pqc_kem = DeterministicKem::ml_kem_768();
        let (cek, classical_dk) = classical_kem.generate_keypair(b"c-seed");
        let (cct, _) = classical_kem.encapsulate(&cek, b"c-rand");
        let (pek, pqc_dk) = pqc_kem.generate_keypair(b"p-seed");
        let (pct, _) = pqc_kem.encapsulate(&pek, b"p-rand");

        let policy = KmsPolicy {
            expected_pcrs: pcrs(),
            min_hypervisor_version: 1,
            allowed_capsule_hashes: vec![bm.capsule_manifest_hash.clone()],
            expected_boot_policy_hash: bm.boot_policy_hash.clone(),
        };
        let kms = KmsSimulator::new(policy);

        Fixture {
            req,
            signer,
            classical_kem,
            pqc_kem,
            classical_dk,
            classical_ct: cct,
            pqc_dk,
            pqc_ct: pct,
            kms,
        }
    }

    fn run(f: &Fixture, floor: &VersionFloor, chain: &mut ReceiptChain) -> Result<Kek, UnlockError> {
        let v = f.signer.verifier();
        attested_hybrid_unlock(
            &f.req,
            &[&v],
            floor,
            0,
            &f.classical_kem,
            &f.pqc_kem,
            KemLeg {
                dk: &f.classical_dk,
                ct: &f.classical_ct,
            },
            KemLeg {
                dk: &f.pqc_dk,
                ct: &f.pqc_ct,
            },
            &f.kms,
            chain,
        )
    }

    #[test]
    fn happy_path_yields_kek_and_chain_verifies() {
        let f = make_fixture();
        let mut chain = ReceiptChain::new();
        let kek = run(&f, &VersionFloor::strict(7), &mut chain).expect("unlock");
        assert_eq!(kek.len(), KEK_LEN);
        assert!(!kek.is_empty());
        // KMS allow receipt + final unlock receipt.
        assert_eq!(chain.len(), 2);
        assert_eq!(chain.verify(), Ok(()));
        assert_eq!(chain.receipts()[1].decision, "allow");
    }

    #[test]
    fn deterministic_kek() {
        let f = make_fixture();
        let mut c1 = ReceiptChain::new();
        let mut c2 = ReceiptChain::new();
        let k1 = run(&f, &VersionFloor::strict(7), &mut c1).unwrap();
        let k2 = run(&f, &VersionFloor::strict(7), &mut c2).unwrap();
        assert!(k1 == k2);
    }

    #[test]
    fn tampered_manifest_blocks_unlock() {
        let mut f = make_fixture();
        // Tamper after signing -> signature no longer covers the body.
        f.req.manifest.boot_policy.minimum_boot_manifest_version = 999;
        let mut chain = ReceiptChain::new();
        let err = run(&f, &VersionFloor::strict(7), &mut chain).unwrap_err();
        assert!(matches!(err, UnlockError::ManifestVerification(_)));
        // Deny recorded, no allow, chain still valid.
        assert_eq!(chain.len(), 1);
        assert!(chain.receipts()[0].decision.starts_with("deny"));
        assert_eq!(chain.verify(), Ok(()));
    }

    #[test]
    fn stale_version_blocks_unlock() {
        let f = make_fixture();
        let mut chain = ReceiptChain::new();
        // Floor higher than the manifest's version 7.
        let err = run(&f, &VersionFloor::strict(99), &mut chain).unwrap_err();
        assert!(matches!(err, UnlockError::Downgrade(_)));
        assert_eq!(chain.len(), 1);
        assert!(chain.receipts()[0].decision.starts_with("deny"));
        assert_eq!(chain.verify(), Ok(()));
    }

    #[test]
    fn failed_attestation_blocks_unlock() {
        let mut f = make_fixture();
        // Break the boot policy hash so the KMS denies (V9).
        f.req.boot_measurement.boot_policy_hash = "sha384:EVIL".into();
        let mut chain = ReceiptChain::new();
        let err = run(&f, &VersionFloor::strict(7), &mut chain).unwrap_err();
        match err {
            UnlockError::AttestationDenied(reason) => {
                assert!(reason.starts_with("boot_policy_hash_mismatch"));
            }
            other => panic!("expected attestation denial, got {other:?}"),
        }
        // KMS deny receipt recorded; no final allow receipt.
        assert_eq!(chain.len(), 1);
        assert_eq!(chain.receipts()[0].decision, "deny");
        assert_eq!(chain.verify(), Ok(()));
    }
}
