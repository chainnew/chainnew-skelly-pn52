//! Acceptance tests for the QRSE structure layer (PAD-QRSE-001).
//!
//! These exercise the cross-module flow end to end against the public API only:
//! keyslot serde round-trip, manifest sign/verify (PQ-required), downgrade
//! rejection, and the full attested hybrid unlock — both the happy path and the
//! fail-closed paths (tamper / stale version / failed attestation).

use hyper_attest::{BootMeasurement, KmsPolicy, KmsSimulator, PcrBank, PCR0, PCR11, PCR7};
use hyper_receipts::ReceiptChain;

use hyper_qrse::combiner::KemSuite;
use hyper_qrse::crypto::{
    DecapKey, DeterministicKem, DeterministicSigner, Kem, KemCiphertext, Verifier,
};
use hyper_qrse::downgrade::{check, DowngradeVerdict, VersionFloor};
use hyper_qrse::keyslot::{
    Argon2idKdf, Keyslot, KeyslotKind, KeyslotStatus, KmsAttestation, WrapSpec,
};
use hyper_qrse::manifest::{
    Audit, BootPolicy, DataPlane, Integrity, ManifestError, ManifestKeyHierarchy, QrsdManifest,
    RollbackProtection, QRSD_FORMAT,
};
use hyper_qrse::unlock::{attested_hybrid_unlock, KemLeg, UnlockError, UnlockRequest, KEK_LEN};

// --------------------------------------------------------------------------
// Fixtures
// --------------------------------------------------------------------------

fn argon2_slot() -> Keyslot {
    Keyslot::new(
        0,
        KeyslotStatus::Active,
        KeyslotKind::Argon2idPassphrase {
            kdf: Argon2idKdf {
                algorithm: "argon2id".into(),
                memory_kib: 1_048_576,
                time_cost: 3,
                parallelism: 4,
            },
            wrap: WrapSpec {
                algorithm: "aes-256-gcm".into(),
                wrapped_key_ref: "blob:slot0".into(),
            },
        },
    )
}

fn hybrid_slot() -> Keyslot {
    Keyslot::new(
        2,
        KeyslotStatus::Active,
        KeyslotKind::HybridRemoteKms {
            kem: KemSuite::transition_768(),
            attestation: KmsAttestation {
                required: true,
                accepted_tee: vec!["amd-sev-snp".into(), "intel-tdx".into()],
                measurement_policy_ref: "pol-meas-v3".into(),
            },
        },
    )
}

fn manifest(with_hybrid: bool) -> QrsdManifest {
    let mut keyslots = vec![argon2_slot()];
    if with_hybrid {
        keyslots.push(hybrid_slot());
    }
    QrsdManifest {
        format: QRSD_FORMAT.to_string(),
        volume_id: "urn:uuid:vol-acceptance".into(),
        created_at: "2026-06-27T00:00:00Z".into(),
        data_plane: DataPlane {
            cipher: "AES-256-XTS".into(),
            xts_raw_key_bits: 512,
            sector_size: 4096,
            integrity: Integrity {
                mode: "none".into(),
                alternatives: vec!["dm-integrity".into()],
            },
        },
        boot_policy: BootPolicy {
            policy_id: "pol-boot-v4".into(),
            secure_boot_required: true,
            measured_boot_required: true,
            pcr_profile: vec!["pcr0".into(), "pcr7".into(), "pcr11".into()],
            minimum_boot_manifest_version: 7,
            rollback_protection: RollbackProtection {
                type_: "tpm-nv-counter".into(),
                counter_name: "qrsd.rollback".into(),
            },
        },
        key_hierarchy: ManifestKeyHierarchy {
            volume_master_key_version: 3,
            active_dek_version: 11,
            keyslots,
        },
        signatures: Vec::new(),
        audit: Audit {
            last_rotation: "2026-06-01T00:00:00Z".into(),
            last_attested_unlock_receipt: "rcpt-000000-aaaaaaaaaaaaaaaa".into(),
            log_chain: "sha384:chainhead".into(),
        },
    }
}

fn pcrs() -> PcrBank {
    let mut p = PcrBank::new();
    p.set(PCR0, "sha384:fw")
        .set(PCR7, "sha384:sb")
        .set(PCR11, "sha384:kern");
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

fn kms_for(bm: &BootMeasurement) -> KmsSimulator {
    KmsSimulator::new(KmsPolicy {
        expected_pcrs: pcrs(),
        min_hypervisor_version: 1,
        allowed_capsule_hashes: vec![bm.capsule_manifest_hash.clone()],
        expected_boot_policy_hash: bm.boot_policy_hash.clone(),
    })
}

struct Legs {
    classical_kem: DeterministicKem,
    pqc_kem: DeterministicKem,
    classical_dk: DecapKey,
    classical_ct: KemCiphertext,
    pqc_dk: DecapKey,
    pqc_ct: KemCiphertext,
}

fn legs() -> Legs {
    let classical_kem = DeterministicKem::x25519();
    let pqc_kem = DeterministicKem::ml_kem_768();
    let (cek, classical_dk) = classical_kem.generate_keypair(b"c");
    let (classical_ct, _) = classical_kem.encapsulate(&cek, b"cr");
    let (pek, pqc_dk) = pqc_kem.generate_keypair(b"p");
    let (pqc_ct, _) = pqc_kem.encapsulate(&pek, b"pr");
    Legs {
        classical_kem,
        pqc_kem,
        classical_dk,
        classical_ct,
        pqc_dk,
        pqc_ct,
    }
}

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

#[test]
fn keyslot_serde_round_trips_pad_shape() {
    for slot in [argon2_slot(), hybrid_slot()] {
        let json = serde_json::to_string_pretty(&slot).unwrap();
        let back: Keyslot = serde_json::from_str(&json).unwrap();
        assert_eq!(back, slot);
    }
    // The hybrid slot exposes the kind tag and the PQC suite as flat fields.
    let json = serde_json::to_string(&hybrid_slot()).unwrap();
    assert!(json.contains(r#""kind":"hybrid_remote_kms""#));
    assert!(json.contains(r#""pqc":"ml-kem-768""#));
}

#[test]
fn manifest_sign_then_verify_happy_path() {
    let mut m = manifest(true);
    let signer = DeterministicSigner::ml_dsa_65("disk-pq", b"seed");
    m.sign(&signer, "disk-manifest");
    let v = signer.verifier();
    let verified = m.verify(&[&v]).expect("pq verified");
    assert_eq!(verified.min_boot_manifest_version(), 7);
}

#[test]
fn classical_only_manifest_is_not_pq_verified() {
    let mut m = manifest(true);
    let ecdsa = DeterministicSigner::ecdsa_p384("disk-classical", b"seed-c");
    m.sign(&ecdsa, "classical-compat");
    let v = ecdsa.verifier();
    assert_eq!(
        m.verify(&[&v]).unwrap_err(),
        ManifestError::InsufficientPostQuantum
    );
}

#[test]
fn downgrade_check_rejects_stale_classical_and_suite() {
    let signer = DeterministicSigner::ml_dsa_65("disk-pq", b"seed");

    // Stale version.
    let mut stale = manifest(true);
    stale.boot_policy.minimum_boot_manifest_version = 3;
    stale.sign(&signer, "disk-manifest");
    let v = signer.verifier();
    let verified = stale.verify(&[&v]).unwrap();
    assert!(matches!(
        check(&verified, &VersionFloor::strict(7), 0),
        DowngradeVerdict::RejectedStaleVersion { .. }
    ));

    // Classical-only (no hybrid keyslot) under a PQC-required floor.
    let mut classical = manifest(false);
    classical.sign(&signer, "disk-manifest");
    let verified = classical.verify(&[&v]).unwrap();
    assert_eq!(
        check(&verified, &VersionFloor::strict(7), 0),
        DowngradeVerdict::RejectedClassicalOnly
    );

    // Suite downgrade: hybrid slot with the PQC leg stripped.
    let mut stripped = manifest(false);
    stripped.key_hierarchy.keyslots.push(Keyslot::new(
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
    stripped.sign(&signer, "disk-manifest");
    let verified = stripped.verify(&[&v]).unwrap();
    assert!(matches!(
        check(&verified, &VersionFloor::strict(7), 0),
        DowngradeVerdict::RejectedSuiteDowngrade { .. }
    ));
}

fn unlock_request() -> (UnlockRequest, DeterministicSigner, KmsSimulator) {
    let mut m = manifest(true);
    let signer = DeterministicSigner::ml_dsa_65("disk-pq", b"seed");
    m.sign(&signer, "disk-manifest");
    let bm = boot_measurement();
    let kms = kms_for(&bm);
    let req = UnlockRequest {
        manifest: m,
        boot_measurement: bm,
        device_id: "pn52-lab-001".into(),
        hypervisor_version: 9,
    };
    (req, signer, kms)
}

#[allow(clippy::too_many_arguments)]
fn do_unlock(
    req: &UnlockRequest,
    signer: &DeterministicSigner,
    kms: &KmsSimulator,
    floor: &VersionFloor,
    l: &Legs,
    chain: &mut ReceiptChain,
) -> Result<hyper_qrse::combiner::Kek, UnlockError> {
    let v = signer.verifier();
    let verifiers: [&dyn Verifier; 1] = [&v];
    attested_hybrid_unlock(
        req,
        &verifiers,
        floor,
        0,
        &l.classical_kem,
        &l.pqc_kem,
        KemLeg {
            dk: &l.classical_dk,
            ct: &l.classical_ct,
        },
        KemLeg {
            dk: &l.pqc_dk,
            ct: &l.pqc_ct,
        },
        kms,
        chain,
    )
}

#[test]
fn attested_hybrid_unlock_happy_path() {
    let (req, signer, kms) = unlock_request();
    let l = legs();
    let mut chain = ReceiptChain::new();
    let kek = do_unlock(&req, &signer, &kms, &VersionFloor::strict(7), &l, &mut chain).expect("kek");
    assert_eq!(kek.len(), KEK_LEN);
    assert_eq!(chain.verify(), Ok(()));
    assert!(chain.len() >= 2);
}

#[test]
fn tampered_manifest_blocks_unlock() {
    let (mut req, signer, kms) = unlock_request();
    req.manifest.boot_policy.minimum_boot_manifest_version = 999; // post-sign tamper
    let l = legs();
    let mut chain = ReceiptChain::new();
    let err = do_unlock(&req, &signer, &kms, &VersionFloor::strict(7), &l, &mut chain).unwrap_err();
    assert!(matches!(err, UnlockError::ManifestVerification(_)));
    assert_eq!(chain.verify(), Ok(()));
}

#[test]
fn stale_version_blocks_unlock() {
    let (req, signer, kms) = unlock_request();
    let l = legs();
    let mut chain = ReceiptChain::new();
    let err = do_unlock(&req, &signer, &kms, &VersionFloor::strict(100), &l, &mut chain).unwrap_err();
    assert!(matches!(err, UnlockError::Downgrade(_)));
    assert_eq!(chain.verify(), Ok(()));
}

#[test]
fn failed_attestation_blocks_unlock() {
    let (mut req, signer, _kms) = unlock_request();
    // Boot policy hash no longer matches the KMS-pinned value.
    req.boot_measurement.boot_policy_hash = "sha384:EVIL".into();
    let kms = kms_for(&boot_measurement()); // pinned to the good hash
    let l = legs();
    let mut chain = ReceiptChain::new();
    let err = do_unlock(&req, &signer, &kms, &VersionFloor::strict(7), &l, &mut chain).unwrap_err();
    assert!(matches!(err, UnlockError::AttestationDenied(_)));
    assert_eq!(chain.verify(), Ok(()));
}
