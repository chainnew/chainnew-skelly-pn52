//! Reproducibly emit a valid, PQ-signed `qrsd-v1` sample manifest.
//!
//! This is the single source of truth for `manifests/sample.qrsd-v1.json`:
//! it builds a manifest from the real `hyper_qrse` types and signs it, so the
//! sample can never drift from the implementation.
//!
//!   cargo run -p hyper-qrse --example gen_sample > manifests/sample.qrsd-v1.json
//!
//! The sample is signed (purpose `disk-manifest`) by deterministic key
//! `disk-pq` with seed `qrse-sample-seed`, plus a transition-only classical
//! `classical-compat` signature. Verify it with:
//!
//!   qrsectl manifest verify manifests/sample.qrsd-v1.json --trust disk-pq=qrse-sample-seed

use hyper_qrse::combiner::KemSuite;
use hyper_qrse::crypto::DeterministicSigner;
use hyper_qrse::keyslot::{
    Argon2idKdf, Keyslot, KeyslotKind, KeyslotStatus, KmsAttestation, WrapSpec,
};
use hyper_qrse::manifest::{
    Audit, BootPolicy, DataPlane, Integrity, ManifestKeyHierarchy, QrsdManifest, RollbackProtection,
    QRSD_FORMAT,
};

fn main() {
    let keyslots = vec![
        Keyslot::new(
            0,
            KeyslotStatus::Active,
            KeyslotKind::Argon2idPassphrase {
                kdf: Argon2idKdf {
                    algorithm: "argon2id".into(),
                    memory_kib: 1_048_576,
                    time_cost: 4,
                    parallelism: 4,
                },
                wrap: WrapSpec {
                    algorithm: "aes-256-kw".into(),
                    wrapped_key_ref: "blob:slot0".into(),
                },
            },
        ),
        Keyslot::new(
            1,
            KeyslotStatus::Active,
            KeyslotKind::Tpm2Sealed {
                pcrs: vec!["7".into(), "11".into()],
                requires_pin: true,
                signed_pcr_policy: true,
            },
        ),
        Keyslot::new(
            2,
            KeyslotStatus::Active,
            KeyslotKind::HybridRemoteKms {
                kem: KemSuite::transition_768(),
                attestation: KmsAttestation {
                    required: true,
                    accepted_tee: vec!["tpm2".into(), "amd-sev-snp-vtpm".into()],
                    measurement_policy_ref: "manifest-prod-v42".into(),
                },
            },
        ),
        Keyslot::new(
            3,
            KeyslotStatus::DisabledUntilBreakGlass,
            KeyslotKind::ThresholdRecovery {
                scheme: "shamir".into(),
                m: 3,
                n: 5,
            },
        ),
    ];

    let mut m = QrsdManifest {
        format: QRSD_FORMAT.to_string(),
        volume_id: "urn:uuid:7f0e2a9b-3c17-4e99-94aa-000000000001".into(),
        created_at: "2026-06-27T00:00:00Z".into(),
        data_plane: DataPlane {
            cipher: "AES-256-XTS".into(),
            xts_raw_key_bits: 512,
            sector_size: 4096,
            integrity: Integrity {
                mode: "none".into(),
                alternatives: vec![
                    "dm-verity".into(),
                    "fs-verity".into(),
                    "dm-integrity-aead".into(),
                ],
            },
        },
        boot_policy: BootPolicy {
            policy_id: "policy-prod-laptop-v4".into(),
            secure_boot_required: true,
            measured_boot_required: true,
            pcr_profile: vec!["7".into(), "11".into()],
            minimum_boot_manifest_version: 42,
            rollback_protection: RollbackProtection {
                type_: "tpm-nv-counter-or-kms-monotonic".into(),
                counter_name: "boot_policy_counter".into(),
            },
        },
        key_hierarchy: ManifestKeyHierarchy {
            volume_master_key_version: 3,
            active_dek_version: 8,
            keyslots,
        },
        signatures: vec![],
        audit: Audit {
            last_rotation: "2026-06-27T00:00:00Z".into(),
            last_attested_unlock_receipt: "rcpt-000000-0000000000000000".into(),
            log_chain: "sha384:0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".into(),
        },
    };

    // Post-quantum manifest signature (primary) + transition-only classical.
    let pq = DeterministicSigner::ml_dsa_65("disk-pq", b"qrse-sample-seed");
    m.sign(&pq, "disk-manifest");
    let classical = DeterministicSigner::ecdsa_p384("disk-classical", b"qrse-sample-seed");
    m.sign(&classical, "classical-compatibility");

    println!("{}", m.to_json().expect("serialize sample manifest"));
}
