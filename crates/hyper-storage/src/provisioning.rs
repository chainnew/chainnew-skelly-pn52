//! Volume provisioning: emit an *unsigned* `qrsd-v1` manifest skeleton from a
//! LUKS2 profile + a hybrid KEM suite, ready for the control plane to sign.
//!
//! This wires together the data-plane mapping ([`crate::luks`]), the boot policy
//! ([`crate::attestation`]) and the hybrid keyslot ([`hyper_qrse::keyslot`]) into
//! a complete [`hyper_qrse::manifest::QrsdManifest`] with an empty `signatures`
//! array. Signing happens elsewhere (`QrsdManifest::sign`) so this stays
//! deterministic and crypto-free: all timestamps are accepted as input strings.

use hyper_qrse::combiner::KemSuite;
use hyper_qrse::keyslot::{Keyslot, KeyslotKind, KeyslotStatus, KmsAttestation};
use hyper_qrse::manifest::{
    Audit, BootPolicy, ManifestKeyHierarchy, QrsdManifest, RollbackProtection, QRSD_FORMAT,
};

use crate::attestation::{AttestationPolicy, LAB_POLICY};
use crate::luks::{Argon2idParams, Luks2Profile, LuksError, DEFAULT_ARGON2ID_PARAMS};

/// Builder for an unsigned `qrsd-v1` volume manifest.
///
/// Construct with [`VolumeProvisioning::new`] (sensible lab defaults), tweak the
/// public fields, then call [`VolumeProvisioning::manifest`].
#[derive(Debug, Clone)]
pub struct VolumeProvisioning {
    pub volume_id: String,
    /// Accepted as an input string (deterministic; no system clock).
    pub created_at: String,
    pub profile: Luks2Profile,
    pub suite: KemSuite,
    pub attestation: AttestationPolicy,
    pub boot_policy_id: String,
    pub measurement_policy_ref: String,
    pub accepted_tee: Vec<String>,
    pub argon2id: Argon2idParams,
    pub wrapped_key_ref: String,
    pub vmk_version: u64,
    pub dek_version: u64,
    pub min_boot_manifest_version: u64,
    pub audit: Audit,
}

impl VolumeProvisioning {
    /// Start a provisioning plan with lab defaults ([`LAB_POLICY`],
    /// [`DEFAULT_ARGON2ID_PARAMS`]). `created_at` is an input timestamp string.
    pub fn new(
        volume_id: impl Into<String>,
        created_at: impl Into<String>,
        profile: Luks2Profile,
        suite: KemSuite,
    ) -> Self {
        VolumeProvisioning {
            volume_id: volume_id.into(),
            created_at: created_at.into(),
            profile,
            suite,
            attestation: LAB_POLICY,
            boot_policy_id: "pol-boot-v1".to_string(),
            measurement_policy_ref: "pol-meas-v1".to_string(),
            accepted_tee: vec!["amd-sev-snp".to_string()],
            argon2id: DEFAULT_ARGON2ID_PARAMS,
            wrapped_key_ref: "blob:slot0".to_string(),
            vmk_version: 1,
            dek_version: 1,
            min_boot_manifest_version: 1,
            audit: Audit {
                last_rotation: String::new(),
                last_attested_unlock_receipt: String::new(),
                log_chain: String::new(),
            },
        }
    }

    fn boot_policy(&self) -> BootPolicy {
        BootPolicy {
            policy_id: self.boot_policy_id.clone(),
            secure_boot_required: self.attestation.require_secure_boot,
            measured_boot_required: true,
            pcr_profile: self
                .attestation
                .required_pcrs
                .iter()
                .map(|p| format!("pcr{p}"))
                .collect(),
            minimum_boot_manifest_version: self.min_boot_manifest_version,
            rollback_protection: RollbackProtection {
                type_: "tpm-nv-counter".to_string(),
                counter_name: "qrsd.rollback".to_string(),
            },
        }
    }

    fn hybrid_keyslot(&self, slot: u32) -> Keyslot {
        Keyslot::new(
            slot,
            KeyslotStatus::Active,
            KeyslotKind::HybridRemoteKms {
                kem: self.suite.clone(),
                attestation: KmsAttestation {
                    required: true,
                    accepted_tee: self.accepted_tee.clone(),
                    measurement_policy_ref: self.measurement_policy_ref.clone(),
                },
            },
        )
    }

    /// Emit the unsigned `qrsd-v1` manifest skeleton.
    ///
    /// Contains an Argon2id passphrase slot (0) and a hybrid remote-KMS slot (1)
    /// carrying the selected KEM suite, with an empty `signatures` array.
    pub fn manifest(&self) -> Result<QrsdManifest, LuksError> {
        let argon = self
            .profile
            .argon2id_keyslot(0, &self.argon2id, self.wrapped_key_ref.clone())?;
        let keyslots = vec![argon, self.hybrid_keyslot(1)];

        Ok(QrsdManifest {
            format: QRSD_FORMAT.to_string(),
            volume_id: self.volume_id.clone(),
            created_at: self.created_at.clone(),
            data_plane: self.profile.data_plane(),
            boot_policy: self.boot_policy(),
            key_hierarchy: ManifestKeyHierarchy {
                volume_master_key_version: self.vmk_version,
                active_dek_version: self.dek_version,
                keyslots,
            },
            signatures: Vec::new(),
            audit: self.audit.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::luks::AES_256_XTS_ARGON2ID;
    use hyper_qrse::crypto::DeterministicSigner;

    fn plan() -> VolumeProvisioning {
        VolumeProvisioning::new(
            "urn:uuid:vol-1",
            "2026-06-27T00:00:00Z",
            AES_256_XTS_ARGON2ID,
            KemSuite::transition_768(),
        )
    }

    #[test]
    fn emits_unsigned_qrsd_v1_skeleton() {
        let m = plan().manifest().unwrap();
        assert_eq!(m.format, QRSD_FORMAT);
        assert_eq!(m.volume_id, "urn:uuid:vol-1");
        assert_eq!(m.created_at, "2026-06-27T00:00:00Z");
        assert_eq!(m.data_plane.cipher, "AES-256-XTS");
        assert!(m.signatures.is_empty());
        assert_eq!(m.key_hierarchy.keyslots.len(), 2);
    }

    #[test]
    fn carries_kem_suite_in_hybrid_slot() {
        let m = plan().manifest().unwrap();
        let hybrid = &m.key_hierarchy.keyslots[1];
        assert!(hybrid.is_hybrid());
        assert!(!hybrid.classical_only());
        assert_eq!(hybrid.kem_suite().unwrap(), &KemSuite::transition_768());
    }

    #[test]
    fn boot_policy_reflects_attestation_pcrs() {
        let m = plan().manifest().unwrap();
        assert_eq!(
            m.boot_policy.pcr_profile,
            vec!["pcr0".to_string(), "pcr7".to_string(), "pcr11".to_string()]
        );
        assert!(!m.boot_policy.secure_boot_required); // LAB_POLICY
        assert!(m.boot_policy.measured_boot_required);
    }

    #[test]
    fn skeleton_is_signable_and_verifies_pq() {
        let mut m = plan().manifest().unwrap();
        let signer = DeterministicSigner::ml_dsa_65("disk-pq", b"seed");
        m.sign(&signer, "disk-manifest");
        let v = signer.verifier();
        assert!(m.verify(&[&v]).is_ok());
    }

    #[test]
    fn fails_closed_on_non_argon2id_profile() {
        let mut p = plan();
        p.profile = Luks2Profile {
            cipher: "aes-xts-plain64",
            key_size_bits: 512,
            pbkdf: "pbkdf2",
        };
        assert!(matches!(
            p.manifest().unwrap_err(),
            LuksError::NotArgon2id { .. }
        ));
    }

    #[test]
    fn manifest_json_round_trips() {
        let m = plan().manifest().unwrap();
        let json = m.to_json().unwrap();
        assert!(json.contains(r#""format": "qrsd-v1""#));
        let back = QrsdManifest::from_json(&json).unwrap();
        assert_eq!(back, m);
    }
}
