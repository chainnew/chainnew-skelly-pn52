//! The `qrsd-v1` disk manifest (PAD-QRSE-001 §9.5) plus signing/verification.
//!
//! A [`QrsdManifest`] is the signed, on-disk policy for a volume: data-plane
//! cipher, boot policy (with rollback protection), the key hierarchy / keyslots,
//! one or more detached signatures, and an audit anchor.
//!
//! Signatures cover [`QrsdManifest::signing_bytes`] — the canonical encoding of
//! the *whole manifest except the `signatures` array* — so a manifest can be
//! re-signed (e.g. adding an ML-DSA signature alongside a transitional ECDSA
//! one) without invalidating earlier signatures.
//!
//! [`QrsdManifest::verify`] is **fail-closed and post-quantum-required**: it only
//! yields a [`VerifiedManifest`] when at least one valid ML-DSA/SLH-DSA
//! signature is present. A manifest carrying only a classical signature is *not*
//! considered post-quantum-verified (it is in transition). `VerifiedManifest`
//! is a type-split capability token that can only be minted by `verify`.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::crypto::{Signature, Signer, Verifier};
use crate::keyslot::Keyslot;

/// The fixed `format` discriminator for this manifest schema.
pub const QRSD_FORMAT: &str = "qrsd-v1";

fn default_format() -> String {
    QRSD_FORMAT.to_string()
}

/// Data-plane integrity policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Integrity {
    pub mode: String,
    #[serde(default)]
    pub alternatives: Vec<String>,
}

/// Data-plane (bulk cipher) policy — stays "boring" AES-256-XTS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DataPlane {
    pub cipher: String,
    pub xts_raw_key_bits: u32,
    pub sector_size: u32,
    pub integrity: Integrity,
}

/// Rollback-protection binding (monotonic counter) for downgrade resistance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RollbackProtection {
    #[serde(rename = "type")]
    pub type_: String,
    pub counter_name: String,
}

/// Boot policy the manifest is bound to (PAD §9.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct BootPolicy {
    pub policy_id: String,
    pub secure_boot_required: bool,
    pub measured_boot_required: bool,
    pub pcr_profile: Vec<String>,
    pub minimum_boot_manifest_version: u64,
    pub rollback_protection: RollbackProtection,
}

/// Key-hierarchy section: versions plus the keyslots themselves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ManifestKeyHierarchy {
    pub volume_master_key_version: u64,
    pub active_dek_version: u64,
    pub keyslots: Vec<Keyslot>,
}

/// Audit anchor section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Audit {
    pub last_rotation: String,
    pub last_attested_unlock_receipt: String,
    pub log_chain: String,
}

/// A detached manifest signature descriptor (PAD §9.5).
///
/// The disk manifest carries an ML-DSA signature plus, during the
/// classical-compatibility transition, an ECDSA signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ManifestSignature {
    pub purpose: String,
    pub algorithm: String,
    pub key_id: String,
    /// Hex-encoded detached signature bytes over [`QrsdManifest::signing_bytes`].
    pub signature_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
}

/// The `qrsd-v1` on-disk volume manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct QrsdManifest {
    #[serde(default = "default_format")]
    pub format: String,
    pub volume_id: String,
    pub created_at: String,
    pub data_plane: DataPlane,
    pub boot_policy: BootPolicy,
    pub key_hierarchy: ManifestKeyHierarchy,
    #[serde(default)]
    pub signatures: Vec<ManifestSignature>,
    pub audit: Audit,
}

/// The signed body: everything except the `signatures` array, in declaration
/// order (serde preserves struct field order → deterministic encoding).
#[derive(Serialize)]
struct ManifestBody<'a> {
    format: &'a str,
    volume_id: &'a str,
    created_at: &'a str,
    data_plane: &'a DataPlane,
    boot_policy: &'a BootPolicy,
    key_hierarchy: &'a ManifestKeyHierarchy,
    audit: &'a Audit,
}

/// Errors from manifest (de)serialization and verification (fail-closed).
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ManifestError {
    #[error("json error: {0}")]
    Json(String),
    #[error("wrong manifest format: expected {expected}, found {found}")]
    BadFormat { expected: String, found: String },
    #[error("no valid signature over the manifest body")]
    NoValidSignature,
    #[error("manifest is only classically signed (transition): a post-quantum (ml-dsa/slh-dsa) signature is required")]
    InsufficientPostQuantum,
    #[error("signature {key_id} has a malformed signature_ref: {detail}")]
    BadSignatureEncoding { key_id: String, detail: String },
}

/// Whether `alg` is a post-quantum signature algorithm.
fn is_pq_signature_alg(alg: &str) -> bool {
    let a = alg.to_ascii_lowercase();
    a.starts_with("ml-dsa") || a.starts_with("slh-dsa")
}

/// A manifest that has passed post-quantum-required verification.
///
/// Type-split capability token: it can only be constructed by
/// [`QrsdManifest::verify`], so possessing one is proof the manifest carried a
/// valid ML-DSA/SLH-DSA signature over its body.
#[derive(Debug, Clone)]
pub struct VerifiedManifest {
    manifest: QrsdManifest,
    /// Purposes of the signatures that verified (for audit/diagnostics).
    verified_purposes: Vec<String>,
}

impl VerifiedManifest {
    /// The underlying verified manifest.
    pub fn manifest(&self) -> &QrsdManifest {
        &self.manifest
    }

    /// Minimum acceptable boot-manifest version declared by the boot policy.
    pub fn min_boot_manifest_version(&self) -> u64 {
        self.manifest.boot_policy.minimum_boot_manifest_version
    }

    /// The keyslots in the verified manifest.
    pub fn keyslots(&self) -> &[Keyslot] {
        &self.manifest.key_hierarchy.keyslots
    }

    /// Purposes of the signatures that verified.
    pub fn verified_purposes(&self) -> &[String] {
        &self.verified_purposes
    }
}

impl QrsdManifest {
    /// Canonical signed body: the whole manifest **except** `signatures`.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let body = ManifestBody {
            format: &self.format,
            volume_id: &self.volume_id,
            created_at: &self.created_at,
            data_plane: &self.data_plane,
            boot_policy: &self.boot_policy,
            key_hierarchy: &self.key_hierarchy,
            audit: &self.audit,
        };
        serde_json::to_vec(&body).expect("manifest body serializes")
    }

    /// Sign the body with `signer` and append a [`ManifestSignature`].
    pub fn sign(&mut self, signer: &dyn Signer, purpose: &str) {
        let sig = signer.sign(&self.signing_bytes());
        self.signatures.push(ManifestSignature {
            purpose: purpose.to_string(),
            algorithm: sig.algorithm.clone(),
            key_id: sig.key_id.clone(),
            signature_ref: hex::encode(&sig.bytes),
            status: None,
            not_after: None,
        });
    }

    /// Verify the manifest, requiring at least one valid **post-quantum**
    /// signature over [`QrsdManifest::signing_bytes`]. Fail-closed.
    ///
    /// * yields [`VerifiedManifest`] if a valid ML-DSA/SLH-DSA signature exists;
    /// * [`ManifestError::InsufficientPostQuantum`] if only a classical
    ///   signature verified (transition state);
    /// * [`ManifestError::NoValidSignature`] if nothing verified.
    pub fn verify(&self, verifiers: &[&dyn Verifier]) -> Result<VerifiedManifest, ManifestError> {
        if self.format != QRSD_FORMAT {
            return Err(ManifestError::BadFormat {
                expected: QRSD_FORMAT.to_string(),
                found: self.format.clone(),
            });
        }
        let body = self.signing_bytes();
        let mut pq_purposes: Vec<String> = Vec::new();
        let mut classical_valid = false;

        for ms in &self.signatures {
            let bytes = match hex::decode(&ms.signature_ref) {
                Ok(b) => b,
                Err(e) => {
                    return Err(ManifestError::BadSignatureEncoding {
                        key_id: ms.key_id.clone(),
                        detail: e.to_string(),
                    });
                }
            };
            let sig = Signature {
                algorithm: ms.algorithm.clone(),
                key_id: ms.key_id.clone(),
                bytes,
            };
            let verified = verifiers.iter().any(|v| {
                v.key_id() == ms.key_id && v.algorithm() == ms.algorithm && v.verify(&body, &sig)
            });
            if verified {
                if is_pq_signature_alg(&ms.algorithm) {
                    pq_purposes.push(ms.purpose.clone());
                } else {
                    classical_valid = true;
                }
            }
        }

        if !pq_purposes.is_empty() {
            Ok(VerifiedManifest {
                manifest: self.clone(),
                verified_purposes: pq_purposes,
            })
        } else if classical_valid {
            Err(ManifestError::InsufficientPostQuantum)
        } else {
            Err(ManifestError::NoValidSignature)
        }
    }

    /// Serialize to pretty JSON.
    pub fn to_json(&self) -> Result<String, ManifestError> {
        serde_json::to_string_pretty(self).map_err(|e| ManifestError::Json(e.to_string()))
    }

    /// Parse from JSON (does not verify; call [`QrsdManifest::verify`]).
    pub fn from_json(s: &str) -> Result<Self, ManifestError> {
        serde_json::from_str(s).map_err(|e| ManifestError::Json(e.to_string()))
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::combiner::KemSuite;
    use crate::keyslot::{
        Argon2idKdf, KeyslotKind, KeyslotStatus, KmsAttestation, WrapSpec,
    };

    /// A manifest fixture; `hybrid` controls whether a hybrid keyslot is present.
    pub fn sample_manifest(hybrid: bool) -> QrsdManifest {
        let mut keyslots = vec![Keyslot::new(
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
        )];
        if hybrid {
            keyslots.push(Keyslot::new(
                2,
                KeyslotStatus::Active,
                KeyslotKind::HybridRemoteKms {
                    kem: KemSuite::transition_768(),
                    attestation: KmsAttestation {
                        required: true,
                        accepted_tee: vec!["amd-sev-snp".into()],
                        measurement_policy_ref: "pol-meas-v3".into(),
                    },
                },
            ));
        }
        QrsdManifest {
            format: QRSD_FORMAT.to_string(),
            volume_id: "urn:uuid:vol-1".into(),
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
}

#[cfg(test)]
mod tests {
    use super::test_support::sample_manifest;
    use super::*;
    use crate::crypto::DeterministicSigner;

    #[test]
    fn signing_bytes_excludes_signatures() {
        let mut m = sample_manifest(true);
        let before = m.signing_bytes();
        let signer = DeterministicSigner::ml_dsa_65("disk-pq", b"seed");
        m.sign(&signer, "disk-manifest");
        // Adding a signature must NOT change the signed body.
        assert_eq!(before, m.signing_bytes());
        assert_eq!(m.signatures.len(), 1);
    }

    #[test]
    fn sign_and_verify_happy_path_pq() {
        let mut m = sample_manifest(true);
        let signer = DeterministicSigner::ml_dsa_65("disk-pq", b"seed");
        m.sign(&signer, "disk-manifest");
        let v = signer.verifier();
        let verified = m.verify(&[&v]).expect("pq verified");
        assert_eq!(verified.min_boot_manifest_version(), 7);
        assert_eq!(verified.verified_purposes(), &["disk-manifest".to_string()]);
    }

    #[test]
    fn classical_only_is_not_pq_verified() {
        let mut m = sample_manifest(true);
        let ecdsa = DeterministicSigner::ecdsa_p384("disk-classical", b"seed-c");
        m.sign(&ecdsa, "classical-compat");
        let v = ecdsa.verifier();
        assert_eq!(
            m.verify(&[&v]).unwrap_err(),
            ManifestError::InsufficientPostQuantum
        );
    }

    #[test]
    fn dual_signed_verifies_pq_even_with_classical_present() {
        let mut m = sample_manifest(true);
        let pq = DeterministicSigner::ml_dsa_65("disk-pq", b"s1");
        let ec = DeterministicSigner::ecdsa_p384("disk-classical", b"s2");
        m.sign(&pq, "disk-manifest");
        m.sign(&ec, "classical-compat");
        let vpq = pq.verifier();
        let vec_ = ec.verifier();
        let verified = m.verify(&[&vpq, &vec_]).expect("pq verified");
        assert_eq!(verified.verified_purposes(), &["disk-manifest".to_string()]);
    }

    #[test]
    fn tampered_body_fails_verify() {
        let mut m = sample_manifest(true);
        let signer = DeterministicSigner::ml_dsa_65("disk-pq", b"seed");
        m.sign(&signer, "disk-manifest");
        // Tamper after signing.
        m.boot_policy.minimum_boot_manifest_version = 999;
        let v = signer.verifier();
        assert_eq!(m.verify(&[&v]).unwrap_err(), ManifestError::NoValidSignature);
    }

    #[test]
    fn no_signatures_fails_closed() {
        let m = sample_manifest(true);
        assert_eq!(m.verify(&[]).unwrap_err(), ManifestError::NoValidSignature);
    }

    #[test]
    fn wrong_format_rejected() {
        let mut m = sample_manifest(true);
        m.format = "qrsd-v0".into();
        let signer = DeterministicSigner::ml_dsa_65("disk-pq", b"seed");
        m.sign(&signer, "disk-manifest");
        let v = signer.verifier();
        assert!(matches!(
            m.verify(&[&v]).unwrap_err(),
            ManifestError::BadFormat { .. }
        ));
    }

    #[test]
    fn json_round_trips() {
        let mut m = sample_manifest(true);
        let signer = DeterministicSigner::ml_dsa_65("disk-pq", b"seed");
        m.sign(&signer, "disk-manifest");
        let json = m.to_json().unwrap();
        assert!(json.contains(r#""format": "qrsd-v1""#));
        let back = QrsdManifest::from_json(&json).unwrap();
        assert_eq!(back, m);
        // Still verifies after a round trip.
        let v = signer.verifier();
        assert!(back.verify(&[&v]).is_ok());
    }
}
