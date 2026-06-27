//! A thin, on-the-wire summary of the storage key hierarchy that bridges to the
//! richer QRSE control-plane types.
//!
//! [`StorageKeyHierarchy`] / [`Keyslot`] keep their original flat, string-typed
//! shape (so existing callers keep working) but can now be *produced from* and
//! *converted to* the algorithm-agile [`hyper_qrse::keyslot::Keyslot`] /
//! [`hyper_qrse::manifest::ManifestKeyHierarchy`]. This is a bridge, not a fork:
//! the rich types remain the source of truth, this is the summary view.

use serde::{Deserialize, Serialize};

use hyper_qrse::hierarchy::{KeyClass, KeyHierarchy};
use hyper_qrse::keyslot::{Keyslot as QrseKeyslot, KeyslotKind, KeyslotStatus};
use hyper_qrse::manifest::ManifestKeyHierarchy;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct StorageKeyHierarchy {
    pub volume_id: String,
    pub dek_version: u64,
    pub vmk_version: u64,
    pub keyslots: Vec<Keyslot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Keyslot {
    pub id: u32,
    pub kind: String,
    pub status: String,
}

/// The snake_case label for a [`KeyslotStatus`] (matches its serde rename).
pub fn keyslot_status_label(status: KeyslotStatus) -> &'static str {
    match status {
        KeyslotStatus::Active => "active",
        KeyslotStatus::DisabledUntilBreakGlass => "disabled_until_break_glass",
        KeyslotStatus::Retired => "retired",
    }
}

/// The snake_case mechanism label for a [`KeyslotKind`] (matches its serde tag).
pub fn keyslot_kind_label(kind: &KeyslotKind) -> &'static str {
    match kind {
        KeyslotKind::Argon2idPassphrase { .. } => "argon2id_passphrase",
        KeyslotKind::Tpm2Sealed { .. } => "tpm2_sealed",
        KeyslotKind::HybridRemoteKms { .. } => "hybrid_remote_kms",
        KeyslotKind::ThresholdRecovery { .. } => "threshold_recovery",
    }
}

impl From<&QrseKeyslot> for Keyslot {
    /// Summarize a rich keyslot into the flat, string-typed view.
    fn from(k: &QrseKeyslot) -> Self {
        Keyslot {
            id: k.slot,
            kind: keyslot_kind_label(&k.kind).to_string(),
            status: keyslot_status_label(k.status).to_string(),
        }
    }
}

impl From<QrseKeyslot> for Keyslot {
    fn from(k: QrseKeyslot) -> Self {
        (&k).into()
    }
}

impl StorageKeyHierarchy {
    /// Produce the flat summary from a rich, control-plane key hierarchy.
    pub fn from_manifest(volume_id: impl Into<String>, mh: &ManifestKeyHierarchy) -> Self {
        StorageKeyHierarchy {
            volume_id: volume_id.into(),
            dek_version: mh.active_dek_version,
            vmk_version: mh.volume_master_key_version,
            keyslots: mh.keyslots.iter().map(Keyslot::from).collect(),
        }
    }

    /// Convert back up to a rich [`ManifestKeyHierarchy`], carrying this
    /// summary's DEK/VMK versions and the supplied rich keyslots.
    ///
    /// The flat summary cannot reconstruct mechanism-specific fields, so the
    /// caller supplies the authoritative rich keyslots; this preserves the
    /// "bridge, not fork" property.
    pub fn to_manifest(&self, keyslots: Vec<QrseKeyslot>) -> ManifestKeyHierarchy {
        ManifestKeyHierarchy {
            volume_master_key_version: self.vmk_version,
            active_dek_version: self.dek_version,
            keyslots,
        }
    }

    /// The ordered DEK-wrapping chain for a rich keyslot, via the standard
    /// QRSE key hierarchy (PAD §9.3).
    pub fn wrapping_chain_for(slot: &QrseKeyslot) -> Vec<KeyClass> {
        KeyHierarchy::standard().wrapping_chain(slot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper_qrse::combiner::KemSuite;
    use hyper_qrse::keyslot::{Argon2idKdf, KmsAttestation, WrapSpec};

    fn rich_hierarchy() -> ManifestKeyHierarchy {
        ManifestKeyHierarchy {
            volume_master_key_version: 3,
            active_dek_version: 11,
            keyslots: vec![
                QrseKeyslot::new(
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
                ),
                QrseKeyslot::new(
                    2,
                    KeyslotStatus::DisabledUntilBreakGlass,
                    KeyslotKind::HybridRemoteKms {
                        kem: KemSuite::transition_768(),
                        attestation: KmsAttestation {
                            required: true,
                            accepted_tee: vec!["amd-sev-snp".into()],
                            measurement_policy_ref: "pol-meas-v3".into(),
                        },
                    },
                ),
            ],
        }
    }

    #[test]
    fn summary_from_rich_hierarchy() {
        let s = StorageKeyHierarchy::from_manifest("vol-1", &rich_hierarchy());
        assert_eq!(s.dek_version, 11);
        assert_eq!(s.vmk_version, 3);
        assert_eq!(s.keyslots.len(), 2);
        assert_eq!(s.keyslots[0].kind, "argon2id_passphrase");
        assert_eq!(s.keyslots[0].status, "active");
        assert_eq!(s.keyslots[1].kind, "hybrid_remote_kms");
        assert_eq!(s.keyslots[1].status, "disabled_until_break_glass");
    }

    #[test]
    fn roundtrip_versions_through_to_manifest() {
        let rich = rich_hierarchy();
        let summary = StorageKeyHierarchy::from_manifest("vol-1", &rich);
        let rebuilt = summary.to_manifest(rich.keyslots.clone());
        assert_eq!(rebuilt, rich);
    }

    #[test]
    fn summary_json_still_flat() {
        let s = StorageKeyHierarchy {
            volume_id: "vol-1".into(),
            dek_version: 1,
            vmk_version: 2,
            keyslots: vec![Keyslot {
                id: 0,
                kind: "argon2id_passphrase".into(),
                status: "active".into(),
            }],
        };
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains(r#""dek_version":1"#));
        let back: StorageKeyHierarchy = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn wrapping_chain_for_hybrid_includes_pqc() {
        let slot = QrseKeyslot::new(
            2,
            KeyslotStatus::Active,
            KeyslotKind::HybridRemoteKms {
                kem: KemSuite::transition_768(),
                attestation: KmsAttestation {
                    required: true,
                    accepted_tee: vec!["amd-sev-snp".into()],
                    measurement_policy_ref: "p".into(),
                },
            },
        );
        let chain = StorageKeyHierarchy::wrapping_chain_for(&slot);
        assert!(chain.contains(&KeyClass::PqcWrappedKey));
        assert_eq!(chain.last(), Some(&KeyClass::Dek));
    }
}
