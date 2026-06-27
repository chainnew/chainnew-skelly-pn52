//! The QRSE key hierarchy (PAD-QRSE-001 §9.3).
//!
//! Keys are layered so that compromise of any single layer is contained and so
//! that rotation can happen at the right cadence per layer:
//!
//! ```text
//! Org root KEK
//!   └─ Tenant / Project KEK
//!        ├─ Device KEK
//!        │    ├─ TPM-sealed key      ─┐
//!        │    ├─ FIDO2 / user key     ├─ wrap → VMK → DEK → AES-256-XTS
//!        │    └─ Recovery key        ─┘ (threshold share)
//!        └─ Remote KMS KEK
//!             ├─ classical leg
//!             ├─ ML-KEM leg          ── hybrid → VMK → DEK → AES-256-XTS
//!             └─ hybrid (combined)
//! ```
//!
//! The model is pure data (serde-round-trippable) so it is host-testable. Given
//! a [`crate::keyslot::Keyslot`], [`KeyHierarchy::wrapping_chain`] returns the
//! ordered list of [`KeyClass`]es that wrap a DEK for that slot.

use serde::{Deserialize, Serialize};

use crate::keyslot::{Keyslot, KeyslotKind};

/// A class of key in the hierarchy (PAD §9.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyClass {
    /// Data encryption key — protects bulk data with AES-256-XTS.
    Dek,
    /// Volume master key — wraps the DEK(s) for one volume.
    Vmk,
    /// Generic key-encryption key (org / tenant / device / remote-kms roots).
    Kek,
    /// Per-device key-encryption key.
    DeviceKey,
    /// User-presence key (e.g. FIDO2).
    UserKey,
    /// Offline recovery key.
    RecoveryKey,
    /// Hardware-sealed key (TPM/fTPM).
    HardwareSealedKey,
    /// Remote KMS key-encryption key.
    RemoteKmsKey,
    /// Key wrapped by a post-quantum (ML-KEM) leg.
    PqcWrappedKey,
    /// One share of a threshold recovery secret.
    ThresholdShare,
    /// Key used to sign audit receipts / manifests.
    AuditSigningKey,
}

/// How often a key of a given class is expected to rotate (PAD §9.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationCadence {
    /// Rotated only when explicitly requested.
    OnDemand,
    /// Rotated on every measured boot.
    PerBoot,
    Daily,
    Monthly,
    Quarterly,
    Annual,
    /// Rotated immediately on suspected compromise (break-glass).
    OnCompromise,
}

/// A node in the key hierarchy tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct KeyNode {
    pub id: String,
    pub class: KeyClass,
    pub rotation: RotationCadence,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<KeyNode>,
}

impl KeyNode {
    /// A leaf node (no children).
    pub fn leaf(id: impl Into<String>, class: KeyClass, rotation: RotationCadence) -> Self {
        KeyNode {
            id: id.into(),
            class,
            rotation,
            children: Vec::new(),
        }
    }

    /// Attach a child and return `self` (builder style).
    pub fn with_child(mut self, child: KeyNode) -> Self {
        self.children.push(child);
        self
    }
}

/// The full key hierarchy for a tenant/device, rooted at the org KEK.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct KeyHierarchy {
    pub root: KeyNode,
}

/// Builder for the standard PAD §9.3 hierarchy.
#[derive(Debug, Clone)]
pub struct KeyHierarchyBuilder {
    org_id: String,
    tenant_id: String,
    device_id: String,
}

impl KeyHierarchyBuilder {
    /// Start a builder with placeholder ids.
    pub fn new() -> Self {
        KeyHierarchyBuilder {
            org_id: "org-root".into(),
            tenant_id: "tenant".into(),
            device_id: "device".into(),
        }
    }

    pub fn org(mut self, id: impl Into<String>) -> Self {
        self.org_id = id.into();
        self
    }
    pub fn tenant(mut self, id: impl Into<String>) -> Self {
        self.tenant_id = id.into();
        self
    }
    pub fn device(mut self, id: impl Into<String>) -> Self {
        self.device_id = id.into();
        self
    }

    /// Build the standard hierarchy tree.
    pub fn build(self) -> KeyHierarchy {
        // Device branch: device KEK -> {TPM, user, recovery} -> VMK -> DEK.
        let vmk_dek = || {
            KeyNode::leaf("vmk", KeyClass::Vmk, RotationCadence::Quarterly)
                .with_child(KeyNode::leaf("dek", KeyClass::Dek, RotationCadence::PerBoot))
        };

        let device = KeyNode::leaf(
            format!("device-kek:{}", self.device_id),
            KeyClass::DeviceKey,
            RotationCadence::Annual,
        )
        .with_child(
            KeyNode::leaf("tpm-sealed", KeyClass::HardwareSealedKey, RotationCadence::PerBoot)
                .with_child(vmk_dek()),
        )
        .with_child(
            KeyNode::leaf("fido2-user", KeyClass::UserKey, RotationCadence::OnDemand)
                .with_child(vmk_dek()),
        )
        .with_child(
            KeyNode::leaf("recovery", KeyClass::RecoveryKey, RotationCadence::OnCompromise)
                .with_child(
                    KeyNode::leaf("share", KeyClass::ThresholdShare, RotationCadence::OnCompromise)
                        .with_child(vmk_dek()),
                ),
        );

        // Remote KMS branch: remote KEK -> {classical, ml-kem, hybrid} -> VMK -> DEK.
        let remote = KeyNode::leaf(
            "remote-kms-kek",
            KeyClass::RemoteKmsKey,
            RotationCadence::Monthly,
        )
        .with_child(KeyNode::leaf("classical-leg", KeyClass::Kek, RotationCadence::Monthly))
        .with_child(KeyNode::leaf(
            "ml-kem-leg",
            KeyClass::PqcWrappedKey,
            RotationCadence::Monthly,
        ))
        .with_child(
            KeyNode::leaf("hybrid", KeyClass::PqcWrappedKey, RotationCadence::Monthly)
                .with_child(vmk_dek()),
        );

        let tenant = KeyNode::leaf(
            format!("tenant-kek:{}", self.tenant_id),
            KeyClass::Kek,
            RotationCadence::Quarterly,
        )
        .with_child(device)
        .with_child(remote);

        let root = KeyNode::leaf(
            format!("org-root-kek:{}", self.org_id),
            KeyClass::Kek,
            RotationCadence::Annual,
        )
        .with_child(tenant);

        KeyHierarchy { root }
    }
}

impl Default for KeyHierarchyBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyHierarchy {
    /// Build the standard hierarchy with default ids.
    pub fn standard() -> Self {
        KeyHierarchyBuilder::new().build()
    }

    /// The ordered chain of key classes that wrap a DEK for `slot`, from the
    /// org root down to the leaf DEK (and implicitly the AES-256-XTS data key).
    ///
    /// The branch taken depends on the keyslot mechanism.
    pub fn wrapping_chain(&self, slot: &Keyslot) -> Vec<KeyClass> {
        let mut chain = vec![KeyClass::Kek, KeyClass::Kek]; // org root, tenant
        match &slot.kind {
            KeyslotKind::Argon2idPassphrase { .. } => {
                chain.push(KeyClass::DeviceKey);
                chain.push(KeyClass::UserKey);
            }
            KeyslotKind::Tpm2Sealed { .. } => {
                chain.push(KeyClass::DeviceKey);
                chain.push(KeyClass::HardwareSealedKey);
            }
            KeyslotKind::ThresholdRecovery { .. } => {
                chain.push(KeyClass::DeviceKey);
                chain.push(KeyClass::RecoveryKey);
                chain.push(KeyClass::ThresholdShare);
            }
            KeyslotKind::HybridRemoteKms { .. } => {
                chain.push(KeyClass::RemoteKmsKey);
                chain.push(KeyClass::PqcWrappedKey);
            }
        }
        chain.push(KeyClass::Vmk);
        chain.push(KeyClass::Dek);
        chain
    }

    /// The rotation cadence recommended for a key class.
    pub fn rotation_for(class: KeyClass) -> RotationCadence {
        match class {
            KeyClass::Dek => RotationCadence::PerBoot,
            KeyClass::Vmk => RotationCadence::Quarterly,
            KeyClass::DeviceKey => RotationCadence::Annual,
            KeyClass::Kek => RotationCadence::Annual,
            KeyClass::UserKey => RotationCadence::OnDemand,
            KeyClass::RecoveryKey => RotationCadence::OnCompromise,
            KeyClass::HardwareSealedKey => RotationCadence::PerBoot,
            KeyClass::RemoteKmsKey => RotationCadence::Monthly,
            KeyClass::PqcWrappedKey => RotationCadence::Monthly,
            KeyClass::ThresholdShare => RotationCadence::OnCompromise,
            KeyClass::AuditSigningKey => RotationCadence::Quarterly,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::combiner::KemSuite;
    use crate::keyslot::{Argon2idKdf, KmsAttestation, KeyslotStatus, WrapSpec};

    fn argon2() -> Keyslot {
        Keyslot::new(
            0,
            KeyslotStatus::Active,
            KeyslotKind::Argon2idPassphrase {
                kdf: Argon2idKdf {
                    algorithm: "argon2id".into(),
                    memory_kib: 1024,
                    time_cost: 3,
                    parallelism: 1,
                },
                wrap: WrapSpec {
                    algorithm: "aes-256-gcm".into(),
                    wrapped_key_ref: "ref".into(),
                },
            },
        )
    }

    fn hybrid() -> Keyslot {
        Keyslot::new(
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
        )
    }

    #[test]
    fn hierarchy_round_trips_json() {
        let h = KeyHierarchy::standard();
        let json = serde_json::to_string(&h).unwrap();
        let back: KeyHierarchy = serde_json::from_str(&json).unwrap();
        assert_eq!(back, h);
        assert_eq!(h.root.class, KeyClass::Kek);
    }

    #[test]
    fn builder_uses_custom_ids() {
        let h = KeyHierarchyBuilder::new()
            .org("acme")
            .tenant("proj-x")
            .device("pn52-001")
            .build();
        assert!(h.root.id.contains("acme"));
    }

    #[test]
    fn wrapping_chain_hybrid_includes_pqc_and_ends_in_dek() {
        let chain = KeyHierarchy::standard().wrapping_chain(&hybrid());
        assert_eq!(chain.first(), Some(&KeyClass::Kek));
        assert!(chain.contains(&KeyClass::RemoteKmsKey));
        assert!(chain.contains(&KeyClass::PqcWrappedKey));
        assert_eq!(chain.last(), Some(&KeyClass::Dek));
    }

    #[test]
    fn wrapping_chain_argon2_goes_via_user_key() {
        let chain = KeyHierarchy::standard().wrapping_chain(&argon2());
        assert!(chain.contains(&KeyClass::DeviceKey));
        assert!(chain.contains(&KeyClass::UserKey));
        assert!(!chain.contains(&KeyClass::PqcWrappedKey));
        assert_eq!(chain.last(), Some(&KeyClass::Dek));
    }

    #[test]
    fn rotation_cadence_is_defined_per_class() {
        assert_eq!(KeyHierarchy::rotation_for(KeyClass::Dek), RotationCadence::PerBoot);
        assert_eq!(
            KeyHierarchy::rotation_for(KeyClass::RecoveryKey),
            RotationCadence::OnCompromise
        );
    }
}
