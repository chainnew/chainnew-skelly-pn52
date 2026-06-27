//! VM capsule manifests and the parsed-vs-trusted type split.
//!
//! Maps to SOW-HSLATE-PN52-002 Part B §1 ("a VM is a signed capsule"), §4
//! ("VM capsule security"), and §8 ("Parser and input hardening").
//!
//! The central safety property: a manifest deserialized from bytes is an
//! [`UntrustedManifest`] and *cannot* launch a VM. It only becomes a
//! [`VerifiedManifest`] by passing [`UntrustedManifest::verify`] against a
//! [`TrustStore`]. Downstream crates (`hyper-vm`) accept only `VerifiedManifest`,
//! so "unsigned capsule cannot run" is enforced by the type system, not by a
//! runtime check someone can forget.
//!
//! V0 scope: signature *verification* is a trust-store membership check on the
//! signing key id plus content-hash matching. Real ECDSA-P384 / ML-DSA-65
//! signature math arrives with the KMS/attested-unlock phases (V4+). The schema
//! and code paths are shaped so that swap is local to `verify`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};
use std::collections::BTreeSet;

pub const CAPSULE_SCHEMA: &str = "chain.vm_capsule.v1";

/// Upper bound on a manifest document, rejected before parsing (§8: bounded
/// allocations, no unbounded inputs). A capsule manifest is small JSON.
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CapsuleManifest {
    pub schema: String,
    pub vm_id: String,
    pub tenant_id: String,
    /// Content hash of the boot image (kernel/initrd bundle).
    pub image_hash: String,
    /// Content hash of the root disk image.
    pub disk_hash: String,
    pub hypervisor_min_version: u64,
    pub boot_policy_version: u64,
    pub devices: DeviceSpec,
    pub memory: MemorySpec,
    pub cpu: CpuSpec,
    pub network: NetworkSpec,
    pub storage: StorageSpec,
    pub signatures: Vec<Signature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DeviceSpec {
    pub passthrough: Vec<String>,
    pub virtio: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MemorySpec {
    pub max_mb: u64,
    pub allow_balloon: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CpuSpec {
    pub vcpus: u32,
    pub cpuid_profile: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct NetworkSpec {
    pub mode: String,
    pub egress_policy: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct StorageSpec {
    pub cipher: String,
    pub integrity: String,
    pub key_version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Signature {
    pub alg: String,
    pub key_id: String,
    /// "active" or "transition" (classical compatibility during PQ migration).
    #[serde(default = "default_sig_status")]
    pub status: String,
}

fn default_sig_status() -> String {
    "active".to_string()
}

/// A manifest that has been parsed but not validated. It is deliberately opaque
/// for launch purposes — there is no way to hand this to `hyper-vm`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UntrustedManifest {
    inner: CapsuleManifest,
}

/// A manifest that passed verification against a [`TrustStore`]. Only this type
/// can be turned into a runnable VM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedManifest {
    inner: CapsuleManifest,
    signature_status: SignatureStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureStatus {
    /// At least one signature from a fully trusted key.
    Trusted,
    /// Only a transition (classical-compatibility) signature was trusted.
    TransitionOnly,
}

/// The set of signing keys this host trusts, plus the minimum hypervisor
/// version it is willing to run. Real deployments load this from a signed,
/// versioned policy bundle; V0 builds it in code/tests.
#[derive(Debug, Clone, Default)]
pub struct TrustStore {
    trusted_key_ids: BTreeSet<String>,
    min_hypervisor_version: u64,
}

impl TrustStore {
    pub fn new(min_hypervisor_version: u64) -> Self {
        Self {
            trusted_key_ids: BTreeSet::new(),
            min_hypervisor_version,
        }
    }

    pub fn trust_key(mut self, key_id: impl Into<String>) -> Self {
        self.trusted_key_ids.insert(key_id.into());
        self
    }

    pub fn trusts(&self, key_id: &str) -> bool {
        self.trusted_key_ids.contains(key_id)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CapsuleError {
    #[error("manifest exceeds {MAX_MANIFEST_BYTES} byte bound ({0} bytes)")]
    TooLarge(usize),
    #[error("manifest is not valid JSON: {0}")]
    Parse(String),
    #[error("unsupported manifest schema: {0}")]
    BadSchema(String),
    #[error("manifest declares no signatures")]
    Unsigned,
    #[error("no signature from a trusted key")]
    UntrustedSigner,
    #[error("hypervisor version {have} below manifest minimum {need}")]
    HypervisorTooOld { have: u64, need: u64 },
    #[error("{which} hash mismatch")]
    HashMismatch { which: &'static str },
}

impl UntrustedManifest {
    /// Parse a manifest from raw bytes with a hard size bound and schema check.
    /// The result is untrusted by construction.
    pub fn parse(bytes: &[u8]) -> Result<Self, CapsuleError> {
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(CapsuleError::TooLarge(bytes.len()));
        }
        let inner: CapsuleManifest =
            serde_json::from_slice(bytes).map_err(|e| CapsuleError::Parse(e.to_string()))?;
        if inner.schema != CAPSULE_SCHEMA {
            return Err(CapsuleError::BadSchema(inner.schema));
        }
        Ok(Self { inner })
    }

    /// Read-only peek at fields needed for logging/inventory before trust is
    /// established. Does not grant launch capability.
    pub fn vm_id(&self) -> &str {
        &self.inner.vm_id
    }

    /// Canonical bytes used for receipt input hashing.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.inner).unwrap_or_default()
    }

    /// Promote to a [`VerifiedManifest`] or fail closed.
    ///
    /// `image_bytes`/`disk_bytes`, when supplied, are hashed and matched against
    /// the manifest's declared content hashes (§4: "every disk image has a
    /// content hash"). Passing `None` skips that check — used in V0 tests that
    /// exercise the trust path without real artifacts on disk.
    pub fn verify(
        self,
        trust: &TrustStore,
        image_bytes: Option<&[u8]>,
        disk_bytes: Option<&[u8]>,
    ) -> Result<VerifiedManifest, CapsuleError> {
        let m = &self.inner;

        if m.signatures.is_empty() {
            return Err(CapsuleError::Unsigned);
        }
        if m.hypervisor_min_version > trust.min_hypervisor_version {
            return Err(CapsuleError::HypervisorTooOld {
                have: trust.min_hypervisor_version,
                need: m.hypervisor_min_version,
            });
        }

        // A trusted "active" signature is preferred; fall back to a trusted
        // transition signature but record the weaker status so policy can
        // refuse it for sensitive VMs / after the migration deadline.
        let mut status: Option<SignatureStatus> = None;
        for sig in &m.signatures {
            if trust.trusts(&sig.key_id) {
                match sig.status.as_str() {
                    "transition" => status = status.or(Some(SignatureStatus::TransitionOnly)),
                    _ => {
                        status = Some(SignatureStatus::Trusted);
                        break;
                    }
                }
            }
        }
        let signature_status = status.ok_or(CapsuleError::UntrustedSigner)?;

        if let Some(bytes) = image_bytes {
            if hash_hex(bytes) != m.image_hash {
                return Err(CapsuleError::HashMismatch { which: "image" });
            }
        }
        if let Some(bytes) = disk_bytes {
            if hash_hex(bytes) != m.disk_hash {
                return Err(CapsuleError::HashMismatch { which: "disk" });
            }
        }

        Ok(VerifiedManifest {
            inner: self.inner,
            signature_status,
        })
    }
}

impl VerifiedManifest {
    pub fn manifest(&self) -> &CapsuleManifest {
        &self.inner
    }
    pub fn vm_id(&self) -> &str {
        &self.inner.vm_id
    }
    pub fn signature_status(&self) -> SignatureStatus {
        self.signature_status
    }
    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.inner).unwrap_or_default()
    }
}

/// `sha384:<hex>` of the given bytes, matching the manifest hash convention.
pub fn hash_hex(bytes: &[u8]) -> String {
    let mut h = Sha384::new();
    h.update(bytes);
    format!("sha384:{}", hex::encode(h.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_json(extra_sig: &str) -> String {
        format!(
            r#"{{
              "schema": "chain.vm_capsule.v1",
              "vm_id": "vm-prod-001",
              "tenant_id": "lab",
              "image_hash": "{img}",
              "disk_hash": "{disk}",
              "hypervisor_min_version": 4,
              "boot_policy_version": 7,
              "devices": {{ "passthrough": [], "virtio": ["blk", "net", "console"] }},
              "memory": {{ "max_mb": 4096, "allow_balloon": false }},
              "cpu": {{ "vcpus": 2, "cpuid_profile": "masked_zen3_guest_v1" }},
              "network": {{ "mode": "isolated", "egress_policy": "deny_by_default" }},
              "storage": {{ "cipher": "AES-256-XTS", "integrity": "manifest_hash_only", "key_version": 3 }},
              "signatures": [{sigs}]
            }}"#,
            img = hash_hex(b"image-bytes"),
            disk = hash_hex(b"disk-bytes"),
            sigs = extra_sig,
        )
    }

    fn trusted_sig() -> &'static str {
        r#"{ "alg": "ecdsa-p384", "key_id": "lab-classical-2026", "status": "active" }"#
    }

    fn trust() -> TrustStore {
        TrustStore::new(12).trust_key("lab-classical-2026")
    }

    #[test]
    fn trusted_signed_manifest_verifies() {
        let u = UntrustedManifest::parse(manifest_json(trusted_sig()).as_bytes()).unwrap();
        let v = u.verify(&trust(), None, None).unwrap();
        assert_eq!(v.signature_status(), SignatureStatus::Trusted);
        assert_eq!(v.vm_id(), "vm-prod-001");
    }

    #[test]
    fn unsigned_manifest_is_rejected() {
        let err = UntrustedManifest::parse(manifest_json("").as_bytes())
            .unwrap()
            .verify(&trust(), None, None)
            .unwrap_err();
        assert_eq!(err, CapsuleError::Unsigned);
    }

    #[test]
    fn untrusted_signer_is_rejected() {
        let sig = r#"{ "alg": "ecdsa-p384", "key_id": "attacker-key", "status": "active" }"#;
        let err = UntrustedManifest::parse(manifest_json(sig).as_bytes())
            .unwrap()
            .verify(&trust(), None, None)
            .unwrap_err();
        assert_eq!(err, CapsuleError::UntrustedSigner);
    }

    #[test]
    fn transition_only_signature_is_flagged() {
        let sig = r#"{ "alg": "ml-dsa-65", "key_id": "lab-pq-transition-2026", "status": "transition" }"#;
        let trust = TrustStore::new(12).trust_key("lab-pq-transition-2026");
        let v = UntrustedManifest::parse(manifest_json(sig).as_bytes())
            .unwrap()
            .verify(&trust, None, None)
            .unwrap();
        assert_eq!(v.signature_status(), SignatureStatus::TransitionOnly);
    }

    #[test]
    fn hypervisor_too_old_is_rejected() {
        let trust = TrustStore::new(1).trust_key("lab-classical-2026");
        let err = UntrustedManifest::parse(manifest_json(trusted_sig()).as_bytes())
            .unwrap()
            .verify(&trust, None, None)
            .unwrap_err();
        assert_eq!(err, CapsuleError::HypervisorTooOld { have: 1, need: 4 });
    }

    #[test]
    fn content_hash_mismatch_is_rejected() {
        let err = UntrustedManifest::parse(manifest_json(trusted_sig()).as_bytes())
            .unwrap()
            .verify(&trust(), Some(b"tampered-image"), None)
            .unwrap_err();
        assert_eq!(err, CapsuleError::HashMismatch { which: "image" });
    }

    #[test]
    fn matching_content_hash_passes() {
        let v = UntrustedManifest::parse(manifest_json(trusted_sig()).as_bytes())
            .unwrap()
            .verify(&trust(), Some(b"image-bytes"), Some(b"disk-bytes"))
            .unwrap();
        assert_eq!(v.signature_status(), SignatureStatus::Trusted);
    }

    #[test]
    fn oversized_input_is_rejected_before_parse() {
        let big = vec![b'x'; MAX_MANIFEST_BYTES + 1];
        assert_eq!(
            UntrustedManifest::parse(&big).unwrap_err(),
            CapsuleError::TooLarge(MAX_MANIFEST_BYTES + 1)
        );
    }

    #[test]
    fn wrong_schema_is_rejected() {
        let j = manifest_json(trusted_sig()).replace("chain.vm_capsule.v1", "evil.v9");
        assert!(matches!(
            UntrustedManifest::parse(j.as_bytes()).unwrap_err(),
            CapsuleError::BadSchema(_)
        ));
    }

    #[test]
    fn garbage_input_does_not_panic() {
        assert!(matches!(
            UntrustedManifest::parse(b"not json at all {{{").unwrap_err(),
            CapsuleError::Parse(_)
        ));
    }
}
