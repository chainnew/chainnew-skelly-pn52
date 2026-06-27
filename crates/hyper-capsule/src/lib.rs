use hyper_receipts::{Receipt, ReceiptDecision};
use serde::{Deserialize, Serialize};

pub const CAPSULE_SCHEMA: &str = "chain.vm_capsule.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct UntrustedCapsuleManifest {
    pub schema: String,
    pub capsule_id: String,
    pub vm_id: String,
    pub image_hash: String,
    pub disk_hash: String,
    pub hypervisor_min_version: u64,
    pub boot_policy_version: u64,
    pub devices: CapsuleDevicePolicy,
    pub memory: MemorySpec,
    pub cpu: CpuSpec,
    pub network: NetworkSpec,
    pub storage: StorageSpec,
    pub signatures: Vec<ManifestSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct VerifiedCapsuleManifest {
    inner: UntrustedCapsuleManifest,
    verification_receipt: Receipt,
}

impl VerifiedCapsuleManifest {
    pub fn inner(&self) -> &UntrustedCapsuleManifest {
        &self.inner
    }

    pub fn receipt(&self) -> &Receipt {
        &self.verification_receipt
    }

    pub fn vm_id(&self) -> &str {
        &self.inner.vm_id
    }

    pub fn capsule_id(&self) -> &str {
        &self.inner.capsule_id
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct ManifestSignature {
    pub alg: String,
    pub key_id: String,
    pub status: SignatureStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SignatureStatus {
    Active,
    Transition,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub struct CapsuleDevicePolicy {
    pub passthrough: Vec<String>,
    pub virtio: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct MemorySpec {
    pub max_mb: u64,
    pub allow_balloon: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct CpuSpec {
    pub vcpus: u16,
    pub cpuid_profile: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct NetworkSpec {
    pub mode: String,
    pub egress_policy: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct StorageSpec {
    pub cipher: String,
    pub integrity: String,
    pub key_version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct VerificationRequest {
    pub computed_capsule_hash: String,
    pub expected_capsule_hash: String,
    pub hypervisor_version: u64,
    pub allow_transition_signatures: bool,
    pub allow_passthrough: bool,
    pub previous_receipt_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapsuleError {
    SchemaMismatch,
    HashMismatch,
    MissingSignature,
    RevokedSignature,
    TransitionSignatureNotAllowed,
    HypervisorTooOld,
    PassthroughDenied,
}

impl UntrustedCapsuleManifest {
    pub fn verify(self, req: VerificationRequest) -> Result<VerifiedCapsuleManifest, CapsuleError> {
        if self.schema != CAPSULE_SCHEMA {
            return Err(CapsuleError::SchemaMismatch);
        }

        if req.computed_capsule_hash != req.expected_capsule_hash {
            return Err(CapsuleError::HashMismatch);
        }

        if self.signatures.is_empty() {
            return Err(CapsuleError::MissingSignature);
        }

        if self.signatures.iter().any(|sig| sig.status == SignatureStatus::Revoked) {
            return Err(CapsuleError::RevokedSignature);
        }

        if !req.allow_transition_signatures
            && self.signatures.iter().any(|sig| sig.status == SignatureStatus::Transition)
        {
            return Err(CapsuleError::TransitionSignatureNotAllowed);
        }

        if req.hypervisor_version < self.hypervisor_min_version {
            return Err(CapsuleError::HypervisorTooOld);
        }

        if !req.allow_passthrough && !self.devices.passthrough.is_empty() {
            return Err(CapsuleError::PassthroughDenied);
        }

        let receipt = Receipt::unsigned(
            format!("capsule-verify:{}", self.capsule_id),
            "manifest_verify",
            format!("vm:{}", self.vm_id),
            ReceiptDecision::Allow,
            None,
            req.computed_capsule_hash,
            req.previous_receipt_hash,
        );

        Ok(VerifiedCapsuleManifest { inner: self, verification_receipt: receipt })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> UntrustedCapsuleManifest {
        UntrustedCapsuleManifest {
            schema: CAPSULE_SCHEMA.into(),
            capsule_id: "cap-1".into(),
            vm_id: "guest-zero".into(),
            image_hash: "sha384:image".into(),
            disk_hash: "sha384:disk".into(),
            hypervisor_min_version: 1,
            boot_policy_version: 1,
            devices: CapsuleDevicePolicy { passthrough: Vec::new(), virtio: vec!["console".into()] },
            memory: MemorySpec { max_mb: 64, allow_balloon: false },
            cpu: CpuSpec { vcpus: 1, cpuid_profile: "masked_zen3_guest_v1".into() },
            network: NetworkSpec { mode: "none".into(), egress_policy: "deny_by_default".into() },
            storage: StorageSpec { cipher: "aes-256-xts".into(), integrity: "manifest_hash_only".into(), key_version: 1 },
            signatures: vec![ManifestSignature { alg: "ed25519".into(), key_id: "lab".into(), status: SignatureStatus::Active }],
        }
    }

    #[test]
    fn verified_capsule_requires_matching_hash() {
        let req = VerificationRequest {
            computed_capsule_hash: "sha384:a".into(),
            expected_capsule_hash: "sha384:b".into(),
            hypervisor_version: 1,
            allow_transition_signatures: true,
            allow_passthrough: false,
            previous_receipt_hash: None,
        };
        assert_eq!(manifest().verify(req), Err(CapsuleError::HashMismatch));
    }

    #[test]
    fn verified_capsule_blocks_passthrough_by_default() {
        let mut m = manifest();
        m.devices.passthrough.push("0000:01:00.0".into());
        let req = VerificationRequest {
            computed_capsule_hash: "sha384:a".into(),
            expected_capsule_hash: "sha384:a".into(),
            hypervisor_version: 1,
            allow_transition_signatures: true,
            allow_passthrough: false,
            previous_receipt_hash: None,
        };
        assert_eq!(m.verify(req), Err(CapsuleError::PassthroughDenied));
    }
}
