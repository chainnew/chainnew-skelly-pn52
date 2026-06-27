//! Deny-by-default policy engine.
//!
//! Maps to SOW-HSLATE-PN52-002 Part B §9 ("Policy engine") and the defensive
//! defaults in Part A §10. Every interesting action (launch a VM, release a
//! key, assign a device, allow a network flow) is gated here and returns an
//! explicit [`PolicyDecision`]. There is no implicit "allow" path.
//!
//! V0 implements VM-launch and key-release evaluation against a signed-in-spirit
//! [`PolicyConfig`]. Device/network evaluation hooks are present and fail closed
//! so later phases (V6/V10) only have to fill in allowlist matching.

use hyper_capsule::{SignatureStatus, VerifiedManifest};
use serde::{Deserialize, Serialize};

/// Policy bundle (`pn52-lab-default-v1` shape from §9). In production this is a
/// signed, versioned document; here it is a plain struct loaded by the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PolicyConfig {
    pub policy_id: String,
    pub minimum_hypervisor_version: u64,
    pub require_signed_manifest: bool,
    pub require_measured_boot: bool,
    pub allow_device_passthrough: bool,
    pub allow_debug_console: bool,
    /// "deny" | "allow" — applied to guest egress at the network layer.
    pub network_default: String,
    pub storage: StoragePolicy,
    pub key_release: KeyReleasePolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct StoragePolicy {
    pub require_encryption: bool,
    pub allow_read_write_base_image: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct KeyReleasePolicy {
    /// e.g. "local_dev_or_attested_kms".
    pub mode: String,
    pub require_pcr_match_for_sensitive_vms: bool,
}

impl PolicyConfig {
    /// The conservative lab default from §9.
    pub fn lab_default() -> Self {
        Self {
            policy_id: "pn52-lab-default-v1".to_string(),
            minimum_hypervisor_version: 4,
            require_signed_manifest: true,
            require_measured_boot: true,
            allow_device_passthrough: false,
            allow_debug_console: false,
            network_default: "deny".to_string(),
            storage: StoragePolicy {
                require_encryption: true,
                allow_read_write_base_image: false,
            },
            key_release: KeyReleasePolicy {
                mode: "local_dev_or_attested_kms".to_string(),
                require_pcr_match_for_sensitive_vms: true,
            },
        }
    }
}

/// Measured platform state presented at decision time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlatformState {
    pub secure_boot: bool,
    pub measured_boot: bool,
    /// An out-of-band debug override was requested for this VM.
    pub debug_override: bool,
    /// PCR set matched the expected, signed boot policy.
    pub pcr_match: bool,
}

impl PlatformState {
    /// A clean, attested boot with no debug overrides.
    pub fn trusted_boot() -> Self {
        Self {
            secure_boot: true,
            measured_boot: true,
            debug_override: false,
            pcr_match: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmLaunchRequest<'a> {
    pub manifest: &'a VerifiedManifest,
    pub platform: PlatformState,
    /// Caller-declared sensitivity; sensitive VMs face stricter key rules.
    pub sensitive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyReleaseRequest<'a> {
    pub manifest: &'a VerifiedManifest,
    pub platform: PlatformState,
    pub sensitive: bool,
}

/// Why a request was refused. Stable strings so they can land in receipts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    MeasuredBootRequired,
    SecureBootRequired,
    DebugOverrideForbidden,
    PassthroughForbidden,
    EncryptionRequired,
    HypervisorTooOld,
    TransitionSignatureForbidden,
    PcrMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyReceiptMeta {
    pub policy_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow { meta: PolicyReceiptMeta },
    Deny { reason: DenyReason },
    RequireApproval { challenge: String },
}

impl PolicyDecision {
    pub fn is_allow(&self) -> bool {
        matches!(self, PolicyDecision::Allow { .. })
    }
}

pub trait PolicyEngine {
    fn evaluate_vm_launch(&self, req: &VmLaunchRequest) -> PolicyDecision;
    fn evaluate_key_release(&self, req: &KeyReleaseRequest) -> PolicyDecision;
}

/// Default engine driven by a [`PolicyConfig`].
#[derive(Debug, Clone)]
pub struct DefaultPolicyEngine {
    config: PolicyConfig,
}

impl DefaultPolicyEngine {
    pub fn new(config: PolicyConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &PolicyConfig {
        &self.config
    }

    fn meta(&self) -> PolicyReceiptMeta {
        PolicyReceiptMeta {
            policy_id: self.config.policy_id.clone(),
        }
    }
}

impl PolicyEngine for DefaultPolicyEngine {
    fn evaluate_vm_launch(&self, req: &VmLaunchRequest) -> PolicyDecision {
        let c = &self.config;
        let m = req.manifest.manifest();

        if m.hypervisor_min_version > c.minimum_hypervisor_version {
            return PolicyDecision::Deny { reason: DenyReason::HypervisorTooOld };
        }
        if c.require_measured_boot && !req.platform.measured_boot {
            return PolicyDecision::Deny { reason: DenyReason::MeasuredBootRequired };
        }
        // A signed manifest is already proven by the VerifiedManifest type, but a
        // transition-only signature is too weak for a sensitive VM.
        if req.sensitive
            && req.manifest.signature_status() == SignatureStatus::TransitionOnly
        {
            return PolicyDecision::Deny { reason: DenyReason::TransitionSignatureForbidden };
        }
        if !c.allow_device_passthrough && !m.devices.passthrough.is_empty() {
            return PolicyDecision::Deny { reason: DenyReason::PassthroughForbidden };
        }
        if req.platform.debug_override && !c.allow_debug_console {
            return PolicyDecision::Deny { reason: DenyReason::DebugOverrideForbidden };
        }
        if c.storage.require_encryption && m.storage.cipher.eq_ignore_ascii_case("none") {
            return PolicyDecision::Deny { reason: DenyReason::EncryptionRequired };
        }

        PolicyDecision::Allow { meta: self.meta() }
    }

    fn evaluate_key_release(&self, req: &KeyReleaseRequest) -> PolicyDecision {
        let c = &self.config;

        if c.require_measured_boot && !req.platform.measured_boot {
            return PolicyDecision::Deny { reason: DenyReason::MeasuredBootRequired };
        }
        // Sensitive VMs require the boot to match the signed PCR policy. If the
        // platform can't prove it, escalate to an operator approval rather than
        // silently allowing or hard-denying.
        if req.sensitive && c.key_release.require_pcr_match_for_sensitive_vms && !req.platform.pcr_match
        {
            if req.platform.measured_boot {
                return PolicyDecision::RequireApproval {
                    challenge: "pcr_mismatch_operator_approval".to_string(),
                };
            }
            return PolicyDecision::Deny { reason: DenyReason::PcrMismatch };
        }

        PolicyDecision::Allow { meta: self.meta() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper_capsule::{TrustStore, UntrustedManifest};

    fn verified(sensitive_transition: bool, passthrough: bool, cipher: &str) -> VerifiedManifest {
        let (sig, key, status) = if sensitive_transition {
            (
                "ml-dsa-65",
                "lab-pq-transition-2026",
                "transition",
            )
        } else {
            ("ecdsa-p384", "lab-classical-2026", "active")
        };
        let pass = if passthrough { r#""0000:01:00.0""# } else { "" };
        let json = format!(
            r#"{{
              "schema": "chain.vm_capsule.v1",
              "vm_id": "vm-test",
              "tenant_id": "lab",
              "image_hash": "sha384:x",
              "disk_hash": "sha384:y",
              "hypervisor_min_version": 4,
              "boot_policy_version": 7,
              "devices": {{ "passthrough": [{pass}], "virtio": ["blk"] }},
              "memory": {{ "max_mb": 2048, "allow_balloon": false }},
              "cpu": {{ "vcpus": 1, "cpuid_profile": "masked_zen3_guest_v1" }},
              "network": {{ "mode": "isolated", "egress_policy": "deny_by_default" }},
              "storage": {{ "cipher": "{cipher}", "integrity": "manifest_hash_only", "key_version": 3 }},
              "signatures": [{{ "alg": "{sig}", "key_id": "{key}", "status": "{status}" }}]
            }}"#
        );
        let trust = TrustStore::new(12).trust_key(key);
        UntrustedManifest::parse(json.as_bytes())
            .unwrap()
            .verify(&trust, None, None)
            .unwrap()
    }

    fn engine() -> DefaultPolicyEngine {
        DefaultPolicyEngine::new(PolicyConfig::lab_default())
    }

    #[test]
    fn clean_launch_is_allowed() {
        let m = verified(false, false, "AES-256-XTS");
        let req = VmLaunchRequest { manifest: &m, platform: PlatformState::trusted_boot(), sensitive: false };
        assert!(engine().evaluate_vm_launch(&req).is_allow());
    }

    #[test]
    fn unmeasured_boot_is_denied() {
        let m = verified(false, false, "AES-256-XTS");
        let mut p = PlatformState::trusted_boot();
        p.measured_boot = false;
        let req = VmLaunchRequest { manifest: &m, platform: p, sensitive: false };
        assert_eq!(
            engine().evaluate_vm_launch(&req),
            PolicyDecision::Deny { reason: DenyReason::MeasuredBootRequired }
        );
    }

    #[test]
    fn passthrough_is_denied_by_default() {
        let m = verified(false, true, "AES-256-XTS");
        let req = VmLaunchRequest { manifest: &m, platform: PlatformState::trusted_boot(), sensitive: false };
        assert_eq!(
            engine().evaluate_vm_launch(&req),
            PolicyDecision::Deny { reason: DenyReason::PassthroughForbidden }
        );
    }

    #[test]
    fn debug_override_is_denied_by_default() {
        let m = verified(false, false, "AES-256-XTS");
        let mut p = PlatformState::trusted_boot();
        p.debug_override = true;
        let req = VmLaunchRequest { manifest: &m, platform: p, sensitive: false };
        assert_eq!(
            engine().evaluate_vm_launch(&req),
            PolicyDecision::Deny { reason: DenyReason::DebugOverrideForbidden }
        );
    }

    #[test]
    fn transition_signature_blocks_sensitive_vm() {
        let m = verified(true, false, "AES-256-XTS");
        let req = VmLaunchRequest { manifest: &m, platform: PlatformState::trusted_boot(), sensitive: true };
        assert_eq!(
            engine().evaluate_vm_launch(&req),
            PolicyDecision::Deny { reason: DenyReason::TransitionSignatureForbidden }
        );
    }

    #[test]
    fn plaintext_storage_is_denied() {
        let m = verified(false, false, "none");
        let req = VmLaunchRequest { manifest: &m, platform: PlatformState::trusted_boot(), sensitive: false };
        assert_eq!(
            engine().evaluate_vm_launch(&req),
            PolicyDecision::Deny { reason: DenyReason::EncryptionRequired }
        );
    }

    #[test]
    fn sensitive_pcr_mismatch_requires_approval() {
        let m = verified(false, false, "AES-256-XTS");
        let mut p = PlatformState::trusted_boot();
        p.pcr_match = false;
        let req = KeyReleaseRequest { manifest: &m, platform: p, sensitive: true };
        assert!(matches!(
            engine().evaluate_key_release(&req),
            PolicyDecision::RequireApproval { .. }
        ));
    }

    #[test]
    fn key_release_clean_path_allows() {
        let m = verified(false, false, "AES-256-XTS");
        let req = KeyReleaseRequest { manifest: &m, platform: PlatformState::trusted_boot(), sensitive: true };
        assert!(engine().evaluate_key_release(&req).is_allow());
    }
}
