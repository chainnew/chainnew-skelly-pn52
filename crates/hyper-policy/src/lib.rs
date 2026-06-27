use hyper_receipts::{Receipt, ReceiptDecision};
use serde::{Deserialize, Serialize};

pub const POLICY_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NetworkDefault {
    Deny,
    Isolated,
    HostOnly,
    Nat,
    Bridge,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    MissingMeasurement,
    SignatureInvalid,
    RollbackDetected,
    HypervisorTooOld,
    DevicePassthroughDenied,
    DebugConsoleDenied,
    NetworkDenied,
    StorageUnlockDenied,
    UnknownVmExit,
    HostInvariantFailed,
    UnsupportedAlgorithm,
    Other(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct ApprovalChallenge {
    pub challenge_id: String,
    pub reason: DenyReason,
    pub subject: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecision {
    Allow { receipt: Receipt },
    Deny { reason: DenyReason },
    RequireApproval { challenge: ApprovalChallenge },
}

impl PolicyDecision {
    pub fn is_allow(&self) -> bool {
        matches!(self, Self::Allow { .. })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct VmLaunchPolicy {
    pub schema_version: u32,
    pub policy_id: String,
    pub minimum_hypervisor_version: u64,
    pub require_signed_manifest: bool,
    pub require_measured_boot: bool,
    pub allow_device_passthrough: bool,
    pub allow_debug_console: bool,
    pub network_default: NetworkDefault,
}

impl VmLaunchPolicy {
    pub fn lab_default() -> Self {
        Self {
            schema_version: POLICY_SCHEMA_VERSION,
            policy_id: "pn52-lab-default-v1".to_string(),
            minimum_hypervisor_version: 1,
            require_signed_manifest: true,
            require_measured_boot: false,
            allow_device_passthrough: false,
            allow_debug_console: true,
            network_default: NetworkDefault::Deny,
        }
    }

    pub fn secure_default() -> Self {
        Self {
            schema_version: POLICY_SCHEMA_VERSION,
            policy_id: "pn52-secure-default-v1".to_string(),
            minimum_hypervisor_version: 1,
            require_signed_manifest: true,
            require_measured_boot: true,
            allow_device_passthrough: false,
            allow_debug_console: false,
            network_default: NetworkDefault::Deny,
        }
    }

    pub fn evaluate_vm_launch(&self, req: &VmLaunchRequest) -> PolicyDecision {
        if req.hypervisor_version < self.minimum_hypervisor_version {
            return PolicyDecision::Deny { reason: DenyReason::HypervisorTooOld };
        }

        if self.require_signed_manifest && !req.manifest_verified {
            return PolicyDecision::Deny { reason: DenyReason::SignatureInvalid };
        }

        if self.require_measured_boot && !req.boot_measurements_present {
            return PolicyDecision::Deny { reason: DenyReason::MissingMeasurement };
        }

        if req.requests_device_passthrough && !self.allow_device_passthrough {
            return PolicyDecision::Deny { reason: DenyReason::DevicePassthroughDenied };
        }

        if req.requests_debug_console && !self.allow_debug_console {
            return PolicyDecision::Deny { reason: DenyReason::DebugConsoleDenied };
        }

        let receipt = Receipt::unsigned(
            format!("policy:{}:{}", self.policy_id, req.vm_id),
            "vm_launch_policy",
            format!("vm:{}", req.vm_id),
            ReceiptDecision::Allow,
            Some(self.policy_id.clone()),
            req.capsule_hash.clone(),
            req.previous_receipt_hash.clone(),
        );

        PolicyDecision::Allow { receipt }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct VmLaunchRequest {
    pub vm_id: String,
    pub manifest_verified: bool,
    pub capsule_hash: String,
    pub hypervisor_version: u64,
    pub boot_measurements_present: bool,
    pub requests_device_passthrough: bool,
    pub requests_debug_console: bool,
    pub previous_receipt_hash: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_policy_denies_missing_measurements() {
        let policy = VmLaunchPolicy::secure_default();
        let req = VmLaunchRequest {
            vm_id: "guest-zero".into(),
            manifest_verified: true,
            capsule_hash: "sha384:capsule".into(),
            hypervisor_version: 1,
            boot_measurements_present: false,
            requests_device_passthrough: false,
            requests_debug_console: false,
            previous_receipt_hash: None,
        };
        assert_eq!(
            policy.evaluate_vm_launch(&req),
            PolicyDecision::Deny { reason: DenyReason::MissingMeasurement }
        );
    }

    #[test]
    fn lab_policy_allows_debug_but_not_passthrough() {
        let policy = VmLaunchPolicy::lab_default();
        let req = VmLaunchRequest {
            vm_id: "guest-zero".into(),
            manifest_verified: true,
            capsule_hash: "sha384:capsule".into(),
            hypervisor_version: 1,
            boot_measurements_present: false,
            requests_device_passthrough: false,
            requests_debug_console: true,
            previous_receipt_hash: None,
        };
        assert!(policy.evaluate_vm_launch(&req).is_allow());
    }
}
//! hyper-policy — deny-by-default policy engine and policy-as-code document
//! (framework §9) for the chain.new hyper-slate PN52 runtime.
//!
//! A [`PolicyDocument`] is parsed from the SOW JSON and enforced by a
//! [`DefaultPolicyEngine`] implementing the [`PolicyEngine`] trait. Every
//! evaluation is fail-closed: it begins at "deny" and only an explicit,
//! fully-satisfied set of conditions yields [`PolicyDecision::Allow`] with a
//! [`PolicyReceipt`]. Decisions and receipts are deterministic (content-hash
//! derived, no clocks, no randomness).
//!
//! This crate defines its own lightweight [`PolicyReceipt`] rather than
//! depending on `hyper-receipts`, to avoid a dependency cycle.
#![forbid(unsafe_code)]

mod document;
mod engine;
mod hash;

pub use document::{
    KeyReleasePolicy, PolicyDocument, PolicyError, StoragePolicy, POLICY_SCHEMA_VERSION,
};
pub use engine::{
    DefaultPolicyEngine, DenyReason, DeviceAssignRequest, FlowRequest, KeyReleaseRequest,
    PolicyDecision, PolicyEngine, PolicyReceipt, VmLaunchRequest,
};
pub use hash::sha384_hex;

// Re-exported for convenience: the core unlock mode used by key-release policy.
pub use hyper_slate_core::policy::UnlockMode;
