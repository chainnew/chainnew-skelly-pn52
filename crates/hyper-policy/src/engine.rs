//! Deny-by-default, fail-closed policy engine (framework §9).
//!
//! Every evaluation starts from "deny" and only an explicit, fully satisfied
//! set of conditions yields an [`PolicyDecision::Allow`] carrying a
//! [`PolicyReceipt`]. Anything ambiguous denies or escalates to approval.

use serde::{Deserialize, Serialize};

use crate::document::PolicyDocument;
use crate::hash::sha384_hex;

/// Evidence emitted alongside an allow decision: a human-readable rationale
/// plus a deterministic hash binding the decision to its inputs.
///
/// This is a local, lightweight receipt so that `hyper-policy` does not depend
/// on `hyper-receipts` (which would create a dependency cycle).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PolicyReceipt {
    /// Why the request was allowed.
    pub rationale: String,
    /// `"sha384:<hex>"` of the policy id and the evaluated request.
    pub inputs_hash: String,
}

/// Reasons a request may be denied. Network/storage/launch specific where the
/// SOW names them; otherwise [`DenyReason::Other`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    /// Launch required a signed manifest but the manifest was unsigned.
    UnsignedManifest,
    /// Device passthrough requested but forbidden by policy.
    PassthroughForbidden,
    /// Hypervisor version is below the policy minimum.
    StaleHypervisor,
    /// Debug console requested but forbidden by policy.
    DebugForbidden,
    /// Network egress was not matched by an allow rule.
    EgressDenied,
    /// Storage encryption required but not present.
    EncryptionRequired,
    /// Sensitive VM presented a non-matching PCR quote.
    PcrMismatch,
    /// Any other fail-closed denial, with context.
    Other(String),
}

/// Outcome of a policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecision {
    /// Request permitted; carries the supporting receipt.
    Allow {
        /// Supporting evidence.
        receipt: PolicyReceipt,
    },
    /// Request denied; carries the reason.
    Deny {
        /// Why it was denied.
        reason: DenyReason,
    },
    /// Request neither allowed nor denied; a human/out-of-band approval is
    /// required. Carries a deterministic challenge to be satisfied.
    RequireApproval {
        /// Deterministic approval challenge.
        challenge: String,
    },
}

/// Request to launch a VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct VmLaunchRequest {
    /// Version of the hypervisor launching the guest.
    pub hypervisor_version: u64,
    /// Whether the boot manifest carries a valid signature.
    pub manifest_signed: bool,
    /// Whether measured boot is in effect.
    pub measured_boot: bool,
    /// Whether the launch requests an interactive debug console.
    pub requests_debug_console: bool,
}

/// Request to release a key to a guest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct KeyReleaseRequest {
    /// Whether the target VM is classified sensitive.
    pub sensitive: bool,
    /// Whether the presented PCR quote matches the expected policy.
    pub pcr_match: bool,
    /// Whether the target storage is encrypted.
    pub encryption: bool,
}

/// Request to assign a device to a guest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DeviceAssignRequest {
    /// Whether the assignment is a passthrough (vs. paravirtual) device.
    pub passthrough: bool,
    /// Device identifier (e.g. BDF or logical name).
    pub device: String,
}

/// Request to permit a network flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct FlowRequest {
    /// `"ingress"` or `"egress"`.
    pub direction: String,
    /// Whether an explicit allow rule matched this flow.
    pub allowed_by_rule: bool,
}

/// The policy engine surface. Every method returns a [`PolicyDecision`].
pub trait PolicyEngine {
    /// Evaluate a VM launch request.
    fn evaluate_vm_launch(&self, req: &VmLaunchRequest) -> PolicyDecision;
    /// Evaluate a key-release request.
    fn evaluate_key_release(&self, req: &KeyReleaseRequest) -> PolicyDecision;
    /// Evaluate a device-assignment request.
    fn evaluate_device_assignment(&self, req: &DeviceAssignRequest) -> PolicyDecision;
    /// Evaluate a network-flow request.
    fn evaluate_network_flow(&self, req: &FlowRequest) -> PolicyDecision;
}

/// Deny-by-default engine bound to a single [`PolicyDocument`].
#[derive(Debug, Clone)]
pub struct DefaultPolicyEngine {
    /// The policy this engine enforces.
    pub doc: PolicyDocument,
}

impl DefaultPolicyEngine {
    /// Construct an engine for the given document.
    pub fn new(doc: PolicyDocument) -> Self {
        Self { doc }
    }

    /// Deterministic hash binding the policy id to a serializable request.
    fn inputs_hash<T: Serialize>(&self, kind: &str, req: &T) -> String {
        // serde_json on a fixed struct is deterministic (field order is
        // declaration order); combined with the policy id this binds the
        // decision to exactly these inputs. No clocks, no randomness.
        let body = serde_json::to_string(req).unwrap_or_default();
        sha384_hex(format!("{}|{}|{}", self.doc.policy_id, kind, body).as_bytes())
    }

    fn allow<T: Serialize>(&self, kind: &str, req: &T, rationale: &str) -> PolicyDecision {
        PolicyDecision::Allow {
            receipt: PolicyReceipt {
                rationale: rationale.to_string(),
                inputs_hash: self.inputs_hash(kind, req),
            },
        }
    }
}

impl PolicyEngine for DefaultPolicyEngine {
    fn evaluate_vm_launch(&self, req: &VmLaunchRequest) -> PolicyDecision {
        if req.hypervisor_version < self.doc.minimum_hypervisor_version {
            return PolicyDecision::Deny {
                reason: DenyReason::StaleHypervisor,
            };
        }
        if self.doc.require_signed_manifest && !req.manifest_signed {
            return PolicyDecision::Deny {
                reason: DenyReason::UnsignedManifest,
            };
        }
        if self.doc.require_measured_boot && !req.measured_boot {
            return PolicyDecision::Deny {
                reason: DenyReason::Other("measured boot required".to_string()),
            };
        }
        if req.requests_debug_console && !self.doc.allow_debug_console {
            return PolicyDecision::Deny {
                reason: DenyReason::DebugForbidden,
            };
        }
        self.allow("vm_launch", req, "launch satisfies all launch gates")
    }

    fn evaluate_key_release(&self, req: &KeyReleaseRequest) -> PolicyDecision {
        if self.doc.storage.require_encryption && !req.encryption {
            return PolicyDecision::Deny {
                reason: DenyReason::EncryptionRequired,
            };
        }
        if req.sensitive
            && self.doc.key_release.require_pcr_match_for_sensitive_vms
            && !req.pcr_match
        {
            // Fail closed but allow an out-of-band approval path rather than a
            // hard deny: a sensitive VM with no PCR match must be escalated.
            return PolicyDecision::RequireApproval {
                challenge: format!("pcr-approval:{}", self.inputs_hash("key_release", req)),
            };
        }
        self.allow("key_release", req, "key release satisfies storage and pcr gates")
    }

    fn evaluate_device_assignment(&self, req: &DeviceAssignRequest) -> PolicyDecision {
        if req.passthrough && !self.doc.allow_device_passthrough {
            return PolicyDecision::Deny {
                reason: DenyReason::PassthroughForbidden,
            };
        }
        self.allow("device_assign", req, "device assignment permitted by policy")
    }

    fn evaluate_network_flow(&self, req: &FlowRequest) -> PolicyDecision {
        // Deny-by-default: a flow is permitted only if an explicit rule matched
        // OR the document's posture is an explicit "allow".
        let permitted = req.allowed_by_rule || self.doc.network_default == "allow";
        if permitted {
            return self.allow("network_flow", req, "flow matched an allow rule or posture");
        }
        let reason = if req.direction == "egress" {
            DenyReason::EgressDenied
        } else {
            DenyReason::Other(format!("{} flow not matched by rule", req.direction))
        };
        PolicyDecision::Deny { reason }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::PolicyDocument;

    fn strict_doc() -> PolicyDocument {
        let j = r#"{
            "schema_version": 1,
            "policy_id": "pol-strict",
            "minimum_hypervisor_version": 52,
            "require_signed_manifest": true,
            "require_measured_boot": true,
            "allow_device_passthrough": false,
            "allow_debug_console": false,
            "network_default": "deny",
            "storage": { "require_encryption": true, "allow_read_write_base_image": false },
            "key_release": { "mode": "tpm2_pcr_policy", "require_pcr_match_for_sensitive_vms": true }
        }"#;
        PolicyDocument::parse(j).unwrap()
    }

    fn engine() -> DefaultPolicyEngine {
        DefaultPolicyEngine::new(strict_doc())
    }

    // ---- VM launch -------------------------------------------------------

    #[test]
    fn launch_happy_path_allows_with_receipt() {
        let d = engine().evaluate_vm_launch(&VmLaunchRequest {
            hypervisor_version: 52,
            manifest_signed: true,
            measured_boot: true,
            requests_debug_console: false,
        });
        match d {
            PolicyDecision::Allow { receipt } => {
                assert!(receipt.inputs_hash.starts_with("sha384:"));
                assert!(!receipt.rationale.is_empty());
            }
            other => panic!("expected allow, got {other:?}"),
        }
    }

    #[test]
    fn launch_unsigned_manifest_denied() {
        let d = engine().evaluate_vm_launch(&VmLaunchRequest {
            hypervisor_version: 52,
            manifest_signed: false,
            measured_boot: true,
            requests_debug_console: false,
        });
        assert_eq!(
            d,
            PolicyDecision::Deny {
                reason: DenyReason::UnsignedManifest
            }
        );
    }

    #[test]
    fn launch_stale_hypervisor_denied() {
        let d = engine().evaluate_vm_launch(&VmLaunchRequest {
            hypervisor_version: 51,
            manifest_signed: true,
            measured_boot: true,
            requests_debug_console: false,
        });
        assert_eq!(
            d,
            PolicyDecision::Deny {
                reason: DenyReason::StaleHypervisor
            }
        );
    }

    #[test]
    fn launch_measured_boot_required_denied() {
        let d = engine().evaluate_vm_launch(&VmLaunchRequest {
            hypervisor_version: 52,
            manifest_signed: true,
            measured_boot: false,
            requests_debug_console: false,
        });
        assert!(matches!(
            d,
            PolicyDecision::Deny {
                reason: DenyReason::Other(_)
            }
        ));
    }

    #[test]
    fn launch_debug_console_denied() {
        let d = engine().evaluate_vm_launch(&VmLaunchRequest {
            hypervisor_version: 52,
            manifest_signed: true,
            measured_boot: true,
            requests_debug_console: true,
        });
        assert_eq!(
            d,
            PolicyDecision::Deny {
                reason: DenyReason::DebugForbidden
            }
        );
    }

    #[test]
    fn launch_debug_allowed_when_policy_permits() {
        let j = r#"{
            "schema_version": 1, "policy_id": "p", "minimum_hypervisor_version": 1,
            "require_signed_manifest": false, "require_measured_boot": false,
            "allow_device_passthrough": false, "allow_debug_console": true,
            "network_default": "deny",
            "storage": { "require_encryption": false, "allow_read_write_base_image": true },
            "key_release": { "mode": "passphrase_only", "require_pcr_match_for_sensitive_vms": false }
        }"#;
        let eng = DefaultPolicyEngine::new(PolicyDocument::parse(j).unwrap());
        let d = eng.evaluate_vm_launch(&VmLaunchRequest {
            hypervisor_version: 1,
            manifest_signed: false,
            measured_boot: false,
            requests_debug_console: true,
        });
        assert!(matches!(d, PolicyDecision::Allow { .. }));
    }

    // ---- Key release -----------------------------------------------------

    #[test]
    fn key_release_happy_path_allows() {
        let d = engine().evaluate_key_release(&KeyReleaseRequest {
            sensitive: true,
            pcr_match: true,
            encryption: true,
        });
        assert!(matches!(d, PolicyDecision::Allow { .. }));
    }

    #[test]
    fn key_release_encryption_required_denied() {
        let d = engine().evaluate_key_release(&KeyReleaseRequest {
            sensitive: false,
            pcr_match: true,
            encryption: false,
        });
        assert_eq!(
            d,
            PolicyDecision::Deny {
                reason: DenyReason::EncryptionRequired
            }
        );
    }

    #[test]
    fn key_release_sensitive_pcr_mismatch_requires_approval() {
        let d = engine().evaluate_key_release(&KeyReleaseRequest {
            sensitive: true,
            pcr_match: false,
            encryption: true,
        });
        match d {
            PolicyDecision::RequireApproval { challenge } => {
                assert!(challenge.starts_with("pcr-approval:sha384:"));
            }
            other => panic!("expected require_approval, got {other:?}"),
        }
    }

    #[test]
    fn key_release_nonsensitive_pcr_mismatch_allows() {
        let d = engine().evaluate_key_release(&KeyReleaseRequest {
            sensitive: false,
            pcr_match: false,
            encryption: true,
        });
        assert!(matches!(d, PolicyDecision::Allow { .. }));
    }

    // ---- Device assignment ----------------------------------------------

    #[test]
    fn passthrough_denied_when_forbidden() {
        let d = engine().evaluate_device_assignment(&DeviceAssignRequest {
            passthrough: true,
            device: "0000:01:00.0".to_string(),
        });
        assert_eq!(
            d,
            PolicyDecision::Deny {
                reason: DenyReason::PassthroughForbidden
            }
        );
    }

    #[test]
    fn paravirtual_device_allowed() {
        let d = engine().evaluate_device_assignment(&DeviceAssignRequest {
            passthrough: false,
            device: "virtio-net".to_string(),
        });
        assert!(matches!(d, PolicyDecision::Allow { .. }));
    }

    // ---- Network flow ----------------------------------------------------

    #[test]
    fn egress_unmatched_denied() {
        let d = engine().evaluate_network_flow(&FlowRequest {
            direction: "egress".to_string(),
            allowed_by_rule: false,
        });
        assert_eq!(
            d,
            PolicyDecision::Deny {
                reason: DenyReason::EgressDenied
            }
        );
    }

    #[test]
    fn ingress_unmatched_denied_other() {
        let d = engine().evaluate_network_flow(&FlowRequest {
            direction: "ingress".to_string(),
            allowed_by_rule: false,
        });
        assert!(matches!(
            d,
            PolicyDecision::Deny {
                reason: DenyReason::Other(_)
            }
        ));
    }

    #[test]
    fn flow_matched_by_rule_allowed() {
        let d = engine().evaluate_network_flow(&FlowRequest {
            direction: "egress".to_string(),
            allowed_by_rule: true,
        });
        assert!(matches!(d, PolicyDecision::Allow { .. }));
    }

    #[test]
    fn flow_allowed_posture_permits_unmatched() {
        let j = r#"{
            "schema_version": 1, "policy_id": "p", "minimum_hypervisor_version": 1,
            "require_signed_manifest": false, "require_measured_boot": false,
            "allow_device_passthrough": false, "allow_debug_console": false,
            "network_default": "allow",
            "storage": { "require_encryption": false, "allow_read_write_base_image": true },
            "key_release": { "mode": "passphrase_only", "require_pcr_match_for_sensitive_vms": false }
        }"#;
        let eng = DefaultPolicyEngine::new(PolicyDocument::parse(j).unwrap());
        let d = eng.evaluate_network_flow(&FlowRequest {
            direction: "egress".to_string(),
            allowed_by_rule: false,
        });
        assert!(matches!(d, PolicyDecision::Allow { .. }));
    }

    // ---- Receipt determinism --------------------------------------------

    #[test]
    fn receipt_hash_is_deterministic() {
        let req = DeviceAssignRequest {
            passthrough: false,
            device: "virtio-blk".to_string(),
        };
        let a = engine().evaluate_device_assignment(&req);
        let b = engine().evaluate_device_assignment(&req);
        assert_eq!(a, b);
    }
}
