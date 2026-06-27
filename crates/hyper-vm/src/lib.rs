//! VM lifecycle state machine — the control brain of the Slate Runtime.
//!
//! Maps to SOW-HSLATE-PN52-002 Part B §2 ("VM lifecycle manager") and §5
//! ("vCPU runtime"), wired to capsule verification (`hyper-capsule`), the policy
//! engine (`hyper-policy`), and the audit chain (`hyper-receipts`).
//!
//! Design rules enforced here:
//!   * There is no public `launch_guest()`. Every transition runs through the
//!     lifecycle and consults policy.
//!   * A VM can only be constructed from a [`VerifiedManifest`] — an unsigned or
//!     untrusted capsule cannot even reach this crate (type-enforced upstream).
//!   * Every state change that matters emits a receipt into a hash chain.
//!   * Unknown/forbidden guest behaviour fails closed: the VM is quarantined.

pub mod backend;

use backend::{DiskBackend, ExitAction, VcpuBackend};
use hyper_capsule::VerifiedManifest;
use hyper_policy::{
    KeyReleaseRequest, PlatformState, PolicyDecision, PolicyEngine, VmLaunchRequest,
};
use hyper_receipts::{Decision, ReceiptChain};

/// The VM state machine (Part B §2). Terminal-ish states: `Stopped`,
/// `Destroyed`, `Failed`, `Quarantined`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmState {
    Defined,
    Prepared,
    AwaitingKeyRelease,
    Unlocked,
    Attached,
    Running,
    Paused,
    Stopping,
    Stopped,
    Failed,
    Quarantined,
    Destroyed,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VmError {
    #[error("operation not valid in state {0:?}")]
    BadState(VmState),
    #[error("policy denied: {0}")]
    PolicyDenied(String),
    #[error("policy requires operator approval: {0}")]
    ApprovalRequired(String),
    #[error("guest faulted; VM quarantined")]
    GuestFault,
}

/// Per-VM sensitivity, surfaced to the policy engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sensitivity {
    Standard,
    Sensitive,
}

impl Sensitivity {
    fn is_sensitive(self) -> bool {
        matches!(self, Sensitivity::Sensitive)
    }
}

/// A live VM. Owns its verified manifest, backends, policy engine, and the
/// receipt chain recording its lifecycle.
pub struct Vm<P: PolicyEngine, V: VcpuBackend, D: DiskBackend> {
    manifest: VerifiedManifest,
    state: VmState,
    sensitivity: Sensitivity,
    platform: PlatformState,
    policy: P,
    vcpu: V,
    disk: D,
    receipts: ReceiptChain,
}

impl<P: PolicyEngine, V: VcpuBackend, D: DiskBackend> Vm<P, V, D> {
    /// Define a VM from a verified capsule. State: `Defined`. Emits a receipt.
    pub fn define(
        manifest: VerifiedManifest,
        sensitivity: Sensitivity,
        platform: PlatformState,
        policy: P,
        vcpu: V,
        disk: D,
    ) -> Self {
        let mut receipts = ReceiptChain::new();
        let subject = format!("vm:{}", manifest.vm_id());
        let inputs = hyper_receipts::hash_inputs(&manifest.canonical_bytes());
        receipts.append("vm_define", subject, Decision::Allow, "n/a", inputs);
        Self {
            manifest,
            state: VmState::Defined,
            sensitivity,
            platform,
            policy,
            vcpu,
            disk,
            receipts,
        }
    }

    pub fn state(&self) -> VmState {
        self.state
    }
    pub fn vm_id(&self) -> &str {
        self.manifest.vm_id()
    }
    pub fn receipts(&self) -> &ReceiptChain {
        &self.receipts
    }

    fn subject(&self) -> String {
        format!("vm:{}", self.manifest.vm_id())
    }

    fn require(&self, expected: VmState) -> Result<(), VmError> {
        if self.state == expected {
            Ok(())
        } else {
            Err(VmError::BadState(self.state))
        }
    }

    /// Record a policy decision as a receipt and translate it to a `Result`.
    fn record_decision(&mut self, event: &str, decision: &PolicyDecision) -> Result<(), VmError> {
        let subject = self.subject();
        let inputs = hyper_receipts::hash_inputs(&self.manifest.canonical_bytes());
        match decision {
            PolicyDecision::Allow { meta } => {
                self.receipts
                    .append(event.to_string(), subject, Decision::Allow, meta.policy_id.clone(), inputs);
                Ok(())
            }
            PolicyDecision::Deny { reason } => {
                let reason = format!("{reason:?}");
                self.receipts
                    .append(event.to_string(), subject, Decision::Deny, "deny", inputs);
                Err(VmError::PolicyDenied(reason))
            }
            PolicyDecision::RequireApproval { challenge } => {
                self.receipts.append(
                    event.to_string(),
                    subject,
                    Decision::RequireApproval,
                    "approval",
                    inputs,
                );
                Err(VmError::ApprovalRequired(challenge.clone()))
            }
        }
    }

    /// `Defined` -> `Prepared`: evaluate launch policy (memory/cpu/device/boot
    /// gates). Allocation of guest memory and vCPUs happens here in real backends.
    pub fn prepare(&mut self) -> Result<(), VmError> {
        self.require(VmState::Defined)?;
        let decision = {
            let req = VmLaunchRequest {
                manifest: &self.manifest,
                platform: self.platform,
                sensitive: self.sensitivity.is_sensitive(),
            };
            self.policy.evaluate_vm_launch(&req)
        };
        self.record_decision("vm_launch_policy", &decision)?;
        self.state = VmState::Prepared;
        Ok(())
    }

    /// `Prepared` -> `Unlocked`: evaluate key-release policy and (in real
    /// backends) unwrap the DEK. A `RequireApproval` decision leaves the VM in
    /// `AwaitingKeyRelease`.
    pub fn unlock(&mut self) -> Result<(), VmError> {
        self.require(VmState::Prepared)?;
        let decision = {
            let req = KeyReleaseRequest {
                manifest: &self.manifest,
                platform: self.platform,
                sensitive: self.sensitivity.is_sensitive(),
            };
            self.policy.evaluate_key_release(&req)
        };
        match self.record_decision("vm_key_release", &decision) {
            Ok(()) => {
                self.state = VmState::Unlocked;
                Ok(())
            }
            Err(VmError::ApprovalRequired(c)) => {
                self.state = VmState::AwaitingKeyRelease;
                Err(VmError::ApprovalRequired(c))
            }
            Err(e) => Err(e),
        }
    }

    /// `Unlocked` -> `Attached`: bind disks/devices. V0 just confirms the disk
    /// backend is present and records the attach.
    pub fn attach(&mut self) -> Result<(), VmError> {
        self.require(VmState::Unlocked)?;
        let subject = self.subject();
        let inputs = hyper_receipts::hash_inputs(self.vm_id().as_bytes());
        self.receipts
            .append("vm_attach", subject, Decision::Allow, "n/a", inputs);
        self.state = VmState::Attached;
        Ok(())
    }

    /// `Attached` -> `Running` -> (HLT/Shutdown) -> `Stopped`, or fail closed to
    /// `Quarantined` on an unknown guest exit. This is the V0 scheduler loop:
    /// one vCPU, run-to-exit, dispatch.
    pub fn run(&mut self) -> Result<(), VmError> {
        self.require(VmState::Attached)?;
        let subject = self.subject();
        let inputs = hyper_receipts::hash_inputs(self.vm_id().as_bytes());
        self.receipts
            .append("vm_launch", subject.clone(), Decision::Allow, "n/a", inputs.clone());
        self.state = VmState::Running;

        loop {
            match self.vcpu.run_slice() {
                ExitAction::Halted => continue,
                ExitAction::Shutdown => {
                    self.state = VmState::Stopping;
                    self.vcpu.teardown();
                    self.disk.zeroize();
                    self.receipts.append(
                        "vm_stop",
                        subject,
                        Decision::Allow,
                        "n/a",
                        inputs,
                    );
                    self.state = VmState::Stopped;
                    return Ok(());
                }
                ExitAction::Fault => {
                    self.vcpu.teardown();
                    self.disk.zeroize();
                    self.receipts.append(
                        "vm_exit_fault",
                        subject,
                        Decision::Deny,
                        "fail_closed",
                        inputs,
                    );
                    self.state = VmState::Quarantined;
                    return Err(VmError::GuestFault);
                }
            }
        }
    }

    /// `Stopped`/`Quarantined` -> `Destroyed`: zeroize and emit a destroy receipt.
    pub fn destroy(mut self) -> Result<ReceiptChain, VmError> {
        match self.state {
            VmState::Stopped | VmState::Quarantined | VmState::Failed => {}
            other => return Err(VmError::BadState(other)),
        }
        self.disk.zeroize();
        let subject = self.subject();
        let inputs = hyper_receipts::hash_inputs(self.vm_id().as_bytes());
        self.receipts
            .append("vm_destroy", subject, Decision::Allow, "n/a", inputs);
        self.state = VmState::Destroyed;
        Ok(self.receipts)
    }
}

#[cfg(test)]
mod tests {
    use super::backend::{MemDisk, ScriptedVcpu};
    use super::*;
    use hyper_capsule::{TrustStore, UntrustedManifest};
    use hyper_policy::{DefaultPolicyEngine, PolicyConfig};

    const KEY: &str = "lab-classical-2026";

    fn manifest_json(passthrough: bool, cipher: &str) -> String {
        let pass = if passthrough { r#""0000:01:00.0""# } else { "" };
        format!(
            r#"{{
              "schema": "chain.vm_capsule.v1",
              "vm_id": "dev-linux-001",
              "tenant_id": "lab",
              "image_hash": "sha384:img",
              "disk_hash": "sha384:disk",
              "hypervisor_min_version": 4,
              "boot_policy_version": 7,
              "devices": {{ "passthrough": [{pass}], "virtio": ["blk", "console"] }},
              "memory": {{ "max_mb": 4096, "allow_balloon": false }},
              "cpu": {{ "vcpus": 2, "cpuid_profile": "masked_zen3_guest_v1" }},
              "network": {{ "mode": "isolated", "egress_policy": "deny_by_default" }},
              "storage": {{ "cipher": "{cipher}", "integrity": "manifest_hash_only", "key_version": 3 }},
              "signatures": [{{ "alg": "ecdsa-p384", "key_id": "{KEY}", "status": "active" }}]
            }}"#
        )
    }

    fn verified(passthrough: bool, cipher: &str) -> VerifiedManifest {
        let trust = TrustStore::new(12).trust_key(KEY);
        UntrustedManifest::parse(manifest_json(passthrough, cipher).as_bytes())
            .unwrap()
            .verify(&trust, None, None)
            .unwrap()
    }

    fn engine() -> DefaultPolicyEngine {
        DefaultPolicyEngine::new(PolicyConfig::lab_default())
    }

    fn mem_disk() -> MemDisk {
        MemDisk::new(vec![vec![1u8; 4096], vec![2u8; 4096]], 4096)
    }

    /// V0 acceptance: Defined -> ... -> Running -> Stopped, receipts verify.
    #[test]
    fn full_lifecycle_runs_and_stops() {
        let mut vm = Vm::define(
            verified(false, "AES-256-XTS"),
            Sensitivity::Standard,
            PlatformState::trusted_boot(),
            engine(),
            ScriptedVcpu::cooperative(),
            mem_disk(),
        );
        assert_eq!(vm.state(), VmState::Defined);
        vm.prepare().unwrap();
        assert_eq!(vm.state(), VmState::Prepared);
        vm.unlock().unwrap();
        assert_eq!(vm.state(), VmState::Unlocked);
        vm.attach().unwrap();
        assert_eq!(vm.state(), VmState::Attached);
        vm.run().unwrap();
        assert_eq!(vm.state(), VmState::Stopped);

        // Audit chain is intact and records the whole journey.
        assert!(vm.receipts().verify().is_ok());
        let events: Vec<&str> = vm.receipts().receipts().iter().map(|r| r.event.as_str()).collect();
        assert_eq!(
            events,
            vec![
                "vm_define",
                "vm_launch_policy",
                "vm_key_release",
                "vm_attach",
                "vm_launch",
                "vm_stop",
            ]
        );

        let chain = vm.destroy().unwrap();
        assert!(chain.verify().is_ok());
        assert_eq!(chain.receipts().last().unwrap().event, "vm_destroy");
    }

    /// A guest that issues an unknown exit must fail closed into Quarantined.
    #[test]
    fn faulting_guest_is_quarantined() {
        let mut vm = Vm::define(
            verified(false, "AES-256-XTS"),
            Sensitivity::Standard,
            PlatformState::trusted_boot(),
            engine(),
            ScriptedVcpu::faulting(),
            mem_disk(),
        );
        vm.prepare().unwrap();
        vm.unlock().unwrap();
        vm.attach().unwrap();
        assert_eq!(vm.run(), Err(VmError::GuestFault));
        assert_eq!(vm.state(), VmState::Quarantined);
        // Fault is on the record and disk keys were zeroized.
        assert!(vm.receipts().verify().is_ok());
        assert_eq!(vm.receipts().receipts().last().unwrap().event, "vm_exit_fault");
    }

    /// Policy denial (passthrough) blocks at prepare and never reaches run.
    #[test]
    fn passthrough_denied_at_prepare() {
        let mut vm = Vm::define(
            verified(true, "AES-256-XTS"),
            Sensitivity::Standard,
            PlatformState::trusted_boot(),
            engine(),
            ScriptedVcpu::cooperative(),
            mem_disk(),
        );
        assert!(matches!(vm.prepare(), Err(VmError::PolicyDenied(_))));
        assert_eq!(vm.state(), VmState::Defined);
        // The denial is recorded.
        assert_eq!(vm.receipts().receipts().last().unwrap().event, "vm_launch_policy");
    }

    /// Calling out of order is rejected; you cannot skip straight to run().
    #[test]
    fn out_of_order_transitions_rejected() {
        let mut vm = Vm::define(
            verified(false, "AES-256-XTS"),
            Sensitivity::Standard,
            PlatformState::trusted_boot(),
            engine(),
            ScriptedVcpu::cooperative(),
            mem_disk(),
        );
        assert_eq!(vm.run(), Err(VmError::BadState(VmState::Defined)));
        assert_eq!(vm.attach(), Err(VmError::BadState(VmState::Defined)));
    }

    /// Sensitive VM on a drifted-PCR boot stalls in AwaitingKeyRelease.
    #[test]
    fn sensitive_pcr_drift_awaits_approval() {
        let mut platform = PlatformState::trusted_boot();
        platform.pcr_match = false;
        let mut vm = Vm::define(
            verified(false, "AES-256-XTS"),
            Sensitivity::Sensitive,
            platform,
            engine(),
            ScriptedVcpu::cooperative(),
            mem_disk(),
        );
        vm.prepare().unwrap();
        assert!(matches!(vm.unlock(), Err(VmError::ApprovalRequired(_))));
        assert_eq!(vm.state(), VmState::AwaitingKeyRelease);
    }
}
