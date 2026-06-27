use hyper_capsule::{UntrustedCapsuleManifest, VerifiedCapsuleManifest, VerificationRequest};
use hyper_policy::{PolicyDecision, VmLaunchPolicy, VmLaunchRequest};
use hyper_receipts::{Receipt, ReceiptChain, ReceiptDecision};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VmState {
    Defined,
    Verified,
    Prepared,
    AwaitingKeyRelease,
    Unlocked,
    Attached,
    Running,
    Paused,
    Stopped,
    Failed,
    Quarantined,
    Destroyed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VmError {
    CapsuleVerificationFailed,
    PolicyDenied,
    InvalidState,
    ReceiptChainRejected,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct DefinedVm {
    pub vm_id: String,
    pub capsule: UntrustedCapsuleManifest,
    pub receipts: ReceiptChain,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct VerifiedVm {
    pub vm_id: String,
    pub capsule: VerifiedCapsuleManifest,
    pub receipts: ReceiptChain,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct PreparedVm {
    pub vm_id: String,
    pub capsule: VerifiedCapsuleManifest,
    pub receipts: ReceiptChain,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct UnlockedVm {
    pub vm_id: String,
    pub capsule: VerifiedCapsuleManifest,
    pub receipts: ReceiptChain,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct AttachedVm {
    pub vm_id: String,
    pub capsule: VerifiedCapsuleManifest,
    pub receipts: ReceiptChain,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct RunningVm {
    pub vm_id: String,
    pub capsule: VerifiedCapsuleManifest,
    pub receipts: ReceiptChain,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct StoppedVm {
    pub vm_id: String,
    pub receipts: ReceiptChain,
}

pub fn define(capsule: UntrustedCapsuleManifest) -> DefinedVm {
    let vm_id = capsule.vm_id.clone();
    let mut receipts = ReceiptChain::new();
    let receipt = Receipt::unsigned(
        format!("vm-define:{vm_id}"),
        "vm_define",
        format!("vm:{vm_id}"),
        ReceiptDecision::Observe,
        None,
        capsule.image_hash.clone(),
        None,
    );
    let _ = receipts.push(receipt);
    DefinedVm { vm_id, capsule, receipts }
}

impl DefinedVm {
    pub fn verify(mut self, req: VerificationRequest) -> Result<VerifiedVm, VmError> {
        let verified = self.capsule.verify(req).map_err(|_| VmError::CapsuleVerificationFailed)?;
        if !self.receipts.push(verified.receipt().clone()) {
            return Err(VmError::ReceiptChainRejected);
        }
        Ok(VerifiedVm { vm_id: self.vm_id, capsule: verified, receipts: self.receipts })
    }
}

impl VerifiedVm {
    pub fn prepare(mut self) -> Result<PreparedVm, VmError> {
        let receipt = Receipt::unsigned(
            format!("vm-prepare:{}", self.vm_id),
            "vm_prepare",
            format!("vm:{}", self.vm_id),
            ReceiptDecision::Allow,
            None,
            self.capsule.receipt().receipt_hash.clone(),
            self.receipts.last_hash(),
        );
        if !self.receipts.push(receipt) {
            return Err(VmError::ReceiptChainRejected);
        }
        Ok(PreparedVm { vm_id: self.vm_id, capsule: self.capsule, receipts: self.receipts })
    }
}

impl PreparedVm {
    pub fn unlock(mut self) -> Result<UnlockedVm, VmError> {
        let receipt = Receipt::unsigned(
            format!("vm-unlock:{}", self.vm_id),
            "vm_key_release",
            format!("vm:{}", self.vm_id),
            ReceiptDecision::Allow,
            None,
            self.capsule.inner().storage.key_version.to_string(),
            self.receipts.last_hash(),
        );
        if !self.receipts.push(receipt) {
            return Err(VmError::ReceiptChainRejected);
        }
        Ok(UnlockedVm { vm_id: self.vm_id, capsule: self.capsule, receipts: self.receipts })
    }
}

impl UnlockedVm {
    pub fn attach(mut self) -> Result<AttachedVm, VmError> {
        let receipt = Receipt::unsigned(
            format!("vm-attach:{}", self.vm_id),
            "vm_attach",
            format!("vm:{}", self.vm_id),
            ReceiptDecision::Allow,
            None,
            self.capsule.inner().disk_hash.clone(),
            self.receipts.last_hash(),
        );
        if !self.receipts.push(receipt) {
            return Err(VmError::ReceiptChainRejected);
        }
        Ok(AttachedVm { vm_id: self.vm_id, capsule: self.capsule, receipts: self.receipts })
    }
}

impl AttachedVm {
    pub fn run(mut self, policy: &VmLaunchPolicy, hypervisor_version: u64) -> Result<RunningVm, VmError> {
        let req = VmLaunchRequest {
            vm_id: self.vm_id.clone(),
            manifest_verified: true,
            capsule_hash: self.capsule.receipt().inputs_hash.clone(),
            hypervisor_version,
            boot_measurements_present: false,
            requests_device_passthrough: !self.capsule.inner().devices.passthrough.is_empty(),
            requests_debug_console: false,
            previous_receipt_hash: self.receipts.last_hash(),
        };

        match policy.evaluate_vm_launch(&req) {
            PolicyDecision::Allow { receipt } => {
                if !self.receipts.push(receipt) {
                    return Err(VmError::ReceiptChainRejected);
                }
                Ok(RunningVm { vm_id: self.vm_id, capsule: self.capsule, receipts: self.receipts })
            }
            PolicyDecision::Deny { .. } | PolicyDecision::RequireApproval { .. } => Err(VmError::PolicyDenied),
        }
    }
}

impl RunningVm {
    pub fn stop(mut self) -> Result<StoppedVm, VmError> {
        let receipt = Receipt::unsigned(
            format!("vm-stop:{}", self.vm_id),
            "vm_stop",
            format!("vm:{}", self.vm_id),
            ReceiptDecision::Observe,
            None,
            self.capsule.receipt().receipt_hash.clone(),
            self.receipts.last_hash(),
        );
        if !self.receipts.push(receipt) {
            return Err(VmError::ReceiptChainRejected);
        }
        Ok(StoppedVm { vm_id: self.vm_id, receipts: self.receipts })
    }
}

impl StoppedVm {
    pub fn destroy(mut self) -> Result<ReceiptChain, VmError> {
        let receipt = Receipt::unsigned(
            format!("vm-destroy:{}", self.vm_id),
            "vm_destroy",
            format!("vm:{}", self.vm_id),
            ReceiptDecision::Observe,
            None,
            "destroyed",
            self.receipts.last_hash(),
        );
        if !self.receipts.push(receipt) {
            return Err(VmError::ReceiptChainRejected);
        }
        Ok(self.receipts)
    }
}
