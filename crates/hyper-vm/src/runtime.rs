//! Typed lifecycle state machine and the [`SlateRuntime`] that drives it.

use hyper_attest::{KeyReleaseDecision, KeyReleaseRequest, KmsSimulator, SecretHandle};
use hyper_capsule::{check_launch, LaunchApproval, LaunchContext, SignatureStatus, VerifiedManifest};
use hyper_devices::{DeviceId, TestDevice, VirtualDeviceGraph};
use hyper_mm::{
    GuestMemoryMap, GuestMemoryRegion, GuestPhysAddr, HostPhysAddr, HostPhysRange, InMemoryNpt,
    MemoryQuotaManager, NestedPageTable, Perms, RegionKind, VmId,
};
use hyper_policy::{
    DefaultPolicyEngine, DeviceAssignRequest, PolicyDecision, PolicyDocument, PolicyEngine,
    VmLaunchRequest,
};
use hyper_receipts::{ReceiptChain, ReceiptEvent};
use hyper_vcpu::{SchedClass, Scheduler, Vcpu, VcpuId, VcpuIdAllocator, VcpuState};

use crate::error::VmError;
use crate::spec::VmCapsule;
use crate::{derive_npt_root, sha384_hex, VmState};

// ---------------------------------------------------------------------------
// Internal carried resources
// ---------------------------------------------------------------------------

/// Heavy runtime resources allocated at `prepare` and carried through to
/// `destroy`. Not part of the public surface; moved between the typed states.
struct VmResources {
    npt: NestedPageTable<InMemoryNpt>,
    quota: MemoryQuotaManager,
    memory: GuestMemoryMap,
    host_ranges: Vec<HostPhysRange>,
    mapping_ids: Vec<u64>,
    npt_root: u64,
    reserved_mb: u64,
}

impl std::fmt::Debug for VmResources {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmResources")
            .field("npt_root", &self.npt_root)
            .field("reserved_mb", &self.reserved_mb)
            .field("regions", &self.memory.regions.len())
            .field("mappings", &self.mapping_ids.len())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Typed state structs — the TYPE encodes the lifecycle state.
// ---------------------------------------------------------------------------

/// A capsule that has been admitted to the runtime (`Defined`). It has been
/// recorded but nothing about it has been validated yet.
#[derive(Debug)]
pub struct VmHandle {
    capsule: VmCapsule,
    vm_id: VmId,
}

impl VmHandle {
    /// The lifecycle state encoded by this type.
    pub fn state(&self) -> VmState {
        VmState::Defined
    }
    /// The VM id assigned at definition.
    pub fn vm_id(&self) -> &VmId {
        &self.vm_id
    }
    /// The underlying capsule.
    pub fn capsule(&self) -> &VmCapsule {
        &self.capsule
    }
}

/// A capsule whose manifest passed verification and the launch gate
/// (`Verified`).
#[derive(Debug)]
pub struct VerifiedVm {
    capsule: VmCapsule,
    vm_id: VmId,
    approval: LaunchApproval,
}

impl VerifiedVm {
    /// The lifecycle state encoded by this type.
    pub fn state(&self) -> VmState {
        VmState::Verified
    }
    /// The VM id.
    pub fn vm_id(&self) -> &VmId {
        &self.vm_id
    }
    /// The launch approval minted by the gate.
    pub fn approval(&self) -> &LaunchApproval {
        &self.approval
    }
}

/// A VM whose guest memory has been allocated under the S2 invariants
/// (`Prepared`).
#[derive(Debug)]
pub struct PreparedVm {
    capsule: VmCapsule,
    vm_id: VmId,
    resources: VmResources,
}

impl PreparedVm {
    /// The lifecycle state encoded by this type.
    pub fn state(&self) -> VmState {
        VmState::Prepared
    }
    /// The VM id.
    pub fn vm_id(&self) -> &VmId {
        &self.vm_id
    }
    /// The assigned guest memory map.
    pub fn memory(&self) -> &GuestMemoryMap {
        &self.resources.memory
    }
}

/// A VM whose volume key has been released by the attested KMS (`Unlocked`).
#[derive(Debug)]
pub struct UnlockedVm {
    capsule: VmCapsule,
    vm_id: VmId,
    resources: VmResources,
    wrapped_vmk: SecretHandle,
}

impl UnlockedVm {
    /// The lifecycle state encoded by this type.
    pub fn state(&self) -> VmState {
        VmState::Unlocked
    }
    /// The VM id.
    pub fn vm_id(&self) -> &VmId {
        &self.vm_id
    }
    /// Length of the released (wrapped) volume master key, in bytes.
    pub fn wrapped_vmk_len(&self) -> usize {
        self.wrapped_vmk.len()
    }
}

/// A VM with devices and vCPUs attached (`Attached`).
pub struct AttachedVm {
    capsule: VmCapsule,
    vm_id: VmId,
    resources: VmResources,
    wrapped_vmk: SecretHandle,
    devices: VirtualDeviceGraph,
    vcpus: Vec<Vcpu>,
}

impl std::fmt::Debug for AttachedVm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachedVm")
            .field("vm_id", &self.vm_id)
            .field("vcpus", &self.vcpus.len())
            .field("devices", &self.devices.device_count())
            .finish()
    }
}

impl AttachedVm {
    /// The lifecycle state encoded by this type.
    pub fn state(&self) -> VmState {
        VmState::Attached
    }
    /// The VM id.
    pub fn vm_id(&self) -> &VmId {
        &self.vm_id
    }
    /// Number of attached vCPUs.
    pub fn vcpu_count(&self) -> usize {
        self.vcpus.len()
    }
    /// Number of attached virtual devices.
    pub fn device_count(&self) -> usize {
        self.devices.device_count()
    }
}

/// The assembled, runnable VM resource bundle (S-level "RunnableVm").
pub struct RunnableVm {
    /// VM id.
    pub vm_id: VmId,
    /// The verified boot manifest backing this VM.
    pub verified_manifest: VerifiedManifest,
    /// The guest memory map.
    pub assigned_memory: GuestMemoryMap,
    /// The guest's vCPUs.
    pub vcpus: Vec<Vcpu>,
    /// The nested-page-table root label.
    pub npt_root: u64,
    /// The virtual device graph.
    pub devices: VirtualDeviceGraph,
    /// The virtual NIC specs in effect.
    pub network: Vec<crate::spec::VirtualNicSpec>,
    /// A snapshot of the audit receipt chain at assembly time.
    pub receipts: ReceiptChain,
}

/// A running guest (`Running`).
pub struct RunningVm {
    vm_id: VmId,
    resources: VmResources,
    wrapped_vmk: SecretHandle,
    scheduler: Scheduler,
    runnable: RunnableVm,
}

impl RunningVm {
    /// The lifecycle state encoded by this type.
    pub fn state(&self) -> VmState {
        VmState::Running
    }
    /// The VM id.
    pub fn vm_id(&self) -> &VmId {
        &self.vm_id
    }
    /// The assembled runnable resource bundle.
    pub fn runnable(&self) -> &RunnableVm {
        &self.runnable
    }
    /// The next vCPU the scheduler would pick, if any.
    pub fn peek_next_runnable(&mut self) -> Option<VcpuId> {
        self.scheduler.next_runnable()
    }
}

/// A paused guest (`Paused`).
pub struct PausedVm {
    vm_id: VmId,
    #[allow(dead_code)]
    resources: VmResources,
    #[allow(dead_code)]
    wrapped_vmk: SecretHandle,
    runnable: RunnableVm,
}

impl PausedVm {
    /// The lifecycle state encoded by this type.
    pub fn state(&self) -> VmState {
        VmState::Paused
    }
    /// The VM id.
    pub fn vm_id(&self) -> &VmId {
        &self.vm_id
    }
    /// The assembled runnable resource bundle.
    pub fn runnable(&self) -> &RunnableVm {
        &self.runnable
    }
}

/// A stopped guest (`Stopped`). Still owns its resources so that `destroy` can
/// zeroize them.
pub struct StoppedVm {
    vm_id: VmId,
    resources: VmResources,
    wrapped_vmk: SecretHandle,
}

impl StoppedVm {
    /// The lifecycle state encoded by this type.
    pub fn state(&self) -> VmState {
        VmState::Stopped
    }
    /// The VM id.
    pub fn vm_id(&self) -> &VmId {
        &self.vm_id
    }
}

// ---------------------------------------------------------------------------
// Terminal receipts
// ---------------------------------------------------------------------------

/// Proof token returned by [`VmLifecycle::snapshot`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotReceipt {
    /// VM the snapshot was taken of.
    pub vm_id: String,
    /// Id of the appended `snapshot` receipt.
    pub receipt_id: String,
    /// Chain head hash after the snapshot was recorded.
    pub chain_head: String,
}

/// Proof token returned by [`VmLifecycle::destroy`]. Its existence attests that
/// the guest's memory and key material were zeroized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestroyReceipt {
    /// VM that was destroyed.
    pub vm_id: String,
    /// Id of the appended `destroy` receipt.
    pub receipt_id: String,
    /// Chain head hash after the destroy was recorded.
    pub chain_head: String,
    /// Number of host page ranges scrubbed.
    pub zeroized_ranges: usize,
}

// ---------------------------------------------------------------------------
// The lifecycle trait
// ---------------------------------------------------------------------------

/// The one and only path from a [`VmCapsule`] to a running guest. Every method
/// is fail-closed and appends an audit receipt.
pub trait VmLifecycle {
    /// Admit a capsule: `-> Defined`.
    fn define(&mut self, capsule: VmCapsule) -> Result<VmHandle, VmError>;
    /// Verify the manifest + run the launch gate: `Defined -> Verified`.
    fn verify(&mut self, handle: VmHandle) -> Result<VerifiedVm, VmError>;
    /// Allocate guest memory under the S2 invariants: `Verified -> Prepared`.
    fn prepare(&mut self, vm: VerifiedVm) -> Result<PreparedVm, VmError>;
    /// Release the volume key via the attested KMS: `Prepared -> Unlocked`.
    fn unlock(&mut self, vm: PreparedVm) -> Result<UnlockedVm, VmError>;
    /// Attach devices + vCPUs: `Unlocked -> Attached`.
    fn attach(&mut self, vm: UnlockedVm) -> Result<AttachedVm, VmError>;
    /// Start the guest: `Attached -> Running`.
    fn run(&mut self, vm: AttachedVm) -> Result<RunningVm, VmError>;
    /// Pause a running guest: `Running -> Paused`.
    fn pause(&mut self, vm: RunningVm) -> Result<PausedVm, VmError>;
    /// Snapshot a paused guest.
    fn snapshot(&mut self, vm: PausedVm) -> Result<SnapshotReceipt, VmError>;
    /// Stop a running guest: `Running -> Stopped`.
    fn stop(&mut self, vm: RunningVm) -> Result<StoppedVm, VmError>;
    /// Zeroize and release a stopped guest's resources.
    fn destroy(&mut self, vm: StoppedVm) -> Result<DestroyReceipt, VmError>;
}

// ---------------------------------------------------------------------------
// SlateRuntime
// ---------------------------------------------------------------------------

/// Base host-physical address for guest RAM allocations. Chosen well clear of
/// the reserved hypervisor range so allocations never overlap it.
const GUEST_HPA_BASE: u64 = 0x1_0000_0000; // 4 GiB
/// Reserved host/hypervisor range (kept far above guest allocations).
const RESERVED_HPA_BASE: u64 = 0xF000_0000_0000;
const RESERVED_HPA_LEN: u64 = 0x10_0000; // 1 MiB
const MIB: u64 = 1024 * 1024;

/// The slate runtime: wires the policy engine, capsule launch gate, memory
/// manager, vCPU scheduler, attested KMS and the audit receipt spine into a
/// single fail-closed lifecycle driver.
pub struct SlateRuntime {
    policy: DefaultPolicyEngine,
    kms: KmsSimulator,
    hypervisor_version: u64,
    receipts: ReceiptChain,
}

impl SlateRuntime {
    /// Build a runtime from an org policy document, an attested KMS simulator
    /// and the running hypervisor version.
    pub fn new(policy_doc: PolicyDocument, kms: KmsSimulator, hypervisor_version: u64) -> Self {
        SlateRuntime {
            policy: DefaultPolicyEngine::new(policy_doc),
            kms,
            hypervisor_version,
            receipts: ReceiptChain::new(),
        }
    }

    /// The audit receipt chain. The integration gate asserts `verify() == Ok`.
    pub fn receipts(&self) -> &ReceiptChain {
        &self.receipts
    }

    /// Hypervisor version this runtime reports to gates.
    pub fn hypervisor_version(&self) -> u64 {
        self.hypervisor_version
    }

    /// The policy id stamped onto policy-driven receipts.
    fn policy_id(&self) -> String {
        self.policy.doc.policy_id.clone()
    }
}

impl VmLifecycle for SlateRuntime {
    fn define(&mut self, capsule: VmCapsule) -> Result<VmHandle, VmError> {
        // The VM id is taken from the verified manifest, binding the lifecycle
        // identity to the signed manifest rather than to caller-supplied data.
        let vm_id = VmId::new(capsule.manifest.inner().vm_id.clone());
        let inputs = sha384_hex(
            format!(
                "define|{}|{}",
                capsule.capsule_id,
                capsule.manifest.inner().image_hash
            )
            .as_bytes(),
        );
        self.receipts.append(
            ReceiptEvent::VmDefine,
            vm_id.as_str(),
            "allow",
            self.policy_id(),
            inputs,
        );
        Ok(VmHandle { capsule, vm_id })
    }

    fn verify(&mut self, handle: VmHandle) -> Result<VerifiedVm, VmError> {
        let VmHandle { capsule, vm_id } = handle;
        let m = capsule.manifest.inner();

        // 1) Deny-by-default policy-engine launch evaluation.
        let launch_req = VmLaunchRequest {
            hypervisor_version: self.hypervisor_version,
            manifest_signed: capsule.manifest.signature_status() == SignatureStatus::Valid,
            measured_boot: capsule.policy.measured_boot,
            requests_debug_console: capsule.policy.requests_debug_console,
        };
        match self.policy.evaluate_vm_launch(&launch_req) {
            PolicyDecision::Allow { .. } => {}
            PolicyDecision::Deny { reason } => {
                let inputs = sha384_hex(format!("verify_deny|{}", vm_id.as_str()).as_bytes());
                self.receipts.append(
                    ReceiptEvent::ManifestVerify,
                    vm_id.as_str(),
                    "deny",
                    self.policy_id(),
                    inputs,
                );
                return Err(VmError::PolicyDenied(format!("{reason:?}")));
            }
            PolicyDecision::RequireApproval { challenge } => {
                let inputs = sha384_hex(format!("verify_approval|{}", vm_id.as_str()).as_bytes());
                self.receipts.append(
                    ReceiptEvent::ManifestVerify,
                    vm_id.as_str(),
                    "require_approval",
                    self.policy_id(),
                    inputs,
                );
                return Err(VmError::PolicyDenied(format!(
                    "out-of-band approval required: {challenge}"
                )));
            }
        }

        // 2) The capsule launch gate (S9). Because the input is a
        //    VerifiedManifest, an unsigned manifest can never reach here.
        let ctx = LaunchContext {
            hypervisor_version: self.hypervisor_version,
            tenant_min_boot_policy: capsule.policy.tenant_min_boot_policy,
            expected_image_hash: m.image_hash.clone(),
            key_unwrap_authorized: capsule.policy.key_unwrap_authorized,
            device_policy_ok: capsule.policy.device_policy_ok,
            memory_budget_mb: capsule.policy.memory_budget_mb,
            debug_override: false,
        };
        let approval = check_launch(&capsule.manifest, &ctx)?;

        let inputs = sha384_hex(format!("verify|{}|{}", vm_id.as_str(), m.image_hash).as_bytes());
        self.receipts.append(
            ReceiptEvent::ManifestVerify,
            vm_id.as_str(),
            "allow",
            self.policy_id(),
            inputs,
        );

        Ok(VerifiedVm {
            capsule,
            vm_id,
            approval,
        })
    }

    fn prepare(&mut self, vm: VerifiedVm) -> Result<PreparedVm, VmError> {
        let VerifiedVm {
            capsule, vm_id, ..
        } = vm;

        let want_mb = capsule.memory.max_mb;
        let mut quota = MemoryQuotaManager::new(capsule.policy.memory_budget_mb);
        quota.try_reserve(want_mb)?;

        let reserved = HostPhysRange {
            start: HostPhysAddr(RESERVED_HPA_BASE),
            len: RESERVED_HPA_LEN,
        };
        let mut npt =
            NestedPageTable::with_reserved_host_range(InMemoryNpt::new(), reserved);

        let len = want_mb.saturating_mul(MIB).max(hyper_mm::PAGE_SIZE);
        let gpa = GuestPhysAddr(0);
        let hpa = HostPhysAddr(GUEST_HPA_BASE);
        // Guest RAM is RW (never W+X); allocate() zeroes the backing pages.
        let record = npt.allocate(vm_id.clone(), gpa, hpa, len, Perms::RW)?;

        let npt_root = derive_npt_root(vm_id.as_str());
        let mut memory = GuestMemoryMap::new(vm_id.clone(), npt_root);
        memory.add_region(
            GuestMemoryRegion {
                gpa_start: gpa,
                len,
                kind: RegionKind::GuestRam,
                perms: Perms::RW,
            },
            "guest-ram",
        );

        let resources = VmResources {
            npt,
            quota,
            memory,
            host_ranges: vec![record.host_physical_range],
            mapping_ids: vec![record.npt_mapping_id],
            npt_root,
            reserved_mb: want_mb,
        };

        let inputs =
            sha384_hex(format!("prepare|{}|{}mb", vm_id.as_str(), want_mb).as_bytes());
        self.receipts.append(
            "vm_prepare",
            vm_id.as_str(),
            "allow",
            self.policy_id(),
            inputs,
        );

        Ok(PreparedVm {
            capsule,
            vm_id,
            resources,
        })
    }

    fn unlock(&mut self, vm: PreparedVm) -> Result<UnlockedVm, VmError> {
        let PreparedVm {
            capsule,
            vm_id,
            resources,
        } = vm;

        let plan = &capsule.key_plan;
        let req = KeyReleaseRequest {
            request_type: "key_release".to_string(),
            device_id: plan.device_id.clone(),
            vm_id: vm_id.as_str().to_string(),
            capsule_hash: plan.capsule_hash.clone(),
            boot_policy_hash: plan.boot_policy_hash.clone(),
            pcrs: plan.pcrs.clone(),
            hypervisor_version: self.hypervisor_version,
            nonce: plan.nonce.clone(),
        };

        // KmsSimulator::evaluate appends the `key_release` receipt itself
        // (allow OR deny) onto our shared chain — the deny path stays audited.
        match self.kms.evaluate(&req, &mut self.receipts) {
            KeyReleaseDecision::Allow { wrapped_vmk, .. } => Ok(UnlockedVm {
                capsule,
                vm_id,
                resources,
                wrapped_vmk,
            }),
            KeyReleaseDecision::Deny { reason } => Err(VmError::KeyReleaseDenied(reason)),
        }
    }

    fn attach(&mut self, vm: UnlockedVm) -> Result<AttachedVm, VmError> {
        let UnlockedVm {
            capsule,
            vm_id,
            resources,
            wrapped_vmk,
        } = vm;

        // Passthrough assignments must pass the deny-by-default device policy.
        for dev in &capsule.devices.passthrough {
            let req = DeviceAssignRequest {
                passthrough: true,
                device: dev.clone(),
            };
            match self.policy.evaluate_device_assignment(&req) {
                PolicyDecision::Allow { .. } => {}
                PolicyDecision::Deny { reason } => {
                    let inputs =
                        sha384_hex(format!("attach_deny|{}|{}", vm_id.as_str(), dev).as_bytes());
                    self.receipts.append(
                        ReceiptEvent::DeviceAssign,
                        vm_id.as_str(),
                        "deny",
                        self.policy_id(),
                        inputs,
                    );
                    return Err(VmError::PolicyDenied(format!(
                        "device passthrough denied for {dev}: {reason:?}"
                    )));
                }
                PolicyDecision::RequireApproval { challenge } => {
                    return Err(VmError::PolicyDenied(format!(
                        "device assignment needs approval: {challenge}"
                    )));
                }
            }
        }

        // Build the virtual device graph: one paravirtual device per disk + NIC.
        let mut devices = VirtualDeviceGraph::new(vm_id.clone());
        let dev_count = capsule.storage.len() + capsule.network.len();
        for i in 0..dev_count {
            let id = DeviceId(i as u32);
            let base = 0x1000u64 + (i as u64) * 0x1000;
            let len = TestDevice::REG_COUNT * 8;
            devices.register(
                Box::new(TestDevice::new(id)),
                Some((base, len)),
                None,
                Some(i as u8),
            )?;
        }

        // Create the vCPUs (deterministic ids from a monotonic allocator).
        let mut alloc = VcpuIdAllocator::new();
        let mut vcpus = Vec::with_capacity(capsule.cpu.vcpus as usize);
        for _ in 0..capsule.cpu.vcpus {
            vcpus.push(Vcpu::new(alloc.alloc(), vm_id.clone()));
        }

        let inputs = sha384_hex(
            format!("attach|{}|{}dev|{}vcpu", vm_id.as_str(), dev_count, vcpus.len()).as_bytes(),
        );
        self.receipts.append(
            ReceiptEvent::DeviceAssign,
            vm_id.as_str(),
            "allow",
            self.policy_id(),
            inputs,
        );

        Ok(AttachedVm {
            capsule,
            vm_id,
            resources,
            wrapped_vmk,
            devices,
            vcpus,
        })
    }

    fn run(&mut self, vm: AttachedVm) -> Result<RunningVm, VmError> {
        let AttachedVm {
            capsule,
            vm_id,
            resources,
            wrapped_vmk,
            devices,
            mut vcpus,
        } = vm;

        // Schedule all vCPUs and mark them running.
        let mut scheduler = Scheduler::new();
        for v in &mut vcpus {
            scheduler.enqueue(v.id, SchedClass::NormalGuest);
            v.state = VcpuState::Running;
        }

        let inputs = sha384_hex(
            format!("run|{}|{}", vm_id.as_str(), capsule.manifest.inner().image_hash).as_bytes(),
        );
        self.receipts.append(
            ReceiptEvent::VmLaunch,
            vm_id.as_str(),
            "allow",
            self.policy_id(),
            inputs,
        );

        let runnable = RunnableVm {
            vm_id: vm_id.clone(),
            verified_manifest: capsule.manifest.clone(),
            assigned_memory: resources.memory.clone(),
            vcpus,
            npt_root: resources.npt_root,
            devices,
            network: capsule.network.clone(),
            receipts: self.receipts.clone(),
        };

        Ok(RunningVm {
            vm_id,
            resources,
            wrapped_vmk,
            scheduler,
            runnable,
        })
    }

    fn pause(&mut self, vm: RunningVm) -> Result<PausedVm, VmError> {
        let RunningVm {
            vm_id,
            resources,
            wrapped_vmk,
            mut runnable,
            ..
        } = vm;
        for v in &mut runnable.vcpus {
            v.state = VcpuState::Blocked;
        }
        let inputs = sha384_hex(format!("pause|{}", vm_id.as_str()).as_bytes());
        self.receipts.append(
            "vm_pause",
            vm_id.as_str(),
            "allow",
            self.policy_id(),
            inputs,
        );
        Ok(PausedVm {
            vm_id,
            resources,
            wrapped_vmk,
            runnable,
        })
    }

    fn snapshot(&mut self, vm: PausedVm) -> Result<SnapshotReceipt, VmError> {
        let inputs = sha384_hex(format!("snapshot|{}", vm.vm_id.as_str()).as_bytes());
        let receipt = self.receipts.append(
            ReceiptEvent::Snapshot,
            vm.vm_id.as_str(),
            "allow",
            self.policy_id(),
            inputs,
        );
        Ok(SnapshotReceipt {
            vm_id: vm.vm_id.as_str().to_string(),
            receipt_id: receipt.receipt_id.clone(),
            chain_head: self.receipts.head_hash().to_string(),
        })
    }

    fn stop(&mut self, vm: RunningVm) -> Result<StoppedVm, VmError> {
        let RunningVm {
            vm_id,
            resources,
            wrapped_vmk,
            mut runnable,
            ..
        } = vm;
        for v in &mut runnable.vcpus {
            v.state = VcpuState::Halted;
        }
        let inputs = sha384_hex(format!("stop|{}", vm_id.as_str()).as_bytes());
        self.receipts.append(
            "vm_stop",
            vm_id.as_str(),
            "allow",
            self.policy_id(),
            inputs,
        );
        // `runnable` (devices, vcpu snapshot) is dropped here; the resources and
        // the wrapped key are retained so `destroy` can zeroize them.
        Ok(StoppedVm {
            vm_id,
            resources,
            wrapped_vmk,
        })
    }

    fn destroy(&mut self, vm: StoppedVm) -> Result<DestroyReceipt, VmError> {
        let StoppedVm {
            vm_id,
            mut resources,
            mut wrapped_vmk,
        } = vm;

        // Tear down mappings (this poisons the freed frames) ...
        for id in &resources.mapping_ids {
            // Best-effort: a missing mapping is already gone.
            let _ = <NestedPageTable<InMemoryNpt> as hyper_mm::Npt>::unmap(&mut resources.npt, *id);
        }
        // ... then scrub the backing host pages to zero (zeroize-on-destroy).
        let zeroized = resources.host_ranges.len();
        for r in &resources.host_ranges {
            resources.npt.zeroizer_mut().mark_zeroed(r.start, r.len);
        }
        // Return the reserved quota and zeroize the released key material.
        resources.quota.release(resources.reserved_mb);
        wrapped_vmk.zeroize();

        let inputs = sha384_hex(format!("destroy|{}", vm_id.as_str()).as_bytes());
        let receipt = self.receipts.append(
            ReceiptEvent::Destroy,
            vm_id.as_str(),
            "allow",
            self.policy_id(),
            inputs,
        );
        Ok(DestroyReceipt {
            vm_id: vm_id.as_str().to_string(),
            receipt_id: receipt.receipt_id.clone(),
            chain_head: self.receipts.head_hash().to_string(),
            zeroized_ranges: zeroized,
        })
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use hyper_attest::{KmsPolicy, PcrBank, PCR0, PCR11, PCR7};
    use hyper_capsule::{parse_manifest, verify, AllowlistVerifier};
    use hyper_policy::PolicyDocument;

    use crate::spec::{
        BootSpec, CpuSpec, DeviceAssignmentSpec, KeyReleasePlan, MemorySpec, VirtualDiskSpec,
        VirtualNicSpec, VmCapsule, VmPolicy,
    };

    const CAPSULE_HASH: &str = "sha384:capsule-good";
    const BOOT_POLICY_HASH: &str = "sha384:bootpol-good";

    fn manifest_json(signed: bool) -> String {
        let sigs = if signed {
            r#"[{ "alg": "ecdsa-p384", "key_id": "key-good", "status": null }]"#
        } else {
            "[]"
        };
        format!(
            r#"{{
                "schema": "chain.vm_capsule.v1",
                "vm_id": "vm-keystone-1",
                "tenant_id": "tenant-a",
                "image_hash": "sha384:image-aa",
                "disk_hash": "sha384:disk-bb",
                "hypervisor_min_version": 10,
                "boot_policy_version": 5,
                "devices": {{ "passthrough": [], "virtio": ["net0", "blk0"] }},
                "memory": {{ "max_mb": 256, "allow_balloon": false }},
                "cpu": {{ "vcpus": 2, "cpuid_profile": "milan-v1" }},
                "network": {{ "mode": "isolated", "egress_policy": "deny-all" }},
                "storage": {{ "cipher": "aes-256-xts", "integrity": "dm-integrity", "key_version": 3 }},
                "signatures": {sigs}
            }}"#
        )
    }

    fn verified_manifest(signed: bool) -> Result<VerifiedManifest, hyper_capsule::CapsuleError> {
        let m = parse_manifest(&manifest_json(signed)).unwrap();
        let v = AllowlistVerifier::new(["key-good"]);
        verify(m, &v, 12, 5)
    }

    fn pcrs() -> PcrBank {
        let mut p = PcrBank::new();
        p.set(PCR0, "sha384:p0")
            .set(PCR7, "sha384:p7")
            .set(PCR11, "sha384:p11");
        p
    }

    fn policy_doc() -> PolicyDocument {
        let j = r#"{
            "schema_version": 1,
            "policy_id": "pol-keystone",
            "minimum_hypervisor_version": 10,
            "require_signed_manifest": true,
            "require_measured_boot": true,
            "allow_device_passthrough": false,
            "allow_debug_console": false,
            "network_default": "deny",
            "storage": { "require_encryption": true, "allow_read_write_base_image": false },
            "key_release": { "mode": "remote_attested_kms", "require_pcr_match_for_sensitive_vms": true }
        }"#;
        PolicyDocument::parse(j).unwrap()
    }

    fn kms() -> KmsSimulator {
        KmsSimulator::new(KmsPolicy {
            expected_pcrs: pcrs(),
            min_hypervisor_version: 10,
            allowed_capsule_hashes: vec![CAPSULE_HASH.to_string()],
            expected_boot_policy_hash: BOOT_POLICY_HASH.to_string(),
        })
    }

    fn runtime() -> SlateRuntime {
        SlateRuntime::new(policy_doc(), kms(), 12)
    }

    fn capsule(manifest: VerifiedManifest) -> VmCapsule {
        VmCapsule {
            capsule_id: "cap-1".to_string(),
            manifest,
            boot: BootSpec {
                firmware: "uefi-ovmf-v1".to_string(),
                cmdline: "console=ttyS0".to_string(),
                boot_policy_version: 5,
            },
            cpu: CpuSpec { vcpus: 2 },
            memory: MemorySpec { max_mb: 256 },
            storage: vec![VirtualDiskSpec {
                disk_id: "blk0".to_string(),
                size_mb: 1024,
                read_only: false,
            }],
            network: vec![VirtualNicSpec {
                nic_id: "net0".to_string(),
                mode: "isolated".to_string(),
            }],
            devices: DeviceAssignmentSpec::default(),
            policy: VmPolicy {
                tenant_min_boot_policy: 5,
                memory_budget_mb: 4096,
                key_unwrap_authorized: true,
                device_policy_ok: true,
                measured_boot: true,
                requests_debug_console: false,
            },
            key_plan: KeyReleasePlan {
                device_id: "dev-blk0".to_string(),
                capsule_hash: CAPSULE_HASH.to_string(),
                boot_policy_hash: BOOT_POLICY_HASH.to_string(),
                pcrs: pcrs(),
                nonce: "nonce-0001".to_string(),
            },
        }
    }

    fn drive_to_running(rt: &mut SlateRuntime, cap: VmCapsule) -> RunningVm {
        let h = rt.define(cap).unwrap();
        let v = rt.verify(h).unwrap();
        let p = rt.prepare(v).unwrap();
        let u = rt.unlock(p).unwrap();
        let a = rt.attach(u).unwrap();
        rt.run(a).unwrap()
    }

    #[test]
    fn full_happy_lifecycle_to_running() {
        let mut rt = runtime();
        let cap = capsule(verified_manifest(true).unwrap());
        let running = drive_to_running(&mut rt, cap);
        assert_eq!(running.state(), VmState::Running);
        assert_eq!(running.runnable().vcpus.len(), 2);
        // disks(1) + nics(1) = 2 paravirtual devices.
        assert_eq!(running.runnable().devices.device_count(), 2);
        assert_eq!(rt.receipts().verify(), Ok(()));
    }

    #[test]
    fn typed_states_report_their_state() {
        let mut rt = runtime();
        let cap = capsule(verified_manifest(true).unwrap());
        let h = rt.define(cap).unwrap();
        assert_eq!(h.state(), VmState::Defined);
        let v = rt.verify(h).unwrap();
        assert_eq!(v.state(), VmState::Verified);
        let p = rt.prepare(v).unwrap();
        assert_eq!(p.state(), VmState::Prepared);
        assert!(p.memory().regions.iter().any(|r| r.kind == RegionKind::GuestRam));
        let u = rt.unlock(p).unwrap();
        assert_eq!(u.state(), VmState::Unlocked);
        assert_eq!(u.wrapped_vmk_len(), 48);
        let a = rt.attach(u).unwrap();
        assert_eq!(a.state(), VmState::Attached);
        assert_eq!(a.vcpu_count(), 2);
    }

    #[test]
    fn receipt_appended_per_transition() {
        let mut rt = runtime();
        let cap = capsule(verified_manifest(true).unwrap());
        let h = rt.define(cap).unwrap();
        assert_eq!(rt.receipts().len(), 1);
        let v = rt.verify(h).unwrap();
        assert_eq!(rt.receipts().len(), 2);
        let p = rt.prepare(v).unwrap();
        assert_eq!(rt.receipts().len(), 3);
        let u = rt.unlock(p).unwrap(); // KMS appends key_release
        assert_eq!(rt.receipts().len(), 4);
        let a = rt.attach(u).unwrap();
        assert_eq!(rt.receipts().len(), 5);
        let r = rt.run(a).unwrap();
        assert_eq!(rt.receipts().len(), 6);
        let s = rt.stop(r).unwrap();
        assert_eq!(rt.receipts().len(), 7);
        let _ = rt.destroy(s).unwrap();
        assert_eq!(rt.receipts().len(), 8);
        assert_eq!(rt.receipts().verify(), Ok(()));
    }

    #[test]
    fn receipt_events_are_in_order() {
        let mut rt = runtime();
        let cap = capsule(verified_manifest(true).unwrap());
        let r = drive_to_running(&mut rt, cap);
        let _ = rt.stop(r).unwrap();
        let events: Vec<&str> = rt.receipts().receipts().iter().map(|r| r.event.as_str()).collect();
        assert_eq!(
            events,
            vec![
                "vm_define",
                "manifest_verify",
                "vm_prepare",
                "key_release",
                "device_assign",
                "vm_launch",
                "vm_stop",
            ]
        );
    }

    #[test]
    fn pause_then_snapshot() {
        let mut rt = runtime();
        let cap = capsule(verified_manifest(true).unwrap());
        let r = drive_to_running(&mut rt, cap);
        let p = rt.pause(r).unwrap();
        assert_eq!(p.state(), VmState::Paused);
        assert!(p.runnable().vcpus.iter().all(|v| v.state == VcpuState::Blocked));
        let snap = rt.snapshot(p).unwrap();
        assert_eq!(snap.vm_id, "vm-keystone-1");
        assert_eq!(snap.chain_head, rt.receipts().head_hash());
        assert_eq!(rt.receipts().verify(), Ok(()));
    }

    #[test]
    fn destroy_zeroizes_and_records() {
        let mut rt = runtime();
        let cap = capsule(verified_manifest(true).unwrap());
        let r = drive_to_running(&mut rt, cap);
        let s = rt.stop(r).unwrap();
        let d = rt.destroy(s).unwrap();
        assert_eq!(d.zeroized_ranges, 1);
        assert_eq!(d.chain_head, rt.receipts().head_hash());
        assert_eq!(rt.receipts().verify(), Ok(()));
    }

    // ---- Fail-closed paths ----------------------------------------------

    #[test]
    fn unsigned_manifest_cannot_be_verified_so_no_capsule() {
        // The ONLY constructor for VerifiedManifest is hyper_capsule::verify; an
        // unsigned manifest fails it, so a VmCapsule can never be built and the
        // lifecycle can never begin. "Unsigned capsule cannot run."
        assert!(verified_manifest(false).is_err());
    }

    #[test]
    fn verify_denies_when_measured_boot_missing() {
        let mut rt = runtime();
        let mut cap = capsule(verified_manifest(true).unwrap());
        cap.policy.measured_boot = false; // policy requires measured boot
        let h = rt.define(cap).unwrap();
        let err = rt.verify(h).unwrap_err();
        assert!(matches!(err, VmError::PolicyDenied(_)));
        // The deny is still audited and the chain stays valid.
        assert_eq!(rt.receipts().verify(), Ok(()));
        assert_eq!(rt.receipts().receipts().last().unwrap().decision, "deny");
    }

    #[test]
    fn verify_denies_when_key_unwrap_unauthorized() {
        let mut rt = runtime();
        let mut cap = capsule(verified_manifest(true).unwrap());
        cap.policy.key_unwrap_authorized = false; // launch gate denies
        let h = rt.define(cap).unwrap();
        let err = rt.verify(h).unwrap_err();
        assert!(matches!(err, VmError::LaunchGate(_)));
    }

    #[test]
    fn verify_denies_on_memory_over_budget() {
        let mut rt = runtime();
        let mut cap = capsule(verified_manifest(true).unwrap());
        cap.policy.memory_budget_mb = 64; // manifest wants 256
        let h = rt.define(cap).unwrap();
        let err = rt.verify(h).unwrap_err();
        assert!(matches!(err, VmError::LaunchGate(_)));
    }

    #[test]
    fn unlock_denies_on_modified_boot_policy() {
        let mut rt = runtime();
        let mut cap = capsule(verified_manifest(true).unwrap());
        cap.key_plan.boot_policy_hash = "sha384:bootpol-EVIL".to_string();
        let h = rt.define(cap).unwrap();
        let v = rt.verify(h).unwrap();
        let p = rt.prepare(v).unwrap();
        let err = rt.unlock(p).unwrap_err();
        match err {
            VmError::KeyReleaseDenied(reason) => {
                assert!(reason.starts_with("boot_policy_hash_mismatch"))
            }
            other => panic!("expected key release deny, got {other:?}"),
        }
        // KMS still recorded the deny.
        assert_eq!(rt.receipts().receipts().last().unwrap().decision, "deny");
        assert_eq!(rt.receipts().verify(), Ok(()));
    }

    #[test]
    fn unlock_denies_on_pcr_mismatch() {
        let mut rt = runtime();
        let mut cap = capsule(verified_manifest(true).unwrap());
        cap.key_plan.pcrs.set(PCR7, "sha384:tampered");
        let h = rt.define(cap).unwrap();
        let v = rt.verify(h).unwrap();
        let p = rt.prepare(v).unwrap();
        let err = rt.unlock(p).unwrap_err();
        assert!(matches!(err, VmError::KeyReleaseDenied(_)));
    }

    #[test]
    fn attach_denies_forbidden_passthrough() {
        let mut rt = runtime();
        let mut cap = capsule(verified_manifest(true).unwrap());
        cap.devices.passthrough = vec!["0000:01:00.0".to_string()];
        let h = rt.define(cap).unwrap();
        let v = rt.verify(h).unwrap();
        let p = rt.prepare(v).unwrap();
        let u = rt.unlock(p).unwrap();
        let err = rt.attach(u).unwrap_err();
        assert!(matches!(err, VmError::PolicyDenied(_)));
        assert_eq!(rt.receipts().verify(), Ok(()));
    }

    #[test]
    fn npt_root_is_deterministic_and_nonzero() {
        let a = derive_npt_root("vm-keystone-1");
        let b = derive_npt_root("vm-keystone-1");
        assert_eq!(a, b);
        assert_ne!(a, 0);
        assert_ne!(derive_npt_root("vm-a"), derive_npt_root("vm-b"));
    }

    #[test]
    fn runnable_snapshot_chain_verifies() {
        let mut rt = runtime();
        let cap = capsule(verified_manifest(true).unwrap());
        let r = drive_to_running(&mut rt, cap);
        // The snapshot embedded in the runnable bundle is itself a valid chain.
        assert_eq!(r.runnable().receipts.verify(), Ok(()));
        assert_eq!(r.runnable().npt_root, derive_npt_root("vm-keystone-1"));
    }
}
