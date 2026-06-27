//! The local control plane: an in-memory registry of VMs driven through the
//! [`hyper_vm`] typed lifecycle, plus a shared audit receipt chain.
//!
//! Everything here is local-only and deny-by-default: there is no network
//! server, no clock and no randomness. The only way a guest reaches `Running`
//! is by walking the fail-closed lifecycle, and an unsigned/untrusted capsule
//! is rejected the moment it is defined (its manifest cannot be verified, so a
//! `VmCapsule` can never be built around it).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use hyper_attest::{KmsPolicy, KmsSimulator, PcrBank, PCR0, PCR11, PCR7};
use hyper_capsule::{parse_manifest, verify, AllowlistVerifier};
use hyper_policy::PolicyDocument;
use hyper_vm::{
    BootSpec, CpuSpec, DeviceAssignmentSpec, KeyReleasePlan, MemorySpec, PausedVm, RunningVm,
    SlateRuntime, SnapshotReceipt, StoppedVm, VerifiedVm, VmCapsule, VmHandle, VmLifecycle,
    VmPolicy, VmState, VirtualDiskSpec, VirtualNicSpec,
};

use crate::error::ControlError;

/// Schema discriminator expected on a control-plane capsule descriptor.
pub const CONTROL_CAPSULE_SCHEMA: &str = "chain.control.capsule.v1";
/// Schema discriminator emitted by [`Control::slate_doctor`].
pub const CONTROL_DOCTOR_SCHEMA: &str = "chain.control.doctor.v1";
/// Schema discriminator emitted by [`Control::policy_inspect`].
pub const CONTROL_POLICY_SCHEMA: &str = "chain.control.policy_view.v1";
/// Schema discriminator emitted by [`Control::receipts_verify`].
pub const CONTROL_RECEIPTS_SCHEMA: &str = "chain.control.receipts_view.v1";
/// Schema version stamped onto control-plane JSON views.
pub const CONTROL_SCHEMA_VERSION: u32 = 1;

/// Default hypervisor version this local control plane reports (PN52).
pub const DEFAULT_HYPERVISOR_VERSION: u64 = 52;
/// Default boot-policy hash the local KMS pins (acceptance V9 anchor).
pub const DEFAULT_BOOT_POLICY_HASH: &str = "sha384:bootpol-local";
/// Default capsule hash the local KMS allow-lists.
pub const DEFAULT_CAPSULE_HASH: &str = "sha384:capsule-local";

/// SHA-384 digest of `bytes`, formatted `"sha384:<hex>"`. Thin wrapper over the
/// shared receipt-spine helper so the whole framework uses one hash format and
/// no new hashing crate is pulled into `hyper-control`.
pub fn sha384_hex(bytes: &[u8]) -> String {
    hyper_receipts::sha384_hex(bytes)
}

// ---------------------------------------------------------------------------
// Control-plane capsule descriptor (the `vm define <file>` input)
// ---------------------------------------------------------------------------

/// The JSON document accepted by [`Control::vm_define`].
///
/// It wraps the signed boot `manifest` (verified via [`hyper_capsule::verify`])
/// together with the host-side specs and policy knobs needed to drive the
/// lifecycle. CPU and memory are taken from the verified manifest so the launch
/// gate and memory allocator can never disagree.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ControlCapsuleSpec {
    /// Must equal [`CONTROL_CAPSULE_SCHEMA`].
    pub schema: String,
    /// Stable identifier for this capsule.
    pub capsule_id: String,
    /// The boot manifest object (verified by the allowlist verifier).
    pub manifest: serde_json::Value,
    /// Signing key ids trusted for this capsule's manifest signatures.
    #[serde(default)]
    pub allowed_key_ids: Vec<String>,
    /// Boot configuration.
    pub boot: BootSpec,
    /// Attached virtual disks.
    #[serde(default)]
    pub storage: Vec<VirtualDiskSpec>,
    /// Attached virtual NICs.
    #[serde(default)]
    pub network: Vec<VirtualNicSpec>,
    /// Passthrough device assignment.
    #[serde(default)]
    pub devices: DeviceAssignmentSpec,
    /// Per-capsule launch policy knobs.
    pub policy: VmPolicy,
    /// Attested key-release plan.
    pub key_plan: KeyReleasePlan,
}

impl ControlCapsuleSpec {
    /// Verify the manifest and assemble a [`VmCapsule`]. Fails closed: an
    /// unsigned/untrusted manifest yields `Err` and no capsule.
    fn into_capsule(self, min_hypervisor_version: u64) -> Result<VmCapsule, ControlError> {
        if self.schema != CONTROL_CAPSULE_SCHEMA {
            return Err(ControlError::Schema {
                expected: CONTROL_CAPSULE_SCHEMA.to_string(),
                got: self.schema,
            });
        }
        let manifest_str = serde_json::to_string(&self.manifest)?;
        let untrusted = parse_manifest(&manifest_str)?;
        let verifier = AllowlistVerifier::new(self.allowed_key_ids.clone());
        // This is the deny point for unsigned/invalid capsules.
        let verified = verify(
            untrusted,
            &verifier,
            min_hypervisor_version,
            self.policy.tenant_min_boot_policy,
        )?;

        let cpu = CpuSpec {
            vcpus: verified.inner().cpu.vcpus,
        };
        let memory = MemorySpec {
            max_mb: verified.inner().memory.max_mb,
        };

        Ok(VmCapsule {
            capsule_id: self.capsule_id,
            manifest: verified,
            boot: self.boot,
            cpu,
            memory,
            storage: self.storage,
            network: self.network,
            devices: self.devices,
            policy: self.policy,
            key_plan: self.key_plan,
        })
    }
}

// ---------------------------------------------------------------------------
// Registry entry: the current typed lifecycle state of a VM
// ---------------------------------------------------------------------------

/// The lifecycle stage of a registered VM. Wraps the (non-`Clone`) typed state
/// structs so the registry can own them between commands and move them through
/// transitions.
enum VmStage {
    Defined(VmHandle),
    Verified(VerifiedVm),
    Running(Box<RunningVm>),
    Paused(Box<PausedVm>),
    Stopped(Box<StoppedVm>),
    /// Terminal: zeroized + released.
    Destroyed,
    /// Terminal: a snapshot consumed the (paused) guest.
    Snapshotted,
    /// A fail-closed fault left the VM unusable; carries the reason.
    Failed(String),
}

impl VmStage {
    fn state(&self) -> VmState {
        match self {
            VmStage::Defined(_) => VmState::Defined,
            VmStage::Verified(_) => VmState::Verified,
            VmStage::Running(_) => VmState::Running,
            VmStage::Paused(_) => VmState::Paused,
            VmStage::Stopped(_) => VmState::Stopped,
            VmStage::Destroyed => VmState::Destroyed,
            VmStage::Snapshotted => VmState::Stopped,
            VmStage::Failed(_) => VmState::Failed,
        }
    }

    fn state_name(&self) -> String {
        match self {
            VmStage::Snapshotted => "snapshotted".to_string(),
            VmStage::Failed(reason) => format!("failed: {reason}"),
            other => serde_json::to_value(other.state())
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_else(|| "unknown".to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// Control
// ---------------------------------------------------------------------------

/// The local control plane behind `hyperctl`.
pub struct Control {
    runtime: SlateRuntime,
    registry: BTreeMap<String, VmStage>,
    snapshots: BTreeMap<String, SnapshotReceipt>,
    policy_doc: PolicyDocument,
}

impl Control {
    /// Build a control plane over an explicit policy document, attested KMS and
    /// hypervisor version.
    pub fn new(policy_doc: PolicyDocument, kms: KmsSimulator, hypervisor_version: u64) -> Self {
        Control {
            runtime: SlateRuntime::new(policy_doc.clone(), kms, hypervisor_version),
            registry: BTreeMap::new(),
            snapshots: BTreeMap::new(),
            policy_doc,
        }
    }

    /// Build a self-contained local control plane with a strict, deny-by-default
    /// policy and a deterministic KMS. Used by `hyperctl` for offline operation.
    pub fn new_local() -> Self {
        Control::new(
            Self::default_policy_doc(),
            Self::default_kms(),
            DEFAULT_HYPERVISOR_VERSION,
        )
    }

    /// The strict, deny-by-default policy document used by [`Control::new_local`].
    pub fn default_policy_doc() -> PolicyDocument {
        let j = r#"{
            "schema_version": 1,
            "policy_id": "pol-hyperctl-local",
            "minimum_hypervisor_version": 52,
            "require_signed_manifest": true,
            "require_measured_boot": true,
            "allow_device_passthrough": false,
            "allow_debug_console": false,
            "network_default": "deny",
            "storage": { "require_encryption": true, "allow_read_write_base_image": false },
            "key_release": { "mode": "remote_attested_kms", "require_pcr_match_for_sensitive_vms": true }
        }"#;
        PolicyDocument::parse(j).expect("built-in local policy is valid")
    }

    /// The deterministic local PCR expectations pinned by [`Control::default_kms`].
    pub fn default_pcrs() -> PcrBank {
        let mut p = PcrBank::new();
        p.set(PCR0, "sha384:p0")
            .set(PCR7, "sha384:p7")
            .set(PCR11, "sha384:p11");
        p
    }

    /// The deterministic KMS simulator used by [`Control::new_local`].
    pub fn default_kms() -> KmsSimulator {
        KmsSimulator::new(KmsPolicy {
            expected_pcrs: Self::default_pcrs(),
            min_hypervisor_version: DEFAULT_HYPERVISOR_VERSION,
            allowed_capsule_hashes: vec![DEFAULT_CAPSULE_HASH.to_string()],
            expected_boot_policy_hash: DEFAULT_BOOT_POLICY_HASH.to_string(),
        })
    }

    // ---- command: slate doctor ------------------------------------------

    /// `slate doctor` — a deterministic JSON health report of the control plane.
    pub fn slate_doctor(&self) -> String {
        let vms: Vec<serde_json::Value> = self
            .registry
            .iter()
            .map(|(id, stage)| {
                serde_json::json!({ "vm_id": id, "state": stage.state_name() })
            })
            .collect();
        let chain_valid = self.runtime.receipts().verify().is_ok();
        let report = serde_json::json!({
            "schema": CONTROL_DOCTOR_SCHEMA,
            "schema_version": CONTROL_SCHEMA_VERSION,
            "status": if chain_valid { "ok" } else { "degraded" },
            "hypervisor_version": self.runtime.hypervisor_version(),
            "policy_id": self.policy_doc.policy_id,
            "deny_by_default": true,
            "network_default": self.policy_doc.network_default,
            "expected_boot_policy_hash": DEFAULT_BOOT_POLICY_HASH,
            "expected_capsule_hash": DEFAULT_CAPSULE_HASH,
            "vm_count": self.registry.len(),
            "receipt_count": self.runtime.receipts().len(),
            "receipt_chain_valid": chain_valid,
            "vms": vms,
        });
        serde_json::to_string_pretty(&report).expect("doctor report serializes")
    }

    // ---- command: vm define ---------------------------------------------

    /// `vm define <file>` — verify a capsule descriptor and admit it to the
    /// runtime (`-> Defined`). Returns the assigned VM id.
    ///
    /// Fails closed: an unsigned/untrusted manifest is rejected here and no VM
    /// is registered.
    pub fn vm_define(&mut self, capsule_json: &str) -> Result<String, ControlError> {
        let spec: ControlCapsuleSpec = serde_json::from_str(capsule_json)?;
        let capsule = spec.into_capsule(self.runtime.hypervisor_version())?;
        let handle = self.runtime.define(capsule)?;
        let id = handle.vm_id().as_str().to_string();
        self.registry.insert(id.clone(), VmStage::Defined(handle));
        Ok(id)
    }

    // ---- command: vm verify ---------------------------------------------

    /// `vm verify <id>` — run the manifest verification + launch gate
    /// (`Defined -> Verified`).
    pub fn vm_verify(&mut self, id: &str) -> Result<String, ControlError> {
        let stage = self.take(id)?;
        let handle = match stage {
            VmStage::Defined(h) => h,
            other => return self.reject(id, "verify", "defined", other),
        };
        match self.runtime.verify(handle) {
            Ok(v) => {
                let img = v.approval().image_hash().to_string();
                self.registry.insert(id.to_string(), VmStage::Verified(v));
                Ok(format!("verified {id}: image {img}"))
            }
            Err(e) => {
                self.registry
                    .insert(id.to_string(), VmStage::Failed(e.to_string()));
                Err(e.into())
            }
        }
    }

    // ---- command: vm launch ---------------------------------------------

    /// `vm launch <id>` — drive a verified VM all the way to `Running`
    /// (`prepare -> unlock -> attach -> run`). Any failed gate marks the VM
    /// `Failed` and returns the denial.
    pub fn vm_launch(&mut self, id: &str) -> Result<String, ControlError> {
        let stage = self.take(id)?;
        let verified = match stage {
            VmStage::Verified(v) => v,
            other => return self.reject(id, "launch", "verified", other),
        };
        match self.drive_to_running(verified) {
            Ok(running) => {
                let vcpus = running.runnable().vcpus.len();
                let devices = running.runnable().devices.device_count();
                self.registry
                    .insert(id.to_string(), VmStage::Running(Box::new(running)));
                Ok(format!("launched {id}: running ({vcpus} vcpus, {devices} devices)"))
            }
            Err(e) => {
                self.registry
                    .insert(id.to_string(), VmStage::Failed(e.to_string()));
                Err(e.into())
            }
        }
    }

    fn drive_to_running(&mut self, v: VerifiedVm) -> Result<RunningVm, hyper_vm::VmError> {
        let prepared = self.runtime.prepare(v)?;
        let unlocked = self.runtime.unlock(prepared)?;
        let attached = self.runtime.attach(unlocked)?;
        self.runtime.run(attached)
    }

    // ---- command: vm pause ----------------------------------------------

    /// `vm pause <id>` — pause a running guest (`Running -> Paused`).
    pub fn vm_pause(&mut self, id: &str) -> Result<String, ControlError> {
        let stage = self.take(id)?;
        let running = match stage {
            VmStage::Running(r) => *r,
            other => return self.reject(id, "pause", "running", other),
        };
        match self.runtime.pause(running) {
            Ok(p) => {
                self.registry
                    .insert(id.to_string(), VmStage::Paused(Box::new(p)));
                Ok(format!("paused {id}"))
            }
            Err(e) => {
                self.registry
                    .insert(id.to_string(), VmStage::Failed(e.to_string()));
                Err(e.into())
            }
        }
    }

    // ---- command: vm snapshot -------------------------------------------

    /// `vm snapshot <id> --name <n>` — snapshot a paused (or running) guest.
    /// The upstream lifecycle consumes the paused guest when snapshotting, so
    /// after this call the VM is terminal (`snapshotted`); the proof token is
    /// retained under `name`.
    pub fn vm_snapshot(&mut self, id: &str, name: &str) -> Result<String, ControlError> {
        let stage = self.take(id)?;
        let paused = match stage {
            VmStage::Paused(p) => *p,
            VmStage::Running(r) => {
                // Convenience: pause-then-snapshot in one step.
                match self.runtime.pause(*r) {
                    Ok(p) => p,
                    Err(e) => {
                        self.registry
                            .insert(id.to_string(), VmStage::Failed(e.to_string()));
                        return Err(e.into());
                    }
                }
            }
            other => return self.reject(id, "snapshot", "running|paused", other),
        };
        match self.runtime.snapshot(paused) {
            Ok(receipt) => {
                let summary = format!(
                    "snapshot `{name}` of {id}: receipt {} @ {}",
                    receipt.receipt_id, receipt.chain_head
                );
                self.snapshots.insert(name.to_string(), receipt);
                self.registry.insert(id.to_string(), VmStage::Snapshotted);
                Ok(summary)
            }
            Err(e) => {
                self.registry
                    .insert(id.to_string(), VmStage::Failed(e.to_string()));
                Err(e.into())
            }
        }
    }

    // ---- command: vm stop -----------------------------------------------

    /// `vm stop <id>` — stop a running guest (`Running -> Stopped`).
    pub fn vm_stop(&mut self, id: &str) -> Result<String, ControlError> {
        let stage = self.take(id)?;
        let running = match stage {
            VmStage::Running(r) => *r,
            other => return self.reject(id, "stop", "running", other),
        };
        match self.runtime.stop(running) {
            Ok(s) => {
                self.registry
                    .insert(id.to_string(), VmStage::Stopped(Box::new(s)));
                Ok(format!("stopped {id}"))
            }
            Err(e) => {
                self.registry
                    .insert(id.to_string(), VmStage::Failed(e.to_string()));
                Err(e.into())
            }
        }
    }

    // ---- command: vm destroy --------------------------------------------

    /// `vm destroy <id> --wipe` — zeroize + release a stopped guest. The `wipe`
    /// flag is a mandatory, deny-by-default confirmation: without it the call is
    /// refused so destruction is never implicit.
    pub fn vm_destroy(&mut self, id: &str, wipe: bool) -> Result<String, ControlError> {
        // Peek without consuming so a refusal leaves the VM intact.
        match self.registry.get(id) {
            None => return Err(ControlError::NotFound(id.to_string())),
            Some(VmStage::Stopped(_)) => {}
            Some(other) => {
                let found = other.state_name();
                return Err(ControlError::InvalidState {
                    action: "destroy".to_string(),
                    id: id.to_string(),
                    found,
                    needed: "stopped".to_string(),
                });
            }
        }
        if !wipe {
            return Err(ControlError::WipeRequired(id.to_string()));
        }
        let stopped = match self.take(id)? {
            VmStage::Stopped(s) => *s,
            // Unreachable given the peek above, but stay fail-closed.
            other => return self.reject(id, "destroy", "stopped", other),
        };
        match self.runtime.destroy(stopped) {
            Ok(receipt) => {
                self.registry.insert(id.to_string(), VmStage::Destroyed);
                Ok(format!(
                    "destroyed {id}: zeroized {} range(s), receipt {} @ {}",
                    receipt.zeroized_ranges, receipt.receipt_id, receipt.chain_head
                ))
            }
            Err(e) => {
                self.registry
                    .insert(id.to_string(), VmStage::Failed(e.to_string()));
                Err(e.into())
            }
        }
    }

    // ---- command: policy inspect ----------------------------------------

    /// `policy inspect` — the active policy document plus posture, as JSON.
    pub fn policy_inspect(&self) -> String {
        let view = serde_json::json!({
            "schema": CONTROL_POLICY_SCHEMA,
            "schema_version": CONTROL_SCHEMA_VERSION,
            "deny_by_default": true,
            "hypervisor_version": self.runtime.hypervisor_version(),
            "policy": self.policy_doc,
        });
        serde_json::to_string_pretty(&view).expect("policy view serializes")
    }

    // ---- command: receipts verify ---------------------------------------

    /// `receipts verify [--vm <id>]` — verify the shared audit chain and report
    /// a JSON summary. Fails closed: a broken chain returns `Err`.
    pub fn receipts_verify(&self, vm: Option<&str>) -> Result<String, ControlError> {
        let chain = self.runtime.receipts();
        chain
            .verify()
            .map_err(|e| ControlError::Receipt(e.to_string()))?;

        let scoped = vm.map(|id| {
            chain
                .receipts()
                .iter()
                .filter(|r| r.subject == id)
                .map(|r| {
                    serde_json::json!({
                        "receipt_id": r.receipt_id,
                        "event": r.event,
                        "decision": r.decision,
                    })
                })
                .collect::<Vec<_>>()
        });

        let view = serde_json::json!({
            "schema": CONTROL_RECEIPTS_SCHEMA,
            "schema_version": CONTROL_SCHEMA_VERSION,
            "valid": true,
            "total": chain.len(),
            "head": chain.head_hash(),
            "vm": vm,
            "vm_receipts": scoped,
        });
        Ok(serde_json::to_string_pretty(&view).expect("receipts view serializes"))
    }

    // ---- internals -------------------------------------------------------

    /// Remove a VM's stage from the registry, erroring if it is unknown.
    fn take(&mut self, id: &str) -> Result<VmStage, ControlError> {
        self.registry
            .remove(id)
            .ok_or_else(|| ControlError::NotFound(id.to_string()))
    }

    /// Re-insert `stage` and return an `InvalidState` error for `action`.
    fn reject<T>(
        &mut self,
        id: &str,
        action: &str,
        needed: &str,
        stage: VmStage,
    ) -> Result<T, ControlError> {
        let found = stage.state_name();
        self.registry.insert(id.to_string(), stage);
        Err(ControlError::InvalidState {
            action: action.to_string(),
            id: id.to_string(),
            found,
            needed: needed.to_string(),
        })
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const CAPSULE_HASH: &str = DEFAULT_CAPSULE_HASH;
    const BOOT_POLICY_HASH: &str = DEFAULT_BOOT_POLICY_HASH;

    fn control() -> Control {
        Control::new_local()
    }

    fn manifest_value(signed: bool) -> serde_json::Value {
        let sigs = if signed {
            serde_json::json!([{ "alg": "ecdsa-p384", "key_id": "key-good", "status": null }])
        } else {
            serde_json::json!([])
        };
        serde_json::json!({
            "schema": "chain.vm_capsule.v1",
            "vm_id": "vm-ctl-1",
            "tenant_id": "tenant-a",
            "image_hash": "sha384:image-aa",
            "disk_hash": "sha384:disk-bb",
            "hypervisor_min_version": 10,
            "boot_policy_version": 5,
            "devices": { "passthrough": [], "virtio": ["net0", "blk0"] },
            "memory": { "max_mb": 256, "allow_balloon": false },
            "cpu": { "vcpus": 2, "cpuid_profile": "milan-v1" },
            "network": { "mode": "isolated", "egress_policy": "deny-all" },
            "storage": { "cipher": "aes-256-xts", "integrity": "dm-integrity", "key_version": 3 },
            "signatures": sigs,
        })
    }

    fn spec_value(signed: bool, passthrough: Vec<&str>) -> serde_json::Value {
        serde_json::json!({
            "schema": CONTROL_CAPSULE_SCHEMA,
            "capsule_id": "cap-1",
            "manifest": manifest_value(signed),
            "allowed_key_ids": ["key-good"],
            "boot": {
                "firmware": "uefi-ovmf-v1",
                "cmdline": "console=ttyS0",
                "boot_policy_version": 5
            },
            "storage": [{ "disk_id": "blk0", "size_mb": 1024, "read_only": false }],
            "network": [{ "nic_id": "net0", "mode": "isolated" }],
            "devices": { "passthrough": passthrough },
            "policy": {
                "tenant_min_boot_policy": 5,
                "memory_budget_mb": 4096,
                "key_unwrap_authorized": true,
                "device_policy_ok": true,
                "measured_boot": true,
                "requests_debug_console": false
            },
            "key_plan": {
                "device_id": "dev-blk0",
                "capsule_hash": CAPSULE_HASH,
                "boot_policy_hash": BOOT_POLICY_HASH,
                "pcrs": { "0": "sha384:p0", "7": "sha384:p7", "11": "sha384:p11" },
                "nonce": "nonce-0001"
            }
        })
    }

    fn good_capsule_json() -> String {
        spec_value(true, vec![]).to_string()
    }

    // ---- happy path ------------------------------------------------------

    #[test]
    fn define_verify_launch_stop_happy_path() {
        let mut c = control();
        let id = c.vm_define(&good_capsule_json()).expect("define");
        assert_eq!(id, "vm-ctl-1");

        let v = c.vm_verify(&id).expect("verify");
        assert!(v.contains("image sha384:image-aa"));

        let l = c.vm_launch(&id).expect("launch");
        assert!(l.contains("running"));
        assert!(l.contains("2 vcpus"));

        let s = c.vm_stop(&id).expect("stop");
        assert!(s.contains("stopped"));

        // The shared audit chain stays valid end to end.
        assert!(c.receipts_verify(None).is_ok());
    }

    #[test]
    fn pause_then_snapshot_then_records() {
        let mut c = control();
        let id = c.vm_define(&good_capsule_json()).unwrap();
        c.vm_verify(&id).unwrap();
        c.vm_launch(&id).unwrap();
        c.vm_pause(&id).expect("pause");
        let out = c.vm_snapshot(&id, "snap-a").expect("snapshot");
        assert!(out.contains("snap-a"));
        assert!(c.snapshots.contains_key("snap-a"));
        assert!(c.receipts_verify(Some(&id)).is_ok());
    }

    #[test]
    fn stop_then_destroy_with_wipe() {
        let mut c = control();
        let id = c.vm_define(&good_capsule_json()).unwrap();
        c.vm_verify(&id).unwrap();
        c.vm_launch(&id).unwrap();
        c.vm_stop(&id).unwrap();
        let out = c.vm_destroy(&id, true).expect("destroy");
        assert!(out.contains("zeroized"));
        assert!(c.receipts_verify(None).is_ok());
    }

    // ---- receipts --------------------------------------------------------

    #[test]
    fn receipts_verify_ok_and_scoped() {
        let mut c = control();
        let id = c.vm_define(&good_capsule_json()).unwrap();
        c.vm_verify(&id).unwrap();
        c.vm_launch(&id).unwrap();

        let all = c.receipts_verify(None).expect("verify all");
        let v: serde_json::Value = serde_json::from_str(&all).unwrap();
        assert_eq!(v["valid"], serde_json::json!(true));
        assert!(v["total"].as_u64().unwrap() >= 5);

        let scoped = c.receipts_verify(Some(&id)).expect("verify scoped");
        let sv: serde_json::Value = serde_json::from_str(&scoped).unwrap();
        assert_eq!(sv["vm"], serde_json::json!(id));
        assert!(sv["vm_receipts"].as_array().unwrap().len() >= 5);
    }

    // ---- deny / fail-closed paths ---------------------------------------

    #[test]
    fn unsigned_capsule_define_is_denied() {
        let mut c = control();
        let json = spec_value(false, vec![]).to_string();
        let err = c.vm_define(&json).unwrap_err();
        assert!(matches!(err, ControlError::Capsule(_)));
        // Nothing was registered.
        assert!(c.receipts_verify(None).is_ok());
    }

    #[test]
    fn untrusted_key_define_is_denied() {
        let mut c = control();
        let mut spec = spec_value(true, vec![]);
        spec["allowed_key_ids"] = serde_json::json!(["some-other-key"]);
        let err = c.vm_define(&spec.to_string()).unwrap_err();
        assert!(matches!(err, ControlError::Capsule(_)));
    }

    #[test]
    fn bad_schema_is_denied() {
        let mut c = control();
        let mut spec = spec_value(true, vec![]);
        spec["schema"] = serde_json::json!("chain.control.capsule.v2");
        let err = c.vm_define(&spec.to_string()).unwrap_err();
        assert!(matches!(err, ControlError::Schema { .. }));
    }

    #[test]
    fn malformed_json_is_denied() {
        let mut c = control();
        let err = c.vm_define("{not json").unwrap_err();
        assert!(matches!(err, ControlError::Json(_)));
    }

    #[test]
    fn launch_before_verify_is_rejected() {
        let mut c = control();
        let id = c.vm_define(&good_capsule_json()).unwrap();
        let err = c.vm_launch(&id).unwrap_err();
        assert!(matches!(err, ControlError::InvalidState { .. }));
    }

    #[test]
    fn verb_on_unknown_vm_is_not_found() {
        let mut c = control();
        assert!(matches!(
            c.vm_verify("ghost").unwrap_err(),
            ControlError::NotFound(_)
        ));
        assert!(matches!(
            c.vm_stop("ghost").unwrap_err(),
            ControlError::NotFound(_)
        ));
    }

    #[test]
    fn destroy_without_wipe_is_refused_and_vm_kept() {
        let mut c = control();
        let id = c.vm_define(&good_capsule_json()).unwrap();
        c.vm_verify(&id).unwrap();
        c.vm_launch(&id).unwrap();
        c.vm_stop(&id).unwrap();
        let err = c.vm_destroy(&id, false).unwrap_err();
        assert!(matches!(err, ControlError::WipeRequired(_)));
        // Still stopped and destroyable with the explicit flag.
        assert!(c.vm_destroy(&id, true).is_ok());
    }

    #[test]
    fn launch_denied_when_passthrough_forbidden() {
        let mut c = control();
        let json = spec_value(true, vec!["0000:01:00.0"]).to_string();
        let id = c.vm_define(&json).unwrap();
        c.vm_verify(&id).unwrap();
        // attach gate denies forbidden passthrough -> VM marked Failed.
        let err = c.vm_launch(&id).unwrap_err();
        assert!(matches!(err, ControlError::Vm(_)));
        // The deny is audited and the chain remains valid.
        assert!(c.receipts_verify(None).is_ok());
    }

    #[test]
    fn verify_denied_when_measured_boot_missing() {
        let mut c = control();
        let mut spec = spec_value(true, vec![]);
        spec["policy"]["measured_boot"] = serde_json::json!(false);
        let id = c.vm_define(&spec.to_string()).unwrap();
        let err = c.vm_verify(&id).unwrap_err();
        assert!(matches!(err, ControlError::Vm(_)));
        assert!(c.receipts_verify(None).is_ok());
    }

    // ---- JSON views ------------------------------------------------------

    #[test]
    fn policy_inspect_is_valid_json() {
        let c = control();
        let s = c.policy_inspect();
        let v: serde_json::Value = serde_json::from_str(&s).expect("valid json");
        assert_eq!(v["schema"], serde_json::json!(CONTROL_POLICY_SCHEMA));
        assert_eq!(v["deny_by_default"], serde_json::json!(true));
        assert_eq!(
            v["policy"]["policy_id"],
            serde_json::json!("pol-hyperctl-local")
        );
    }

    #[test]
    fn slate_doctor_is_valid_json_and_tracks_vms() {
        let mut c = control();
        let before: serde_json::Value =
            serde_json::from_str(&c.slate_doctor()).expect("valid json");
        assert_eq!(before["vm_count"], serde_json::json!(0));
        assert_eq!(before["status"], serde_json::json!("ok"));

        let id = c.vm_define(&good_capsule_json()).unwrap();
        c.vm_verify(&id).unwrap();
        let after: serde_json::Value =
            serde_json::from_str(&c.slate_doctor()).expect("valid json");
        assert_eq!(after["vm_count"], serde_json::json!(1));
        assert_eq!(after["vms"][0]["state"], serde_json::json!("verified"));
    }

    #[test]
    fn ids_are_deterministic_across_runs() {
        let mut a = control();
        let mut b = control();
        let ida = a.vm_define(&good_capsule_json()).unwrap();
        let idb = b.vm_define(&good_capsule_json()).unwrap();
        assert_eq!(ida, idb);
    }
}
