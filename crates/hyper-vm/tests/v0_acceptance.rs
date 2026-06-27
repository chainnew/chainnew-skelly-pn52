//! Phase V0 acceptance gate for the slate-runtime keystone (hyper-vm).
//!
//! Exercises the full typed lifecycle through [`SlateRuntime`] and asserts the
//! fail-closed doctrine: an unsigned capsule can never reach `Running`, every
//! transition appends an audit receipt, and any tampering with the chain is
//! detected.

use hyper_attest::{KmsPolicy, KmsSimulator, PcrBank, PCR0, PCR11, PCR7};
use hyper_capsule::{
    parse_manifest, verify, AllowlistVerifier, CapsuleError, VerifiedManifest,
};
use hyper_policy::PolicyDocument;
use hyper_receipts::ReceiptChain;

use hyper_vm::{
    BootSpec, CpuSpec, DeviceAssignmentSpec, KeyReleasePlan, MemorySpec, SlateRuntime,
    VirtualDiskSpec, VirtualNicSpec, VmCapsule, VmLifecycle, VmPolicy, VmState,
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
            "vm_id": "vm-v0",
            "tenant_id": "tenant-a",
            "image_hash": "sha384:image-aa",
            "disk_hash": "sha384:disk-bb",
            "hypervisor_min_version": 10,
            "boot_policy_version": 5,
            "devices": {{ "passthrough": [], "virtio": ["net0", "blk0"] }},
            "memory": {{ "max_mb": 512, "allow_balloon": false }},
            "cpu": {{ "vcpus": 4, "cpuid_profile": "milan-v1" }},
            "network": {{ "mode": "isolated", "egress_policy": "deny-all" }},
            "storage": {{ "cipher": "aes-256-xts", "integrity": "dm-integrity", "key_version": 3 }},
            "signatures": {sigs}
        }}"#
    )
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
        "policy_id": "pol-v0",
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

/// Build a VmCapsule. Returns `Err` for an unsigned manifest because the only
/// constructor for `VerifiedManifest` is `hyper_capsule::verify`.
fn build_capsule(signed: bool) -> Result<VmCapsule, CapsuleError> {
    let untrusted = parse_manifest(&manifest_json(signed)).unwrap();
    let verifier = AllowlistVerifier::new(["key-good"]);
    let manifest: VerifiedManifest = verify(untrusted, &verifier, 12, 5)?;

    Ok(VmCapsule {
        capsule_id: "cap-v0".to_string(),
        manifest,
        boot: BootSpec {
            firmware: "uefi-ovmf-v1".to_string(),
            cmdline: "console=ttyS0 ro".to_string(),
            boot_policy_version: 5,
        },
        cpu: CpuSpec { vcpus: 4 },
        memory: MemorySpec { max_mb: 512 },
        storage: vec![VirtualDiskSpec {
            disk_id: "blk0".to_string(),
            size_mb: 4096,
            read_only: false,
        }],
        network: vec![VirtualNicSpec {
            nic_id: "net0".to_string(),
            mode: "isolated".to_string(),
        }],
        devices: DeviceAssignmentSpec::default(),
        policy: VmPolicy {
            tenant_min_boot_policy: 5,
            memory_budget_mb: 8192,
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
            nonce: "nonce-v0".to_string(),
        },
    })
}

#[test]
fn v0_full_lifecycle_defined_through_stopped() {
    let mut rt = runtime();
    let cap = build_capsule(true).expect("signed capsule builds");

    // Defined -> Verified -> Prepared -> Unlocked -> Attached -> Running.
    let handle = rt.define(cap).expect("define");
    assert_eq!(handle.state(), VmState::Defined);
    assert_eq!(rt.receipts().len(), 1);

    let verified = rt.verify(handle).expect("verify");
    assert_eq!(verified.state(), VmState::Verified);
    assert_eq!(rt.receipts().len(), 2);

    let prepared = rt.prepare(verified).expect("prepare");
    assert_eq!(prepared.state(), VmState::Prepared);
    assert_eq!(rt.receipts().len(), 3);

    let unlocked = rt.unlock(prepared).expect("unlock");
    assert_eq!(unlocked.state(), VmState::Unlocked);
    assert_eq!(unlocked.wrapped_vmk_len(), 48);
    assert_eq!(rt.receipts().len(), 4);

    let attached = rt.attach(unlocked).expect("attach");
    assert_eq!(attached.state(), VmState::Attached);
    assert_eq!(attached.vcpu_count(), 4);
    assert_eq!(rt.receipts().len(), 5);

    let running = rt.run(attached).expect("run");
    assert_eq!(running.state(), VmState::Running);
    assert_eq!(running.runnable().vcpus.len(), 4);
    assert_eq!(rt.receipts().len(), 6);

    // Running -> Stopped.
    let stopped = rt.stop(running).expect("stop");
    assert_eq!(stopped.state(), VmState::Stopped);
    assert_eq!(rt.receipts().len(), 7);

    // A receipt was appended per major step and the chain is intact.
    assert_eq!(rt.receipts().verify(), Ok(()));

    // ... and the resources can be zeroized + released.
    let destroyed = rt.destroy(stopped).expect("destroy");
    assert_eq!(destroyed.zeroized_ranges, 1);
    assert_eq!(rt.receipts().len(), 8);
    assert_eq!(rt.receipts().verify(), Ok(()));
}

#[test]
fn v0_unsigned_capsule_cannot_run() {
    // An unsigned manifest fails verification, so a VmCapsule cannot be built,
    // so define()/the lifecycle can never begin. Unsigned capsule cannot run.
    let err = build_capsule(false).unwrap_err();
    assert!(
        matches!(err, CapsuleError::SignatureNotValid(_) | CapsuleError::NoSignatures),
        "unexpected error: {err:?}"
    );
}

#[test]
fn v0_tampered_receipt_fails_verify() {
    let mut rt = runtime();
    let cap = build_capsule(true).unwrap();

    let h = rt.define(cap).unwrap();
    let v = rt.verify(h).unwrap();
    let p = rt.prepare(v).unwrap();
    let u = rt.unlock(p).unwrap();
    let a = rt.attach(u).unwrap();
    let _running = rt.run(a).unwrap();

    // The pristine chain verifies.
    assert_eq!(rt.receipts().verify(), Ok(()));

    // Round-trip through JSON, tamper with a receipt's decision, and confirm
    // verification now fails closed.
    let json = rt.receipts().to_json().unwrap();
    let tampered_json = json.replacen("\"allow\"", "\"deny\"", 1);
    assert_ne!(json, tampered_json, "tamper should have changed the json");

    let tampered = ReceiptChain::from_json(&tampered_json).unwrap();
    assert!(
        tampered.verify().is_err(),
        "tampering with a receipt must break chain verification"
    );
}
