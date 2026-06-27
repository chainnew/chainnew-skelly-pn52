//! Phase V0 walkthrough (SOW Part B §14).
//!
//! Drives a signed capsule manifest through the full Slate Runtime lifecycle on
//! the host — no bare metal — and prints the hash-chained receipt log. Pass a
//! capsule manifest path as the first argument, or run with none to use the
//! built-in sample.
//!
//!   cargo run -p hyper-slate-vm-demo [path/to/capsule.manifest.json]

use std::process::ExitCode;

use hyper_capsule::{TrustStore, UntrustedManifest};
use hyper_policy::{DefaultPolicyEngine, PlatformState, PolicyConfig};
use hyper_vm::backend::{MemDisk, ScriptedVcpu};
use hyper_vm::{Sensitivity, Vm};

const SAMPLE_MANIFEST: &str = r#"{
  "schema": "chain.vm_capsule.v1",
  "vm_id": "dev-linux-001",
  "tenant_id": "lab",
  "image_hash": "sha384:0000",
  "disk_hash": "sha384:0000",
  "hypervisor_min_version": 4,
  "boot_policy_version": 7,
  "devices": { "passthrough": [], "virtio": ["blk", "net", "console"] },
  "memory": { "max_mb": 4096, "allow_balloon": false },
  "cpu": { "vcpus": 2, "cpuid_profile": "masked_zen3_guest_v1" },
  "network": { "mode": "isolated", "egress_policy": "deny_by_default" },
  "storage": { "cipher": "AES-256-XTS", "integrity": "manifest_hash_only", "key_version": 3 },
  "signatures": [
    { "alg": "ecdsa-p384", "key_id": "lab-classical-2026", "status": "active" },
    { "alg": "ml-dsa-65", "key_id": "lab-pq-transition-2026", "status": "transition" }
  ]
}"#;

fn main() -> ExitCode {
    let bytes = match std::env::args().nth(1) {
        Some(path) => match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("failed to read {path}: {e}");
                return ExitCode::FAILURE;
            }
        },
        None => SAMPLE_MANIFEST.as_bytes().to_vec(),
    };

    // Trust store and policy this host runs under (a real node loads these from
    // a signed, versioned policy bundle).
    let trust = TrustStore::new(12).trust_key("lab-classical-2026");
    let policy = DefaultPolicyEngine::new(PolicyConfig::lab_default());

    // 1. Parse (untrusted) and 2. verify (-> only now launchable).
    let untrusted = match UntrustedManifest::parse(&bytes) {
        Ok(u) => u,
        Err(e) => {
            eprintln!("parse rejected: {e}");
            return ExitCode::FAILURE;
        }
    };
    println!("parsed capsule for vm_id={} (untrusted)", untrusted.vm_id());

    let verified = match untrusted.verify(&trust, None, None) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("verification rejected (fail closed): {e}");
            return ExitCode::FAILURE;
        }
    };
    println!(
        "verified capsule: signature_status={:?}",
        verified.signature_status()
    );

    // 3..N. Lifecycle on dummy backends.
    let mut vm = Vm::define(
        verified,
        Sensitivity::Standard,
        PlatformState::trusted_boot(),
        policy,
        ScriptedVcpu::cooperative(),
        MemDisk::new(vec![vec![0xAB; 4096]], 4096),
    );

    macro_rules! step {
        ($name:literal, $call:expr) => {
            match $call {
                Ok(()) => println!("  {:<8} -> {:?}", $name, vm.state()),
                Err(e) => {
                    eprintln!("  {:<8} -> ERROR: {e}", $name);
                    return ExitCode::FAILURE;
                }
            }
        };
    }
    step!("prepare", vm.prepare());
    step!("unlock", vm.unlock());
    step!("attach", vm.attach());
    step!("run", vm.run());

    // Verify and print the audit chain.
    match vm.receipts().verify() {
        Ok(()) => println!("\nreceipt chain verified ({} receipts)", vm.receipts().len()),
        Err(e) => {
            eprintln!("receipt chain FAILED verification: {e}");
            return ExitCode::FAILURE;
        }
    }
    if let Ok(json) = vm.receipts().to_json() {
        println!("\n{json}");
    }

    ExitCode::SUCCESS
}
