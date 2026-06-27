# 09 — Virtual Framework (Slate Runtime), Phase V0

This document tracks the **upper-half** virtual framework described in
SOW-HSLATE-PN52-002 Part B. The lower-half substrate (UEFI app → `no_std`
host → AMD SVM/NPT/IOMMU) lives in `hyper-x86` / `hyper-amd-svm` / `hyper-pn52`.
The virtual framework is the layer that turns the substrate into a VM
*product*: signed capsules, a lifecycle, policy, and tamper-evident receipts.

## What Phase V0 delivers

Per Part B §14, **V0 runs entirely on the host (or in QEMU) with dummy
backends** so the lifecycle, policy, and audit machinery can be built and tested
before any bare-metal guest exists. The following crates are implemented and
unit-tested:

| Crate | Part B ref | Responsibility |
|---|---|---|
| `hyper-receipts` | §12 | Hash-chained, tamper-evident audit log (`chain.receipt.v1`). |
| `hyper-capsule` | §1, §4, §8 | Capsule manifest parsing + the `Untrusted → Verified` type split. |
| `hyper-policy` | §9, A§10 | Deny-by-default policy engine (launch + key release). |
| `hyper-vm` | §2, §5 | VM lifecycle state machine + pluggable vCPU/disk backends. |
| `hyper-slate-vm-demo` (app) | §11, §15 | Walkthrough: drive a signed capsule to `Stopped`, print receipts. |

### V0 acceptance criteria (met)

> A fake VM capsule can move Defined → Verified → Prepared → Running → Stopped.
> Unsigned capsule cannot run. Receipt chain verifies.

- **Lifecycle:** `Vm::{define, prepare, unlock, attach, run, destroy}` walk the
  state machine; out-of-order calls return `BadState`.
- **Unsigned cannot run:** a `Vm` can only be constructed from a
  `VerifiedManifest`. `UntrustedManifest::verify` fails closed on missing
  signatures, untrusted signers, stale hypervisor version, or content-hash
  mismatch — so an unsigned capsule never reaches `hyper-vm` at all.
- **Receipts verify:** every transition appends a hash-chained receipt; editing,
  dropping, or reordering any link is detected by `ReceiptChain::verify`.
- **Fail-closed guest exits:** an unknown VM exit quarantines the VM and zeroizes
  disk key material, on the record.

## The parsed-vs-trusted boundary

The single most important safety property. Bytes off the wire become an
`UntrustedManifest`; only `verify(&TrustStore, …)` yields a `VerifiedManifest`;
only a `VerifiedManifest` can build a `Vm`. This makes the entire class of
"accidentally launched an unverified thing" bugs (Part B §1) unrepresentable.

```
bytes ──parse──▶ UntrustedManifest ──verify(TrustStore)──▶ VerifiedManifest ──▶ Vm
                       │                      │
                  (cannot launch)        fail closed on:
                                         unsigned / untrusted signer /
                                         hv too old / hash mismatch
```

## Lifecycle and where policy/receipts hook in

```
define ─▶ Defined            receipt: vm_define
prepare ─▶ Prepared          policy: evaluate_vm_launch   receipt: vm_launch_policy
unlock  ─▶ Unlocked          policy: evaluate_key_release receipt: vm_key_release
         (or AwaitingKeyRelease on RequireApproval)
attach  ─▶ Attached          receipt: vm_attach
run     ─▶ Running ─▶ Stopped receipt: vm_launch, vm_stop
         (or Quarantined on guest fault: receipt vm_exit_fault, keys zeroized)
destroy ─▶ Destroyed         receipt: vm_destroy
```

## Run it

```bash
cargo test -p hyper-receipts -p hyper-capsule -p hyper-policy -p hyper-vm
cargo run  -p hyper-slate-vm-demo                                   # built-in sample
cargo run  -p hyper-slate-vm-demo -- manifests/sample.chainvm-capsule.json
```

## Deliberate V0 simplifications (and where they go next)

These are honest stubs, not hidden gaps:

- **Signatures are trust-store membership checks, not crypto.** Real
  ECDSA-P384 / ML-DSA-65 verification arrives with the KMS/attested-unlock phase
  (V4+). The swap is local to `UntrustedManifest::verify`.
- **vCPU and disk are dummy backends** (`ScriptedVcpu`, `MemDisk`) behind the
  `VcpuBackend` / `DiskBackend` traits. V1 swaps in the `hyper-amd-svm` VMRUN
  loop and a `hyper-storage`-backed encrypted disk without touching `hyper-vm`.
- **Memory/NPT and the device bus are collapsed** into `hyper-vm` for V0. Part B
  §13 extracts `hyper-mm`, `hyper-vcpu`, `hyper-devices`, `hyper-virtio` as the
  guest gains real memory and devices (V1–V3).
- **Receipt sequencing uses a logical counter, not a wall clock**, to keep
  tamper-evidence reproducible. Real nodes add a timestamp field alongside it.

## Mapping to the security backlog (Part A §12)

| Backlog item | Status in V0 |
|---|---|
| S0 — hash-chained event log | ✅ `hyper-receipts` |
| S1 — `VerifiedManifest` type split | ✅ `hyper-capsule` (launch impossible from unverified) |
| S8 — KMS unlock requires manifest + measurement match | ◑ modeled in `hyper-policy::evaluate_key_release` (PCR/measured-boot gates); real KMS later |
| S10 — panic-safe zeroization | ◑ disk key zeroized on stop/fault/destroy; full key-zeroize discipline later |
| S11 — fuzz VM manifest parser | ◑ bounded parser + negative tests; fuzz target later |
| S13 — guest DoS throttling | ☐ V0 runs one cooperative slice loop; rate-limiting in V1 scheduler |
