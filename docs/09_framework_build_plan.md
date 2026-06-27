# Framework Build Plan

This document turns the uploaded PN52 defensive framework scope into build gates for this repository.

## First branch slice

```text
hyper-receipts  -> hash-chained audit receipts
hyper-policy    -> launch policy decisions
hyper-capsule   -> .chainvm manifest verification types
hyper-vm        -> typed VM lifecycle transitions
```

## Required runtime path

```text
Defined capsule
  -> Verified capsule
  -> Prepared VM
  -> Key-release approved VM
  -> Attached VM
  -> Running VM
  -> Stopped VM
  -> Retired VM
```

Each transition should append a receipt. A later controller can export the chain for audit, debugging, and incident review.

## Workstreams

| Workstream | Repo landing zone | First gate |
| --- | --- | --- |
| Firmware posture | `crates/hyper-pn52` | read-only baseline report |
| Boot policy | `crates/hyper-policy` | stale or unsigned policy refused |
| VM capsule security | `crates/hyper-capsule` | unverified manifests cannot run |
| Receipts | `crates/hyper-receipts` | chain verification works |
| VM lifecycle | `crates/hyper-vm` | invalid transition unavailable or rejected |
| Memory isolation | future `hyper-mm` | guest memory plan cannot include host pages |
| Device model | future `hyper-devices` | no passthrough in MVP |
| Virtual storage | `crates/hyper-storage` plus future backend | disk attach requires verified manifest |
| Attestation | future `hyper-attest` | key release request includes measured boot evidence |
| Control plane | future `hyper-control` | local-only API first |

## Build phases

| Phase | Goal | Gate |
| --- | --- | --- |
| V0 | Dummy backend | fake VM can complete lifecycle with receipts |
| V1 | First SVM guest | HLT-loop guest exits cleanly |
| V2 | Console | guest output visible |
| V3 | Virtual disk | read-only block backend validates source hash |
| V4 | Linux boot | kernel reaches initramfs |
| V5 | Encrypted capsule | storage attaches after policy approval |
| V6 | Network | isolated virtual NIC only |
| V7 | Multi-VM | separate memory, storage, and identity |
| V8 | Snapshot | signed snapshot metadata verifies |
| V9 | Attested unlock | changed boot policy blocks key release |
| V10 | Controlled device assignment | explicit policy and IOMMU evidence required |

## Next branch

Add `hyper-mm` and a dummy vCPU backend so V0 can run completely in normal unit tests before PN52 hardware is involved.
