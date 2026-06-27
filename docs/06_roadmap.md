# Roadmap

## Sprint 0 — proof inventory

- host-side `hyper-pn52-doctor` ingests Stage B tarball;
- emits JSON report;
- verifies SVM/IOMMU/fTPM/Secure Boot state;
- validates no destructive prerequisites are accidentally marked done.

## Sprint 1 — UEFI probe

- GOP text;
- memory map;
- ACPI RSDP/XSDT signatures;
- SMBIOS type 0/1/2/4/17;
- CPUID SVM and invariant TSC bits.

## Sprint 2 — no_std kernel

- `ExitBootServices()`;
- GDT/IDT;
- identity + higher-half mapping;
- APIC/timer tick;
- PCI walker.

## Sprint 3 — SVM first light

- EFER.SVME;
- VM_HSAVE_PA;
- VMCB layout test;
- first HLT-loop guest;
- log VMEXIT.

## Sprint 4 — NPT + IOMMU

- NPT identity map;
- IVRS parse;
- DMA remap domains;
- deny unknown devices by default.

## Sprint 5 — storage skeleton

- NVMe read-only;
- VM disk manifest;
- virtio-blk emulation skeleton;
- encrypted VM capsule model.

## Sprint 6 — measured/PQ control plane

- boot manifest hash;
- KMS simulator;
- hybrid classical + ML-KEM metadata placeholders;
- ML-DSA detached manifest signature placeholder.

## Sprint 7 — slate-runtime V0

- 12-layer virtual framework, host-testable, no hardware required;
- new crates: `hyper-mm`, `hyper-vcpu`, `hyper-devices`, `hyper-virtio`,
  `hyper-net`, `hyper-capsule`, `hyper-policy`, `hyper-attest`, `hyper-receipts`,
  `hyper-vm`, `hyper-control`;
- typed VM lifecycle (`Defined → Verified → Prepared → Unlocked → Attached →
  Running`) with a per-transition tamper-evident receipt chain;
- deny-by-default everywhere: memory (S2), VM exits (S3), device routing,
  egress, policy, attested key release;
- `.chainvm` capsule layout + `Untrusted → Verified → LaunchApproval` funnel;
- firmware baseline schema (`manifests/firmware-baseline.schema.json`);
- V0..V10 acceptance gates defined in `docs/09_virtual_framework.md`;
- V0 implemented + host-testable; V1+ require the x86/SVM substrate on PN52.
