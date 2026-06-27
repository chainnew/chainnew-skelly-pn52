# Virtual Framework Integration Plan

This document defines how the PN52 Type-1 slate should host the chain.new virtual framework without collapsing security boundaries.

## Layer model

```text
Firmware / UEFI / TPM / Secure Boot
        ↓
hyper-uefi-probe.efi
        ↓
hyper-slate no_std kernel
        ↓
VM root partition
        ↓
policy engine + attestation + device model
        ↓
.chain capsule store
        ↓
guest VMs and product workloads
```

## First integration target

The first virtual-framework target is not a general-purpose cloud stack. It is a controlled lab root that can boot one deliberately boring guest and prove:

1. CPU virtualization enters and exits cleanly.
2. Nested page translation is present but minimally permissive.
3. Interrupts are explicit and observable.
4. DMA is denied until AMD-Vi/IOMMU policy is known.
5. Storage is read-only until the manifest and key-release model are proven.
6. Every privileged transition emits a receipt.

## VM root responsibilities

The VM root is the first privileged management layer above the bare hypervisor. It owns:

- guest lifecycle state;
- VM manifest parsing;
- virtual CPU scheduling policy;
- virtual device inventory;
- debug console routing;
- attestation challenge and response;
- storage unlock requests;
- crash capture and closeout receipts.

The VM root must not own raw firmware writes, SPI mutation, PSP/AGESA changes, or hidden host persistence.

## Guest capsule contract

A guest capsule is allowed to launch only when all of these are true:

```text
capsule_hash matches manifest
manifest version is not rolled back
signature chain is accepted
boot measurements match accepted PCR policy
storage unlock policy returns allow
IOMMU/device policy has no unresolved deny-by-default gaps
```

## Minimal guest sequence

1. `guest-zero`: HLT-loop guest. Proves VMRUN/VMEXIT and register save/restore.
2. `guest-one`: tiny serial-console toy kernel. Proves memory map, console, and exit routing.
3. `guest-two`: Linux bzImage or UKI loader. Proves real boot path.
4. `guest-three`: encrypted `.chain` capsule. Proves measured unlock and policy receipt chain.
5. `guest-four`: tyle.chain.new / hyper.chain.new service guest. Proves product integration.

## Device-model bias

Start with emulated or paravirtual devices before attempting pass-through.

Recommended order:

1. serial console;
2. virtio-mmio or PCI discovery shim;
3. read-only block device;
4. synthetic network interface;
5. timer source;
6. interrupt controller refinement;
7. carefully scoped PCI passthrough only after AMD-Vi is proven.

## Receipt model

Every launch should produce a machine-readable receipt:

```json
{
  "schema_version": 1,
  "vm_id": "guest-zero",
  "capsule_hash": "sha256:...",
  "boot_policy_id": "lab-default",
  "measurements": [],
  "devices": [],
  "decision": "allow",
  "reason": "lab_hlt_guest"
}
```

## Non-negotiables

- Fail closed when measurements are missing.
- Deny DMA until IOMMU state is known.
- Never hide firmware mutation behind a convenience command.
- Keep crypto/key-release logic separate from sector I/O performance work.
- Treat the PN52 as a lab board until recovery, flashing, serial, and SPI read-back are boring.
