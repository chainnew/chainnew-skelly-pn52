# chain.new hyper-slate — PN52 Type-1 Rust Hypervisor Skeleton

This is a starter skeleton for a **Rust-first Type-1 hypervisor substrate** targeting the
ASUS ExpertCenter PN52 / AMD Cezanne platform. It is intentionally conservative:

- boot as a **Rust UEFI application** first;
- rely on vendor firmware for DRAM/PSP/EC/GOP/NVMe early init;
- transition to a `no_std` Rust kernel after `ExitBootServices()`;
- bring up AMD SVM, NPT, AMD-Vi/IOMMU, PCI, NVMe, and xHCI in layers;
- keep disk encryption and key-release architecture as a separate but integrated control plane;
- add post-quantum/hybrid key-management metadata without putting PQC in the sector data path.

## What this is

A working repository shape, roadmap, schemas, scripts, and Rust module skeleton that an engineering
team can turn into a real project.

## What this is not

This is **not** a production hypervisor, not a firmware replacement, not a BIOS flasher, and not a
cryptographic module. It deliberately avoids SPI writes and PSP/AGESA/EC modification.

## Fast path

```bash
# 1. Review the docs.
less docs/01_architecture.md
less docs/05_lab_safety.md
less docs/06_virtual_framework.md
less docs/07_defensive_controls.md
less docs/09_framework_build_plan.md
less docs/10_quantum_resistant_storage_plan.md

# 2. Install Rust targets.
rustup target add x86_64-unknown-uefi
rustup target add x86_64-unknown-none

# 3. Build host tooling.
cargo build -p hyper-pn52-doctor

# 4. Check the first virtual framework slice.
cargo test -p hyper-receipts
cargo test -p hyper-policy
cargo test -p hyper-capsule
cargo check -p hyper-vm

# 5. Build UEFI probe once dependencies are fetched.
cargo build -p hyper-uefi-probe --target x86_64-unknown-uefi

# 6. Collect PN52 ground truth from Linux live USB.
sudo scripts/collect_stage_b.sh /mnt/usb/pn52-research

# 7. Read-only SPI collection only after lab rules are met.
sudo scripts/dump_spi_readonly.sh /mnt/usb/pn52-research/firmware
```

## Repo layout

```text
apps/
  hyper-pn52-doctor/        host-side inventory/security/report CLI
  hyper-uefi-probe/         Rust UEFI probe app
  hyper-slate-kms-prototype/placeholder KMS/attestation simulator
crates/
  hyper-slate-core/         shared manifests, key hierarchy, policy types
  hyper-pn52/               PN52 inventory parsers and report model
  hyper-x86/                no_std x86 substrate: CPU, paging, APIC, PCI
  hyper-amd-svm/            no_std AMD SVM/VMCB/NPT/IOMMU skeleton
  hyper-storage/            encrypted-storage metadata and PQC/hybrid wrapping model
  hyper-receipts/           hash-chained audit receipt primitives
  hyper-policy/             launch policy decisions and deny reasons
  hyper-capsule/            .chainvm untrusted/verified manifest split
  hyper-vm/                 typed VM lifecycle transitions
docs/                       architecture, roadmap, threat model, test plan
manifests/                  JSON schemas and sample boot/volume/VM manifests
scripts/                    lab collection, QEMU, LUKS examples, hashing
```

## Engineering mantra

```text
First prove. Then boot. Then virtualize. Then encrypt. Then attest. Then scale.
```
