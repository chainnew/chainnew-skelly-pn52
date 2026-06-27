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

# 2. Install Rust targets.
rustup target add x86_64-unknown-uefi
rustup target add x86_64-unknown-none

# 3. Build host tooling.
cargo build -p hyper-pn52-doctor

# 4. Build UEFI probe once dependencies are fetched.
cargo build -p hyper-uefi-probe --target x86_64-unknown-uefi

# 5. Collect PN52 ground truth from Linux live USB.
sudo scripts/collect_stage_b.sh /mnt/usb/pn52-research

# 6. Read-only SPI collection only after lab rules are met.
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
docs/                       architecture, roadmap, threat model, test plan
manifests/                  JSON schemas and sample boot/volume/VM manifests
scripts/                    lab collection, QEMU, LUKS examples, hashing
```

## Slate Runtime (virtual framework)

The `slate-runtime` is the host-testable virtual framework that models the full
VM lifecycle before it touches AMD SVM on real hardware. It is a 12-layer stack
of plain `std` crates (deny-by-default, fail-closed, typed lifecycle,
hash-chained receipts). V0 (this commit) is implemented and host-testable; V1+
bind the same contracts to the `hyper-x86` / `hyper-amd-svm` substrate on a real
PN52. See `docs/09_virtual_framework.md`.

```text
crates/
  hyper-mm/                 guest memory model + NPT orchestration (S2 invariants)
  hyper-vcpu/               vCPU runtime, scheduler, fail-closed VM-exit dispatch
  hyper-devices/            virtual device bus (MMIO/port routing, deny-by-default)
  hyper-virtio/             virtio device models (console, blk, rng, net, pvclock)
  hyper-net/                policy-first virtual network (egress default-deny)
  hyper-capsule/            capsule manifest parse + Untrusted/Verified split
  hyper-policy/             deny-by-default policy engine + policy-as-code
  hyper-attest/             TPM/fTPM PCR capture, KMS unlock sim, attested release
  hyper-receipts/           audit spine: hash-chained receipts + security log
  hyper-vm/                 keystone: VmCapsule + typed lifecycle state machine
  hyper-control/            control plane / orchestration over lifecycle + audit
manifests/
  firmware-baseline.schema.json   captured PN52 firmware ground truth
```

## QRSE control plane

QRSE (quantum-resistant storage encryption) is the algorithm-agile storage
control plane (PAD-QRSE-001). Doctrine: the data plane stays boring
(AES-256-XTS), the control plane becomes quantum-ready — a hybrid
HKDF-SHA384(X25519 ‖ ML-KEM) KEK combiner with context/suite binding,
algorithm-agile `qrsd-v1` keyslots (argon2id / tpm2 / hybrid-kms / threshold),
an Org→Tenant→Device→KMS→VMK→DEK key hierarchy, downgrade protection
(monotonic version + suite binding + reject classical-only), and ML-DSA /
SLH-DSA signed manifests released under attestation. Level 1 + Level 2 are
host-testable here; real RustCrypto ML-KEM/ML-DSA and FIPS validation are
Level 3, swappable behind the `Kem`/`Signer`/`Verifier` traits.

```text
crates/
  hyper-qrse/               crypto traits, hybrid KEK combiner, keyslots, manifests
apps/
  qrsectl/                  operator CLI over qrsd-v1 manifests + unlock flow
manifests/
  qrsd-v1.schema.json       QRSE disk manifest schema (PAD §9.5)
  sample.qrsd-v1.json       filled example (X25519+ML-KEM-768, ML-DSA-65, AES-256-XTS)
docs/
  10_qrse_architecture.md   QRSE control-plane doctrine and flows
```

## Engineering mantra

```text
First prove. Then boot. Then virtualize. Then encrypt. Then attest. Then scale.
```
