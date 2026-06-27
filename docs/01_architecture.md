# Architecture

```text
ASUS Vendor Firmware / AMI Aptio / AGESA / PSP / EC
        |
        | UEFI Boot Manager launches signed or unsigned lab app
        v
hyper-uefi-probe.efi
        |  collects GOP, memory map, ACPI RSDP, SMBIOS, PCI config table
        |  optional: measures boot manifest to TPM PCR later
        v
ExitBootServices()
        v
hyper-slate no_std kernel
        |-- GDT / IDT / paging / APIC / HPET / TSC
        |-- PCI ECAM walker + MSI/MSI-X discovery
        |-- AMD SVM: EFER.SVME, VM_HSAVE_PA, VMCB, VMRUN
        |-- NPT: guest physical -> host physical translations
        |-- AMD-Vi: IVRS parsing, DMA remapping domains
        |-- storage plane: NVMe read-only first, virtio-blk later
        |-- console plane: GOP framebuffer + optional UART
        v
Guests
        |-- stage 0: tiny HLT-loop guest
        |-- stage 1: toy kernel guest
        |-- stage 2: Linux guest via bzImage/UKI loader
        |-- stage 3: encrypted VM capsule unlocked after attestation
```

The design has two planes:

1. **Hypervisor substrate plane** — CPU, memory, interrupts, devices, SVM, NPT, IOMMU.
2. **Storage security control plane** — manifests, key hierarchy, LUKS2/TPM2 integration, remote unlock, PQC/hybrid wrappers.

Keep these separate. Do not let cryptographic experiments destabilize the hypervisor bring-up path.
