# Threat Model

## Protect against first

- stolen powered-off device;
- raw disk/VM image theft;
- cloud snapshot theft;
- evil-maid bootloader/initramfs replacement;
- rollback to old signed boot policy;
- malicious recovery-key access;
- device passthrough DMA escaping guest boundaries.

## Do not claim protection against yet

- malicious PSP/AGESA/firmware vendor;
- compromised SMM;
- runtime host compromise after unlock;
- cold-boot/key-in-RAM extraction;
- malicious physical attacker with unlimited bench time;
- full side-channel resistance.

## Controls

- AES-256-XTS at rest;
- signed and measured boot manifests;
- TPM/fTPM PCR reports;
- IOMMU for DMA domains;
- per-VM/per-volume DEKs;
- threshold recovery for high-value keys;
- tamper-evident audit receipts.
