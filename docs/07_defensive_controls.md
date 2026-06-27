# Defensive Controls Matrix

This repo must treat threat modelling as part of engineering, not a document added at the end.

## Control philosophy

The PN52 slate should be safe by construction:

- default deny;
- explicit allow lists;
- measured transitions;
- reproducible artifacts;
- signed manifests;
- read-only firmware tooling by default;
- deterministic recovery paths;
- receipts for every privileged action.

## Threat classes

| Threat class | Example | Default mitigation |
| --- | --- | --- |
| Firmware tampering | SPI, UEFI variable, boot option mutation | read-only scripts, external recovery prerequisites, signed boot artifacts |
| Boot rollback | older vulnerable slate or policy | monotonic policy version, signed manifest, measured boot checks |
| DMA compromise | device or firmware DMA into VM root | AMD-Vi/IOMMU deny-by-default domains |
| Guest escape | malformed device request or VMEXIT handling bug | tiny device model first, fuzzable parsers, no broad passthrough |
| Key theft | VMK/KEK released to bad boot state | TPM PCR policy, remote attestation, threshold recovery path |
| Supply-chain drift | untracked firmware/toolchain/image changes | hashes, pinned manifests, artifact receipts |
| Operator error | accidental flash/write command | explicit safety gates, dry-run default, destructive command separation |
| Debug backdoor | serial/GDB console left exposed | build profile gating, visible debug receipts, no hidden listeners |

## Mandatory controls before real guests

1. Boot artifact hash manifest.
2. Reproducible UEFI probe build notes.
3. PN52 inventory report from Linux live USB.
4. ACPI IVRS presence and IOMMU-group capture.
5. Secure Boot state capture.
6. TPM PCR bank capture.
7. Read-only SPI dump verification, only if lab recovery is ready.
8. VMEXIT event log for guest-zero.
9. Panic/crash capture path.
10. Operator-visible deny reason for every failed launch.

## Hardware mutation rule

No command in this repo should mutate SPI flash, PSP, AGESA, EC firmware, boot firmware, Secure Boot keys, NVRAM, TPM NV indices, or production disks unless the repository has a dedicated safety approval flow and recovery proof.

Until then, mutation belongs outside this repo.

## Review gates

Every PR that touches low-level boot, SVM, NPT, IOMMU, storage unlock, or firmware-adjacent logic should answer:

```text
What can this brick?
What can this bypass?
What can this leak?
What does it measure?
What does it refuse to do?
How do we recover if the assumption is wrong?
```
