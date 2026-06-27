# Boot Chain Plan

## Phase A — lab boot

```text
UEFI firmware -> UEFI Shell -> hyper-uefi-probe.efi -> no_std kernel
```

No Secure Boot requirements while the skeleton is unstable.

## Phase B — controlled Secure Boot

```text
UEFI firmware -> enrolled lab key -> signed hyper-slate.efi -> no_std kernel
```

Custom PK/KEK/db only after recovery path and rollback path are tested.

## Phase C — measured boot

```text
UEFI firmware -> TPM PCR0/PCR7
hyper-slate.efi -> PCR11 boot manifest extend
KMS/verifier -> key release only for accepted manifest/version
```

PCR policy is a product feature, not a bring-up dependency.
