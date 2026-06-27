# Storage and Post-Quantum Control Plane

Bulk data encryption stays classical and conservative:

```text
AES-256-XTS for mutable block devices
optional dm-verity/fs-verity for immutable roots/images
optional dm-crypt AEAD + dm-integrity for selected high-integrity volumes
```

PQC belongs in the key-management and signing control plane:

```text
DEK -> VMK -> local keyslot / TPM keyslot / recovery keyslot / remote KMS keyslot
remote KMS keyslot := HKDF-SHA384(X25519-or-P256 shared secret || ML-KEM shared secret)
boot/storage manifests := classical signature now + ML-DSA signature during transition
recovery/offline root := optional SLH-DSA detached signature where size is acceptable
```

## Hybrid unwrap transcript

```text
context = volume_id || device_id || tenant_id || boot_manifest_hash || policy_version || alg_suite
KEK = HKDF-SHA384(
  salt = SHA384(transcript),
  ikm  = classical_shared_secret || ml_kem_shared_secret,
  info = "chainnew-hyper-slate-storage-unlock-v1" || context
)
```

Hard rule: reject downgrade from hybrid to classical-only after a volume policy marks hybrid as required.
