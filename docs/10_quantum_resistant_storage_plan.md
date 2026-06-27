# Quantum-Resistant Storage Plan

The storage plan is intentionally boring in the data path and agile in the control path.

## Core rule

```text
Bulk disk data stays on AES-256-XTS.
Post-quantum work belongs in key wrapping, manifests, attestation, transport, recovery, and policy.
```

## Immediate baseline

| Area | Default |
| --- | --- |
| Sector cipher | AES-256-XTS |
| Mutable-disk integrity | manifest/hash first; authenticated mutable blocks later |
| Immutable images | signed manifest, optional verity-style hash tree later |
| Volume metadata | versioned, signed, rollback-aware |
| Key release | policy-bound and receipt-backed |
| Remote unlock | hybrid-ready design, not required for lab boot |
| Signatures | classical now, transition fields for PQ signatures |

## Hybrid control-plane target

```text
classical shared secret: X25519 or P-256
post-quantum shared secret: ML-KEM-768 or ML-KEM-1024
combiner: HKDF-SHA384
context: vm_id | device_id | capsule_hash | policy_version | algorithm_suite
```

Rules:

- fail closed if a required component is missing;
- bind the algorithm suite into the derived key context;
- record the accepted suite in a receipt;
- reject rollback to weaker metadata unless a dedicated recovery policy allows it;
- never put ML-KEM or signatures in the sector I/O hot path.

## Repo landing zones

| Requirement | Landing zone |
| --- | --- |
| disk/key metadata | `crates/hyper-storage` |
| VM capsule hash/signature binding | `crates/hyper-capsule` |
| launch and key-release receipts | `crates/hyper-receipts` |
| policy decision | `crates/hyper-policy` |
| KMS/attestation request model | future `hyper-attest` |
| storage backend | future `hyper-vblk` or `hyper-storage-backend` |

## Prototype metadata shape

```json
{
  "format": "chain.storage_policy.v1",
  "volume_id": "dev-linux-root",
  "data_plane": {
    "cipher": "aes-256-xts",
    "sector_size": 4096,
    "integrity": "manifest_hash_only"
  },
  "key_hierarchy": {
    "volume_master_key_version": 1,
    "active_dek_version": 1,
    "keyslots": [
      {
        "slot": 0,
        "type": "local_dev",
        "status": "active"
      },
      {
        "slot": 1,
        "type": "hybrid_remote_kms",
        "status": "planned",
        "kem": {
          "classical": "x25519",
          "pqc": "ml-kem-768",
          "combiner": "hkdf-sha384"
        }
      }
    ]
  }
}
```

## Acceptance gates

1. A `.chainvm` disk cannot attach without a verified capsule manifest.
2. A key-release receipt is created before an encrypted disk is attached.
3. Algorithm suite is explicit in storage metadata.
4. Metadata version is monotonic.
5. Legacy or transition suites are visible in receipts.
6. Disk crypto context never stores long-lived plaintext in serialized metadata.
