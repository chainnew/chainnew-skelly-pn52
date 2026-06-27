# QRSE Control Plane Architecture

QRSE (quantum-resistant storage encryption) is the control plane that makes
chain.new hyper-slate storage quantum-ready **without touching the sector data
path**. It is specified by PAD-QRSE-001 and implemented host-testable in the
`hyper-qrse` crate, with extensions in `hyper-storage`, `hyper-attest`,
`hyper-receipts`, and the `qrsectl` CLI.

## Doctrine: boring data plane, agile control plane

```text
data plane  (boring)   : AES-256-XTS on the block device, unchanged
control plane (agile)  : algorithm-agile keyslots, hybrid KEK derivation,
                         downgrade-resistant signed manifests, layered key
                         hierarchy, attested key release
```

The cipher protecting bytes on disk is conservative and stable. Everything that
*chooses, derives, wraps, signs, and releases* the keys becomes algorithm-agile.
This is the central design pattern of PAD-QRSE-001 §16: the quantum threat to
storage is a **key-management** problem, not a bulk-cipher problem, so AES-256-XTS
stays put and the PQC work happens entirely above it. No post-quantum primitive
ever sits in the per-sector hot path.

`hyper-qrse` is a plain `std` library with `#![forbid(unsafe_code)]`. Every
post-quantum primitive sits behind the `crypto::Kem` / `crypto::Signer` /
`crypto::Verifier` traits, so a real RustCrypto ML-KEM / ML-DSA implementation
drops in later without changing a single caller.

## Hybrid KEK combiner (§9.4)

The key-encryption key is derived by combining a classical and a post-quantum
shared secret. Implemented in `hyper-qrse::combiner::hybrid_combine`:

```text
KEK = HKDF-SHA384(
        salt = SHA384(transcript),
        IKM  = ss_classical || ss_pqc,
        info = "storage-unlock-v1" || context
      )
```

The construction is hybrid by composition: the KEK is secure as long as *either*
leg holds. X25519 protects against a classical adversary today; ML-KEM protects
against a future cryptographically-relevant quantum computer harvesting today's
ciphertext. Rules enforced in the combiner:

- **Fail closed** if either required shared secret is missing or all-zero
  (`SharedSecret::is_live`); a dead leg returns `CryptoError::EmptySharedSecret`,
  never a degraded single-leg KEK.
- **Context binding.** `CombinerContext` (volume_id, device_id, policy_id,
  policy_version, algorithm_suite, boot_measurement) is length-prefix encoded and
  folded into the HKDF `info`. Change any of it and the KEK changes — this is how
  rebinding and downgrade attacks are defeated.
- **Suite binding.** The `KemSuite` canonical string (`x25519+ml-kem-768+
  hkdf-sha384`) is bound into `info`; a different suite is a different KEK.
- **Leg order matters.** `ss_classical || ss_pqc` is not interchangeable with the
  reverse, so the two legs cannot be swapped.
- **Zeroization.** The derived `Kek` and the intermediate IKM are zeroized on
  drop; `Kek` never prints its bytes and is read only through `Kek::expose`.

Two profiles ship: `KemSuite::transition_768` (X25519 + ML-KEM-768, the default
commercial transition profile) and `KemSuite::high_assurance_1024` (X25519 +
ML-KEM-1024, CNSA-leaning).

## Algorithm-agile keyslots (qrsd-v1)

A `qrsd-v1` manifest (`format: "qrsd-v1"`, PAD §9.5, schema in
`manifests/qrsd-v1.schema.json`) carries a `key_hierarchy.keyslots[]` array where
each slot names its own unlock method, so a volume can be unlocked by any of
several independent paths:

```text
argon2id     : passphrase / recovery, KDF-derived
tpm2         : TPM2 PCR-policy sealed (PCR0/PCR7/PCR11 boot state)
hybrid-kms   : remote release, hybrid X25519 + ML-KEM KEK (the combiner above)
threshold    : k-of-n split across custodians / shares
```

Slots are additive and independently revocable. New algorithms are added as new
slot types behind the same traits — the manifest format does not change.

## Key hierarchy (§9.3)

```text
Org root  ->  Tenant  ->  Device  ->  KMS  ->  VMK  ->  DEK
```

The **DEK** encrypts sectors (AES-256-XTS, data plane). The **VMK** wraps the DEK
and is itself wrapped per keyslot by a KEK. The hybrid-kms keyslot's KEK is
produced by the combiner from a device/KMS leg pair; the org/tenant/device tiers
scope authority and revocation upward. Rotating an upper tier re-wraps without
re-encrypting bulk data, because only the wrapping keys change — the DEK and the
sectors it protects are untouched.

## Downgrade protection

PAD-QRSE-001 treats hybrid-to-classical downgrade as a primary attack. Three
independent mechanisms:

1. **Monotonic policy version.** `policy_version` is bound into the KEK context
   and the manifest; a rollback to an older policy is a different (wrong) KEK and
   is rejected by `boot_policy.rollback_protection`.
2. **Suite binding.** The negotiated `KemSuite` is authenticated in the combiner
   `info`; an attacker cannot silently substitute a weaker suite.
3. **Reject classical-only.** Once a volume's policy marks hybrid as required, a
   classical-only unlock is refused — the missing PQC leg fails the combiner
   closed rather than producing a usable single-leg KEK.

## Signed manifests (ML-DSA / SLH-DSA)

Manifests are signed with detached post-quantum signatures via `crypto::Signer`:
ML-DSA-65 for online manifest/boot/disk signing, SLH-DSA-128s for offline /
recovery roots where the larger signature is acceptable (PAD §16.3). ECDSA-P384
is available as a transition-only classical signer. Verification routes through
`crypto::Verifier`; a manifest with a wrong key_id, wrong algorithm, or tampered
body fails verification closed. The `signatures[]` array allows multiple
detached signatures (e.g. classical + PQC during transition).

## Attested hybrid unlock flow

```text
1. Boot measures firmware/kernel/policy into PcrBank (PCR0/PCR7/PCR11).
2. qrsectl reads the signed qrsd-v1 manifest; verify ML-DSA-65 signature.
3. KmsSimulator.evaluate(KeyReleaseRequest) checks KmsPolicy against the
   boot measurement + inputs_hash -> KeyReleaseDecision (allow/deny).
4. On allow, the hybrid-kms keyslot yields ss_classical + ss_pqc.
5. hybrid_combine binds {volume_id, device, policy_id, policy_version,
   suite, boot_measurement} into the KEK; mismatch => fail closed.
6. KEK unwraps VMK -> DEK; AES-256-XTS mounts the volume.
7. Every step appends a hash-chained ReceiptChain entry (audit spine).
```

Boot measurement is bound at step 5: a volume sealed to one boot state will not
unlock under a different one. Deny decisions, signature failures, and dead-leg
failures are all logged and fail closed.

## Crate map

| Crate            | Role in QRSE                                              |
| ---------------- | -------------------------------------------------------- |
| `hyper-qrse`     | crypto traits, hybrid combiner, keyslots, manifests      |
| `hyper-storage`  | volume/DEK metadata, hybrid wrapping model               |
| `hyper-attest`   | PcrBank, BootMeasurement, KmsSimulator, attested release |
| `hyper-receipts` | hash-chained ReceiptChain audit spine                    |
| `qrsectl`        | operator CLI over manifests + unlock flow                |

## PAD maturity mapping

- **Level 1 (deployable today):** algorithm-agile keyslots, signed manifests,
  layered key hierarchy, downgrade protection — modelled and **host-testable
  here**.
- **Level 2 (hybrid transitional):** hybrid X25519 + ML-KEM KEK combiner with
  context/suite binding and attested release — modelled and **host-testable
  here** with deterministic stand-in primitives.
- **Level 3 (future / FIPS):** real RustCrypto ML-KEM / ML-DSA implementations
  and FIPS-validated modules. These swap in behind the `Kem` / `Signer` /
  `Verifier` traits with no caller changes. The bundled `Deterministic*`
  primitives are reproducible test vectors only and must never protect real
  secrets.
