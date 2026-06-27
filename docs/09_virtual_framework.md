# Slate Runtime — Virtual Framework

The **slate-runtime** is the virtual (host-testable) framework layer of
chain.new hyper-slate. It models the full VM lifecycle — capsule verification,
memory, vCPU dispatch, devices, network, attestation, policy, audit — as plain
`std` Rust crates so that the *doctrine* (deny-by-default, fail-closed, typed
lifecycle, tamper-evident receipts) can be proven from host unit tests **before**
any of it touches AMD SVM on real PN52 hardware.

> **V0 status (this commit):** the entire virtual framework is implemented and
> host-testable. It does **not** require the PN52, AMD-V/SVM, NPT, or a real
> TPM. V1+ bind these same contracts to the `hyper-x86` / `hyper-amd-svm`
> substrate on real hardware. The virtual framework is the spec; the substrate
> is the implementation that must satisfy it.

First prove. Then boot. Then virtualize. Then encrypt. Then attest. Then scale.

## The 12-layer stack

The runtime is a layered stack. Each layer is a crate (the substrate is two);
dependencies flow strictly **upward** (no cycles). Lower layers know nothing of
higher ones.

```text
 L12  hyper-control     control plane / orchestration, admission, fleet API
 L11  hyper-vm          keystone: VmCapsule + typed lifecycle state machine
 L10  hyper-receipts    audit spine: hash-chained receipts + security log
 L9   hyper-attest      TPM/fTPM PCR capture, KMS unlock sim, attested release
 L8   hyper-policy      deny-by-default policy engine + policy-as-code document
 L7   hyper-capsule     capsule manifest parse + Untrusted/Verified split
 L6   hyper-net         policy-first virtual network (egress default-deny)
 L5   hyper-virtio      virtio device models (console, blk, rng, net, pvclock)
 L4   hyper-devices     virtual device bus (MMIO/port routing, deny-by-default)
 L3   hyper-vcpu        vCPU runtime, scheduler, fail-closed VM-exit dispatch
 L2   hyper-mm          guest memory model + NPT orchestration (S2 invariants)
 L1   hyper-x86 /       no_std x86 substrate + AMD SVM/VMCB/NPT/IOMMU
      hyper-amd-svm     (real hardware; out of scope for V0 host tests)
```

### Crates and dependency direction

| Layer | Crate | Depends on (in-tree) | Role |
|------:|-------|----------------------|------|
| L2 | `hyper-mm` | — | Guest memory + NPT model; enforces the S2 invariants (no W+X pages, no overlap with the reserved host range, zeroize-before-assign). Exports `VmId`. |
| L3 | `hyper-vcpu` | `hyper-mm` | vCPU lifecycle, round-robin scheduler, VM-exit dispatcher. Unknown / un-allowlisted exits **terminate** the guest (S3). VMEXIT-storm throttle (S13). |
| L4 | `hyper-devices` | `hyper-mm` | Virtual device bus. MMIO/port accesses route to a registered `VirtualDevice` only when an explicit route exists; otherwise fail closed. |
| L5 | `hyper-virtio` | `hyper-devices`, `hyper-mm` | Deterministic virtio device models: `VirtioConsole`, `VirtioBlk` (integrity-checked, read-only), `VirtioRng`, `VirtioNet`, `PvClock`. |
| L6 | `hyper-net` | `hyper-policy` | Virtual network. Egress default-deny; ingress always deny-by-default; `None`/`Isolated` deny all egress. Identity (MAC/IP) is content-hash derived. |
| L7 | `hyper-capsule` | `hyper-slate-core` | Capsule manifest parsing with a type-level `Untrusted`→`Verified` split. The only path to a `VerifiedManifest` is `verify`; the only path to a `LaunchApproval` is `check_launch`. |
| L8 | `hyper-policy` | `hyper-slate-core` | Policy-as-code document + deny-by-default `PolicyEngine`. Begins at "deny"; only a fully satisfied condition set yields `Allow` + a `PolicyReceipt`. Deliberately does **not** depend on `hyper-receipts` (cycle avoidance). |
| L9 | `hyper-attest` | `hyper-slate-core`, `hyper-receipts` | fTPM PCR banks, KMS unlock **simulator**, attested key release. A modified boot policy blocks release (V9). Writes `key_release` receipts. |
| L10 | `hyper-receipts` | — | Two independent SHA-384 hash chains: `ReceiptChain` (one receipt per policy-relevant decision) and `SecurityLog` (severity-tagged events). Deterministic; `verify` fails closed. |
| L11 | `hyper-vm` | `hyper-vcpu`, `hyper-mm`, `hyper-devices`, `hyper-policy`, `hyper-capsule`, `hyper-receipts`, `hyper-attest` | Keystone. `VmCapsule` + the typed lifecycle. No `launch_guest()`; the only way to a running guest is to walk the typed states. Every transition appends a receipt. |
| L12 | `hyper-control` | `hyper-vm`, `hyper-policy`, `hyper-receipts`, `hyper-capsule`, `hyper-attest` | Control plane: admission, orchestration, fleet-facing API over the lifecycle and audit spine. |

Doctrine notes that hold across every layer:

- **Deny-by-default / fail-closed.** Memory mappings, device routes, network
  flows, VM exits, policy decisions, and key releases all start at "deny". Only
  an explicit, fully satisfied condition set produces an allow.
- **Determinism.** All identifiers are counter- or content-hash derived. No
  randomness, no `uuid`, no system clock anywhere in the runtime.
- **No `unsafe`.** Every crate begins with `#![forbid(unsafe_code)]`.
- **Hashing.** SHA-384, formatted `"sha384:<hex>"`, via a shared helper. The
  receipt spine and all higher layers share one canonical formatting.

## VM lifecycle state machine

`hyper-vm` encodes the lifecycle in the Rust **type system**: each state is a
distinct struct (`VmHandle`, `VerifiedVm`, `PreparedVm`, `UnlockedVm`,
`AttachedVm`, `RunnableVm`/`RunningVm`, `PausedVm`, `StoppedVm`). Calling `run`
before `unlock`/`attach` does not compile. Holding a `VerifiedManifest` (whose
only constructor is `hyper_capsule::verify`) makes an unverified launch
unrepresentable.

```text
                 verify (manifest + launch gate)
   [Defined] ───────────────────────────────────► [Verified]
                 prepare (allocate guest memory, S2 invariants)
   [Verified] ──────────────────────────────────► [Prepared]
                 unlock (attested key release via KMS sim)
   [Prepared] ──────────────────────────────────► [Unlocked]
                 attach (wire vCPUs + devices + network)
   [Unlocked] ──────────────────────────────────► [Attached]
                 run
   [Attached] ──────────────────────────────────► [Running]
                 pause / resume
   [Running]  ◄────────────────────────────────► [Paused]
                 stop
   [Running] ───────────────────────────────────► [Stopped] ──► [Destroyed]

   Any state ─(invariant / gate failure)─► [Failed] | [Quarantined]
```

- Every transition appends a tamper-evident receipt onto the runtime's
  `ReceiptChain`; the chain `verify`s end-to-end.
- Each gate is fail-closed: a failed manifest verification, a failed S2 memory
  invariant, or a denied key release does not advance the state — it produces
  `Failed`/`Quarantined`, never a silently-running guest.
- `Defined → Verified` is the **launch gate** (capsule + policy). `Prepared →
  Unlocked` is the **attestation gate** (PCRs + boot-policy hash). `Unlocked →
  Attached` wires the device/network graph under deny-by-default routing.

## The `.chainvm` capsule layout

A `.chainvm` capsule is the signed, self-describing unit the runtime admits. It
binds a manifest, an encrypted image, and detached signatures so the launch gate
can verify everything before any memory is allocated.

```text
example.chainvm
├── manifest.json        chain.vm_capsule.v1 — the signed description (below)
├── image.bin            guest disk image (cipher + integrity per `storage`)
├── boot/                firmware profile + cmdline references (boot_policy_version)
└── signatures/          detached signatures over the canonical manifest bytes
    ├── ecdsa-p384.sig   classical (transition)
    ├── ed25519.sig      classical (optional)
    └── ml-dsa-65.sig    post-quantum (future / hybrid)
```

`manifest.json` (`chain.vm_capsule.v1`) carries:

- `schema` — must equal `chain.vm_capsule.v1`.
- `vm_id`, `tenant_id` — stable identifiers.
- `image_hash`, `disk_hash` — `"sha384:<hex>"` content hashes; the launch gate
  checks `image_hash` against the expected value.
- `hypervisor_min_version`, `boot_policy_version` — rollback / minimum-version
  gates.
- `devices` { `passthrough`, `virtio` }, `memory` { `max_mb`, `allow_balloon` },
  `cpu` { `vcpus`, `cpuid_profile` }, `network` { `mode`, `egress_policy` },
  `storage` { `cipher`, `integrity`, `key_version` }.
- `signatures[]` — `{ alg, key_id, status }`, where `alg ∈ { ecdsa-p384,
  ed25519, ml-dsa-65 }`.

Verification is a one-way funnel: `parse_manifest` → `UntrustedManifest`,
`AllowlistVerifier::verify` → `VerifiedManifest`, `check_launch` →
`LaunchApproval`. There is no other constructor for the verified types, so an
unverified or unsigned capsule cannot enter the lifecycle.

## V0..V10 roadmap with acceptance gates

V0 is the virtual framework in this commit (host-testable). V1 onward bind the
same contracts to the AMD SVM substrate on real PN52 hardware; each Vn carries
an explicit, testable acceptance gate.

| Version | Theme | Acceptance gate |
|--------:|-------|-----------------|
| **V0** | Virtual framework (this commit) | All 12 layers compile; every deny/fail-closed path has a passing host unit test; `cargo test` green with `#![forbid(unsafe_code)]`, no randomness, no clocks. |
| **V1** | SVM first light (hardware) | EFER.SVME set, `VM_HSAVE_PA` configured, VMCB built, first HLT-loop guest runs and the first VMEXIT is logged on the PN52. |
| **V2** | Virtio console | Guest byte output is captured deterministically through `VirtioConsole` (matches the V0 `hyper-virtio` console model). |
| **V3** | Virtio-blk integrity | Read-only block reads verify against the expected `"sha384:<hex>"`; a single flipped backend byte fails the read **closed**. |
| **V4** | NPT memory invariants | On hardware, NPT enforces no writable+executable page, no mapping overlapping the reserved host range, and zeroize-before-assign (S2). |
| **V5** | Device bus + IOMMU | Virtual device bus routes only registered MMIO/ports; AMD-Vi assigns only allowlisted devices; unknown devices are denied by default. |
| **V6** | Virtual network | Egress is default-deny; only an explicit `EgressRule` (or explicit `allow` posture) permits a flow; `None`/`Isolated` deny all egress. |
| **V7** | Capsule verification | An unverified/unsigned `.chainvm` cannot launch; only `verify` + `check_launch` admit a capsule into the lifecycle. |
| **V8** | Policy engine | Launch, key-release, device-assign, and flow decisions are deny-by-default; every allow emits a deterministic `PolicyReceipt`. |
| **V9** | Attested key release | A modified boot policy (changed `boot_policy_hash` / PCRs) blocks key release; a `key_release` receipt records the deny. |
| **V10** | Lifecycle + control plane at scale | Full typed lifecycle drives real guests; the runtime `ReceiptChain` and `SecurityLog` `verify` end-to-end; `hyper-control` admits and orchestrates a fleet. |

Each gate is a regression contract: the host-testable V0 models for V2/V3/V6/V8/V9
already exist, so the hardware bring-up of V1+ is validated against behaviour the
virtual framework has already pinned.
