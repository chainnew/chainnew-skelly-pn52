//! hyper-vm — the slate-runtime keystone: a VM capsule plus a typed lifecycle
//! state machine that ties the whole framework together (V0, host-testable).
//!
//! Doctrine: there is NO public `launch_guest()` / run-from-raw API. The ONLY
//! way to obtain a running guest is to walk the typed lifecycle —
//! `Defined -> Verified -> Prepared -> Unlocked -> Attached -> Running` — via a
//! [`SlateRuntime`] implementing [`VmLifecycle`]. Each state is encoded in the
//! Rust type system, so e.g. calling [`VmLifecycle::run`] before
//! [`VmLifecycle::unlock`] / [`VmLifecycle::attach`] simply does not type-check.
//!
//! Every transition appends a tamper-evident receipt onto the runtime's
//! [`hyper_receipts::ReceiptChain`]; every gate is fail-closed.
#![forbid(unsafe_code)]

mod error;
mod runtime;
mod spec;

pub use error::VmError;
pub use runtime::{
    AttachedVm, DestroyReceipt, PausedVm, PreparedVm, RunnableVm, RunningVm, SlateRuntime,
    SnapshotReceipt, StoppedVm, UnlockedVm, VerifiedVm, VmHandle, VmLifecycle,
};
pub use spec::{
    BootSpec, CpuSpec, DeviceAssignmentSpec, KeyReleasePlan, MemorySpec, VirtualDiskSpec,
    VirtualNicSpec, VmCapsule, VmPolicy,
};

/// Lifecycle state of a VM. The typed state structs ([`VmHandle`],
/// [`VerifiedVm`], ...) encode these at the type level; this enum is the
/// reflective, value-level view returned by their `state()` accessors and is
/// also used to stamp receipts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmState {
    /// A capsule has been admitted but nothing has been validated yet.
    Defined,
    /// The manifest passed verification + the launch gate.
    Verified,
    /// Guest memory has been allocated under the S2 invariants.
    Prepared,
    /// Waiting for the attested KMS to release the volume key.
    AwaitingKeyRelease,
    /// The KMS released the wrapped volume key.
    Unlocked,
    /// Devices and vCPUs have been attached.
    Attached,
    /// The guest is running.
    Running,
    /// The guest is paused (resumable in a later phase).
    Paused,
    /// The guest is being torn down.
    Stopping,
    /// The guest has stopped cleanly.
    Stopped,
    /// A fail-closed fault occurred.
    Failed,
    /// The guest was isolated for forensic inspection.
    Quarantined,
    /// All resources have been zeroized and released.
    Destroyed,
}

/// Compute a `"sha384:<hex>"` digest over `bytes`.
///
/// Thin wrapper over [`hyper_capsule::sha384_hex`] so the whole framework shares
/// one canonical hash formatting with the capsule + receipt spines. No new
/// external crates are pulled in by hyper-vm for hashing.
pub fn sha384_hex(bytes: &[u8]) -> String {
    hyper_capsule::sha384_hex(bytes)
}

/// Derive a deterministic, non-zero `npt_root` label from a VM id. Purely a
/// function of the id — no randomness, no clock.
pub(crate) fn derive_npt_root(vm_id: &str) -> u64 {
    let h = sha384_hex(vm_id.as_bytes());
    let hex = h.strip_prefix("sha384:").unwrap_or(&h);
    // First 16 hex chars -> u64. The digest is never all-zero in practice, but
    // force a non-zero root regardless so callers can treat 0 as "unset".
    let v = u64::from_str_radix(&hex[..16], 16).unwrap_or(1);
    v | 1
}
