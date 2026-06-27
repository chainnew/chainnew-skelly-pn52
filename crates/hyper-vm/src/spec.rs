//! Declarative VM capsule specification structs.
//!
//! These are plain, serde-mapped value types (the "wire" description of a VM).
//! The capsule itself ([`VmCapsule`]) additionally carries a
//! [`hyper_capsule::VerifiedManifest`], whose only constructor is
//! `hyper_capsule::verify`. That makes it *impossible* to assemble a capsule —
//! and therefore to enter the lifecycle — around an unverified/unsigned
//! manifest.

use serde::{Deserialize, Serialize};

use hyper_attest::PcrBank;
use hyper_capsule::VerifiedManifest;

/// Boot configuration for the guest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct BootSpec {
    /// Firmware profile name (e.g. `"uefi-ovmf-v1"`).
    pub firmware: String,
    /// Kernel command line passed to the guest.
    pub cmdline: String,
    /// Boot policy version this guest was authored against.
    pub boot_policy_version: u64,
}

/// CPU configuration for the guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CpuSpec {
    /// Number of virtual CPUs to create.
    pub vcpus: u32,
}

/// Memory configuration for the guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MemorySpec {
    /// Maximum guest RAM, in megabytes.
    pub max_mb: u64,
}

/// A virtual disk attached to the guest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct VirtualDiskSpec {
    /// Stable identifier for the disk.
    pub disk_id: String,
    /// Disk capacity, in megabytes.
    pub size_mb: u64,
    /// Whether the disk is opened read-only.
    pub read_only: bool,
}

/// A virtual NIC attached to the guest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct VirtualNicSpec {
    /// Stable identifier for the NIC.
    pub nic_id: String,
    /// Network mode (e.g. `"nat"`, `"isolated"`).
    pub mode: String,
}

/// Host devices to assign directly (passthrough) to the guest.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DeviceAssignmentSpec {
    /// Host device identifiers to pass through.
    pub passthrough: Vec<String>,
}

/// Per-capsule policy knobs evaluated by the launch gate. The declarative,
/// org-wide policy document lives in the [`crate::SlateRuntime`]; these are the
/// capsule-specific inputs to the gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct VmPolicy {
    /// Tenant-enforced minimum boot policy version.
    pub tenant_min_boot_policy: u64,
    /// Memory budget available to this capsule, in megabytes.
    pub memory_budget_mb: u64,
    /// Whether key unwrap is authorized for this launch.
    pub key_unwrap_authorized: bool,
    /// Whether the device policy check passed.
    pub device_policy_ok: bool,
    /// Whether measured boot is in effect.
    pub measured_boot: bool,
    /// Whether the launch requests an interactive debug console.
    pub requests_debug_console: bool,
}

/// The attested key-release plan: the inputs the KMS simulator evaluates when
/// the lifecycle reaches the unlock step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct KeyReleasePlan {
    /// Storage device the wrapped key is bound to.
    pub device_id: String,
    /// `"sha384:<hex>"` capsule hash presented to the KMS.
    pub capsule_hash: String,
    /// `"sha384:<hex>"` boot policy hash presented to the KMS.
    pub boot_policy_hash: String,
    /// PCR quote presented to the KMS.
    pub pcrs: PcrBank,
    /// Deterministic, single-use nonce for the request.
    pub nonce: String,
}

/// A fully described VM capsule. Holding a [`VerifiedManifest`] (which has no
/// public constructor other than `hyper_capsule::verify`) is what makes an
/// unverified/unsigned launch unrepresentable.
#[derive(Debug, Clone)]
pub struct VmCapsule {
    /// Stable identifier for this capsule.
    pub capsule_id: String,
    /// The signed, verified boot manifest.
    pub manifest: VerifiedManifest,
    /// Boot configuration.
    pub boot: BootSpec,
    /// CPU configuration.
    pub cpu: CpuSpec,
    /// Memory configuration.
    pub memory: MemorySpec,
    /// Attached virtual disks.
    pub storage: Vec<VirtualDiskSpec>,
    /// Attached virtual NICs.
    pub network: Vec<VirtualNicSpec>,
    /// Passthrough device assignment.
    pub devices: DeviceAssignmentSpec,
    /// Per-capsule launch policy knobs.
    pub policy: VmPolicy,
    /// Attested key-release plan.
    pub key_plan: KeyReleasePlan,
}
