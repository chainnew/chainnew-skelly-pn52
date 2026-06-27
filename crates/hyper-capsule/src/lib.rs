use hyper_receipts::{Receipt, ReceiptDecision};
use serde::{Deserialize, Serialize};

pub const CAPSULE_SCHEMA: &str = "chain.vm_capsule.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct UntrustedCapsuleManifest {
    pub schema: String,
    pub capsule_id: String,
    pub vm_id: String,
    pub image_hash: String,
    pub disk_hash: String,
    pub hypervisor_min_version: u64,
    pub boot_policy_version: u64,
    pub devices: CapsuleDevicePolicy,
    pub memory: MemorySpec,
    pub cpu: CpuSpec,
    pub network: NetworkSpec,
    pub storage: StorageSpec,
    pub signatures: Vec<ManifestSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct VerifiedCapsuleManifest {
    inner: UntrustedCapsuleManifest,
    verification_receipt: Receipt,
}

impl VerifiedCapsuleManifest {
    pub fn inner(&self) -> &UntrustedCapsuleManifest {
        &self.inner
    }

    pub fn receipt(&self) -> &Receipt {
        &self.verification_receipt
    }

    pub fn vm_id(&self) -> &str {
        &self.inner.vm_id
    }

    pub fn capsule_id(&self) -> &str {
        &self.inner.capsule_id
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct ManifestSignature {
    pub alg: String,
    pub key_id: String,
    pub status: SignatureStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SignatureStatus {
    Active,
    Transition,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub struct CapsuleDevicePolicy {
    pub passthrough: Vec<String>,
    pub virtio: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct MemorySpec {
    pub max_mb: u64,
    pub allow_balloon: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct CpuSpec {
    pub vcpus: u16,
    pub cpuid_profile: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct NetworkSpec {
    pub mode: String,
    pub egress_policy: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct StorageSpec {
    pub cipher: String,
    pub integrity: String,
    pub key_version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct VerificationRequest {
    pub computed_capsule_hash: String,
    pub expected_capsule_hash: String,
    pub hypervisor_version: u64,
    pub allow_transition_signatures: bool,
    pub allow_passthrough: bool,
    pub previous_receipt_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapsuleError {
    SchemaMismatch,
    HashMismatch,
    MissingSignature,
    RevokedSignature,
    TransitionSignatureNotAllowed,
    HypervisorTooOld,
    PassthroughDenied,
}

impl UntrustedCapsuleManifest {
    pub fn verify(self, req: VerificationRequest) -> Result<VerifiedCapsuleManifest, CapsuleError> {
        if self.schema != CAPSULE_SCHEMA {
            return Err(CapsuleError::SchemaMismatch);
        }

        if req.computed_capsule_hash != req.expected_capsule_hash {
            return Err(CapsuleError::HashMismatch);
        }

        if self.signatures.is_empty() {
            return Err(CapsuleError::MissingSignature);
        }

        if self.signatures.iter().any(|sig| sig.status == SignatureStatus::Revoked) {
            return Err(CapsuleError::RevokedSignature);
        }

        if !req.allow_transition_signatures
            && self.signatures.iter().any(|sig| sig.status == SignatureStatus::Transition)
        {
            return Err(CapsuleError::TransitionSignatureNotAllowed);
        }

        if req.hypervisor_version < self.hypervisor_min_version {
            return Err(CapsuleError::HypervisorTooOld);
        }

        if !req.allow_passthrough && !self.devices.passthrough.is_empty() {
            return Err(CapsuleError::PassthroughDenied);
        }

        let receipt = Receipt::unsigned(
            format!("capsule-verify:{}", self.capsule_id),
            "manifest_verify",
            format!("vm:{}", self.vm_id),
            ReceiptDecision::Allow,
            None,
            req.computed_capsule_hash,
            req.previous_receipt_hash,
        );

        Ok(VerifiedCapsuleManifest { inner: self, verification_receipt: receipt })
    }
}

//! hyper-capsule — VM capsule manifest parsing with a type-level
//! Untrusted/Verified split (S1) and the launch gate (S9).
//!
//! Doctrine: an unverified manifest must be IMPOSSIBLE to launch. The only way
//! to obtain a [`VerifiedManifest`] is via [`verify`], and the only way to
//! obtain a [`LaunchApproval`] is via [`check_launch`] on a `VerifiedManifest`.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};
use thiserror::Error;

/// Schema string expected on the top-level capsule manifest.
pub const CAPSULE_SCHEMA: &str = "chain.vm_capsule.v1";

/// Algorithms accepted by the host [`AllowlistVerifier`].
pub const ALLOWED_ALGS: [&str; 3] = ["ecdsa-p384", "ed25519", "ml-dsa-65"];

/// Compute a `"sha384:<hex>"` digest string over the given bytes.
pub fn sha384_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha384::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    format!("sha384:{}", hex::encode(digest))
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors produced while parsing or verifying a capsule manifest.
#[derive(Debug, Error)]
pub enum CapsuleError {
    /// The manifest JSON could not be deserialized.
    #[error("malformed capsule manifest json: {0}")]
    Json(String),
    /// The `schema` field did not equal [`CAPSULE_SCHEMA`].
    #[error("unexpected schema: expected `{expected}`, got `{got}`")]
    Schema {
        /// Expected schema string.
        expected: String,
        /// Schema string found in the manifest.
        got: String,
    },
    /// The manifest carries no signatures at all.
    #[error("manifest has no signatures")]
    NoSignatures,
    /// No signature on the manifest could be verified as valid.
    #[error("no valid signature: signature status is {0:?}")]
    SignatureNotValid(SignatureStatus),
    /// The manifest's hypervisor floor exceeds the runtime's version.
    #[error("hypervisor too old: runtime {runtime} < manifest minimum {minimum}")]
    HypervisorTooOld {
        /// Hypervisor version supplied to `verify`.
        runtime: u64,
        /// `hypervisor_min_version` from the manifest.
        minimum: u64,
    },
    /// The manifest's boot policy version is below the tenant's floor.
    #[error("boot policy rollback: manifest {found} < tenant minimum {minimum}")]
    BootPolicyRollback {
        /// `boot_policy_version` from the manifest.
        found: u64,
        /// Tenant-enforced minimum boot policy version.
        minimum: u64,
    },
}

/// Errors produced by the launch gate ([`check_launch`]). Every variant is a
/// fail-closed denial of launch.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum GateError {
    /// Signature status on the verified manifest is not [`SignatureStatus::Valid`].
    #[error("signature not valid: {0:?}")]
    SignatureNotValid(SignatureStatus),
    /// Policy status on the verified manifest is not [`PolicyStatus::Pass`].
    #[error("policy not passing: {0:?}")]
    PolicyNotPassing(PolicyStatus),
    /// The image hash does not match the launch context's expectation.
    #[error("image hash mismatch: expected `{expected}`, manifest `{found}`")]
    ImageHashMismatch {
        /// Hash the launch context expects.
        expected: String,
        /// Hash recorded in the manifest.
        found: String,
    },
    /// The runtime hypervisor version is below the manifest minimum.
    #[error("hypervisor too old: runtime {runtime} < manifest minimum {minimum}")]
    HypervisorTooOld {
        /// Hypervisor version in the launch context.
        runtime: u64,
        /// `hypervisor_min_version` from the manifest.
        minimum: u64,
    },
    /// The boot policy version is below the tenant's floor.
    #[error("boot policy rollback: manifest {found} < tenant minimum {minimum}")]
    BootPolicyRollback {
        /// `boot_policy_version` from the manifest.
        found: u64,
        /// Tenant-enforced minimum boot policy version.
        minimum: u64,
    },
    /// Key unwrap was not authorized for this launch.
    #[error("key unwrap not authorized")]
    KeyUnwrapNotAuthorized,
    /// The device policy check did not pass.
    #[error("device policy denied")]
    DevicePolicyDenied,
    /// Requested memory exceeds the launch context budget.
    #[error("memory over budget: manifest {requested}mb > budget {budget}mb")]
    MemoryOverBudget {
        /// `memory.max_mb` from the manifest.
        requested: u64,
        /// Budget supplied in the launch context.
        budget: u64,
    },
    /// A debug override was requested; never permitted in a launch.
    #[error("debug override is not permitted")]
    DebugOverride,
}

// ---------------------------------------------------------------------------
// Untrusted manifest (S1)
// ---------------------------------------------------------------------------

/// A capsule manifest exactly as parsed from JSON. This type is "untrusted":
/// nothing about it has been checked beyond structural deserialization. It can
/// never be launched directly — it must pass through [`verify`] first.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct UntrustedManifest {
    /// Schema discriminator; must equal [`CAPSULE_SCHEMA`].
    pub schema: String,
    /// Stable identifier of the VM capsule.
    pub vm_id: String,
    /// Owning tenant identifier.
    pub tenant_id: String,
    /// `"sha384:<hex>"` digest of the boot image.
    pub image_hash: String,
    /// `"sha384:<hex>"` digest of the backing disk.
    pub disk_hash: String,
    /// Minimum hypervisor version this capsule may run on.
    pub hypervisor_min_version: u64,
    /// Boot policy version this capsule was authored against.
    pub boot_policy_version: u64,
    /// Device exposure for the capsule.
    pub devices: Devices,
    /// Memory configuration.
    pub memory: Memory,
    /// CPU configuration.
    pub cpu: Cpu,
    /// Network configuration.
    pub network: Network,
    /// Storage configuration.
    pub storage: Storage,
    /// Signatures over the manifest.
    pub signatures: Vec<CapsuleSignature>,
}

/// Device exposure for a capsule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Devices {
    /// Host devices passed through directly.
    pub passthrough: Vec<String>,
    /// virtio devices exposed to the guest.
    pub virtio: Vec<String>,
}

/// Memory configuration for a capsule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Memory {
    /// Maximum memory in megabytes.
    pub max_mb: u64,
    /// Whether the memory balloon device is permitted.
    pub allow_balloon: bool,
}

/// CPU configuration for a capsule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Cpu {
    /// Number of virtual CPUs.
    pub vcpus: u32,
    /// CPUID masking profile name.
    pub cpuid_profile: String,
}

/// Network configuration for a capsule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Network {
    /// Network mode (e.g. `"nat"`, `"isolated"`).
    pub mode: String,
    /// Egress policy identifier.
    pub egress_policy: String,
}

/// Storage configuration for a capsule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Storage {
    /// Disk cipher suite.
    pub cipher: String,
    /// Integrity mode.
    pub integrity: String,
    /// Key version used to wrap the volume key.
    pub key_version: u64,
}

/// A single signature claim over the manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct CapsuleSignature {
    /// Signature algorithm identifier.
    pub alg: String,
    /// Identifier of the signing key.
    pub key_id: String,
    /// Optional pre-asserted status string (never trusted by `verify`).
    pub status: Option<String>,
}

/// Parse a capsule manifest from JSON, enforcing the schema discriminator.
///
/// Returns an [`UntrustedManifest`] — note the deliberate naming: parsing
/// alone confers no trust.
pub fn parse_manifest(s: &str) -> Result<UntrustedManifest, CapsuleError> {
    let m: UntrustedManifest =
        serde_json::from_str(s).map_err(|e| CapsuleError::Json(e.to_string()))?;
    if m.schema != CAPSULE_SCHEMA {
        return Err(CapsuleError::Schema {
            expected: CAPSULE_SCHEMA.to_string(),
            got: m.schema,
        });
    }
    Ok(m)
}

// ---------------------------------------------------------------------------
// Status enums
// ---------------------------------------------------------------------------

/// Outcome of signature verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureStatus {
    /// No verification has been performed yet.
    Unverified,
    /// At least one signature was verified as valid.
    Valid,
    /// Verification ran and rejected all signatures.
    Invalid,
}

/// Outcome of policy checks (hypervisor floor + boot-policy floor).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStatus {
    /// Policy has not been evaluated.
    Unchecked,
    /// Policy checks passed.
    Pass,
    /// Policy checks failed.
    Fail,
}

// ---------------------------------------------------------------------------
// Signature verifier
// ---------------------------------------------------------------------------

/// Strategy for verifying the signatures on a manifest.
pub trait SignatureVerifier {
    /// Inspect the manifest and return the resulting [`SignatureStatus`].
    fn verify(&self, m: &UntrustedManifest) -> SignatureStatus;
}

/// Host-side verifier that accepts a signature only when its `key_id` is in the
/// configured allowlist AND its `alg` is in [`ALLOWED_ALGS`].
#[derive(Debug, Clone, Default)]
pub struct AllowlistVerifier {
    /// Key identifiers trusted by this verifier.
    pub allowed_key_ids: Vec<String>,
}

impl AllowlistVerifier {
    /// Build a verifier from an iterator of allowed key id strings.
    pub fn new<I, S>(allowed_key_ids: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            allowed_key_ids: allowed_key_ids.into_iter().map(Into::into).collect(),
        }
    }
}

impl SignatureVerifier for AllowlistVerifier {
    fn verify(&self, m: &UntrustedManifest) -> SignatureStatus {
        if m.signatures.is_empty() {
            return SignatureStatus::Invalid;
        }
        let any_valid = m.signatures.iter().any(|s| {
            ALLOWED_ALGS.contains(&s.alg.as_str())
                && self.allowed_key_ids.iter().any(|k| k == &s.key_id)
        });
        if any_valid {
            SignatureStatus::Valid
        } else {
            SignatureStatus::Invalid
        }
    }
}

// ---------------------------------------------------------------------------
// Verified manifest (S1)
// ---------------------------------------------------------------------------

/// A manifest that has passed signature verification and policy floors.
///
/// The fields are private and there is no public constructor: the ONLY way to
/// obtain a `VerifiedManifest` is via [`verify`]. This makes it impossible to
/// launch an unverified manifest.
#[derive(Debug, Clone)]
pub struct VerifiedManifest {
    inner: UntrustedManifest,
    signature_status: SignatureStatus,
    policy_status: PolicyStatus,
}

impl VerifiedManifest {
    /// The underlying manifest.
    pub fn inner(&self) -> &UntrustedManifest {
        &self.inner
    }
    /// Signature verification outcome (always [`SignatureStatus::Valid`] for a
    /// successfully constructed value).
    pub fn signature_status(&self) -> SignatureStatus {
        self.signature_status
    }
    /// Policy evaluation outcome.
    pub fn policy_status(&self) -> PolicyStatus {
        self.policy_status
    }
}

/// Verify an untrusted manifest: run the supplied [`SignatureVerifier`], enforce
/// the hypervisor floor and the tenant's boot-policy floor, and — only if all
/// pass — produce a [`VerifiedManifest`].
///
/// Fails closed: any failure returns `Err` and yields no `VerifiedManifest`.
pub fn verify(
    m: UntrustedManifest,
    v: &dyn SignatureVerifier,
    min_hypervisor_version: u64,
    tenant_min_boot_policy: u64,
) -> Result<VerifiedManifest, CapsuleError> {
    if m.signatures.is_empty() {
        return Err(CapsuleError::NoSignatures);
    }

    let signature_status = v.verify(&m);
    if signature_status != SignatureStatus::Valid {
        return Err(CapsuleError::SignatureNotValid(signature_status));
    }

    if min_hypervisor_version < m.hypervisor_min_version {
        return Err(CapsuleError::HypervisorTooOld {
            runtime: min_hypervisor_version,
            minimum: m.hypervisor_min_version,
        });
    }

    if m.boot_policy_version < tenant_min_boot_policy {
        return Err(CapsuleError::BootPolicyRollback {
            found: m.boot_policy_version,
            minimum: tenant_min_boot_policy,
        });
    }

    Ok(VerifiedManifest {
        inner: m,
        signature_status,
        policy_status: PolicyStatus::Pass,
    })
}

// ---------------------------------------------------------------------------
// Launch gate (S9)
// ---------------------------------------------------------------------------

/// Runtime context evaluated by the launch gate.
#[derive(Debug, Clone)]
pub struct LaunchContext {
    /// Hypervisor version of the runtime attempting the launch.
    pub hypervisor_version: u64,
    /// Tenant-enforced minimum boot policy version.
    pub tenant_min_boot_policy: u64,
    /// Image hash the launcher expects (`"sha384:<hex>"`).
    pub expected_image_hash: String,
    /// Whether key unwrap is authorized for this launch.
    pub key_unwrap_authorized: bool,
    /// Whether the device policy check passed.
    pub device_policy_ok: bool,
    /// Memory budget available, in megabytes.
    pub memory_budget_mb: u64,
    /// Whether a debug override was requested (never permitted).
    pub debug_override: bool,
}

/// Proof token that a launch was approved by [`check_launch`].
///
/// Private fields + no public constructor: only the gate can mint one.
#[derive(Debug, Clone)]
pub struct LaunchApproval {
    vm_id: String,
    image_hash: String,
}

impl LaunchApproval {
    /// The capsule's VM id.
    pub fn vm_id(&self) -> &str {
        &self.vm_id
    }
    /// The image hash that was approved.
    pub fn image_hash(&self) -> &str {
        &self.image_hash
    }
}

/// The launch gate (S9). Enforces every SOW launch condition against a
/// [`VerifiedManifest`]. Because the input type can only be produced by
/// [`verify`], there is no way to launch an unverified manifest.
///
/// Fails closed: any unmet condition returns the corresponding [`GateError`].
pub fn check_launch(
    vm: &VerifiedManifest,
    ctx: &LaunchContext,
) -> Result<LaunchApproval, GateError> {
    // No debug overrides, ever.
    if ctx.debug_override {
        return Err(GateError::DebugOverride);
    }

    // Signature must be valid.
    if vm.signature_status != SignatureStatus::Valid {
        return Err(GateError::SignatureNotValid(vm.signature_status));
    }

    // Policy must have passed.
    if vm.policy_status != PolicyStatus::Pass {
        return Err(GateError::PolicyNotPassing(vm.policy_status));
    }

    let m = &vm.inner;

    // Image hash must match expectation.
    if m.image_hash != ctx.expected_image_hash {
        return Err(GateError::ImageHashMismatch {
            expected: ctx.expected_image_hash.clone(),
            found: m.image_hash.clone(),
        });
    }

    // Runtime hypervisor must satisfy the manifest floor.
    if ctx.hypervisor_version < m.hypervisor_min_version {
        return Err(GateError::HypervisorTooOld {
            runtime: ctx.hypervisor_version,
            minimum: m.hypervisor_min_version,
        });
    }

    // Boot policy must not roll back below the tenant floor.
    if m.boot_policy_version < ctx.tenant_min_boot_policy {
        return Err(GateError::BootPolicyRollback {
            found: m.boot_policy_version,
            minimum: ctx.tenant_min_boot_policy,
        });
    }

    // Key unwrap must be authorized.
    if !ctx.key_unwrap_authorized {
        return Err(GateError::KeyUnwrapNotAuthorized);
    }

    // Device policy must pass.
    if !ctx.device_policy_ok {
        return Err(GateError::DevicePolicyDenied);
    }

    // Memory must be within budget.
    if m.memory.max_mb > ctx.memory_budget_mb {
        return Err(GateError::MemoryOverBudget {
            requested: m.memory.max_mb,
            budget: ctx.memory_budget_mb,
        });
    }

    Ok(LaunchApproval {
        vm_id: m.vm_id.clone(),
        image_hash: m.image_hash.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> UntrustedCapsuleManifest {
        UntrustedCapsuleManifest {
            schema: CAPSULE_SCHEMA.into(),
            capsule_id: "cap-1".into(),
            vm_id: "guest-zero".into(),
            image_hash: "sha384:image".into(),
            disk_hash: "sha384:disk".into(),
            hypervisor_min_version: 1,
            boot_policy_version: 1,
            devices: CapsuleDevicePolicy { passthrough: Vec::new(), virtio: vec!["console".into()] },
            memory: MemorySpec { max_mb: 64, allow_balloon: false },
            cpu: CpuSpec { vcpus: 1, cpuid_profile: "masked_zen3_guest_v1".into() },
            network: NetworkSpec { mode: "none".into(), egress_policy: "deny_by_default".into() },
            storage: StorageSpec { cipher: "aes-256-xts".into(), integrity: "manifest_hash_only".into(), key_version: 1 },
            signatures: vec![ManifestSignature { alg: "ed25519".into(), key_id: "lab".into(), status: SignatureStatus::Active }],
    fn good_json() -> String {
        r#"{
            "schema": "chain.vm_capsule.v1",
            "vm_id": "vm-001",
            "tenant_id": "tenant-a",
            "image_hash": "sha384:aa",
            "disk_hash": "sha384:bb",
            "hypervisor_min_version": 10,
            "boot_policy_version": 5,
            "devices": { "passthrough": ["gpu0"], "virtio": ["net0", "blk0"] },
            "memory": { "max_mb": 2048, "allow_balloon": false },
            "cpu": { "vcpus": 4, "cpuid_profile": "milan-v1" },
            "network": { "mode": "isolated", "egress_policy": "deny-all" },
            "storage": { "cipher": "aes-256-xts", "integrity": "dm-integrity", "key_version": 3 },
            "signatures": [
                { "alg": "ecdsa-p384", "key_id": "key-good", "status": null }
            ]
        }"#
        .to_string()
    }

    fn allowlist() -> AllowlistVerifier {
        AllowlistVerifier::new(["key-good"])
    }

    fn good_ctx() -> LaunchContext {
        LaunchContext {
            hypervisor_version: 12,
            tenant_min_boot_policy: 5,
            expected_image_hash: "sha384:aa".to_string(),
            key_unwrap_authorized: true,
            device_policy_ok: true,
            memory_budget_mb: 4096,
            debug_override: false,
        }
    }

    #[test]
    fn verified_capsule_requires_matching_hash() {
        let req = VerificationRequest {
            computed_capsule_hash: "sha384:a".into(),
            expected_capsule_hash: "sha384:b".into(),
            hypervisor_version: 1,
            allow_transition_signatures: true,
            allow_passthrough: false,
            previous_receipt_hash: None,
        };
        assert_eq!(manifest().verify(req), Err(CapsuleError::HashMismatch));
    }

    #[test]
    fn verified_capsule_blocks_passthrough_by_default() {
        let mut m = manifest();
        m.devices.passthrough.push("0000:01:00.0".into());
        let req = VerificationRequest {
            computed_capsule_hash: "sha384:a".into(),
            expected_capsule_hash: "sha384:a".into(),
            hypervisor_version: 1,
            allow_transition_signatures: true,
            allow_passthrough: false,
            previous_receipt_hash: None,
        };
        assert_eq!(m.verify(req), Err(CapsuleError::PassthroughDenied));
    fn sha384_hex_format() {
        let h = sha384_hex(b"");
        assert!(h.starts_with("sha384:"));
        // SHA-384 produces 48 bytes -> 96 hex chars.
        assert_eq!(h.len(), "sha384:".len() + 96);
        assert_eq!(
            h,
            "sha384:38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
    }

    #[test]
    fn parse_good_manifest() {
        let m = parse_manifest(&good_json()).expect("should parse");
        assert_eq!(m.vm_id, "vm-001");
        assert_eq!(m.devices.virtio, vec!["net0", "blk0"]);
        assert_eq!(m.memory.max_mb, 2048);
        assert_eq!(m.signatures.len(), 1);
    }

    #[test]
    fn parse_rejects_bad_schema() {
        let bad = good_json().replace("chain.vm_capsule.v1", "chain.vm_capsule.v2");
        let err = parse_manifest(&bad).unwrap_err();
        assert!(matches!(err, CapsuleError::Schema { .. }));
    }

    #[test]
    fn parse_rejects_unknown_field() {
        let bad = good_json().replace(
            "\"vm_id\": \"vm-001\",",
            "\"vm_id\": \"vm-001\",\n            \"rogue\": 1,",
        );
        let err = parse_manifest(&bad).unwrap_err();
        assert!(matches!(err, CapsuleError::Json(_)));
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(matches!(
            parse_manifest("not json").unwrap_err(),
            CapsuleError::Json(_)
        ));
    }

    #[test]
    fn verify_with_allowlist_yields_verified() {
        let m = parse_manifest(&good_json()).unwrap();
        let v = verify(m, &allowlist(), 12, 5).expect("should verify");
        assert_eq!(v.signature_status(), SignatureStatus::Valid);
        assert_eq!(v.policy_status(), PolicyStatus::Pass);
        assert_eq!(v.inner().vm_id, "vm-001");
    }

    #[test]
    fn verify_fails_when_key_not_allowed() {
        let m = parse_manifest(&good_json()).unwrap();
        let v = AllowlistVerifier::new(["some-other-key"]);
        let err = verify(m, &v, 12, 5).unwrap_err();
        assert!(matches!(
            err,
            CapsuleError::SignatureNotValid(SignatureStatus::Invalid)
        ));
    }

    #[test]
    fn verify_fails_when_alg_not_allowed() {
        let bad = good_json().replace("ecdsa-p384", "rsa-pkcs1");
        let m = parse_manifest(&bad).unwrap();
        let err = verify(m, &allowlist(), 12, 5).unwrap_err();
        assert!(matches!(
            err,
            CapsuleError::SignatureNotValid(SignatureStatus::Invalid)
        ));
    }

    #[test]
    fn verify_fails_with_no_signatures() {
        let bad = good_json().replace(
            "\"signatures\": [\n                { \"alg\": \"ecdsa-p384\", \"key_id\": \"key-good\", \"status\": null }\n            ]",
            "\"signatures\": []",
        );
        let m = parse_manifest(&bad).unwrap();
        let err = verify(m, &allowlist(), 12, 5).unwrap_err();
        assert!(matches!(err, CapsuleError::NoSignatures));
    }

    #[test]
    fn verify_fails_hypervisor_too_old() {
        let m = parse_manifest(&good_json()).unwrap();
        // runtime 9 < manifest minimum 10
        let err = verify(m, &allowlist(), 9, 5).unwrap_err();
        assert!(matches!(err, CapsuleError::HypervisorTooOld { .. }));
    }

    #[test]
    fn verify_fails_boot_policy_rollback() {
        let m = parse_manifest(&good_json()).unwrap();
        // manifest boot_policy 5 < tenant minimum 6
        let err = verify(m, &allowlist(), 12, 6).unwrap_err();
        assert!(matches!(err, CapsuleError::BootPolicyRollback { .. }));
    }

    #[test]
    fn gate_full_good_path() {
        let m = parse_manifest(&good_json()).unwrap();
        let v = verify(m, &allowlist(), 12, 5).unwrap();
        let approval = check_launch(&v, &good_ctx()).expect("should launch");
        assert_eq!(approval.vm_id(), "vm-001");
        assert_eq!(approval.image_hash(), "sha384:aa");
    }

    #[test]
    fn gate_rejects_debug_override() {
        let m = parse_manifest(&good_json()).unwrap();
        let v = verify(m, &allowlist(), 12, 5).unwrap();
        let mut ctx = good_ctx();
        ctx.debug_override = true;
        assert_eq!(check_launch(&v, &ctx).unwrap_err(), GateError::DebugOverride);
    }

    #[test]
    fn gate_rejects_image_hash_mismatch() {
        let m = parse_manifest(&good_json()).unwrap();
        let v = verify(m, &allowlist(), 12, 5).unwrap();
        let mut ctx = good_ctx();
        ctx.expected_image_hash = "sha384:zz".to_string();
        assert!(matches!(
            check_launch(&v, &ctx).unwrap_err(),
            GateError::ImageHashMismatch { .. }
        ));
    }

    #[test]
    fn gate_rejects_hypervisor_too_old() {
        let m = parse_manifest(&good_json()).unwrap();
        let v = verify(m, &allowlist(), 12, 5).unwrap();
        let mut ctx = good_ctx();
        ctx.hypervisor_version = 9;
        assert!(matches!(
            check_launch(&v, &ctx).unwrap_err(),
            GateError::HypervisorTooOld { .. }
        ));
    }

    #[test]
    fn gate_rejects_boot_policy_rollback() {
        let m = parse_manifest(&good_json()).unwrap();
        let v = verify(m, &allowlist(), 12, 5).unwrap();
        let mut ctx = good_ctx();
        ctx.tenant_min_boot_policy = 6;
        assert!(matches!(
            check_launch(&v, &ctx).unwrap_err(),
            GateError::BootPolicyRollback { .. }
        ));
    }

    #[test]
    fn gate_rejects_unauthorized_key_unwrap() {
        let m = parse_manifest(&good_json()).unwrap();
        let v = verify(m, &allowlist(), 12, 5).unwrap();
        let mut ctx = good_ctx();
        ctx.key_unwrap_authorized = false;
        assert_eq!(
            check_launch(&v, &ctx).unwrap_err(),
            GateError::KeyUnwrapNotAuthorized
        );
    }

    #[test]
    fn gate_rejects_device_policy() {
        let m = parse_manifest(&good_json()).unwrap();
        let v = verify(m, &allowlist(), 12, 5).unwrap();
        let mut ctx = good_ctx();
        ctx.device_policy_ok = false;
        assert_eq!(
            check_launch(&v, &ctx).unwrap_err(),
            GateError::DevicePolicyDenied
        );
    }

    #[test]
    fn gate_rejects_memory_over_budget() {
        let m = parse_manifest(&good_json()).unwrap();
        let v = verify(m, &allowlist(), 12, 5).unwrap();
        let mut ctx = good_ctx();
        ctx.memory_budget_mb = 1024; // manifest wants 2048
        assert!(matches!(
            check_launch(&v, &ctx).unwrap_err(),
            GateError::MemoryOverBudget { .. }
        ));
    }

    #[test]
    fn gate_memory_at_budget_ok() {
        let m = parse_manifest(&good_json()).unwrap();
        let v = verify(m, &allowlist(), 12, 5).unwrap();
        let mut ctx = good_ctx();
        ctx.memory_budget_mb = 2048; // exactly equal is allowed
        assert!(check_launch(&v, &ctx).is_ok());
    }

    #[test]
    fn pre_asserted_status_is_ignored_by_verify() {
        // A manifest claiming "valid" but signed by an untrusted key must fail.
        let bad = good_json()
            .replace("\"status\": null", "\"status\": \"valid\"")
            .replace("key-good", "key-evil");
        let m = parse_manifest(&bad).unwrap();
        assert!(verify(m, &allowlist(), 12, 5).is_err());
    }
}
