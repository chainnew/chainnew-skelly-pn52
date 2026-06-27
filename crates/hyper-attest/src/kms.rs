//! KMS unlock simulator: attested key-release evaluation (S6/S8, §10).
//!
//! [`KmsSimulator`] evaluates a [`KeyReleaseRequest`] against a [`KmsPolicy`]
//! and releases a (simulated) wrapped volume master key *only* when every
//! attestation gate passes:
//!
//! 1. boot policy hash matches the policy's pinned value (acceptance **V9**: a
//!    modified boot policy MUST block release),
//! 2. all expected PCRs match,
//! 3. the capsule hash is allow-listed,
//! 4. the hypervisor version is at or above the minimum.
//!
//! Every decision (allow or deny) is recorded as a `key_release` receipt on the
//! shared [`ReceiptChain`] so the audit spine stays tamper-evident and the deny
//! path is fail-closed and traceable.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};
use thiserror::Error;

use hyper_receipts::{ReceiptChain, ReceiptEvent};

use crate::pcr::PcrBank;
use crate::secret::SecretHandle;

/// Policy id stamped onto key-release receipts.
pub const KMS_POLICY_ID: &str = "pol-kms-attested-unlock";

/// `"format"` tag stamped onto [`AttestedUnlockEvidence`] summaries.
pub const ATTESTED_UNLOCK_FORMAT: &str = "attested-hybrid-unlock-v1";

/// Errors raised by attestation (de)serialization helpers.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AttestError {
    #[error("json error: {0}")]
    Json(String),
}

/// The algorithm-agility binding a key-release request expects: the classical
/// KEM, the post-quantum KEM, and the combiner that derive the hybrid KEK.
///
/// This mirrors the suite identifiers the downstream QRSE combiner binds into
/// its HKDF `info` (PAD-QRSE-001 §9.4), kept here as a local, dependency-free
/// value so the attest layer can record *which* hybrid suite an unlock was
/// attested under without taking a dependency on the storage/QRSE crate.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SuiteBinding {
    pub classical: String,
    pub pqc: String,
    pub combiner: String,
}

impl SuiteBinding {
    /// Build a suite binding from its three identifiers.
    pub fn new(
        classical: impl Into<String>,
        pqc: impl Into<String>,
        combiner: impl Into<String>,
    ) -> Self {
        SuiteBinding {
            classical: classical.into(),
            pqc: pqc.into(),
            combiner: combiner.into(),
        }
    }

    /// The default commercial transition profile: X25519 + ML-KEM-768.
    pub fn transition_768() -> Self {
        SuiteBinding::new("x25519", "ml-kem-768", "hkdf-sha384")
    }

    /// CNSA-leaning high-assurance profile: X25519 + ML-KEM-1024.
    pub fn high_assurance_1024() -> Self {
        SuiteBinding::new("x25519", "ml-kem-1024", "hkdf-sha384")
    }

    /// Canonical, unambiguous wire form (`"classical+pqc+combiner"`), matching
    /// the QRSE combiner's suite encoding.
    pub fn canonical(&self) -> String {
        format!("{}+{}+{}", self.classical, self.pqc, self.combiner)
    }
}

/// A request for the KMS to release a wrapped volume key for a VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct KeyReleaseRequest {
    pub request_type: String,
    pub device_id: String,
    pub vm_id: String,
    pub capsule_hash: String,
    pub boot_policy_hash: String,
    pub pcrs: PcrBank,
    pub hypervisor_version: u64,
    pub nonce: String,
}

impl KeyReleaseRequest {
    /// Convenience constructor for the common PCR0/7/11 attested-unlock request.
    ///
    /// Builds a `"key_release"` request whose PCR bank carries exactly the
    /// firmware ([`PCR0`](crate::PCR0)), Secure-Boot-policy ([`PCR7`](crate::PCR7))
    /// and unified-kernel ([`PCR11`](crate::PCR11)) registers — the standard set
    /// an attested storage unlock is gated on.
    #[allow(clippy::too_many_arguments)]
    pub fn attested_unlock(
        device_id: impl Into<String>,
        vm_id: impl Into<String>,
        capsule_hash: impl Into<String>,
        boot_policy_hash: impl Into<String>,
        pcr0: impl Into<String>,
        pcr7: impl Into<String>,
        pcr11: impl Into<String>,
        hypervisor_version: u64,
        nonce: impl Into<String>,
    ) -> Self {
        let mut pcrs = PcrBank::new();
        pcrs.set(crate::pcr::PCR0, pcr0)
            .set(crate::pcr::PCR7, pcr7)
            .set(crate::pcr::PCR11, pcr11);
        KeyReleaseRequest {
            request_type: "key_release".to_string(),
            device_id: device_id.into(),
            vm_id: vm_id.into(),
            capsule_hash: capsule_hash.into(),
            boot_policy_hash: boot_policy_hash.into(),
            pcrs,
            hypervisor_version,
            nonce: nonce.into(),
        }
    }

    /// Pair this request with the hybrid [`SuiteBinding`] it expects, yielding a
    /// [`SuitedKeyReleaseRequest`].
    ///
    /// This is the additive, non-breaking way to attach algorithm-suite
    /// awareness to a release request: the base `KeyReleaseRequest` shape (and
    /// every existing constructor / receipt projection) is left untouched, so a
    /// request without a suite keeps its old behavior exactly.
    pub fn with_suite(self, suite: SuiteBinding) -> SuitedKeyReleaseRequest {
        SuitedKeyReleaseRequest {
            request: self,
            suite: Some(suite),
        }
    }

    /// The ordered, canonical projection that the receipt `inputs_hash` and the
    /// simulated wrapped key are derived from.
    fn canonical(&self) -> ReqCanonical<'_> {
        ReqCanonical {
            request_type: &self.request_type,
            device_id: &self.device_id,
            vm_id: &self.vm_id,
            capsule_hash: &self.capsule_hash,
            boot_policy_hash: &self.boot_policy_hash,
            pcrs: &self.pcrs,
            hypervisor_version: self.hypervisor_version,
            nonce: &self.nonce,
        }
    }

    /// Deterministic `"sha384:<hex>"` hash over the canonical request fields.
    pub fn inputs_hash(&self) -> String {
        let bytes = serde_json::to_vec(&self.canonical()).expect("canonical request serializes");
        crate::sha384_hex(&bytes)
    }

    /// Serialize to pretty JSON.
    pub fn to_json(&self) -> Result<String, AttestError> {
        serde_json::to_string_pretty(self).map_err(|e| AttestError::Json(e.to_string()))
    }

    /// Rehydrate from JSON.
    pub fn from_json(s: &str) -> Result<Self, AttestError> {
        serde_json::from_str(s).map_err(|e| AttestError::Json(e.to_string()))
    }
}

#[derive(Serialize)]
struct ReqCanonical<'a> {
    request_type: &'a str,
    device_id: &'a str,
    vm_id: &'a str,
    capsule_hash: &'a str,
    boot_policy_hash: &'a str,
    pcrs: &'a PcrBank,
    hypervisor_version: u64,
    nonce: &'a str,
}

/// A [`KeyReleaseRequest`] paired with the optional hybrid [`SuiteBinding`] it
/// expects.
///
/// Additive carrier: the base request is left untouched and nested under
/// `request`, with the suite alongside it. A missing `suite`
/// (`#[serde(default)]`) deserializes to `None`, so a request without suite
/// awareness keeps its old behavior exactly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SuitedKeyReleaseRequest {
    pub request: KeyReleaseRequest,
    #[serde(default)]
    pub suite: Option<SuiteBinding>,
}

impl SuitedKeyReleaseRequest {
    /// Wrap a request that carries no suite expectation (old behavior).
    pub fn new(request: KeyReleaseRequest) -> Self {
        SuitedKeyReleaseRequest {
            request,
            suite: None,
        }
    }

    /// Serialize to pretty JSON.
    pub fn to_json(&self) -> Result<String, AttestError> {
        serde_json::to_string_pretty(self).map_err(|e| AttestError::Json(e.to_string()))
    }

    /// Rehydrate from JSON.
    pub fn from_json(s: &str) -> Result<Self, AttestError> {
        serde_json::from_str(s).map_err(|e| AttestError::Json(e.to_string()))
    }
}

/// A structured, receipt-embeddable summary of an *allowed* attested hybrid
/// unlock.
///
/// Produced by [`KmsSimulator::attested_unlock_evidence`] only for an
/// [`KeyReleaseDecision::Allow`]. It records the device/VM identity, the hybrid
/// [`SuiteBinding`] the unlock was attested under, and the individual gate
/// results (PCR match, boot-policy match, capsule allow-listing, hypervisor
/// floor) so an auditor can see *why* the release passed — without re-running
/// the policy. It is a pure derivation; it does not change `evaluate()`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AttestedUnlockEvidence {
    /// Schema tag — always [`ATTESTED_UNLOCK_FORMAT`].
    pub format: String,
    pub device_id: String,
    pub vm_id: String,
    /// The hybrid suite the request declared, if any.
    #[serde(default)]
    pub suite: Option<SuiteBinding>,
    /// Whether the request's PCRs satisfied every expected register.
    pub pcr_match: bool,
    /// Whether the request's boot-policy hash matched the pinned value (V9).
    pub boot_policy_match: bool,
    /// Whether the capsule hash was on the policy allow-list.
    pub capsule_allowlisted: bool,
    /// Whether the hypervisor version met the policy minimum.
    pub hypervisor_version_ok: bool,
    /// The canonical request inputs hash (links to the `key_release` receipt).
    pub inputs_hash: String,
    /// The policy id the unlock was evaluated under.
    pub policy_id: String,
}

impl AttestedUnlockEvidence {
    /// Serialize to pretty JSON, suitable for embedding alongside a receipt.
    pub fn to_json(&self) -> Result<String, AttestError> {
        serde_json::to_string_pretty(self).map_err(|e| AttestError::Json(e.to_string()))
    }

    /// Rehydrate from JSON.
    pub fn from_json(s: &str) -> Result<Self, AttestError> {
        serde_json::from_str(s).map_err(|e| AttestError::Json(e.to_string()))
    }
}

/// The conditions a [`KeyReleaseRequest`] must satisfy for the KMS to unwrap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct KmsPolicy {
    pub expected_pcrs: PcrBank,
    pub min_hypervisor_version: u64,
    pub allowed_capsule_hashes: Vec<String>,
    pub expected_boot_policy_hash: String,
}

/// The outcome of an attested key-release evaluation.
#[derive(Debug)]
pub enum KeyReleaseDecision {
    /// Attestation passed; the wrapped VMK is released alongside the audit
    /// receipt that recorded the allow.
    Allow {
        wrapped_vmk: SecretHandle,
        receipt_json: String,
    },
    /// Attestation failed (fail-closed); no key material is released.
    Deny { reason: String },
}

impl KeyReleaseDecision {
    /// Whether this is an [`KeyReleaseDecision::Allow`].
    pub fn is_allow(&self) -> bool {
        matches!(self, KeyReleaseDecision::Allow { .. })
    }

    /// The deny reason, if this is a deny.
    pub fn deny_reason(&self) -> Option<&str> {
        match self {
            KeyReleaseDecision::Deny { reason } => Some(reason.as_str()),
            KeyReleaseDecision::Allow { .. } => None,
        }
    }
}

/// Stateless evaluator that releases keys per a fixed [`KmsPolicy`].
#[derive(Debug, Clone)]
pub struct KmsSimulator {
    pub policy: KmsPolicy,
}

impl KmsSimulator {
    /// Build a simulator bound to `policy`.
    pub fn new(policy: KmsPolicy) -> Self {
        KmsSimulator { policy }
    }

    /// Internal gate check returning the first failing reason, fail-closed.
    fn deny_reason_for(&self, req: &KeyReleaseRequest) -> Option<String> {
        // V9: a modified boot policy must block release — check it first.
        if req.boot_policy_hash != self.policy.expected_boot_policy_hash {
            return Some(format!(
                "boot_policy_hash_mismatch: expected {}, got {}",
                self.policy.expected_boot_policy_hash, req.boot_policy_hash
            ));
        }
        if let Some(pcr) = req.pcrs.first_mismatch(&self.policy.expected_pcrs) {
            return Some(format!("pcr_mismatch: pcr{pcr}"));
        }
        if !self
            .policy
            .allowed_capsule_hashes
            .iter()
            .any(|h| h == &req.capsule_hash)
        {
            return Some(format!("capsule_not_allowlisted: {}", req.capsule_hash));
        }
        if req.hypervisor_version < self.policy.min_hypervisor_version {
            return Some(format!(
                "hypervisor_version_below_minimum: {} < {}",
                req.hypervisor_version, self.policy.min_hypervisor_version
            ));
        }
        None
    }

    /// Simulated key wrap: deterministic 48-byte VMK derived from the request
    /// and the pinned boot policy. No randomness, no clock.
    fn simulated_wrapped_vmk(&self, req: &KeyReleaseRequest) -> SecretHandle {
        let mut hasher = Sha384::new();
        hasher.update(b"vmk-wrap\x00");
        hasher.update(req.device_id.as_bytes());
        hasher.update(b"\x00");
        hasher.update(req.vm_id.as_bytes());
        hasher.update(b"\x00");
        hasher.update(req.capsule_hash.as_bytes());
        hasher.update(b"\x00");
        hasher.update(self.policy.expected_boot_policy_hash.as_bytes());
        SecretHandle::new(hasher.finalize().to_vec())
    }

    /// Evaluate `req` against the policy, recording a `key_release` receipt on
    /// `chain` and returning the release decision.
    pub fn evaluate(
        &self,
        req: &KeyReleaseRequest,
        chain: &mut ReceiptChain,
    ) -> KeyReleaseDecision {
        let inputs_hash = req.inputs_hash();
        match self.deny_reason_for(req) {
            Some(reason) => {
                chain.append(
                    ReceiptEvent::KeyRelease,
                    req.vm_id.clone(),
                    "deny",
                    KMS_POLICY_ID,
                    inputs_hash,
                );
                KeyReleaseDecision::Deny { reason }
            }
            None => {
                let receipt = chain.append(
                    ReceiptEvent::KeyRelease,
                    req.vm_id.clone(),
                    "allow",
                    KMS_POLICY_ID,
                    inputs_hash,
                );
                let receipt_json = serde_json::to_string_pretty(receipt)
                    .expect("appended receipt serializes");
                KeyReleaseDecision::Allow {
                    wrapped_vmk: self.simulated_wrapped_vmk(req),
                    receipt_json,
                }
            }
        }
    }

    /// Evaluate a [`SuitedKeyReleaseRequest`], delegating to [`Self::evaluate`].
    ///
    /// The suite binding is carried for evidence/audit only and does not change
    /// the gate logic, so existing `evaluate()` semantics are preserved exactly.
    pub fn evaluate_suited(
        &self,
        req: &SuitedKeyReleaseRequest,
        chain: &mut ReceiptChain,
    ) -> KeyReleaseDecision {
        self.evaluate(&req.request, chain)
    }

    /// Produce an [`AttestedUnlockEvidence`] summary for an *allowed* decision.
    ///
    /// Returns `None` (fail-closed) when `decision` is a deny: no positive
    /// unlock evidence is ever minted for a denied request. On an allow it
    /// recomputes each gate result against this simulator's policy so the
    /// summary is self-describing and embeddable in a receipt. This is a pure
    /// read of the request + policy; it does not mutate the chain or re-evaluate.
    pub fn attested_unlock_evidence(
        &self,
        req: &KeyReleaseRequest,
        suite: Option<&SuiteBinding>,
        decision: &KeyReleaseDecision,
    ) -> Option<AttestedUnlockEvidence> {
        if !decision.is_allow() {
            return None;
        }
        Some(AttestedUnlockEvidence {
            format: ATTESTED_UNLOCK_FORMAT.to_string(),
            device_id: req.device_id.clone(),
            vm_id: req.vm_id.clone(),
            suite: suite.cloned(),
            pcr_match: req.pcrs.satisfies(&self.policy.expected_pcrs),
            boot_policy_match: req.boot_policy_hash == self.policy.expected_boot_policy_hash,
            capsule_allowlisted: self
                .policy
                .allowed_capsule_hashes
                .iter()
                .any(|h| h == &req.capsule_hash),
            hypervisor_version_ok: req.hypervisor_version >= self.policy.min_hypervisor_version,
            inputs_hash: req.inputs_hash(),
            policy_id: KMS_POLICY_ID.to_string(),
        })
    }

    /// Evidence helper for a [`SuitedKeyReleaseRequest`], forwarding its carried
    /// [`SuiteBinding`] into [`Self::attested_unlock_evidence`].
    pub fn attested_unlock_evidence_suited(
        &self,
        req: &SuitedKeyReleaseRequest,
        decision: &KeyReleaseDecision,
    ) -> Option<AttestedUnlockEvidence> {
        self.attested_unlock_evidence(&req.request, req.suite.as_ref(), decision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcr::{PCR0, PCR11, PCR7};

    fn expected_pcrs() -> PcrBank {
        let mut p = PcrBank::new();
        p.set(PCR0, "sha384:p0")
            .set(PCR7, "sha384:p7")
            .set(PCR11, "sha384:p11");
        p
    }

    fn policy() -> KmsPolicy {
        KmsPolicy {
            expected_pcrs: expected_pcrs(),
            min_hypervisor_version: 5,
            allowed_capsule_hashes: vec!["sha384:capsule-good".to_string()],
            expected_boot_policy_hash: "sha384:bootpol-good".to_string(),
        }
    }

    fn good_request() -> KeyReleaseRequest {
        KeyReleaseRequest {
            request_type: "key_release".to_string(),
            device_id: "dev-1".to_string(),
            vm_id: "vm-1".to_string(),
            capsule_hash: "sha384:capsule-good".to_string(),
            boot_policy_hash: "sha384:bootpol-good".to_string(),
            pcrs: expected_pcrs(),
            hypervisor_version: 7,
            nonce: "nonce-0001".to_string(),
        }
    }

    #[test]
    fn matching_request_allows_and_chain_verifies() {
        let sim = KmsSimulator::new(policy());
        let mut chain = ReceiptChain::new();
        let decision = sim.evaluate(&good_request(), &mut chain);

        match decision {
            KeyReleaseDecision::Allow {
                wrapped_vmk,
                receipt_json,
            } => {
                assert_eq!(wrapped_vmk.len(), 48); // SHA-384 = 48 bytes
                assert!(receipt_json.contains("key_release"));
                assert!(receipt_json.contains("allow"));
            }
            KeyReleaseDecision::Deny { reason } => panic!("expected allow, got deny: {reason}"),
        }

        assert_eq!(chain.len(), 1);
        assert_eq!(chain.verify(), Ok(()));
        assert_eq!(chain.receipts()[0].event, "key_release");
        assert_eq!(chain.receipts()[0].decision, "allow");
    }

    #[test]
    fn pcr_mismatch_denies() {
        let sim = KmsSimulator::new(policy());
        let mut chain = ReceiptChain::new();
        let mut req = good_request();
        req.pcrs.set(PCR7, "sha384:tampered");

        let decision = sim.evaluate(&req, &mut chain);
        assert!(!decision.is_allow());
        assert!(decision.deny_reason().unwrap().starts_with("pcr_mismatch"));
        // Deny still recorded for audit, and the chain stays valid.
        assert_eq!(chain.len(), 1);
        assert_eq!(chain.receipts()[0].decision, "deny");
        assert_eq!(chain.verify(), Ok(()));
    }

    #[test]
    fn modified_boot_policy_denies_v9() {
        let sim = KmsSimulator::new(policy());
        let mut chain = ReceiptChain::new();
        let mut req = good_request();
        req.boot_policy_hash = "sha384:bootpol-EVIL".to_string();

        let decision = sim.evaluate(&req, &mut chain);
        assert!(!decision.is_allow());
        assert!(decision
            .deny_reason()
            .unwrap()
            .starts_with("boot_policy_hash_mismatch"));
        assert_eq!(chain.verify(), Ok(()));
    }

    #[test]
    fn non_allowlisted_capsule_denies() {
        let sim = KmsSimulator::new(policy());
        let mut chain = ReceiptChain::new();
        let mut req = good_request();
        req.capsule_hash = "sha384:capsule-unknown".to_string();

        let decision = sim.evaluate(&req, &mut chain);
        assert!(!decision.is_allow());
        assert!(decision
            .deny_reason()
            .unwrap()
            .starts_with("capsule_not_allowlisted"));
    }

    #[test]
    fn below_minimum_version_denies() {
        let sim = KmsSimulator::new(policy());
        let mut chain = ReceiptChain::new();
        let mut req = good_request();
        req.hypervisor_version = 4; // min is 5

        let decision = sim.evaluate(&req, &mut chain);
        assert!(!decision.is_allow());
        assert!(decision
            .deny_reason()
            .unwrap()
            .starts_with("hypervisor_version_below_minimum"));
    }

    #[test]
    fn boot_policy_checked_before_other_gates() {
        // Everything wrong at once -> boot policy reported first (V9 priority).
        let sim = KmsSimulator::new(policy());
        let mut chain = ReceiptChain::new();
        let mut req = good_request();
        req.boot_policy_hash = "evil".to_string();
        req.capsule_hash = "evil".to_string();
        req.hypervisor_version = 0;
        req.pcrs = PcrBank::new();

        let decision = sim.evaluate(&req, &mut chain);
        assert!(decision
            .deny_reason()
            .unwrap()
            .starts_with("boot_policy_hash_mismatch"));
    }

    #[test]
    fn wrapped_vmk_is_deterministic() {
        let sim = KmsSimulator::new(policy());
        let a = sim.simulated_wrapped_vmk(&good_request());
        let b = sim.simulated_wrapped_vmk(&good_request());
        let ba = a.expose(|x| x.to_vec());
        let bb = b.expose(|x| x.to_vec());
        assert_eq!(ba, bb);
    }

    #[test]
    fn inputs_hash_is_deterministic_and_prefixed() {
        let req = good_request();
        let h1 = req.inputs_hash();
        let h2 = req.inputs_hash();
        assert_eq!(h1, h2);
        assert!(h1.starts_with("sha384:"));
    }

    #[test]
    fn request_json_round_trips() {
        let req = good_request();
        let json = req.to_json().unwrap();
        let back = KeyReleaseRequest::from_json(&json).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn suite_binding_builders_and_canonical() {
        let s = SuiteBinding::transition_768();
        assert_eq!(s.classical, "x25519");
        assert_eq!(s.pqc, "ml-kem-768");
        assert_eq!(s.combiner, "hkdf-sha384");
        assert_eq!(s.canonical(), "x25519+ml-kem-768+hkdf-sha384");

        let h = SuiteBinding::high_assurance_1024();
        assert_eq!(h.canonical(), "x25519+ml-kem-1024+hkdf-sha384");

        let c = SuiteBinding::new("a", "b", "c");
        assert_eq!(c.canonical(), "a+b+c");
        assert_eq!(SuiteBinding::default(), SuiteBinding::new("", "", ""));
    }

    #[test]
    fn attested_unlock_constructor_builds_pcr0_7_11_request() {
        let req = KeyReleaseRequest::attested_unlock(
            "dev-1",
            "vm-1",
            "sha384:capsule-good",
            "sha384:bootpol-good",
            "sha384:p0",
            "sha384:p7",
            "sha384:p11",
            7,
            "nonce-0001",
        );
        assert_eq!(req.request_type, "key_release");
        assert_eq!(req.pcrs.get(PCR0), Some("sha384:p0"));
        assert_eq!(req.pcrs.get(PCR7), Some("sha384:p7"));
        assert_eq!(req.pcrs.get(PCR11), Some("sha384:p11"));
        assert_eq!(req.pcrs.len(), 3);
        // It satisfies the standard policy and is allowed.
        let sim = KmsSimulator::new(policy());
        let mut chain = ReceiptChain::new();
        assert!(sim.evaluate(&req, &mut chain).is_allow());
    }

    #[test]
    fn with_suite_does_not_alter_base_request_or_decision() {
        let base = good_request();
        let suited = base.clone().with_suite(SuiteBinding::transition_768());
        // The flattened request is byte-for-byte the original.
        assert_eq!(suited.request, base);
        assert_eq!(suited.suite, Some(SuiteBinding::transition_768()));

        let sim = KmsSimulator::new(policy());
        let mut a = ReceiptChain::new();
        let mut b = ReceiptChain::new();
        let d_base = sim.evaluate(&base, &mut a);
        let d_suited = sim.evaluate_suited(&suited, &mut b);
        assert_eq!(d_base.is_allow(), d_suited.is_allow());
        // Same inputs_hash => suite carriage didn't perturb the canonical request.
        assert_eq!(a.receipts()[0].inputs_hash, b.receipts()[0].inputs_hash);
    }

    #[test]
    fn evidence_minted_on_allow_with_all_gates_true() {
        let sim = KmsSimulator::new(policy());
        let mut chain = ReceiptChain::new();
        let req = good_request();
        let decision = sim.evaluate(&req, &mut chain);
        let suite = SuiteBinding::high_assurance_1024();
        let ev = sim
            .attested_unlock_evidence(&req, Some(&suite), &decision)
            .expect("allow yields evidence");
        assert_eq!(ev.format, ATTESTED_UNLOCK_FORMAT);
        assert_eq!(ev.device_id, "dev-1");
        assert_eq!(ev.vm_id, "vm-1");
        assert_eq!(ev.suite, Some(suite));
        assert!(ev.pcr_match);
        assert!(ev.boot_policy_match);
        assert!(ev.capsule_allowlisted);
        assert!(ev.hypervisor_version_ok);
        assert_eq!(ev.policy_id, KMS_POLICY_ID);
        assert_eq!(ev.inputs_hash, req.inputs_hash());
    }

    #[test]
    fn no_evidence_on_deny_fail_closed() {
        let sim = KmsSimulator::new(policy());
        let mut chain = ReceiptChain::new();
        let mut req = good_request();
        req.boot_policy_hash = "sha384:bootpol-EVIL".to_string();
        let decision = sim.evaluate(&req, &mut chain);
        assert!(!decision.is_allow());
        // Fail-closed: no positive unlock evidence for a denied request.
        assert!(sim
            .attested_unlock_evidence(&req, None, &decision)
            .is_none());
    }

    #[test]
    fn evidence_suited_forwards_carried_suite() {
        let sim = KmsSimulator::new(policy());
        let mut chain = ReceiptChain::new();
        let suited = good_request().with_suite(SuiteBinding::transition_768());
        let decision = sim.evaluate_suited(&suited, &mut chain);
        let ev = sim
            .attested_unlock_evidence_suited(&suited, &decision)
            .expect("allow yields evidence");
        assert_eq!(ev.suite, Some(SuiteBinding::transition_768()));
        // No suite carried => None in evidence.
        let bare = SuitedKeyReleaseRequest::new(good_request());
        let d2 = sim.evaluate_suited(&bare, &mut chain);
        let ev2 = sim.attested_unlock_evidence_suited(&bare, &d2).unwrap();
        assert_eq!(ev2.suite, None);
    }

    #[test]
    fn suited_request_json_round_trips_and_is_backward_compatible() {
        let suited = good_request().with_suite(SuiteBinding::transition_768());
        let json = suited.to_json().unwrap();
        let back = SuitedKeyReleaseRequest::from_json(&json).unwrap();
        assert_eq!(back, suited);
        assert!(json.contains("\"request\""));
        assert!(json.contains("\"suite\""));

        // A bare carrier (no suite) round-trips with suite => None.
        let bare = SuitedKeyReleaseRequest::new(good_request());
        let bare_back = SuitedKeyReleaseRequest::from_json(&bare.to_json().unwrap()).unwrap();
        assert_eq!(bare_back.request, good_request());
        assert_eq!(bare_back.suite, None);

        // `suite` is `#[serde(default)]`: a payload that omits it parses to None.
        let no_suite = format!(
            "{{\"request\":{}}}",
            good_request().to_json().unwrap()
        );
        let parsed = SuitedKeyReleaseRequest::from_json(&no_suite).unwrap();
        assert_eq!(parsed.request, good_request());
        assert_eq!(parsed.suite, None);
    }

    #[test]
    fn evidence_json_round_trips() {
        let sim = KmsSimulator::new(policy());
        let mut chain = ReceiptChain::new();
        let req = good_request();
        let decision = sim.evaluate(&req, &mut chain);
        let ev = sim
            .attested_unlock_evidence(&req, Some(&SuiteBinding::transition_768()), &decision)
            .unwrap();
        let json = ev.to_json().unwrap();
        assert!(json.contains(ATTESTED_UNLOCK_FORMAT));
        let back = AttestedUnlockEvidence::from_json(&json).unwrap();
        assert_eq!(back, ev);
    }

    #[test]
    fn allow_then_deny_chain_links_and_verifies() {
        let sim = KmsSimulator::new(policy());
        let mut chain = ReceiptChain::new();
        let _ = sim.evaluate(&good_request(), &mut chain);
        let mut bad = good_request();
        bad.boot_policy_hash = "x".to_string();
        let _ = sim.evaluate(&bad, &mut chain);
        assert_eq!(chain.len(), 2);
        assert_eq!(chain.verify(), Ok(()));
        assert_eq!(chain.receipts()[0].decision, "allow");
        assert_eq!(chain.receipts()[1].decision, "deny");
    }
}
