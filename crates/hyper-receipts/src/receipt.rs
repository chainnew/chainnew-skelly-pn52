//! Hash-chained, tamper-evident audit receipts (`chain.receipt.v1`).
//!
//! A [`ReceiptChain`] is an append-only log where each [`Receipt`] commits to
//! the previous receipt's hash, forming a tamper-evident spine for the
//! attest / vm / control subsystems.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::hash::{genesis_hash, sha384_hex};

/// JSON schema identifier carried by every [`Receipt`].
pub const RECEIPT_SCHEMA: &str = "chain.receipt.v1";

fn default_receipt_schema() -> String {
    RECEIPT_SCHEMA.to_string()
}

/// Canonical receipt event names. Use [`ReceiptEvent::as_str`] for the wire
/// form; the chain accepts any `&str` event so callers may extend this set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptEvent {
    Boot,
    FirmwareBaseline,
    VmDefine,
    ManifestVerify,
    KeyRelease,
    VmLaunch,
    VmExitFault,
    DeviceAssign,
    Snapshot,
    Destroy,
    Recovery,
    PolicyChange,
}

impl ReceiptEvent {
    /// Stable snake_case wire name for this event.
    pub fn as_str(self) -> &'static str {
        match self {
            ReceiptEvent::Boot => "boot",
            ReceiptEvent::FirmwareBaseline => "firmware_baseline",
            ReceiptEvent::VmDefine => "vm_define",
            ReceiptEvent::ManifestVerify => "manifest_verify",
            ReceiptEvent::KeyRelease => "key_release",
            ReceiptEvent::VmLaunch => "vm_launch",
            ReceiptEvent::VmExitFault => "vm_exit_fault",
            ReceiptEvent::DeviceAssign => "device_assign",
            ReceiptEvent::Snapshot => "snapshot",
            ReceiptEvent::Destroy => "destroy",
            ReceiptEvent::Recovery => "recovery",
            ReceiptEvent::PolicyChange => "policy_change",
        }
    }
}

impl From<ReceiptEvent> for String {
    fn from(e: ReceiptEvent) -> String {
        e.as_str().to_string()
    }
}

/// Optional detached-signature descriptor for a receipt. The signature itself
/// lives out of band; this only records the algorithm and signing key id.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct ReceiptSignature {
    pub alg: String,
    pub key_id: String,
}

/// A single tamper-evident audit receipt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct Receipt {
    #[serde(default = "default_receipt_schema")]
    pub schema: String,
    pub receipt_id: String,
    pub event: String,
    pub subject: String,
    pub decision: String,
    pub policy_id: String,
    pub inputs_hash: String,
    pub previous_receipt_hash: String,
    pub receipt_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<ReceiptSignature>,
}

/// The ordered, canonical subset of fields that the `receipt_hash` commits to.
/// `receipt_id` and `signature` are intentionally excluded.
#[derive(Serialize)]
struct ReceiptCanonical<'a> {
    schema: &'a str,
    event: &'a str,
    subject: &'a str,
    decision: &'a str,
    policy_id: &'a str,
    inputs_hash: &'a str,
    previous_receipt_hash: &'a str,
}

fn compute_receipt_hash(
    schema: &str,
    event: &str,
    subject: &str,
    decision: &str,
    policy_id: &str,
    inputs_hash: &str,
    previous_receipt_hash: &str,
) -> String {
    let canonical = ReceiptCanonical {
        schema,
        event,
        subject,
        decision,
        policy_id,
        inputs_hash,
        previous_receipt_hash,
    };
    // serde_json preserves struct field order, giving a deterministic encoding.
    let bytes = serde_json::to_vec(&canonical).expect("canonical receipt serializes");
    sha384_hex(&bytes)
}

/// Errors raised while verifying or rehydrating a [`ReceiptChain`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ChainError {
    #[error("receipt {index} has wrong schema: expected {expected}, found {found}")]
    BadSchema {
        index: usize,
        expected: String,
        found: String,
    },
    #[error("receipt {index} hash mismatch: expected {expected}, found {found}")]
    HashMismatch {
        index: usize,
        expected: String,
        found: String,
    },
    #[error("receipt {index} broken link: previous_receipt_hash {found} != {expected}")]
    BrokenLink {
        index: usize,
        expected: String,
        found: String,
    },
    #[error("json error: {0}")]
    Json(String),
}

/// An append-only, hash-chained sequence of [`Receipt`]s.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct ReceiptChain {
    genesis_hash: String,
    receipts: Vec<Receipt>,
}

impl Default for ReceiptChain {
    fn default() -> Self {
        Self::new()
    }
}

impl ReceiptChain {
    /// Create an empty chain anchored to the fixed genesis hash.
    pub fn new() -> Self {
        ReceiptChain {
            genesis_hash: genesis_hash(),
            receipts: Vec::new(),
        }
    }

    /// Hash that the first appended receipt links back to.
    pub fn genesis_hash(&self) -> &str {
        &self.genesis_hash
    }

    /// Hash of the most recent receipt, or the genesis hash if empty.
    pub fn head_hash(&self) -> &str {
        match self.receipts.last() {
            Some(r) => &r.receipt_hash,
            None => &self.genesis_hash,
        }
    }

    /// Append a new receipt, computing its `receipt_hash` over the canonical
    /// fields and linking `previous_receipt_hash` to the prior head.
    ///
    /// `event` accepts anything convertible into a `String`, including
    /// [`ReceiptEvent`] and `&str`.
    pub fn append(
        &mut self,
        event: impl Into<String>,
        subject: impl Into<String>,
        decision: impl Into<String>,
        policy_id: impl Into<String>,
        inputs_hash: impl Into<String>,
    ) -> &Receipt {
        let event = event.into();
        let subject = subject.into();
        let decision = decision.into();
        let policy_id = policy_id.into();
        let inputs_hash = inputs_hash.into();
        let previous_receipt_hash = self.head_hash().to_string();
        let schema = RECEIPT_SCHEMA.to_string();

        let receipt_hash = compute_receipt_hash(
            &schema,
            &event,
            &subject,
            &decision,
            &policy_id,
            &inputs_hash,
            &previous_receipt_hash,
        );

        // Deterministic id: append counter + a prefix of the content hash.
        let index = self.receipts.len();
        let hex_part = receipt_hash
            .strip_prefix("sha384:")
            .unwrap_or(&receipt_hash);
        let receipt_id = format!("rcpt-{index:06}-{}", &hex_part[..16]);

        self.receipts.push(Receipt {
            schema,
            receipt_id,
            event,
            subject,
            decision,
            policy_id,
            inputs_hash,
            previous_receipt_hash,
            receipt_hash,
            signature: None,
        });
        self.receipts
            .last()
            .expect("just pushed a receipt")
    }

    /// All receipts in append order.
    pub fn receipts(&self) -> &[Receipt] {
        &self.receipts
    }

    /// Number of receipts in the chain.
    pub fn len(&self) -> usize {
        self.receipts.len()
    }

    /// Whether the chain holds no receipts.
    pub fn is_empty(&self) -> bool {
        self.receipts.is_empty()
    }

    /// Recompute every receipt hash and verify all prev-links. Fails closed:
    /// any schema mismatch, hash mismatch, or broken link returns `Err`.
    pub fn verify(&self) -> Result<(), ChainError> {
        let mut expected_prev = self.genesis_hash.clone();
        for (index, r) in self.receipts.iter().enumerate() {
            if r.schema != RECEIPT_SCHEMA {
                return Err(ChainError::BadSchema {
                    index,
                    expected: RECEIPT_SCHEMA.to_string(),
                    found: r.schema.clone(),
                });
            }
            if r.previous_receipt_hash != expected_prev {
                return Err(ChainError::BrokenLink {
                    index,
                    expected: expected_prev,
                    found: r.previous_receipt_hash.clone(),
                });
            }
            let recomputed = compute_receipt_hash(
                &r.schema,
                &r.event,
                &r.subject,
                &r.decision,
                &r.policy_id,
                &r.inputs_hash,
                &r.previous_receipt_hash,
            );
            if recomputed != r.receipt_hash {
                return Err(ChainError::HashMismatch {
                    index,
                    expected: recomputed,
                    found: r.receipt_hash.clone(),
                });
            }
            expected_prev = r.receipt_hash.clone();
        }
        Ok(())
    }

    /// Serialize the chain to pretty JSON.
    pub fn to_json(&self) -> Result<String, ChainError> {
        serde_json::to_string_pretty(self).map_err(|e| ChainError::Json(e.to_string()))
    }

    /// Rehydrate a chain from JSON. Does not implicitly verify; call
    /// [`ReceiptChain::verify`] afterwards to validate integrity.
    pub fn from_json(s: &str) -> Result<Self, ChainError> {
        serde_json::from_str(s).map_err(|e| ChainError::Json(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn populate(chain: &mut ReceiptChain) {
        chain.append(ReceiptEvent::Boot, "host", "allow", "pol-boot", "sha384:aa");
        chain.append(
            ReceiptEvent::FirmwareBaseline,
            "fw0",
            "allow",
            "pol-fw",
            "sha384:bb",
        );
        chain.append(
            ReceiptEvent::VmDefine,
            "vm-1",
            "allow",
            "pol-vm",
            "sha384:cc",
        );
        chain.append(
            ReceiptEvent::KeyRelease,
            "vm-1",
            "deny",
            "pol-key",
            "sha384:dd",
        );
    }

    #[test]
    fn empty_chain_head_is_genesis() {
        let chain = ReceiptChain::new();
        assert!(chain.is_empty());
        assert_eq!(chain.head_hash(), chain.genesis_hash());
        assert_eq!(chain.verify(), Ok(()));
    }

    #[test]
    fn append_links_and_verifies() {
        let mut chain = ReceiptChain::new();
        populate(&mut chain);
        assert_eq!(chain.len(), 4);

        // First receipt links to genesis.
        assert_eq!(chain.receipts()[0].previous_receipt_hash, *chain.genesis_hash());
        // Subsequent receipts link to the prior hash.
        for w in chain.receipts().windows(2) {
            assert_eq!(w[1].previous_receipt_hash, w[0].receipt_hash);
        }
        // Head equals the last receipt hash.
        assert_eq!(chain.head_hash(), chain.receipts()[3].receipt_hash);

        assert_eq!(chain.verify(), Ok(()));
    }

    #[test]
    fn event_wire_names_used_in_receipt() {
        let mut chain = ReceiptChain::new();
        chain.append(ReceiptEvent::VmExitFault, "vm-2", "deny", "p", "sha384:00");
        assert_eq!(chain.receipts()[0].event, "vm_exit_fault");
        assert_eq!(chain.receipts()[0].schema, RECEIPT_SCHEMA);
    }

    #[test]
    fn receipt_ids_are_deterministic() {
        let mut a = ReceiptChain::new();
        let mut b = ReceiptChain::new();
        populate(&mut a);
        populate(&mut b);
        let ids_a: Vec<_> = a.receipts().iter().map(|r| r.receipt_id.clone()).collect();
        let ids_b: Vec<_> = b.receipts().iter().map(|r| r.receipt_id.clone()).collect();
        assert_eq!(ids_a, ids_b);
        assert!(ids_a[0].starts_with("rcpt-000000-"));
    }

    #[test]
    fn mutating_middle_receipt_fails_verify() {
        let mut chain = ReceiptChain::new();
        populate(&mut chain);
        assert_eq!(chain.verify(), Ok(()));

        // Tamper with a middle receipt's decision without fixing its hash.
        chain.receipts[1].decision = "allow_tampered".to_string();
        match chain.verify() {
            Err(ChainError::HashMismatch { index, .. }) => assert_eq!(index, 1),
            other => panic!("expected HashMismatch at 1, got {other:?}"),
        }
    }

    #[test]
    fn rehashing_middle_breaks_following_link() {
        let mut chain = ReceiptChain::new();
        populate(&mut chain);

        // Tamper AND recompute the receipt's own hash: the next link must break.
        let r = &mut chain.receipts[1];
        r.subject = "evil".to_string();
        r.receipt_hash = compute_receipt_hash(
            &r.schema,
            &r.event,
            &r.subject,
            &r.decision,
            &r.policy_id,
            &r.inputs_hash,
            &r.previous_receipt_hash,
        );
        match chain.verify() {
            Err(ChainError::BrokenLink { index, .. }) => assert_eq!(index, 2),
            other => panic!("expected BrokenLink at 2, got {other:?}"),
        }
    }

    #[test]
    fn bad_schema_fails_verify() {
        let mut chain = ReceiptChain::new();
        populate(&mut chain);
        chain.receipts[0].schema = "chain.receipt.v0".to_string();
        match chain.verify() {
            Err(ChainError::BadSchema { index, .. }) => assert_eq!(index, 0),
            other => panic!("expected BadSchema, got {other:?}"),
        }
    }

    #[test]
    fn json_round_trip_preserves_and_verifies() {
        let mut chain = ReceiptChain::new();
        populate(&mut chain);
        let json = chain.to_json().unwrap();
        let restored = ReceiptChain::from_json(&json).unwrap();
        assert_eq!(restored, chain);
        assert_eq!(restored.verify(), Ok(()));
    }

    #[test]
    fn signature_is_optional_in_json() {
        let mut chain = ReceiptChain::new();
        chain.append(ReceiptEvent::Snapshot, "vm-9", "allow", "p", "sha384:ff");
        let json = chain.to_json().unwrap();
        // No signature was set, so it is omitted from the encoding.
        assert!(!json.contains("signature"));

        chain.receipts[0].signature = Some(ReceiptSignature {
            alg: "ed25519".to_string(),
            key_id: "key-1".to_string(),
        });
        let json2 = chain.to_json().unwrap();
        assert!(json2.contains("ed25519"));
        let restored = ReceiptChain::from_json(&json2).unwrap();
        assert_eq!(restored, chain);
    }
}
