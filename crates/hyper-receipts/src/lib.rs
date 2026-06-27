//! Hash-chained, tamper-evident audit receipts.
//!
//! Maps to SOW-HSLATE-PN52-002 Part B §12 ("Receipts and audit chain") and the
//! `chain.receipt.v1` schema. Each receipt commits to the hash of the previous
//! receipt, so any edit, reorder, or deletion in the chain is detectable by
//! recomputing hashes forward from the genesis link.
//!
//! V0 scope (host/QEMU): the chain is deterministic and signature-free. Real
//! Ed25519/ML-DSA signing of receipts is a later phase (V4+/attested unlock).
//! We therefore key the chain on a logical sequence number rather than a
//! wall-clock timestamp, which keeps tamper-evidence reproducible in tests.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};

pub const RECEIPT_SCHEMA: &str = "chain.receipt.v1";

/// The genesis link that the first real receipt chains from. A fixed sentinel
/// rather than all-zeroes so a truncated chain cannot be silently re-rooted.
pub const GENESIS_PREV_HASH: &str = "sha384:genesis";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny,
    RequireApproval,
}

/// A single tamper-evident audit record. `receipt_hash` is derived from the
/// canonical encoding of every other field, so it is never set by callers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Receipt {
    pub schema: String,
    /// Logical position in the chain; genesis-chained receipt is `seq = 0`.
    pub seq: u64,
    /// Deterministic id derived from the receipt hash (no RNG/clock in V0).
    pub receipt_id: String,
    pub event: String,
    pub subject: String,
    pub decision: Decision,
    pub policy_id: String,
    /// Hash over the decision inputs (manifest, measurements, request, …).
    pub inputs_hash: String,
    pub previous_receipt_hash: String,
    pub receipt_hash: String,
}

impl Receipt {
    /// Recompute the canonical hash for this receipt's contents.
    fn compute_hash(
        seq: u64,
        event: &str,
        subject: &str,
        decision: &Decision,
        policy_id: &str,
        inputs_hash: &str,
        previous_receipt_hash: &str,
    ) -> String {
        // Length-prefixed field concatenation so distinct field boundaries can
        // never collide (e.g. "ab"+"c" vs "a"+"bc") — a classic hash-chain bug.
        let decision = match decision {
            Decision::Allow => "allow",
            Decision::Deny => "deny",
            Decision::RequireApproval => "require_approval",
        };
        let mut h = Sha384::new();
        for field in [
            RECEIPT_SCHEMA,
            event,
            subject,
            decision,
            policy_id,
            inputs_hash,
            previous_receipt_hash,
        ] {
            h.update((field.len() as u64).to_le_bytes());
            h.update(field.as_bytes());
        }
        h.update(seq.to_le_bytes());
        format!("sha384:{}", hex::encode(h.finalize()))
    }

    /// Verify this receipt's stored hash matches its contents.
    fn recompute_matches(&self) -> bool {
        let expected = Self::compute_hash(
            self.seq,
            &self.event,
            &self.subject,
            &self.decision,
            &self.policy_id,
            &self.inputs_hash,
            &self.previous_receipt_hash,
        );
        expected == self.receipt_hash
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReceiptError {
    #[error("receipt {seq} has a corrupted hash")]
    HashMismatch { seq: u64 },
    #[error("receipt {seq} does not chain to the previous receipt")]
    BrokenLink { seq: u64 },
    #[error("receipt {seq} is out of sequence")]
    SequenceGap { seq: u64 },
}

/// An append-only, hash-chained log. `head_hash()` is the commitment a caller
/// (e.g. an attestation receipt or an exported evidence bundle) can pin.
#[derive(Debug, Clone, Default)]
pub struct ReceiptChain {
    receipts: Vec<Receipt>,
}

impl ReceiptChain {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.receipts.is_empty()
    }

    pub fn len(&self) -> usize {
        self.receipts.len()
    }

    pub fn receipts(&self) -> &[Receipt] {
        &self.receipts
    }

    /// Hash of the most recent receipt, or the genesis sentinel if empty.
    pub fn head_hash(&self) -> String {
        self.receipts
            .last()
            .map(|r| r.receipt_hash.clone())
            .unwrap_or_else(|| GENESIS_PREV_HASH.to_string())
    }

    /// Append a new receipt, chaining it to the current head.
    pub fn append(
        &mut self,
        event: impl Into<String>,
        subject: impl Into<String>,
        decision: Decision,
        policy_id: impl Into<String>,
        inputs_hash: impl Into<String>,
    ) -> &Receipt {
        let seq = self.receipts.len() as u64;
        let previous_receipt_hash = self.head_hash();
        let event = event.into();
        let subject = subject.into();
        let policy_id = policy_id.into();
        let inputs_hash = inputs_hash.into();
        let receipt_hash = Receipt::compute_hash(
            seq,
            &event,
            &subject,
            &decision,
            &policy_id,
            &inputs_hash,
            &previous_receipt_hash,
        );
        // First 16 bytes of the hash are a stable, collision-resistant id.
        let receipt_id = receipt_hash
            .strip_prefix("sha384:")
            .map(|h| h[..32].to_string())
            .unwrap_or_default();
        self.receipts.push(Receipt {
            schema: RECEIPT_SCHEMA.to_string(),
            seq,
            receipt_id,
            event,
            subject,
            decision,
            policy_id,
            inputs_hash,
            previous_receipt_hash,
            receipt_hash,
        });
        self.receipts.last().expect("just pushed")
    }

    /// Walk the chain from genesis, proving every link and stored hash. Any
    /// tamper (edited field, reordered or dropped link) fails verification.
    pub fn verify(&self) -> Result<(), ReceiptError> {
        let mut prev = GENESIS_PREV_HASH.to_string();
        for (idx, r) in self.receipts.iter().enumerate() {
            if r.seq != idx as u64 {
                return Err(ReceiptError::SequenceGap { seq: r.seq });
            }
            if r.previous_receipt_hash != prev {
                return Err(ReceiptError::BrokenLink { seq: r.seq });
            }
            if !r.recompute_matches() {
                return Err(ReceiptError::HashMismatch { seq: r.seq });
            }
            prev = r.receipt_hash.clone();
        }
        Ok(())
    }

    /// Serialize the whole chain (for an incident export bundle, S15).
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(&self.receipts)
    }
}

/// Convenience: hash an arbitrary byte slice as decision-input commitment.
pub fn hash_inputs(bytes: &[u8]) -> String {
    let mut h = Sha384::new();
    h.update(bytes);
    format!("sha384:{}", hex::encode(h.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_chain() -> ReceiptChain {
        let mut c = ReceiptChain::new();
        c.append("boot", "device:pn52-lab-001", Decision::Allow, "p1", hash_inputs(b"boot"));
        c.append("vm_launch", "vm:dev-001", Decision::Allow, "p1", hash_inputs(b"launch"));
        c.append("vm_stop", "vm:dev-001", Decision::Allow, "p1", hash_inputs(b"stop"));
        c
    }

    #[test]
    fn fresh_chain_verifies() {
        assert!(sample_chain().verify().is_ok());
    }

    #[test]
    fn first_receipt_chains_from_genesis() {
        let c = sample_chain();
        assert_eq!(c.receipts()[0].previous_receipt_hash, GENESIS_PREV_HASH);
        assert_eq!(c.receipts()[1].previous_receipt_hash, c.receipts()[0].receipt_hash);
    }

    #[test]
    fn edited_field_is_detected() {
        let mut c = sample_chain();
        c.receipts[1].subject = "vm:attacker-001".to_string();
        assert_eq!(c.verify(), Err(ReceiptError::HashMismatch { seq: 1 }));
    }

    #[test]
    fn dropped_link_is_detected() {
        let mut c = sample_chain();
        c.receipts.remove(1);
        // seq 2 now sits at index 1 -> sequence gap caught first.
        assert!(c.verify().is_err());
    }

    #[test]
    fn reordered_links_are_detected() {
        let mut c = sample_chain();
        c.receipts.swap(0, 1);
        assert!(c.verify().is_err());
    }

    #[test]
    fn head_hash_tracks_last() {
        let c = sample_chain();
        assert_eq!(c.head_hash(), c.receipts().last().unwrap().receipt_hash);
    }

    #[test]
    fn empty_chain_head_is_genesis() {
        assert_eq!(ReceiptChain::new().head_hash(), GENESIS_PREV_HASH);
    }
}
