use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};

pub const RECEIPT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptDecision {
    Allow,
    Deny,
    RequireApproval,
    Observe,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct ReceiptSignature {
    pub alg: String,
    pub key_id: String,
    pub sig_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct Receipt {
    pub schema_version: u32,
    pub receipt_id: String,
    pub event: String,
    pub subject: String,
    pub decision: ReceiptDecision,
    pub policy_id: Option<String>,
    pub inputs_hash: String,
    pub previous_receipt_hash: Option<String>,
    pub receipt_hash: String,
    pub signature: Option<ReceiptSignature>,
}

impl Receipt {
    pub fn unsigned(
        receipt_id: impl Into<String>,
        event: impl Into<String>,
        subject: impl Into<String>,
        decision: ReceiptDecision,
        policy_id: Option<String>,
        inputs_hash: impl Into<String>,
        previous_receipt_hash: Option<String>,
    ) -> Self {
        let mut receipt = Self {
            schema_version: RECEIPT_SCHEMA_VERSION,
            receipt_id: receipt_id.into(),
            event: event.into(),
            subject: subject.into(),
            decision,
            policy_id,
            inputs_hash: inputs_hash.into(),
            previous_receipt_hash,
            receipt_hash: String::new(),
            signature: None,
        };
        receipt.receipt_hash = receipt.compute_hash();
        receipt
    }

    pub fn compute_hash(&self) -> String {
        let mut h = Sha384::new();
        h.update(self.schema_version.to_be_bytes());
        h.update(b"\x1f");
        h.update(self.receipt_id.as_bytes());
        h.update(b"\x1f");
        h.update(self.event.as_bytes());
        h.update(b"\x1f");
        h.update(self.subject.as_bytes());
        h.update(b"\x1f");
        h.update(format!("{:?}", self.decision).as_bytes());
        h.update(b"\x1f");
        h.update(self.policy_id.as_deref().unwrap_or(""));
        h.update(b"\x1f");
        h.update(self.inputs_hash.as_bytes());
        h.update(b"\x1f");
        h.update(self.previous_receipt_hash.as_deref().unwrap_or(""));
        format!("sha384:{}", hex::encode(h.finalize()))
    }

    pub fn verify_hash(&self) -> bool {
        self.receipt_hash == self.compute_hash()
    }

    pub fn signed(mut self, signature: ReceiptSignature) -> Self {
        self.signature = Some(signature);
        self
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct ReceiptChain {
    pub receipts: Vec<Receipt>,
}

impl ReceiptChain {
    pub fn new() -> Self {
        Self { receipts: Vec::new() }
    }

    pub fn last_hash(&self) -> Option<String> {
        self.receipts.last().map(|r| r.receipt_hash.clone())
    }

    pub fn push(&mut self, receipt: Receipt) -> bool {
        let expected_prev = self.last_hash();
        let hash_ok = receipt.verify_hash();
        let prev_ok = receipt.previous_receipt_hash == expected_prev;
        if hash_ok && prev_ok {
            self.receipts.push(receipt);
            true
        } else {
            false
        }
    }

    pub fn verify(&self) -> bool {
        let mut previous: Option<String> = None;
        for receipt in &self.receipts {
            if receipt.previous_receipt_hash != previous || !receipt.verify_hash() {
                return false;
            }
            previous = Some(receipt.receipt_hash.clone());
        }
        true
    }
}

pub fn sha384_hex(bytes: &[u8]) -> String {
    let mut h = Sha384::new();
    h.update(bytes);
    format!("sha384:{}", hex::encode(h.finalize()))
}
//! hyper-receipts — hash-chained, tamper-evident audit receipts and a
//! hash-chained security-event log (backlog S0) for the chain.new hyper-slate
//! runtime. This is the audit spine shared by the attest / vm / control layers.
//!
//! Two independent SHA-384 hash chains are provided:
//!
//! * [`ReceiptChain`] of [`Receipt`]s (`chain.receipt.v1`) — one signed-able
//!   receipt per policy-relevant decision.
//! * [`SecurityLog`] of [`SecurityEvent`]s (`chain.security_event.v1`) —
//!   structured, severity-tagged security events.
//!
//! Both chains are deterministic (no randomness, no clocks) and fail closed on
//! [`ReceiptChain::verify`] / [`SecurityLog::verify`].
#![forbid(unsafe_code)]

mod hash;
mod receipt;
mod security;

pub use hash::{genesis_hash, sha384_hex};
pub use receipt::{
    ChainError, Receipt, ReceiptChain, ReceiptEvent, ReceiptSignature, RECEIPT_SCHEMA,
};
pub use security::{
    SecurityEvent, SecurityLog, SecurityLogError, Severity, SECURITY_EVENT_SCHEMA,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_hash_verifies() {
        let receipt = Receipt::unsigned(
            "r1",
            "vm_launch",
            "vm:guest-zero",
            ReceiptDecision::Allow,
            Some("lab".to_string()),
            "sha384:inputs",
            None,
        );
        assert!(receipt.verify_hash());
    }

    #[test]
    fn receipt_chain_detects_wrong_previous_hash() {
        let mut chain = ReceiptChain::new();
        let first = Receipt::unsigned(
            "r1",
            "vm_define",
            "vm:a",
            ReceiptDecision::Allow,
            None,
            "sha384:a",
            None,
        );
        assert!(chain.push(first));

        let bad = Receipt::unsigned(
            "r2",
            "vm_launch",
            "vm:a",
            ReceiptDecision::Allow,
            None,
            "sha384:b",
            Some("sha384:not-the-previous".to_string()),
        );
        assert!(!chain.push(bad));
    fn sha384_hex_format_is_stable() {
        // SHA-384 of the empty input is a known constant.
        let h = sha384_hex(b"");
        assert!(h.starts_with("sha384:"));
        assert_eq!(h.len(), "sha384:".len() + 96);
        assert_eq!(
            h,
            "sha384:38b060a751ac96384cd9327eb1b1e36a21fdb71114be0743\
4c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
    }

    #[test]
    fn genesis_hash_is_fixed_all_zero() {
        assert_eq!(genesis_hash(), format!("sha384:{}", "0".repeat(96)));
    }

    #[test]
    fn the_two_chains_use_distinct_schemas() {
        assert_ne!(RECEIPT_SCHEMA, SECURITY_EVENT_SCHEMA);
        assert_eq!(RECEIPT_SCHEMA, "chain.receipt.v1");
        assert_eq!(SECURITY_EVENT_SCHEMA, "chain.security_event.v1");
    }
}
