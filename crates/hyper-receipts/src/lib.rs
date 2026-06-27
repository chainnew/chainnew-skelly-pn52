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
    }
}
