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
