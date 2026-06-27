//! hyper-policy — deny-by-default policy engine and policy-as-code document
//! (framework §9) for the chain.new hyper-slate PN52 runtime.
//!
//! A [`PolicyDocument`] is parsed from the SOW JSON and enforced by a
//! [`DefaultPolicyEngine`] implementing the [`PolicyEngine`] trait. Every
//! evaluation is fail-closed: it begins at "deny" and only an explicit,
//! fully-satisfied set of conditions yields [`PolicyDecision::Allow`] with a
//! [`PolicyReceipt`]. Decisions and receipts are deterministic (content-hash
//! derived, no clocks, no randomness).
//!
//! This crate defines its own lightweight [`PolicyReceipt`] rather than
//! depending on `hyper-receipts`, to avoid a dependency cycle.
#![forbid(unsafe_code)]

mod document;
mod engine;
mod hash;

pub use document::{
    KeyReleasePolicy, PolicyDocument, PolicyError, StoragePolicy, POLICY_SCHEMA_VERSION,
};
pub use engine::{
    DefaultPolicyEngine, DenyReason, DeviceAssignRequest, FlowRequest, KeyReleaseRequest,
    PolicyDecision, PolicyEngine, PolicyReceipt, VmLaunchRequest,
};
pub use hash::sha384_hex;

// Re-exported for convenience: the core unlock mode used by key-release policy.
pub use hyper_slate_core::policy::UnlockMode;
