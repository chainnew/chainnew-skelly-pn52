//! hyper-control — the local control plane (§11) behind `hyperctl` for the
//! chain.new hyper-slate PN52 "slate-runtime" virtual framework (V0,
//! host-testable layer).
//!
//! This crate wires the typed [`hyper_vm`] lifecycle, the deny-by-default
//! [`hyper_policy`] document, the attested [`hyper_attest`] KMS simulator and
//! the tamper-evident [`hyper_receipts`] audit spine into a single, local-only
//! [`Control`] surface. There is NO network server: every method maps to a
//! `hyperctl` subcommand and is fail-closed.
//!
//! Doctrine carried over from the rest of the framework:
//!
//! * An unsigned/untrusted capsule can never run — its manifest fails
//!   [`hyper_capsule::verify`] at [`Control::vm_define`], so no VM is ever
//!   registered around it.
//! * Every lifecycle transition appends an audit receipt; the chain is
//!   verifiable via [`Control::receipts_verify`].
//! * Ids and hashes are deterministic (counter / content-hash derived); no
//!   randomness, no clock.
#![forbid(unsafe_code)]

mod control;
mod error;

pub use control::{
    sha384_hex, Control, ControlCapsuleSpec, CONTROL_CAPSULE_SCHEMA, CONTROL_DOCTOR_SCHEMA,
    CONTROL_POLICY_SCHEMA, CONTROL_RECEIPTS_SCHEMA, CONTROL_SCHEMA_VERSION,
    DEFAULT_BOOT_POLICY_HASH, DEFAULT_CAPSULE_HASH, DEFAULT_HYPERVISOR_VERSION,
};
pub use error::ControlError;
