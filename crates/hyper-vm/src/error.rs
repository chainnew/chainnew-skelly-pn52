//! Fail-closed error type for the VM lifecycle.

use thiserror::Error;

use hyper_capsule::GateError;
use hyper_devices::DevError;
use hyper_mm::MmError;
use hyper_receipts::ChainError;

/// Errors produced by [`crate::VmLifecycle`] transitions. Every variant is a
/// fail-closed denial: no guest state advances past a failed gate.
#[derive(Debug, Error)]
pub enum VmError {
    /// The policy engine denied (or escalated) a transition.
    #[error("policy denied: {0}")]
    PolicyDenied(String),

    /// The capsule launch gate rejected the launch.
    #[error("launch gate denied: {0}")]
    LaunchGate(#[from] GateError),

    /// A manifest/capsule verification step failed.
    #[error("capsule verification failed: {0}")]
    Capsule(String),

    /// Guest memory allocation or an S2 invariant check failed.
    #[error("memory error: {0}")]
    Memory(#[from] MmError),

    /// Device assignment failed.
    #[error("device error: {0}")]
    Device(#[from] DevError),

    /// The attested KMS refused to release the volume key (fail-closed).
    #[error("key release denied: {0}")]
    KeyReleaseDenied(String),

    /// The audit receipt chain failed verification.
    #[error("receipt chain error: {0}")]
    Receipt(#[from] ChainError),

    /// A lifecycle precondition was not met.
    #[error("invalid transition: {0}")]
    InvalidTransition(String),
}
