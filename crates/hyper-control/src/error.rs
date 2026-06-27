//! Fail-closed error type for the local control plane (§11).

use thiserror::Error;

use hyper_capsule::CapsuleError;
use hyper_vm::VmError;

/// Errors produced by [`crate::Control`]. Every variant is a fail-closed
/// denial: no VM advances past a failed gate and nothing is left half-mutated
/// in a usable state.
#[derive(Debug, Error)]
pub enum ControlError {
    /// The control-plane capsule descriptor JSON could not be deserialized.
    #[error("malformed control capsule json: {0}")]
    Json(String),

    /// The descriptor carried an unexpected `schema` discriminator.
    #[error("unexpected schema: expected `{expected}`, got `{got}`")]
    Schema {
        /// Expected schema string.
        expected: String,
        /// Schema string found in the descriptor.
        got: String,
    },

    /// Manifest parsing/verification failed (e.g. unsigned or untrusted key).
    /// This is where an unsigned/invalid capsule is denied at `vm_define`.
    #[error("capsule verification failed: {0}")]
    Capsule(#[from] CapsuleError),

    /// A VM lifecycle transition was denied by the runtime.
    #[error("lifecycle denied: {0}")]
    Vm(#[from] VmError),

    /// No VM with the given id is registered.
    #[error("unknown vm id: {0}")]
    NotFound(String),

    /// The VM exists but is not in a state from which this command is valid.
    #[error("invalid state for `{action}` on `{id}`: vm is `{found}`, need `{needed}`")]
    InvalidState {
        /// The command that was attempted.
        action: String,
        /// The VM id.
        id: String,
        /// The VM's current lifecycle state.
        found: String,
        /// The state(s) the command requires.
        needed: String,
    },

    /// `vm_destroy` was called without the explicit `wipe` confirmation.
    /// Destruction zeroizes guest memory + key material and is deny-by-default.
    #[error("destroy refused for `{0}`: pass --wipe to confirm zeroization")]
    WipeRequired(String),

    /// The audit receipt chain failed integrity verification.
    #[error("receipt chain verification failed: {0}")]
    Receipt(String),
}

impl From<serde_json::Error> for ControlError {
    fn from(e: serde_json::Error) -> Self {
        ControlError::Json(e.to_string())
    }
}
