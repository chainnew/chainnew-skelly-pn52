//! Crate error type for the higher-level (non-trait) virtio device API.
//!
//! The [`hyper_devices::VirtualDevice`] trait methods return [`DevError`]; the
//! richer device-level operations (e.g. integrity-checked block reads) return
//! [`VirtioError`], which wraps `DevError` and adds virtio-specific failures.

use hyper_devices::DevError;
use thiserror::Error;

/// Errors produced by `hyper-virtio` device-level operations. All variants fail
/// closed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum VirtioError {
    /// A bus/device-level error propagated from the backend.
    #[error("device error: {0}")]
    Dev(#[from] DevError),

    /// A sector index was outside the backing store.
    #[error("sector {index} out of range (capacity {capacity})")]
    SectorOutOfRange { index: u64, capacity: u64 },

    /// Backend bytes did not match the expected digest (tamper-evident read).
    #[error("integrity check failed for {what}: expected {expected}, got {actual}")]
    IntegrityFailure {
        what: String,
        expected: String,
        actual: String,
    },

    /// The integrity configuration was inconsistent with the backing store
    /// (e.g. a per-sector hash list whose length differs from the sector count).
    #[error("integrity config invalid: backend has {expected_sectors} sectors but {provided} hashes provided")]
    IntegrityConfig {
        expected_sectors: u64,
        provided: usize,
    },
}
