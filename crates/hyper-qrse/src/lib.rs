//! hyper-qrse — the QRSE (quantum-resistant storage encryption) control plane.
//!
//! Doctrine (PAD-QRSE-001): the disk cipher stays boring (AES-256-XTS lives in
//! the data plane, outside this crate). What becomes quantum-ready is the
//! *control plane*: algorithm-agile keyslots, a hybrid classical+PQC key
//! combiner, downgrade-resistant signed manifests, a layered key hierarchy, and
//! attested key release.
//!
//! Level 1 (deployable today) + Level 2 (hybrid transitional) of the PAD land
//! here as host-testable Rust. All post-quantum primitives sit behind the
//! [`crypto::Kem`] / [`crypto::Signer`] traits so a real RustCrypto ML-KEM /
//! ML-DSA implementation drops in later without API churn.
#![forbid(unsafe_code)]

pub mod combiner;
pub mod crypto;

// Structure layer on top of the crypto core:
pub mod downgrade;
pub mod hierarchy;
pub mod keyslot;
pub mod manifest;
pub mod unlock;
