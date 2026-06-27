//! Hashing helpers for the receipt / security-event spine.
//!
//! All hashes are SHA-384 and formatted as the string `"sha384:<hex>"`.

use sha2::{Digest, Sha384};

/// SHA-384 digest of `bytes`, formatted as `"sha384:<lowercase-hex>"`.
pub fn sha384_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha384::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    format!("sha384:{}", hex::encode(digest))
}

/// The fixed genesis hash used as the predecessor of the first link in a
/// chain: `"sha384:"` followed by 48 zero bytes (96 hex chars).
pub fn genesis_hash() -> String {
    format!("sha384:{}", "0".repeat(96))
}
