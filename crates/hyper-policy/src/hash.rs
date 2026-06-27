//! Hashing helpers for the policy engine.
//!
//! All hashes are SHA-384 and formatted as the string `"sha384:<hex>"`,
//! matching the receipt / security-event spine convention.

use sha2::{Digest, Sha384};

/// SHA-384 digest of `bytes`, formatted as `"sha384:<lowercase-hex>"`.
pub fn sha384_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha384::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    format!("sha384:{}", hex::encode(digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_prefixed() {
        let a = sha384_hex(b"hello");
        let b = sha384_hex(b"hello");
        assert_eq!(a, b);
        assert!(a.starts_with("sha384:"));
        // 7 chars prefix + 96 hex chars.
        assert_eq!(a.len(), "sha384:".len() + 96);
    }

    #[test]
    fn distinct_inputs_distinct_hashes() {
        assert_ne!(sha384_hex(b"a"), sha384_hex(b"b"));
    }
}
