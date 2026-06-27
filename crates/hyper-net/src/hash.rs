//! Hashing helper for deterministic network identity/IDs.
//!
//! Reuses the canonical `"sha384:<hex>"` formatter from `hyper-policy` so the
//! whole runtime shares one hash convention (and `hyper-net` need not pull in
//! `sha2`/`hex` directly).

/// SHA-384 digest of `bytes`, formatted as `"sha384:<lowercase-hex>"`.
pub fn net_hash(bytes: &[u8]) -> String {
    hyper_policy::sha384_hex(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_prefixed() {
        let a = net_hash(b"flow");
        assert_eq!(a, net_hash(b"flow"));
        assert!(a.starts_with("sha384:"));
        assert_eq!(a.len(), "sha384:".len() + 96);
    }

    #[test]
    fn distinct_inputs_distinct_hashes() {
        assert_ne!(net_hash(b"a"), net_hash(b"b"));
    }
}
