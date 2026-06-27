//! Zeroizing secret handle for released key material (S10).
//!
//! [`SecretHandle`] wraps raw bytes (e.g. a wrapped volume master key) and
//! guarantees the buffer is overwritten with zeros when the handle is dropped.
//! Its [`Debug`] impl never reveals the contents — only the length — so secrets
//! cannot leak into logs or panic messages.

/// A length-revealing, content-hiding owner of secret bytes.
///
/// The wrapped buffer is zeroized both on an explicit [`SecretHandle::zeroize`]
/// and automatically on [`Drop`]. The bytes are never printed.
pub struct SecretHandle {
    bytes: Vec<u8>,
}

impl SecretHandle {
    /// Take ownership of `bytes` as a secret.
    pub fn new(bytes: Vec<u8>) -> Self {
        SecretHandle { bytes }
    }

    /// Number of secret bytes held.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the handle holds no bytes.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Guarded read access to the secret: the bytes are only visible inside the
    /// provided closure, never returned or copied out by the accessor itself.
    pub fn expose<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        f(&self.bytes)
    }

    /// Overwrite the secret buffer with zeros in place. Idempotent.
    pub fn zeroize(&mut self) {
        for b in self.bytes.iter_mut() {
            *b = 0;
        }
    }
}

impl Drop for SecretHandle {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl std::fmt::Debug for SecretHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretHandle")
            .field("len", &self.bytes.len())
            .field("bytes", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn len_and_expose_work() {
        let h = SecretHandle::new(vec![1, 2, 3, 4]);
        assert_eq!(h.len(), 4);
        assert!(!h.is_empty());
        let sum: u32 = h.expose(|b| b.iter().map(|&x| x as u32).sum());
        assert_eq!(sum, 10);
    }

    #[test]
    fn zeroize_overwrites_but_keeps_length() {
        let mut h = SecretHandle::new(vec![9, 9, 9, 9, 9]);
        h.zeroize();
        assert_eq!(h.len(), 5);
        h.expose(|b| assert!(b.iter().all(|&x| x == 0)));
    }

    #[test]
    fn debug_never_prints_contents() {
        let h = SecretHandle::new(vec![0xde, 0xad, 0xbe, 0xef]);
        let rendered = format!("{h:?}");
        assert!(rendered.contains("len"));
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("222")); // 0xde == 222 decimal
        assert!(!rendered.contains("de")); // hex form
    }

    #[test]
    fn drop_zeroizes_via_zeroize_path() {
        // Drop delegates to zeroize(); exercise the same code path explicitly
        // (reading freed memory would require unsafe, which is forbidden).
        let mut h = SecretHandle::new(vec![7; 32]);
        h.zeroize();
        h.expose(|b| assert!(b.iter().all(|&x| x == 0)));
        drop(h); // must not panic
    }
}
