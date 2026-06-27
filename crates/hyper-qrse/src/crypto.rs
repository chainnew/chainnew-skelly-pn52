//! Algorithm-agile crypto primitives for the QRSE control plane.
//!
//! Doctrine (PAD-QRSE-001 §16): the data plane stays boring (AES-256-XTS,
//! elsewhere); the control plane becomes algorithm-agile. Everything here is
//! expressed behind [`Kem`] / [`Signer`] / [`Verifier`] traits so a real
//! RustCrypto ML-KEM / X25519 / ML-DSA implementation can be dropped in later
//! *without changing any caller*.
//!
//! The bundled implementations are **deterministic test vectors**, not real
//! cryptography: they are seed-driven SHA-384/HMAC expansions so unit tests are
//! reproducible and host-only. They are clearly named `Deterministic*` and must
//! never be used to protect real secrets.

use core::fmt;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha384};
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha384 = Hmac<Sha384>;

/// Errors from KEM / signature primitives. Fail-closed by construction.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    #[error("empty or zero shared secret")]
    EmptySharedSecret,
    #[error("decapsulation failed: malformed ciphertext")]
    Decapsulation,
    #[error("key material has wrong length: expected {expected}, got {got}")]
    BadKeyLength { expected: usize, got: usize },
    #[error("hkdf expand failed")]
    Hkdf,
    #[error("algorithm `{0}` is not supported")]
    UnsupportedAlgorithm(String),
}

/// A 32-byte symmetric shared secret. Zeroized on drop.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret(pub(crate) [u8; 32]);

impl SharedSecret {
    pub fn from_bytes(b: [u8; 32]) -> Self {
        SharedSecret(b)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    /// A shared secret is "live" only if it is not all-zero (fail-closed input
    /// to the combiner).
    pub fn is_live(&self) -> bool {
        self.0.iter().any(|&x| x != 0)
    }
}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print secret bytes.
        write!(f, "SharedSecret(****)")
    }
}

/// Opaque KEM key / ciphertext material (bytes carry no secrecy guarantees on
/// their own; decap keys are wrapped by the caller's key hierarchy).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncapKey(pub Vec<u8>);
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecapKey(pub Vec<u8>);
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KemCiphertext(pub Vec<u8>);

/// A key-encapsulation mechanism. Used for BOTH the classical leg (DH modelled
/// as a KEM) and the post-quantum leg of the hybrid combiner.
pub trait Kem {
    /// Stable algorithm identifier, e.g. `"x25519"` or `"ml-kem-768"`.
    fn algorithm(&self) -> &str;
    /// Deterministically derive a keypair from `seed`.
    fn generate_keypair(&self, seed: &[u8]) -> (EncapKey, DecapKey);
    /// Encapsulate to `ek`, deriving randomness from `seed`.
    fn encapsulate(&self, ek: &EncapKey, seed: &[u8]) -> (KemCiphertext, SharedSecret);
    /// Decapsulate `ct` with `dk`.
    fn decapsulate(&self, dk: &DecapKey, ct: &KemCiphertext) -> Result<SharedSecret, CryptoError>;
}

/// A detached-signature signer (boot/disk/manifest signing — PAD §16.3).
pub trait Signer {
    fn algorithm(&self) -> &str;
    fn key_id(&self) -> &str;
    /// Public key bytes, for embedding in a manifest / trust store.
    fn public_key(&self) -> Vec<u8>;
    fn sign(&self, message: &[u8]) -> Signature;
}

/// A signature verifier keyed by `key_id`.
pub trait Verifier {
    fn algorithm(&self) -> &str;
    fn key_id(&self) -> &str;
    fn verify(&self, message: &[u8], sig: &Signature) -> bool;
}

/// A detached signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub algorithm: String,
    pub key_id: String,
    pub bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Deterministic test implementations (NOT real crypto).
// ---------------------------------------------------------------------------

fn kdf(domain: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha384::new();
    h.update(domain.as_bytes());
    for p in parts {
        h.update((p.len() as u64).to_be_bytes());
        h.update(p);
    }
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d[..32]);
    out
}

/// A deterministic, seed-driven KEM standing in for a real one. The shared
/// secret is reproducible from (decap key seed, ciphertext) so encaps/decaps
/// round-trips in tests. **Not secure.**
#[derive(Debug, Clone)]
pub struct DeterministicKem {
    algorithm: String,
    /// Declared sizes (purely for realistic metadata; PAD §3.2 tables).
    pub declared_ek_bytes: usize,
    pub declared_ct_bytes: usize,
}

impl DeterministicKem {
    pub fn new(algorithm: impl Into<String>, declared_ek_bytes: usize, declared_ct_bytes: usize) -> Self {
        DeterministicKem {
            algorithm: algorithm.into(),
            declared_ek_bytes,
            declared_ct_bytes,
        }
    }
    /// X25519-shaped stand-in (classical leg).
    pub fn x25519() -> Self {
        Self::new("x25519", 32, 32)
    }
    /// ML-KEM-768 stand-in (PAD §3.2: ek 1184 B, ct 1088 B).
    pub fn ml_kem_768() -> Self {
        Self::new("ml-kem-768", 1184, 1088)
    }
    /// ML-KEM-1024 stand-in (PAD §3.2: ek 1568 B, ct 1568 B).
    pub fn ml_kem_1024() -> Self {
        Self::new("ml-kem-1024", 1568, 1568)
    }

    fn root(&self, seed: &[u8]) -> [u8; 32] {
        kdf("qrse:kem:root", &[self.algorithm.as_bytes(), seed])
    }
}

impl Kem for DeterministicKem {
    fn algorithm(&self) -> &str {
        &self.algorithm
    }

    fn generate_keypair(&self, seed: &[u8]) -> (EncapKey, DecapKey) {
        let root = self.root(seed);
        // Decap key carries the root so decapsulation reproduces `ek` exactly.
        let ek = kdf("qrse:kem:ek", &[&root]).to_vec();
        (EncapKey(ek), DecapKey(root.to_vec()))
    }

    fn encapsulate(&self, ek: &EncapKey, seed: &[u8]) -> (KemCiphertext, SharedSecret) {
        // ct = enc-randomness commitment bound to ek; ss derived from (ek, ct).
        let r = kdf("qrse:kem:r", &[&ek.0, seed]);
        let ct = kdf("qrse:kem:ct", &[&ek.0, &r]).to_vec();
        let ss = kdf("qrse:kem:ss", &[&ek.0, &ct]);
        (KemCiphertext(ct), SharedSecret(ss))
    }

    fn decapsulate(&self, dk: &DecapKey, ct: &KemCiphertext) -> Result<SharedSecret, CryptoError> {
        if dk.0.is_empty() {
            return Err(CryptoError::BadKeyLength { expected: 32, got: 0 });
        }
        if ct.0.is_empty() {
            return Err(CryptoError::Decapsulation);
        }
        // dk carries the root; reproduce the exact `ek` from generate_keypair,
        // then ss from (ek, ct) — matching encapsulate().
        let ek = kdf("qrse:kem:ek", &[&dk.0]);
        let ss = kdf("qrse:kem:ss", &[&ek, &ct.0]);
        Ok(SharedSecret(ss))
    }
}

/// Deterministic HMAC-based signer standing in for ML-DSA / SLH-DSA / ECDSA.
/// **Not secure** — for reproducible host tests only.
#[derive(Debug, Clone)]
pub struct DeterministicSigner {
    algorithm: String,
    key_id: String,
    secret: [u8; 32],
    declared_sig_bytes: usize,
}

impl DeterministicSigner {
    pub fn new(
        algorithm: impl Into<String>,
        key_id: impl Into<String>,
        seed: &[u8],
        declared_sig_bytes: usize,
    ) -> Self {
        let algorithm = algorithm.into();
        let key_id = key_id.into();
        let secret = kdf("qrse:sig:sk", &[algorithm.as_bytes(), key_id.as_bytes(), seed]);
        DeterministicSigner {
            algorithm,
            key_id,
            secret,
            declared_sig_bytes,
        }
    }
    /// ML-DSA-65 stand-in (PAD §3.2: sig ~3309 B).
    pub fn ml_dsa_65(key_id: impl Into<String>, seed: &[u8]) -> Self {
        Self::new("ml-dsa-65", key_id, seed, 3309)
    }
    /// SLH-DSA-128s stand-in (PAD §3.2: sig ~7856 B).
    pub fn slh_dsa_128s(key_id: impl Into<String>, seed: &[u8]) -> Self {
        Self::new("slh-dsa-128s", key_id, seed, 7856)
    }
    /// ECDSA-P384 stand-in (transition-only classical signer).
    pub fn ecdsa_p384(key_id: impl Into<String>, seed: &[u8]) -> Self {
        Self::new("ecdsa-p384", key_id, seed, 104)
    }

    fn mac(&self, message: &[u8]) -> Vec<u8> {
        let mut m = HmacSha384::new_from_slice(&self.secret).expect("hmac key");
        m.update(self.algorithm.as_bytes());
        m.update(b"|");
        m.update(message);
        m.finalize().into_bytes().to_vec()
    }

    /// A `Verifier` for the public side of this key.
    pub fn verifier(&self) -> DeterministicVerifier {
        DeterministicVerifier {
            algorithm: self.algorithm.clone(),
            key_id: self.key_id.clone(),
            secret: self.secret,
        }
    }
}

impl Signer for DeterministicSigner {
    fn algorithm(&self) -> &str {
        &self.algorithm
    }
    fn key_id(&self) -> &str {
        &self.key_id
    }
    fn public_key(&self) -> Vec<u8> {
        // Deterministic "public key" = hash of the secret (test stand-in).
        kdf("qrse:sig:pk", &[&self.secret]).to_vec()
    }
    fn sign(&self, message: &[u8]) -> Signature {
        let mut bytes = self.mac(message);
        // Pad to the declared (realistic) signature size so manifest size
        // budgeting in tests is meaningful.
        if bytes.len() < self.declared_sig_bytes {
            let pad = kdf("qrse:sig:pad", &[&bytes]);
            while bytes.len() < self.declared_sig_bytes {
                let take = (self.declared_sig_bytes - bytes.len()).min(pad.len());
                bytes.extend_from_slice(&pad[..take]);
            }
        }
        Signature {
            algorithm: self.algorithm.clone(),
            key_id: self.key_id.clone(),
            bytes,
        }
    }
}

/// Verifier counterpart to [`DeterministicSigner`]. In a real deployment this
/// would hold only a *public* key; the test stand-in recomputes the MAC.
#[derive(Debug, Clone)]
pub struct DeterministicVerifier {
    algorithm: String,
    key_id: String,
    secret: [u8; 32],
}

impl DeterministicVerifier {
    fn mac(&self, message: &[u8]) -> Vec<u8> {
        let mut m = HmacSha384::new_from_slice(&self.secret).expect("hmac key");
        m.update(self.algorithm.as_bytes());
        m.update(b"|");
        m.update(message);
        m.finalize().into_bytes().to_vec()
    }
}

impl Verifier for DeterministicVerifier {
    fn algorithm(&self) -> &str {
        &self.algorithm
    }
    fn key_id(&self) -> &str {
        &self.key_id
    }
    fn verify(&self, message: &[u8], sig: &Signature) -> bool {
        if sig.algorithm != self.algorithm || sig.key_id != self.key_id {
            return false;
        }
        let expect = self.mac(message);
        // Compare the MAC prefix (signatures are padded to declared size).
        if sig.bytes.len() < expect.len() {
            return false;
        }
        // Constant-time-ish prefix compare via HMAC verify semantics.
        let mut m = HmacSha384::new_from_slice(&self.secret).expect("hmac key");
        m.update(self.algorithm.as_bytes());
        m.update(b"|");
        m.update(message);
        m.verify_truncated_left(&sig.bytes[..expect.len()]).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kem_roundtrip_classical_and_pqc() {
        for kem in [DeterministicKem::x25519(), DeterministicKem::ml_kem_768()] {
            let (ek, dk) = kem.generate_keypair(b"seed-A");
            let (ct, ss_enc) = kem.encapsulate(&ek, b"enc-rand");
            let ss_dec = kem.decapsulate(&dk, &ct).expect("decap");
            assert_eq!(ss_enc, ss_dec, "{} roundtrip", kem.algorithm());
            assert!(ss_enc.is_live());
        }
    }

    #[test]
    fn kem_decap_rejects_empty_ciphertext() {
        let kem = DeterministicKem::ml_kem_768();
        let (_ek, dk) = kem.generate_keypair(b"s");
        assert_eq!(
            kem.decapsulate(&dk, &KemCiphertext(vec![])),
            Err(CryptoError::Decapsulation)
        );
    }

    #[test]
    fn signer_sign_verify_and_tamper() {
        let signer = DeterministicSigner::ml_dsa_65("lab-pq-2026", b"sk-seed");
        let v = signer.verifier();
        let sig = signer.sign(b"disk-manifest-bytes");
        assert!(v.verify(b"disk-manifest-bytes", &sig));
        // Tampered message.
        assert!(!v.verify(b"disk-manifest-bytez", &sig));
        // Declared size honored (realistic budgeting).
        assert_eq!(sig.bytes.len(), 3309);
    }

    #[test]
    fn verifier_rejects_wrong_key_or_alg() {
        let a = DeterministicSigner::ml_dsa_65("key-a", b"seed-a");
        let b = DeterministicSigner::ml_dsa_65("key-b", b"seed-b");
        let sig = a.sign(b"m");
        assert!(!b.verifier().verify(b"m", &sig)); // wrong key
        let slh = DeterministicSigner::slh_dsa_128s("key-a", b"seed-a");
        assert!(!slh.verifier().verify(b"m", &sig)); // wrong alg
    }

    #[test]
    fn shared_secret_never_leaks_in_debug() {
        let ss = SharedSecret::from_bytes([7u8; 32]);
        assert_eq!(format!("{ss:?}"), "SharedSecret(****)");
    }
}
