//! The hybrid classical+PQC key combiner (PAD-QRSE-001 §9.4).
//!
//! ```text
//! KEK = HKDF-SHA384(
//!         salt = H(transcript),
//!         IKM  = ss_classical || ss_pqc,
//!         info = "storage-unlock-v1" || context
//!       )
//! ```
//!
//! Rules enforced here (PAD §9.4 / §16.2):
//! - Fail closed if *either* required shared secret is missing / all-zero.
//! - Bind the algorithm suite into the HKDF `info`.
//! - Bind boot measurements and policy version into the transcript/context.
//! - The output KEK is zeroized on drop.

use hkdf::Hkdf;
use sha2::{Digest, Sha384};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::{CryptoError, SharedSecret};

/// Domain-separation label for the storage-unlock combiner. Versioned so a
/// future combiner change is a *different* KEK, never a silent collision.
pub const COMBINER_LABEL: &[u8] = b"storage-unlock-v1";

/// The algorithm-agile suite identifiers bound into every derivation.
/// Mirrors `hyper_storage::pqc::HybridKemSuite` but owned + serde-friendly.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct KemSuite {
    pub classical: String,
    pub pqc: String,
    pub combiner: String,
}

impl KemSuite {
    /// The default commercial transition profile (PAD §3.2): X25519 + ML-KEM-768.
    pub fn transition_768() -> Self {
        KemSuite {
            classical: "x25519".into(),
            pqc: "ml-kem-768".into(),
            combiner: "hkdf-sha384".into(),
        }
    }
    /// CNSA-leaning high-assurance profile: X25519 + ML-KEM-1024.
    pub fn high_assurance_1024() -> Self {
        KemSuite {
            classical: "x25519".into(),
            pqc: "ml-kem-1024".into(),
            combiner: "hkdf-sha384".into(),
        }
    }
    /// Canonical, unambiguous wire form for binding into `info`.
    pub fn canonical(&self) -> String {
        format!("{}+{}+{}", self.classical, self.pqc, self.combiner)
    }
}

/// Everything bound into the combiner `info` field (PAD §9.4 `context`).
/// Every field here is authenticated: change any of it and the KEK changes,
/// which is exactly how downgrade/rebinding attacks are defeated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CombinerContext {
    pub volume_id: String,
    pub device_id: String,
    pub policy_id: String,
    pub policy_version: u64,
    pub algorithm_suite: KemSuite,
    /// Boot measurement digest the KEK is bound to (e.g. a PCR/manifest hash).
    pub boot_measurement: String,
}

impl CombinerContext {
    /// Length-prefixed canonical encoding (no field-boundary ambiguity).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut put = |s: &[u8]| {
            out.extend_from_slice(&(s.len() as u64).to_be_bytes());
            out.extend_from_slice(s);
        };
        put(self.volume_id.as_bytes());
        put(self.device_id.as_bytes());
        put(self.policy_id.as_bytes());
        put(&self.policy_version.to_be_bytes());
        put(self.algorithm_suite.canonical().as_bytes());
        put(self.boot_measurement.as_bytes());
        out
    }
}

/// A derived key-encryption key. Zeroized on drop; never `Debug`-printed.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Kek(Vec<u8>);

impl Kek {
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    /// Controlled access to the key bytes (e.g. to unwrap a VMK).
    pub fn expose<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        f(&self.0)
    }
}

impl core::fmt::Debug for Kek {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Kek(**** {} bytes)", self.0.len())
    }
}

/// Derive a hybrid KEK from a classical and a post-quantum shared secret.
///
/// `output_len` is the KEK length in bytes (commonly 32 or 64). Fails closed if
/// either shared secret is all-zero (PAD §9.4: "Fail closed if either required
/// component fails").
pub fn hybrid_combine(
    ss_classical: &SharedSecret,
    ss_pqc: &SharedSecret,
    transcript: &[u8],
    context: &CombinerContext,
    output_len: usize,
) -> Result<Kek, CryptoError> {
    if !ss_classical.is_live() || !ss_pqc.is_live() {
        return Err(CryptoError::EmptySharedSecret);
    }

    // salt = H(transcript)
    let salt = Sha384::digest(transcript);

    // IKM = ss_classical || ss_pqc
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(ss_classical.as_bytes());
    ikm.extend_from_slice(ss_pqc.as_bytes());

    // info = LABEL || context
    let mut info = Vec::new();
    info.extend_from_slice(COMBINER_LABEL);
    info.extend_from_slice(&context.to_bytes());

    let hk = Hkdf::<Sha384>::new(Some(&salt), &ikm);
    let mut okm = vec![0u8; output_len];
    hk.expand(&info, &mut okm).map_err(|_| CryptoError::Hkdf)?;
    ikm.zeroize();

    Ok(Kek(okm))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SharedSecret;

    fn ctx() -> CombinerContext {
        CombinerContext {
            volume_id: "vol-1".into(),
            device_id: "pn52-lab-001".into(),
            policy_id: "policy-prod-v4".into(),
            policy_version: 42,
            algorithm_suite: KemSuite::transition_768(),
            boot_measurement: "sha384:bootmeas".into(),
        }
    }

    #[test]
    fn deterministic_for_same_inputs() {
        let c = SharedSecret::from_bytes([1u8; 32]);
        let p = SharedSecret::from_bytes([2u8; 32]);
        let k1 = hybrid_combine(&c, &p, b"transcript", &ctx(), 32).unwrap();
        let k2 = hybrid_combine(&c, &p, b"transcript", &ctx(), 32).unwrap();
        assert!(k1 == k2);
        assert_eq!(k1.len(), 32);
    }

    #[test]
    fn fails_closed_on_dead_secret() {
        let live = SharedSecret::from_bytes([1u8; 32]);
        let dead = SharedSecret::from_bytes([0u8; 32]);
        assert_eq!(
            hybrid_combine(&dead, &live, b"t", &ctx(), 32).unwrap_err(),
            CryptoError::EmptySharedSecret
        );
        assert_eq!(
            hybrid_combine(&live, &dead, b"t", &ctx(), 32).unwrap_err(),
            CryptoError::EmptySharedSecret
        );
    }

    #[test]
    fn context_is_bound_into_kek() {
        let c = SharedSecret::from_bytes([1u8; 32]);
        let p = SharedSecret::from_bytes([2u8; 32]);
        let base = hybrid_combine(&c, &p, b"t", &ctx(), 32).unwrap();

        // Changing the suite, policy version, or boot measurement => different KEK.
        let mut other = ctx();
        other.policy_version = 43;
        assert!(hybrid_combine(&c, &p, b"t", &other, 32).unwrap() != base);

        let mut other2 = ctx();
        other2.algorithm_suite = KemSuite::high_assurance_1024();
        assert!(hybrid_combine(&c, &p, b"t", &other2, 32).unwrap() != base);

        let mut other3 = ctx();
        other3.boot_measurement = "sha384:tampered".into();
        assert!(hybrid_combine(&c, &p, b"t", &other3, 32).unwrap() != base);
    }

    #[test]
    fn transcript_is_bound() {
        let c = SharedSecret::from_bytes([1u8; 32]);
        let p = SharedSecret::from_bytes([2u8; 32]);
        let a = hybrid_combine(&c, &p, b"transcript-A", &ctx(), 32).unwrap();
        let b = hybrid_combine(&c, &p, b"transcript-B", &ctx(), 32).unwrap();
        assert!(a != b);
    }

    #[test]
    fn order_of_legs_matters() {
        // ss_classical||ss_pqc must not equal ss_pqc||ss_classical.
        let a = SharedSecret::from_bytes([1u8; 32]);
        let b = SharedSecret::from_bytes([2u8; 32]);
        let k1 = hybrid_combine(&a, &b, b"t", &ctx(), 32).unwrap();
        let k2 = hybrid_combine(&b, &a, b"t", &ctx(), 32).unwrap();
        assert!(k1 != k2);
    }
}
