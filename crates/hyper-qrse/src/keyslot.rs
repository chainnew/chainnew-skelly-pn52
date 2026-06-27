//! Algorithm-agile keyslots (PAD-QRSE-001 §9.5).
//!
//! A volume can be unlocked through several *independent* keyslots, each backed
//! by a different mechanism (a passphrase-derived key, a TPM-sealed key, a
//! hybrid remote-KMS key, or a threshold recovery scheme). Each keyslot is a
//! self-describing, serde-round-trippable record so the on-disk `qrsd-v1`
//! manifest stays algorithm-agile: a new mechanism is a new variant, never a
//! breaking change to existing slots.
//!
//! The kind-specific data is modelled as an internally-tagged enum
//! ([`KeyslotKind`], tagged on `"kind"`) flattened into [`Keyslot`] so the wire
//! shape is the flat object the PAD §9.5 schema shows:
//!
//! ```json
//! { "slot": 2, "status": "active", "kind": "hybrid_remote_kms",
//!   "kem": { "classical": "x25519", "pqc": "ml-kem-768", "combiner": "hkdf-sha384" },
//!   "attestation": { "required": true, "accepted_tee": ["amd-sev-snp"],
//!                    "measurement_policy_ref": "pol-meas-v3" } }
//! ```

use serde::{Deserialize, Serialize};

use crate::combiner::KemSuite;

/// Lifecycle state of a keyslot (PAD §9.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyslotStatus {
    /// Usable for unlock.
    Active,
    /// Administratively held until a break-glass procedure re-enables it.
    DisabledUntilBreakGlass,
    /// Permanently retired; kept only for audit / historical reference.
    Retired,
}

/// Argon2id passphrase KDF parameters (PAD §9.5 `kdf` object).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Argon2idKdf {
    pub algorithm: String,
    pub memory_kib: u32,
    pub time_cost: u32,
    pub parallelism: u32,
}

/// Key-wrapping descriptor for a passphrase keyslot (PAD §9.5 `wrap` object).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct WrapSpec {
    pub algorithm: String,
    pub wrapped_key_ref: String,
}

/// Attestation requirements for a hybrid remote-KMS keyslot (PAD §9.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct KmsAttestation {
    pub required: bool,
    pub accepted_tee: Vec<String>,
    pub measurement_policy_ref: String,
}

/// The mechanism backing a keyslot, plus its mechanism-specific fields.
///
/// Internally tagged on `"kind"` so it flattens into [`Keyslot`] as a flat
/// object matching the PAD §9.5 wire shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KeyslotKind {
    /// Passphrase-derived key (Argon2id) wrapping the next key in the chain.
    Argon2idPassphrase { kdf: Argon2idKdf, wrap: WrapSpec },
    /// TPM2-sealed key bound to a PCR policy.
    Tpm2Sealed {
        pcrs: Vec<String>,
        requires_pin: bool,
        signed_pcr_policy: bool,
    },
    /// Hybrid classical+PQC key released by a remote KMS after attestation.
    HybridRemoteKms {
        kem: KemSuite,
        attestation: KmsAttestation,
    },
    /// Threshold (m-of-n) recovery scheme.
    ThresholdRecovery { scheme: String, m: u32, n: u32 },
}

/// A single algorithm-agile keyslot (PAD §9.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Keyslot {
    pub slot: u32,
    pub status: KeyslotStatus,
    /// Mechanism + mechanism-specific fields, flattened into this object.
    #[serde(flatten)]
    pub kind: KeyslotKind,
}

impl Keyslot {
    /// Construct a keyslot from its parts.
    pub fn new(slot: u32, status: KeyslotStatus, kind: KeyslotKind) -> Self {
        Keyslot { slot, status, kind }
    }

    /// Whether this slot may currently be used for unlock.
    pub fn is_active(&self) -> bool {
        self.status == KeyslotStatus::Active
    }

    /// Whether this slot is a hybrid remote-KMS slot (carries a KEM suite).
    pub fn is_hybrid(&self) -> bool {
        matches!(self.kind, KeyslotKind::HybridRemoteKms { .. })
    }

    /// Whether this slot provides **no** post-quantum (PQC) leg.
    ///
    /// Argon2id / TPM2 / threshold slots are classical-only by construction. A
    /// hybrid slot is classical-only **only if** its PQC leg has been stripped
    /// (empty `pqc`), which is exactly the suite-downgrade case `downgrade.rs`
    /// must reject.
    pub fn classical_only(&self) -> bool {
        match &self.kind {
            KeyslotKind::HybridRemoteKms { kem, .. } => kem.pqc.trim().is_empty(),
            _ => true,
        }
    }

    /// The hybrid KEM suite, if this is a hybrid remote-KMS slot.
    pub fn kem_suite(&self) -> Option<&KemSuite> {
        match &self.kind {
            KeyslotKind::HybridRemoteKms { kem, .. } => Some(kem),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argon2_slot() -> Keyslot {
        Keyslot::new(
            0,
            KeyslotStatus::Active,
            KeyslotKind::Argon2idPassphrase {
                kdf: Argon2idKdf {
                    algorithm: "argon2id".into(),
                    memory_kib: 1_048_576,
                    time_cost: 3,
                    parallelism: 4,
                },
                wrap: WrapSpec {
                    algorithm: "aes-256-gcm".into(),
                    wrapped_key_ref: "blob:slot0".into(),
                },
            },
        )
    }

    fn hybrid_slot() -> Keyslot {
        Keyslot::new(
            2,
            KeyslotStatus::Active,
            KeyslotKind::HybridRemoteKms {
                kem: KemSuite::transition_768(),
                attestation: KmsAttestation {
                    required: true,
                    accepted_tee: vec!["amd-sev-snp".into(), "intel-tdx".into()],
                    measurement_policy_ref: "pol-meas-v3".into(),
                },
            },
        )
    }

    #[test]
    fn argon2_slot_round_trips_flat_shape() {
        let slot = argon2_slot();
        let json = serde_json::to_string(&slot).unwrap();
        // The kind tag is flattened in as a sibling field.
        assert!(json.contains(r#""kind":"argon2id_passphrase""#));
        assert!(json.contains(r#""memory_kib":1048576"#));
        let back: Keyslot = serde_json::from_str(&json).unwrap();
        assert_eq!(back, slot);
    }

    #[test]
    fn hybrid_slot_round_trips_and_exposes_suite() {
        let slot = hybrid_slot();
        let json = serde_json::to_string(&slot).unwrap();
        assert!(json.contains(r#""kind":"hybrid_remote_kms""#));
        assert!(json.contains(r#""pqc":"ml-kem-768""#));
        let back: Keyslot = serde_json::from_str(&json).unwrap();
        assert_eq!(back, slot);
        assert_eq!(back.kem_suite().unwrap().pqc, "ml-kem-768");
    }

    #[test]
    fn deserializes_pad_shape() {
        let src = r#"{
            "slot": 5,
            "status": "disabled_until_break_glass",
            "kind": "tpm2_sealed",
            "pcrs": ["sha384:pcr7", "sha384:pcr11"],
            "requires_pin": true,
            "signed_pcr_policy": true
        }"#;
        let slot: Keyslot = serde_json::from_str(src).unwrap();
        assert_eq!(slot.slot, 5);
        assert_eq!(slot.status, KeyslotStatus::DisabledUntilBreakGlass);
        assert!(!slot.is_active());
        match slot.kind {
            KeyslotKind::Tpm2Sealed {
                ref pcrs,
                requires_pin,
                signed_pcr_policy,
            } => {
                assert_eq!(pcrs.len(), 2);
                assert!(requires_pin);
                assert!(signed_pcr_policy);
            }
            _ => panic!("wrong kind"),
        }
    }

    #[test]
    fn threshold_round_trips() {
        let slot = Keyslot::new(
            3,
            KeyslotStatus::Retired,
            KeyslotKind::ThresholdRecovery {
                scheme: "shamir-gf256".into(),
                m: 3,
                n: 5,
            },
        );
        let json = serde_json::to_string(&slot).unwrap();
        let back: Keyslot = serde_json::from_str(&json).unwrap();
        assert_eq!(back, slot);
    }

    #[test]
    fn classical_only_and_hybrid_helpers() {
        assert!(argon2_slot().classical_only());
        assert!(!argon2_slot().is_hybrid());

        let h = hybrid_slot();
        assert!(h.is_hybrid());
        assert!(!h.classical_only());

        // A hybrid slot with the PQC leg stripped is classical-only (downgrade).
        let stripped = Keyslot::new(
            2,
            KeyslotStatus::Active,
            KeyslotKind::HybridRemoteKms {
                kem: KemSuite {
                    classical: "x25519".into(),
                    pqc: "".into(),
                    combiner: "hkdf-sha384".into(),
                },
                attestation: KmsAttestation {
                    required: true,
                    accepted_tee: vec!["amd-sev-snp".into()],
                    measurement_policy_ref: "pol".into(),
                },
            },
        );
        assert!(stripped.is_hybrid());
        assert!(stripped.classical_only());
    }
}
