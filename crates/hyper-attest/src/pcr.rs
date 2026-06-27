//! PCR (Platform Configuration Register) banks and boot measurements.
//!
//! A [`PcrBank`] is the deterministic, ordered set of TPM/fTPM PCR digests
//! captured during measured boot. A [`BootMeasurement`] bundles the firmware /
//! kernel / boot-policy / capsule digests together with the PCR bank that a
//! KMS unlock policy is evaluated against (S6/S8, §10).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Firmware / platform code measurement register.
pub const PCR0: u8 = 0;
/// Secure Boot policy measurement register.
pub const PCR7: u8 = 7;
/// Unified-kernel / boot-aggregate measurement register.
pub const PCR11: u8 = 11;

/// An ordered map of PCR index -> `"sha384:<hex>"` digest string.
///
/// Backed by a [`BTreeMap`] so iteration order (and therefore any derived
/// hash / JSON encoding) is deterministic.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PcrBank(BTreeMap<u8, String>);

impl PcrBank {
    /// Create an empty bank.
    pub fn new() -> Self {
        PcrBank(BTreeMap::new())
    }

    /// Record (or overwrite) the digest for a PCR index.
    pub fn set(&mut self, pcr: u8, digest: impl Into<String>) -> &mut Self {
        self.0.insert(pcr, digest.into());
        self
    }

    /// Read the digest recorded for a PCR index, if any.
    pub fn get(&self, pcr: u8) -> Option<&str> {
        self.0.get(&pcr).map(String::as_str)
    }

    /// Number of populated PCRs.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether no PCRs are populated.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterate `(pcr, digest)` pairs in ascending PCR order.
    pub fn iter(&self) -> impl Iterator<Item = (u8, &str)> {
        self.0.iter().map(|(k, v)| (*k, v.as_str()))
    }

    /// The first PCR index in `expected` whose digest is missing or differs in
    /// `self`, or `None` if `self` satisfies every expected register.
    ///
    /// Fail-closed: a PCR expected but absent in `self` counts as a mismatch.
    pub fn first_mismatch(&self, expected: &PcrBank) -> Option<u8> {
        for (pcr, want) in expected.0.iter() {
            if self.0.get(pcr).map(String::as_str) != Some(want.as_str()) {
                return Some(*pcr);
            }
        }
        None
    }

    /// Whether `self` matches every register named in `expected`.
    pub fn satisfies(&self, expected: &PcrBank) -> bool {
        self.first_mismatch(expected).is_none()
    }
}

/// A captured measured-boot record. The four `*_hash` fields are the discrete
/// component digests; `pcrs` is the extended TPM/fTPM state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct BootMeasurement {
    pub uefi_app_hash: String,
    pub kernel_hash: String,
    pub boot_policy_hash: String,
    pub capsule_manifest_hash: String,
    pub pcrs: PcrBank,
}

impl BootMeasurement {
    /// Construct a boot measurement.
    pub fn new(
        uefi_app_hash: impl Into<String>,
        kernel_hash: impl Into<String>,
        boot_policy_hash: impl Into<String>,
        capsule_manifest_hash: impl Into<String>,
        pcrs: PcrBank,
    ) -> Self {
        BootMeasurement {
            uefi_app_hash: uefi_app_hash.into(),
            kernel_hash: kernel_hash.into(),
            boot_policy_hash: boot_policy_hash.into(),
            capsule_manifest_hash: capsule_manifest_hash.into(),
            pcrs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_get_round_trips() {
        let mut bank = PcrBank::new();
        bank.set(PCR0, "sha384:aa").set(PCR7, "sha384:bb");
        assert_eq!(bank.get(PCR0), Some("sha384:aa"));
        assert_eq!(bank.get(PCR7), Some("sha384:bb"));
        assert_eq!(bank.get(PCR11), None);
        assert_eq!(bank.len(), 2);
        assert!(!bank.is_empty());
    }

    #[test]
    fn iteration_is_ascending_and_deterministic() {
        let mut a = PcrBank::new();
        a.set(PCR11, "c").set(PCR0, "a").set(PCR7, "b");
        let order: Vec<u8> = a.iter().map(|(k, _)| k).collect();
        assert_eq!(order, vec![PCR0, PCR7, PCR11]);
    }

    #[test]
    fn satisfies_requires_every_expected_register() {
        let mut expected = PcrBank::new();
        expected.set(PCR0, "x").set(PCR7, "y");

        let mut actual = PcrBank::new();
        actual.set(PCR0, "x").set(PCR7, "y").set(PCR11, "extra");
        // Extra registers are allowed.
        assert!(actual.satisfies(&expected));
        assert_eq!(actual.first_mismatch(&expected), None);
    }

    #[test]
    fn missing_expected_register_is_a_mismatch() {
        let mut expected = PcrBank::new();
        expected.set(PCR0, "x").set(PCR7, "y");
        let mut actual = PcrBank::new();
        actual.set(PCR0, "x");
        assert!(!actual.satisfies(&expected));
        assert_eq!(actual.first_mismatch(&expected), Some(PCR7));
    }

    #[test]
    fn differing_digest_is_a_mismatch() {
        let mut expected = PcrBank::new();
        expected.set(PCR7, "good");
        let mut actual = PcrBank::new();
        actual.set(PCR7, "evil");
        assert_eq!(actual.first_mismatch(&expected), Some(PCR7));
    }

    #[test]
    fn pcr_bank_json_is_a_map() {
        let mut bank = PcrBank::new();
        bank.set(PCR0, "sha384:aa");
        let json = serde_json::to_string(&bank).unwrap();
        assert_eq!(json, r#"{"0":"sha384:aa"}"#);
        let back: PcrBank = serde_json::from_str(&json).unwrap();
        assert_eq!(back, bank);
    }

    #[test]
    fn boot_measurement_round_trips() {
        let mut pcrs = PcrBank::new();
        pcrs.set(PCR0, "p0").set(PCR7, "p7").set(PCR11, "p11");
        let bm = BootMeasurement::new("uefi", "kern", "bootpol", "capman", pcrs);
        let json = serde_json::to_string(&bm).unwrap();
        let back: BootMeasurement = serde_json::from_str(&json).unwrap();
        assert_eq!(back, bm);
    }
}
