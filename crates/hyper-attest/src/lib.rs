//! hyper-attest — TPM/fTPM PCR capture, a KMS unlock *simulator*, attested
//! key release and tamper-evident key-release receipts for the chain.new
//! hyper-slate runtime (S6/S8, §10).
//!
//! This is the host-testable V0 layer: there is no real TPM or KMS, only a
//! deterministic simulator that exercises the attested-unlock decision logic
//! and writes `key_release` receipts onto the shared [`hyper_receipts`] audit
//! spine. Acceptance **V9** is enforced: a modified boot policy blocks release.
//!
//! All hashes are SHA-384, formatted `"sha384:<hex>"` (see [`sha384_hex`]),
//! matching the receipt spine. Nothing here uses randomness or a clock.
#![forbid(unsafe_code)]

mod kms;
mod pcr;
mod secret;

pub use kms::{
    AttestError, AttestedUnlockEvidence, KeyReleaseDecision, KeyReleaseRequest, KmsPolicy,
    KmsSimulator, SuiteBinding, SuitedKeyReleaseRequest, ATTESTED_UNLOCK_FORMAT, KMS_POLICY_ID,
};
pub use pcr::{BootMeasurement, PcrBank, PCR0, PCR11, PCR7};
pub use secret::SecretHandle;

/// SHA-384 digest of `bytes`, formatted as `"sha384:<lowercase-hex>"`.
///
/// Thin wrapper over [`hyper_receipts::sha384_hex`] so attest-layer callers
/// share one canonical hash formatting with the receipt spine.
pub fn sha384_hex(bytes: &[u8]) -> String {
    hyper_receipts::sha384_hex(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper_receipts::ReceiptChain;

    #[test]
    fn sha384_hex_matches_receipts_format() {
        let h = sha384_hex(b"");
        assert!(h.starts_with("sha384:"));
        assert_eq!(h, hyper_receipts::sha384_hex(b""));
    }

    #[test]
    fn end_to_end_attested_unlock() {
        // Capture a boot measurement, derive a request, evaluate it.
        let mut pcrs = PcrBank::new();
        pcrs.set(PCR0, "sha384:fw")
            .set(PCR7, "sha384:sb")
            .set(PCR11, "sha384:kern");
        let measurement =
            BootMeasurement::new("uefi", "kernel", "sha384:bp", "sha384:cap", pcrs.clone());

        let policy = KmsPolicy {
            expected_pcrs: pcrs.clone(),
            min_hypervisor_version: 1,
            allowed_capsule_hashes: vec![measurement.capsule_manifest_hash.clone()],
            expected_boot_policy_hash: measurement.boot_policy_hash.clone(),
        };

        let req = KeyReleaseRequest {
            request_type: "key_release".to_string(),
            device_id: "dev".to_string(),
            vm_id: "vm-x".to_string(),
            capsule_hash: measurement.capsule_manifest_hash.clone(),
            boot_policy_hash: measurement.boot_policy_hash.clone(),
            pcrs,
            hypervisor_version: 9,
            nonce: "n-1".to_string(),
        };

        let sim = KmsSimulator::new(policy);
        let mut chain = ReceiptChain::new();
        let decision = sim.evaluate(&req, &mut chain);
        assert!(decision.is_allow());
        assert_eq!(chain.verify(), Ok(()));
    }
}
