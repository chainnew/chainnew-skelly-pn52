//! Policy-as-code document (framework §9).
//!
//! A [`PolicyDocument`] is the declarative, JSON-mapped source of truth that
//! the engine evaluates requests against. It is parsed from the SOW JSON and
//! is deny-by-default in spirit: every gate it exposes is a *restriction*.

use serde::{Deserialize, Serialize};

use hyper_slate_core::policy::UnlockMode;

/// Current schema version for the policy document.
pub const POLICY_SCHEMA_VERSION: u32 = 1;

/// Errors produced while parsing or validating a [`PolicyDocument`].
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// The input was not valid JSON or did not match the document shape.
    #[error("invalid policy document json: {0}")]
    Json(#[from] serde_json::Error),

    /// The document declared a schema version this build cannot interpret.
    #[error("unsupported policy schema_version {found} (expected {expected})")]
    UnsupportedSchema {
        /// Version found in the document.
        found: u32,
        /// Version this build supports.
        expected: u32,
    },

    /// A field held a value outside the accepted set.
    #[error("invalid policy field: {0}")]
    InvalidField(String),
}

/// Storage-related restrictions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct StoragePolicy {
    /// When true, volumes must be encrypted before keys/data are released.
    pub require_encryption: bool,
    /// When false, the base (golden) image must be opened read-only.
    pub allow_read_write_base_image: bool,
}

/// Key-release restrictions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct KeyReleasePolicy {
    /// Unlock mode this policy mandates, mapped to the core [`UnlockMode`].
    pub mode: String,
    /// When true, sensitive VMs must present a matching PCR quote.
    pub require_pcr_match_for_sensitive_vms: bool,
}

impl KeyReleasePolicy {
    /// Resolve the declared [`mode`](Self::mode) string to the core
    /// [`UnlockMode`] enum. Returns `None` for an unrecognized mode.
    pub fn unlock_mode(&self) -> Option<UnlockMode> {
        Some(match self.mode.as_str() {
            "passphrase_only" => UnlockMode::PassphraseOnly,
            "tpm2_pcr_policy" => UnlockMode::Tpm2PcrPolicy,
            "tpm2_pin" => UnlockMode::Tpm2Pin,
            "fido2_hmac_secret" => UnlockMode::Fido2HmacSecret,
            "smartcard_pkcs11" => UnlockMode::SmartcardPkcs11,
            "remote_attested_kms" => UnlockMode::RemoteAttestedKms,
            "threshold_recovery" => UnlockMode::ThresholdRecovery,
            "hybrid_classical_pqc" => UnlockMode::HybridClassicalPqc,
            _ => return None,
        })
    }
}

/// Declarative, deny-by-default policy document (framework §9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PolicyDocument {
    /// Schema version of this document.
    pub schema_version: u32,
    /// Stable identifier for this policy.
    pub policy_id: String,
    /// Minimum acceptable hypervisor version; older launchers are stale.
    pub minimum_hypervisor_version: u64,
    /// Require a signed boot manifest before launch.
    pub require_signed_manifest: bool,
    /// Require measured boot before launch.
    pub require_measured_boot: bool,
    /// Allow PCI/device passthrough assignment to guests.
    pub allow_device_passthrough: bool,
    /// Allow attaching an interactive debug console to guests.
    pub allow_debug_console: bool,
    /// Default network posture: `"deny"` (recommended) or `"allow"`.
    pub network_default: String,
    /// Storage restrictions.
    pub storage: StoragePolicy,
    /// Key-release restrictions.
    pub key_release: KeyReleasePolicy,
}

impl PolicyDocument {
    /// Parse a [`PolicyDocument`] from the SOW JSON, validating its schema
    /// version and well-formedness. Fails closed on any error.
    pub fn parse(s: &str) -> Result<Self, PolicyError> {
        let doc: PolicyDocument = serde_json::from_str(s)?;
        if doc.schema_version != POLICY_SCHEMA_VERSION {
            return Err(PolicyError::UnsupportedSchema {
                found: doc.schema_version,
                expected: POLICY_SCHEMA_VERSION,
            });
        }
        match doc.network_default.as_str() {
            "deny" | "allow" => {}
            other => {
                return Err(PolicyError::InvalidField(format!(
                    "network_default must be \"deny\" or \"allow\", got {other:?}"
                )));
            }
        }
        if doc.key_release.unlock_mode().is_none() {
            return Err(PolicyError::InvalidField(format!(
                "key_release.mode unrecognized: {:?}",
                doc.key_release.mode
            )));
        }
        Ok(doc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn sample_json() -> String {
        r#"{
            "schema_version": 1,
            "policy_id": "pol-001",
            "minimum_hypervisor_version": 52,
            "require_signed_manifest": true,
            "require_measured_boot": true,
            "allow_device_passthrough": false,
            "allow_debug_console": false,
            "network_default": "deny",
            "storage": {
                "require_encryption": true,
                "allow_read_write_base_image": false
            },
            "key_release": {
                "mode": "tpm2_pcr_policy",
                "require_pcr_match_for_sensitive_vms": true
            }
        }"#
        .to_string()
    }

    #[test]
    fn parses_happy_document() {
        let doc = PolicyDocument::parse(&sample_json()).expect("parse");
        assert_eq!(doc.policy_id, "pol-001");
        assert_eq!(doc.minimum_hypervisor_version, 52);
        assert!(doc.require_signed_manifest);
        assert!(!doc.allow_device_passthrough);
        assert_eq!(doc.network_default, "deny");
        assert!(doc.storage.require_encryption);
        assert_eq!(
            doc.key_release.unlock_mode(),
            Some(UnlockMode::Tpm2PcrPolicy)
        );
    }

    #[test]
    fn rejects_bad_schema_version() {
        let j = sample_json().replace("\"schema_version\": 1", "\"schema_version\": 999");
        let err = PolicyDocument::parse(&j).unwrap_err();
        assert!(matches!(err, PolicyError::UnsupportedSchema { found: 999, .. }));
    }

    #[test]
    fn rejects_bad_network_default() {
        let j = sample_json().replace("\"deny\"", "\"sometimes\"");
        let err = PolicyDocument::parse(&j).unwrap_err();
        assert!(matches!(err, PolicyError::InvalidField(_)));
    }

    #[test]
    fn rejects_unknown_unlock_mode() {
        let j = sample_json().replace("tpm2_pcr_policy", "telepathy");
        let err = PolicyDocument::parse(&j).unwrap_err();
        assert!(matches!(err, PolicyError::InvalidField(_)));
    }

    #[test]
    fn rejects_malformed_json() {
        let err = PolicyDocument::parse("{not json").unwrap_err();
        assert!(matches!(err, PolicyError::Json(_)));
    }

    #[test]
    fn round_trips_via_serde() {
        let doc = PolicyDocument::parse(&sample_json()).unwrap();
        let s = serde_json::to_string(&doc).unwrap();
        let back = PolicyDocument::parse(&s).unwrap();
        assert_eq!(doc, back);
    }
}
