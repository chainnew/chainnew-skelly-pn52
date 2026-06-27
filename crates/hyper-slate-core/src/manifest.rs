use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct BootPolicyManifest {
    pub schema_version: u32,
    pub policy_id: String,
    pub minimum_version: u64,
    pub secure_boot_required: bool,
    pub measured_boot_required: bool,
    pub accepted_pcrs: Vec<u8>,
    pub boot_manifest_hash: String,
    pub signatures: Vec<ManifestSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct ManifestSignature {
    pub alg: String,
    pub key_id: String,
    pub sig_ref: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct VolumeManifest {
    pub schema_version: u32,
    pub volume_id: String,
    pub cipher: String,
    pub sector_size: u32,
    pub keyslots: Vec<KeyslotManifest>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct KeyslotManifest {
    pub slot: u32,
    pub kind: String,
    pub status: String,
    pub algorithm_suite: Option<String>,
}
