use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct StorageKeyHierarchy {
    pub volume_id: String,
    pub dek_version: u64,
    pub vmk_version: u64,
    pub keyslots: Vec<Keyslot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Keyslot {
    pub id: u32,
    pub kind: String,
    pub status: String,
}
