use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct Pn52SecurityReport {
    pub secure_boot: SecureBootState,
    pub ftpm_present: bool,
    pub pcr_banks: Vec<String>,
    pub spi_write_protected: Option<bool>,
    pub amd_psb_fused: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SecureBootState { Enabled, Disabled, SetupMode, Unknown }

pub fn parse_mokutil_state(text: &str) -> SecureBootState {
    let lower = text.to_ascii_lowercase();
    if lower.contains("secureboot enabled") { SecureBootState::Enabled }
    else if lower.contains("secureboot disabled") { SecureBootState::Disabled }
    else { SecureBootState::Unknown }
}
