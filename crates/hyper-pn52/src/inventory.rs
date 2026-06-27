use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct Pn52Inventory {
    pub schema_version: u32,
    pub captured_at_utc: String,
    pub cpu: Option<Pn52CpuInfo>,
    pub pci_devices: Vec<crate::pci::PciDevice>,
    pub acpi_tables: Vec<crate::acpi::AcpiTableInfo>,
    pub security: Option<crate::security::Pn52SecurityReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct Pn52CpuInfo {
    pub sku: String,
    pub family: Option<u32>,
    pub model: Option<u32>,
    pub cores: Option<u32>,
    pub threads: Option<u32>,
    pub svm: bool,
    pub invariant_tsc: bool,
}

pub fn parse_lscpu(text: &str) -> Pn52CpuInfo {
    let mut out = Pn52CpuInfo::default();
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("Model name:") {
            out.sku = v.trim().to_owned();
        }
        if let Some(v) = line.strip_prefix("CPU(s):") {
            out.threads = v.trim().parse().ok();
        }
        if let Some(v) = line.strip_prefix("Core(s) per socket:") {
            out.cores = v.trim().parse().ok();
        }
    }
    out
}
