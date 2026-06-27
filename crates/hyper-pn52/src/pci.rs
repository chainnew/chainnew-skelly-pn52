use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct PciDevice {
    pub bdf: String,
    pub class_name: String,
    pub vendor_device: String,
    pub driver: Option<String>,
    pub iommu_group: Option<u32>,
}

pub fn parse_lspci_tree(text: &str) -> Vec<String> {
    text.lines().map(str::trim).filter(|l| !l.is_empty()).map(ToOwned::to_owned).collect()
}
