use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct AcpiTableInfo {
    pub signature: String,
    pub present: bool,
}

pub fn detect_table_signatures(text: &str) -> Vec<AcpiTableInfo> {
    ["RSDP", "XSDT", "FACP", "APIC", "MCFG", "HPET", "IVRS", "TPM2"]
        .iter()
        .map(|sig| AcpiTableInfo { signature: (*sig).into(), present: text.contains(sig) })
        .collect()
}
