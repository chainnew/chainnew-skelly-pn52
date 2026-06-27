use crate::Pn52Inventory;

pub fn markdown_report(inv: &Pn52Inventory) -> String {
    let mut s = String::new();
    s.push_str("# PN52 inventory report\n\n");
    s.push_str(&format!("schema_version: {}\n\n", inv.schema_version));
    if let Some(cpu) = &inv.cpu {
        s.push_str(&format!("## CPU\n\n- sku: `{}`\n- svm: `{}`\n- invariant_tsc: `{}`\n\n", cpu.sku, cpu.svm, cpu.invariant_tsc));
    }
    s.push_str(&format!("## PCI\n\n{} devices parsed.\n", inv.pci_devices.len()));
    s
}
