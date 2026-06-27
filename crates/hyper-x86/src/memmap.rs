#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryKind { Usable, Reserved, Mmio, Acpi, BootServices, RuntimeServices }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryRegion {
    pub start: u64,
    pub len: u64,
    pub kind: MemoryKind,
}
