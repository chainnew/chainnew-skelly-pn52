#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NptRoot {
    pub pml4_pa: u64,
}

pub fn identity_map_plan(_start: u64, _len: u64) -> NptRoot {
    NptRoot { pml4_pa: 0 }
}
