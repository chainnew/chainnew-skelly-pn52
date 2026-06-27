#[repr(C, align(4096))]
pub struct VmcbPage {
    pub bytes: [u8; 4096],
}

#[repr(C, packed)]
pub struct VmcbControlArea {
    pub intercept_cr_read: u32,
    pub intercept_cr_write: u32,
    pub intercept_dr_read: u32,
    pub intercept_dr_write: u32,
    pub intercept_exceptions: u32,
    pub intercept_instr1: u32,
    pub intercept_instr2: u32,
    pub intercept_instr3: u32,
    pub reserved_20: u32,
    pub pause_filter_threshold: u16,
    pub pause_filter_count: u16,
    pub iopm_base_pa: u64,
    pub msrpm_base_pa: u64,
    pub tsc_offset: u64,
    pub guest_asid: u32,
    pub tlb_control: u8,
    pub reserved_45: [u8; 3],
    pub int_ctl: u32,
    pub int_vector: u32,
    pub exit_code: u64,
    pub exit_info1: u64,
    pub exit_info2: u64,
    pub exit_int_info: u64,
    pub np_enable: u64,
}

pub const VMEXIT_HLT: u64 = 0x40;
pub const VMEXIT_NPF: u64 = 0x400; // placeholder: verify against AMD APM before using
