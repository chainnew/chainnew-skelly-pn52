pub const EFER: u32 = 0xC000_0080;
pub const VM_HSAVE_PA: u32 = 0xC001_0117;
pub const EFER_SVME: u64 = 1 << 12;

pub unsafe fn rdmsr(msr: u32) -> u64 {
    let high: u32;
    let low: u32;
    core::arch::asm!("rdmsr", in("ecx") msr, out("edx") high, out("eax") low, options(nomem, nostack, preserves_flags));
    ((high as u64) << 32) | low as u64
}

pub unsafe fn wrmsr(msr: u32, val: u64) {
    let high = (val >> 32) as u32;
    let low = val as u32;
    core::arch::asm!("wrmsr", in("ecx") msr, in("edx") high, in("eax") low, options(nomem, nostack, preserves_flags));
}
