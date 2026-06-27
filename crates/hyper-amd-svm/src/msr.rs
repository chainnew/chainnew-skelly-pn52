pub const EFER: u32 = 0xC000_0080;
pub const VM_HSAVE_PA: u32 = 0xC001_0117;
pub const EFER_SVME: u64 = 1 << 12;

#[cfg(target_arch = "x86_64")]
pub unsafe fn rdmsr(msr: u32) -> u64 {
    let high: u32;
    let low: u32;
    core::arch::asm!(
        "rdmsr",
        in("ecx") msr,
        out("edx") high,
        out("eax") low,
        options(nomem, nostack, preserves_flags),
    );
    ((high as u64) << 32) | low as u64
}

#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn rdmsr(_msr: u32) -> u64 {
    unimplemented!("x86_64 only")
    panic!("rdmsr is only available on x86_64 targets")
}

#[cfg(target_arch = "x86_64")]
pub unsafe fn wrmsr(msr: u32, val: u64) {
    let high = (val >> 32) as u32;
    let low = val as u32;
    core::arch::asm!(
        "wrmsr",
        in("ecx") msr,
        in("edx") high,
        in("eax") low,
        options(nomem, nostack, preserves_flags),
    );
}

#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn wrmsr(_msr: u32, _val: u64) {
    panic!("wrmsr is only available on x86_64 targets")
}

#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn wrmsr(_msr: u32, _val: u64) {
    unimplemented!("x86_64 only")
}
