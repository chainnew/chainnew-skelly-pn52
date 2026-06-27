#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuCaps {
    pub svm: bool,
    pub invariant_tsc: bool,
    pub x2apic: bool,
}

#[cfg(target_arch = "x86_64")]
pub fn detect_cpu_caps() -> CpuCaps {
    let leaf1 = unsafe { core::arch::x86_64::__cpuid(1) };
    let ext1 = unsafe { core::arch::x86_64::__cpuid(0x8000_0001) };
    let ext7 = unsafe { core::arch::x86_64::__cpuid(0x8000_0007) };
    CpuCaps { svm: (ext1.ecx & (1 << 2)) != 0, invariant_tsc: (ext7.edx & (1 << 8)) != 0, x2apic: (leaf1.ecx & (1 << 21)) != 0 }
}

#[cfg(not(target_arch = "x86_64"))]
pub fn detect_cpu_caps() -> CpuCaps { CpuCaps { svm: false, invariant_tsc: false, x2apic: false } }
