use crate::msr::{rdmsr, wrmsr, EFER, EFER_SVME, VM_HSAVE_PA};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SvmError { NotSupported, VmrunFailed, InvalidVmcb }

pub unsafe fn enable_svm(host_save_pa: u64) {
    let mut efer = rdmsr(EFER);
    efer |= EFER_SVME;
    wrmsr(EFER, efer);
    wrmsr(VM_HSAVE_PA, host_save_pa);
}

#[cfg(target_arch = "x86_64")]
pub unsafe fn vmrun(vmcb_pa: u64) {
    core::arch::asm!("vmrun rax", in("rax") vmcb_pa, options(nostack));
}

#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn vmrun(_vmcb_pa: u64) {
    unimplemented!("x86_64 only")
}
