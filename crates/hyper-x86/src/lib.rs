#![no_std]

pub mod cpu;
pub mod memmap;
pub mod pci;
pub mod port;
pub mod serial;

#[cfg(target_arch = "x86_64")]
pub unsafe fn halt_forever() -> ! {
    loop { core::arch::asm!("hlt"); }
}

#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn halt_forever() -> ! {
    unimplemented!("x86_64 only")
}
