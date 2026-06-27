#![no_std]

pub mod cpu;
pub mod memmap;
pub mod pci;

#[cfg(target_arch = "x86_64")]
pub mod port;

#[cfg(target_arch = "x86_64")]
pub mod serial;

#[cfg(target_arch = "x86_64")]
pub unsafe fn halt_forever() -> ! {
    loop {
        core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn halt_forever() -> ! {
    loop {
        core::hint::spin_loop();
    }
}
