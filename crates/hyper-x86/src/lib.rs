#![no_std]

pub mod cpu;
pub mod memmap;
pub mod pci;
pub mod port;
pub mod serial;

pub unsafe fn halt_forever() -> ! {
    loop { core::arch::asm!("hlt"); }
}
