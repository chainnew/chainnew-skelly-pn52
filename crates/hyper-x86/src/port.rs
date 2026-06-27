#[cfg(target_arch = "x86_64")]
pub unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack, preserves_flags));
}

#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn outb(_port: u16, _val: u8) {
    unimplemented!("x86_64 only")
}

#[cfg(target_arch = "x86_64")]
pub unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    core::arch::asm!("in al, dx", out("al") val, in("dx") port, options(nomem, nostack, preserves_flags));
    val
}

#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn inb(_port: u16) -> u8 {
    unimplemented!("x86_64 only")
}
