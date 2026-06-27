use crate::port::{inb, outb};

pub const COM1: u16 = 0x3F8;

pub unsafe fn init_16550(base: u16) {
    outb(base + 1, 0x00);
    outb(base + 3, 0x80);
    outb(base + 0, 0x03);
    outb(base + 1, 0x00);
    outb(base + 3, 0x03);
    outb(base + 2, 0xC7);
    outb(base + 4, 0x0B);
}

pub unsafe fn write_byte(base: u16, b: u8) {
    while (inb(base + 5) & 0x20) == 0 {}
    outb(base, b);
}
