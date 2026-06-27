#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bdf { pub bus: u8, pub device: u8, pub function: u8 }

impl Bdf {
    pub const fn new(bus: u8, device: u8, function: u8) -> Self { Self { bus, device, function } }
    pub const fn config_addr(self, offset: u8) -> u32 {
        0x8000_0000 | ((self.bus as u32) << 16) | ((self.device as u32) << 11) | ((self.function as u32) << 8) | ((offset as u32) & 0xfc)
    }
}
