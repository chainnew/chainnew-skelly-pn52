//! `VirtioConsole` — a minimal virtio-console output model.
//!
//! The guest writes bytes one at a time to the data register via
//! [`VirtualDevice::mmio_write`]; the host drains them with
//! [`VirtioConsole::take_output`] / [`VirtioConsole::output_str`]. This backs
//! acceptance **V2** ("guest writes `hello`, host receives it").
//!
//! MMIO register map (device-local offsets, all `Width::Byte`/`Width::Dword`):
//!   * `0x00` `DATA`    — write: append the low byte; read: 0.
//!   * `0x04` `PENDING` — read: number of buffered (undrained) bytes.

use hyper_devices::{DevError, DeviceAction, DeviceId, VirtualDevice, Width};

/// Device-local offset of the data register.
pub const REG_DATA: u64 = 0x00;
/// Device-local offset of the pending-length register.
pub const REG_PENDING: u64 = 0x04;
/// Total MMIO window length for a console device.
pub const MMIO_LEN: u64 = 0x08;

/// A virtio-console model that captures guest output into a host-side buffer.
#[derive(Debug, Clone)]
pub struct VirtioConsole {
    id: DeviceId,
    out: Vec<u8>,
}

impl VirtioConsole {
    /// Create an empty console with the given stable device id.
    pub fn new(id: DeviceId) -> Self {
        VirtioConsole {
            id,
            out: Vec::new(),
        }
    }

    /// Number of buffered (undrained) output bytes.
    pub fn pending(&self) -> usize {
        self.out.len()
    }

    /// Borrow the buffered output without draining it.
    pub fn output(&self) -> &[u8] {
        &self.out
    }

    /// Lossy UTF-8 view of the buffered output (does not drain).
    pub fn output_str(&self) -> String {
        String::from_utf8_lossy(&self.out).into_owned()
    }

    /// Drain and return all buffered output bytes.
    pub fn take_output(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.out)
    }
}

impl VirtualDevice for VirtioConsole {
    fn device_id(&self) -> DeviceId {
        self.id
    }

    fn mmio_read(&mut self, offset: u64, width: Width) -> Result<u64, DevError> {
        match offset {
            REG_DATA => Ok(0),
            REG_PENDING => Ok(self.out.len() as u64 & width.mask()),
            other => Err(DevError::OffsetOutOfRange { offset: other }),
        }
    }

    fn mmio_write(&mut self, offset: u64, width: Width, value: u64) -> Result<(), DevError> {
        match offset {
            REG_DATA => {
                // A console data register is byte-oriented; reject wider writes
                // fail-closed so a guest can't silently drop bytes.
                if width != Width::Byte {
                    return Err(DevError::UnsupportedWidth { offset, width });
                }
                if value & !Width::Byte.mask() != 0 {
                    return Err(DevError::ValueTooWide { value, width });
                }
                self.out.push(value as u8);
                Ok(())
            }
            REG_PENDING => Err(DevError::OffsetOutOfRange { offset }),
            other => Err(DevError::OffsetOutOfRange { offset: other }),
        }
    }

    fn io_read(&mut self, port: u16, _width: Width) -> Result<u32, DevError> {
        Err(DevError::OffsetOutOfRange {
            offset: port as u64,
        })
    }

    fn io_write(&mut self, port: u16, _width: Width, _value: u32) -> Result<(), DevError> {
        Err(DevError::OffsetOutOfRange {
            offset: port as u64,
        })
    }

    fn tick(&mut self) -> DeviceAction {
        DeviceAction::None
    }

    fn reset(&mut self) {
        self.out.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_hello() {
        let mut c = VirtioConsole::new(DeviceId(1));
        for &b in b"hello" {
            c.mmio_write(REG_DATA, Width::Byte, b as u64).unwrap();
        }
        assert_eq!(c.pending(), 5);
        assert_eq!(c.output_str(), "hello");
        // take_output drains.
        assert_eq!(c.take_output(), b"hello");
        assert_eq!(c.pending(), 0);
        assert_eq!(c.output_str(), "");
    }

    #[test]
    fn pending_register_readback() {
        let mut c = VirtioConsole::new(DeviceId(2));
        c.mmio_write(REG_DATA, Width::Byte, b'A' as u64).unwrap();
        c.mmio_write(REG_DATA, Width::Byte, b'B' as u64).unwrap();
        assert_eq!(c.mmio_read(REG_PENDING, Width::Dword).unwrap(), 2);
        assert_eq!(c.mmio_read(REG_DATA, Width::Byte).unwrap(), 0);
    }

    #[test]
    fn wide_write_rejected() {
        let mut c = VirtioConsole::new(DeviceId(3));
        assert_eq!(
            c.mmio_write(REG_DATA, Width::Word, 0x4142),
            Err(DevError::UnsupportedWidth {
                offset: REG_DATA,
                width: Width::Word
            })
        );
        // Value not fitting a byte is rejected.
        assert_eq!(
            c.mmio_write(REG_DATA, Width::Byte, 0x1ff),
            Err(DevError::ValueTooWide {
                value: 0x1ff,
                width: Width::Byte
            })
        );
        assert_eq!(c.pending(), 0);
    }

    #[test]
    fn unknown_offset_and_ports_denied() {
        let mut c = VirtioConsole::new(DeviceId(4));
        assert_eq!(
            c.mmio_read(0x40, Width::Byte),
            Err(DevError::OffsetOutOfRange { offset: 0x40 })
        );
        assert_eq!(
            c.mmio_write(0x40, Width::Byte, 0),
            Err(DevError::OffsetOutOfRange { offset: 0x40 })
        );
        assert!(c.io_read(0, Width::Byte).is_err());
        assert!(c.io_write(0, Width::Byte, 0).is_err());
    }

    #[test]
    fn reset_clears_buffer() {
        let mut c = VirtioConsole::new(DeviceId(5));
        c.mmio_write(REG_DATA, Width::Byte, b'x' as u64).unwrap();
        c.reset();
        assert_eq!(c.pending(), 0);
        assert_eq!(c.tick(), DeviceAction::None);
    }
}
