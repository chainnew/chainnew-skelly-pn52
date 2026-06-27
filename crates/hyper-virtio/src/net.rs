//! Cheap virtio-net and pvclock stubs.
//!
//! These are intentionally minimal V0 models: enough surface to register on the
//! device bus and behave deterministically, with no real networking or clock.

use hyper_devices::{DevError, DeviceAction, DeviceId, VirtualDevice, Width};

use crate::hash::sha384;

/// Read: low 32 bits of the deterministic MAC.
pub const NET_REG_MAC_LO: u64 = 0x00;
/// Read: high 16 bits of the deterministic MAC.
pub const NET_REG_MAC_HI: u64 = 0x08;
/// Write: append `value`'s low byte to the TX byte counter; Read: TX byte count.
pub const NET_REG_TX: u64 = 0x10;
/// Total MMIO window length for the net stub.
pub const NET_MMIO_LEN: u64 = 0x18;

/// A minimal virtio-net stub with a deterministic MAC and a TX byte counter.
#[derive(Debug, Clone)]
pub struct VirtioNet {
    id: DeviceId,
    mac: [u8; 6],
    tx_bytes: u64,
}

impl VirtioNet {
    /// Create a net stub whose MAC is derived deterministically from `name`
    /// (locally-administered, unicast). No randomness.
    pub fn new(id: DeviceId, name: &str) -> Self {
        let d = sha384(name.as_bytes());
        let mut mac = [d[0], d[1], d[2], d[3], d[4], d[5]];
        mac[0] = (mac[0] & 0xfe) | 0x02; // locally administered, unicast
        VirtioNet {
            id,
            mac,
            tx_bytes: 0,
        }
    }

    /// The device's deterministic MAC address.
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// Total bytes "transmitted" so far.
    pub fn tx_bytes(&self) -> u64 {
        self.tx_bytes
    }

    fn mac_lo(&self) -> u64 {
        u32::from_le_bytes([self.mac[0], self.mac[1], self.mac[2], self.mac[3]]) as u64
    }

    fn mac_hi(&self) -> u64 {
        u16::from_le_bytes([self.mac[4], self.mac[5]]) as u64
    }
}

impl VirtualDevice for VirtioNet {
    fn device_id(&self) -> DeviceId {
        self.id
    }

    fn mmio_read(&mut self, offset: u64, width: Width) -> Result<u64, DevError> {
        match offset {
            NET_REG_MAC_LO => Ok(self.mac_lo() & width.mask()),
            NET_REG_MAC_HI => Ok(self.mac_hi() & width.mask()),
            NET_REG_TX => Ok(self.tx_bytes & width.mask()),
            other => Err(DevError::OffsetOutOfRange { offset: other }),
        }
    }

    fn mmio_write(&mut self, offset: u64, _width: Width, value: u64) -> Result<(), DevError> {
        match offset {
            NET_REG_TX => {
                self.tx_bytes = self.tx_bytes.saturating_add(value & 0xff);
                Ok(())
            }
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
        self.tx_bytes = 0;
    }
}

/// Read: current monotonic tick counter (advanced only by [`VirtualDevice::tick`]).
pub const CLK_REG_NOW: u64 = 0x00;
/// Total MMIO window length for the pvclock stub.
pub const CLK_MMIO_LEN: u64 = 0x08;

/// A paravirtual clock stub. It exposes a monotonic counter that advances by one
/// per [`VirtualDevice::tick`] — it never reads the host clock, so it stays
/// deterministic.
#[derive(Debug, Clone)]
pub struct PvClock {
    id: DeviceId,
    now: u64,
}

impl PvClock {
    /// Create a pvclock stub starting at tick 0.
    pub fn new(id: DeviceId) -> Self {
        PvClock { id, now: 0 }
    }

    /// The current tick value.
    pub fn now(&self) -> u64 {
        self.now
    }
}

impl VirtualDevice for PvClock {
    fn device_id(&self) -> DeviceId {
        self.id
    }

    fn mmio_read(&mut self, offset: u64, width: Width) -> Result<u64, DevError> {
        match offset {
            CLK_REG_NOW => Ok(self.now & width.mask()),
            other => Err(DevError::OffsetOutOfRange { offset: other }),
        }
    }

    fn mmio_write(&mut self, offset: u64, _width: Width, _value: u64) -> Result<(), DevError> {
        Err(DevError::OffsetOutOfRange { offset })
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
        self.now = self.now.saturating_add(1);
        DeviceAction::None
    }

    fn reset(&mut self) {
        self.now = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn net_mac_is_deterministic_and_locally_administered() {
        let a = VirtioNet::new(DeviceId(1), "eth0");
        let b = VirtioNet::new(DeviceId(2), "eth0");
        assert_eq!(a.mac(), b.mac());
        assert_ne!(a.mac(), VirtioNet::new(DeviceId(3), "eth1").mac());
        // Locally-administered unicast bits.
        assert_eq!(a.mac()[0] & 0x03, 0x02);
    }

    #[test]
    fn net_tx_counter_and_mac_regs() {
        let mut n = VirtioNet::new(DeviceId(1), "eth0");
        n.mmio_write(NET_REG_TX, Width::Byte, 0x40).unwrap();
        n.mmio_write(NET_REG_TX, Width::Byte, 0x10).unwrap();
        assert_eq!(n.mmio_read(NET_REG_TX, Width::Qword).unwrap(), 0x50);
        assert_eq!(n.tx_bytes(), 0x50);
        assert_eq!(
            n.mmio_read(NET_REG_MAC_LO, Width::Dword).unwrap(),
            u32::from_le_bytes([n.mac()[0], n.mac()[1], n.mac()[2], n.mac()[3]]) as u64
        );
        n.reset();
        assert_eq!(n.tx_bytes(), 0);
        assert!(n.mmio_read(0x99, Width::Byte).is_err());
    }

    #[test]
    fn pvclock_advances_on_tick_only() {
        let mut c = PvClock::new(DeviceId(1));
        assert_eq!(c.now(), 0);
        c.tick();
        c.tick();
        assert_eq!(c.now(), 2);
        assert_eq!(c.mmio_read(CLK_REG_NOW, Width::Qword).unwrap(), 2);
        assert!(c.mmio_write(CLK_REG_NOW, Width::Qword, 5).is_err());
        c.reset();
        assert_eq!(c.now(), 0);
    }
}
