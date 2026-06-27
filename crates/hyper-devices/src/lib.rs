//! hyper-devices — virtual device bus / framework (slate-runtime V0, SOW §6).
//!
//! Host-testable layer. Provides a deny-by-default virtual device graph: MMIO
//! addresses and I/O ports are routed to registered [`VirtualDevice`]s only when
//! an explicit route exists. Any access to an unregistered address or port fails
//! closed with a [`DevError`].
//!
//! This crate is plain `std` + `thiserror`; it deliberately models the device
//! bus in memory so the routing/fail-closed behaviour can be exercised from host
//! unit tests. It reuses [`hyper_mm::VmId`] for VM identity.
#![forbid(unsafe_code)]

use thiserror::Error;

pub use hyper_mm::VmId;

// ---------------------------------------------------------------------------
// Newtypes
// ---------------------------------------------------------------------------

/// Stable, deterministic identifier for a registered virtual device. Ids are
/// derived from the registration order (a monotonic counter), never random.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceId(pub u32);

impl DeviceId {
    /// Borrow the inner numeric id.
    pub fn get(&self) -> u32 {
        self.0
    }
}

// ---------------------------------------------------------------------------
// Access width
// ---------------------------------------------------------------------------

/// Width of an MMIO / port-I/O access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Width {
    /// 1 byte (8 bits).
    Byte,
    /// 2 bytes (16 bits).
    Word,
    /// 4 bytes (32 bits).
    Dword,
    /// 8 bytes (64 bits).
    Qword,
}

impl Width {
    /// Number of bytes covered by this width.
    pub fn bytes(&self) -> u64 {
        match self {
            Width::Byte => 1,
            Width::Word => 2,
            Width::Dword => 4,
            Width::Qword => 8,
        }
    }

    /// Number of bits covered by this width.
    pub fn bits(&self) -> u32 {
        (self.bytes() * 8) as u32
    }

    /// Mask selecting the low `bytes()` of a value (all-ones for `Qword`).
    pub fn mask(&self) -> u64 {
        match self {
            Width::Qword => u64::MAX,
            other => (1u64 << other.bits()) - 1,
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors produced by the device bus. All public fns fail closed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum DevError {
    /// No MMIO route covers the requested guest physical address.
    #[error("unmapped MMIO address {0:#x}")]
    UnmappedAddress(u64),

    /// No I/O-port route covers the requested port.
    #[error("unknown I/O port {0:#x}")]
    UnknownPort(u16),

    /// A route referenced a device index that is not present in the graph.
    #[error("unknown device index {0}")]
    UnknownDevice(usize),

    /// The device received an access width it does not support.
    #[error("unsupported access width {width:?} at offset {offset:#x}")]
    UnsupportedWidth { offset: u64, width: Width },

    /// The access fell outside the device's registered range/register file.
    #[error("offset {offset:#x} out of range for device")]
    OffsetOutOfRange { offset: u64 },

    /// The value written did not fit the access width.
    #[error("value {value:#x} does not fit access width {width:?}")]
    ValueTooWide { value: u64, width: Width },
}

// ---------------------------------------------------------------------------
// Device actions
// ---------------------------------------------------------------------------

/// Side effect requested by a device after a [`VirtualDevice::tick`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceAction {
    /// Nothing to do.
    None,
    /// Raise the given interrupt request line.
    RaiseIrq(u8),
    /// The device requests a reset.
    NeedsReset,
}

// ---------------------------------------------------------------------------
// VirtualDevice trait
// ---------------------------------------------------------------------------

/// A virtual device attached to the bus. Offsets passed to the MMIO/IO methods
/// are *device-local* (already translated from the global address/port by the
/// [`VirtualDeviceGraph`]).
pub trait VirtualDevice {
    /// Stable identifier for this device.
    fn device_id(&self) -> DeviceId;

    /// Read `width` bytes at device-local MMIO `offset`.
    fn mmio_read(&mut self, offset: u64, width: Width) -> Result<u64, DevError>;

    /// Write `value` of `width` bytes at device-local MMIO `offset`.
    fn mmio_write(&mut self, offset: u64, width: Width, value: u64) -> Result<(), DevError>;

    /// Read `width` bytes from device-local I/O `port` offset.
    fn io_read(&mut self, port: u16, width: Width) -> Result<u32, DevError>;

    /// Write `value` of `width` bytes to device-local I/O `port` offset.
    fn io_write(&mut self, port: u16, width: Width, value: u32) -> Result<(), DevError>;

    /// Advance device time by one step, returning any requested side effect.
    fn tick(&mut self) -> DeviceAction;

    /// Reset the device to its power-on state.
    fn reset(&mut self);
}

// ---------------------------------------------------------------------------
// Route tables
// ---------------------------------------------------------------------------

/// A single `[base, base+len) -> device index` MMIO route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MmioRoute {
    pub base: u64,
    pub len: u64,
    pub device_index: usize,
}

impl MmioRoute {
    fn end(&self) -> u64 {
        self.base.saturating_add(self.len)
    }

    fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.end()
    }

    fn overlaps(&self, base: u64, len: u64) -> bool {
        let other_end = base.saturating_add(len);
        self.base < other_end && base < self.end()
    }
}

/// Deny-by-default table mapping MMIO `[base, base+len)` ranges to device
/// indices. Translation of an unrouted address yields `None`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MmioRouteTable {
    routes: Vec<MmioRoute>,
}

impl MmioRouteTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Install a route. Rejects zero-length ranges and ranges overlapping an
    /// existing route (fail closed).
    pub fn insert(&mut self, base: u64, len: u64, device_index: usize) -> Result<(), DevError> {
        if len == 0 {
            return Err(DevError::OffsetOutOfRange { offset: base });
        }
        if let Some(existing) = self.routes.iter().find(|r| r.overlaps(base, len)) {
            return Err(DevError::UnmappedAddress(existing.base));
        }
        self.routes.push(MmioRoute {
            base,
            len,
            device_index,
        });
        Ok(())
    }

    /// Translate a global MMIO `addr` to `(device_index, device_local_offset)`,
    /// or `None` if no route covers it.
    pub fn translate(&self, addr: u64) -> Option<(usize, u64)> {
        self.routes
            .iter()
            .find(|r| r.contains(addr))
            .map(|r| (r.device_index, addr - r.base))
    }

    /// All installed routes.
    pub fn routes(&self) -> &[MmioRoute] {
        &self.routes
    }
}

/// A single `[base, base+len) -> device index` I/O-port route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoPortRoute {
    pub base: u16,
    pub len: u16,
    pub device_index: usize,
}

impl IoPortRoute {
    fn end(&self) -> u32 {
        self.base as u32 + self.len as u32
    }

    fn contains(&self, port: u16) -> bool {
        let p = port as u32;
        p >= self.base as u32 && p < self.end()
    }

    fn overlaps(&self, base: u16, len: u16) -> bool {
        let other_end = base as u32 + len as u32;
        (self.base as u32) < other_end && (base as u32) < self.end()
    }
}

/// Deny-by-default table mapping I/O-port ranges to device indices.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct IoPortRouteTable {
    routes: Vec<IoPortRoute>,
}

impl IoPortRouteTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Install a port route. Rejects zero-length and overlapping ranges.
    pub fn insert(&mut self, base: u16, len: u16, device_index: usize) -> Result<(), DevError> {
        if len == 0 {
            return Err(DevError::UnknownPort(base));
        }
        if let Some(existing) = self.routes.iter().find(|r| r.overlaps(base, len)) {
            return Err(DevError::UnknownPort(existing.base));
        }
        self.routes.push(IoPortRoute {
            base,
            len,
            device_index,
        });
        Ok(())
    }

    /// Translate a global `port` to `(device_index, device_local_port)`, or
    /// `None` if no route covers it.
    pub fn translate(&self, port: u16) -> Option<(usize, u16)> {
        self.routes
            .iter()
            .find(|r| r.contains(port))
            .map(|r| (r.device_index, port - r.base))
    }

    /// All installed routes.
    pub fn routes(&self) -> &[IoPortRoute] {
        &self.routes
    }
}

/// A single `device index -> irq line` route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IrqRoute {
    pub device_index: usize,
    pub irq: u8,
}

/// Deny-by-default table mapping device indices to interrupt lines.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct IrqRouteTable {
    routes: Vec<IrqRoute>,
}

impl IrqRouteTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind `device_index` to `irq`. Replaces any existing binding for that
    /// device.
    pub fn insert(&mut self, device_index: usize, irq: u8) {
        if let Some(existing) = self.routes.iter_mut().find(|r| r.device_index == device_index) {
            existing.irq = irq;
        } else {
            self.routes.push(IrqRoute { device_index, irq });
        }
    }

    /// Look up the irq line for `device_index`, or `None` if unbound.
    pub fn irq_for(&self, device_index: usize) -> Option<u8> {
        self.routes
            .iter()
            .find(|r| r.device_index == device_index)
            .map(|r| r.irq)
    }

    /// All installed routes.
    pub fn routes(&self) -> &[IrqRoute] {
        &self.routes
    }
}

// ---------------------------------------------------------------------------
// VirtualDeviceGraph
// ---------------------------------------------------------------------------

/// The virtual device bus for a single VM. Owns the registered devices and the
/// MMIO / I/O-port / IRQ route tables. All dispatch is deny-by-default: any
/// access to an unregistered address or port returns a [`DevError`].
pub struct VirtualDeviceGraph {
    vm_id: VmId,
    devices: Vec<Box<dyn VirtualDevice>>,
    mmio_routes: MmioRouteTable,
    io_routes: IoPortRouteTable,
    irq_routes: IrqRouteTable,
}

impl VirtualDeviceGraph {
    /// Create an empty device graph for `vm_id`.
    pub fn new(vm_id: VmId) -> Self {
        VirtualDeviceGraph {
            vm_id,
            devices: Vec::new(),
            mmio_routes: MmioRouteTable::new(),
            io_routes: IoPortRouteTable::new(),
            irq_routes: IrqRouteTable::new(),
        }
    }

    /// The VM this bus belongs to.
    pub fn vm_id(&self) -> &VmId {
        &self.vm_id
    }

    /// Number of registered devices.
    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    /// Borrow the MMIO route table.
    pub fn mmio_routes(&self) -> &MmioRouteTable {
        &self.mmio_routes
    }

    /// Borrow the I/O-port route table.
    pub fn io_routes(&self) -> &IoPortRouteTable {
        &self.io_routes
    }

    /// Borrow the IRQ route table.
    pub fn irq_routes(&self) -> &IrqRouteTable {
        &self.irq_routes
    }

    /// Register `device`, installing optional MMIO range, I/O-port range and IRQ
    /// binding. Returns the assigned device index. Route conflicts fail closed
    /// and leave the device unregistered.
    pub fn register(
        &mut self,
        device: Box<dyn VirtualDevice>,
        mmio_range: Option<(u64, u64)>,
        io_ports: Option<(u16, u16)>,
        irq: Option<u8>,
    ) -> Result<usize, DevError> {
        let index = self.devices.len();

        // Validate all routes BEFORE pushing the device, so a conflict cannot
        // leave the graph half-registered.
        if let Some((base, len)) = mmio_range {
            self.mmio_routes.insert(base, len, index)?;
        }
        if let Some((base, len)) = io_ports {
            if let Err(e) = self.io_routes.insert(base, len, index) {
                // Roll back the MMIO route we just added for this device.
                self.mmio_routes.routes.retain(|r| r.device_index != index);
                return Err(e);
            }
        }
        if let Some(line) = irq {
            self.irq_routes.insert(index, line);
        }

        self.devices.push(device);
        Ok(index)
    }

    /// Resolve a device index to a mutable device reference, fail-closed.
    fn device_mut(&mut self, index: usize) -> Result<&mut (dyn VirtualDevice + '_), DevError> {
        match self.devices.get_mut(index) {
            Some(b) => Ok(&mut **b),
            None => Err(DevError::UnknownDevice(index)),
        }
    }

    /// Dispatch an MMIO read at global guest physical `addr`.
    pub fn dispatch_mmio_read(&mut self, addr: u64, width: Width) -> Result<u64, DevError> {
        let (index, offset) = self
            .mmio_routes
            .translate(addr)
            .ok_or(DevError::UnmappedAddress(addr))?;
        self.device_mut(index)?.mmio_read(offset, width)
    }

    /// Dispatch an MMIO write at global guest physical `addr`.
    pub fn dispatch_mmio_write(
        &mut self,
        addr: u64,
        width: Width,
        value: u64,
    ) -> Result<(), DevError> {
        let (index, offset) = self
            .mmio_routes
            .translate(addr)
            .ok_or(DevError::UnmappedAddress(addr))?;
        self.device_mut(index)?.mmio_write(offset, width, value)
    }

    /// Dispatch an I/O-port read at global `port`.
    pub fn dispatch_io_read(&mut self, port: u16, width: Width) -> Result<u32, DevError> {
        let (index, local) = self
            .io_routes
            .translate(port)
            .ok_or(DevError::UnknownPort(port))?;
        self.device_mut(index)?.io_read(local, width)
    }

    /// Dispatch an I/O-port write at global `port`.
    pub fn dispatch_io_write(
        &mut self,
        port: u16,
        width: Width,
        value: u32,
    ) -> Result<(), DevError> {
        let (index, local) = self
            .io_routes
            .translate(port)
            .ok_or(DevError::UnknownPort(port))?;
        self.device_mut(index)?.io_write(local, width, value)
    }

    /// Tick the device at `index`, returning its requested action.
    pub fn tick_device(&mut self, index: usize) -> Result<DeviceAction, DevError> {
        Ok(self.device_mut(index)?.tick())
    }

    /// Look up the IRQ line bound to the device at `index`.
    pub fn irq_for(&self, index: usize) -> Option<u8> {
        self.irq_routes.irq_for(index)
    }

    /// Reset the device at `index`.
    pub fn reset_device(&mut self, index: usize) -> Result<(), DevError> {
        self.device_mut(index)?.reset();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// TestDevice — a tiny in-memory device used by tests (and as a reference impl).
// ---------------------------------------------------------------------------

/// A minimal [`VirtualDevice`] with a small register file, used in tests and as
/// a reference implementation. It backs both its MMIO and I/O surfaces with the
/// same 8-register file (offset / 8 selects the register).
#[derive(Debug, Clone)]
pub struct TestDevice {
    id: DeviceId,
    regs: [u64; 8],
    ticks: u32,
    /// Number of ticks after which `tick` requests an IRQ on this line.
    irq_after: Option<(u32, u8)>,
}

impl TestDevice {
    /// Register count in the backing file.
    pub const REG_COUNT: u64 = 8;

    /// Create a fresh device with the given id and zeroed registers.
    pub fn new(id: DeviceId) -> Self {
        TestDevice {
            id,
            regs: [0; 8],
            ticks: 0,
            irq_after: None,
        }
    }

    /// Configure the device to request `irq` once it has been ticked `after`
    /// times.
    pub fn with_irq_after(mut self, after: u32, irq: u8) -> Self {
        self.irq_after = Some((after, irq));
        self
    }

    /// Directly inspect a register (for assertions).
    pub fn reg(&self, index: usize) -> Option<u64> {
        self.regs.get(index).copied()
    }

    fn reg_index(offset: u64) -> Result<usize, DevError> {
        if !offset.is_multiple_of(8) {
            return Err(DevError::OffsetOutOfRange { offset });
        }
        let idx = offset / 8;
        if idx >= Self::REG_COUNT {
            return Err(DevError::OffsetOutOfRange { offset });
        }
        Ok(idx as usize)
    }
}

impl VirtualDevice for TestDevice {
    fn device_id(&self) -> DeviceId {
        self.id
    }

    fn mmio_read(&mut self, offset: u64, width: Width) -> Result<u64, DevError> {
        let idx = Self::reg_index(offset)?;
        Ok(self.regs[idx] & width.mask())
    }

    fn mmio_write(&mut self, offset: u64, width: Width, value: u64) -> Result<(), DevError> {
        let idx = Self::reg_index(offset)?;
        if value & !width.mask() != 0 {
            return Err(DevError::ValueTooWide { value, width });
        }
        self.regs[idx] = value;
        Ok(())
    }

    fn io_read(&mut self, port: u16, width: Width) -> Result<u32, DevError> {
        // I/O ports are byte-addressed onto the same register file.
        let idx = Self::reg_index(port as u64)?;
        let mask = (width.mask() & u32::MAX as u64) as u32;
        Ok((self.regs[idx] as u32) & mask)
    }

    fn io_write(&mut self, port: u16, width: Width, value: u32) -> Result<(), DevError> {
        let idx = Self::reg_index(port as u64)?;
        let mask = (width.mask() & u32::MAX as u64) as u32;
        if value & !mask != 0 {
            return Err(DevError::ValueTooWide {
                value: value as u64,
                width,
            });
        }
        self.regs[idx] = value as u64;
        Ok(())
    }

    fn tick(&mut self) -> DeviceAction {
        self.ticks = self.ticks.saturating_add(1);
        if let Some((after, irq)) = self.irq_after {
            if self.ticks >= after {
                return DeviceAction::RaiseIrq(irq);
            }
        }
        DeviceAction::None
    }

    fn reset(&mut self) {
        self.regs = [0; 8];
        self.ticks = 0;
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const VM: &str = "vm-dev-0";

    fn graph() -> VirtualDeviceGraph {
        VirtualDeviceGraph::new(VmId::new(VM))
    }

    #[test]
    fn width_helpers() {
        assert_eq!(Width::Byte.bytes(), 1);
        assert_eq!(Width::Word.bytes(), 2);
        assert_eq!(Width::Dword.bytes(), 4);
        assert_eq!(Width::Qword.bytes(), 8);
        assert_eq!(Width::Byte.mask(), 0xff);
        assert_eq!(Width::Word.mask(), 0xffff);
        assert_eq!(Width::Dword.mask(), 0xffff_ffff);
        assert_eq!(Width::Qword.mask(), u64::MAX);
        assert_eq!(Width::Qword.bits(), 64);
    }

    #[test]
    fn register_and_mmio_roundtrip() {
        let mut g = graph();
        let idx = g
            .register(
                Box::new(TestDevice::new(DeviceId(1))),
                Some((0xfee0_0000, 0x40)),
                None,
                None,
            )
            .unwrap();
        assert_eq!(idx, 0);
        assert_eq!(g.device_count(), 1);

        // Write then read back through the global address.
        g.dispatch_mmio_write(0xfee0_0008, Width::Qword, 0xdead_beef)
            .unwrap();
        let v = g.dispatch_mmio_read(0xfee0_0008, Width::Qword).unwrap();
        assert_eq!(v, 0xdead_beef);

        // Offset translation: base maps to device offset 0.
        g.dispatch_mmio_write(0xfee0_0000, Width::Dword, 0x1234)
            .unwrap();
        assert_eq!(
            g.dispatch_mmio_read(0xfee0_0000, Width::Dword).unwrap(),
            0x1234
        );
    }

    #[test]
    fn unknown_mmio_is_denied() {
        let mut g = graph();
        g.register(
            Box::new(TestDevice::new(DeviceId(1))),
            Some((0x1000, 0x40)),
            None,
            None,
        )
        .unwrap();
        // Outside the registered range.
        assert_eq!(
            g.dispatch_mmio_read(0x2000, Width::Dword),
            Err(DevError::UnmappedAddress(0x2000))
        );
        assert_eq!(
            g.dispatch_mmio_write(0x2000, Width::Dword, 0),
            Err(DevError::UnmappedAddress(0x2000))
        );
        // Empty graph denies everything.
        let mut empty = graph();
        assert_eq!(
            empty.dispatch_mmio_read(0x1000, Width::Byte),
            Err(DevError::UnmappedAddress(0x1000))
        );
    }

    #[test]
    fn io_port_roundtrip_and_translation() {
        let mut g = graph();
        g.register(
            Box::new(TestDevice::new(DeviceId(7))),
            None,
            Some((0x60, 0x40)),
            None,
        )
        .unwrap();
        // Port 0x68 -> device-local port 0x08 -> register 1.
        g.dispatch_io_write(0x68, Width::Dword, 0xcafe).unwrap();
        assert_eq!(g.dispatch_io_read(0x68, Width::Dword).unwrap(), 0xcafe);
    }

    #[test]
    fn unknown_port_is_denied() {
        let mut g = graph();
        g.register(
            Box::new(TestDevice::new(DeviceId(7))),
            None,
            Some((0x60, 0x10)),
            None,
        )
        .unwrap();
        assert_eq!(
            g.dispatch_io_read(0x300, Width::Byte),
            Err(DevError::UnknownPort(0x300))
        );
        assert_eq!(
            g.dispatch_io_write(0x300, Width::Byte, 0),
            Err(DevError::UnknownPort(0x300))
        );
    }

    #[test]
    fn irq_lookup() {
        let mut g = graph();
        let idx = g
            .register(
                Box::new(TestDevice::new(DeviceId(2))),
                Some((0x5000, 0x10)),
                None,
                Some(11),
            )
            .unwrap();
        assert_eq!(g.irq_for(idx), Some(11));
        // A device with no irq returns None.
        let idx2 = g
            .register(
                Box::new(TestDevice::new(DeviceId(3))),
                Some((0x6000, 0x10)),
                None,
                None,
            )
            .unwrap();
        assert_eq!(g.irq_for(idx2), None);
    }

    #[test]
    fn tick_action_raises_irq() {
        let mut g = graph();
        let idx = g
            .register(
                Box::new(TestDevice::new(DeviceId(4)).with_irq_after(2, 9)),
                Some((0x7000, 0x10)),
                None,
                Some(9),
            )
            .unwrap();
        assert_eq!(g.tick_device(idx).unwrap(), DeviceAction::None);
        assert_eq!(g.tick_device(idx).unwrap(), DeviceAction::RaiseIrq(9));
    }

    #[test]
    fn tick_unknown_device_denied() {
        let mut g = graph();
        assert_eq!(g.tick_device(99), Err(DevError::UnknownDevice(99)));
        assert_eq!(g.reset_device(99), Err(DevError::UnknownDevice(99)));
    }

    #[test]
    fn reset_clears_registers() {
        let mut g = graph();
        let idx = g
            .register(
                Box::new(TestDevice::new(DeviceId(5))),
                Some((0x8000, 0x40)),
                None,
                None,
            )
            .unwrap();
        g.dispatch_mmio_write(0x8000, Width::Qword, 0x42).unwrap();
        assert_eq!(g.dispatch_mmio_read(0x8000, Width::Qword).unwrap(), 0x42);
        g.reset_device(idx).unwrap();
        assert_eq!(g.dispatch_mmio_read(0x8000, Width::Qword).unwrap(), 0);
    }

    #[test]
    fn overlapping_mmio_route_rejected() {
        let mut g = graph();
        g.register(
            Box::new(TestDevice::new(DeviceId(1))),
            Some((0x1000, 0x100)),
            None,
            None,
        )
        .unwrap();
        let err = g
            .register(
                Box::new(TestDevice::new(DeviceId(2))),
                Some((0x1080, 0x100)),
                None,
                None,
            )
            .unwrap_err();
        assert_eq!(err, DevError::UnmappedAddress(0x1000));
        // The second device must NOT have been registered.
        assert_eq!(g.device_count(), 1);
    }

    #[test]
    fn overlapping_io_route_rolls_back_mmio() {
        let mut g = graph();
        g.register(
            Box::new(TestDevice::new(DeviceId(1))),
            None,
            Some((0x60, 0x10)),
            None,
        )
        .unwrap();
        // This registration adds a valid MMIO route but a conflicting IO route;
        // the whole registration must fail and roll back the MMIO route.
        let err = g
            .register(
                Box::new(TestDevice::new(DeviceId(2))),
                Some((0x9000, 0x10)),
                Some((0x68, 0x10)),
                None,
            )
            .unwrap_err();
        assert_eq!(err, DevError::UnknownPort(0x60));
        assert_eq!(g.device_count(), 1);
        // The rolled-back MMIO route must not resolve.
        assert_eq!(
            g.dispatch_mmio_read(0x9000, Width::Byte),
            Err(DevError::UnmappedAddress(0x9000))
        );
    }

    #[test]
    fn zero_length_routes_rejected() {
        let mut mt = MmioRouteTable::new();
        assert!(mt.insert(0x1000, 0, 0).is_err());
        let mut it = IoPortRouteTable::new();
        assert!(it.insert(0x60, 0, 0).is_err());
    }

    #[test]
    fn device_offset_out_of_range_and_value_too_wide() {
        let mut dev = TestDevice::new(DeviceId(1));
        // Unaligned offset.
        assert_eq!(
            dev.mmio_read(0x3, Width::Byte),
            Err(DevError::OffsetOutOfRange { offset: 0x3 })
        );
        // Beyond register file (8 regs * 8 bytes = 0x40).
        assert_eq!(
            dev.mmio_read(0x40, Width::Qword),
            Err(DevError::OffsetOutOfRange { offset: 0x40 })
        );
        // Value wider than the access width.
        assert_eq!(
            dev.mmio_write(0, Width::Byte, 0x1ff),
            Err(DevError::ValueTooWide {
                value: 0x1ff,
                width: Width::Byte
            })
        );
    }

    #[test]
    fn width_truncates_on_read() {
        let mut dev = TestDevice::new(DeviceId(1));
        dev.mmio_write(0, Width::Qword, 0xdead_beef_cafe_babe)
            .unwrap();
        assert_eq!(dev.mmio_read(0, Width::Byte).unwrap(), 0xbe);
        assert_eq!(dev.mmio_read(0, Width::Word).unwrap(), 0xbabe);
        assert_eq!(dev.mmio_read(0, Width::Dword).unwrap(), 0xcafe_babe);
        assert_eq!(dev.reg(0), Some(0xdead_beef_cafe_babe));
    }

    #[test]
    fn route_table_translate_direct() {
        let mut mt = MmioRouteTable::new();
        mt.insert(0x1000, 0x100, 3).unwrap();
        assert_eq!(mt.translate(0x1000), Some((3, 0)));
        assert_eq!(mt.translate(0x10ff), Some((3, 0xff)));
        assert_eq!(mt.translate(0x1100), None);
        assert_eq!(mt.routes().len(), 1);

        let mut it = IoPortRouteTable::new();
        it.insert(0x60, 0x10, 2).unwrap();
        assert_eq!(it.translate(0x60), Some((2, 0)));
        assert_eq!(it.translate(0x6f), Some((2, 0xf)));
        assert_eq!(it.translate(0x70), None);

        let mut irt = IrqRouteTable::new();
        irt.insert(5, 3);
        irt.insert(5, 4); // replace
        assert_eq!(irt.irq_for(5), Some(4));
        assert_eq!(irt.irq_for(6), None);
        assert_eq!(irt.routes().len(), 1);
    }

    #[test]
    fn device_id_and_action_variants() {
        let dev = TestDevice::new(DeviceId(42));
        assert_eq!(dev.device_id(), DeviceId(42));
        assert_eq!(dev.device_id().get(), 42);
        // NeedsReset variant exists and is distinct.
        assert_ne!(DeviceAction::NeedsReset, DeviceAction::None);
    }

    #[test]
    fn vm_id_is_preserved() {
        let g = graph();
        assert_eq!(g.vm_id().as_str(), VM);
    }
}
