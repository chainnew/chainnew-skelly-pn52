//! hyper-virtio — minimal virtio device *models* for the chain.new hyper-slate
//! runtime (slate-runtime V0, SOW §6 MVP).
//!
//! This is the host-testable layer: each device is a small, deterministic state
//! machine implementing [`hyper_devices::VirtualDevice`], with a coherent (but
//! deliberately not spec-complete) MMIO surface. Nothing here uses randomness, a
//! system clock, or `unsafe`.
//!
//! Devices provided:
//!   * [`VirtioConsole`] — captures guest byte output (acceptance **V2**).
//!   * [`VirtioBlk`] — read-only block device that verifies backend bytes
//!     against an expected `"sha384:<hex>"` digest; a flipped byte fails the
//!     read closed (acceptance **V3**).
//!   * [`VirtioRng`] — deterministic counter/hash DRBG.
//!   * [`VirtioNet`] / [`PvClock`] — cheap deterministic stubs.
//!
//! All hashes use SHA-384 formatted as `"sha384:<hex>"` via [`sha384_hex`],
//! matching the runtime-wide convention.
#![forbid(unsafe_code)]

mod blk;
mod console;
mod error;
mod hash;
mod net;
mod rng;

// Re-export the bus vocabulary so downstream callers can use one import path.
pub use hyper_devices::{
    DevError, DeviceAction, DeviceId, VirtualDevice, VirtualDeviceGraph, Width,
};

pub use blk::{
    BlkIntegrity, BlockBackend, InMemoryBlockBackend, VirtioBlk, CMD_LOAD, MMIO_LEN as BLK_MMIO_LEN,
    REG_CAPACITY, REG_COMMAND, REG_DATA as BLK_REG_DATA, REG_SECTOR_SEL, REG_SECTOR_SIZE,
    REG_STATUS, STATUS_INTEGRITY, STATUS_OK, STATUS_OUT_OF_RANGE,
};
pub use console::{
    VirtioConsole, MMIO_LEN as CONSOLE_MMIO_LEN, REG_DATA as CONSOLE_REG_DATA, REG_PENDING,
};
pub use error::VirtioError;
pub use hash::{sha384, sha384_hex};
pub use net::{
    PvClock, VirtioNet, CLK_MMIO_LEN, CLK_REG_NOW, NET_MMIO_LEN, NET_REG_MAC_HI, NET_REG_MAC_LO,
    NET_REG_TX,
};
pub use rng::{VirtioRng, MMIO_LEN as RNG_MMIO_LEN, REG_DATA as RNG_REG_DATA, REG_SEED};

#[cfg(test)]
mod integration_tests {
    use super::*;
    use hyper_mm::VmId;

    fn graph() -> VirtualDeviceGraph {
        VirtualDeviceGraph::new(VmId::new("vm-virtio-0"))
    }

    #[test]
    fn console_on_bus_captures_hello() {
        // Direct device handle: guest writes "hello", host receives it (V2).
        let mut console = VirtioConsole::new(DeviceId(1));
        for &b in b"hello" {
            console
                .mmio_write(CONSOLE_REG_DATA, Width::Byte, b as u64)
                .unwrap();
        }
        assert_eq!(console.output_str(), "hello");

        // And via the deny-by-default bus dispatch path.
        let mut g = graph();
        let base = 0xfeb0_0000u64;
        g.register(
            Box::new(VirtioConsole::new(DeviceId(2))),
            Some((base, CONSOLE_MMIO_LEN)),
            None,
            None,
        )
        .unwrap();
        for &b in b"hi" {
            g.dispatch_mmio_write(base + CONSOLE_REG_DATA, Width::Byte, b as u64)
                .unwrap();
        }
        assert_eq!(
            g.dispatch_mmio_read(base + REG_PENDING, Width::Dword).unwrap(),
            2
        );
    }

    #[test]
    fn blk_read_verifies_and_detects_tamper() {
        let data = b"the-quick-brown!".to_vec(); // 16 bytes, two 8-byte sectors
        let backend = InMemoryBlockBackend::new(data.clone(), 8);
        let hashes = vec![sha384_hex(&data[0..8]), sha384_hex(&data[8..16])];
        let blk = VirtioBlk::new_per_sector(DeviceId(1), backend, hashes.clone());
        assert_eq!(blk.read_sector(0).unwrap(), b"the-quic");

        // Tamper one byte -> read fails closed.
        let mut tampered = InMemoryBlockBackend::new(data, 8);
        *tampered.byte_mut(2).unwrap() ^= 0xff;
        let blk2 = VirtioBlk::new_per_sector(DeviceId(2), tampered, hashes);
        assert!(matches!(
            blk2.read_sector(0),
            Err(VirtioError::IntegrityFailure { .. })
        ));
    }

    #[test]
    fn rng_is_deterministic_for_same_seed() {
        let mut a = VirtioRng::new(DeviceId(1), 0xc0ffee);
        let mut b = VirtioRng::new(DeviceId(2), 0xc0ffee);
        assert_eq!(a.bytes(256), b.bytes(256));
    }

    #[test]
    fn sha384_hex_format_matches_convention() {
        let h = sha384_hex(b"abc");
        assert!(h.starts_with("sha384:"));
        assert_eq!(h.len(), "sha384:".len() + 96);
    }
}
