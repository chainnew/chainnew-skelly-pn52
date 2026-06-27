//! `VirtioRng` — a *deterministic* virtio-rng model.
//!
//! There is no real entropy here (this is the host-testable V0 layer and the
//! build forbids randomness / clocks). Bytes are produced by a counter-based
//! hash DRBG: block `n` is `SHA-384(seed_le || n_le)`, yielded byte-by-byte and
//! refilled as it drains. The same seed always produces the same stream, which
//! is exactly what the determinism test requires.

use hyper_devices::{DevError, DeviceAction, DeviceId, VirtualDevice, Width};

use crate::hash::sha384;

/// Device-local MMIO offset of the data register (read yields random bytes).
pub const REG_DATA: u64 = 0x00;
/// Device-local MMIO offset of the seed-low register (write reseeds + resets).
pub const REG_SEED: u64 = 0x08;
/// Total MMIO window length.
pub const MMIO_LEN: u64 = 0x10;

/// Size of one DRBG output block (SHA-384 digest length).
const BLOCK_LEN: usize = 48;

/// A deterministic counter/hash-based RNG device.
#[derive(Debug, Clone)]
pub struct VirtioRng {
    id: DeviceId,
    seed: u64,
    counter: u64,
    block: [u8; BLOCK_LEN],
    pos: usize,
}

impl VirtioRng {
    /// Create an RNG seeded with `seed`. The stream is fully determined by the
    /// seed (no randomness, no clock).
    pub fn new(id: DeviceId, seed: u64) -> Self {
        let mut r = VirtioRng {
            id,
            seed,
            counter: 0,
            block: [0; BLOCK_LEN],
            pos: BLOCK_LEN, // force a refill on first byte
        };
        r.refill();
        r
    }

    /// Reseed the generator and rewind the stream to the start.
    pub fn reseed(&mut self, seed: u64) {
        self.seed = seed;
        self.counter = 0;
        self.pos = BLOCK_LEN;
        self.refill();
    }

    fn refill(&mut self) {
        let mut input = [0u8; 16];
        input[0..8].copy_from_slice(&self.seed.to_le_bytes());
        input[8..16].copy_from_slice(&self.counter.to_le_bytes());
        self.block = sha384(&input);
        self.counter = self.counter.wrapping_add(1);
        self.pos = 0;
    }

    /// Produce the next deterministic byte.
    pub fn next_byte(&mut self) -> u8 {
        if self.pos >= BLOCK_LEN {
            self.refill();
        }
        let b = self.block[self.pos];
        self.pos += 1;
        b
    }

    /// Fill `buf` with deterministic bytes from the stream.
    pub fn fill(&mut self, buf: &mut [u8]) {
        for slot in buf.iter_mut() {
            *slot = self.next_byte();
        }
    }

    /// Produce `n` deterministic bytes as a new vector.
    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut v = vec![0u8; n];
        self.fill(&mut v);
        v
    }
}

impl VirtualDevice for VirtioRng {
    fn device_id(&self) -> DeviceId {
        self.id
    }

    fn mmio_read(&mut self, offset: u64, width: Width) -> Result<u64, DevError> {
        match offset {
            REG_DATA => {
                // Assemble `width` bytes little-endian from the stream.
                let mut val: u64 = 0;
                for i in 0..width.bytes() {
                    val |= (self.next_byte() as u64) << (i * 8);
                }
                Ok(val & width.mask())
            }
            other => Err(DevError::OffsetOutOfRange { offset: other }),
        }
    }

    fn mmio_write(&mut self, offset: u64, width: Width, value: u64) -> Result<(), DevError> {
        match offset {
            REG_SEED => {
                if value & !width.mask() != 0 {
                    return Err(DevError::ValueTooWide { value, width });
                }
                self.reseed(value);
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
        // Rewind to the start of the current seed's stream.
        self.counter = 0;
        self.pos = BLOCK_LEN;
        self.refill();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_same_seed() {
        let mut a = VirtioRng::new(DeviceId(1), 0x1234_5678);
        let mut b = VirtioRng::new(DeviceId(2), 0x1234_5678);
        assert_eq!(a.bytes(100), b.bytes(100));
    }

    #[test]
    fn different_seed_differs() {
        let mut a = VirtioRng::new(DeviceId(1), 1);
        let mut b = VirtioRng::new(DeviceId(2), 2);
        assert_ne!(a.bytes(64), b.bytes(64));
    }

    #[test]
    fn crosses_block_boundary() {
        // 48-byte blocks; ask for more to force a refill and ensure continuity.
        let mut a = VirtioRng::new(DeviceId(1), 7);
        let first = a.bytes(200);
        let mut b = VirtioRng::new(DeviceId(2), 7);
        // Reading in two halves must equal reading all at once.
        let mut half = b.bytes(120);
        half.extend(b.bytes(80));
        assert_eq!(first, half);
    }

    #[test]
    fn reset_rewinds_stream() {
        let mut a = VirtioRng::new(DeviceId(1), 99);
        let s1 = a.bytes(50);
        a.reset();
        let s2 = a.bytes(50);
        assert_eq!(s1, s2);
    }

    #[test]
    fn mmio_read_matches_byte_stream() {
        let mut a = VirtioRng::new(DeviceId(1), 0xabcd);
        let mut b = VirtioRng::new(DeviceId(2), 0xabcd);
        // One qword read == eight bytes assembled little-endian.
        let word = a.mmio_read(REG_DATA, Width::Qword).unwrap();
        let mut expected = 0u64;
        for i in 0..8 {
            expected |= (b.next_byte() as u64) << (i * 8);
        }
        assert_eq!(word, expected);
    }

    #[test]
    fn mmio_reseed_changes_stream() {
        let mut a = VirtioRng::new(DeviceId(1), 1);
        let before = a.bytes(16);
        a.mmio_write(REG_SEED, Width::Qword, 1).unwrap();
        let after = a.bytes(16);
        // Reseeding to the same value rewinds to the same stream.
        assert_eq!(before, after);
        a.mmio_write(REG_SEED, Width::Qword, 2).unwrap();
        assert_ne!(a.bytes(16), before);
    }

    #[test]
    fn unknown_offset_denied() {
        let mut a = VirtioRng::new(DeviceId(1), 1);
        assert!(a.mmio_read(0x40, Width::Byte).is_err());
        assert!(a.mmio_write(0x40, Width::Byte, 0).is_err());
        assert!(a.io_read(0, Width::Byte).is_err());
        assert_eq!(a.tick(), DeviceAction::None);
    }
}
