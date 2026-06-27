//! `VirtioBlk` — a read-only virtio-block model with integrity verification.
//!
//! A [`VirtioBlk`] wraps a [`BlockBackend`] and an *expected* SHA-384 digest
//! (formatted `"sha384:<hex>"`). Every sector read re-hashes the bytes returned
//! by the backend and compares them against the expectation: a single flipped
//! byte makes the read fail closed. This backs acceptance **V3** (tamper-evident
//! read-only disk). The device is read-only by construction — there is no write
//! path.
//!
//! Integrity may be expressed two ways:
//!   * [`BlkIntegrity::PerSector`] — one digest per sector (cheap per-sector
//!     verification), or
//!   * [`BlkIntegrity::Image`] — one digest over the whole concatenated image
//!     (any sector read first verifies the full image).

use hyper_devices::{DevError, DeviceAction, DeviceId, VirtualDevice, Width};

use crate::error::VirtioError;
use crate::hash::sha384_hex;

/// Backing store for a [`VirtioBlk`] device.
pub trait BlockBackend {
    /// Number of sectors in the backing store.
    fn sectors(&self) -> u64;

    /// Return the raw bytes of sector `idx`, or a [`DevError`] if `idx` is out
    /// of range.
    fn read_sector(&self, idx: u64) -> Result<Vec<u8>, DevError>;
}

/// A simple in-memory [`BlockBackend`] holding a contiguous image split into
/// fixed-size sectors.
#[derive(Debug, Clone)]
pub struct InMemoryBlockBackend {
    /// The raw image bytes (length must be a multiple of `sector_size`).
    pub data: Vec<u8>,
    /// Size of each sector in bytes.
    pub sector_size: u64,
}

impl InMemoryBlockBackend {
    /// Build a backend from `data`, padding the final partial sector with
    /// zeros so the image is a whole number of `sector_size` sectors.
    pub fn new(mut data: Vec<u8>, sector_size: u64) -> Self {
        assert!(sector_size > 0, "sector_size must be non-zero");
        let rem = data.len() as u64 % sector_size;
        if rem != 0 {
            data.resize(data.len() + (sector_size - rem) as usize, 0);
        }
        InMemoryBlockBackend { data, sector_size }
    }

    /// Mutable access to the byte at absolute image `offset` (test/tamper aid).
    pub fn byte_mut(&mut self, offset: usize) -> Option<&mut u8> {
        self.data.get_mut(offset)
    }
}

impl BlockBackend for InMemoryBlockBackend {
    fn sectors(&self) -> u64 {
        self.data.len() as u64 / self.sector_size
    }

    fn read_sector(&self, idx: u64) -> Result<Vec<u8>, DevError> {
        let start = idx
            .checked_mul(self.sector_size)
            .ok_or(DevError::OffsetOutOfRange { offset: idx })?;
        let end = start
            .checked_add(self.sector_size)
            .ok_or(DevError::OffsetOutOfRange { offset: idx })?;
        if end > self.data.len() as u64 {
            return Err(DevError::OffsetOutOfRange { offset: idx });
        }
        Ok(self.data[start as usize..end as usize].to_vec())
    }
}

/// How a [`VirtioBlk`] expresses its expected content digest(s).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlkIntegrity {
    /// One `"sha384:<hex>"` digest per sector, indexed by sector number.
    PerSector(Vec<String>),
    /// One `"sha384:<hex>"` digest over the entire concatenated image.
    Image(String),
}

/// MMIO command codes written to [`REG_COMMAND`].
pub const CMD_LOAD: u64 = 1;

/// Device-local MMIO offsets.
/// Read: capacity in sectors (u64).
pub const REG_CAPACITY: u64 = 0x00;
/// Read: sector size in bytes (u64).
pub const REG_SECTOR_SIZE: u64 = 0x08;
/// Write: select the sector to operate on.
pub const REG_SECTOR_SEL: u64 = 0x10;
/// Write: issue a command (see `CMD_*`).
pub const REG_COMMAND: u64 = 0x18;
/// Read: status of the last command (0 = ok, non-zero = error code).
pub const REG_STATUS: u64 = 0x20;
/// Read: next byte of the loaded sector buffer (auto-increments).
pub const REG_DATA: u64 = 0x28;
/// Total MMIO window length.
pub const MMIO_LEN: u64 = 0x30;

/// Status codes reported via [`REG_STATUS`].
pub const STATUS_OK: u64 = 0;
/// The selected sector index was out of range.
pub const STATUS_OUT_OF_RANGE: u64 = 1;
/// The backend bytes failed the integrity check.
pub const STATUS_INTEGRITY: u64 = 2;

/// A read-only virtio-block device with content integrity verification.
#[derive(Debug, Clone)]
pub struct VirtioBlk<B: BlockBackend> {
    id: DeviceId,
    backend: B,
    integrity: BlkIntegrity,
    // MMIO state.
    selected: u64,
    status: u64,
    buffer: Vec<u8>,
    cursor: usize,
}

impl<B: BlockBackend> VirtioBlk<B> {
    /// Create a read-only device verifying each sector against `hashes[idx]`.
    pub fn new_per_sector(id: DeviceId, backend: B, hashes: Vec<String>) -> Self {
        Self::with_integrity(id, backend, BlkIntegrity::PerSector(hashes))
    }

    /// Create a read-only device verifying the whole image against
    /// `image_hash`.
    pub fn new_image(id: DeviceId, backend: B, image_hash: impl Into<String>) -> Self {
        Self::with_integrity(id, backend, BlkIntegrity::Image(image_hash.into()))
    }

    /// Create a device with an explicit [`BlkIntegrity`] policy.
    pub fn with_integrity(id: DeviceId, backend: B, integrity: BlkIntegrity) -> Self {
        VirtioBlk {
            id,
            backend,
            integrity,
            selected: 0,
            status: STATUS_OK,
            buffer: Vec::new(),
            cursor: 0,
        }
    }

    /// Number of sectors exposed by the backend.
    pub fn capacity_sectors(&self) -> u64 {
        self.backend.sectors()
    }

    /// Sector size in bytes (0 for an empty backend).
    pub fn sector_size(&self) -> u64 {
        if self.backend.sectors() == 0 {
            0
        } else {
            // All sectors are the same size; sample sector 0.
            self.backend
                .read_sector(0)
                .map(|s| s.len() as u64)
                .unwrap_or(0)
        }
    }

    /// Borrow the backend (e.g. to read raw bytes in tests).
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Mutable backend access (e.g. to tamper with bytes in tests).
    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    /// Helper: compute the digest of the whole concatenated image.
    fn image_digest(&self) -> Result<String, VirtioError> {
        let n = self.backend.sectors();
        let mut all = Vec::new();
        for i in 0..n {
            all.extend_from_slice(&self.backend.read_sector(i)?);
        }
        Ok(sha384_hex(&all))
    }

    /// Verify the entire image / all sectors against the expected digest(s).
    pub fn verify(&self) -> Result<(), VirtioError> {
        match &self.integrity {
            BlkIntegrity::Image(expected) => {
                let actual = self.image_digest()?;
                if &actual != expected {
                    return Err(VirtioError::IntegrityFailure {
                        what: "image".to_string(),
                        expected: expected.clone(),
                        actual,
                    });
                }
                Ok(())
            }
            BlkIntegrity::PerSector(hashes) => {
                let n = self.backend.sectors();
                if hashes.len() as u64 != n {
                    return Err(VirtioError::IntegrityConfig {
                        expected_sectors: n,
                        provided: hashes.len(),
                    });
                }
                for i in 0..n {
                    self.read_sector(i)?;
                }
                Ok(())
            }
        }
    }

    /// Read sector `idx`, verifying its bytes against the expected digest.
    ///
    /// Returns [`VirtioError::IntegrityFailure`] if the backend bytes do not
    /// match (a single flipped byte triggers this), or
    /// [`VirtioError::SectorOutOfRange`] for an invalid index.
    pub fn read_sector(&self, idx: u64) -> Result<Vec<u8>, VirtioError> {
        let capacity = self.backend.sectors();
        if idx >= capacity {
            return Err(VirtioError::SectorOutOfRange {
                index: idx,
                capacity,
            });
        }
        let bytes = self.backend.read_sector(idx)?;
        match &self.integrity {
            BlkIntegrity::PerSector(hashes) => {
                let expected =
                    hashes
                        .get(idx as usize)
                        .ok_or(VirtioError::IntegrityConfig {
                            expected_sectors: capacity,
                            provided: hashes.len(),
                        })?;
                let actual = sha384_hex(&bytes);
                if &actual != expected {
                    return Err(VirtioError::IntegrityFailure {
                        what: format!("sector {idx}"),
                        expected: expected.clone(),
                        actual,
                    });
                }
            }
            BlkIntegrity::Image(expected) => {
                let actual = self.image_digest()?;
                if &actual != expected {
                    return Err(VirtioError::IntegrityFailure {
                        what: "image".to_string(),
                        expected: expected.clone(),
                        actual,
                    });
                }
            }
        }
        Ok(bytes)
    }
}

impl<B: BlockBackend> VirtualDevice for VirtioBlk<B> {
    fn device_id(&self) -> DeviceId {
        self.id
    }

    fn mmio_read(&mut self, offset: u64, width: Width) -> Result<u64, DevError> {
        match offset {
            REG_CAPACITY => Ok(self.capacity_sectors() & width.mask()),
            REG_SECTOR_SIZE => Ok(self.sector_size() & width.mask()),
            REG_STATUS => Ok(self.status & width.mask()),
            REG_DATA => {
                // Fail closed: only readable after a successful CMD_LOAD.
                if self.status != STATUS_OK {
                    return Err(DevError::OffsetOutOfRange { offset });
                }
                match self.buffer.get(self.cursor) {
                    Some(&b) => {
                        self.cursor += 1;
                        Ok(b as u64 & width.mask())
                    }
                    None => Err(DevError::OffsetOutOfRange { offset }),
                }
            }
            other => Err(DevError::OffsetOutOfRange { offset: other }),
        }
    }

    fn mmio_write(&mut self, offset: u64, _width: Width, value: u64) -> Result<(), DevError> {
        match offset {
            REG_SECTOR_SEL => {
                self.selected = value;
                Ok(())
            }
            REG_COMMAND => {
                if value == CMD_LOAD {
                    match self.read_sector(self.selected) {
                        Ok(bytes) => {
                            self.buffer = bytes;
                            self.cursor = 0;
                            self.status = STATUS_OK;
                        }
                        Err(VirtioError::SectorOutOfRange { .. }) => {
                            self.buffer.clear();
                            self.cursor = 0;
                            self.status = STATUS_OUT_OF_RANGE;
                        }
                        Err(_) => {
                            self.buffer.clear();
                            self.cursor = 0;
                            self.status = STATUS_INTEGRITY;
                        }
                    }
                    Ok(())
                } else {
                    Err(DevError::OffsetOutOfRange { offset })
                }
            }
            // Capacity / sector-size / status / data are read-only; the device
            // itself is read-only, so any other write fails closed.
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
        self.selected = 0;
        self.status = STATUS_OK;
        self.buffer.clear();
        self.cursor = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image() -> (InMemoryBlockBackend, Vec<String>, String) {
        // Two 8-byte sectors.
        let data = b"SECTOR00SECTOR11".to_vec();
        let backend = InMemoryBlockBackend::new(data.clone(), 8);
        let per_sector = vec![
            sha384_hex(&data[0..8]),
            sha384_hex(&data[8..16]),
        ];
        let image_hash = sha384_hex(&data);
        (backend, per_sector, image_hash)
    }

    #[test]
    fn reads_sector_zero_and_verifies() {
        let (backend, hashes, _) = image();
        let blk = VirtioBlk::new_per_sector(DeviceId(1), backend, hashes);
        assert_eq!(blk.capacity_sectors(), 2);
        assert_eq!(blk.sector_size(), 8);
        assert_eq!(blk.read_sector(0).unwrap(), b"SECTOR00");
        assert_eq!(blk.read_sector(1).unwrap(), b"SECTOR11");
        blk.verify().unwrap();
    }

    #[test]
    fn tampered_byte_fails_read() {
        let (mut backend, hashes, _) = image();
        // Flip one byte in sector 0.
        *backend.byte_mut(3).unwrap() ^= 0xff;
        let blk = VirtioBlk::new_per_sector(DeviceId(2), backend, hashes);
        let err = blk.read_sector(0).unwrap_err();
        assert!(matches!(err, VirtioError::IntegrityFailure { .. }));
        // Sector 1 is still fine.
        assert_eq!(blk.read_sector(1).unwrap(), b"SECTOR11");
        // Whole-image verify also fails.
        assert!(blk.verify().is_err());
    }

    #[test]
    fn image_mode_verifies_and_detects_tamper() {
        let (backend, _, image_hash) = image();
        let blk = VirtioBlk::new_image(DeviceId(3), backend, image_hash.clone());
        assert_eq!(blk.read_sector(0).unwrap(), b"SECTOR00");
        blk.verify().unwrap();

        let (mut tampered, _, _) = image();
        *tampered.byte_mut(10).unwrap() ^= 0x01;
        let blk2 = VirtioBlk::new_image(DeviceId(4), tampered, image_hash);
        assert!(blk2.read_sector(0).unwrap_err().to_string().contains("integrity"));
    }

    #[test]
    fn out_of_range_sector_fails() {
        let (backend, hashes, _) = image();
        let blk = VirtioBlk::new_per_sector(DeviceId(5), backend, hashes);
        let err = blk.read_sector(99).unwrap_err();
        assert_eq!(
            err,
            VirtioError::SectorOutOfRange {
                index: 99,
                capacity: 2
            }
        );
    }

    #[test]
    fn mmio_load_and_stream() {
        let (backend, hashes, _) = image();
        let mut blk = VirtioBlk::new_per_sector(DeviceId(6), backend, hashes);
        assert_eq!(blk.mmio_read(REG_CAPACITY, Width::Qword).unwrap(), 2);
        assert_eq!(blk.mmio_read(REG_SECTOR_SIZE, Width::Qword).unwrap(), 8);

        // Select sector 1 and load it.
        blk.mmio_write(REG_SECTOR_SEL, Width::Qword, 1).unwrap();
        blk.mmio_write(REG_COMMAND, Width::Dword, CMD_LOAD).unwrap();
        assert_eq!(blk.mmio_read(REG_STATUS, Width::Dword).unwrap(), STATUS_OK);

        let mut got = Vec::new();
        for _ in 0..8 {
            got.push(blk.mmio_read(REG_DATA, Width::Byte).unwrap() as u8);
        }
        assert_eq!(got, b"SECTOR11");
        // Past the end fails closed.
        assert!(blk.mmio_read(REG_DATA, Width::Byte).is_err());
    }

    #[test]
    fn mmio_load_tampered_sets_status_and_denies_data() {
        let (mut backend, hashes, _) = image();
        *backend.byte_mut(0).unwrap() ^= 0xaa;
        let mut blk = VirtioBlk::new_per_sector(DeviceId(7), backend, hashes);
        blk.mmio_write(REG_SECTOR_SEL, Width::Qword, 0).unwrap();
        blk.mmio_write(REG_COMMAND, Width::Dword, CMD_LOAD).unwrap();
        assert_eq!(
            blk.mmio_read(REG_STATUS, Width::Dword).unwrap(),
            STATUS_INTEGRITY
        );
        // No data may be streamed after an integrity failure.
        assert!(blk.mmio_read(REG_DATA, Width::Byte).is_err());
    }

    #[test]
    fn mmio_out_of_range_load_sets_status() {
        let (backend, hashes, _) = image();
        let mut blk = VirtioBlk::new_per_sector(DeviceId(8), backend, hashes);
        blk.mmio_write(REG_SECTOR_SEL, Width::Qword, 42).unwrap();
        blk.mmio_write(REG_COMMAND, Width::Dword, CMD_LOAD).unwrap();
        assert_eq!(
            blk.mmio_read(REG_STATUS, Width::Dword).unwrap(),
            STATUS_OUT_OF_RANGE
        );
    }

    #[test]
    fn writes_other_than_command_are_denied() {
        let (backend, hashes, _) = image();
        let mut blk = VirtioBlk::new_per_sector(DeviceId(9), backend, hashes);
        assert!(blk.mmio_write(REG_CAPACITY, Width::Qword, 5).is_err());
        assert!(blk.mmio_write(REG_DATA, Width::Byte, 1).is_err());
        // Unknown command is denied.
        assert!(blk.mmio_write(REG_COMMAND, Width::Dword, 99).is_err());
    }

    #[test]
    fn reset_clears_state() {
        let (backend, hashes, _) = image();
        let mut blk = VirtioBlk::new_per_sector(DeviceId(10), backend, hashes);
        blk.mmio_write(REG_SECTOR_SEL, Width::Qword, 1).unwrap();
        blk.mmio_write(REG_COMMAND, Width::Dword, CMD_LOAD).unwrap();
        blk.reset();
        assert_eq!(blk.mmio_read(REG_STATUS, Width::Dword).unwrap(), STATUS_OK);
        assert!(blk.mmio_read(REG_DATA, Width::Byte).is_err());
        assert_eq!(blk.tick(), DeviceAction::None);
    }

    #[test]
    fn per_sector_hash_count_mismatch_is_config_error() {
        let (backend, _, _) = image();
        let blk = VirtioBlk::new_per_sector(DeviceId(11), backend, vec!["sha384:x".to_string()]);
        assert!(matches!(
            blk.verify(),
            Err(VirtioError::IntegrityConfig { .. })
        ));
    }
}
