//! hyper-mm — guest memory model + NPT orchestration (slate-runtime V0).
//!
//! Host-testable layer. Provides a deny-by-default Nested Page Table (NPT)
//! abstraction together with the SOW S2 memory invariants:
//!   * no writable+executable pages,
//!   * no mappings overlapping the reserved host/hypervisor range,
//!   * every host page must be zeroed before it is assigned to a guest.
//!
//! This crate deliberately does NOT depend on the x86/svm crates; it models
//! the NPT in memory so the invariants can be exercised from host unit tests.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Page size used for zeroization / assignment bookkeeping (4 KiB).
pub const PAGE_SIZE: u64 = 4096;

/// Schema version for JSON-mapped structures in this crate.
pub const SCHEMA_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Newtypes
// ---------------------------------------------------------------------------

/// Guest physical address.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct GuestPhysAddr(pub u64);

/// Host physical address.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct HostPhysAddr(pub u64);

/// Opaque, stable identifier for a virtual machine.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct VmId(pub String);

impl VmId {
    /// Construct a `VmId` from anything string-like.
    pub fn new(id: impl Into<String>) -> Self {
        VmId(id.into())
    }

    /// Borrow the inner string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Permissions
// ---------------------------------------------------------------------------

/// Read / write / execute permission bits for a mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Perms {
    pub r: bool,
    pub w: bool,
    pub x: bool,
}

impl Perms {
    /// Read-only.
    pub const RO: Perms = Perms {
        r: true,
        w: false,
        x: false,
    };
    /// Read-write (no execute).
    pub const RW: Perms = Perms {
        r: true,
        w: true,
        x: false,
    };
    /// Read-execute (no write).
    pub const RX: Perms = Perms {
        r: true,
        w: false,
        x: true,
    };

    /// True if both writable and executable (forbidden under W^X).
    pub fn is_write_execute(&self) -> bool {
        self.w && self.x
    }
}

// ---------------------------------------------------------------------------
// Regions
// ---------------------------------------------------------------------------

/// Classification of a guest memory region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegionKind {
    GuestRam,
    GuestRom,
    MmioTrap,
    SharedVirtioRing,
    GuardPage,
}

/// A contiguous region of the guest physical address space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct GuestMemoryRegion {
    pub gpa_start: GuestPhysAddr,
    pub len: u64,
    pub kind: RegionKind,
    pub perms: Perms,
}

impl GuestMemoryRegion {
    /// Exclusive end of the region.
    pub fn gpa_end(&self) -> u64 {
        self.gpa_start.0.saturating_add(self.len)
    }
}

// ---------------------------------------------------------------------------
// Physical ranges
// ---------------------------------------------------------------------------

/// A guest-physical `[start, start+len)` range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct GuestPhysRange {
    pub start: GuestPhysAddr,
    pub len: u64,
}

/// A host-physical `[start, start+len)` range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct HostPhysRange {
    pub start: HostPhysAddr,
    pub len: u64,
}

impl HostPhysRange {
    fn end(&self) -> u64 {
        self.start.0.saturating_add(self.len)
    }

    /// True if this range overlaps `other` (half-open intervals).
    pub fn overlaps(&self, other: &HostPhysRange) -> bool {
        self.start.0 < other.end() && other.start.0 < self.end()
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors produced by the memory-management layer. All public fns fail closed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum MmError {
    #[error("zero-length mapping is not allowed")]
    ZeroLength,

    #[error("writable+executable mapping rejected (W^X violation)")]
    WriteExecuteForbidden,

    #[error("mapping host range overlaps the reserved host/hypervisor range")]
    OverlapsReservedHostRange,

    #[error("target host page(s) not zeroed before assignment")]
    PageNotZeroed,

    #[error("host page is poisoned and cannot be assigned until re-zeroed")]
    PagePoisoned,

    #[error("unknown mapping id {0}")]
    UnknownMapping(u64),

    #[error("memory quota exceeded: requested {requested_mb} MB, {available_mb} MB available")]
    QuotaExceeded { requested_mb: u64, available_mb: u64 },
}

// ---------------------------------------------------------------------------
// Npt trait + InMemoryNpt
// ---------------------------------------------------------------------------

/// Nested page table abstraction. Deny-by-default: `translate` returns `None`
/// for any address that has not been explicitly mapped.
pub trait Npt {
    /// Install a mapping `[gpa, gpa+len) -> [hpa, hpa+len)` with `perms`.
    /// Returns a stable, deterministic mapping id.
    fn map(
        &mut self,
        gpa: GuestPhysAddr,
        hpa: HostPhysAddr,
        len: u64,
        perms: Perms,
    ) -> Result<u64, MmError>;

    /// Remove a previously installed mapping.
    fn unmap(&mut self, mapping_id: u64) -> Result<(), MmError>;

    /// Translate a guest physical address, or `None` if unmapped.
    fn translate(&self, gpa: GuestPhysAddr) -> Option<HostPhysAddr>;
}

/// A single recorded mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NptMapping {
    pub id: u64,
    pub gpa: GuestPhysAddr,
    pub hpa: HostPhysAddr,
    pub len: u64,
    pub perms: Perms,
}

/// In-memory `Npt` implementation that records every mapping. Mapping ids are
/// derived from a monotonic counter so they are fully deterministic.
#[derive(Debug, Default)]
pub struct InMemoryNpt {
    next_id: u64,
    mappings: BTreeMap<u64, NptMapping>,
}

impl InMemoryNpt {
    pub fn new() -> Self {
        Self::default()
    }

    /// All currently installed mappings, ordered by id.
    pub fn mappings(&self) -> impl Iterator<Item = &NptMapping> {
        self.mappings.values()
    }

    /// Number of installed mappings.
    pub fn len(&self) -> usize {
        self.mappings.len()
    }

    /// True if no mappings are installed.
    pub fn is_empty(&self) -> bool {
        self.mappings.is_empty()
    }
}

impl Npt for InMemoryNpt {
    fn map(
        &mut self,
        gpa: GuestPhysAddr,
        hpa: HostPhysAddr,
        len: u64,
        perms: Perms,
    ) -> Result<u64, MmError> {
        if len == 0 {
            return Err(MmError::ZeroLength);
        }
        let id = self.next_id;
        self.next_id += 1;
        self.mappings.insert(
            id,
            NptMapping {
                id,
                gpa,
                hpa,
                len,
                perms,
            },
        );
        Ok(id)
    }

    fn unmap(&mut self, mapping_id: u64) -> Result<(), MmError> {
        self.mappings
            .remove(&mapping_id)
            .map(|_| ())
            .ok_or(MmError::UnknownMapping(mapping_id))
    }

    fn translate(&self, gpa: GuestPhysAddr) -> Option<HostPhysAddr> {
        for m in self.mappings.values() {
            let start = m.gpa.0;
            let end = start.saturating_add(m.len);
            if gpa.0 >= start && gpa.0 < end {
                let offset = gpa.0 - start;
                return Some(HostPhysAddr(m.hpa.0.saturating_add(offset)));
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// PageZeroizer
// ---------------------------------------------------------------------------

/// State of a host page frame in the zeroization lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageState {
    /// Zeroed and eligible for assignment.
    Zeroed,
    /// Currently assigned to a guest.
    Assigned,
    /// Freed and poisoned; must be re-zeroed before reuse.
    Poisoned,
}

/// Tracks the zeroization state of host page frames. Pages must be explicitly
/// marked zeroed before they can be assigned; freeing a page poisons it.
#[derive(Debug, Default)]
pub struct PageZeroizer {
    frames: BTreeMap<u64, PageState>,
}

impl PageZeroizer {
    pub fn new() -> Self {
        Self::default()
    }

    fn frame_range(start: u64, len: u64) -> (u64, u64) {
        let first = start / PAGE_SIZE;
        // inclusive last frame touched by [start, start+len)
        let last = start.saturating_add(len - 1) / PAGE_SIZE;
        (first, last)
    }

    /// Mark every page frame covering `[hpa, hpa+len)` as zeroed.
    pub fn mark_zeroed(&mut self, hpa: HostPhysAddr, len: u64) {
        if len == 0 {
            return;
        }
        let (first, last) = Self::frame_range(hpa.0, len);
        for f in first..=last {
            self.frames.insert(f, PageState::Zeroed);
        }
    }

    /// Query the state of the frame containing `hpa`.
    pub fn state(&self, hpa: HostPhysAddr) -> Option<PageState> {
        self.frames.get(&(hpa.0 / PAGE_SIZE)).copied()
    }

    /// True iff every frame covering `[hpa, hpa+len)` is currently `Zeroed`.
    pub fn is_zeroed(&self, hpa: HostPhysAddr, len: u64) -> bool {
        if len == 0 {
            return false;
        }
        let (first, last) = Self::frame_range(hpa.0, len);
        (first..=last).all(|f| matches!(self.frames.get(&f), Some(PageState::Zeroed)))
    }

    /// Validate-and-consume: requires the frames to be zeroed, then transitions
    /// them to `Assigned`. Fails closed if any frame is not zeroed.
    pub fn assign(&mut self, hpa: HostPhysAddr, len: u64) -> Result<(), MmError> {
        if len == 0 {
            return Err(MmError::ZeroLength);
        }
        let (first, last) = Self::frame_range(hpa.0, len);
        for f in first..=last {
            match self.frames.get(&f) {
                Some(PageState::Zeroed) => {}
                Some(PageState::Poisoned) => return Err(MmError::PagePoisoned),
                _ => return Err(MmError::PageNotZeroed),
            }
        }
        for f in first..=last {
            self.frames.insert(f, PageState::Assigned);
        }
        Ok(())
    }

    /// Poison every frame covering `[hpa, hpa+len)` (called on free).
    pub fn poison(&mut self, hpa: HostPhysAddr, len: u64) {
        if len == 0 {
            return;
        }
        let (first, last) = Self::frame_range(hpa.0, len);
        for f in first..=last {
            self.frames.insert(f, PageState::Poisoned);
        }
    }
}

// ---------------------------------------------------------------------------
// MemoryQuotaManager
// ---------------------------------------------------------------------------

/// Tracks committed memory against a hard cap, in megabytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MemoryQuotaManager {
    pub max_mb: u64,
    pub used_mb: u64,
}

impl MemoryQuotaManager {
    pub fn new(max_mb: u64) -> Self {
        MemoryQuotaManager { max_mb, used_mb: 0 }
    }

    /// Megabytes still available.
    pub fn available_mb(&self) -> u64 {
        self.max_mb.saturating_sub(self.used_mb)
    }

    /// Reserve `mb` megabytes. Fails closed if it would exceed the cap.
    pub fn try_reserve(&mut self, mb: u64) -> Result<(), MmError> {
        let available = self.available_mb();
        if mb > available {
            return Err(MmError::QuotaExceeded {
                requested_mb: mb,
                available_mb: available,
            });
        }
        self.used_mb += mb;
        Ok(())
    }

    /// Release `mb` previously reserved megabytes.
    pub fn release(&mut self, mb: u64) {
        self.used_mb = self.used_mb.saturating_sub(mb);
    }
}

// ---------------------------------------------------------------------------
// MmioTrapRegistry
// ---------------------------------------------------------------------------

/// A registered MMIO trap range within the guest physical space.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MmioTrapRange {
    pub range: GuestPhysRange,
    pub device: String,
}

/// Registry of MMIO trap ranges. Lookups are by containment.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MmioTrapRegistry {
    traps: Vec<MmioTrapRange>,
}

impl MmioTrapRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a trap range for `device`.
    pub fn register(&mut self, range: GuestPhysRange, device: impl Into<String>) {
        self.traps.push(MmioTrapRange {
            range,
            device: device.into(),
        });
    }

    /// Find the trap covering `gpa`, if any.
    pub fn lookup(&self, gpa: GuestPhysAddr) -> Option<&MmioTrapRange> {
        self.traps.iter().find(|t| {
            let start = t.range.start.0;
            let end = start.saturating_add(t.range.len);
            gpa.0 >= start && gpa.0 < end
        })
    }

    /// All registered traps.
    pub fn traps(&self) -> &[MmioTrapRange] {
        &self.traps
    }
}

// ---------------------------------------------------------------------------
// AllocationRecord
// ---------------------------------------------------------------------------

/// Record of a single guest memory allocation produced by
/// [`NestedPageTable::allocate`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AllocationRecord {
    pub guest_physical_range: GuestPhysRange,
    pub host_physical_range: HostPhysRange,
    pub npt_mapping_id: u64,
    pub owner_vm_id: VmId,
    pub zeroed_before_assign: bool,
}

// ---------------------------------------------------------------------------
// NestedPageTable — enforcing wrapper
// ---------------------------------------------------------------------------

/// Enforcing wrapper around any [`Npt`]. On every `map` it enforces the S2
/// memory invariants: rejects W+X, rejects overlap with a configured reserved
/// host/hypervisor range, and requires the target page(s) to be zeroed before
/// assignment.
#[derive(Debug)]
pub struct NestedPageTable<N: Npt> {
    npt: N,
    reserved_host: Option<HostPhysRange>,
    zeroizer: PageZeroizer,
    records: BTreeMap<u64, NptMapping>,
}

impl<N: Npt> NestedPageTable<N> {
    /// Wrap `npt` with no reserved range configured.
    pub fn new(npt: N) -> Self {
        NestedPageTable {
            npt,
            reserved_host: None,
            zeroizer: PageZeroizer::new(),
            records: BTreeMap::new(),
        }
    }

    /// Wrap `npt` and reserve `reserved` host range for the hypervisor; any
    /// mapping overlapping it will be rejected.
    pub fn with_reserved_host_range(npt: N, reserved: HostPhysRange) -> Self {
        let mut t = Self::new(npt);
        t.reserved_host = Some(reserved);
        t
    }

    /// Configure / replace the reserved host range.
    pub fn set_reserved_host_range(&mut self, reserved: HostPhysRange) {
        self.reserved_host = Some(reserved);
    }

    /// Mutable access to the zeroizer (e.g. to mark pages zeroed before map).
    pub fn zeroizer_mut(&mut self) -> &mut PageZeroizer {
        &mut self.zeroizer
    }

    /// Shared access to the zeroizer.
    pub fn zeroizer(&self) -> &PageZeroizer {
        &self.zeroizer
    }

    /// Borrow the underlying NPT.
    pub fn inner(&self) -> &N {
        &self.npt
    }

    /// Invariant: no mapping maps the host/hypervisor reserved range. Because
    /// `map` rejects such mappings, this returns `false` for valid tables.
    pub fn maps_host_hypervisor_text(&self) -> bool {
        match self.reserved_host {
            Some(reserved) => self.records.values().any(|m| {
                let hr = HostPhysRange {
                    start: m.hpa,
                    len: m.len,
                };
                hr.overlaps(&reserved)
            }),
            None => false,
        }
    }

    /// Invariant: no mapping is simultaneously writable and executable. Because
    /// `map` rejects W+X, this returns `false` for valid tables.
    pub fn has_writable_executable_pages(&self) -> bool {
        self.records.values().any(|m| m.perms.is_write_execute())
    }

    fn enforce(&self, hpa: HostPhysAddr, len: u64, perms: Perms) -> Result<(), MmError> {
        if len == 0 {
            return Err(MmError::ZeroLength);
        }
        if perms.is_write_execute() {
            return Err(MmError::WriteExecuteForbidden);
        }
        if let Some(reserved) = self.reserved_host {
            let hr = HostPhysRange { start: hpa, len };
            if hr.overlaps(&reserved) {
                return Err(MmError::OverlapsReservedHostRange);
            }
        }
        Ok(())
    }

    /// Allocate and map a guest region from a zeroed host range, producing an
    /// [`AllocationRecord`]. The host range is zeroed before assignment, so
    /// `zeroed_before_assign` is always `true` on success.
    pub fn allocate(
        &mut self,
        owner: VmId,
        gpa: GuestPhysAddr,
        hpa: HostPhysAddr,
        len: u64,
        perms: Perms,
    ) -> Result<AllocationRecord, MmError> {
        // Validate invariants first (fail closed before touching state).
        self.enforce(hpa, len, perms)?;
        // Allocation zeroes the backing pages prior to assignment.
        self.zeroizer.mark_zeroed(hpa, len);
        let mapping_id = self.map(gpa, hpa, len, perms)?;
        Ok(AllocationRecord {
            guest_physical_range: GuestPhysRange { start: gpa, len },
            host_physical_range: HostPhysRange { start: hpa, len },
            npt_mapping_id: mapping_id,
            owner_vm_id: owner,
            zeroed_before_assign: true,
        })
    }
}

impl<N: Npt> Npt for NestedPageTable<N> {
    fn map(
        &mut self,
        gpa: GuestPhysAddr,
        hpa: HostPhysAddr,
        len: u64,
        perms: Perms,
    ) -> Result<u64, MmError> {
        self.enforce(hpa, len, perms)?;
        // Require the target page(s) to be zeroed, then mark them assigned.
        self.zeroizer.assign(hpa, len)?;
        let id = self.npt.map(gpa, hpa, len, perms)?;
        self.records.insert(
            id,
            NptMapping {
                id,
                gpa,
                hpa,
                len,
                perms,
            },
        );
        Ok(id)
    }

    fn unmap(&mut self, mapping_id: u64) -> Result<(), MmError> {
        self.npt.unmap(mapping_id)?;
        if let Some(m) = self.records.remove(&mapping_id) {
            // Poison freed pages so they cannot be reassigned without re-zero.
            self.zeroizer.poison(m.hpa, m.len);
        }
        Ok(())
    }

    fn translate(&self, gpa: GuestPhysAddr) -> Option<HostPhysAddr> {
        self.npt.translate(gpa)
    }
}

// ---------------------------------------------------------------------------
// GuestMemoryMap
// ---------------------------------------------------------------------------

/// Top-level description of a VM's guest memory layout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct GuestMemoryMap {
    pub schema_version: u32,
    pub vm_id: VmId,
    pub regions: Vec<GuestMemoryRegion>,
    pub npt_root: u64,
    pub mmio_traps: MmioTrapRegistry,
}

impl GuestMemoryMap {
    /// Create an empty memory map for `vm_id` rooted at `npt_root`.
    pub fn new(vm_id: VmId, npt_root: u64) -> Self {
        GuestMemoryMap {
            schema_version: SCHEMA_VERSION,
            vm_id,
            regions: Vec::new(),
            npt_root,
            mmio_traps: MmioTrapRegistry::new(),
        }
    }

    /// Add a region to the map; MMIO regions also register a trap.
    pub fn add_region(&mut self, region: GuestMemoryRegion, device: impl Into<String>) {
        if region.kind == RegionKind::MmioTrap {
            self.mmio_traps.register(
                GuestPhysRange {
                    start: region.gpa_start,
                    len: region.len,
                },
                device,
            );
        }
        self.regions.push(region);
    }

    /// Find the region containing `gpa`, if any.
    pub fn region_at(&self, gpa: GuestPhysAddr) -> Option<&GuestMemoryRegion> {
        self.regions
            .iter()
            .find(|r| gpa.0 >= r.gpa_start.0 && gpa.0 < r.gpa_end())
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const VM: &str = "vm-test-0";

    fn npt() -> NestedPageTable<InMemoryNpt> {
        NestedPageTable::new(InMemoryNpt::new())
    }

    #[test]
    fn perms_consts() {
        assert!(!Perms::RO.is_write_execute());
        assert!(!Perms::RW.is_write_execute());
        assert!(!Perms::RX.is_write_execute());
        let wx = Perms {
            r: true,
            w: true,
            x: true,
        };
        assert!(wx.is_write_execute());
    }

    #[test]
    fn deny_by_default_translate_unmapped_is_none() {
        let table = npt();
        assert_eq!(table.translate(GuestPhysAddr(0x1000)), None);
        let inner = InMemoryNpt::new();
        assert_eq!(inner.translate(GuestPhysAddr(0)), None);
    }

    #[test]
    fn map_then_translate_with_offset() {
        let mut table = npt();
        table.zeroizer_mut().mark_zeroed(HostPhysAddr(0x4000), PAGE_SIZE);
        let id = table
            .map(GuestPhysAddr(0x1000), HostPhysAddr(0x4000), PAGE_SIZE, Perms::RW)
            .unwrap();
        assert_eq!(id, 0);
        assert_eq!(
            table.translate(GuestPhysAddr(0x1000)),
            Some(HostPhysAddr(0x4000))
        );
        assert_eq!(
            table.translate(GuestPhysAddr(0x1010)),
            Some(HostPhysAddr(0x4010))
        );
        assert_eq!(table.translate(GuestPhysAddr(0x2000)), None);
    }

    #[test]
    fn deterministic_mapping_ids() {
        let mut inner = InMemoryNpt::new();
        let a = inner
            .map(GuestPhysAddr(0), HostPhysAddr(0), PAGE_SIZE, Perms::RO)
            .unwrap();
        let b = inner
            .map(GuestPhysAddr(PAGE_SIZE), HostPhysAddr(PAGE_SIZE), PAGE_SIZE, Perms::RO)
            .unwrap();
        assert_eq!((a, b), (0, 1));
        assert_eq!(inner.len(), 2);
        assert!(!inner.is_empty());
    }

    #[test]
    fn wx_map_is_rejected() {
        let mut table = npt();
        table.zeroizer_mut().mark_zeroed(HostPhysAddr(0x4000), PAGE_SIZE);
        let wx = Perms {
            r: true,
            w: true,
            x: true,
        };
        let err = table
            .map(GuestPhysAddr(0x1000), HostPhysAddr(0x4000), PAGE_SIZE, wx)
            .unwrap_err();
        assert_eq!(err, MmError::WriteExecuteForbidden);
        assert!(!table.has_writable_executable_pages());
    }

    #[test]
    fn overlap_reserved_host_range_is_rejected() {
        let reserved = HostPhysRange {
            start: HostPhysAddr(0x8000),
            len: PAGE_SIZE,
        };
        let mut table =
            NestedPageTable::with_reserved_host_range(InMemoryNpt::new(), reserved);
        table.zeroizer_mut().mark_zeroed(HostPhysAddr(0x8000), PAGE_SIZE);
        let err = table
            .map(GuestPhysAddr(0x1000), HostPhysAddr(0x8000), PAGE_SIZE, Perms::RW)
            .unwrap_err();
        assert_eq!(err, MmError::OverlapsReservedHostRange);
        assert!(!table.maps_host_hypervisor_text());

        // A non-overlapping host range is accepted.
        table.zeroizer_mut().mark_zeroed(HostPhysAddr(0x9000), PAGE_SIZE);
        table
            .map(GuestPhysAddr(0x1000), HostPhysAddr(0x9000), PAGE_SIZE, Perms::RW)
            .unwrap();
        assert!(!table.maps_host_hypervisor_text());
    }

    #[test]
    fn assign_non_zeroed_page_is_rejected() {
        let mut table = npt();
        // No mark_zeroed call -> page is not zeroed.
        let err = table
            .map(GuestPhysAddr(0x1000), HostPhysAddr(0x4000), PAGE_SIZE, Perms::RW)
            .unwrap_err();
        assert_eq!(err, MmError::PageNotZeroed);
    }

    #[test]
    fn poisoned_page_rejected_until_rezeroed() {
        let mut table = npt();
        table.zeroizer_mut().mark_zeroed(HostPhysAddr(0x4000), PAGE_SIZE);
        let id = table
            .map(GuestPhysAddr(0x1000), HostPhysAddr(0x4000), PAGE_SIZE, Perms::RW)
            .unwrap();
        table.unmap(id).unwrap();
        assert_eq!(
            table.zeroizer().state(HostPhysAddr(0x4000)),
            Some(PageState::Poisoned)
        );
        // Re-map without re-zeroing -> poisoned.
        let err = table
            .map(GuestPhysAddr(0x1000), HostPhysAddr(0x4000), PAGE_SIZE, Perms::RW)
            .unwrap_err();
        assert_eq!(err, MmError::PagePoisoned);
        // After re-zeroing it works again.
        table.zeroizer_mut().mark_zeroed(HostPhysAddr(0x4000), PAGE_SIZE);
        table
            .map(GuestPhysAddr(0x1000), HostPhysAddr(0x4000), PAGE_SIZE, Perms::RW)
            .unwrap();
    }

    #[test]
    fn allocate_yields_zeroed_before_assign_true() {
        let mut table = npt();
        let rec = table
            .allocate(
                VmId::new(VM),
                GuestPhysAddr(0x1000),
                HostPhysAddr(0x4000),
                PAGE_SIZE,
                Perms::RW,
            )
            .unwrap();
        assert!(rec.zeroed_before_assign);
        assert_eq!(rec.owner_vm_id, VmId::new(VM));
        assert_eq!(rec.npt_mapping_id, 0);
        assert_eq!(rec.host_physical_range.start, HostPhysAddr(0x4000));
        assert_eq!(rec.guest_physical_range.start, GuestPhysAddr(0x1000));
        assert_eq!(
            table.translate(GuestPhysAddr(0x1000)),
            Some(HostPhysAddr(0x4000))
        );
    }

    #[test]
    fn allocate_still_enforces_wx() {
        let mut table = npt();
        let wx = Perms {
            r: true,
            w: true,
            x: true,
        };
        let err = table
            .allocate(
                VmId::new(VM),
                GuestPhysAddr(0x1000),
                HostPhysAddr(0x4000),
                PAGE_SIZE,
                wx,
            )
            .unwrap_err();
        assert_eq!(err, MmError::WriteExecuteForbidden);
    }

    #[test]
    fn quota_over_reserve_is_rejected() {
        let mut q = MemoryQuotaManager::new(128);
        q.try_reserve(64).unwrap();
        q.try_reserve(64).unwrap();
        assert_eq!(q.used_mb, 128);
        assert_eq!(q.available_mb(), 0);
        let err = q.try_reserve(1).unwrap_err();
        assert_eq!(
            err,
            MmError::QuotaExceeded {
                requested_mb: 1,
                available_mb: 0
            }
        );
        q.release(64);
        q.try_reserve(64).unwrap();
    }

    #[test]
    fn unmap_unknown_is_error() {
        let mut inner = InMemoryNpt::new();
        assert_eq!(inner.unmap(99), Err(MmError::UnknownMapping(99)));
    }

    #[test]
    fn zero_length_map_rejected() {
        let mut inner = InMemoryNpt::new();
        assert_eq!(
            inner.map(GuestPhysAddr(0), HostPhysAddr(0), 0, Perms::RO),
            Err(MmError::ZeroLength)
        );
        let mut table = npt();
        assert_eq!(
            table.map(GuestPhysAddr(0), HostPhysAddr(0), 0, Perms::RO),
            Err(MmError::ZeroLength)
        );
    }

    #[test]
    fn mmio_trap_registry_register_and_lookup() {
        let mut reg = MmioTrapRegistry::new();
        reg.register(
            GuestPhysRange {
                start: GuestPhysAddr(0xfee0_0000),
                len: 0x1000,
            },
            "lapic",
        );
        let hit = reg.lookup(GuestPhysAddr(0xfee0_0500)).unwrap();
        assert_eq!(hit.device, "lapic");
        assert!(reg.lookup(GuestPhysAddr(0x1000)).is_none());
    }

    #[test]
    fn guest_memory_map_regions_and_mmio() {
        let mut map = GuestMemoryMap::new(VmId::new(VM), 0x1000);
        map.add_region(
            GuestMemoryRegion {
                gpa_start: GuestPhysAddr(0),
                len: 0x10000,
                kind: RegionKind::GuestRam,
                perms: Perms::RW,
            },
            "",
        );
        map.add_region(
            GuestMemoryRegion {
                gpa_start: GuestPhysAddr(0xfee0_0000),
                len: 0x1000,
                kind: RegionKind::MmioTrap,
                perms: Perms::RW,
            },
            "lapic",
        );
        assert_eq!(map.regions.len(), 2);
        assert_eq!(map.mmio_traps.traps().len(), 1);
        assert_eq!(
            map.region_at(GuestPhysAddr(0x500)).unwrap().kind,
            RegionKind::GuestRam
        );
        assert!(map.mmio_traps.lookup(GuestPhysAddr(0xfee0_0001)).is_some());
        assert_eq!(map.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn host_range_overlap_logic() {
        let a = HostPhysRange {
            start: HostPhysAddr(0),
            len: 0x1000,
        };
        let b = HostPhysRange {
            start: HostPhysAddr(0x1000),
            len: 0x1000,
        };
        let c = HostPhysRange {
            start: HostPhysAddr(0x800),
            len: 0x1000,
        };
        assert!(!a.overlaps(&b)); // adjacent, half-open: no overlap
        assert!(a.overlaps(&c));
        assert!(c.overlaps(&b));
    }
}
