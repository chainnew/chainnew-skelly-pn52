//! Pluggable vCPU and disk backends.
//!
//! Part B §3 (vCPU runtime) and §7 (storage) describe hardware-backed
//! implementations on AMD SVM/NPT and NVMe. For Phase V0 we run on the host
//! with *dummy* backends so the lifecycle, policy, and receipt machinery can be
//! exercised and tested without bare metal. V1+ replaces these with the
//! `hyper-amd-svm` and `hyper-storage` implementations behind the same traits.

/// What the VM-exit dispatcher decided after a single guest run slice
/// (mirrors §4 `VmExitAction`, trimmed to what V0 needs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitAction {
    /// Guest executed HLT / yielded; scheduler may re-run it.
    Halted,
    /// Guest requested shutdown.
    Shutdown,
    /// Fail-closed: unknown/forbidden exit. The VM must be killed.
    Fault,
}

/// Abstracts "run this vCPU until the next VM exit".
pub trait VcpuBackend {
    /// Run one slice; returns the exit action. Real backends call VMRUN.
    fn run_slice(&mut self) -> ExitAction;
    /// Zeroize any vCPU state (Part A §10: keys zeroed before halt).
    fn teardown(&mut self);
}

/// Abstracts an attached, decrypted virtual disk.
pub trait DiskBackend {
    /// Read one sector's worth of bytes. Errors fail the VM closed.
    fn read_sector(&mut self, lba: u64) -> Result<Vec<u8>, DiskError> {
        let _ = lba;
        Err(DiskError::NotReadable)
    }
    fn sector_size(&self) -> u32 {
        4096
    }
    /// Drop key material. Called on destroy (zeroize_on_drop semantics).
    fn zeroize(&mut self);
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DiskError {
    #[error("disk is not readable in this mode")]
    NotReadable,
    #[error("sector {0} out of range")]
    OutOfRange(u64),
}

/// A scripted vCPU used in tests/examples: returns a fixed sequence of exits,
/// then `Shutdown` once the script is exhausted.
#[derive(Debug, Default)]
pub struct ScriptedVcpu {
    script: Vec<ExitAction>,
    cursor: usize,
    torn_down: bool,
}

impl ScriptedVcpu {
    /// A vCPU that halts a few times then shuts down cleanly.
    pub fn cooperative() -> Self {
        Self {
            script: vec![ExitAction::Halted, ExitAction::Halted, ExitAction::Shutdown],
            cursor: 0,
            torn_down: false,
        }
    }

    /// A vCPU whose first exit is an unknown/forbidden reason.
    pub fn faulting() -> Self {
        Self {
            script: vec![ExitAction::Fault],
            cursor: 0,
            torn_down: false,
        }
    }

    pub fn was_torn_down(&self) -> bool {
        self.torn_down
    }
}

impl VcpuBackend for ScriptedVcpu {
    fn run_slice(&mut self) -> ExitAction {
        let action = self.script.get(self.cursor).copied().unwrap_or(ExitAction::Shutdown);
        self.cursor += 1;
        action
    }
    fn teardown(&mut self) {
        self.torn_down = true;
    }
}

/// An in-memory disk for V0 read tests; tracks whether it was zeroized.
#[derive(Debug)]
pub struct MemDisk {
    sectors: Vec<Vec<u8>>,
    sector_size: u32,
    zeroized: bool,
}

impl MemDisk {
    pub fn new(sectors: Vec<Vec<u8>>, sector_size: u32) -> Self {
        Self { sectors, sector_size, zeroized: false }
    }
    pub fn was_zeroized(&self) -> bool {
        self.zeroized
    }
}

impl DiskBackend for MemDisk {
    fn read_sector(&mut self, lba: u64) -> Result<Vec<u8>, DiskError> {
        self.sectors
            .get(lba as usize)
            .cloned()
            .ok_or(DiskError::OutOfRange(lba))
    }
    fn sector_size(&self) -> u32 {
        self.sector_size
    }
    fn zeroize(&mut self) {
        for s in &mut self.sectors {
            s.iter_mut().for_each(|b| *b = 0);
        }
        self.zeroized = true;
    }
}
