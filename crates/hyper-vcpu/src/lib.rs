//! hyper-vcpu — vCPU runtime, round-robin scheduler and VM-exit dispatcher
//! (slate-runtime V0, host-testable layer).
//!
//! This crate models the SVM/vCPU control plane in plain `std` so the
//! fail-closed VM-exit dispatch logic (SOW S3) and the VMEXIT-storm throttle
//! (SOW S13) can be exercised from host unit tests. It deliberately does NOT
//! talk to real hardware; an [`SvmBackend`] abstraction lets tests script the
//! sequence of VM exits a run loop observes.
//!
//! Design rules:
//!   * deny-by-default dispatch — unknown / un-allowlisted exits terminate the
//!     guest rather than silently resuming it,
//!   * deterministic identifiers (monotonic counter, no randomness/clock),
//!   * no `unsafe`.
#![forbid(unsafe_code)]

use std::collections::{BTreeSet, VecDeque};

use thiserror::Error;

pub use hyper_mm::VmId;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors produced by the vCPU runtime.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum VcpuError {
    /// A run loop was asked to step a vCPU that is no longer runnable.
    #[error("vcpu {0:?} is not runnable (state {1:?})")]
    NotRunnable(VcpuId, VcpuState),

    /// The backend yielded more exits than the configured budget allowed.
    #[error("run loop exceeded step budget of {0}")]
    StepBudgetExceeded(u64),
}

// ---------------------------------------------------------------------------
// Newtypes
// ---------------------------------------------------------------------------

/// Stable, deterministic identifier for a virtual CPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VcpuId(pub u32);

impl VcpuId {
    /// Borrow the inner numeric id.
    pub fn as_u32(self) -> u32 {
        self.0
    }
}

/// Monotonic, deterministic allocator for [`VcpuId`]s.
///
/// IDs are derived purely from an internal counter; there is no randomness,
/// uuid or system clock involved, so identical construction sequences always
/// produce identical ids.
#[derive(Debug, Default, Clone)]
pub struct VcpuIdAllocator {
    next: u32,
}

impl VcpuIdAllocator {
    /// Create a fresh allocator starting at id 0.
    pub fn new() -> Self {
        Self { next: 0 }
    }

    /// Allocate the next deterministic id.
    pub fn alloc(&mut self) -> VcpuId {
        let id = VcpuId(self.next);
        self.next += 1;
        id
    }
}

// ---------------------------------------------------------------------------
// vCPU state model
// ---------------------------------------------------------------------------

/// Lifecycle state of a vCPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VcpuState {
    /// Eligible to be scheduled.
    Ready,
    /// Currently executing (or selected to execute).
    Running,
    /// Voluntarily descheduled (e.g. after `HLT`); not runnable until woken.
    Blocked,
    /// Stopped cleanly.
    Halted,
    /// Forcibly terminated by the dispatcher (fail-closed).
    Killed,
    /// Isolated for forensic inspection; never resumed automatically.
    Quarantined,
}

impl VcpuState {
    /// Whether a vCPU in this state may be handed to a backend `run`.
    pub fn is_runnable(self) -> bool {
        matches!(self, VcpuState::Ready | VcpuState::Running)
    }

    /// Whether this is a terminal state.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            VcpuState::Halted | VcpuState::Killed | VcpuState::Quarantined
        )
    }
}

/// Which classes of events the hypervisor intercepts for a vCPU.
///
/// Every flag defaults to `true` (intercept everything): the safe, fail-closed
/// posture. Clearing a flag means the corresponding exit is treated as a
/// pass-through and simply resumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterceptPolicy {
    /// Intercept `CPUID`.
    pub cpuid: bool,
    /// Intercept MSR reads/writes.
    pub msr: bool,
    /// Intercept port I/O.
    pub io: bool,
    /// Intercept `HLT`.
    pub hlt: bool,
}

impl Default for InterceptPolicy {
    fn default() -> Self {
        Self {
            cpuid: true,
            msr: true,
            io: true,
            hlt: true,
        }
    }
}

/// Per-vCPU runtime counters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VcpuRunStats {
    /// Total number of VM exits observed.
    pub exits: u64,
    /// The most recent exit reason, if any.
    pub last_exit_reason: Option<VmExitReason>,
}

/// A virtual CPU bound to a guest VM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vcpu {
    /// Deterministic id.
    pub id: VcpuId,
    /// Owning guest.
    pub vm_id: VmId,
    /// Current lifecycle state.
    pub state: VcpuState,
    /// Accumulated run statistics.
    pub run_stats: VcpuRunStats,
    /// Interception configuration.
    pub intercept_policy: InterceptPolicy,
}

impl Vcpu {
    /// Construct a `Ready` vCPU with default (intercept-all) policy.
    pub fn new(id: VcpuId, vm_id: VmId) -> Self {
        Self {
            id,
            vm_id,
            state: VcpuState::Ready,
            run_stats: VcpuRunStats::default(),
            intercept_policy: InterceptPolicy::default(),
        }
    }

    /// Record an exit: bump the counter and remember the reason.
    fn record_exit(&mut self, reason: &VmExitReason) {
        self.run_stats.exits = self.run_stats.exits.saturating_add(1);
        self.run_stats.last_exit_reason = Some(reason.clone());
    }
}

// ---------------------------------------------------------------------------
// VM exit reasons / actions
// ---------------------------------------------------------------------------

/// The reason a guest vCPU exited back to the hypervisor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmExitReason {
    /// `CPUID` instruction with the given leaf.
    Cpuid { leaf: u32 },
    /// `RDMSR` of the given MSR.
    MsrRead { msr: u32 },
    /// `WRMSR` of the given MSR with the supplied value.
    MsrWrite { msr: u32, val: u64 },
    /// Port I/O; `write` distinguishes `OUT` from `IN`.
    Io { port: u16, write: bool },
    /// `HLT` instruction.
    Hlt,
    /// Nested page fault at the given guest physical address.
    NestedPageFault { gpa: u64 },
    /// External interrupt with the given vector.
    ExternalIrq { vector: u8 },
    /// Triple fault / shutdown.
    Shutdown,
    /// Any exit code the model does not understand.
    Unknown(u64),
}

/// What the dispatcher decided to do about a VM exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmExitAction {
    /// Re-enter the guest unchanged.
    Resume,
    /// Inject the architectural exception with the given vector, then resume.
    InjectException(u8),
    /// Emulate the instruction in the hypervisor, then resume.
    EmulateAndResume,
    /// Block this vCPU until something wakes it.
    BlockVcpu,
    /// Tear down the whole guest (fail-closed).
    KillVm,
    /// Isolate the guest for inspection (fail-closed, recoverable).
    QuarantineVm,
    /// Stop the host — reserved for unrecoverable host-level faults.
    HaltHost,
}

// ---------------------------------------------------------------------------
// Backend abstraction
// ---------------------------------------------------------------------------

/// Abstraction over "running" a vCPU until its next VM exit.
///
/// Real implementations would drive `VMRUN`; the host-testable
/// [`FakeBackend`] replays a scripted sequence instead.
pub trait SvmBackend {
    /// Run `vcpu` until it exits, returning the exit reason.
    fn run(&mut self, vcpu: &mut Vcpu) -> VmExitReason;
}

/// A scripted backend that yields a predetermined sequence of exits.
///
/// Once the script is exhausted it reports [`VmExitReason::Shutdown`], so run
/// loops always terminate.
#[derive(Debug, Clone, Default)]
pub struct FakeBackend {
    /// Remaining scripted exits, consumed front-to-back.
    pub scripted: Vec<VmExitReason>,
    cursor: usize,
}

impl FakeBackend {
    /// Build a backend from a script.
    pub fn new(scripted: Vec<VmExitReason>) -> Self {
        Self {
            scripted,
            cursor: 0,
        }
    }

    /// Whether every scripted exit has been consumed.
    pub fn is_exhausted(&self) -> bool {
        self.cursor >= self.scripted.len()
    }
}

impl SvmBackend for FakeBackend {
    fn run(&mut self, vcpu: &mut Vcpu) -> VmExitReason {
        vcpu.state = VcpuState::Running;
        let reason = self
            .scripted
            .get(self.cursor)
            .cloned()
            .unwrap_or(VmExitReason::Shutdown);
        if self.cursor < self.scripted.len() {
            self.cursor += 1;
        }
        reason
    }
}

// ---------------------------------------------------------------------------
// Exit dispatcher (SOW S3 / S13)
// ---------------------------------------------------------------------------

/// General-protection fault vector, injected on denied MSR access.
const GP_FAULT_VECTOR: u8 = 13;

/// Fail-closed VM-exit dispatcher.
///
/// MSR and I/O accesses are deny-by-default: only ports / MSRs present in the
/// respective allowlists are emulated, everything else is rejected. A per-vCPU
/// exit budget (`exit_storm_limit`) throttles VMEXIT storms (SOW S13): once a
/// vCPU exceeds it, the guest is killed.
#[derive(Debug, Clone)]
pub struct ExitDispatcher {
    /// MSRs permitted for emulation.
    pub msr_allow: BTreeSet<u32>,
    /// I/O ports permitted for emulation.
    pub io_allow: BTreeSet<u16>,
    /// Maximum exits a single vCPU may take before being killed.
    pub exit_storm_limit: u64,
}

impl Default for ExitDispatcher {
    fn default() -> Self {
        Self {
            msr_allow: BTreeSet::new(),
            io_allow: BTreeSet::new(),
            exit_storm_limit: 1024,
        }
    }
}

impl ExitDispatcher {
    /// Construct a dispatcher with explicit allowlists and storm limit.
    pub fn new(
        msr_allow: BTreeSet<u32>,
        io_allow: BTreeSet<u16>,
        exit_storm_limit: u64,
    ) -> Self {
        Self {
            msr_allow,
            io_allow,
            exit_storm_limit,
        }
    }

    /// Classify and act on a single VM exit, mutating `vcpu` accordingly.
    ///
    /// The exit is recorded first (so the storm counter always advances), then
    /// the storm budget is enforced, then the reason is dispatched. The vCPU's
    /// `state` is updated to reflect any terminal/blocking decision.
    pub fn handle(&self, reason: VmExitReason, vcpu: &mut Vcpu) -> VmExitAction {
        vcpu.record_exit(&reason);

        // S13: VMEXIT-storm throttle. Fail closed once over budget.
        if vcpu.run_stats.exits > self.exit_storm_limit {
            return self.apply(vcpu, VmExitAction::KillVm);
        }

        let action = match reason {
            VmExitReason::Cpuid { .. } => {
                if vcpu.intercept_policy.cpuid {
                    // Emulate with a masked/sanitised leaf result.
                    VmExitAction::EmulateAndResume
                } else {
                    VmExitAction::Resume
                }
            }
            VmExitReason::MsrRead { msr } | VmExitReason::MsrWrite { msr, .. } => {
                if !vcpu.intercept_policy.msr {
                    VmExitAction::Resume
                } else if self.msr_allow.contains(&msr) {
                    VmExitAction::EmulateAndResume
                } else {
                    // Default deny: inject #GP(0) into the guest.
                    VmExitAction::InjectException(GP_FAULT_VECTOR)
                }
            }
            VmExitReason::Io { port, .. } => {
                if !vcpu.intercept_policy.io {
                    VmExitAction::Resume
                } else if self.io_allow.contains(&port) {
                    VmExitAction::EmulateAndResume
                } else {
                    // Default deny: quarantine the guest for inspection.
                    VmExitAction::QuarantineVm
                }
            }
            VmExitReason::Hlt => {
                if vcpu.intercept_policy.hlt {
                    VmExitAction::BlockVcpu
                } else {
                    VmExitAction::Resume
                }
            }
            VmExitReason::NestedPageFault { gpa } => {
                // A fault at the null GPA is never legitimate -> kill.
                if gpa == 0 {
                    VmExitAction::KillVm
                } else {
                    VmExitAction::EmulateAndResume
                }
            }
            VmExitReason::ExternalIrq { .. } => VmExitAction::Resume,
            VmExitReason::Shutdown => VmExitAction::KillVm,
            VmExitReason::Unknown(_) => VmExitAction::KillVm,
        };

        self.apply(vcpu, action)
    }

    /// Reflect an action into the vCPU's lifecycle state and return it.
    fn apply(&self, vcpu: &mut Vcpu, action: VmExitAction) -> VmExitAction {
        match action {
            VmExitAction::Resume
            | VmExitAction::EmulateAndResume
            | VmExitAction::InjectException(_) => {
                if !vcpu.state.is_terminal() {
                    vcpu.state = VcpuState::Running;
                }
            }
            VmExitAction::BlockVcpu => vcpu.state = VcpuState::Blocked,
            VmExitAction::KillVm => vcpu.state = VcpuState::Killed,
            VmExitAction::QuarantineVm => vcpu.state = VcpuState::Quarantined,
            VmExitAction::HaltHost => vcpu.state = VcpuState::Halted,
        }
        action
    }
}

// ---------------------------------------------------------------------------
// Run loop
// ---------------------------------------------------------------------------

/// Drive a vCPU through `backend` + `dispatcher` until it stops being
/// runnable or the step budget is hit.
///
/// Returns the number of exits processed. Fails closed if `max_steps` is
/// exhausted while the vCPU is still runnable (guards against infinite loops).
pub fn run_loop(
    backend: &mut dyn SvmBackend,
    dispatcher: &ExitDispatcher,
    vcpu: &mut Vcpu,
    max_steps: u64,
) -> Result<u64, VcpuError> {
    if !vcpu.state.is_runnable() {
        return Err(VcpuError::NotRunnable(vcpu.id, vcpu.state));
    }

    let mut steps = 0u64;
    while vcpu.state.is_runnable() {
        if steps >= max_steps {
            return Err(VcpuError::StepBudgetExceeded(max_steps));
        }
        let reason = backend.run(vcpu);
        let action = dispatcher.handle(reason, vcpu);
        steps += 1;
        // Resume-like actions keep the loop going; terminal/blocking actions
        // flip the state and the `is_runnable` guard ends the loop.
        if matches!(action, VmExitAction::HaltHost) {
            break;
        }
    }
    Ok(steps)
}

// ---------------------------------------------------------------------------
// Scheduler
// ---------------------------------------------------------------------------

/// Scheduling class, ordered from highest to lowest priority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SchedClass {
    /// Critical host services — always run first.
    CriticalHost,
    /// Control-plane VM.
    ControlVm,
    /// Ordinary tenant guest.
    NormalGuest,
    /// Untrusted sandboxed guest.
    SandboxGuest,
    /// Detonation / malware-analysis guest.
    DetonationGuest,
    /// Best-effort background guest.
    BackgroundGuest,
}

impl SchedClass {
    /// Highest-to-lowest priority order used by the scheduler.
    pub const PRIORITY_ORDER: [SchedClass; 6] = [
        SchedClass::CriticalHost,
        SchedClass::ControlVm,
        SchedClass::NormalGuest,
        SchedClass::SandboxGuest,
        SchedClass::DetonationGuest,
        SchedClass::BackgroundGuest,
    ];

    fn index(self) -> usize {
        match self {
            SchedClass::CriticalHost => 0,
            SchedClass::ControlVm => 1,
            SchedClass::NormalGuest => 2,
            SchedClass::SandboxGuest => 3,
            SchedClass::DetonationGuest => 4,
            SchedClass::BackgroundGuest => 5,
        }
    }
}

/// Strict-priority, round-robin-within-priority scheduler.
///
/// Higher-priority classes are always drained before lower ones; within a
/// single class, vCPUs are cycled fairly (FIFO with re-enqueue on selection).
/// Blocked vCPUs are skipped and dropped from the run queues until re-enqueued.
#[derive(Debug, Clone)]
pub struct Scheduler {
    queues: [VecDeque<VcpuId>; 6],
    blocked: BTreeSet<VcpuId>,
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl Scheduler {
    /// Create an empty scheduler.
    pub fn new() -> Self {
        Self {
            queues: Default::default(),
            blocked: BTreeSet::new(),
        }
    }

    /// Add (or re-add) a vCPU to the run queue for `class`.
    ///
    /// Enqueuing clears any prior `block` for that vCPU. Duplicate enqueues of
    /// an already-queued id in the same class are ignored to keep round-robin
    /// fair.
    pub fn enqueue(&mut self, id: VcpuId, class: SchedClass) {
        self.blocked.remove(&id);
        let q = &mut self.queues[class.index()];
        if !q.contains(&id) {
            q.push_back(id);
        }
    }

    /// Mark a vCPU as blocked: it will be skipped (and removed) by
    /// [`Scheduler::next_runnable`] until it is enqueued again.
    pub fn block(&mut self, id: VcpuId) {
        self.blocked.insert(id);
        for q in &mut self.queues {
            q.retain(|&qid| qid != id);
        }
    }

    /// Pick the next vCPU to run: the front of the highest-priority non-empty
    /// class, rotated to the back for fairness. Returns `None` if nothing is
    /// runnable.
    pub fn next_runnable(&mut self) -> Option<VcpuId> {
        for q in &mut self.queues {
            while let Some(id) = q.pop_front() {
                if self.blocked.contains(&id) {
                    // Stale entry for a blocked vCPU: drop it.
                    continue;
                }
                q.push_back(id);
                return Some(id);
            }
        }
        None
    }

    /// Total number of queued (runnable) vCPUs across all classes.
    pub fn len(&self) -> usize {
        self.queues.iter().map(VecDeque::len).sum()
    }

    /// Whether no vCPU is currently runnable.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn vm() -> VmId {
        VmId::new("vm-test")
    }

    fn vcpu() -> Vcpu {
        Vcpu::new(VcpuId(0), vm())
    }

    #[test]
    fn id_allocator_is_deterministic() {
        let mut a = VcpuIdAllocator::new();
        let mut b = VcpuIdAllocator::new();
        assert_eq!(a.alloc(), VcpuId(0));
        assert_eq!(a.alloc(), VcpuId(1));
        assert_eq!(b.alloc(), VcpuId(0));
        assert_eq!(b.alloc(), VcpuId(1));
        assert_eq!(a.alloc().as_u32(), 2);
    }

    #[test]
    fn intercept_policy_defaults_all_true() {
        let p = InterceptPolicy::default();
        assert!(p.cpuid && p.msr && p.io && p.hlt);
    }

    #[test]
    fn cpuid_emulates_and_resumes() {
        let d = ExitDispatcher::default();
        let mut v = vcpu();
        let action = d.handle(VmExitReason::Cpuid { leaf: 1 }, &mut v);
        assert_eq!(action, VmExitAction::EmulateAndResume);
        assert_eq!(v.state, VcpuState::Running);
        assert_eq!(v.run_stats.exits, 1);
        assert_eq!(
            v.run_stats.last_exit_reason,
            Some(VmExitReason::Cpuid { leaf: 1 })
        );
    }

    #[test]
    fn unknown_exit_kills_vm() {
        let d = ExitDispatcher::default();
        let mut v = vcpu();
        let action = d.handle(VmExitReason::Unknown(0xdead), &mut v);
        assert_eq!(action, VmExitAction::KillVm);
        assert_eq!(v.state, VcpuState::Killed);
    }

    #[test]
    fn shutdown_kills_vm() {
        let d = ExitDispatcher::default();
        let mut v = vcpu();
        assert_eq!(d.handle(VmExitReason::Shutdown, &mut v), VmExitAction::KillVm);
        assert_eq!(v.state, VcpuState::Killed);
    }

    #[test]
    fn msr_not_allowlisted_is_denied() {
        let d = ExitDispatcher::default();
        let mut v = vcpu();
        // read
        assert_eq!(
            d.handle(VmExitReason::MsrRead { msr: 0x10 }, &mut v),
            VmExitAction::InjectException(GP_FAULT_VECTOR)
        );
        // write
        assert_eq!(
            d.handle(VmExitReason::MsrWrite { msr: 0x10, val: 7 }, &mut v),
            VmExitAction::InjectException(GP_FAULT_VECTOR)
        );
    }

    #[test]
    fn msr_allowlisted_is_emulated() {
        let mut allow = BTreeSet::new();
        allow.insert(0x10u32);
        let d = ExitDispatcher::new(allow, BTreeSet::new(), 1024);
        let mut v = vcpu();
        assert_eq!(
            d.handle(VmExitReason::MsrRead { msr: 0x10 }, &mut v),
            VmExitAction::EmulateAndResume
        );
    }

    #[test]
    fn io_not_allowlisted_is_denied() {
        let d = ExitDispatcher::default();
        let mut v = vcpu();
        let action = d.handle(VmExitReason::Io { port: 0x60, write: true }, &mut v);
        assert_eq!(action, VmExitAction::QuarantineVm);
        assert_eq!(v.state, VcpuState::Quarantined);
    }

    #[test]
    fn io_allowlisted_is_emulated() {
        let mut io = BTreeSet::new();
        io.insert(0x60u16);
        let d = ExitDispatcher::new(BTreeSet::new(), io, 1024);
        let mut v = vcpu();
        assert_eq!(
            d.handle(VmExitReason::Io { port: 0x60, write: false }, &mut v),
            VmExitAction::EmulateAndResume
        );
    }

    #[test]
    fn hlt_blocks_vcpu() {
        let d = ExitDispatcher::default();
        let mut v = vcpu();
        assert_eq!(d.handle(VmExitReason::Hlt, &mut v), VmExitAction::BlockVcpu);
        assert_eq!(v.state, VcpuState::Blocked);
    }

    #[test]
    fn npt_fault_emulates_or_kills() {
        let d = ExitDispatcher::default();
        let mut v = vcpu();
        assert_eq!(
            d.handle(VmExitReason::NestedPageFault { gpa: 0x1000 }, &mut v),
            VmExitAction::EmulateAndResume
        );
        let mut v2 = vcpu();
        assert_eq!(
            d.handle(VmExitReason::NestedPageFault { gpa: 0 }, &mut v2),
            VmExitAction::KillVm
        );
        assert_eq!(v2.state, VcpuState::Killed);
    }

    #[test]
    fn external_irq_resumes() {
        let d = ExitDispatcher::default();
        let mut v = vcpu();
        assert_eq!(
            d.handle(VmExitReason::ExternalIrq { vector: 32 }, &mut v),
            VmExitAction::Resume
        );
    }

    #[test]
    fn disabled_interception_passes_through() {
        let d = ExitDispatcher::default();
        let mut v = vcpu();
        v.intercept_policy.msr = false;
        v.intercept_policy.io = false;
        v.intercept_policy.cpuid = false;
        v.intercept_policy.hlt = false;
        assert_eq!(
            d.handle(VmExitReason::MsrRead { msr: 0x10 }, &mut v),
            VmExitAction::Resume
        );
        assert_eq!(
            d.handle(VmExitReason::Io { port: 0x99, write: true }, &mut v),
            VmExitAction::Resume
        );
        assert_eq!(
            d.handle(VmExitReason::Cpuid { leaf: 0 }, &mut v),
            VmExitAction::Resume
        );
        assert_eq!(d.handle(VmExitReason::Hlt, &mut v), VmExitAction::Resume);
    }

    #[test]
    fn exit_storm_kills_vm() {
        let d = ExitDispatcher::new(BTreeSet::new(), BTreeSet::new(), 3);
        let mut v = vcpu();
        // First 3 exits are within budget (ExternalIrq -> Resume).
        for _ in 0..3 {
            let a = d.handle(VmExitReason::ExternalIrq { vector: 1 }, &mut v);
            assert_eq!(a, VmExitAction::Resume);
        }
        // 4th exit exceeds the budget -> KillVm regardless of reason.
        let a = d.handle(VmExitReason::ExternalIrq { vector: 1 }, &mut v);
        assert_eq!(a, VmExitAction::KillVm);
        assert_eq!(v.state, VcpuState::Killed);
    }

    #[test]
    fn round_robin_fairness_within_class() {
        let mut s = Scheduler::new();
        s.enqueue(VcpuId(1), SchedClass::NormalGuest);
        s.enqueue(VcpuId(2), SchedClass::NormalGuest);
        s.enqueue(VcpuId(3), SchedClass::NormalGuest);
        let seq: Vec<u32> = (0..6)
            .map(|_| s.next_runnable().unwrap().as_u32())
            .collect();
        assert_eq!(seq, vec![1, 2, 3, 1, 2, 3]);
    }

    #[test]
    fn strict_priority_across_classes() {
        let mut s = Scheduler::new();
        s.enqueue(VcpuId(9), SchedClass::BackgroundGuest);
        s.enqueue(VcpuId(1), SchedClass::CriticalHost);
        s.enqueue(VcpuId(5), SchedClass::NormalGuest);
        // CriticalHost wins and keeps winning under strict priority.
        assert_eq!(s.next_runnable(), Some(VcpuId(1)));
        assert_eq!(s.next_runnable(), Some(VcpuId(1)));
        s.block(VcpuId(1));
        assert_eq!(s.next_runnable(), Some(VcpuId(5)));
        s.block(VcpuId(5));
        assert_eq!(s.next_runnable(), Some(VcpuId(9)));
    }

    #[test]
    fn block_removes_from_queue() {
        let mut s = Scheduler::new();
        s.enqueue(VcpuId(1), SchedClass::NormalGuest);
        s.enqueue(VcpuId(2), SchedClass::NormalGuest);
        s.block(VcpuId(1));
        assert_eq!(s.next_runnable(), Some(VcpuId(2)));
        assert_eq!(s.next_runnable(), Some(VcpuId(2)));
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn enqueue_clears_block_and_dedups() {
        let mut s = Scheduler::new();
        s.enqueue(VcpuId(1), SchedClass::NormalGuest);
        s.enqueue(VcpuId(1), SchedClass::NormalGuest); // dup ignored
        assert_eq!(s.len(), 1);
        s.block(VcpuId(1));
        assert!(s.is_empty());
        s.enqueue(VcpuId(1), SchedClass::NormalGuest); // un-blocks
        assert_eq!(s.next_runnable(), Some(VcpuId(1)));
    }

    #[test]
    fn empty_scheduler_returns_none() {
        let mut s = Scheduler::new();
        assert!(s.is_empty());
        assert_eq!(s.next_runnable(), None);
    }

    #[test]
    fn fake_backend_drives_run_loop() {
        let mut backend = FakeBackend::new(vec![
            VmExitReason::Cpuid { leaf: 0 },
            VmExitReason::ExternalIrq { vector: 32 },
            VmExitReason::Hlt, // -> BlockVcpu ends the loop
        ]);
        let d = ExitDispatcher::default();
        let mut v = vcpu();
        let steps = run_loop(&mut backend, &d, &mut v, 100).unwrap();
        assert_eq!(steps, 3);
        assert_eq!(v.state, VcpuState::Blocked);
        assert_eq!(v.run_stats.exits, 3);
        assert!(backend.is_exhausted());
    }

    #[test]
    fn run_loop_kills_on_unknown() {
        let mut backend = FakeBackend::new(vec![
            VmExitReason::Cpuid { leaf: 0 },
            VmExitReason::Unknown(0xbad),
            VmExitReason::Cpuid { leaf: 1 }, // never reached
        ]);
        let d = ExitDispatcher::default();
        let mut v = vcpu();
        let steps = run_loop(&mut backend, &d, &mut v, 100).unwrap();
        assert_eq!(steps, 2);
        assert_eq!(v.state, VcpuState::Killed);
    }

    #[test]
    fn run_loop_exhausted_backend_shuts_down() {
        let mut backend = FakeBackend::new(vec![]);
        let d = ExitDispatcher::default();
        let mut v = vcpu();
        // Empty script -> Shutdown -> KillVm on first step.
        let steps = run_loop(&mut backend, &d, &mut v, 100).unwrap();
        assert_eq!(steps, 1);
        assert_eq!(v.state, VcpuState::Killed);
    }

    #[test]
    fn run_loop_rejects_non_runnable() {
        let mut backend = FakeBackend::new(vec![]);
        let d = ExitDispatcher::default();
        let mut v = vcpu();
        v.state = VcpuState::Killed;
        let err = run_loop(&mut backend, &d, &mut v, 10).unwrap_err();
        assert_eq!(err, VcpuError::NotRunnable(VcpuId(0), VcpuState::Killed));
    }

    #[test]
    fn run_loop_step_budget_enforced() {
        // ExternalIrq always resumes; with a huge storm limit it never ends.
        let mut backend = FakeBackend::new(
            std::iter::repeat_n(VmExitReason::ExternalIrq { vector: 1 }, 50).collect(),
        );
        let d = ExitDispatcher::new(BTreeSet::new(), BTreeSet::new(), u64::MAX);
        let mut v = vcpu();
        let err = run_loop(&mut backend, &d, &mut v, 5).unwrap_err();
        assert_eq!(err, VcpuError::StepBudgetExceeded(5));
    }
}
