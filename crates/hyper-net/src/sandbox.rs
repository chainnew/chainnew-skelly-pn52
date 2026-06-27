//! Per-VM network sandbox: deterministic identity (MAC/IP) plus flow counters.

use serde::{Deserialize, Serialize};

use crate::hash::net_hash;
use crate::policy::{NetworkMode, NetworkPolicy};

/// Running totals for flows evaluated against a sandbox.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct FlowCounters {
    /// Number of flows allowed.
    pub allowed: u64,
    /// Number of flows denied.
    pub denied: u64,
    /// Notional bytes accounted to allowed flows.
    pub bytes: u64,
}

/// Notional bytes attributed to each allowed flow (header/setup overhead).
/// Keeps the `bytes` counter meaningful even though `evaluate_flow` does not
/// carry a payload length.
pub(crate) const FLOW_OVERHEAD_BYTES: u64 = 64;

/// A virtual network endpoint bound to one VM, governed by a [`NetworkPolicy`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct NetworkSandbox {
    /// Identifier of the VM this sandbox belongs to.
    pub vm_id: String,
    /// Networking mode in effect.
    pub mode: NetworkMode,
    /// Policy governing this sandbox.
    pub policy: NetworkPolicy,
    /// Deterministic, locally-administered MAC address.
    pub mac: String,
    /// Deterministic private IPv4 address.
    pub ip: String,
    /// Flow accounting.
    pub counters: FlowCounters,
}

/// Parse two hex chars from `hex` at byte offset `i*2`.
fn octet(hex: &str, i: usize) -> u8 {
    u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap_or(0)
}

/// Deterministic locally-administered MAC derived from the VM id.
///
/// The leading octet is `0x02` (locally administered, unicast); the remaining
/// five octets come from the content hash. No randomness, no clocks.
pub fn derive_mac(vm_id: &str) -> String {
    let h = net_hash(format!("mac|{vm_id}").as_bytes());
    let hex = &h["sha384:".len()..];
    format!(
        "02:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        octet(hex, 0),
        octet(hex, 1),
        octet(hex, 2),
        octet(hex, 3),
        octet(hex, 4),
    )
}

/// Deterministic private IPv4 (`10.x.y.z`) derived from the VM id.
pub fn derive_ip(vm_id: &str) -> String {
    let h = net_hash(format!("ip|{vm_id}").as_bytes());
    let hex = &h["sha384:".len()..];
    // Keep the last octet in 1..=254 to avoid network/broadcast addresses.
    let last = octet(hex, 2) % 254 + 1;
    format!("10.{}.{}.{}", octet(hex, 0), octet(hex, 1), last)
}

impl NetworkSandbox {
    /// Construct a sandbox with deterministically derived MAC/IP and zeroed
    /// counters. The sandbox `vm_id` is taken from the policy so identity and
    /// policy never disagree.
    pub fn new(mode: NetworkMode, policy: NetworkPolicy) -> Self {
        let vm_id = policy.vm_id.clone();
        let mac = derive_mac(&vm_id);
        let ip = derive_ip(&vm_id);
        Self {
            vm_id,
            mode,
            policy,
            mac,
            ip,
            counters: FlowCounters::default(),
        }
    }

    /// Record an allowed flow.
    pub(crate) fn record_allow(&mut self) {
        self.counters.allowed += 1;
        self.counters.bytes += FLOW_OVERHEAD_BYTES;
    }

    /// Record a denied flow.
    pub(crate) fn record_deny(&mut self) {
        self.counters.denied += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::NetworkPolicy;

    fn policy() -> NetworkPolicy {
        let j = r#"{
            "schema_version": 1, "vm_id": "vm-abc", "default": "deny",
            "egress": [], "ingress": [],
            "dns": { "mode": "deny", "servers": [] }
        }"#;
        NetworkPolicy::parse(j).unwrap()
    }

    #[test]
    fn mac_is_locally_administered_and_deterministic() {
        let a = derive_mac("vm-abc");
        let b = derive_mac("vm-abc");
        assert_eq!(a, b);
        assert!(a.starts_with("02:"));
        assert_eq!(a.split(':').count(), 6);
        assert_ne!(derive_mac("vm-abc"), derive_mac("vm-xyz"));
    }

    #[test]
    fn ip_is_private_and_deterministic() {
        let a = derive_ip("vm-abc");
        assert_eq!(a, derive_ip("vm-abc"));
        assert!(a.starts_with("10."));
        let last: u8 = a.rsplit('.').next().unwrap().parse().unwrap();
        assert!((1..=254).contains(&last));
    }

    #[test]
    fn new_sandbox_zeroes_counters_and_binds_identity() {
        let sb = NetworkSandbox::new(NetworkMode::Nat, policy());
        assert_eq!(sb.vm_id, "vm-abc");
        assert_eq!(sb.counters, FlowCounters::default());
        assert_eq!(sb.mac, derive_mac("vm-abc"));
        assert_eq!(sb.ip, derive_ip("vm-abc"));
    }

    #[test]
    fn counters_increment() {
        let mut sb = NetworkSandbox::new(NetworkMode::Nat, policy());
        sb.record_allow();
        sb.record_allow();
        sb.record_deny();
        assert_eq!(sb.counters.allowed, 2);
        assert_eq!(sb.counters.denied, 1);
        assert_eq!(sb.counters.bytes, 2 * FLOW_OVERHEAD_BYTES);
    }
}
