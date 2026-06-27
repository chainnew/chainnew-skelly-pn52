//! hyper-net — policy-first virtual network framework (framework §8) for the
//! chain.new hyper-slate PN52 runtime.
//!
//! Egress is **default-deny**: a flow is permitted only when an explicit
//! [`EgressRule`] matches its `(proto, dst, port)` tuple (or the policy
//! `default` posture is explicitly `"allow"`). Ingress is always deny-by-default
//! with no posture override. The isolation modes [`NetworkMode::None`] and
//! [`NetworkMode::Isolated`] deny all egress unconditionally. Every decision is
//! fail-closed and deterministic — sandbox identity (MAC/IP) is content-hash
//! derived, with no clocks or randomness.
//!
//! Reuses `hyper-policy`'s [`hyper_policy::FlowRequest`],
//! [`hyper_policy::PolicyDecision`], and [`hyper_policy::DenyReason`] for
//! cross-runtime consistency (see [`VSwitch::as_flow_request`] and
//! [`FlowDecision::to_policy_decision`]).
#![forbid(unsafe_code)]

mod hash;
mod policy;
mod sandbox;
mod switch;

pub use hash::net_hash;
pub use policy::{
    DnsConfig, EgressRule, IngressRule, NetworkError, NetworkMode, NetworkPolicy,
    NETWORK_SCHEMA_VERSION,
};
pub use sandbox::{derive_ip, derive_mac, FlowCounters, NetworkSandbox};
pub use switch::{FlowDecision, VSwitch};

#[cfg(test)]
mod integration_tests {
    use super::*;

    fn policy_json() -> &'static str {
        r#"{
            "schema_version": 1,
            "vm_id": "vm-int",
            "default": "deny",
            "egress": [
                { "proto": "tcp", "dst": "10.0.0.5", "port": 443, "purpose": "https-api" },
                { "proto": "udp", "dst": "*", "port": 53, "purpose": "dns" }
            ],
            "ingress": [],
            "dns": { "mode": "forward", "servers": ["10.0.0.53"] }
        }"#
    }

    #[test]
    fn end_to_end_default_deny_egress() {
        let policy = NetworkPolicy::parse(policy_json()).unwrap();
        let mut sandbox = NetworkSandbox::new(NetworkMode::Nat, policy);
        let mut sw = VSwitch::new(100);

        // Allowed: matches the https-api rule.
        assert!(sw
            .evaluate_flow(&mut sandbox, "tcp", "10.0.0.5", 443, true)
            .is_allow());
        // Allowed: matches the wildcard dns rule.
        assert!(sw
            .evaluate_flow(&mut sandbox, "udp", "1.1.1.1", 53, true)
            .is_allow());
        // Denied: no rule for this destination.
        assert!(matches!(
            sw.evaluate_flow(&mut sandbox, "tcp", "8.8.8.8", 80, true),
            FlowDecision::Deny { .. }
        ));
        // Denied: ingress is default-deny with no rules.
        assert!(matches!(
            sw.evaluate_flow(&mut sandbox, "tcp", "10.0.0.5", 443, false),
            FlowDecision::Deny { .. }
        ));

        assert_eq!(sandbox.counters.allowed, 2);
        assert_eq!(sandbox.counters.denied, 2);
    }
}
