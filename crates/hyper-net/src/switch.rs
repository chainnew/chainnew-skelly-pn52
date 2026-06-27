//! Policy-first virtual switch (framework §8): default-deny flow evaluation.
//!
//! [`VSwitch::evaluate_flow`] is fail-closed. A flow begins denied and is only
//! allowed when every gate is satisfied:
//!   1. the sandbox mode is not an isolation posture (`None`/`Isolated`);
//!   2. for egress, an explicit [`crate::EgressRule`] matches (or the policy
//!      `default` posture is `"allow"`);
//!   3. for ingress, an explicit [`crate::IngressRule`] matches (ingress is
//!      always deny-by-default — there is no posture override);
//!   4. the per-second rate limit is not exceeded.
//!
//! Every decision updates the sandbox [`crate::FlowCounters`].

use serde::{Deserialize, Serialize};

use hyper_policy::{DenyReason, FlowRequest, PolicyDecision};

use crate::sandbox::NetworkSandbox;

/// Outcome of a single flow evaluation.
///
/// We define a dedicated, network-local decision (rather than reusing
/// [`hyper_policy::PolicyDecision`] directly) because a virtual switch never
/// emits the `RequireApproval` variant and carries a flat reason string. The
/// reason strings are derived from [`hyper_policy::DenyReason`] so the language
/// stays consistent across the runtime, and [`FlowDecision::to_policy_decision`]
/// bridges to the shared type when a caller needs it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowDecision {
    /// Flow permitted.
    Allow,
    /// Flow denied, with a human-readable reason.
    Deny {
        /// Why the flow was denied.
        reason: String,
    },
}

impl FlowDecision {
    /// True if the flow was allowed.
    pub fn is_allow(&self) -> bool {
        matches!(self, FlowDecision::Allow)
    }

    /// Bridge to the shared [`hyper_policy::PolicyDecision`]. Allows carry no
    /// receipt here (the switch is the enforcement point, not the policy
    /// engine); denies map to [`DenyReason::Other`] preserving the reason text.
    pub fn to_policy_decision(&self, receipt: hyper_policy::PolicyReceipt) -> PolicyDecision {
        match self {
            FlowDecision::Allow => PolicyDecision::Allow { receipt },
            FlowDecision::Deny { reason } => PolicyDecision::Deny {
                reason: DenyReason::Other(reason.clone()),
            },
        }
    }
}

/// A policy-first virtual switch shared by sandboxes on a segment.
///
/// The rate limiter is deterministic and clock-free: `evaluate_flow` consumes
/// one slot from the current logical-second window; [`VSwitch::tick`] opens the
/// next window. With `rate_limit_per_sec == 0` the limiter is disabled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct VSwitch {
    /// Maximum flows permitted per logical second (`0` = unlimited).
    pub rate_limit_per_sec: u32,
    /// Flows evaluated as candidate-allows in the current window.
    pub flows_this_window: u32,
}

impl Default for VSwitch {
    fn default() -> Self {
        Self::new(0)
    }
}

impl VSwitch {
    /// Construct a switch with the given per-second rate limit (`0` disables).
    pub fn new(rate_limit_per_sec: u32) -> Self {
        Self {
            rate_limit_per_sec,
            flows_this_window: 0,
        }
    }

    /// Advance to the next logical second, resetting the rate-limit window.
    pub fn tick(&mut self) {
        self.flows_this_window = 0;
    }

    /// True if admitting one more flow would exceed the rate limit.
    fn rate_limited(&self) -> bool {
        self.rate_limit_per_sec != 0 && self.flows_this_window >= self.rate_limit_per_sec
    }

    /// Evaluate a flow against the sandbox policy, fail-closed.
    ///
    /// `egress = true` evaluates `proto`/`dst`/`port` against egress rules;
    /// `egress = false` treats `dst` as the *source* and evaluates ingress
    /// rules. Updates the sandbox counters and (on a candidate-allow) the
    /// rate-limit window.
    pub fn evaluate_flow(
        &mut self,
        sandbox: &mut NetworkSandbox,
        proto: &str,
        dst: &str,
        port: u16,
        egress: bool,
    ) -> FlowDecision {
        // Gate 1: isolation postures deny everything, unconditionally.
        if sandbox.mode.denies_all_egress() {
            sandbox.record_deny();
            return FlowDecision::Deny {
                reason: format!("{:?}: mode isolates the sandbox", sandbox.mode),
            };
        }

        // Gate 2/3: deny-by-default rule matching.
        let matched_by_rule = if egress {
            sandbox.policy.match_egress(proto, dst, port).is_some()
                || sandbox.policy.default_allows()
        } else {
            // Ingress is always deny-by-default: no posture override.
            sandbox.policy.match_ingress(proto, dst, port).is_some()
        };

        if !matched_by_rule {
            sandbox.record_deny();
            let reason = if egress {
                format!("{:?}", DenyReason::EgressDenied)
            } else {
                format!("{:?}", DenyReason::Other("ingress not matched by rule".to_string()))
            };
            return FlowDecision::Deny { reason };
        }

        // Gate 4: rate limit (only consulted once the flow would otherwise be
        // allowed, so denied flows never consume the budget).
        if self.rate_limited() {
            sandbox.record_deny();
            return FlowDecision::Deny {
                reason: format!(
                    "rate_limited: {} flows/s exceeded",
                    self.rate_limit_per_sec
                ),
            };
        }

        self.flows_this_window += 1;
        sandbox.record_allow();
        FlowDecision::Allow
    }

    /// Build the shared [`hyper_policy::FlowRequest`] describing a decision,
    /// for callers that feed the policy spine. Reuses the upstream type.
    pub fn as_flow_request(direction_egress: bool, allowed_by_rule: bool) -> FlowRequest {
        FlowRequest {
            direction: if direction_egress { "egress" } else { "ingress" }.to_string(),
            allowed_by_rule,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{NetworkMode, NetworkPolicy};
    use crate::sandbox::FlowCounters;

    fn policy(default: &str) -> NetworkPolicy {
        let j = format!(
            r#"{{
                "schema_version": 1, "vm_id": "vm-net", "default": "{default}",
                "egress": [
                    {{ "proto": "tcp", "dst": "10.0.0.5", "port": 443, "purpose": "api" }}
                ],
                "ingress": [
                    {{ "proto": "tcp", "src": "10.0.0.1", "port": 22, "purpose": "ssh" }}
                ],
                "dns": {{ "mode": "deny", "servers": [] }}
            }}"#
        );
        NetworkPolicy::parse(&j).unwrap()
    }

    fn sandbox(mode: NetworkMode, default: &str) -> NetworkSandbox {
        NetworkSandbox::new(mode, policy(default))
    }

    #[test]
    fn egress_allowed_to_matching_rule() {
        let mut sw = VSwitch::default();
        let mut sb = sandbox(NetworkMode::Nat, "deny");
        let d = sw.evaluate_flow(&mut sb, "tcp", "10.0.0.5", 443, true);
        assert_eq!(d, FlowDecision::Allow);
        assert_eq!(sb.counters.allowed, 1);
        assert_eq!(sb.counters.denied, 0);
    }

    #[test]
    fn egress_denied_on_dst_mismatch() {
        let mut sw = VSwitch::default();
        let mut sb = sandbox(NetworkMode::Nat, "deny");
        let d = sw.evaluate_flow(&mut sb, "tcp", "1.2.3.4", 443, true);
        assert!(matches!(d, FlowDecision::Deny { .. }));
        assert_eq!(sb.counters.denied, 1);
        assert_eq!(sb.counters.allowed, 0);
    }

    #[test]
    fn egress_denied_on_port_mismatch() {
        let mut sw = VSwitch::default();
        let mut sb = sandbox(NetworkMode::Nat, "deny");
        let d = sw.evaluate_flow(&mut sb, "tcp", "10.0.0.5", 8443, true);
        assert!(matches!(d, FlowDecision::Deny { .. }));
        assert_eq!(sb.counters.denied, 1);
    }

    #[test]
    fn ingress_default_denies() {
        let mut sw = VSwitch::default();
        let mut sb = sandbox(NetworkMode::Nat, "deny");
        // Unmatched ingress source -> deny.
        let d = sw.evaluate_flow(&mut sb, "tcp", "9.9.9.9", 22, false);
        assert!(matches!(d, FlowDecision::Deny { .. }));
        assert_eq!(sb.counters.denied, 1);
    }

    #[test]
    fn ingress_allowed_when_rule_matches() {
        let mut sw = VSwitch::default();
        let mut sb = sandbox(NetworkMode::Nat, "deny");
        let d = sw.evaluate_flow(&mut sb, "tcp", "10.0.0.1", 22, false);
        assert_eq!(d, FlowDecision::Allow);
        assert_eq!(sb.counters.allowed, 1);
    }

    #[test]
    fn isolated_denies_all_egress() {
        let mut sw = VSwitch::default();
        let mut sb = sandbox(NetworkMode::Isolated, "allow");
        // Even with default "allow" and a matching tuple, isolation wins.
        let d = sw.evaluate_flow(&mut sb, "tcp", "10.0.0.5", 443, true);
        assert!(matches!(d, FlowDecision::Deny { .. }));
        assert_eq!(sb.counters.denied, 1);
    }

    #[test]
    fn none_mode_denies_all() {
        let mut sw = VSwitch::default();
        let mut sb = sandbox(NetworkMode::None, "allow");
        let d = sw.evaluate_flow(&mut sb, "udp", "8.8.8.8", 53, true);
        assert!(matches!(d, FlowDecision::Deny { .. }));
    }

    #[test]
    fn default_allow_posture_permits_unmatched_egress() {
        let mut sw = VSwitch::default();
        let mut sb = sandbox(NetworkMode::Nat, "allow");
        let d = sw.evaluate_flow(&mut sb, "tcp", "203.0.113.1", 9999, true);
        assert_eq!(d, FlowDecision::Allow);
    }

    #[test]
    fn default_allow_does_not_open_ingress() {
        let mut sw = VSwitch::default();
        let mut sb = sandbox(NetworkMode::Nat, "allow");
        // Posture "allow" must NOT open unmatched ingress.
        let d = sw.evaluate_flow(&mut sb, "tcp", "9.9.9.9", 22, false);
        assert!(matches!(d, FlowDecision::Deny { .. }));
    }

    #[test]
    fn rate_limit_denies_excess_and_tick_resets() {
        let mut sw = VSwitch::new(2);
        let mut sb = sandbox(NetworkMode::Nat, "deny");
        assert!(sw.evaluate_flow(&mut sb, "tcp", "10.0.0.5", 443, true).is_allow());
        assert!(sw.evaluate_flow(&mut sb, "tcp", "10.0.0.5", 443, true).is_allow());
        // Third in the same window exceeds the limit.
        let d = sw.evaluate_flow(&mut sb, "tcp", "10.0.0.5", 443, true);
        assert!(matches!(d, FlowDecision::Deny { .. }));
        assert_eq!(sb.counters.allowed, 2);
        assert_eq!(sb.counters.denied, 1);
        // New window restores budget.
        sw.tick();
        assert!(sw.evaluate_flow(&mut sb, "tcp", "10.0.0.5", 443, true).is_allow());
        assert_eq!(sb.counters.allowed, 3);
    }

    #[test]
    fn denied_flows_do_not_consume_rate_budget() {
        let mut sw = VSwitch::new(1);
        let mut sb = sandbox(NetworkMode::Nat, "deny");
        // A denied (mismatched) flow should not burn the single token.
        assert!(matches!(
            sw.evaluate_flow(&mut sb, "tcp", "1.2.3.4", 443, true),
            FlowDecision::Deny { .. }
        ));
        assert_eq!(sw.flows_this_window, 0);
        // The one allowed flow still goes through.
        assert!(sw.evaluate_flow(&mut sb, "tcp", "10.0.0.5", 443, true).is_allow());
    }

    #[test]
    fn counters_accumulate_across_flows() {
        let mut sw = VSwitch::default();
        let mut sb = sandbox(NetworkMode::Nat, "deny");
        sw.evaluate_flow(&mut sb, "tcp", "10.0.0.5", 443, true); // allow
        sw.evaluate_flow(&mut sb, "tcp", "1.1.1.1", 443, true); // deny
        sw.evaluate_flow(&mut sb, "tcp", "10.0.0.5", 443, true); // allow
        assert_eq!(sb.counters.allowed, 2);
        assert_eq!(sb.counters.denied, 1);
        assert_ne!(sb.counters, FlowCounters::default());
    }

    #[test]
    fn bridge_to_policy_decision() {
        let allow = FlowDecision::Allow;
        let receipt = hyper_policy::PolicyReceipt {
            rationale: "r".to_string(),
            inputs_hash: "sha384:00".to_string(),
        };
        assert!(matches!(
            allow.to_policy_decision(receipt.clone()),
            PolicyDecision::Allow { .. }
        ));
        let deny = FlowDecision::Deny {
            reason: "x".to_string(),
        };
        assert!(matches!(
            deny.to_policy_decision(receipt),
            PolicyDecision::Deny {
                reason: DenyReason::Other(_)
            }
        ));
    }

    #[test]
    fn flow_request_helper_reuses_upstream_type() {
        let req = VSwitch::as_flow_request(true, false);
        assert_eq!(req.direction, "egress");
        assert!(!req.allowed_by_rule);
    }
}
