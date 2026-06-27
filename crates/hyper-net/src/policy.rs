//! Network policy-as-code document (framework §8).
//!
//! A [`NetworkPolicy`] is the declarative, JSON-mapped source of truth that the
//! [`crate::VSwitch`] evaluates flows against. It is parsed from the SOW JSON
//! and is **deny-by-default** in spirit: egress is permitted only when an
//! explicit [`EgressRule`] matches, and ingress is denied unless an explicit
//! [`IngressRule`] matches.

use serde::{Deserialize, Serialize};

/// Current schema version for the network policy document.
pub const NETWORK_SCHEMA_VERSION: u32 = 1;

/// Errors produced while parsing or validating a [`NetworkPolicy`].
#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    /// The input was not valid JSON or did not match the document shape.
    #[error("invalid network policy json: {0}")]
    Json(#[from] serde_json::Error),

    /// The document declared a schema version this build cannot interpret.
    #[error("unsupported network schema_version {found} (expected {expected})")]
    UnsupportedSchema {
        /// Version found in the document.
        found: u32,
        /// Version this build supports.
        expected: u32,
    },

    /// A field held a value outside the accepted set.
    #[error("invalid network policy field: {0}")]
    InvalidField(String),
}

/// Virtual networking mode for a sandbox (framework §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    /// No network device at all.
    None,
    /// Device present but fully isolated; no egress or ingress.
    Isolated,
    /// Communication permitted with the host only.
    HostOnly,
    /// Network address translation to an upstream network.
    Nat,
    /// Bridged onto a shared L2 segment.
    Bridge,
    /// Encrypted overlay gated on remote attestation.
    AttestedOverlay,
}

impl NetworkMode {
    /// Modes that deny *all* egress unconditionally, regardless of policy
    /// rules. These are the fail-closed isolation postures.
    pub fn denies_all_egress(self) -> bool {
        matches!(self, NetworkMode::None | NetworkMode::Isolated)
    }
}

/// A single egress allow rule. A flow is permitted only if it matches a rule's
/// `proto`, `dst`, and `port`. The wildcards `"*"`/`"any"` (proto, dst) and
/// port `0` (any port) widen a rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct EgressRule {
    /// Transport/application protocol, e.g. `"tcp"`, `"udp"`, or `"*"`.
    pub proto: String,
    /// Destination host/CIDR/literal, or `"*"`/`"any"` for any destination.
    pub dst: String,
    /// Destination port; `0` matches any port.
    pub port: u16,
    /// Human-readable justification for audit (framework §8).
    pub purpose: String,
}

/// A single ingress allow rule. Ingress is denied by default; a flow is
/// permitted only if it matches a rule's `proto`, `src`, and `port`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct IngressRule {
    /// Transport/application protocol, e.g. `"tcp"`, `"udp"`, or `"*"`.
    pub proto: String,
    /// Source host/CIDR/literal, or `"*"`/`"any"` for any source.
    pub src: String,
    /// Destination port; `0` matches any port.
    pub port: u16,
    /// Human-readable justification for audit (framework §8).
    pub purpose: String,
}

/// DNS configuration for the sandbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DnsConfig {
    /// DNS posture, e.g. `"deny"`, `"forward"`, or `"resolver"`.
    pub mode: String,
    /// Permitted upstream resolver addresses.
    pub servers: Vec<String>,
}

/// Returns true if a rule field is a wildcard token.
fn is_wildcard(s: &str) -> bool {
    s == "*" || s.eq_ignore_ascii_case("any")
}

impl EgressRule {
    /// Does this rule match the given flow tuple?
    pub fn matches(&self, proto: &str, dst: &str, port: u16) -> bool {
        (is_wildcard(&self.proto) || self.proto.eq_ignore_ascii_case(proto))
            && (is_wildcard(&self.dst) || self.dst == dst)
            && (self.port == 0 || self.port == port)
    }
}

impl IngressRule {
    /// Does this rule match the given flow tuple?
    pub fn matches(&self, proto: &str, src: &str, port: u16) -> bool {
        (is_wildcard(&self.proto) || self.proto.eq_ignore_ascii_case(proto))
            && (is_wildcard(&self.src) || self.src == src)
            && (self.port == 0 || self.port == port)
    }
}

/// Declarative, deny-by-default network policy document (framework §8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct NetworkPolicy {
    /// Schema version of this document.
    pub schema_version: u32,
    /// Identifier of the VM/sandbox this policy governs.
    pub vm_id: String,
    /// Default posture for unmatched egress: `"deny"` (recommended) or
    /// `"allow"`. Ingress always defaults to deny.
    pub default: String,
    /// Explicit egress allow rules.
    pub egress: Vec<EgressRule>,
    /// Explicit ingress allow rules.
    pub ingress: Vec<IngressRule>,
    /// DNS configuration.
    pub dns: DnsConfig,
}

impl NetworkPolicy {
    /// Parse a [`NetworkPolicy`] from the SOW JSON, validating its schema
    /// version and well-formedness. Fails closed on any error.
    pub fn parse(s: &str) -> Result<Self, NetworkError> {
        let pol: NetworkPolicy = serde_json::from_str(s)?;
        if pol.schema_version != NETWORK_SCHEMA_VERSION {
            return Err(NetworkError::UnsupportedSchema {
                found: pol.schema_version,
                expected: NETWORK_SCHEMA_VERSION,
            });
        }
        match pol.default.as_str() {
            "deny" | "allow" => {}
            other => {
                return Err(NetworkError::InvalidField(format!(
                    "default must be \"deny\" or \"allow\", got {other:?}"
                )));
            }
        }
        Ok(pol)
    }

    /// True if the default posture explicitly permits unmatched egress.
    pub fn default_allows(&self) -> bool {
        self.default == "allow"
    }

    /// First egress rule matching the flow tuple, if any.
    pub fn match_egress(&self, proto: &str, dst: &str, port: u16) -> Option<&EgressRule> {
        self.egress.iter().find(|r| r.matches(proto, dst, port))
    }

    /// First ingress rule matching the flow tuple, if any.
    pub fn match_ingress(&self, proto: &str, src: &str, port: u16) -> Option<&IngressRule> {
        self.ingress.iter().find(|r| r.matches(proto, src, port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn sample_json() -> String {
        r#"{
            "schema_version": 1,
            "vm_id": "vm-001",
            "default": "deny",
            "egress": [
                { "proto": "tcp", "dst": "10.0.0.5", "port": 443, "purpose": "api" },
                { "proto": "udp", "dst": "*", "port": 53, "purpose": "dns" }
            ],
            "ingress": [
                { "proto": "tcp", "src": "10.0.0.1", "port": 22, "purpose": "admin" }
            ],
            "dns": { "mode": "forward", "servers": ["10.0.0.53"] }
        }"#
        .to_string()
    }

    #[test]
    fn parses_happy_document() {
        let p = NetworkPolicy::parse(&sample_json()).expect("parse");
        assert_eq!(p.vm_id, "vm-001");
        assert_eq!(p.default, "deny");
        assert_eq!(p.egress.len(), 2);
        assert_eq!(p.ingress.len(), 1);
        assert_eq!(p.dns.mode, "forward");
        assert_eq!(p.dns.servers, vec!["10.0.0.53".to_string()]);
    }

    #[test]
    fn rejects_bad_schema_version() {
        let j = sample_json().replace("\"schema_version\": 1", "\"schema_version\": 7");
        let err = NetworkPolicy::parse(&j).unwrap_err();
        assert!(matches!(err, NetworkError::UnsupportedSchema { found: 7, .. }));
    }

    #[test]
    fn rejects_bad_default() {
        let j = sample_json().replace("\"deny\"", "\"maybe\"");
        let err = NetworkPolicy::parse(&j).unwrap_err();
        assert!(matches!(err, NetworkError::InvalidField(_)));
    }

    #[test]
    fn rejects_malformed_json() {
        let err = NetworkPolicy::parse("{not json").unwrap_err();
        assert!(matches!(err, NetworkError::Json(_)));
    }

    #[test]
    fn round_trips_via_serde() {
        let p = NetworkPolicy::parse(&sample_json()).unwrap();
        let s = serde_json::to_string(&p).unwrap();
        let back = NetworkPolicy::parse(&s).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn egress_exact_match() {
        let p = NetworkPolicy::parse(&sample_json()).unwrap();
        assert!(p.match_egress("tcp", "10.0.0.5", 443).is_some());
        assert!(p.match_egress("tcp", "10.0.0.5", 80).is_none());
        assert!(p.match_egress("tcp", "1.2.3.4", 443).is_none());
    }

    #[test]
    fn egress_wildcards() {
        let p = NetworkPolicy::parse(&sample_json()).unwrap();
        // udp/*:53 matches any destination on port 53.
        assert!(p.match_egress("udp", "8.8.8.8", 53).is_some());
        assert!(p.match_egress("UDP", "8.8.8.8", 53).is_some());
        assert!(p.match_egress("udp", "8.8.8.8", 54).is_none());
    }

    #[test]
    fn ingress_match() {
        let p = NetworkPolicy::parse(&sample_json()).unwrap();
        assert!(p.match_ingress("tcp", "10.0.0.1", 22).is_some());
        assert!(p.match_ingress("tcp", "10.0.0.2", 22).is_none());
    }

    #[test]
    fn mode_isolation_flags() {
        assert!(NetworkMode::None.denies_all_egress());
        assert!(NetworkMode::Isolated.denies_all_egress());
        assert!(!NetworkMode::Nat.denies_all_egress());
    }

    #[test]
    fn mode_serde_snake_case() {
        let s = serde_json::to_string(&NetworkMode::AttestedOverlay).unwrap();
        assert_eq!(s, "\"attested_overlay\"");
        let m: NetworkMode = serde_json::from_str("\"host_only\"").unwrap();
        assert_eq!(m, NetworkMode::HostOnly);
    }
}
