//! Hash-chained security-event log (`chain.security_event.v1`, backlog S0).
//!
//! Independent of the audit-receipt spine but built on the same SHA-384 hash
//! chain. Records component-level security events with structured fields.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::hash::{genesis_hash, sha384_hex};

/// JSON schema identifier carried by every [`SecurityEvent`].
pub const SECURITY_EVENT_SCHEMA: &str = "chain.security_event.v1";

fn default_security_schema() -> String {
    SECURITY_EVENT_SCHEMA.to_string()
}

/// Severity ladder for security events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Stable snake_case wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// A single hash-chained security event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct SecurityEvent {
    #[serde(default = "default_security_schema")]
    pub schema: String,
    pub event_id: String,
    pub severity: Severity,
    pub component: String,
    pub event: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vm_id: Option<String>,
    pub action: String,
    pub fields: BTreeMap<String, String>,
    pub hash_prev: String,
    pub hash_this: String,
}

/// Canonical, ordered subset that `hash_this` commits to (everything but the
/// `event_id` and `hash_this` itself).
#[derive(Serialize)]
struct SecurityCanonical<'a> {
    schema: &'a str,
    severity: Severity,
    component: &'a str,
    event: &'a str,
    vm_id: &'a Option<String>,
    action: &'a str,
    fields: &'a BTreeMap<String, String>,
    hash_prev: &'a str,
}

#[allow(clippy::too_many_arguments)]
fn compute_security_hash(
    schema: &str,
    severity: Severity,
    component: &str,
    event: &str,
    vm_id: &Option<String>,
    action: &str,
    fields: &BTreeMap<String, String>,
    hash_prev: &str,
) -> String {
    let canonical = SecurityCanonical {
        schema,
        severity,
        component,
        event,
        vm_id,
        action,
        fields,
        hash_prev,
    };
    let bytes = serde_json::to_vec(&canonical).expect("canonical security event serializes");
    sha384_hex(&bytes)
}

/// Errors raised while verifying or rehydrating a [`SecurityLog`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SecurityLogError {
    #[error("event {index} has wrong schema: expected {expected}, found {found}")]
    BadSchema {
        index: usize,
        expected: String,
        found: String,
    },
    #[error("event {index} hash mismatch: expected {expected}, found {found}")]
    HashMismatch {
        index: usize,
        expected: String,
        found: String,
    },
    #[error("event {index} broken link: hash_prev {found} != {expected}")]
    BrokenLink {
        index: usize,
        expected: String,
        found: String,
    },
    #[error("json error: {0}")]
    Json(String),
}

/// An append-only, hash-chained security-event log.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct SecurityLog {
    genesis_hash: String,
    events: Vec<SecurityEvent>,
}

impl Default for SecurityLog {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityLog {
    /// Create an empty log anchored to the fixed genesis hash.
    pub fn new() -> Self {
        SecurityLog {
            genesis_hash: genesis_hash(),
            events: Vec::new(),
        }
    }

    /// Hash that the first appended event links back to.
    pub fn genesis_hash(&self) -> &str {
        &self.genesis_hash
    }

    /// Hash of the most recent event, or the genesis hash if empty.
    pub fn head_hash(&self) -> &str {
        match self.events.last() {
            Some(e) => &e.hash_this,
            None => &self.genesis_hash,
        }
    }

    /// Append a security event, computing `hash_this` and linking `hash_prev`.
    pub fn append(
        &mut self,
        severity: Severity,
        component: impl Into<String>,
        event: impl Into<String>,
        vm_id: Option<String>,
        action: impl Into<String>,
        fields: BTreeMap<String, String>,
    ) -> &SecurityEvent {
        let schema = SECURITY_EVENT_SCHEMA.to_string();
        let component = component.into();
        let event = event.into();
        let action = action.into();
        let hash_prev = self.head_hash().to_string();

        let hash_this = compute_security_hash(
            &schema, severity, &component, &event, &vm_id, &action, &fields, &hash_prev,
        );

        let index = self.events.len();
        let hex_part = hash_this.strip_prefix("sha384:").unwrap_or(&hash_this);
        let event_id = format!("sec-{index:06}-{}", &hex_part[..16]);

        self.events.push(SecurityEvent {
            schema,
            event_id,
            severity,
            component,
            event,
            vm_id,
            action,
            fields,
            hash_prev,
            hash_this,
        });
        self.events.last().expect("just pushed an event")
    }

    /// All events in append order.
    pub fn events(&self) -> &[SecurityEvent] {
        &self.events
    }

    /// Number of events in the log.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether the log holds no events.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Recompute every event hash and verify all prev-links. Fails closed.
    pub fn verify(&self) -> Result<(), SecurityLogError> {
        let mut expected_prev = self.genesis_hash.clone();
        for (index, e) in self.events.iter().enumerate() {
            if e.schema != SECURITY_EVENT_SCHEMA {
                return Err(SecurityLogError::BadSchema {
                    index,
                    expected: SECURITY_EVENT_SCHEMA.to_string(),
                    found: e.schema.clone(),
                });
            }
            if e.hash_prev != expected_prev {
                return Err(SecurityLogError::BrokenLink {
                    index,
                    expected: expected_prev,
                    found: e.hash_prev.clone(),
                });
            }
            let recomputed = compute_security_hash(
                &e.schema,
                e.severity,
                &e.component,
                &e.event,
                &e.vm_id,
                &e.action,
                &e.fields,
                &e.hash_prev,
            );
            if recomputed != e.hash_this {
                return Err(SecurityLogError::HashMismatch {
                    index,
                    expected: recomputed,
                    found: e.hash_this.clone(),
                });
            }
            expected_prev = e.hash_this.clone();
        }
        Ok(())
    }

    /// Serialize the log to pretty JSON.
    pub fn to_json(&self) -> Result<String, SecurityLogError> {
        serde_json::to_string_pretty(self).map_err(|e| SecurityLogError::Json(e.to_string()))
    }

    /// Rehydrate a log from JSON. Call [`SecurityLog::verify`] afterwards.
    pub fn from_json(s: &str) -> Result<Self, SecurityLogError> {
        serde_json::from_str(s).map_err(|e| SecurityLogError::Json(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn populate(log: &mut SecurityLog) {
        log.append(
            Severity::Low,
            "boot",
            "measured_boot_ok",
            None,
            "log",
            fields(&[("pcr", "0")]),
        );
        log.append(
            Severity::High,
            "attest",
            "manifest_signature_invalid",
            Some("vm-1".to_string()),
            "deny",
            fields(&[("key_id", "k1"), ("reason", "bad_sig")]),
        );
        log.append(
            Severity::Critical,
            "vm",
            "vm_exit_fault",
            Some("vm-1".to_string()),
            "quarantine",
            fields(&[("fault", "triple")]),
        );
    }

    #[test]
    fn empty_log_verifies() {
        let log = SecurityLog::new();
        assert!(log.is_empty());
        assert_eq!(log.head_hash(), log.genesis_hash());
        assert_eq!(log.verify(), Ok(()));
    }

    #[test]
    fn append_links_and_verifies() {
        let mut log = SecurityLog::new();
        populate(&mut log);
        assert_eq!(log.len(), 3);
        assert_eq!(log.events()[0].hash_prev, *log.genesis_hash());
        for w in log.events().windows(2) {
            assert_eq!(w[1].hash_prev, w[0].hash_this);
        }
        assert_eq!(log.verify(), Ok(()));
        // schema + severity wire form sanity.
        assert_eq!(log.events()[1].schema, SECURITY_EVENT_SCHEMA);
        assert_eq!(log.events()[2].severity.as_str(), "critical");
    }

    #[test]
    fn deterministic_event_ids() {
        let mut a = SecurityLog::new();
        let mut b = SecurityLog::new();
        populate(&mut a);
        populate(&mut b);
        let ids_a: Vec<_> = a.events().iter().map(|e| e.event_id.clone()).collect();
        let ids_b: Vec<_> = b.events().iter().map(|e| e.event_id.clone()).collect();
        assert_eq!(ids_a, ids_b);
        assert!(ids_a[0].starts_with("sec-000000-"));
    }

    #[test]
    fn tamper_middle_event_fails() {
        let mut log = SecurityLog::new();
        populate(&mut log);
        assert_eq!(log.verify(), Ok(()));

        log.events[1].action = "allow".to_string();
        match log.verify() {
            Err(SecurityLogError::HashMismatch { index, .. }) => assert_eq!(index, 1),
            other => panic!("expected HashMismatch at 1, got {other:?}"),
        }
    }

    #[test]
    fn tamper_fields_detected() {
        let mut log = SecurityLog::new();
        populate(&mut log);
        log.events[2]
            .fields
            .insert("fault".to_string(), "double".to_string());
        assert!(matches!(
            log.verify(),
            Err(SecurityLogError::HashMismatch { index: 2, .. })
        ));
    }

    #[test]
    fn rehash_breaks_next_link() {
        let mut log = SecurityLog::new();
        populate(&mut log);
        let e = &mut log.events[0];
        e.component = "spoof".to_string();
        e.hash_this = compute_security_hash(
            &e.schema,
            e.severity,
            &e.component,
            &e.event,
            &e.vm_id,
            &e.action,
            &e.fields,
            &e.hash_prev,
        );
        assert!(matches!(
            log.verify(),
            Err(SecurityLogError::BrokenLink { index: 1, .. })
        ));
    }

    #[test]
    fn bad_schema_fails() {
        let mut log = SecurityLog::new();
        populate(&mut log);
        log.events[0].schema = "x".to_string();
        assert!(matches!(
            log.verify(),
            Err(SecurityLogError::BadSchema { index: 0, .. })
        ));
    }

    #[test]
    fn json_round_trip() {
        let mut log = SecurityLog::new();
        populate(&mut log);
        let json = log.to_json().unwrap();
        let restored = SecurityLog::from_json(&json).unwrap();
        assert_eq!(restored, log);
        assert_eq!(restored.verify(), Ok(()));
    }
}
