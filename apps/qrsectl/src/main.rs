//! qrsectl — operator CLI for the QRSE (quantum-resistant storage encryption)
//! control plane (PAD-QRSE-001 §21 prototype flow).
//!
//! Stateless / one-shot, exactly like `hyperctl`: every invocation builds fresh
//! in-memory state from its arguments, runs a single command, prints a
//! deterministic JSON (or short text) result, and exits. There is no network
//! server, no persistence, and no randomness/clock/uuid — all key derivation is
//! routed through `hyper_qrse::combiner::hybrid_combine` and all signature
//! verification through the `hyper_qrse::crypto::Verifier` trait.
//!
//! Fail-closed: any deny/verification-failure exits non-zero.
//!   exit 0  — success / Ok verdict
//!   exit 1  — usage / IO / parse error
//!   exit 2  — manifest verification denied (no valid PQ signature)
//!   exit 3  — downgrade check denied
//!
//! Subcommands:
//!   qrsectl manifest verify <file> --trust <key_id>=<seed> ...
//!   qrsectl manifest inspect <file>
//!   qrsectl combiner demo
//!   qrsectl downgrade check <file> --floor <n> --trust <key_id>=<seed> ...
//!   qrsectl suites
//!
//! Because the bundled crypto core is a *deterministic test stand-in*, signature
//! verification needs the per-key seed that minted the signer; supply it with
//! `--trust <key_id>=<seed>`. Verifiers are reconstructed via the public
//! `crypto::Signer`/`Verifier` traits only — no crypto is reinvented here.

use std::process;

use clap::{Parser, Subcommand};
use serde_json::json;

use hyper_qrse::combiner::{self, CombinerContext, KemSuite};
use hyper_qrse::crypto::{DeterministicKem, DeterministicSigner, Kem, Verifier};
use hyper_qrse::downgrade::{self, DowngradeVerdict, VersionFloor};
use hyper_qrse::keyslot::{Keyslot, KeyslotKind, KeyslotStatus};
use hyper_qrse::manifest::{ManifestError, QrsdManifest};

#[derive(Parser)]
#[command(name = "qrsectl")]
#[command(about = "QRSE control-plane operator CLI (deterministic, fail-closed)")]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// qrsd-v1 disk-manifest commands.
    #[command(subcommand)]
    Manifest(ManifestCmd),
    /// Hybrid classical+PQC KEK combiner demonstrations.
    #[command(subcommand)]
    Combiner(CombinerCmd),
    /// Downgrade-resistance checks.
    #[command(subcommand)]
    Downgrade(DowngradeCmd),
    /// List the supported KEM suite profiles.
    Suites,
}

#[derive(Subcommand)]
enum ManifestCmd {
    /// Parse a qrsd-v1 manifest and verify its signatures (PQ-required).
    Verify {
        /// Path to a qrsd-v1 manifest JSON file.
        file: String,
        /// Trust material `key_id=seed` for a deterministic verifier (repeatable).
        #[arg(long = "trust", value_name = "KEY_ID=SEED")]
        trust: Vec<String>,
    },
    /// Pretty-print the key facts of a qrsd-v1 manifest.
    Inspect {
        /// Path to a qrsd-v1 manifest JSON file.
        file: String,
    },
}

#[derive(Subcommand)]
enum CombinerCmd {
    /// Run both deterministic KEM legs, derive a KEK, and show context binding.
    Demo,
}

#[derive(Subcommand)]
enum DowngradeCmd {
    /// Verify a manifest, then run downgrade::check against a version floor.
    Check {
        /// Path to a qrsd-v1 manifest JSON file.
        file: String,
        /// Lowest acceptable minimum_boot_manifest_version (tenant floor).
        #[arg(long)]
        floor: u64,
        /// Device monotonic counter: highest version previously accepted.
        #[arg(long, default_value_t = 0)]
        counter: u64,
        /// Tolerate a fully classical-only manifest (default: deny).
        #[arg(long, default_value_t = false)]
        allow_classical_only: bool,
        /// Trust material `key_id=seed` for a deterministic verifier (repeatable).
        #[arg(long = "trust", value_name = "KEY_ID=SEED")]
        trust: Vec<String>,
    },
}

/// A CLI error carrying the process exit code to fail-close with.
#[derive(Debug)]
struct CliError {
    code: i32,
    message: String,
}

impl CliError {
    fn usage(message: impl Into<String>) -> Self {
        CliError { code: 1, message: message.into() }
    }
}

/// Lowercase hex encoder (no external dep; deterministic).
fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Whether `alg` is a post-quantum signature algorithm (mirrors manifest.rs).
fn is_pq_signature_alg(alg: &str) -> bool {
    let a = alg.to_ascii_lowercase();
    a.starts_with("ml-dsa") || a.starts_with("slh-dsa")
}

/// Parse `--trust key_id=seed` entries into (key_id, seed) pairs.
fn parse_trust(entries: &[String]) -> Result<Vec<(String, String)>, CliError> {
    entries
        .iter()
        .map(|e| {
            e.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .ok_or_else(|| {
                    CliError::usage(format!("malformed --trust `{e}` (expected key_id=seed)"))
                })
        })
        .collect()
}

/// Owns a verifier so a `&dyn Verifier` slice can be borrowed from it.
struct VerifierHolder(hyper_qrse::crypto::DeterministicVerifier);

/// Reconstruct deterministic verifiers for the signatures present in `m`, using
/// the supplied trust seeds. Only the public Signer/Verifier traits are used.
fn build_verifiers(m: &QrsdManifest, trust: &[(String, String)]) -> Vec<VerifierHolder> {
    let mut out = Vec::new();
    for sig in &m.signatures {
        if let Some((_, seed)) = trust.iter().find(|(k, _)| *k == sig.key_id) {
            // declared_sig_bytes is irrelevant to verification.
            let signer = DeterministicSigner::new(
                sig.algorithm.clone(),
                sig.key_id.clone(),
                seed.as_bytes(),
                1,
            );
            out.push(VerifierHolder(signer.verifier()));
        }
    }
    out
}

fn read_manifest(file: &str) -> Result<QrsdManifest, CliError> {
    let json = std::fs::read_to_string(file)
        .map_err(|e| CliError::usage(format!("cannot read {file}: {e}")))?;
    QrsdManifest::from_json(&json).map_err(|e| CliError::usage(format!("cannot parse {file}: {e}")))
}

fn status_str(s: KeyslotStatus) -> &'static str {
    match s {
        KeyslotStatus::Active => "active",
        KeyslotStatus::DisabledUntilBreakGlass => "disabled_until_break_glass",
        KeyslotStatus::Retired => "retired",
    }
}

fn kind_str(k: &KeyslotKind) -> &'static str {
    match k {
        KeyslotKind::Argon2idPassphrase { .. } => "argon2id_passphrase",
        KeyslotKind::Tpm2Sealed { .. } => "tpm2_sealed",
        KeyslotKind::HybridRemoteKms { .. } => "hybrid_remote_kms",
        KeyslotKind::ThresholdRecovery { .. } => "threshold_recovery",
    }
}

fn keyslot_summary(slot: &Keyslot) -> serde_json::Value {
    let mut v = json!({
        "slot": slot.slot,
        "status": status_str(slot.status),
        "kind": kind_str(&slot.kind),
        "is_hybrid": slot.is_hybrid(),
        "classical_only": slot.classical_only(),
    });
    if let Some(suite) = slot.kem_suite() {
        v["kem_suite"] = json!(suite.canonical());
    }
    v
}

// ---------------------------------------------------------------------------
// Subcommand implementations.
// ---------------------------------------------------------------------------

fn manifest_verify(file: &str, trust: &[String]) -> Result<String, CliError> {
    let m = read_manifest(file)?;
    let trust = parse_trust(trust)?;
    let holders = build_verifiers(&m, &trust);
    let verifiers: Vec<&dyn Verifier> = holders.iter().map(|h| &h.0 as &dyn Verifier).collect();

    let signatures: Vec<serde_json::Value> = m
        .signatures
        .iter()
        .map(|s| {
            json!({
                "purpose": s.purpose,
                "algorithm": s.algorithm,
                "key_id": s.key_id,
                "post_quantum": is_pq_signature_alg(&s.algorithm),
                "have_trust": trust.iter().any(|(k, _)| *k == s.key_id),
            })
        })
        .collect();

    match m.verify(&verifiers) {
        Ok(v) => Ok(serde_json::to_string_pretty(&json!({
            "result": "pq_verified",
            "volume_id": m.volume_id,
            "verified_purposes": v.verified_purposes(),
            "min_boot_manifest_version": v.min_boot_manifest_version(),
            "signatures": signatures,
        }))
        .unwrap()),
        Err(ManifestError::InsufficientPostQuantum) => Err(CliError {
            code: 2,
            message: serde_json::to_string_pretty(&json!({
                "result": "transition_classical_only",
                "denied": true,
                "reason": "manifest is only classically signed; a post-quantum (ml-dsa/slh-dsa) signature is required",
                "volume_id": m.volume_id,
                "signatures": signatures,
            }))
            .unwrap(),
        }),
        Err(e) => Err(CliError {
            code: 2,
            message: serde_json::to_string_pretty(&json!({
                "result": "denied",
                "denied": true,
                "reason": e.to_string(),
                "volume_id": m.volume_id,
                "signatures": signatures,
            }))
            .unwrap(),
        }),
    }
}

fn manifest_inspect(file: &str) -> Result<String, CliError> {
    let m = read_manifest(file)?;
    let keyslots: Vec<serde_json::Value> =
        m.key_hierarchy.keyslots.iter().map(keyslot_summary).collect();
    let signatures: Vec<serde_json::Value> = m
        .signatures
        .iter()
        .map(|s| {
            json!({
                "purpose": s.purpose,
                "algorithm": s.algorithm,
                "key_id": s.key_id,
                "post_quantum": is_pq_signature_alg(&s.algorithm),
            })
        })
        .collect();
    let any_pq = m.signatures.iter().any(|s| is_pq_signature_alg(&s.algorithm));

    Ok(serde_json::to_string_pretty(&json!({
        "format": m.format,
        "volume_id": m.volume_id,
        "created_at": m.created_at,
        "data_plane": {
            "cipher": m.data_plane.cipher,
            "xts_raw_key_bits": m.data_plane.xts_raw_key_bits,
            "sector_size": m.data_plane.sector_size,
            "integrity_mode": m.data_plane.integrity.mode,
        },
        "boot_policy": {
            "policy_id": m.boot_policy.policy_id,
            "secure_boot_required": m.boot_policy.secure_boot_required,
            "measured_boot_required": m.boot_policy.measured_boot_required,
            "pcr_profile": m.boot_policy.pcr_profile,
            "minimum_boot_manifest_version": m.boot_policy.minimum_boot_manifest_version,
        },
        "key_hierarchy": {
            "volume_master_key_version": m.key_hierarchy.volume_master_key_version,
            "active_dek_version": m.key_hierarchy.active_dek_version,
            "keyslots": keyslots,
        },
        "signatures": signatures,
        "carries_pq_signature": any_pq,
    }))
    .unwrap())
}

fn combiner_demo() -> Result<String, CliError> {
    // Run the two deterministic KEM legs (classical + post-quantum).
    let classical = DeterministicKem::x25519();
    let pqc = DeterministicKem::ml_kem_768();

    let (ek_c, _dk_c) = classical.generate_keypair(b"qrsectl-demo-classical");
    let (_ct_c, ss_classical) = classical.encapsulate(&ek_c, b"qrsectl-demo-enc");

    let (ek_p, _dk_p) = pqc.generate_keypair(b"qrsectl-demo-pqc");
    let (_ct_p, ss_pqc) = pqc.encapsulate(&ek_p, b"qrsectl-demo-enc");

    let base_ctx = CombinerContext {
        volume_id: "urn:uuid:vol-demo".into(),
        device_id: "pn52-lab-001".into(),
        policy_id: "policy-prod".into(),
        policy_version: 42,
        algorithm_suite: KemSuite::transition_768(),
        boot_measurement: "sha384:bootmeas-demo".into(),
    };

    let transcript = base_ctx.to_bytes();
    let kek = combiner::hybrid_combine(&ss_classical, &ss_pqc, &transcript, &base_ctx, 32)
        .map_err(|e| CliError::usage(format!("combine failed: {e}")))?;

    // Same secrets but a bumped policy version => a different KEK (downgrade /
    // rebinding resistance via §9.4 context binding).
    let mut bumped_ctx = base_ctx.clone();
    bumped_ctx.policy_version = 43;
    let bumped_transcript = bumped_ctx.to_bytes();
    let kek_bumped =
        combiner::hybrid_combine(&ss_classical, &ss_pqc, &bumped_transcript, &bumped_ctx, 32)
            .map_err(|e| CliError::usage(format!("combine failed: {e}")))?;

    let kek_hex = kek.expose(to_hex);
    let kek_bumped_hex = kek_bumped.expose(to_hex);
    let bound_to_context = kek != kek_bumped;

    Ok(serde_json::to_string_pretty(&json!({
        "combiner": KemSuite::transition_768().combiner,
        "kdf": "hkdf-sha384",
        "classical_leg": classical.algorithm(),
        "pqc_leg": pqc.algorithm(),
        "suite": base_ctx.algorithm_suite.canonical(),
        "kek_len_bytes": kek.len(),
        "kek_policy_v42": kek_hex,
        "kek_policy_v43": kek_bumped_hex,
        "bound_to_context": bound_to_context,
        "note": "changing policy_version (or any context field) yields a different KEK",
    }))
    .unwrap())
}

fn downgrade_check(
    file: &str,
    floor: u64,
    counter: u64,
    allow_classical_only: bool,
    trust: &[String],
) -> Result<String, CliError> {
    let m = read_manifest(file)?;
    let trust = parse_trust(trust)?;
    let holders = build_verifiers(&m, &trust);
    let verifiers: Vec<&dyn Verifier> = holders.iter().map(|h| &h.0 as &dyn Verifier).collect();

    // A downgrade check requires a post-quantum-verified manifest (fail-closed).
    let verified = m.verify(&verifiers).map_err(|e| CliError {
        code: 2,
        message: serde_json::to_string_pretty(&json!({
            "result": "verify_denied",
            "denied": true,
            "reason": e.to_string(),
        }))
        .unwrap(),
    })?;

    let floor_policy = VersionFloor {
        tenant_min_manifest_version: floor,
        require_pqc_signature: true,
        allow_classical_only,
    };
    let verdict = downgrade::check(&verified, &floor_policy, counter);

    let verdict_json = match &verdict {
        DowngradeVerdict::Ok => json!({ "verdict": "ok" }),
        DowngradeVerdict::RejectedStaleVersion { found, floor } => json!({
            "verdict": "rejected_stale_version",
            "found": found,
            "floor": floor,
        }),
        DowngradeVerdict::RejectedClassicalOnly => json!({
            "verdict": "rejected_classical_only",
        }),
        DowngradeVerdict::RejectedSuiteDowngrade { from, to } => json!({
            "verdict": "rejected_suite_downgrade",
            "from": from,
            "to": to,
        }),
    };

    let out = serde_json::to_string_pretty(&json!({
        "volume_id": m.volume_id,
        "tenant_floor": floor,
        "monotonic_counter": counter,
        "allow_classical_only": allow_classical_only,
        "ok": verdict.is_ok(),
        "result": verdict_json,
    }))
    .unwrap();

    if verdict.is_ok() {
        Ok(out)
    } else {
        Err(CliError { code: 3, message: out })
    }
}

fn suites() -> Result<String, CliError> {
    let profiles = [
        ("transition_768", KemSuite::transition_768()),
        ("high_assurance_1024", KemSuite::high_assurance_1024()),
    ];
    let list: Vec<serde_json::Value> = profiles
        .iter()
        .map(|(name, s)| {
            json!({
                "profile": name,
                "classical": s.classical,
                "pqc": s.pqc,
                "combiner": s.combiner,
                "canonical": s.canonical(),
            })
        })
        .collect();
    Ok(serde_json::to_string_pretty(&json!({ "suites": list })).unwrap())
}

fn run() -> Result<String, CliError> {
    let cli = Cli::parse();
    match cli.cmd {
        Command::Manifest(ManifestCmd::Verify { file, trust }) => manifest_verify(&file, &trust),
        Command::Manifest(ManifestCmd::Inspect { file }) => manifest_inspect(&file),
        Command::Combiner(CombinerCmd::Demo) => combiner_demo(),
        Command::Downgrade(DowngradeCmd::Check {
            file,
            floor,
            counter,
            allow_classical_only,
            trust,
        }) => downgrade_check(&file, floor, counter, allow_classical_only, &trust),
        Command::Suites => suites(),
    }
}

fn main() {
    match run() {
        Ok(out) => println!("{out}"),
        Err(CliError { code, message }) => {
            eprintln!("{message}");
            process::exit(code);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper_qrse::keyslot::{Argon2idKdf, KmsAttestation, WrapSpec};
    use hyper_qrse::manifest::{
        Audit, BootPolicy, DataPlane, Integrity, ManifestKeyHierarchy, RollbackProtection,
        QRSD_FORMAT,
    };

    const SEED: &[u8] = b"qrsectl-test-seed";

    fn fixture_manifest(hybrid: bool, min_boot_version: u64) -> QrsdManifest {
        let mut keyslots = vec![Keyslot::new(
            0,
            KeyslotStatus::Active,
            KeyslotKind::Argon2idPassphrase {
                kdf: Argon2idKdf {
                    algorithm: "argon2id".into(),
                    memory_kib: 1_048_576,
                    time_cost: 3,
                    parallelism: 4,
                },
                wrap: WrapSpec {
                    algorithm: "aes-256-gcm".into(),
                    wrapped_key_ref: "blob:slot0".into(),
                },
            },
        )];
        if hybrid {
            keyslots.push(Keyslot::new(
                2,
                KeyslotStatus::Active,
                KeyslotKind::HybridRemoteKms {
                    kem: KemSuite::transition_768(),
                    attestation: KmsAttestation {
                        required: true,
                        accepted_tee: vec!["amd-sev-snp".into()],
                        measurement_policy_ref: "pol-meas-v3".into(),
                    },
                },
            ));
        }
        QrsdManifest {
            format: QRSD_FORMAT.to_string(),
            volume_id: "urn:uuid:vol-test".into(),
            created_at: "2026-06-27T00:00:00Z".into(),
            data_plane: DataPlane {
                cipher: "AES-256-XTS".into(),
                xts_raw_key_bits: 512,
                sector_size: 4096,
                integrity: Integrity {
                    mode: "none".into(),
                    alternatives: vec![],
                },
            },
            boot_policy: BootPolicy {
                policy_id: "pol-boot-v4".into(),
                secure_boot_required: true,
                measured_boot_required: true,
                pcr_profile: vec!["pcr0".into(), "pcr7".into(), "pcr11".into()],
                minimum_boot_manifest_version: min_boot_version,
                rollback_protection: RollbackProtection {
                    type_: "tpm-nv-counter".into(),
                    counter_name: "qrsd.rollback".into(),
                },
            },
            key_hierarchy: ManifestKeyHierarchy {
                volume_master_key_version: 3,
                active_dek_version: 11,
                keyslots,
            },
            signatures: vec![],
            audit: Audit {
                last_rotation: "2026-06-01T00:00:00Z".into(),
                last_attested_unlock_receipt: "rcpt-000000-aaaaaaaaaaaaaaaa".into(),
                log_chain: "sha384:chainhead".into(),
            },
        }
    }

    /// Write a PQ-signed manifest to the scratchpad and return its path.
    fn write_pq_manifest(name: &str, hybrid: bool, min_boot_version: u64) -> String {
        let mut m = fixture_manifest(hybrid, min_boot_version);
        let signer = DeterministicSigner::ml_dsa_65("disk-pq", SEED);
        m.sign(&signer, "disk-manifest");
        let dir = std::env::temp_dir().join("qrsectl-tests");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, m.to_json().unwrap()).unwrap();
        path.to_string_lossy().into_owned()
    }

    fn write_classical_manifest(name: &str) -> String {
        let mut m = fixture_manifest(true, 7);
        let signer = DeterministicSigner::ecdsa_p384("disk-classical", SEED);
        m.sign(&signer, "classical-compat");
        let dir = std::env::temp_dir().join("qrsectl-tests");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, m.to_json().unwrap()).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn suites_lists_both_profiles() {
        let out = suites().unwrap();
        assert!(out.contains("transition_768"));
        assert!(out.contains("high_assurance_1024"));
        assert!(out.contains("x25519+ml-kem-768+hkdf-sha384"));
    }

    #[test]
    fn combiner_demo_is_bound_to_context() {
        let out = combiner_demo().unwrap();
        assert!(out.contains("\"kek_len_bytes\": 32"));
        assert!(out.contains("\"bound_to_context\": true"));
        // Deterministic: two runs are byte-identical.
        assert_eq!(out, combiner_demo().unwrap());
    }

    #[test]
    fn parse_trust_rejects_malformed() {
        assert!(parse_trust(&["no-equals-sign".to_string()]).is_err());
        let ok = parse_trust(&["disk-pq=seed".to_string()]).unwrap();
        assert_eq!(ok, vec![("disk-pq".to_string(), "seed".to_string())]);
    }

    #[test]
    fn is_pq_signature_alg_classifies() {
        assert!(is_pq_signature_alg("ml-dsa-65"));
        assert!(is_pq_signature_alg("SLH-DSA-128s"));
        assert!(!is_pq_signature_alg("ecdsa-p384"));
    }

    #[test]
    fn manifest_verify_happy_path_pq() {
        let path = write_pq_manifest("verify-ok.json", true, 7);
        let out = manifest_verify(&path, &["disk-pq=qrsectl-test-seed".to_string()]).unwrap();
        assert!(out.contains("\"result\": \"pq_verified\""));
        assert!(out.contains("disk-manifest"));
    }

    #[test]
    fn manifest_verify_without_trust_fails_closed() {
        let path = write_pq_manifest("verify-notrust.json", true, 7);
        let err = manifest_verify(&path, &[]).unwrap_err();
        assert_eq!(err.code, 2);
    }

    #[test]
    fn manifest_verify_classical_only_denied() {
        let path = write_classical_manifest("verify-classical.json");
        let err =
            manifest_verify(&path, &["disk-classical=qrsectl-test-seed".to_string()]).unwrap_err();
        assert_eq!(err.code, 2);
        assert!(err.message.contains("transition_classical_only"));
    }

    #[test]
    fn manifest_inspect_reports_facts() {
        let path = write_pq_manifest("inspect.json", true, 7);
        let out = manifest_inspect(&path).unwrap();
        assert!(out.contains("AES-256-XTS"));
        assert!(out.contains("hybrid_remote_kms"));
        assert!(out.contains("x25519+ml-kem-768+hkdf-sha384"));
        assert!(out.contains("\"carries_pq_signature\": true"));
    }

    #[test]
    fn downgrade_check_ok() {
        let path = write_pq_manifest("dg-ok.json", true, 7);
        let out =
            downgrade_check(&path, 7, 5, false, &["disk-pq=qrsectl-test-seed".to_string()]).unwrap();
        assert!(out.contains("\"ok\": true"));
    }

    #[test]
    fn downgrade_check_rejects_stale_version() {
        let path = write_pq_manifest("dg-stale.json", true, 4);
        let err = downgrade_check(&path, 7, 0, false, &["disk-pq=qrsectl-test-seed".to_string()])
            .unwrap_err();
        assert_eq!(err.code, 3);
        assert!(err.message.contains("rejected_stale_version"));
    }

    #[test]
    fn downgrade_check_rejects_classical_only_path() {
        // A hybrid-free manifest that is still PQ-signed: no PQC unlock path.
        let path = write_pq_manifest("dg-classical.json", false, 7);
        let err = downgrade_check(&path, 7, 0, false, &["disk-pq=qrsectl-test-seed".to_string()])
            .unwrap_err();
        assert_eq!(err.code, 3);
        assert!(err.message.contains("rejected_classical_only"));
    }
}
