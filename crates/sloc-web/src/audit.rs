// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Nima Shafie <nimzshafie@gmail.com>
#![allow(clippy::redundant_pub_crate)]

//! Structured security audit logging for SIEM ingestion.
//!
//! Every security-relevant event — authentication success/failure, session
//! lifecycle (login/logout), lockout, and unauthenticated-server refusals — is
//! emitted through [`record`], which:
//!
//! 1. Always emits a structured `tracing` event on the `audit` target so it flows
//!    into whatever subscriber the operator has configured (stdout, journald, …).
//! 2. When `SLOC_AUDIT_LOG=<path>` is set, additionally appends the event as a
//!    single JSON line (JSONL) to that file. JSONL is the lingua franca of SIEM
//!    ingestion (Splunk, Elastic/Logstash, Sentinel, Loki) — one self-describing
//!    record per line, tail-and-ship friendly.
//!
//! The JSON sink is deliberately append-only and best-effort: a failure to write
//! an audit line must never take down a request, so write errors are swallowed
//! after a single `tracing::error!`. Writes are serialised through a process-wide
//! mutex so concurrent requests cannot interleave partial lines.

use std::{
    fs::OpenOptions,
    io::Write as _,
    sync::{Mutex, OnceLock},
};

/// Serialises concurrent appends to the audit file so lines never interleave.
fn write_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Path of the JSONL audit sink, if `SLOC_AUDIT_LOG` is configured and non-empty.
fn audit_log_path() -> Option<String> {
    std::env::var("SLOC_AUDIT_LOG")
        .ok()
        .filter(|s| !s.trim().is_empty())
}

/// Size cap (bytes) that triggers rotation of the audit log. `SLOC_AUDIT_LOG_MAX_BYTES`
/// takes precedence (byte-precise, for fine tuning); otherwise `SLOC_AUDIT_LOG_MAX_MB`
/// (default 10 MB) is used. `0` from either disables rotation (grow forever).
fn audit_log_max_bytes() -> u64 {
    if let Some(bytes) = std::env::var("SLOC_AUDIT_LOG_MAX_BYTES")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        return bytes;
    }
    std::env::var("SLOC_AUDIT_LOG_MAX_MB")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(10)
        * 1024
        * 1024
}

/// Number of rotated generations to keep, from `SLOC_AUDIT_LOG_KEEP` (default 5).
fn audit_log_keep() -> u32 {
    std::env::var("SLOC_AUDIT_LOG_KEEP")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(5)
}

/// Marker used as the `prev` link of the very first record in a chain.
const AUDIT_CHAIN_GENESIS: &str = "genesis";

/// The keyed-integrity secret from `SLOC_AUDIT_HMAC_KEY`, if configured and
/// non-empty. When present, every appended record is hash-chained (tamper-evident);
/// when absent, the record format is byte-for-byte identical to the legacy log.
fn audit_hmac_key() -> Option<String> {
    std::env::var("SLOC_AUDIT_HMAC_KEY")
        .ok()
        .filter(|s| !s.is_empty())
}

/// In-memory chain tip (the `mac` of the last record written this process). Guarded
/// so the chain advances in the same order as the file appends. Seeded lazily from
/// the existing log so the chain survives restarts.
fn chain_last() -> &'static Mutex<Option<String>> {
    static L: OnceLock<Mutex<Option<String>>> = OnceLock::new();
    L.get_or_init(|| Mutex::new(None))
}

/// Recover the chain tip (last record's `mac`) from an existing log so a restart
/// continues the same chain. Returns the genesis marker when the file is absent,
/// empty, or its last record is not part of a chain.
fn seed_prev_from_file(path: &str) -> String {
    let Ok(contents) = std::fs::read_to_string(path) else {
        return AUDIT_CHAIN_GENESIS.to_owned();
    };
    for line in contents.lines().rev() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(serde_json::Value::Object(obj)) = serde_json::from_str::<serde_json::Value>(line)
            && let Some(serde_json::Value::String(mac)) = obj.get("mac")
        {
            return mac.clone();
        }
        break;
    }
    AUDIT_CHAIN_GENESIS.to_owned()
}

/// Record one security audit event.
///
/// * `event`   — stable machine-readable event name (e.g. `auth_failure`).
/// * `outcome` — one of `success`, `failure`, `denied`, `warning`.
/// * `fields`  — additional key/value context (peer IP, path, method, reason …).
///
/// Emits a structured `tracing` event always, and appends a JSON line to the
/// `SLOC_AUDIT_LOG` file when configured.
pub(crate) fn record(event: &str, outcome: &str, fields: &[(&str, &str)]) {
    // Structured tracing: one event per security decision, on the `audit` target.
    tracing::info!(
        target: "audit",
        event,
        outcome,
        fields = ?fields,
        "security audit event"
    );

    if let Some(path) = audit_log_path() {
        append_json_line(&path, event, outcome, fields);
    }
}

/// Format one event as a JSON line and append it to `path`. Split out from
/// [`record`] so it is directly testable with an explicit path, without touching
/// the process-global `SLOC_AUDIT_LOG` env var (which would race across threads).
fn append_json_line(path: &str, event: &str, outcome: &str, fields: &[(&str, &str)]) {
    // Best-effort append under the process-wide write lock. Never propagate errors:
    // an audit-sink failure must not affect the request being served. The lock is
    // taken first so the (optional) hash-chain state and the file writes advance in
    // the same order.
    let _guard = write_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    // Self-maintaining: rotate the sink by size before appending so it can never
    // grow without bound. Rotation failure is non-fatal — we still try to append.
    let max_bytes = audit_log_max_bytes();
    if max_bytes > 0
        && let Err(e) =
            sloc_core::rotate_log(std::path::Path::new(path), max_bytes, audit_log_keep())
    {
        tracing::error!(target: "audit", error = %e, path = %path,
                "failed to rotate audit log");
    }

    let mut map = serde_json::Map::with_capacity(fields.len() + 5);
    map.insert(
        "ts".to_owned(),
        serde_json::Value::String(chrono::Utc::now().to_rfc3339()),
    );
    map.insert(
        "event".to_owned(),
        serde_json::Value::String(event.to_owned()),
    );
    map.insert(
        "outcome".to_owned(),
        serde_json::Value::String(outcome.to_owned()),
    );
    for (k, v) in fields {
        map.insert((*k).to_owned(), serde_json::Value::String((*v).to_owned()));
    }

    // Opt-in tamper-evidence: when SLOC_AUDIT_HMAC_KEY is set, chain each record to
    // the previous one with a keyed HMAC-SHA256 so any edit, reorder, or truncation
    // of the log becomes detectable. The MAC covers the record including its `prev`
    // link but excluding `mac` itself. Absent the key, nothing below runs and the
    // record is identical to the legacy format.
    if let Some(key) = audit_hmac_key() {
        let mut last = chain_last()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if last.is_none() {
            *last = Some(seed_prev_from_file(path));
        }
        let prev = last
            .clone()
            .unwrap_or_else(|| AUDIT_CHAIN_GENESIS.to_owned());
        map.insert("prev".to_owned(), serde_json::Value::String(prev));
        let Ok(body) = serde_json::to_string(&serde_json::Value::Object(map.clone())) else {
            return;
        };
        let mac = sloc_git::hmac_sha256_hex(key.as_bytes(), body.as_bytes());
        map.insert("mac".to_owned(), serde_json::Value::String(mac.clone()));
        *last = Some(mac);
    }

    let Ok(mut line) = serde_json::to_string(&serde_json::Value::Object(map)) else {
        return;
    };
    line.push('\n');

    match OpenOptions::new().create(true).append(true).open(path) {
        Ok(mut f) => {
            if let Err(e) = f.write_all(line.as_bytes()) {
                tracing::error!(target: "audit", error = %e, path = %path,
                    "failed to write audit log line");
            }
        }
        Err(e) => {
            tracing::error!(target: "audit", error = %e, path = %path,
                "failed to open audit log file");
        }
    }
}

/// Outcome of verifying a tamper-evident audit log.
#[derive(Debug)]
pub struct AuditVerifyReport {
    /// Number of records inspected (up to and including any failure).
    pub records: usize,
    /// True when the whole chain verified.
    pub ok: bool,
    /// 1-based line number of the first broken record, if any.
    pub first_bad_line: Option<usize>,
    /// Human-readable detail of the first failure, if any.
    pub detail: Option<String>,
}

fn verify_failure(records: usize, line: usize, msg: &str) -> AuditVerifyReport {
    AuditVerifyReport {
        records,
        ok: false,
        first_bad_line: Some(line),
        detail: Some(msg.to_owned()),
    }
}

/// Verify a hash-chained audit log written with `SLOC_AUDIT_HMAC_KEY`.
///
/// Walks every JSON line, recomputes each record's keyed MAC, and checks the
/// `prev` linkage forms an unbroken chain from the genesis marker. Returns the
/// first line that fails, so an operator can pinpoint tampering.
///
/// # Errors
///
/// Never returns `Err`; read/parse problems are reported via the returned
/// [`AuditVerifyReport`] (`ok == false`).
#[must_use]
pub fn verify_audit_file(path: &std::path::Path, key: &str) -> AuditVerifyReport {
    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            return AuditVerifyReport {
                records: 0,
                ok: false,
                first_bad_line: None,
                detail: Some(format!("cannot read log: {e}")),
            };
        }
    };
    let mut expected_prev = AUDIT_CHAIN_GENESIS.to_owned();
    let mut records = 0usize;
    for (idx, raw) in contents.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        records += 1;
        let lineno = idx + 1;
        let Ok(serde_json::Value::Object(mut obj)) =
            serde_json::from_str::<serde_json::Value>(line)
        else {
            return verify_failure(records, lineno, "line is not a JSON object");
        };
        let Some(serde_json::Value::String(stored_mac)) = obj.remove("mac") else {
            return verify_failure(records, lineno, "record has no `mac` (not a chained log?)");
        };
        let Some(serde_json::Value::String(prev)) = obj.get("prev").cloned() else {
            return verify_failure(records, lineno, "record has no `prev` link");
        };
        if prev != expected_prev {
            return verify_failure(
                records,
                lineno,
                "prev-hash does not match previous record (chain broken)",
            );
        }
        let Ok(body) = serde_json::to_string(&serde_json::Value::Object(obj)) else {
            return verify_failure(records, lineno, "re-serialisation failed");
        };
        let recomputed = sloc_git::hmac_sha256_hex(key.as_bytes(), body.as_bytes());
        if recomputed != stored_mac {
            return verify_failure(records, lineno, "MAC mismatch (record was modified)");
        }
        expected_prev = stored_mac;
    }
    AuditVerifyReport {
        records,
        ok: true,
        first_bad_line: None,
        detail: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_does_not_panic() {
        // Smoke test: the public entry point must never panic regardless of whether
        // a sink is configured (it reads the process-global env var, so it makes no
        // assertions about file contents — that is covered below via append_json_line).
        record("unit_test_event", "success", &[("k", "v")]);
    }

    #[test]
    fn append_json_line_writes_one_record_per_event() {
        // Uses an explicit unique path (no global env) so it is race-free under the
        // parallel test runner.
        let dir = std::env::temp_dir().join("sloc_audit_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join(format!("audit-{}.log", uuid::Uuid::new_v4()));
        let path_str = path.to_string_lossy().into_owned();

        append_json_line(
            &path_str,
            "auth_failure",
            "failure",
            &[("peer_ip", "10.0.0.9"), ("path", "/analyze")],
        );
        append_json_line(
            &path_str,
            "auth_success",
            "success",
            &[("peer_ip", "10.0.0.9")],
        );

        let contents = std::fs::read_to_string(&path).expect("audit file written");
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2, "one JSON line per event");

        let first: serde_json::Value =
            serde_json::from_str(lines[0]).expect("each line is valid JSON");
        assert_eq!(first["event"], "auth_failure");
        assert_eq!(first["outcome"], "failure");
        assert_eq!(first["peer_ip"], "10.0.0.9");
        assert_eq!(first["path"], "/analyze");
        assert!(
            first["ts"].is_string(),
            "record carries an RFC3339 timestamp"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// Build one chained JSON line exactly the way `append_json_line` does, so the
    /// verifier can be exercised without touching the process-global chain state or
    /// the `SLOC_AUDIT_HMAC_KEY` env var (both of which would race under the parallel
    /// test runner). Returns `(line, mac)`.
    fn build_chained_line(
        key: &str,
        prev: &str,
        ts: &str,
        event: &str,
        outcome: &str,
        extra: &[(&str, &str)],
    ) -> (String, String) {
        let mut map = serde_json::Map::new();
        map.insert("ts".to_owned(), serde_json::Value::String(ts.to_owned()));
        map.insert(
            "event".to_owned(),
            serde_json::Value::String(event.to_owned()),
        );
        map.insert(
            "outcome".to_owned(),
            serde_json::Value::String(outcome.to_owned()),
        );
        for (k, v) in extra {
            map.insert((*k).to_owned(), serde_json::Value::String((*v).to_owned()));
        }
        map.insert(
            "prev".to_owned(),
            serde_json::Value::String(prev.to_owned()),
        );
        let body = serde_json::to_string(&serde_json::Value::Object(map.clone())).unwrap();
        let mac = sloc_git::hmac_sha256_hex(key.as_bytes(), body.as_bytes());
        map.insert("mac".to_owned(), serde_json::Value::String(mac.clone()));
        let line = serde_json::to_string(&serde_json::Value::Object(map)).unwrap();
        (line, mac)
    }

    #[test]
    fn verify_accepts_intact_chain_and_flags_tampering() {
        let key = "unit-test-audit-key";
        let (l1, m1) = build_chained_line(
            key,
            AUDIT_CHAIN_GENESIS,
            "2026-07-20T00:00:00+00:00",
            "login_success",
            "success",
            &[("peer_ip", "10.0.0.1")],
        );
        let (l2, _m2) = build_chained_line(
            key,
            &m1,
            "2026-07-20T00:00:01+00:00",
            "auth_failure",
            "failure",
            &[("peer_ip", "10.0.0.2")],
        );

        let dir = std::env::temp_dir().join("sloc_audit_chain_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join(format!("chain-{}.log", uuid::Uuid::new_v4()));

        // Intact chain verifies.
        std::fs::write(&path, format!("{l1}\n{l2}\n")).unwrap();
        let ok = verify_audit_file(&path, key);
        assert!(ok.ok, "intact chain must verify: {ok:?}");
        assert_eq!(ok.records, 2);

        // Editing a record's outcome breaks its MAC and is caught at that line.
        let tampered = format!("{}\n{l2}\n", l1.replace("success", "denied"));
        std::fs::write(&path, tampered).unwrap();
        let bad = verify_audit_file(&path, key);
        assert!(!bad.ok, "tampered record must fail verification");
        assert_eq!(bad.first_bad_line, Some(1));

        // Deleting the first record breaks the second's prev linkage.
        std::fs::write(&path, format!("{l2}\n")).unwrap();
        let broken = verify_audit_file(&path, key);
        assert!(!broken.ok, "removed record must break the chain");
        assert_eq!(broken.first_bad_line, Some(1));

        let _ = std::fs::remove_file(&path);
    }
}
