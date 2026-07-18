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
    let mut map = serde_json::Map::with_capacity(fields.len() + 3);
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
    let Ok(mut line) = serde_json::to_string(&serde_json::Value::Object(map)) else {
        return;
    };
    line.push('\n');

    // Best-effort append under the process-wide write lock. Never propagate errors:
    // an audit-sink failure must not affect the request being served.
    let _guard = write_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    // Self-maintaining: rotate the sink by size before appending so it can never
    // grow without bound. Rotation failure is non-fatal — we still try to append.
    let max_bytes = audit_log_max_bytes();
    if max_bytes > 0 {
        if let Err(e) =
            sloc_core::rotate_log(std::path::Path::new(path), max_bytes, audit_log_keep())
        {
            tracing::error!(target: "audit", error = %e, path = %path,
                "failed to rotate audit log");
        }
    }

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
}
