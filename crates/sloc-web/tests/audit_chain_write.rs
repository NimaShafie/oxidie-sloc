// Coverage for the hash-chained audit *writer* path, driven through the router's
// audit hook. When SLOC_AUDIT_LOG + SLOC_AUDIT_HMAC_KEY are set, a security event
// (here: a failed authentication) appends a tamper-evident record — exercising
// seed_prev_from_file (recovering the chain tip from an existing log) and the
// HMAC-chaining branch of append_json_line, both private and reachable only via
// audit::record on the server path.
//
// Single test on purpose: the audit writer keeps a process-global chain tip, so we
// avoid intra-file parallelism. This file is its own test binary, so the env vars
// it sets cannot leak into other test files.

use std::sync::Once;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::Value;
use sloc_web::make_test_router_with_key;
use tower::ServiceExt;

/// Send one request with the WRONG key: an authentication failure that routes
/// through the audit hook.
async fn fail_auth() {
    let resp = make_test_router_with_key("the-real-key")
        .oneshot(
            Request::get("/api-docs")
                .header(header::ACCEPT, "application/json")
                .header(header::AUTHORIZATION, "Bearer definitely-wrong-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(resp.status(), StatusCode::OK);
    let _ = resp.into_body().collect().await;
}

/// Parse the non-blank lines of the audit log into JSON records.
fn records(log: &std::path::Path) -> Vec<Value> {
    std::fs::read_to_string(log)
        .expect("audit log readable")
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("line is JSON"))
        .collect()
}

fn mac(rec: &Value) -> String {
    rec.get("mac")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned()
}

#[tokio::test]
async fn failed_auth_appends_a_chained_record_seeded_from_the_existing_log() {
    static INIT: Once = Once::new();

    let dir = std::env::temp_dir().join(format!("sloc-audit-chain-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.join("audit.jsonl");

    // Pre-existing chained record: its `mac` is the tip seed_prev_from_file must
    // recover and link the next record's `prev` to.
    let seed_mac = "seedmac0000000000000000000000000000000000000000000000000000000001";
    std::fs::write(
        &log,
        format!("{{\"ts\":\"2026-07-20T00:00:00+00:00\",\"event\":\"seed\",\"outcome\":\"success\",\"mac\":\"{seed_mac}\"}}\n"),
    )
    .unwrap();

    INIT.call_once(|| {
        // FIXME: Audit that the environment access only happens in single-threaded code.
        unsafe { std::env::set_var("SLOC_AUDIT_LOG", log.to_string_lossy().to_string()) };
        // FIXME: Audit that the environment access only happens in single-threaded code.
        unsafe { std::env::set_var("SLOC_AUDIT_HMAC_KEY", "chain-test-key") };
    });

    // A request with the WRONG key is an authentication failure → audit::record →
    // append_json_line under the configured sink + HMAC key. Fire it twice: the
    // first append recovers the tip from the file (seed_prev_from_file); the second
    // links off the in-memory tip carried in chain_last, exercising both paths.
    fail_auth().await;
    let after_first = records(&log);
    assert!(after_first.len() >= 2, "first record appended");
    // First appended record links to the tip recovered from the pre-seeded file.
    assert_eq!(
        after_first[1].get("prev").and_then(Value::as_str),
        Some(seed_mac),
        "new record's prev must link to the recovered chain tip"
    );
    assert!(
        !mac(&after_first[1]).is_empty(),
        "record carries a computed MAC"
    );

    fail_auth().await;
    let after_second = records(&log);
    assert_eq!(after_second.len(), 3, "second record appended");
    // Second appended record chains off the FIRST appended record's mac — proving
    // the in-memory chain tip (chain_last) advanced rather than re-seeding.
    assert_eq!(
        after_second[2].get("prev").and_then(Value::as_str),
        Some(mac(&after_second[1]).as_str()),
        "second record must chain off the in-memory tip"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
