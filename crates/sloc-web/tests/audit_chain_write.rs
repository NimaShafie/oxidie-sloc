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
use axum::http::{header, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use sloc_web::make_test_router_with_key;
use tower::ServiceExt;

#[tokio::test]
async fn failed_auth_appends_a_chained_record_seeded_from_the_existing_log() {
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

    static INIT: Once = Once::new();
    INIT.call_once(|| {
        std::env::set_var("SLOC_AUDIT_LOG", log.to_string_lossy().to_string());
        std::env::set_var("SLOC_AUDIT_HMAC_KEY", "chain-test-key");
    });

    // A request with the WRONG key is an authentication failure → audit::record →
    // append_json_line under the configured sink + HMAC key.
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
    // The exact status isn't the point (401), only that it was rejected, not served.
    assert_ne!(resp.status(), StatusCode::OK);
    let _ = resp.into_body().collect().await;

    let contents = std::fs::read_to_string(&log).expect("audit log readable");
    let lines: Vec<&str> = contents.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(
        lines.len() >= 2,
        "a new audit record must have been appended: {contents}"
    );

    // The appended record is a valid chained record linked to the seed tip.
    let last: Value = serde_json::from_str(lines.last().unwrap()).expect("appended line is JSON");
    assert_eq!(
        last.get("prev").and_then(Value::as_str),
        Some(seed_mac),
        "new record's prev must link to the recovered chain tip"
    );
    assert!(
        last.get("mac")
            .and_then(Value::as_str)
            .is_some_and(|m| !m.is_empty()),
        "new record carries a computed MAC"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
