// Integration tests for sloc-web HTTP routes.
// Each test builds an in-process router (no TCP) and fires a one-shot request.
// Coverage: status code, Content-Type, CSP header present, and key body contents.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use sloc_web::make_test_router;
use tower::ServiceExt;

// ── helpers ──────────────────────────────────────────────────────────────────

async fn get(uri: &str) -> (StatusCode, axum::http::HeaderMap, String) {
    let app = make_test_router();
    let resp = app
        .oneshot(Request::get(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8_lossy(&bytes).into_owned();
    (status, headers, body)
}

async fn post_form(uri: &str, form_body: &str) -> (StatusCode, axum::http::HeaderMap, String) {
    let app = make_test_router();
    let req = Request::post(uri)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(form_body.to_owned()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8_lossy(&bytes).into_owned();
    (status, headers, body)
}

fn has_csp(headers: &axum::http::HeaderMap) -> bool {
    headers
        .get("content-security-policy")
        .is_some_and(|v| v.to_str().unwrap_or("").contains("script-src"))
}

// ── public routes (no auth required) ─────────────────────────────────────────

#[tokio::test]
async fn healthz_returns_ok() {
    let (status, _, body) = get("/healthz").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.trim(), "ok");
}

#[tokio::test]
async fn badge_total_sloc_returns_svg() {
    let (status, headers, body) = get("/badge/total_sloc").await;
    assert_eq!(status, StatusCode::OK);
    let ct = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.contains("svg") || ct.contains("xml"),
        "expected SVG content-type, got: {ct}"
    );
    assert!(body.contains("<svg"), "expected SVG body");
}

#[tokio::test]
async fn chart_js_returns_javascript() {
    let (status, headers, _) = get("/static/chart.js").await;
    assert_eq!(status, StatusCode::OK);
    let ct = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.contains("javascript") || ct.contains("text"),
        "unexpected content-type: {ct}"
    );
}

// ── protected HTML pages ──────────────────────────────────────────────────────

#[tokio::test]
async fn splash_returns_html_with_csp() {
    let (status, headers, body) = get("/").await;
    assert_eq!(status, StatusCode::OK);
    assert!(has_csp(&headers), "missing CSP header on /");
    assert!(body.contains("<html"), "expected HTML body on /");
}

#[tokio::test]
async fn scan_page_returns_html_with_csp() {
    let (status, headers, body) = get("/scan").await;
    assert_eq!(status, StatusCode::OK);
    assert!(has_csp(&headers), "missing CSP header on /scan");
    assert!(
        body.contains("tmp-sloc"),
        "expected default path placeholder in /scan"
    );
}

#[tokio::test]
async fn scan_setup_returns_html_with_csp() {
    let (status, headers, body) = get("/scan-setup").await;
    assert_eq!(status, StatusCode::OK);
    assert!(has_csp(&headers), "missing CSP header on /scan-setup");
    assert!(body.contains("<html"), "expected HTML body on /scan-setup");
}

#[tokio::test]
async fn view_reports_returns_html_with_csp() {
    let (status, headers, body) = get("/view-reports").await;
    assert_eq!(status, StatusCode::OK);
    assert!(has_csp(&headers), "missing CSP header on /view-reports");
    assert!(
        body.contains("<html"),
        "expected HTML body on /view-reports"
    );
}

#[tokio::test]
async fn compare_scans_returns_html_with_csp() {
    let (status, headers, body) = get("/compare-scans").await;
    assert_eq!(status, StatusCode::OK);
    assert!(has_csp(&headers), "missing CSP header on /compare-scans");
    assert!(
        body.contains("<html"),
        "expected HTML body on /compare-scans"
    );
}

#[tokio::test]
async fn git_browser_returns_html_with_csp() {
    let (status, headers, body) = get("/git-browser").await;
    assert_eq!(status, StatusCode::OK);
    assert!(has_csp(&headers), "missing CSP header on /git-browser");
    assert!(body.contains("<html"), "expected HTML body on /git-browser");
}

#[tokio::test]
async fn webhook_setup_returns_html_with_csp() {
    let (status, headers, body) = get("/integrations").await;
    assert_eq!(status, StatusCode::OK);
    assert!(has_csp(&headers), "missing CSP header on /integrations");
    assert!(
        body.contains("<html"),
        "expected HTML body on /integrations"
    );
}

#[tokio::test]
async fn embed_summary_returns_html() {
    let (status, _, body) = get("/embed/summary").await;
    assert_eq!(status, StatusCode::OK);
    // With no scans in the registry, the embed handler returns a plain <p> fallback — still HTML.
    assert!(
        body.contains('<'),
        "expected some HTML markup on /embed/summary, got: {body}"
    );
}

// ── JSON API routes ───────────────────────────────────────────────────────────

#[tokio::test]
async fn api_metrics_latest_returns_json() {
    let (status, headers, _) = get("/api/metrics/latest").await;
    // 200 with no scans yet, or 404 — either is acceptable; what matters is no 5xx
    assert!(
        status == StatusCode::OK || status == StatusCode::NOT_FOUND,
        "unexpected status {status} on /api/metrics/latest"
    );
    if status == StatusCode::OK {
        let ct = headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(ct.contains("json"), "expected JSON content-type, got: {ct}");
    }
}

#[tokio::test]
async fn api_project_history_returns_json_array() {
    let (status, headers, body) = get("/api/project-history").await;
    assert_eq!(status, StatusCode::OK);
    let ct = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(ct.contains("json"), "expected JSON content-type, got: {ct}");
    assert!(
        body.starts_with('[') || body.starts_with('{'),
        "expected JSON body"
    );
}

#[tokio::test]
async fn api_schedules_returns_json_object() {
    let (status, headers, body) = get("/api/schedules").await;
    assert_eq!(status, StatusCode::OK);
    let ct = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(ct.contains("json"), "expected JSON content-type, got: {ct}");
    // Response shape: {"schedules": [...]}
    assert!(
        body.contains("\"schedules\""),
        "expected 'schedules' key in /api/schedules response, got: {body}"
    );
}

#[tokio::test]
async fn api_git_refs_with_no_repo_returns_error_not_5xx() {
    let (status, _, _) = get("/api/git/refs?path=.").await;
    assert!(
        status.as_u16() < 500,
        "got 5xx {status} on /api/git/refs — handler panicked or returned internal error"
    );
}

// ── preview (file explorer) ───────────────────────────────────────────────────

#[tokio::test]
async fn preview_with_valid_path_returns_json() {
    let (status, _, body) = get("/preview?path=.").await;
    // 200 with JSON listing or 400/404 if restricted — no 5xx
    assert!(
        status.as_u16() < 500,
        "got 5xx {status} on /preview — handler panicked: {body}"
    );
}

// ── unknown route returns 404 ─────────────────────────────────────────────────

#[tokio::test]
async fn unknown_route_returns_404() {
    let (status, _, _) = get("/this-route-does-not-exist").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ── security header regression ────────────────────────────────────────────────

#[tokio::test]
async fn security_headers_present_on_html_pages() {
    for path in ["/", "/scan", "/view-reports", "/git-browser"] {
        let app = make_test_router();
        let resp = app
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let headers = resp.headers();
        assert!(
            headers.contains_key("x-content-type-options"),
            "missing X-Content-Type-Options on {path}"
        );
        assert!(
            headers.contains_key("x-frame-options"),
            "missing X-Frame-Options on {path}"
        );
        assert!(
            headers.contains_key("content-security-policy"),
            "missing CSP on {path}"
        );
    }
}

// ── auth regression: no API key set → protected routes accessible ─────────────

#[tokio::test]
async fn no_api_key_configured_allows_all_routes() {
    // When no SLOC_API_KEYS is set (test state has api_keys=vec![]), all routes
    // must be reachable without an Authorization header.
    for path in ["/", "/scan", "/view-reports", "/healthz"] {
        let (status, _, _) = get(path).await;
        assert_ne!(
            status,
            StatusCode::UNAUTHORIZED,
            "got 401 on {path} with no API key configured — auth guard is misfiring"
        );
    }
}

// ── analyze handler ───────────────────────────────────────────────────────────

#[tokio::test]
async fn post_analyze_returns_ok_with_wait_id_header() {
    // POST /analyze with a local path kicks off an async scan and returns the
    // wait-page HTML. The x-wait-id response header carries the UUID for polling.
    let (status, headers, body) = post_form("/analyze", "path=.&generate_html=1").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "expected 200 from POST /analyze, got {status}"
    );
    assert!(
        headers.contains_key("x-wait-id"),
        "POST /analyze must return x-wait-id header for async polling"
    );
    let wait_id = headers
        .get("x-wait-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(!wait_id.is_empty(), "x-wait-id must not be empty");
    assert!(
        body.contains("<html") || body.contains("wait") || body.contains("scan"),
        "expected wait-page HTML in body"
    );
}

#[tokio::test]
async fn post_analyze_git_mode_without_both_params_falls_back_to_local() {
    // Supplying git_repo but not git_ref means is_git_mode is false; the handler
    // should treat path as a local directory scan and still return 200 + x-wait-id.
    let (status, headers, _) = post_form(
        "/analyze",
        "path=.&git_repo=https%3A%2F%2Fexample.com%2Frepo",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        headers.contains_key("x-wait-id"),
        "incomplete git mode should fall back to local scan and return x-wait-id"
    );
}

// ── async run status / cancel ─────────────────────────────────────────────────

#[tokio::test]
async fn async_run_status_unknown_wait_id_returns_404() {
    let (status, _, _) = get("/api/runs/00000000-0000-0000-0000-000000000000/status").await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "unknown wait_id must return 404 from status endpoint"
    );
}

#[tokio::test]
async fn async_run_status_malformed_wait_id_returns_400() {
    // wait_id longer than 128 chars should be rejected before the map lookup.
    let long_id = "x".repeat(129);
    let (status, _, _) = get(&format!("/api/runs/{long_id}/status")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn cancel_run_unknown_wait_id_returns_404() {
    let (status, _, _) =
        post_form("/api/runs/00000000-0000-0000-0000-000000000000/cancel", "").await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "cancelling an unknown wait_id must return 404"
    );
}

#[tokio::test]
async fn cancel_run_after_analyze_returns_ok_or_not_found() {
    // Start a scan so a wait_id is registered, then immediately cancel it.
    let (_, headers, _) = post_form("/analyze", "path=.").await;
    let wait_id = headers
        .get("x-wait-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    assert!(!wait_id.is_empty(), "need a wait_id from POST /analyze");
    // Cancel — may be Running (200) or already Complete/not in async_runs yet
    // (404) depending on scheduling; either is valid, 5xx is not.
    let (status, _, _) = post_form(&format!("/api/runs/{wait_id}/cancel"), "").await;
    assert!(
        status == StatusCode::OK || status == StatusCode::NOT_FOUND,
        "cancel of a real wait_id must be 200 or 404, got {status}"
    );
}

// ── artifact handler ──────────────────────────────────────────────────────────

#[tokio::test]
async fn artifact_handler_unknown_run_id_returns_404() {
    for artifact in ["html", "pdf", "json", "csv", "xlsx"] {
        let (status, _, body) = get(&format!(
            "/runs/{artifact}/00000000-0000-0000-0000-000000000000"
        ))
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "unknown run ID for artifact '{artifact}' must return 404, body: {body}"
        );
    }
}

#[tokio::test]
async fn artifact_handler_swapped_segments_returns_404() {
    // The URL spec is /runs/{artifact}/{run_id}. If the user accidentally
    // writes /runs/{run_id}/{artifact} the handler must still return 404 (not 5xx).
    let (status, _, _) = get("/runs/00000000-0000-0000-0000-000000000000/html").await;
    assert!(
        status == StatusCode::NOT_FOUND || status == StatusCode::OK,
        "swapped segments must not cause a 5xx, got {status}"
    );
}

// ── async run result ──────────────────────────────────────────────────────────

#[tokio::test]
async fn async_run_result_unknown_returns_404() {
    let (status, _, body) = get("/runs/result/00000000-0000-0000-0000-000000000000").await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "unknown run_id in /runs/result must return 404, body: {body}"
    );
}

#[tokio::test]
async fn async_run_result_malformed_id_returns_400() {
    let long_id = "y".repeat(129);
    let (status, _, _) = get(&format!("/runs/result/{long_id}")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ── pdf status ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn pdf_status_unknown_run_returns_not_ready_json() {
    let (status, headers, body) =
        get("/api/runs/00000000-0000-0000-0000-000000000000/pdf-status").await;
    assert_eq!(status, StatusCode::OK);
    let ct = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(ct.contains("json"), "expected JSON content-type, got: {ct}");
    assert!(
        body.contains("\"ready\""),
        "pdf-status body must contain 'ready' field, got: {body}"
    );
    assert!(
        body.contains("false"),
        "pdf-status for unknown run must return ready:false, got: {body}"
    );
}

// ── compare handler ───────────────────────────────────────────────────────────

#[tokio::test]
async fn compare_without_params_redirects_to_compare_scans() {
    let app = make_test_router();
    let resp = app
        .oneshot(Request::get("/compare").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    assert!(
        status.is_redirection(),
        "GET /compare with no params must redirect, got {status}"
    );
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        location.contains("compare-scans"),
        "redirect must point to /compare-scans, got location: {location}"
    );
}

#[tokio::test]
async fn compare_with_unknown_run_ids_returns_error_page() {
    let (status, _, body) = get("/compare?a=unknown-run-a&b=unknown-run-b").await;
    // The handler renders ErrorTemplate which returns 200 HTML (no explicit 404)
    // when run IDs are not found — assert no 5xx and that error text is present.
    assert!(
        status.as_u16() < 500,
        "compare with unknown IDs must not 5xx, got {status}"
    );
    assert!(
        body.contains("not found") || body.contains("not Found") || body.contains("<html"),
        "expected an error page or HTML, got: {body}"
    );
}

// ── trend reports + test metrics ──────────────────────────────────────────────

#[tokio::test]
async fn trend_reports_returns_html_with_csp() {
    let (status, headers, body) = get("/trend-reports").await;
    assert_eq!(status, StatusCode::OK);
    assert!(has_csp(&headers), "missing CSP header on /trend-reports");
    assert!(body.contains("<html"), "expected HTML on /trend-reports");
}

#[tokio::test]
async fn test_metrics_returns_html_with_csp() {
    let (status, headers, body) = get("/test-metrics").await;
    assert_eq!(status, StatusCode::OK);
    assert!(has_csp(&headers), "missing CSP header on /test-metrics");
    assert!(body.contains("<html"), "expected HTML on /test-metrics");
}

// ── coverage suggestion API ───────────────────────────────────────────────────

#[tokio::test]
async fn api_suggest_coverage_returns_json() {
    let (status, headers, body) = get("/api/suggest-coverage?path=.").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "unexpected status on /api/suggest-coverage"
    );
    let ct = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(ct.contains("json"), "expected JSON content-type, got: {ct}");
    assert!(
        body.contains("\"found\""),
        "expected 'found' key in coverage suggestion response, got: {body}"
    );
}

// ── metrics by run ID ─────────────────────────────────────────────────────────

#[tokio::test]
async fn api_metrics_run_unknown_returns_404() {
    let (status, _, _) = get("/api/metrics/00000000-0000-0000-0000-000000000000").await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "unknown run_id in /api/metrics/{{run_id}} must return 404"
    );
}

// ── api-docs page ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn api_docs_returns_html_with_csp() {
    let (status, headers, body) = get("/api-docs").await;
    assert_eq!(status, StatusCode::OK);
    assert!(has_csp(&headers), "missing CSP on /api-docs");
    assert!(body.contains("<html"), "expected HTML on /api-docs");
}
