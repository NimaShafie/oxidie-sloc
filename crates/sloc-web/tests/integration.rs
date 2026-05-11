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
