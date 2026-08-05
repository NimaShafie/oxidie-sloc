// Coverage for the pre-access consent-banner feature, exercised end-to-end through
// the router: the consent gate middleware (consent_gate / consent_gate_applies /
// request_has_consent / consent_banner_text), the interstitial renderer
// (render_consent_page / html_escape_consent), and the acknowledgement handler
// (auth::auth_consent_accept). All are private/free functions reachable only via
// the router, so these drive real HTTP requests and assert observable behaviour.
//
// The banner is enabled by the process-global SLOC_CONSENT_BANNER env var. Cargo
// compiles each integration-test file into its OWN test binary (separate process),
// so setting it here cannot affect other test files; within this file every test
// wants the banner ON, set exactly once via a Once.

use std::sync::Once;

use axum::http::Request;
use axum::{
    body::Body,
    http::{StatusCode, header},
};
use http_body_util::BodyExt;
use sloc_web::make_test_router;
use tower::ServiceExt;

// Deliberately includes &, <, >, " so html_escape_consent is exercised.
const BANNER: &str = r#"Restricted & <monitored> "system""#;

fn enable_banner() {
    static INIT: Once = Once::new();
    // FIXME: Audit that the environment access only happens in single-threaded code.
    INIT.call_once(|| unsafe { std::env::set_var("SLOC_CONSENT_BANNER", BANNER) });
}

async fn body_string(resp: axum::response::Response) -> String {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[tokio::test]
async fn browser_navigation_without_cookie_gets_the_consent_page() {
    enable_banner();
    let resp = make_test_router()
        .oneshot(
            Request::get("/")
                .header(header::ACCEPT, "text/html")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(
        body.contains("Notice and Consent"),
        "consent interstitial expected"
    );
    // Operator banner text is present AND HTML-escaped (html_escape_consent).
    assert!(body.contains("Restricted &amp; &lt;monitored&gt; &quot;system&quot;"));
    // The "I Agree" action points at the accept endpoint with the return path.
    assert!(body.contains("/auth/consent?next="));
}

#[tokio::test]
async fn request_with_consent_cookie_passes_through() {
    enable_banner();
    let resp = make_test_router()
        .oneshot(
            Request::get("/")
                .header(header::ACCEPT, "text/html")
                .header(header::COOKIE, "sloc_consent=1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(
        !body.contains("Notice and Consent"),
        "an acknowledged session must not be re-gated"
    );
}

#[tokio::test]
async fn exempt_path_is_not_gated() {
    enable_banner();
    // /healthz is on the exempt list — never intercepted even as a browser GET.
    let resp = make_test_router()
        .oneshot(
            Request::get("/healthz")
                .header(header::ACCEPT, "text/html")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(!body_string(resp).await.contains("Notice and Consent"));
}

#[tokio::test]
async fn non_html_request_is_not_gated() {
    enable_banner();
    // A JSON (non-text/html) GET is an API/asset fetch, not a page navigation.
    let resp = make_test_router()
        .oneshot(
            Request::get("/")
                .header(header::ACCEPT, "application/json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(!body_string(resp).await.contains("Notice and Consent"));
}

#[tokio::test]
async fn non_get_method_is_not_gated() {
    enable_banner();
    // A POST is never a top-level navigation, so the gate lets it reach its handler
    // (which may reject it for other reasons, but never with the consent page).
    let resp = make_test_router()
        .oneshot(
            Request::post("/analyze")
                .header(header::ACCEPT, "text/html")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("path=."))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(!body_string(resp).await.contains("Notice and Consent"));
}

#[tokio::test]
async fn accepting_consent_sets_cookie_and_redirects_to_safe_next() {
    enable_banner();
    let resp = make_test_router()
        .oneshot(
            Request::get("/auth/consent?next=/scan")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);
    let cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        cookie.contains("sloc_consent=1"),
        "acknowledgement cookie set"
    );
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert_eq!(loc, "/scan", "returns the user to their original path");
}

#[tokio::test]
async fn accepting_consent_rejects_offsite_next() {
    enable_banner();
    // An absolute/offsite next must be sanitised back to "/" (open-redirect guard).
    let resp = make_test_router()
        .oneshot(
            Request::get("/auth/consent?next=http://evil.example/x")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert_eq!(loc, "/", "offsite redirect target must be neutralised");
}
