// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Nima Shafie <nimzshafie@gmail.com>
#![allow(clippy::redundant_pub_crate)]

//! Authentication middleware and login form handlers.
//!
//! Provides Bearer-token / X-API-Key / session-cookie auth,
//! login lockout on repeated failures, and the GET/POST /auth/login routes.

use std::{
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use axum::{
    body::Body,
    extract::{Form, Query, State},
    http::{header, HeaderValue, Request, StatusCode},
    middleware::Next,
    response::{Html, IntoResponse, Response},
};

use crate::{AppState, CspNonce, LoginTemplate};
use askama::Template as _;

// ── Middleware ────────────────────────────────────────────────────────────────

/// 503 response returned when server mode is active but no API key is configured.
/// Fails closed: browsers get an explanatory HTML page, API clients get a plain 503.
fn unconfigured_server_mode_response(req: &Request<Body>) -> Response {
    tracing::warn!(
        event = "auth_unconfigured_server_mode",
        path = %req.uri().path(),
        "Rejected request: server mode requires SLOC_API_KEY or SLOC_API_KEYS"
    );
    if is_browser_request(req) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Html(
                r#"<!doctype html><html><head><meta charset="utf-8">
<title>Authentication Required — OxideSLOC</title>
<style>body{font-family:system-ui,sans-serif;max-width:520px;margin:80px auto;padding:0 24px;color:#2f241c}
h1{color:#b85d33}p{line-height:1.6}code{background:#f3e9e0;padding:2px 6px;border-radius:4px}</style>
</head><body>
<h1>Authentication not configured</h1>
<p>This server is running in network mode but <code>SLOC_API_KEY</code> is not set.</p>
<p>Restart with <code>SLOC_API_KEY=&lt;secret&gt;</code> or <code>SLOC_API_KEYS=&lt;k1,k2&gt;</code>
to enable access.</p>
</body></html>"#
                    .to_owned(),
            ),
        )
            .into_response();
    }
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(header::WWW_AUTHENTICATE, "Bearer realm=\"oxide-sloc\"")],
        "503 Service Unavailable — set SLOC_API_KEY to enable server-mode access\n",
    )
        .into_response()
}

pub(crate) async fn require_api_key(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    if state.api_keys.is_empty() {
        // In server mode with no API key configured every protected route would
        // be publicly accessible. Fail closed so operators must opt in.
        // Desktop mode (server_mode = false) keeps the open-by-default behaviour.
        if state.server_mode {
            return unconfigured_server_mode_response(&req);
        }
        return next.run(req).await;
    }

    let keys = &state.api_keys;
    let peer_ip = req
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), |c| c.0.ip());

    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_owned);
    let x_api_key = req
        .headers()
        .get("X-API-Key")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let session_cookie = req
        .headers()
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(extract_session_cookie)
        .map(str::to_owned);

    let session_valid = check_session_valid(session_cookie.as_deref(), &state);
    let any_credential_provided =
        auth_header.is_some() || x_api_key.is_some() || session_cookie.is_some();
    let valid = session_valid
        || [&auth_header, &x_api_key]
            .iter()
            .filter_map(|o| o.as_deref())
            .any(|k| {
                keys.iter().any(|expected| {
                    use secrecy::ExposeSecret;
                    ct_eq(k, expected.expose_secret())
                })
            });

    if valid {
        return next.run(req).await;
    }

    if state.rate_limiter.is_auth_locked_out(peer_ip) {
        return auth_lockout_response(&req, &state.rate_limiter, peer_ip);
    }

    if any_credential_provided {
        state.rate_limiter.record_auth_failure(peer_ip);
        let path = req.uri().path().to_owned();
        tracing::warn!(event = "auth_failure", peer_addr = %peer_ip, path = %path,
            "API key authentication failed");
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer realm=\"oxide-sloc\"")],
            "401 Unauthorized\n",
        )
            .into_response();
    }

    // No credential — redirect browsers, plain 401 for API clients.
    if is_browser_request(&req) {
        let next_path = req.uri().path_and_query().map_or("/", |pq| pq.as_str());
        let next_path = sanitize_next(next_path);
        let login_url = format!("/auth/login?next={}", urlencode_path(next_path));
        let location = HeaderValue::from_str(&login_url)
            .unwrap_or_else(|_| HeaderValue::from_static("/auth/login"));
        let mut resp = StatusCode::FOUND.into_response();
        resp.headers_mut().insert(header::LOCATION, location);
        return resp;
    }
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer realm=\"oxide-sloc\"")],
        "401 Unauthorized\n",
    )
        .into_response()
}

// ── Session helpers ───────────────────────────────────────────────────────────

fn check_session_valid(token: Option<&str>, state: &AppState) -> bool {
    let Some(tok) = token else { return false };
    let now = Instant::now();
    let mut sessions = state
        .sessions
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(&expiry) = sessions.get(tok) {
        if now < expiry {
            return true;
        }
        sessions.remove(tok);
    }
    false
}

fn auth_lockout_response(
    req: &Request<Body>,
    rate_limiter: &crate::IpRateLimiter,
    peer_ip: IpAddr,
) -> Response {
    tracing::warn!(event = "auth_lockout", peer_addr = %peer_ip,
        "Authentication locked out after repeated failures");
    let remaining = rate_limiter.auth_lockout_remaining_secs(peer_ip);
    let retry_after =
        HeaderValue::from_str(&remaining.to_string()).unwrap_or(HeaderValue::from_static("3600"));
    if is_browser_request(req) {
        let minutes = remaining.div_ceil(60).max(1);
        let s = if minutes == 1 { "" } else { "s" };
        let body = format!(
            r#"<!doctype html><html><head><meta charset="utf-8">
<title>Locked Out — OxideSLOC</title>
<style>body{{font-family:system-ui,sans-serif;max-width:520px;margin:80px auto;padding:0 24px;color:#2f241c}}
h1{{color:#b85d33}}p{{line-height:1.6}}code{{background:#f3e9e0;padding:2px 6px;border-radius:4px}}</style>
</head><body>
<h1>Too many failed sign-in attempts</h1>
<p>Access from your IP is temporarily locked. Lockout expires in approximately
<strong>{minutes} minute{s}</strong>.</p>
<p>To clear immediately, restart the server.</p>
<p>For trusted LAN testing, leave <code>SLOC_API_KEY</code> unset, or raise the
threshold via <code>SLOC_AUTH_LOCKOUT_FAILS</code> / <code>SLOC_AUTH_LOCKOUT_SECS</code>.</p>
</body></html>"#
        );
        let mut resp = (StatusCode::TOO_MANY_REQUESTS, Html(body)).into_response();
        resp.headers_mut().insert(header::RETRY_AFTER, retry_after);
        return resp;
    }
    let mut resp = (
        StatusCode::TOO_MANY_REQUESTS,
        format!("429 Too Many Requests — locked out, retry in {remaining}s\n"),
    )
        .into_response();
    resp.headers_mut().insert(header::RETRY_AFTER, retry_after);
    resp
}

fn ct_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

fn extract_session_cookie(cookie_header: &str) -> Option<&str> {
    cookie_header.split(';').find_map(|pair| {
        let pair = pair.trim();
        let (k, v) = pair.split_once('=')?;
        if k.trim() == "sloc_session" {
            Some(v.trim())
        } else {
            None
        }
    })
}

fn is_browser_request(req: &Request<Body>) -> bool {
    req.headers()
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|a| a.contains("text/html"))
}

/// Returns `raw` only if it is a safe same-origin relative path to redirect to
/// after login.  Any value that could cause a redirect loop or open redirect
/// (e.g. `/auth/login*`, `//host`, paths containing `://`) is replaced with `/`.
fn sanitize_next(raw: &str) -> &str {
    if raw.starts_with('/')
        && !raw.starts_with("//")
        && !raw.contains("://")
        && !raw.starts_with("/auth/login")
    {
        raw
    } else {
        "/"
    }
}

fn urlencode_path(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'~'
            | b'/'
            | b'?'
            | b'='
            | b'&'
            | b'#' => {
                out.push(b as char);
            }
            _ => {
                use std::fmt::Write as _;
                write!(&mut out, "%{b:02X}").ok();
            }
        }
    }
    out
}

// ── Login form handlers ────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub(crate) struct LoginQuery {
    next: Option<String>,
    error: Option<String>,
}

#[derive(serde::Deserialize)]
pub(crate) struct LoginFormData {
    key: String,
    next: Option<String>,
}

pub(crate) async fn auth_login_get(
    State(state): State<AppState>,
    Query(query): Query<LoginQuery>,
    axum::extract::Extension(CspNonce(csp_nonce)): axum::extract::Extension<CspNonce>,
) -> Response {
    if state.api_keys.is_empty() {
        let mut resp = StatusCode::FOUND.into_response();
        resp.headers_mut()
            .insert(header::LOCATION, HeaderValue::from_static("/"));
        return resp;
    }
    let has_error = query.error.as_deref() == Some("1");
    let next_url = query.next.as_deref().map_or("/", sanitize_next).to_string();
    let lockout_threshold = state.rate_limiter.auth_lockout_threshold;
    Html(
        LoginTemplate {
            csp_nonce,
            has_error,
            next_url,
            lockout_threshold,
        }
        .render()
        .unwrap_or_else(|e| format!("<pre>Template error: {e}</pre>")),
    )
    .into_response()
}

pub(crate) async fn auth_login_post(
    State(state): State<AppState>,
    axum::extract::ConnectInfo(peer_addr): axum::extract::ConnectInfo<SocketAddr>,
    Form(form): Form<LoginFormData>,
) -> Response {
    let peer_ip = peer_addr.ip();
    let next_url = form
        .next
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or("/");
    let safe_next = sanitize_next(next_url);

    let valid = state.api_keys.iter().any(|expected| {
        use secrecy::ExposeSecret;
        ct_eq(&form.key, expected.expose_secret())
    });

    if valid {
        const SESSION_SECS: u64 = 8 * 3600;
        let session_id = uuid::Uuid::new_v4().to_string();
        let now = Instant::now();
        let expiry = now + Duration::from_secs(SESSION_SECS);
        let mut sessions = state
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Evict expired sessions to prevent unbounded memory growth under sustained logins.
        sessions.retain(|_, &mut exp| exp > now);
        sessions.insert(session_id.clone(), expiry);
        drop(sessions);
        let secure_flag = if state.tls_enabled { "; Secure" } else { "" };
        let cookie_value = format!(
            "sloc_session={session_id}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_SECS}{secure_flag}",
        );
        let location =
            HeaderValue::from_str(safe_next).unwrap_or_else(|_| HeaderValue::from_static("/"));
        let cookie_hv = HeaderValue::from_str(&cookie_value)
            .unwrap_or_else(|_| HeaderValue::from_static("sloc_session=; Path=/; HttpOnly"));
        let mut resp = StatusCode::FOUND.into_response();
        resp.headers_mut().insert(header::LOCATION, location);
        resp.headers_mut().insert(header::SET_COOKIE, cookie_hv);
        resp
    } else {
        state.rate_limiter.record_auth_failure(peer_ip);
        tracing::warn!(event = "auth_failure", peer_addr = %peer_ip, path = "/auth/login",
            "Login form authentication failed");
        let error_url = format!("/auth/login?next={}&error=1", urlencode_path(safe_next));
        let location = HeaderValue::from_str(&error_url)
            .unwrap_or_else(|_| HeaderValue::from_static("/auth/login?error=1"));
        let mut resp = StatusCode::FOUND.into_response();
        resp.headers_mut().insert(header::LOCATION, location);
        resp
    }
}

// ── Logout handler ────────────────────────────────────────────────────────────

/// POST /auth/logout — invalidates the current session cookie immediately.
/// Redirects to /auth/login (or / when no API key is configured).
pub(crate) async fn auth_logout(State(state): State<AppState>, req: Request<Body>) -> Response {
    // Remove the session from the server-side store so the token is dead instantly.
    if let Some(tok) = req
        .headers()
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(extract_session_cookie)
    {
        let mut sessions = state
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        sessions.remove(tok);
    }

    // Expire the cookie on the client side regardless.
    let expire_cookie =
        "sloc_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT";

    let redirect_to = if state.api_keys.is_empty() {
        "/"
    } else {
        "/auth/login"
    };
    let location = HeaderValue::from_str(redirect_to).unwrap_or(HeaderValue::from_static("/"));
    let cookie_hv = HeaderValue::from_str(expire_cookie)
        .unwrap_or_else(|_| HeaderValue::from_static("sloc_session=; Path=/; HttpOnly; Max-Age=0"));

    let mut resp = StatusCode::FOUND.into_response();
    resp.headers_mut().insert(header::LOCATION, location);
    resp.headers_mut().insert(header::SET_COOKIE, cookie_hv);
    tracing::info!(event = "auth_logout", "Session invalidated via logout");
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── sanitize_next ────────────────────────────────────────────────────────

    #[test]
    fn sanitize_next_accepts_simple_path() {
        assert_eq!(sanitize_next("/dashboard"), "/dashboard");
    }

    #[test]
    fn sanitize_next_accepts_path_with_query() {
        assert_eq!(sanitize_next("/scan?path=."), "/scan?path=.");
    }

    #[test]
    fn sanitize_next_accepts_root() {
        assert_eq!(sanitize_next("/"), "/");
    }

    #[test]
    fn sanitize_next_accepts_nested_path() {
        assert_eq!(
            sanitize_next("/api/runs/some-id/status"),
            "/api/runs/some-id/status"
        );
    }

    #[test]
    fn sanitize_next_rejects_double_slash_open_redirect() {
        assert_eq!(sanitize_next("//evil.com/steal"), "/");
    }

    #[test]
    fn sanitize_next_rejects_absolute_url_with_scheme() {
        assert_eq!(sanitize_next("https://evil.com"), "/");
    }

    #[test]
    fn sanitize_next_rejects_javascript_scheme() {
        assert_eq!(sanitize_next("javascript://xss"), "/");
    }

    #[test]
    fn sanitize_next_rejects_exact_login_path() {
        assert_eq!(sanitize_next("/auth/login"), "/");
    }

    #[test]
    fn sanitize_next_rejects_login_path_with_query() {
        assert_eq!(sanitize_next("/auth/login?next=/foo"), "/");
    }

    #[test]
    fn sanitize_next_rejects_empty_string() {
        assert_eq!(sanitize_next(""), "/");
    }

    #[test]
    fn sanitize_next_rejects_relative_path_without_leading_slash() {
        assert_eq!(sanitize_next("dashboard"), "/");
    }

    // ── urlencode_path ───────────────────────────────────────────────────────

    #[test]
    fn urlencode_path_passes_through_safe_chars() {
        assert_eq!(urlencode_path("/scan?path=."), "/scan?path=.");
    }

    #[test]
    fn urlencode_path_preserves_alphanumeric_and_path_chars() {
        let s = "/abc/DEF/123?foo=bar&baz=qux#anchor";
        assert_eq!(urlencode_path(s), s);
    }

    #[test]
    fn urlencode_path_encodes_spaces() {
        assert_eq!(urlencode_path("/path with space"), "/path%20with%20space");
    }

    #[test]
    fn urlencode_path_encodes_plus_sign() {
        assert!(
            urlencode_path("/a+b").contains("%2B"),
            "'+' must be percent-encoded"
        );
    }

    #[test]
    fn urlencode_path_encodes_angle_brackets() {
        let encoded = urlencode_path("<script>");
        assert!(
            encoded.contains("%3C") && encoded.contains("%3E"),
            "angle brackets must be encoded"
        );
    }

    #[test]
    fn urlencode_path_empty_string() {
        assert_eq!(urlencode_path(""), "");
    }

    #[test]
    fn urlencode_path_preserves_tilde_and_underscore() {
        assert_eq!(urlencode_path("/~user_name"), "/~user_name");
    }

    // ── extract_session_cookie ───────────────────────────────────────────────

    #[test]
    fn extract_session_cookie_found_single() {
        assert_eq!(
            extract_session_cookie("sloc_session=abc123"),
            Some("abc123")
        );
    }

    #[test]
    fn extract_session_cookie_found_among_multiple() {
        assert_eq!(
            extract_session_cookie("other=val; sloc_session=mysession; another=x"),
            Some("mysession")
        );
    }

    #[test]
    fn extract_session_cookie_not_found() {
        assert_eq!(extract_session_cookie("other=value; unrelated=abc"), None);
    }

    #[test]
    fn extract_session_cookie_empty_header() {
        assert_eq!(extract_session_cookie(""), None);
    }

    #[test]
    fn extract_session_cookie_partial_name_no_match() {
        assert_eq!(extract_session_cookie("sloc_session_extra=abc"), None);
    }

    #[test]
    fn extract_session_cookie_first_wins() {
        assert_eq!(
            extract_session_cookie("sloc_session=first; sloc_session=second"),
            Some("first")
        );
    }

    #[test]
    fn extract_session_cookie_with_extra_whitespace() {
        assert_eq!(
            extract_session_cookie("  sloc_session  =  token_val  "),
            Some("token_val")
        );
    }
}
