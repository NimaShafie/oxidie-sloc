use crate::config::McpConfig;
use crate::http_client::HttpClient;
use anyhow::Result;
use serde_json::Value;

pub async fn get_metrics_latest(
    server_url: Option<String>,
    cfg: &McpConfig,
    http: &HttpClient,
) -> Result<Value> {
    let base = cfg.resolve_server_url(server_url.as_deref())?;
    http.get_json(&format!("{base}/api/metrics/latest")).await
}

pub async fn get_metrics_history(
    server_url: Option<String>,
    limit: Option<u64>,
    cfg: &McpConfig,
    http: &HttpClient,
) -> Result<Value> {
    let base = cfg.resolve_server_url(server_url.as_deref())?;
    let limit = limit.unwrap_or(100);
    http.get_json(&format!("{base}/api/metrics/history?limit={limit}"))
        .await
}

pub async fn get_run_metrics(
    run_id: String,
    server_url: Option<String>,
    cfg: &McpConfig,
    http: &HttpClient,
) -> Result<Value> {
    let base = cfg.resolve_server_url(server_url.as_deref())?;
    http.get_json(&format!("{base}/api/metrics/{run_id}")).await
}

pub async fn health_check(
    server_url: Option<String>,
    cfg: &McpConfig,
    http: &HttpClient,
) -> Result<Value> {
    let base = cfg.resolve_server_url(server_url.as_deref())?;
    let status = http.get_json(&format!("{base}/api/health")).await?;
    let version = http
        .get_json(&format!("{base}/api/version"))
        .await
        .unwrap_or_default();
    Ok(serde_json::json!({ "health": status, "version": version }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::McpConfig;
    use crate::http_client::HttpClient;

    fn cfg(url: &str) -> McpConfig {
        McpConfig {
            server_url: Some(url.into()),
            bin_path: "oxide-sloc".into(),
            api_key: None,
            allowed_roots: vec![],
        }
    }

    fn unreachable_http() -> HttpClient {
        HttpClient::new(None)
    }

    // ── resolve_server_url integration ────────────────────────────────────────

    #[test]
    fn resolve_url_no_server_configured_errors() {
        let no_url_cfg = McpConfig {
            server_url: None,
            bin_path: "oxide-sloc".into(),
            api_key: None,
            allowed_roots: vec![],
        };
        // All functions call resolve_server_url first; check it fails cleanly
        assert!(no_url_cfg.resolve_server_url(None).is_err());
    }

    #[test]
    fn resolve_url_mismatch_errors() {
        let c = cfg("http://localhost:4317");
        assert!(c.resolve_server_url(Some("http://evil.com")).is_err());
    }

    // ── get_metrics_latest ────────────────────────────────────────────────────

    #[tokio::test]
    async fn get_metrics_latest_unreachable_returns_err() {
        let c = cfg("http://127.0.0.1:19999");
        let http = unreachable_http();
        let result = get_metrics_latest(None, &c, &http).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn get_metrics_latest_no_server_url_returns_err() {
        let c = McpConfig {
            server_url: None,
            bin_path: "oxide-sloc".into(),
            api_key: None,
            allowed_roots: vec![],
        };
        let http = unreachable_http();
        let result = get_metrics_latest(None, &c, &http).await;
        assert!(result.is_err());
    }

    // ── get_metrics_history ───────────────────────────────────────────────────

    #[tokio::test]
    async fn get_metrics_history_unreachable_returns_err() {
        let c = cfg("http://127.0.0.1:19999");
        let http = unreachable_http();
        let result = get_metrics_history(None, None, &c, &http).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn get_metrics_history_custom_limit_unreachable_returns_err() {
        let c = cfg("http://127.0.0.1:19999");
        let http = unreachable_http();
        let result = get_metrics_history(None, Some(50), &c, &http).await;
        assert!(result.is_err());
    }

    // ── get_run_metrics ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn get_run_metrics_unreachable_returns_err() {
        let c = cfg("http://127.0.0.1:19999");
        let http = unreachable_http();
        let result = get_run_metrics("some-run-id".into(), None, &c, &http).await;
        assert!(result.is_err());
    }

    // ── health_check ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn health_check_unreachable_returns_err() {
        let c = cfg("http://127.0.0.1:19999");
        let http = unreachable_http();
        let result = health_check(None, &c, &http).await;
        assert!(result.is_err());
    }

    // ── in-process mock server ────────────────────────────────────────────────

    async fn spawn_mock_metrics_server() -> (String, tokio::task::AbortHandle) {
        use axum::{Json, Router, routing::get};
        let app = Router::new()
            .route("/api/metrics/latest", get(|| async {
                Json(serde_json::json!({"run_id":"latest-run","summary_totals":{"code_lines":100}}))
            }))
            .route("/api/metrics/history", get(|| async {
                Json(serde_json::json!([{"run_id":"run1"},{"run_id":"run2"}]))
            }))
            .route("/api/metrics/{run_id}", get(|| async {
                Json(serde_json::json!({"run_id":"specific-run","summary_totals":{}}))
            }))
            .route("/api/health", get(|| async {
                Json(serde_json::json!({"status":"ok"}))
            }))
            .route("/api/version", get(|| async {
                Json(serde_json::json!({"version":"1.5.65","name":"oxide-sloc"}))
            }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://127.0.0.1:{port}"), handle.abort_handle())
    }

    // ── get_metrics_latest success ────────────────────────────────────────────

    #[tokio::test]
    async fn get_metrics_latest_returns_json_on_success() {
        let (base, _h) = spawn_mock_metrics_server().await;
        let c = cfg(&base);
        let http = HttpClient::new(None);
        let v = get_metrics_latest(None, &c, &http).await.unwrap();
        assert_eq!(v["run_id"], "latest-run");
    }

    #[tokio::test]
    async fn get_metrics_latest_with_matching_server_url_succeeds() {
        let (base, _h) = spawn_mock_metrics_server().await;
        let c = cfg(&base);
        let http = HttpClient::new(None);
        let v = get_metrics_latest(Some(base.clone()), &c, &http)
            .await
            .unwrap();
        assert_eq!(v["run_id"], "latest-run");
    }

    // ── get_metrics_history success ───────────────────────────────────────────

    #[tokio::test]
    async fn get_metrics_history_default_limit_succeeds() {
        let (base, _h) = spawn_mock_metrics_server().await;
        let c = cfg(&base);
        let http = HttpClient::new(None);
        let v = get_metrics_history(None, None, &c, &http).await.unwrap();
        assert!(v.is_array(), "history must be a JSON array");
    }

    #[tokio::test]
    async fn get_metrics_history_custom_limit_succeeds() {
        let (base, _h) = spawn_mock_metrics_server().await;
        let c = cfg(&base);
        let http = HttpClient::new(None);
        let v = get_metrics_history(None, Some(50), &c, &http)
            .await
            .unwrap();
        assert!(v.is_array());
    }

    // ── get_run_metrics success ───────────────────────────────────────────────

    #[tokio::test]
    async fn get_run_metrics_returns_json_on_success() {
        let (base, _h) = spawn_mock_metrics_server().await;
        let c = cfg(&base);
        let http = HttpClient::new(None);
        let v = get_run_metrics("abc-run-id".into(), None, &c, &http)
            .await
            .unwrap();
        assert_eq!(v["run_id"], "specific-run");
    }

    // ── health_check success ──────────────────────────────────────────────────

    #[tokio::test]
    async fn health_check_returns_combined_json_on_success() {
        let (base, _h) = spawn_mock_metrics_server().await;
        let c = cfg(&base);
        let http = HttpClient::new(None);
        let v = health_check(None, &c, &http).await.unwrap();
        assert_eq!(v["health"]["status"], "ok");
        assert_eq!(v["version"]["name"], "oxide-sloc");
    }

    #[tokio::test]
    async fn health_check_version_failure_still_returns_ok() {
        // The health_check function uses unwrap_or_default() for the version call,
        // so even if /api/version returns an error, health must still succeed.
        use axum::{Json, Router, routing::get};
        let app = Router::new()
            .route(
                "/api/health",
                get(|| async { Json(serde_json::json!({"status":"ok"})) }),
            )
            .route(
                "/api/version",
                get(|| async { axum::http::StatusCode::INTERNAL_SERVER_ERROR }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let _h = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let base = format!("http://127.0.0.1:{port}");
        let c = cfg(&base);
        let http = HttpClient::new(None);
        let v = health_check(None, &c, &http).await.unwrap();
        assert_eq!(v["health"]["status"], "ok");
        assert!(
            v["version"].is_null(),
            "version must be null when /api/version fails"
        );
    }
}
