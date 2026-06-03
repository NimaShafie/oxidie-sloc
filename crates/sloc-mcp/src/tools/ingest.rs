use crate::config::McpConfig;
use crate::http_client::HttpClient;
use anyhow::Result;
use serde_json::Value;

pub async fn ingest_result(
    server_url: Option<String>,
    json_path: Option<String>,
    json_inline: Option<String>,
    cfg: &McpConfig,
    http: &HttpClient,
) -> Result<Value> {
    let body: Value = if let Some(path) = json_path {
        cfg.check_path_allowed(&path)?;
        let content = tokio::fs::read_to_string(&path).await?;
        serde_json::from_str(&content)?
    } else if let Some(inline) = json_inline {
        serde_json::from_str(&inline)?
    } else {
        anyhow::bail!("either json_path or json_inline is required");
    };

    let base = cfg.resolve_server_url(server_url.as_deref())?;
    http.post_json(&format!("{base}/api/ingest"), &body).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::McpConfig;
    use crate::http_client::HttpClient;

    fn unreachable_cfg() -> McpConfig {
        McpConfig {
            server_url: Some("http://127.0.0.1:19999".into()),
            bin_path: "oxide-sloc".into(),
            api_key: None,
            allowed_roots: vec![],
        }
    }

    fn no_url_cfg() -> McpConfig {
        McpConfig {
            server_url: None,
            bin_path: "oxide-sloc".into(),
            api_key: None,
            allowed_roots: vec![],
        }
    }

    fn http() -> HttpClient {
        HttpClient::new(None)
    }

    // ── neither path nor inline → error ───────────────────────────────────────

    #[tokio::test]
    async fn ingest_result_no_source_returns_error() {
        let result = ingest_result(None, None, None, &unreachable_cfg(), &http()).await;
        assert!(result.is_err());
        let msg = format!("{:?}", result.unwrap_err());
        assert!(
            msg.contains("either json_path or json_inline"),
            "error must explain what is required: {msg}"
        );
    }

    // ── inline JSON: invalid JSON ─────────────────────────────────────────────

    #[tokio::test]
    async fn ingest_result_invalid_inline_json_returns_error() {
        let result = ingest_result(
            None,
            None,
            Some("this is not valid json {{{".into()),
            &unreachable_cfg(),
            &http(),
        )
        .await;
        assert!(result.is_err());
    }

    // ── inline JSON: server unreachable ───────────────────────────────────────

    #[tokio::test]
    async fn ingest_result_inline_json_unreachable_server_returns_error() {
        let result = ingest_result(
            None,
            None,
            Some(r#"{"run_id":"test","summary":{}}"#.into()),
            &unreachable_cfg(),
            &http(),
        )
        .await;
        assert!(result.is_err());
    }

    // ── no server URL configured → error before HTTP ──────────────────────────

    #[tokio::test]
    async fn ingest_result_no_server_url_errors_immediately() {
        let result = ingest_result(
            None,
            None,
            Some(r#"{"key":"val"}"#.into()),
            &no_url_cfg(),
            &http(),
        )
        .await;
        assert!(result.is_err());
    }

    // ── json_path: nonexistent file ───────────────────────────────────────────

    #[tokio::test]
    async fn ingest_result_nonexistent_json_path_returns_error() {
        let result = ingest_result(
            None,
            Some("/nonexistent/__sloc_test_file__.json".into()),
            None,
            &unreachable_cfg(),
            &http(),
        )
        .await;
        assert!(result.is_err());
    }

    // ── in-process mock server (success paths) ────────────────────────────────

    async fn spawn_ingest_server() -> (String, tokio::task::AbortHandle) {
        use axum::{routing::post, Json, Router};
        let app = Router::new().route(
            "/api/ingest",
            post(|| async { Json(serde_json::json!({"ok": true, "run_id": "new-run"})) }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://127.0.0.1:{port}"), handle.abort_handle())
    }

    fn live_cfg(base: &str) -> McpConfig {
        McpConfig {
            server_url: Some(base.into()),
            bin_path: "oxide-sloc".into(),
            api_key: None,
            allowed_roots: vec![],
        }
    }

    #[tokio::test]
    async fn ingest_result_inline_json_succeeds() {
        let (base, _h) = spawn_ingest_server().await;
        let cfg = live_cfg(&base);
        let result = ingest_result(
            None,
            None,
            Some(r#"{"run_id":"test","summary_totals":{"code_lines":100}}"#.into()),
            &cfg,
            &http(),
        )
        .await
        .unwrap();
        assert_eq!(result["ok"], true);
        assert_eq!(result["run_id"], "new-run");
    }

    #[tokio::test]
    async fn ingest_result_json_path_succeeds() {
        let (base, _h) = spawn_ingest_server().await;
        let cfg = live_cfg(&base);

        let tmp = tempfile::tempdir().unwrap();
        let json_file = tmp.path().join("run.json");
        std::fs::write(
            &json_file,
            r#"{"run_id":"from-file","summary_totals":{"code_lines":50}}"#,
        )
        .unwrap();

        let result = ingest_result(
            None,
            Some(json_file.to_str().unwrap().to_owned()),
            None,
            &cfg,
            &http(),
        )
        .await
        .unwrap();
        assert_eq!(result["ok"], true);
    }

    #[tokio::test]
    async fn ingest_result_inline_invalid_json_is_rejected_before_http() {
        let (base, _h) = spawn_ingest_server().await;
        let cfg = live_cfg(&base);
        let result = ingest_result(None, None, Some("[[[broken".into()), &cfg, &http()).await;
        assert!(result.is_err());
    }
}
