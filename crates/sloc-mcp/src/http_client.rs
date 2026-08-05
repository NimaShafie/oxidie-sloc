use anyhow::Result;
use serde_json::Value;

pub struct HttpClient {
    client: reqwest::Client,
    api_key: Option<String>,
}

impl HttpClient {
    pub fn new(api_key: Option<String>) -> Self {
        // Ensure a rustls crypto provider is installed before building the
        // reqwest client.  This is a no-op when one is already configured
        // (the error is intentionally ignored via `let _`).
        static CRYPTO: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        CRYPTO.get_or_init(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
        Self {
            client: reqwest::Client::new(),
            api_key,
        }
    }

    pub async fn get_json(&self, url: &str) -> Result<Value> {
        let mut req = self.client.get(url);
        if let Some(key) = &self.api_key {
            req = req.bearer_auth(key);
        }
        let resp = req.send().await?;
        let status = resp.status();
        if !status.is_success() {
            anyhow::bail!("server returned {status} for GET {url}");
        }
        Ok(resp.json().await?)
    }

    pub async fn post_json(&self, url: &str, body: &Value) -> Result<Value> {
        let mut req = self.client.post(url).json(body);
        if let Some(key) = &self.api_key {
            req = req.bearer_auth(key);
        }
        let resp = req.send().await?;
        let status = resp.status();
        if !status.is_success() {
            anyhow::bail!("server returned {status} for POST {url}");
        }
        Ok(resp.json().await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── HttpClient::new ───────────────────────────────────────────────────────

    #[test]
    fn new_without_api_key() {
        let client = HttpClient::new(None);
        assert!(client.api_key.is_none());
    }

    #[test]
    fn new_with_api_key() {
        let client = HttpClient::new(Some("my-token".into()));
        assert_eq!(client.api_key.as_deref(), Some("my-token"));
    }

    #[test]
    fn new_with_empty_api_key() {
        let client = HttpClient::new(Some(String::new()));
        assert_eq!(client.api_key.as_deref(), Some(""));
    }

    // ── get_json / post_json error paths (non-reachable URL) ─────────────────

    #[tokio::test]
    async fn get_json_unreachable_host_returns_error() {
        let client = HttpClient::new(None);
        let result = client
            .get_json("http://127.0.0.1:19999/__nonexistent_endpoint__")
            .await;
        assert!(result.is_err(), "unreachable host must return an error");
    }

    #[tokio::test]
    async fn post_json_unreachable_host_returns_error() {
        let client = HttpClient::new(None);
        let result = client
            .post_json(
                "http://127.0.0.1:19999/__nonexistent_endpoint__",
                &serde_json::json!({"key": "value"}),
            )
            .await;
        assert!(result.is_err(), "unreachable host must return an error");
    }

    #[tokio::test]
    async fn get_json_with_api_key_unreachable_returns_error() {
        let client = HttpClient::new(Some("bearer-token".into()));
        let result = client.get_json("http://127.0.0.1:19999/__test__").await;
        assert!(result.is_err());
    }

    // ── in-process mock HTTP server ───────────────────────────────────────────

    /// Spawn a minimal Axum server and return (`base_url`, `abort_handle`).
    async fn spawn_mock(
        get_json: &'static str,
        post_json: &'static str,
    ) -> (String, tokio::task::AbortHandle) {
        use axum::{
            Router,
            http::StatusCode,
            response::IntoResponse,
            routing::{get, post},
        };
        let app = Router::new()
            .route(
                "/json",
                get(move || async move {
                    (
                        [(axum::http::header::CONTENT_TYPE, "application/json")],
                        get_json,
                    )
                        .into_response()
                }),
            )
            .route(
                "/json",
                post(move || async move {
                    (
                        [(axum::http::header::CONTENT_TYPE, "application/json")],
                        post_json,
                    )
                        .into_response()
                }),
            )
            .route(
                "/error",
                get(|| async { StatusCode::INTERNAL_SERVER_ERROR.into_response() }),
            )
            .route(
                "/not-found",
                get(|| async { StatusCode::NOT_FOUND.into_response() }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://127.0.0.1:{port}"), handle.abort_handle())
    }

    // ── get_json success paths ────────────────────────────────────────────────

    #[tokio::test]
    async fn get_json_returns_parsed_json_on_200() {
        let (base, _handle) = spawn_mock(r#"{"key":"value","num":42}"#, "{}").await;
        let client = HttpClient::new(None);
        let v = client.get_json(&format!("{base}/json")).await.unwrap();
        assert_eq!(v["key"], "value");
        assert_eq!(v["num"], 42);
    }

    #[tokio::test]
    async fn get_json_with_bearer_token_succeeds() {
        let (base, _handle) = spawn_mock(r#"{"auth":"ok"}"#, "{}").await;
        let client = HttpClient::new(Some("my-token".into()));
        let v = client.get_json(&format!("{base}/json")).await.unwrap();
        assert_eq!(v["auth"], "ok");
    }

    #[tokio::test]
    async fn get_json_returns_error_on_500() {
        let (base, _handle) = spawn_mock("{}", "{}").await;
        let client = HttpClient::new(None);
        let result = client.get_json(&format!("{base}/error")).await;
        assert!(result.is_err());
        let msg = format!("{:?}", result.unwrap_err());
        assert!(msg.contains("500"));
    }

    #[tokio::test]
    async fn get_json_returns_error_on_404() {
        let (base, _handle) = spawn_mock("{}", "{}").await;
        let client = HttpClient::new(None);
        assert!(client.get_json(&format!("{base}/not-found")).await.is_err());
    }

    // ── post_json success paths ───────────────────────────────────────────────

    #[tokio::test]
    async fn post_json_returns_parsed_json_on_200() {
        let (base, _handle) = spawn_mock("{}", r#"{"posted":true}"#).await;
        let client = HttpClient::new(None);
        let v = client
            .post_json(&format!("{base}/json"), &serde_json::json!({"x":1}))
            .await
            .unwrap();
        assert_eq!(v["posted"], true);
    }

    #[tokio::test]
    async fn post_json_with_bearer_token_succeeds() {
        let (base, _handle) = spawn_mock("{}", r#"{"ok":true}"#).await;
        let client = HttpClient::new(Some("tok".into()));
        let v = client
            .post_json(&format!("{base}/json"), &serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(v["ok"], true);
    }
}
