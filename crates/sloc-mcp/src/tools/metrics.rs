use crate::config::McpConfig;
use crate::http_client::HttpClient;
use anyhow::Result;
use serde_json::Value;

pub async fn get_metrics_latest(
    server_url: Option<String>,
    cfg: &McpConfig,
    http: &HttpClient,
) -> Result<Value> {
    let base = server_url.as_deref().unwrap_or(cfg.server_url()?);
    http.get_json(&format!("{base}/api/metrics/latest")).await
}

pub async fn get_metrics_history(
    server_url: Option<String>,
    limit: Option<u64>,
    cfg: &McpConfig,
    http: &HttpClient,
) -> Result<Value> {
    let base = server_url.as_deref().unwrap_or(cfg.server_url()?);
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
    let base = server_url.as_deref().unwrap_or(cfg.server_url()?);
    http.get_json(&format!("{base}/api/metrics/{run_id}")).await
}

pub async fn health_check(
    server_url: Option<String>,
    cfg: &McpConfig,
    http: &HttpClient,
) -> Result<Value> {
    let base = server_url.as_deref().unwrap_or(cfg.server_url()?);
    let status = http.get_json(&format!("{base}/api/health")).await?;
    let version = http
        .get_json(&format!("{base}/api/version"))
        .await
        .unwrap_or_default();
    Ok(serde_json::json!({ "health": status, "version": version }))
}
