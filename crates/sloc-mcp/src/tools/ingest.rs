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
        let content = tokio::fs::read_to_string(&path).await?;
        serde_json::from_str(&content)?
    } else if let Some(inline) = json_inline {
        serde_json::from_str(&inline)?
    } else {
        anyhow::bail!("either json_path or json_inline is required");
    };

    let base = server_url.as_deref().unwrap_or(cfg.server_url()?);
    http.post_json(&format!("{base}/api/ingest"), &body).await
}
