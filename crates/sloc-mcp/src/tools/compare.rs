use crate::config::McpConfig;
use anyhow::Result;
use serde_json::Value;
use std::path::PathBuf;
use tokio::process::Command;

pub async fn compare_runs(
    baseline_path: String,
    current_path: String,
    cfg: &McpConfig,
) -> Result<Value> {
    let tmp = tempfile_path();
    let output = Command::new(&cfg.bin_path)
        .arg("diff")
        .arg(&baseline_path)
        .arg(&current_path)
        .arg("--json-out")
        .arg(&tmp)
        .arg("--quiet")
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("oxide-sloc diff failed: {stderr}");
    }

    let content = tokio::fs::read_to_string(&tmp).await?;
    let _ = tokio::fs::remove_file(&tmp).await;
    Ok(serde_json::from_str(&content)?)
}

fn tempfile_path() -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("sloc-mcp-diff-{}.json", timestamp()));
    p
}

fn timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
