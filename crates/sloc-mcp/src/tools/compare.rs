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
    cfg.check_path_allowed(&baseline_path)?;
    cfg.check_path_allowed(&current_path)?;
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
    p.push(format!(
        "sloc-mcp-diff-{}.json",
        uuid::Uuid::new_v4().simple()
    ));
    p
}
