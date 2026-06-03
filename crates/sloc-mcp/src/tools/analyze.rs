use crate::config::McpConfig;
use anyhow::Result;
use serde_json::{json, Value};
use std::path::PathBuf;
use tokio::process::Command;

pub async fn analyze_path(
    path: String,
    config_file: Option<String>,
    cfg: &McpConfig,
) -> Result<Value> {
    cfg.check_path_allowed(&path)?;
    let tmp = tempfile_path();
    let mut cmd = Command::new(&cfg.bin_path);
    cmd.arg("analyze")
        .arg(&path)
        .arg("--json-out")
        .arg(&tmp)
        .arg("--quiet");
    if let Some(cf) = &config_file {
        cmd.arg("--config").arg(cf);
    }

    let output = cmd.output().await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("oxide-sloc analyze failed: {stderr}");
    }

    let content = tokio::fs::read_to_string(&tmp).await?;
    let _ = tokio::fs::remove_file(&tmp).await;

    let run: Value = serde_json::from_str(&content)?;
    Ok(summarize_run(&run))
}

fn summarize_run(run: &Value) -> Value {
    let totals = &run["summary_totals"];
    let languages: Vec<Value> = run["totals_by_language"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .map(|l| {
                    json!({
                        "language": l["language"],
                        "files": l["files"],
                        "code_lines": l["code_lines"],
                        "comment_lines": l["comment_lines"],
                        "blank_lines": l["blank_lines"],
                        "functions": l["functions"],
                        "test_count": l["test_count"],
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    json!({
        "files_analyzed": totals["files_analyzed"],
        "files_skipped": totals["files_skipped"],
        "code_lines": totals["code_lines"],
        "comment_lines": totals["comment_lines"],
        "blank_lines": totals["blank_lines"],
        "total_physical_lines": totals["total_physical_lines"],
        "functions": totals["functions"],
        "classes": totals["classes"],
        "test_count": totals["test_count"],
        "test_assertion_count": totals["test_assertion_count"],
        "git_branch": run["git_branch"],
        "git_commit_short": run["git_commit_short"],
        "git_nearest_tag": run["git_nearest_tag"],
        "languages": languages,
    })
}

fn tempfile_path() -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("sloc-mcp-{}.json", uuid::Uuid::new_v4().simple()));
    p
}
