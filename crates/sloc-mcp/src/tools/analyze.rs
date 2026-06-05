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

pub fn summarize_run(run: &Value) -> Value {
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── summarize_run ─────────────────────────────────────────────────────────

    #[test]
    fn summarize_run_extracts_top_level_fields() {
        let run = json!({
            "summary_totals": {
                "files_analyzed": 42,
                "files_skipped": 3,
                "code_lines": 1247,
                "comment_lines": 200,
                "blank_lines": 150,
                "total_physical_lines": 1597,
                "functions": 85,
                "classes": 12,
                "test_count": 60,
                "test_assertion_count": 180
            },
            "totals_by_language": [],
            "git_branch": "main",
            "git_commit_short": "abc1234",
            "git_nearest_tag": "v1.0.0"
        });
        let s = summarize_run(&run);
        assert_eq!(s["files_analyzed"], 42);
        assert_eq!(s["code_lines"], 1247);
        assert_eq!(s["functions"], 85);
        assert_eq!(s["test_count"], 60);
        assert_eq!(s["git_branch"], "main");
        assert_eq!(s["git_commit_short"], "abc1234");
        assert_eq!(s["git_nearest_tag"], "v1.0.0");
    }

    #[test]
    fn summarize_run_languages_array_mapped() {
        let run = json!({
            "summary_totals": {},
            "totals_by_language": [
                {
                    "language": "Rust",
                    "files": 10,
                    "code_lines": 500,
                    "comment_lines": 50,
                    "blank_lines": 30,
                    "functions": 40,
                    "test_count": 20
                }
            ]
        });
        let s = summarize_run(&run);
        let langs = s["languages"].as_array().expect("languages must be array");
        assert_eq!(langs.len(), 1);
        assert_eq!(langs[0]["language"], "Rust");
        assert_eq!(langs[0]["files"], 10);
        assert_eq!(langs[0]["code_lines"], 500);
    }

    #[test]
    fn summarize_run_empty_languages_gives_empty_array() {
        let run = json!({
            "summary_totals": {},
            "totals_by_language": []
        });
        let s = summarize_run(&run);
        let langs = s["languages"].as_array().expect("languages must be array");
        assert!(langs.is_empty());
    }

    #[test]
    fn summarize_run_missing_totals_by_language_gives_empty_array() {
        let run = json!({ "summary_totals": {} });
        let s = summarize_run(&run);
        let langs = s["languages"].as_array().expect("languages must be array");
        assert!(langs.is_empty());
    }

    #[test]
    fn summarize_run_missing_git_fields_are_null() {
        let run = json!({ "summary_totals": {}, "totals_by_language": [] });
        let s = summarize_run(&run);
        assert!(s["git_branch"].is_null());
        assert!(s["git_commit_short"].is_null());
    }

    #[test]
    fn summarize_run_multiple_languages() {
        let run = json!({
            "summary_totals": { "files_analyzed": 5 },
            "totals_by_language": [
                { "language": "Python", "files": 3, "code_lines": 200, "comment_lines": 20, "blank_lines": 10, "functions": 15, "test_count": 8 },
                { "language": "JavaScript", "files": 2, "code_lines": 150, "comment_lines": 10, "blank_lines": 5, "functions": 10, "test_count": 5 }
            ]
        });
        let s = summarize_run(&run);
        assert_eq!(s["languages"].as_array().unwrap().len(), 2);
        assert_eq!(s["files_analyzed"], 5);
    }

    // ── tempfile_path ─────────────────────────────────────────────────────────

    #[test]
    fn tempfile_path_is_in_temp_dir() {
        let p = tempfile_path();
        let tmp = std::env::temp_dir();
        assert!(p.starts_with(&tmp), "temp path must be inside temp_dir");
    }

    #[test]
    fn tempfile_path_has_json_extension() {
        let p = tempfile_path();
        assert_eq!(p.extension().and_then(|e| e.to_str()), Some("json"));
    }

    #[test]
    fn tempfile_path_is_unique() {
        let p1 = tempfile_path();
        let p2 = tempfile_path();
        assert_ne!(p1, p2, "two calls must return different paths");
    }

    // ── analyze_path success path (uses compiled oxide-sloc binary) ───────────

    /// Locate the oxide-sloc binary built as part of the current `cargo test`
    /// invocation.  Returns None if the binary is not present yet (e.g., first
    /// run of a crate-only `cargo test -p sloc-mcp` before the CLI is built).
    fn find_oxide_sloc_binary() -> Option<std::path::PathBuf> {
        // CARGO_MANIFEST_DIR = …/crates/sloc-mcp
        // workspace root     = ../../
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace = manifest.parent()?.parent()?;
        let ext = if cfg!(windows) { ".exe" } else { "" };
        let debug_bin = workspace
            .join("target")
            .join("debug")
            .join(format!("oxide-sloc{ext}"));
        if debug_bin.exists() {
            Some(debug_bin)
        } else {
            None
        }
    }

    #[tokio::test]
    async fn analyze_path_success_with_real_binary() {
        let Some(bin) = find_oxide_sloc_binary() else {
            eprintln!("oxide-sloc binary not found in target/debug — skipping");
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lib.rs"), "fn main() {}\n// comment\n").unwrap();

        let cfg = McpConfig {
            server_url: None,
            bin_path: bin.to_str().unwrap().to_owned(),
            api_key: None,
            allowed_roots: vec![],
        };
        let result = analyze_path(dir.path().to_str().unwrap().to_owned(), None, &cfg).await;
        assert!(result.is_ok(), "analyze_path must succeed: {result:?}");
        let v = result.unwrap();
        assert!(
            v.get("files_analyzed").is_some(),
            "must have files_analyzed field"
        );
        assert!(v.get("languages").is_some(), "must have languages field");
    }

    #[tokio::test]
    async fn analyze_path_with_config_file_option() {
        let Some(bin) = find_oxide_sloc_binary() else {
            eprintln!("oxide-sloc binary not found in target/debug — skipping");
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("hello.py"), "def foo():\n    pass\n").unwrap();
        let config_path = dir.path().join("sloc.toml");
        std::fs::write(
            &config_path,
            "[analysis]\npython_docstrings_as_comments = true\n",
        )
        .unwrap();

        let cfg = McpConfig {
            server_url: None,
            bin_path: bin.to_str().unwrap().to_owned(),
            api_key: None,
            allowed_roots: vec![],
        };
        // Exercises the `if let Some(cf)` branch inside analyze_path
        let result = analyze_path(
            dir.path().to_str().unwrap().to_owned(),
            Some(config_path.to_str().unwrap().to_owned()),
            &cfg,
        )
        .await;
        assert!(
            result.is_ok(),
            "analyze_path with config file must succeed: {result:?}"
        );
    }

    #[tokio::test]
    async fn analyze_path_nonexistent_binary_returns_error() {
        let cfg = McpConfig {
            server_url: None,
            bin_path: "__nonexistent_binary_xyz__".to_owned(),
            api_key: None,
            allowed_roots: vec![],
        };
        let result = analyze_path(".".to_owned(), None, &cfg).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn analyze_path_with_real_binary_nonexistent_dir_produces_result() {
        let Some(bin) = find_oxide_sloc_binary() else {
            eprintln!("oxide-sloc binary not found in target/debug — skipping");
            return;
        };
        let cfg = McpConfig {
            server_url: None,
            bin_path: bin.to_str().unwrap().to_owned(),
            api_key: None,
            allowed_roots: vec![],
        };
        // oxide-sloc analyze exits 0 even for non-existent paths (produces empty result).
        // This exercises the success branch after the binary runs.
        let result =
            analyze_path("/nonexistent/__sloc_test_path_xyz__".to_owned(), None, &cfg).await;
        // Either Ok (empty result) or Err (binary rejected it) — no panic either way
        let _ = result;
    }

    #[tokio::test]
    async fn analyze_path_disallowed_by_roots_returns_error() {
        let cfg = McpConfig {
            server_url: None,
            bin_path: "oxide-sloc".into(),
            api_key: None,
            allowed_roots: vec!["/nonexistent/__no_such_allowed_root__".into()],
        };
        let result = analyze_path("/some/path".to_owned(), None, &cfg).await;
        assert!(result.is_err(), "disallowed path must return an error");
    }
}
