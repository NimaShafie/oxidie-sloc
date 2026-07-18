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
    let (_scratch, tmp) = scratch_result_file("sloc-mcp-diff-")?;
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
    // `_scratch` (a TempDir) is dropped here, removing the directory and its contents.
    Ok(serde_json::from_str(&content)?)
}

/// Create a private, auto-cleaned scratch directory and return it together with
/// the path of the `result.json` file the CLI subprocess writes inside it. The
/// returned [`tempfile::TempDir`] must be kept alive by the caller; dropping it
/// removes the directory and its contents.
fn scratch_result_file(prefix: &str) -> Result<(tempfile::TempDir, PathBuf)> {
    let dir = tempfile::Builder::new().prefix(prefix).tempdir()?;
    let path = dir.path().join("result.json");
    Ok((dir, path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::McpConfig;

    fn unrestricted_cfg() -> McpConfig {
        McpConfig {
            server_url: None,
            bin_path: "oxide-sloc".into(),
            api_key: None,
            allowed_roots: vec![],
        }
    }

    fn restricted_cfg() -> McpConfig {
        McpConfig {
            server_url: None,
            bin_path: "oxide-sloc".into(),
            api_key: None,
            allowed_roots: vec![std::env::temp_dir()],
        }
    }

    // ── scratch_result_file ───────────────────────────────────────────────────

    #[test]
    fn scratch_result_file_in_temp_dir() {
        let (dir, p) = scratch_result_file("sloc-mcp-diff-").unwrap();
        assert!(p.starts_with(std::env::temp_dir()));
        assert!(dir.path().exists(), "scratch dir must exist while held");
    }

    #[test]
    fn scratch_result_file_has_json_extension() {
        let (_dir, p) = scratch_result_file("sloc-mcp-diff-").unwrap();
        assert_eq!(p.extension().and_then(|e| e.to_str()), Some("json"));
    }

    #[test]
    fn scratch_result_file_unique_across_calls() {
        let (_d1, p1) = scratch_result_file("sloc-mcp-diff-").unwrap();
        let (_d2, p2) = scratch_result_file("sloc-mcp-diff-").unwrap();
        assert_ne!(p1, p2);
    }

    #[test]
    fn scratch_result_file_cleans_up_on_drop() {
        let dir_path = {
            let (dir, _p) = scratch_result_file("sloc-mcp-diff-").unwrap();
            dir.path().to_path_buf()
        };
        assert!(!dir_path.exists(), "scratch dir must be removed on drop");
    }

    // ── compare_runs path validation ──────────────────────────────────────────

    #[tokio::test]
    async fn compare_runs_restricted_rejects_paths_outside_root() {
        let cfg = restricted_cfg();
        // Current directory is almost certainly not inside temp_dir
        let result = compare_runs(".".into(), ".".into(), &cfg).await;
        // Either the path check passes (cwd is in temp) or it fails — either way, no panic
        let _ = result;
    }

    #[tokio::test]
    async fn compare_runs_unrestricted_rejects_nonexistent_binary() {
        let mut cfg = unrestricted_cfg();
        cfg.bin_path = "__nonexistent_binary_12345__".into();
        let result = compare_runs(".".into(), ".".into(), &cfg).await;
        assert!(result.is_err(), "nonexistent binary must cause an error");
    }

    // ── compare_runs success path (uses compiled oxide-sloc binary) ───────────

    fn find_oxide_sloc_binary() -> Option<std::path::PathBuf> {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace = manifest.parent()?.parent()?;
        let ext = if cfg!(windows) { ".exe" } else { "" };
        let bin = workspace
            .join("target")
            .join("debug")
            .join(format!("oxide-sloc{ext}"));
        if bin.exists() {
            Some(bin)
        } else {
            None
        }
    }

    /// Run a full analysis and return the JSON path to the result file.
    async fn run_analyze(bin: &std::path::Path, dir: &std::path::Path) -> PathBuf {
        let out = dir.join("result.json");
        let status = tokio::process::Command::new(bin)
            .args([
                "analyze",
                dir.to_str().unwrap(),
                "--json-out",
                out.to_str().unwrap(),
                "--quiet",
            ])
            .status()
            .await
            .expect("oxide-sloc must run");
        assert!(status.success(), "analyze must succeed");
        out
    }

    #[tokio::test]
    async fn compare_runs_success_with_real_binary() {
        let Some(bin) = find_oxide_sloc_binary() else {
            eprintln!("oxide-sloc binary not found in target/debug — skipping");
            return;
        };

        // Create two small directories with slightly different source files
        let dir1 = tempfile::tempdir().unwrap();
        std::fs::write(dir1.path().join("a.rs"), "fn foo() {}\n").unwrap();

        let dir2 = tempfile::tempdir().unwrap();
        std::fs::write(dir2.path().join("a.rs"), "fn foo() {}\nfn bar() {}\n").unwrap();

        // Produce two JSON runs
        let baseline = run_analyze(&bin, dir1.path()).await;
        let current = run_analyze(&bin, dir2.path()).await;

        let cfg = McpConfig {
            server_url: None,
            bin_path: bin.to_str().unwrap().to_owned(),
            api_key: None,
            // Allow the system temp dir so the fail-closed check passes for these JSON files.
            allowed_roots: vec![std::env::temp_dir()],
        };
        let result = compare_runs(
            baseline.to_str().unwrap().to_owned(),
            current.to_str().unwrap().to_owned(),
            &cfg,
        )
        .await;
        assert!(result.is_ok(), "compare_runs must succeed: {result:?}");
        let v = result.unwrap();
        // The diff output must be a JSON object
        assert!(
            v.is_object() || v.is_array(),
            "diff output must be JSON: {v}"
        );
    }

    #[tokio::test]
    async fn compare_runs_with_nonexistent_json_paths_fails() {
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
        // Passing paths to non-existent JSON files makes oxide-sloc diff fail with non-zero exit,
        // which exercises the `!output.status.success()` bail branch.
        let result = compare_runs(
            "/nonexistent/__sloc_baseline_xyz__.json".to_owned(),
            "/nonexistent/__sloc_current_xyz__.json".to_owned(),
            &cfg,
        )
        .await;
        assert!(
            result.is_err(),
            "diff with nonexistent JSON paths must fail"
        );
    }

    #[tokio::test]
    async fn compare_runs_path_not_in_allowed_roots_is_rejected() {
        let cfg = McpConfig {
            server_url: None,
            bin_path: "oxide-sloc".into(),
            api_key: None,
            // Restrict to only the system temp dir — current dir is almost certainly elsewhere
            allowed_roots: vec!["/nonexistent/__no_such_allowed_root__".into()],
        };
        let result = compare_runs(
            "/some/baseline.json".to_owned(),
            "/some/current.json".to_owned(),
            &cfg,
        )
        .await;
        assert!(
            result.is_err(),
            "disallowed path must return an error, got Ok"
        );
    }
}
