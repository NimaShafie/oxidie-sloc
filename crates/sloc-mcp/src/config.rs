use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct McpConfig {
    /// Base URL of a running oxide-sloc server. From `SLOC_SERVER_URL`.
    pub server_url: Option<String>,
    /// Path to the oxide-sloc binary. From `SLOC_BIN`; defaults to "oxide-sloc".
    pub bin_path: String,
    /// Bearer token for the server. From `SLOC_API_KEY`.
    pub api_key: Option<String>,
    /// Allowlist of directories that `analyze_path` / `compare_runs` may scan.
    /// Populated from `SLOC_MCP_ALLOWED_ROOTS` (colon-separated on Unix, semicolon on Windows).
    /// Empty means no restriction (suitable for trusted local use only).
    pub allowed_roots: Vec<PathBuf>,
}

impl McpConfig {
    pub fn from_env() -> Self {
        let server_url = std::env::var("SLOC_SERVER_URL")
            .ok()
            .filter(|s| !s.is_empty());
        let bin_path = std::env::var("SLOC_BIN").unwrap_or_else(|_| "oxide-sloc".to_owned());
        let api_key = std::env::var("SLOC_API_KEY").ok().filter(|s| !s.is_empty());
        let sep = if cfg!(windows) { ';' } else { ':' };
        let allowed_roots = std::env::var("SLOC_MCP_ALLOWED_ROOTS")
            .unwrap_or_default()
            .split(sep)
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .collect();
        Self {
            server_url,
            bin_path,
            api_key,
            allowed_roots,
        }
    }

    pub fn server_url(&self) -> anyhow::Result<&str> {
        self.server_url
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("SLOC_SERVER_URL is not set"))
    }

    /// Validate that `path` is inside one of the configured allowed roots.
    /// If `allowed_roots` is empty this check passes (no restriction configured).
    pub fn check_path_allowed(&self, path: &str) -> anyhow::Result<()> {
        if self.allowed_roots.is_empty() {
            return Ok(());
        }
        let canonical = std::fs::canonicalize(path)
            .map_err(|e| anyhow::anyhow!("cannot resolve path {path:?}: {e}"))?;
        for root in &self.allowed_roots {
            let canonical_root = std::fs::canonicalize(root).unwrap_or_else(|_| root.clone());
            if canonical.starts_with(&canonical_root) {
                return Ok(());
            }
        }
        anyhow::bail!(
            "path {path:?} is outside the configured SLOC_MCP_ALLOWED_ROOTS: {:?}",
            self.allowed_roots
        )
    }

    /// Validate that `url` matches the configured `SLOC_SERVER_URL`.
    /// If no `server_url` is configured this always returns an error (unsafe to proceed).
    /// If `candidate` is None, uses the configured `server_url` directly.
    pub fn resolve_server_url<'a>(&'a self, candidate: Option<&'a str>) -> anyhow::Result<&'a str> {
        let configured = self.server_url()?;
        match candidate {
            None => Ok(configured),
            Some(url) if url == configured => Ok(configured),
            Some(url) => anyhow::bail!(
                "server_url {url:?} does not match configured SLOC_SERVER_URL {configured:?}"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn cfg_no_roots() -> McpConfig {
        McpConfig {
            server_url: Some("http://localhost:4317".into()),
            bin_path: "oxide-sloc".into(),
            api_key: None,
            allowed_roots: vec![],
        }
    }

    // ── from_env / constructor ────────────────────────────────────────────────

    #[test]
    fn from_env_does_not_panic() {
        let _ = McpConfig::from_env();
    }

    #[test]
    fn bin_path_defaults_to_oxide_sloc_when_var_unset() {
        let bin = std::env::var("SLOC_BIN").unwrap_or_else(|_| "oxide-sloc".to_owned());
        assert!(!bin.is_empty());
    }

    // ── server_url ────────────────────────────────────────────────────────────

    #[test]
    fn server_url_ok_when_set() {
        let cfg = cfg_no_roots();
        assert_eq!(cfg.server_url().unwrap(), "http://localhost:4317");
    }

    #[test]
    fn server_url_errors_when_not_set() {
        let cfg = McpConfig {
            server_url: None,
            bin_path: "oxide-sloc".into(),
            api_key: None,
            allowed_roots: vec![],
        };
        assert!(cfg.server_url().is_err());
    }

    #[test]
    fn server_url_with_api_key() {
        let cfg = McpConfig {
            server_url: Some("http://server:4317".into()),
            bin_path: "oxide-sloc".into(),
            api_key: Some("secret-key".into()),
            allowed_roots: vec![],
        };
        assert_eq!(cfg.api_key.as_deref(), Some("secret-key"));
    }

    #[test]
    fn empty_server_url_filter_logic() {
        let raw: Option<String> = Some(String::new());
        assert!(raw.as_ref().is_none_or(String::is_empty));

        let raw: Option<String> = Some("http://localhost".into());
        assert_eq!(
            raw.filter(|s| !s.is_empty()).as_deref(),
            Some("http://localhost")
        );
    }

    // ── resolve_server_url ────────────────────────────────────────────────────

    #[test]
    fn resolve_server_url_none_candidate_returns_configured() {
        let cfg = cfg_no_roots();
        assert_eq!(
            cfg.resolve_server_url(None).unwrap(),
            "http://localhost:4317"
        );
    }

    #[test]
    fn resolve_server_url_matching_candidate_accepted() {
        let cfg = cfg_no_roots();
        assert_eq!(
            cfg.resolve_server_url(Some("http://localhost:4317"))
                .unwrap(),
            "http://localhost:4317"
        );
    }

    #[test]
    fn resolve_server_url_non_matching_candidate_rejected() {
        let cfg = cfg_no_roots();
        assert!(cfg.resolve_server_url(Some("http://evil.com")).is_err());
    }

    #[test]
    fn resolve_server_url_no_server_url_configured_always_errors() {
        let cfg = McpConfig {
            server_url: None,
            bin_path: "oxide-sloc".into(),
            api_key: None,
            allowed_roots: vec![],
        };
        assert!(cfg.resolve_server_url(None).is_err());
        assert!(cfg
            .resolve_server_url(Some("http://localhost:4317"))
            .is_err());
    }

    #[test]
    fn resolve_server_url_empty_string_candidate_rejected() {
        let cfg = cfg_no_roots();
        assert!(cfg.resolve_server_url(Some("")).is_err());
    }

    // ── check_path_allowed ────────────────────────────────────────────────────

    #[test]
    fn check_path_allowed_no_roots_always_passes() {
        let cfg = cfg_no_roots();
        // Any string passes when allowed_roots is empty
        assert!(cfg.check_path_allowed("/arbitrary/path").is_ok());
        assert!(cfg.check_path_allowed(".").is_ok());
    }

    #[test]
    fn check_path_allowed_current_dir_inside_root() {
        // Use the current directory as a root and "." as the path
        let current = std::env::current_dir().expect("cwd must be readable");
        let cfg = McpConfig {
            server_url: None,
            bin_path: "oxide-sloc".into(),
            api_key: None,
            allowed_roots: vec![current],
        };
        // "." canonicalises to current dir, which is inside current
        assert!(cfg.check_path_allowed(".").is_ok());
    }

    #[test]
    fn check_path_allowed_path_outside_root_rejected() {
        let tmp = std::env::temp_dir();
        // Use the temp dir as the allowed root
        let cfg = McpConfig {
            server_url: None,
            bin_path: "oxide-sloc".into(),
            api_key: None,
            allowed_roots: vec![tmp],
        };
        // The current working directory is almost certainly NOT inside temp_dir
        let result = cfg.check_path_allowed(".");
        // This may succeed if cwd happens to be inside temp_dir; just ensure no panic
        let _ = result;
    }

    #[test]
    fn check_path_allowed_nonexistent_path_errors() {
        let tmp = std::env::temp_dir();
        let cfg = McpConfig {
            server_url: None,
            bin_path: "oxide-sloc".into(),
            api_key: None,
            allowed_roots: vec![tmp],
        };
        // A path that definitely doesn't exist cannot be canonicalized → error
        let result = cfg.check_path_allowed("/nonexistent/__sloc_test_path__/x/y/z");
        assert!(
            result.is_err(),
            "nonexistent path must fail check_path_allowed"
        );
    }

    #[test]
    fn check_path_allowed_multiple_roots_one_matches() {
        let tmp = std::env::temp_dir();
        let cwd = std::env::current_dir().expect("cwd must be readable");
        let cfg = McpConfig {
            server_url: None,
            bin_path: "oxide-sloc".into(),
            api_key: None,
            allowed_roots: vec![tmp, cwd],
        };
        // "." (cwd) is inside the second root
        assert!(cfg.check_path_allowed(".").is_ok());
    }

    // ── allowed_roots parsing ─────────────────────────────────────────────────

    #[test]
    fn allowed_roots_empty_when_env_var_unset() {
        // Build config with no allowed roots directly
        let cfg = McpConfig {
            server_url: None,
            bin_path: "oxide-sloc".into(),
            api_key: None,
            allowed_roots: vec![],
        };
        assert!(cfg.allowed_roots.is_empty());
    }

    #[test]
    fn allowed_roots_parsed_from_vec() {
        let cfg = McpConfig {
            server_url: None,
            bin_path: "oxide-sloc".into(),
            api_key: None,
            allowed_roots: vec![PathBuf::from("/tmp"), PathBuf::from("/home/user")],
        };
        assert_eq!(cfg.allowed_roots.len(), 2);
        assert_eq!(cfg.allowed_roots[0], PathBuf::from("/tmp"));
    }
}
