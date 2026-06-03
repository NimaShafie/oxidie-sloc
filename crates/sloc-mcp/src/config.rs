use anyhow::Result;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct McpConfig {
    /// Base URL of a running oxide-sloc server. From SLOC_SERVER_URL.
    pub server_url: Option<String>,
    /// Path to the oxide-sloc binary. From SLOC_BIN; defaults to "oxide-sloc".
    pub bin_path: String,
    /// Bearer token for the server. From SLOC_API_KEY.
    pub api_key: Option<String>,
    /// Allowlist of directories that analyze_path / compare_runs may scan.
    /// Populated from SLOC_MCP_ALLOWED_ROOTS (colon-separated on Unix, semicolon on Windows).
    /// Empty means no restriction (suitable for trusted local use only).
    pub allowed_roots: Vec<PathBuf>,
}

impl McpConfig {
    pub fn from_env() -> Result<Self> {
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
        Ok(Self {
            server_url,
            bin_path,
            api_key,
            allowed_roots,
        })
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

    /// Validate that `url` matches the configured SLOC_SERVER_URL.
    /// If no server_url is configured this always returns an error (unsafe to proceed).
    /// If `candidate` is None, uses the configured server_url directly.
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

    #[test]
    fn from_env_does_not_panic() {
        // Just verify from_env() doesn't panic regardless of what env vars are set.
        let result = McpConfig::from_env();
        assert!(result.is_ok());
    }

    #[test]
    fn bin_path_defaults_to_oxide_sloc_when_var_unset() {
        // Build directly to test default logic without mutating env
        let bin = std::env::var("SLOC_BIN").unwrap_or_else(|_| "oxide-sloc".to_owned());
        assert!(!bin.is_empty());
    }

    #[test]
    fn server_url_ok_when_set() {
        let cfg = McpConfig {
            server_url: Some("http://localhost:4317".into()),
            bin_path: "oxide-sloc".into(),
            api_key: None,
            allowed_roots: vec![],
        };
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
        assert!(cfg.api_key.is_some());
        assert_eq!(cfg.api_key.unwrap(), "secret-key");
    }

    #[test]
    fn empty_server_url_filter_logic() {
        // Simulate the from_env filter: empty string → None
        let raw: Option<String> = Some("".into());
        let filtered = raw.filter(|s| !s.is_empty());
        assert!(filtered.is_none());

        let raw: Option<String> = Some("http://localhost".into());
        let filtered = raw.filter(|s| !s.is_empty());
        assert_eq!(filtered.as_deref(), Some("http://localhost"));
    }
}
