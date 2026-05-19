use anyhow::Result;

#[derive(Debug, Clone)]
pub struct McpConfig {
    /// Base URL of a running oxide-sloc server. From SLOC_SERVER_URL.
    pub server_url: Option<String>,
    /// Path to the oxide-sloc binary. From SLOC_BIN; defaults to "oxide-sloc".
    pub bin_path: String,
    /// Bearer token for the server. From SLOC_API_KEY.
    pub api_key: Option<String>,
}

impl McpConfig {
    pub fn from_env() -> Result<Self> {
        let server_url = std::env::var("SLOC_SERVER_URL")
            .ok()
            .filter(|s| !s.is_empty());
        let bin_path = std::env::var("SLOC_BIN").unwrap_or_else(|_| "oxide-sloc".to_owned());
        let api_key = std::env::var("SLOC_API_KEY").ok().filter(|s| !s.is_empty());
        Ok(Self {
            server_url,
            bin_path,
            api_key,
        })
    }

    pub fn server_url(&self) -> anyhow::Result<&str> {
        self.server_url
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("SLOC_SERVER_URL is not set"))
    }
}
