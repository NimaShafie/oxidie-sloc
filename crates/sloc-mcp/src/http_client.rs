use anyhow::Result;
use serde_json::Value;

pub struct HttpClient {
    client: reqwest::Client,
    api_key: Option<String>,
}

impl HttpClient {
    pub fn new(api_key: Option<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_key,
        }
    }

    pub async fn get_json(&self, url: &str) -> Result<Value> {
        let mut req = self.client.get(url);
        if let Some(key) = &self.api_key {
            req = req.bearer_auth(key);
        }
        let resp = req.send().await?;
        let status = resp.status();
        if !status.is_success() {
            anyhow::bail!("server returned {status} for GET {url}");
        }
        Ok(resp.json().await?)
    }

    pub async fn post_json(&self, url: &str, body: &Value) -> Result<Value> {
        let mut req = self.client.post(url).json(body);
        if let Some(key) = &self.api_key {
            req = req.bearer_auth(key);
        }
        let resp = req.send().await?;
        let status = resp.status();
        if !status.is_success() {
            anyhow::bail!("server returned {status} for POST {url}");
        }
        Ok(resp.json().await?)
    }
}
