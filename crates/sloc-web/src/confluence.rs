// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Nima Shafie <nimzshafie@gmail.com>
//
// Atlassian Confluence integration — Cloud (API v2) and Server/DC (API v1).

use std::collections::HashMap;
use std::path::Path;

use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Json, Response},
};
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use sloc_core::read_json;
use sloc_report::{render_confluence_storage, render_confluence_wiki_markup};

use super::{recover_artifacts_from_registry, AppState};

// ── config structs ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConfluenceTier {
    /// Atlassian Cloud — uses REST API v2 at /wiki/api/v2/
    #[default]
    Cloud,
    /// Self-hosted Confluence Server or Data Center — uses REST API v1 at /rest/api/
    Server,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConfluenceConfig {
    pub tier: ConfluenceTier,
    /// Base URL, e.g. "<https://mycompany.atlassian.net>" or "<https://confluence.corp.com>"
    pub base_url: String,
    /// Cloud: Atlassian account email. Server: username (blank if using a PAT).
    pub username: String,
    /// Cloud: API token. Server: password or Personal Access Token.
    #[serde(skip)]
    pub credential: String,
    pub space_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_page_id: Option<String>,
    /// per-schedule auto-post override; key = schedule UUID string, value = enabled
    #[serde(default)]
    pub schedule_auto_post: HashMap<String, bool>,
}

impl ConfluenceConfig {
    fn is_cloud_url(&self) -> bool {
        self.base_url.to_lowercase().contains(".atlassian.net")
    }

    fn effective_tier(&self) -> &ConfluenceTier {
        if self.tier == ConfluenceTier::Cloud || self.is_cloud_url() {
            &ConfluenceTier::Cloud
        } else {
            &ConfluenceTier::Server
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConfluenceConfigStore {
    pub config: Option<ConfluenceConfig>,
}

impl ConfluenceConfigStore {
    pub fn load(path: &Path) -> Self {
        let mut store: Self = std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        if let Some(ref mut cfg) = store.config {
            if let Ok(token) = std::env::var("SLOC_CONFLUENCE_TOKEN") {
                cfg.credential = token;
            }
        }
        store
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    pub fn is_configured(&self) -> bool {
        self.config
            .as_ref()
            .is_some_and(|c| !c.base_url.is_empty() && !c.credential.is_empty())
    }
}

// ── Confluence API client ─────────────────────────────────────────────────────

pub struct ConfluenceClient {
    client: reqwest::Client,
    base_url: String,
    auth_header: String,
    tier: ConfluenceTier,
    space_key: String,
    parent_page_id: Option<String>,
}

struct PageSummary {
    id: String,
    version_number: u32,
}

impl ConfluenceClient {
    pub fn new(config: &ConfluenceConfig) -> Self {
        let auth_header = if config.username.is_empty() {
            // Server PAT — Bearer token
            format!("Bearer {}", config.credential)
        } else {
            let raw = format!("{}:{}", config.username, config.credential);
            let encoded = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
            format!("Basic {encoded}")
        };

        Self {
            client: reqwest::Client::new(),
            base_url: config.base_url.trim_end_matches('/').to_owned(),
            auth_header,
            tier: config.effective_tier().clone(),
            space_key: config.space_key.clone(),
            parent_page_id: config.parent_page_id.clone(),
        }
    }

    async fn find_space_id(&self) -> anyhow::Result<String> {
        let url = format!(
            "{}/wiki/api/v2/spaces?keys={}&limit=1",
            self.base_url, self.space_key
        );
        let resp: serde_json::Value = self
            .client
            .get(&url)
            .header("Authorization", &self.auth_header)
            .header("Accept", "application/json")
            .send()
            .await?
            .json()
            .await?;
        resp["results"][0]["id"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| anyhow::anyhow!("Confluence space '{}' not found", self.space_key))
    }

    async fn find_page_cloud(
        &self,
        space_id: &str,
        title: &str,
    ) -> anyhow::Result<Option<PageSummary>> {
        let enc = urlencoding_encode(title);
        let url = format!(
            "{}/wiki/api/v2/pages?spaceId={}&title={}&limit=1&expand=version",
            self.base_url, space_id, enc
        );
        let resp: serde_json::Value = self
            .client
            .get(&url)
            .header("Authorization", &self.auth_header)
            .header("Accept", "application/json")
            .send()
            .await?
            .json()
            .await?;
        let results = resp["results"].as_array();
        if results.is_none_or(std::vec::Vec::is_empty) {
            return Ok(None);
        }
        let page = &resp["results"][0];
        let id = page["id"].as_str().unwrap_or("").to_owned();
        // Confluence version numbers are small; truncation is not possible in practice.
        #[allow(clippy::cast_possible_truncation)]
        let ver = page["version"]["number"].as_u64().unwrap_or(1) as u32;
        Ok(Some(PageSummary {
            id,
            version_number: ver,
        }))
    }

    async fn find_page_server(&self, title: &str) -> anyhow::Result<Option<PageSummary>> {
        let enc = urlencoding_encode(title);
        let url = format!(
            "{}/rest/api/content?spaceKey={}&title={}&type=page&expand=version&limit=1",
            self.base_url, self.space_key, enc
        );
        let resp: serde_json::Value = self
            .client
            .get(&url)
            .header("Authorization", &self.auth_header)
            .header("Accept", "application/json")
            .send()
            .await?
            .json()
            .await?;
        let results = resp["results"].as_array();
        if results.is_none_or(std::vec::Vec::is_empty) {
            return Ok(None);
        }
        let page = &resp["results"][0];
        let id = page["id"].as_str().unwrap_or("").to_owned();
        // Confluence version numbers are small; truncation is not possible in practice.
        #[allow(clippy::cast_possible_truncation)]
        let ver = page["version"]["number"].as_u64().unwrap_or(1) as u32;
        Ok(Some(PageSummary {
            id,
            version_number: ver,
        }))
    }

    async fn create_cloud(
        &self,
        space_id: &str,
        title: &str,
        body_html: &str,
    ) -> anyhow::Result<String> {
        let mut payload = serde_json::json!({
            "spaceId": space_id,
            "title": title,
            "body": { "representation": "storage", "value": body_html }
        });
        if let Some(parent_id) = &self.parent_page_id {
            payload["parentId"] = serde_json::Value::String(parent_id.clone());
        }
        let resp = self
            .client
            .post(format!("{}/wiki/api/v2/pages", self.base_url))
            .header("Authorization", &self.auth_header)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(&payload)
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Confluence Cloud create failed (HTTP {status}): {body}");
        }
        let created: serde_json::Value = resp.json().await?;
        Ok(created["id"].as_str().unwrap_or("").to_owned())
    }

    async fn create_server(&self, title: &str, body_html: &str) -> anyhow::Result<String> {
        let mut payload = serde_json::json!({
            "type": "page",
            "space": { "key": self.space_key },
            "title": title,
            "body": { "storage": { "value": body_html, "representation": "storage" } }
        });
        if let Some(parent_id) = &self.parent_page_id {
            payload["ancestors"] = serde_json::json!([{ "id": parent_id }]);
        }
        let resp = self
            .client
            .post(format!("{}/rest/api/content", self.base_url))
            .header("Authorization", &self.auth_header)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(&payload)
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Confluence Server create failed (HTTP {status}): {body}");
        }
        let created: serde_json::Value = resp.json().await?;
        Ok(created["id"].as_str().unwrap_or("").to_owned())
    }

    async fn update_cloud(
        &self,
        page_id: &str,
        ver: u32,
        title: &str,
        body_html: &str,
    ) -> anyhow::Result<()> {
        let payload = serde_json::json!({
            "version": { "number": ver + 1 },
            "title": title,
            "body": { "representation": "storage", "value": body_html }
        });
        let resp = self
            .client
            .put(format!("{}/wiki/api/v2/pages/{page_id}", self.base_url))
            .header("Authorization", &self.auth_header)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(&payload)
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Confluence Cloud update failed (HTTP {status}): {body}");
        }
        Ok(())
    }

    async fn update_server(
        &self,
        page_id: &str,
        ver: u32,
        title: &str,
        body_html: &str,
    ) -> anyhow::Result<()> {
        let payload = serde_json::json!({
            "version": { "number": ver + 1 },
            "type": "page",
            "title": title,
            "space": { "key": self.space_key },
            "body": { "storage": { "value": body_html, "representation": "storage" } }
        });
        let resp = self
            .client
            .put(format!("{}/rest/api/content/{page_id}", self.base_url))
            .header("Authorization", &self.auth_header)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(&payload)
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Confluence Server update failed (HTTP {status}): {body}");
        }
        Ok(())
    }

    pub async fn test_connection(&self) -> anyhow::Result<()> {
        let url = match self.tier {
            ConfluenceTier::Cloud => {
                format!("{}/wiki/api/v2/spaces?limit=1", self.base_url)
            }
            ConfluenceTier::Server => {
                format!("{}/rest/api/space?limit=1", self.base_url)
            }
        };
        let resp = self
            .client
            .get(&url)
            .header("Authorization", &self.auth_header)
            .header("Accept", "application/json")
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status();
            anyhow::bail!("Confluence connection test failed (HTTP {status})");
        }
        Ok(())
    }
}

/// Create or update a Confluence page with the SLOC scan result. Returns the
/// page ID of the created or updated page.
pub async fn post_to_confluence(
    client: &ConfluenceClient,
    run: &sloc_core::AnalysisRun,
    page_title: &str,
    report_url: Option<&str>,
) -> anyhow::Result<String> {
    let body_html = render_confluence_storage(run, report_url);

    match client.tier {
        ConfluenceTier::Cloud => {
            let space_id = client.find_space_id().await?;
            match client.find_page_cloud(&space_id, page_title).await? {
                None => client.create_cloud(&space_id, page_title, &body_html).await,
                Some(existing) => {
                    client
                        .update_cloud(
                            &existing.id,
                            existing.version_number,
                            page_title,
                            &body_html,
                        )
                        .await?;
                    Ok(existing.id)
                }
            }
        }
        ConfluenceTier::Server => match client.find_page_server(page_title).await? {
            None => client.create_server(page_title, &body_html).await,
            Some(existing) => {
                client
                    .update_server(
                        &existing.id,
                        existing.version_number,
                        page_title,
                        &body_html,
                    )
                    .await?;
                Ok(existing.id)
            }
        },
    }
}

// ── request / response types ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SaveConfluenceConfig {
    pub tier: Option<String>,
    pub base_url: String,
    pub username: String,
    /// Blank means "keep existing credential"
    pub credential: String,
    pub space_key: String,
    pub parent_page_id: Option<String>,
    #[serde(default)]
    pub schedule_auto_post: HashMap<String, bool>,
}

#[derive(Debug, Deserialize)]
pub struct PostToConfluenceRequest {
    pub run_id: String,
    pub page_title: String,
    pub report_url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RunIdQuery {
    pub run_id: String,
}

// ── route handlers ────────────────────────────────────────────────────────────

pub async fn api_get_confluence_config(State(state): State<AppState>) -> impl IntoResponse {
    let store = state.confluence.lock().await;
    Json(store.config.as_ref().map_or_else(
        || {
            serde_json::json!({
                "configured": false,
                "tier": "cloud",
                "base_url": "",
                "username": "",
                "api_token_set": false,
                "space_key": "",
                "parent_page_id": null,
                "schedule_auto_post": {}
            })
        },
        |c| {
            serde_json::json!({
                "configured": true,
                "tier": if c.tier == ConfluenceTier::Cloud { "cloud" } else { "server" },
                "base_url": c.base_url,
                "username": c.username,
                "api_token_set": !c.credential.is_empty(),
                "space_key": c.space_key,
                "parent_page_id": c.parent_page_id,
                "schedule_auto_post": c.schedule_auto_post
            })
        },
    ))
}

pub async fn api_save_confluence_config(
    State(state): State<AppState>,
    Json(body): Json<SaveConfluenceConfig>,
) -> impl IntoResponse {
    let tier = match body.tier.as_deref() {
        Some("server") => ConfluenceTier::Server,
        _ => ConfluenceTier::Cloud,
    };

    let mut store = state.confluence.lock().await;
    let existing_credential = store
        .config
        .as_ref()
        .map(|c| c.credential.clone())
        .unwrap_or_default();

    let credential = if body.credential.is_empty() {
        existing_credential
    } else {
        body.credential.clone()
    };

    store.config = Some(ConfluenceConfig {
        tier,
        base_url: body.base_url.trim_end_matches('/').to_owned(),
        username: body.username.clone(),
        credential,
        space_key: body.space_key.clone(),
        parent_page_id: body.parent_page_id.clone().filter(|s| !s.is_empty()),
        schedule_auto_post: body.schedule_auto_post.clone(),
    });
    let _ = store.save(&state.confluence_path);
    drop(store);
    Json(serde_json::json!({ "ok": true }))
}

pub async fn api_test_confluence(State(state): State<AppState>) -> Response {
    let config = {
        let store = state.confluence.lock().await;
        store.config.clone()
    };
    let Some(config) = config else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "ok": false, "error": "Confluence is not configured." })),
        )
            .into_response();
    };
    let client = ConfluenceClient::new(&config);
    match client.test_connection().await {
        Ok(()) => Json(serde_json::json!({ "ok": true })).into_response(),
        Err(e) => {
            tracing::warn!("Confluence connection test failed: {e:#}");
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "ok": false, "error": "Connection test failed." })),
            )
                .into_response()
        }
    }
}

pub async fn api_post_to_confluence(
    State(state): State<AppState>,
    Json(body): Json<PostToConfluenceRequest>,
) -> Response {
    if body.run_id.is_empty()
        || body.run_id.len() > 128
        || !body
            .run_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "ok": false, "error": "Invalid run_id" })),
        )
            .into_response();
    }

    let config = {
        let store = state.confluence.lock().await;
        store.config.clone()
    };
    let Some(config) = config else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "error": "Confluence is not configured. Visit /confluence-setup first."
            })),
        )
            .into_response();
    };

    // Locate artifacts
    let artifacts = {
        let map = state.artifacts.lock().await;
        map.get(&body.run_id).cloned()
    };
    let artifacts = if let Some(a) = artifacts {
        a
    } else {
        let reg = state.registry.lock().await;
        match reg.find_by_run_id(&body.run_id) {
            Some(entry) => recover_artifacts_from_registry(entry),
            None => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({
                        "ok": false,
                        "error": "Run not found in scan history."
                    })),
                )
                    .into_response();
            }
        }
    };

    let json_path = match &artifacts.json_path {
        Some(p) => p.clone(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "error": "No JSON result saved for this run."
                })),
            )
                .into_response();
        }
    };

    let run = match read_json(&json_path) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "ok": false,
                    "error": format!("Could not load scan result: {e}")
                })),
            )
                .into_response();
        }
    };

    let client = ConfluenceClient::new(&config);
    let report_url = body.report_url.as_deref();

    match post_to_confluence(&client, &run, &body.page_title, report_url).await {
        Ok(page_id) => Json(serde_json::json!({ "ok": true, "page_id": page_id })).into_response(),
        Err(e) => {
            tracing::warn!("Confluence publish failed for run '{}': {e:#}", body.run_id);
            (
                StatusCode::BAD_GATEWAY,
                Json(
                    serde_json::json!({ "ok": false, "error": "Failed to publish to Confluence." }),
                ),
            )
                .into_response()
        }
    }
}

pub async fn api_wiki_markup(
    State(state): State<AppState>,
    Query(q): Query<RunIdQuery>,
) -> Response {
    if q.run_id.len() > 128 || q.run_id.contains('/') || q.run_id.contains('\\') {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let artifacts = {
        let map = state.artifacts.lock().await;
        map.get(&q.run_id).cloned()
    };
    let artifacts = if let Some(a) = artifacts {
        a
    } else {
        let reg = state.registry.lock().await;
        match reg.find_by_run_id(&q.run_id) {
            Some(entry) => recover_artifacts_from_registry(entry),
            None => return StatusCode::NOT_FOUND.into_response(),
        }
    };

    let json_path = match &artifacts.json_path {
        Some(p) => p.clone(),
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    let Ok(run) = read_json(&json_path) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };

    let markup = render_confluence_wiki_markup(&run);
    (
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        markup,
    )
        .into_response()
}

// ── auto-post hook (called from git_webhook.rs) ────────────────────────────────

pub async fn maybe_auto_post_confluence(
    state: &AppState,
    sched_id: uuid::Uuid,
    run: &sloc_core::AnalysisRun,
    run_id: &str,
) {
    let (config, enabled) = {
        let store = state.confluence.lock().await;
        let en = store
            .config
            .as_ref()
            .and_then(|c| c.schedule_auto_post.get(&sched_id.to_string()))
            .copied()
            .unwrap_or(false);
        (store.config.clone(), en)
    };

    if !enabled {
        return;
    }
    let Some(config) = config else { return };

    let client = ConfluenceClient::new(&config);
    let title = format!(
        "OxideSLOC — {} ({})",
        run.effective_configuration.reporting.report_title,
        &run_id[..run_id.len().min(8)]
    );

    // Build a server URL for the report link using bind_address from config
    let bind = &state.base_config.web.bind_address;
    let proto = if state.tls_enabled { "https" } else { "http" };
    let report_url = format!("{proto}://{bind}/runs/result/{run_id}");

    if let Err(e) = post_to_confluence(&client, run, &title, Some(&report_url)).await {
        eprintln!("[sloc-confluence] auto-post failed for schedule {sched_id}: {e:#}");
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn urlencoding_encode(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            b' ' => out.push('+'),
            _ => {
                out.push('%');
                write!(out, "{b:02X}").expect("write to String is infallible");
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    // ── ConfluenceTier default ────────────────────────────────────────────────

    #[test]
    fn tier_default_is_cloud() {
        assert_eq!(ConfluenceTier::default(), ConfluenceTier::Cloud);
    }

    // ── ConfluenceConfig::is_cloud_url / effective_tier ───────────────────────

    #[test]
    fn effective_tier_atlassian_net_is_cloud() {
        let cfg = ConfluenceConfig {
            tier: ConfluenceTier::Server,
            base_url: "https://mycompany.atlassian.net".into(),
            ..Default::default()
        };
        assert_eq!(cfg.effective_tier(), &ConfluenceTier::Cloud);
    }

    #[test]
    fn effective_tier_server_url_is_server() {
        let cfg = ConfluenceConfig {
            tier: ConfluenceTier::Server,
            base_url: "https://confluence.corp.com".into(),
            ..Default::default()
        };
        assert_eq!(cfg.effective_tier(), &ConfluenceTier::Server);
    }

    #[test]
    fn effective_tier_cloud_flag_overrides_non_cloud_url() {
        let cfg = ConfluenceConfig {
            tier: ConfluenceTier::Cloud,
            base_url: "https://confluence.corp.com".into(),
            ..Default::default()
        };
        // tier field is Cloud, so effective_tier must also be Cloud
        assert_eq!(cfg.effective_tier(), &ConfluenceTier::Cloud);
    }

    // ── ConfluenceConfigStore::is_configured ──────────────────────────────────

    #[test]
    fn is_configured_no_config_returns_false() {
        let store = ConfluenceConfigStore { config: None };
        assert!(!store.is_configured());
    }

    #[test]
    fn is_configured_empty_base_url_returns_false() {
        let store = ConfluenceConfigStore {
            config: Some(ConfluenceConfig {
                base_url: String::new(),
                credential: "token".into(),
                ..Default::default()
            }),
        };
        assert!(!store.is_configured());
    }

    #[test]
    fn is_configured_empty_credential_returns_false() {
        let store = ConfluenceConfigStore {
            config: Some(ConfluenceConfig {
                base_url: "https://mycompany.atlassian.net".into(),
                credential: String::new(),
                ..Default::default()
            }),
        };
        assert!(!store.is_configured());
    }

    #[test]
    fn is_configured_both_fields_set_returns_true() {
        let store = ConfluenceConfigStore {
            config: Some(ConfluenceConfig {
                base_url: "https://mycompany.atlassian.net".into(),
                credential: "my-api-token".into(),
                ..Default::default()
            }),
        };
        assert!(store.is_configured());
    }

    // ── ConfluenceConfigStore::save / load round-trip ─────────────────────────

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("confluence.json");

        let original = ConfluenceConfigStore {
            config: Some(ConfluenceConfig {
                tier: ConfluenceTier::Server,
                base_url: "https://confluence.corp.com".into(),
                username: "alice".into(),
                credential: "secret".into(),
                space_key: "DEV".into(),
                parent_page_id: Some("12345".into()),
                schedule_auto_post: std::collections::HashMap::new(),
            }),
        };

        original.save(&path).expect("save must succeed");

        // credential is #[serde(skip)] so it won't be in the file
        let loaded = ConfluenceConfigStore::load(&path);
        assert!(loaded.config.is_some());
        let cfg = loaded.config.as_ref().unwrap();
        assert_eq!(cfg.base_url, "https://confluence.corp.com");
        assert_eq!(cfg.username, "alice");
        assert_eq!(cfg.space_key, "DEV");
        assert_eq!(cfg.parent_page_id.as_deref(), Some("12345"));
        // credential is skipped in serialization
        assert!(cfg.credential.is_empty());
    }

    #[test]
    fn load_nonexistent_file_returns_default() {
        let store = ConfluenceConfigStore::load(std::path::Path::new(
            "/nonexistent/__sloc_test_confluence__.json",
        ));
        assert!(store.config.is_none());
        assert!(!store.is_configured());
    }

    #[test]
    fn save_empty_store_then_load() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("empty.json");
        let store = ConfluenceConfigStore { config: None };
        store.save(&path).expect("save empty store must succeed");
        let loaded = ConfluenceConfigStore::load(&path);
        assert!(loaded.config.is_none());
    }

    // ── urlencoding_encode ────────────────────────────────────────────────────

    #[test]
    fn encode_alphanumeric_unchanged() {
        assert_eq!(urlencoding_encode("HelloWorld123"), "HelloWorld123");
    }

    #[test]
    fn encode_unreserved_chars_unchanged() {
        assert_eq!(urlencoding_encode("-_.~"), "-_.~");
    }

    #[test]
    fn encode_space_becomes_plus() {
        assert_eq!(urlencoding_encode("hello world"), "hello+world");
    }

    #[test]
    fn encode_slash_percent_encoded() {
        assert_eq!(urlencoding_encode("a/b"), "a%2Fb");
    }

    #[test]
    fn encode_ampersand_percent_encoded() {
        assert_eq!(urlencoding_encode("a&b"), "a%26b");
    }

    #[test]
    fn encode_empty_string() {
        assert_eq!(urlencoding_encode(""), "");
    }

    #[test]
    fn encode_mixed_content() {
        let result = urlencoding_encode("My Report 2024/01");
        assert!(result.contains("My+Report+2024"));
        assert!(result.contains("%2F01"));
    }
}

// ── HTTP-mocked tests for ConfluenceClient ────────────────────────────────────
//
// Uses a minimal Axum router on a random port (tokio TcpListener) as the mock
// Confluence server. No extra deps — axum and tokio are already in [dependencies].

#[cfg(test)]
mod http_tests {
    use super::*;
    use axum::{routing, Json, Router};
    use std::net::SocketAddr;

    fn setup_tls() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    fn cloud_cfg(base_url: &str) -> ConfluenceConfig {
        ConfluenceConfig {
            tier: ConfluenceTier::Cloud,
            base_url: base_url.to_owned(),
            username: "user@example.com".to_owned(),
            credential: "api-token-123".to_owned(),
            space_key: "MYSPACE".to_owned(),
            parent_page_id: None,
            schedule_auto_post: Default::default(),
        }
    }

    fn server_cfg(base_url: &str) -> ConfluenceConfig {
        ConfluenceConfig {
            tier: ConfluenceTier::Server,
            base_url: base_url.to_owned(),
            username: "admin".to_owned(),
            credential: "password".to_owned(),
            space_key: "MYSPACE".to_owned(),
            parent_page_id: None,
            schedule_auto_post: Default::default(),
        }
    }

    /// Spin up a throw-away Axum app on an ephemeral port, return the bound address.
    async fn start_mock(app: Router) -> SocketAddr {
        // Install a TLS crypto provider so reqwest::Client::new() doesn't panic.
        setup_tls();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });
        addr
    }

    #[tokio::test]
    async fn test_connection_cloud_ok() {
        let app = Router::new().route(
            "/wiki/api/v2/spaces",
            routing::get(|| async { Json(serde_json::json!({"results": []})) }),
        );
        let addr = start_mock(app).await;
        let client = ConfluenceClient::new(&cloud_cfg(&format!("http://{addr}")));
        assert!(
            client.test_connection().await.is_ok(),
            "test_connection should succeed with 200"
        );
    }

    #[tokio::test]
    async fn test_connection_cloud_unauthorized() {
        use axum::http::StatusCode;
        let app = Router::new().route(
            "/wiki/api/v2/spaces",
            routing::get(|| async { StatusCode::UNAUTHORIZED }),
        );
        let addr = start_mock(app).await;
        let client = ConfluenceClient::new(&cloud_cfg(&format!("http://{addr}")));
        assert!(
            client.test_connection().await.is_err(),
            "test_connection should fail with 401"
        );
    }

    #[tokio::test]
    async fn test_connection_server_ok() {
        let app = Router::new().route(
            "/rest/api/space",
            routing::get(|| async { Json(serde_json::json!({"results": []})) }),
        );
        let addr = start_mock(app).await;
        let client = ConfluenceClient::new(&server_cfg(&format!("http://{addr}")));
        assert!(
            client.test_connection().await.is_ok(),
            "server test_connection should succeed"
        );
    }

    #[tokio::test]
    async fn test_connection_server_unauthorized() {
        use axum::http::StatusCode;
        let app = Router::new().route(
            "/rest/api/space",
            routing::get(|| async { StatusCode::UNAUTHORIZED }),
        );
        let addr = start_mock(app).await;
        let client = ConfluenceClient::new(&server_cfg(&format!("http://{addr}")));
        assert!(
            client.test_connection().await.is_err(),
            "server test_connection should fail with 401"
        );
    }

    #[tokio::test]
    async fn find_space_id_cloud_returns_id() {
        let app = Router::new().route(
            "/wiki/api/v2/spaces",
            routing::get(|| async {
                Json(serde_json::json!({"results": [{"id": "12345", "key": "MYSPACE"}]}))
            }),
        );
        let addr = start_mock(app).await;
        let client = ConfluenceClient::new(&cloud_cfg(&format!("http://{addr}")));
        let space_id = client
            .find_space_id()
            .await
            .expect("should return space id");
        assert_eq!(space_id, "12345");
    }

    #[tokio::test]
    async fn find_space_id_cloud_not_found_returns_error() {
        let app = Router::new().route(
            "/wiki/api/v2/spaces",
            routing::get(|| async { Json(serde_json::json!({"results": []})) }),
        );
        let addr = start_mock(app).await;
        let client = ConfluenceClient::new(&cloud_cfg(&format!("http://{addr}")));
        assert!(
            client.find_space_id().await.is_err(),
            "should error when space not found"
        );
    }

    #[tokio::test]
    async fn find_page_cloud_not_found_returns_none() {
        let app = Router::new().route(
            "/wiki/api/v2/pages",
            routing::get(|| async { Json(serde_json::json!({"results": []})) }),
        );
        let addr = start_mock(app).await;
        let client = ConfluenceClient::new(&cloud_cfg(&format!("http://{addr}")));
        let result = client
            .find_page_cloud("99", "My Report")
            .await
            .expect("should not error");
        assert!(result.is_none(), "should return None when page not found");
    }

    #[tokio::test]
    async fn find_page_cloud_found_returns_summary() {
        let app = Router::new().route(
            "/wiki/api/v2/pages",
            routing::get(|| async {
                Json(serde_json::json!({"results": [{"id": "777", "version": {"number": 3}}]}))
            }),
        );
        let addr = start_mock(app).await;
        let client = ConfluenceClient::new(&cloud_cfg(&format!("http://{addr}")));
        let result = client
            .find_page_cloud("99", "My Report")
            .await
            .expect("should not error");
        let ps = result.expect("should find the page");
        assert_eq!(ps.id, "777");
        assert_eq!(ps.version_number, 3);
    }

    #[tokio::test]
    async fn find_page_server_not_found_returns_none() {
        let app = Router::new().route(
            "/rest/api/content",
            routing::get(|| async { Json(serde_json::json!({"results": []})) }),
        );
        let addr = start_mock(app).await;
        let client = ConfluenceClient::new(&server_cfg(&format!("http://{addr}")));
        let result = client
            .find_page_server("My Report")
            .await
            .expect("should not error");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn find_page_server_found_returns_summary() {
        let app = Router::new().route(
            "/rest/api/content",
            routing::get(|| async {
                Json(serde_json::json!({"results": [{"id": "888", "version": {"number": 2}}]}))
            }),
        );
        let addr = start_mock(app).await;
        let client = ConfluenceClient::new(&server_cfg(&format!("http://{addr}")));
        let result = client
            .find_page_server("My Report")
            .await
            .expect("should not error");
        let ps = result.expect("should find the page");
        assert_eq!(ps.id, "888");
        assert_eq!(ps.version_number, 2);
    }

    #[tokio::test]
    async fn create_cloud_page_success() {
        let app = Router::new().route(
            "/wiki/api/v2/pages",
            routing::post(|| async { Json(serde_json::json!({"id": "555"})) }),
        );
        let addr = start_mock(app).await;
        let client = ConfluenceClient::new(&cloud_cfg(&format!("http://{addr}")));
        let id = client
            .create_cloud("99", "My Report", "<p>content</p>")
            .await
            .expect("create should succeed");
        assert_eq!(id, "555");
    }

    #[tokio::test]
    async fn create_cloud_page_failure_returns_error() {
        use axum::http::StatusCode;
        let app = Router::new().route(
            "/wiki/api/v2/pages",
            routing::post(|| async { StatusCode::FORBIDDEN }),
        );
        let addr = start_mock(app).await;
        let client = ConfluenceClient::new(&cloud_cfg(&format!("http://{addr}")));
        assert!(
            client
                .create_cloud("99", "My Report", "<p>content</p>")
                .await
                .is_err(),
            "create should fail with 403"
        );
    }

    #[tokio::test]
    async fn create_server_page_success() {
        let app = Router::new().route(
            "/rest/api/content",
            routing::post(|| async { Json(serde_json::json!({"id": "444"})) }),
        );
        let addr = start_mock(app).await;
        let client = ConfluenceClient::new(&server_cfg(&format!("http://{addr}")));
        let id = client
            .create_server("My Report", "<p>content</p>")
            .await
            .expect("server create should succeed");
        assert_eq!(id, "444");
    }

    #[tokio::test]
    async fn update_cloud_page_success() {
        let app = Router::new().route(
            "/wiki/api/v2/pages/{id}",
            routing::put(|| async { Json(serde_json::json!({"id": "777"})) }),
        );
        let addr = start_mock(app).await;
        let client = ConfluenceClient::new(&cloud_cfg(&format!("http://{addr}")));
        assert!(
            client
                .update_cloud("777", 3, "My Report", "<p>updated</p>")
                .await
                .is_ok(),
            "update_cloud should succeed"
        );
    }

    #[tokio::test]
    async fn update_server_page_success() {
        let app = Router::new().route(
            "/rest/api/content/{id}",
            routing::put(|| async { Json(serde_json::json!({"id": "888"})) }),
        );
        let addr = start_mock(app).await;
        let client = ConfluenceClient::new(&server_cfg(&format!("http://{addr}")));
        assert!(
            client
                .update_server("888", 2, "My Report", "<p>updated</p>")
                .await
                .is_ok(),
            "update_server should succeed"
        );
    }
}
