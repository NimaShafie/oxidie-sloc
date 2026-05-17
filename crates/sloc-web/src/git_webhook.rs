// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Nima Shafie <nimzshafie@gmail.com>
//
// Webhook receiver + schedule management for automated SLOC scanning.
// Supports GitHub, GitLab, and Bitbucket push events, plus polling schedules.

use std::path::Path;
use std::time::Duration;

use axum::{
    body::Bytes,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json},
};
use serde::{Deserialize, Serialize};

use tracing::info;

use sloc_git::{
    clone_or_fetch, create_worktree, destroy_worktree, get_sha, parse_bitbucket_push,
    parse_github_push, parse_gitlab_push,
    webhook::{verify_bitbucket_sig, verify_github_sig},
    ScanSchedule, ScanScheduleKind, ScanScheduleProvider, WebhookEvent,
};

use sloc_core::AnalysisRun;

use super::{
    git_clone_dest, register_artifacts_in_registry, scan_path_to_artifacts, AppState, RunArtifacts,
};

// ── request types ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize)]
pub struct CreateScheduleRequest {
    pub label: String,
    pub repo_url: String,
    pub branch: String,
    pub kind: String,
    pub provider: Option<String>,
    pub interval_secs: Option<u64>,
    /// Webhook HMAC secret. If omitted, a random secret is auto-generated.
    pub webhook_secret: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ScheduleIdQuery {
    pub id: uuid::Uuid,
}

// ── schedule CRUD ─────────────────────────────────────────────────────────────

pub async fn api_list_schedules(State(state): State<AppState>) -> impl IntoResponse {
    let store = state.schedules.lock().await;
    Json(serde_json::json!({ "schedules": store.schedules }))
}

pub async fn api_create_schedule(
    State(state): State<AppState>,
    Json(body): Json<CreateScheduleRequest>,
) -> impl IntoResponse {
    let schedule = build_schedule(body);
    let schedule_id = schedule.id;
    let is_poll = schedule.kind == ScanScheduleKind::Poll;
    {
        let mut store = state.schedules.lock().await;
        store.schedules.push(schedule.clone());
        let _ = store.save(&state.schedules_path);
    }
    if is_poll {
        let interval = schedule.interval_secs.unwrap_or(300);
        let st = state;
        tokio::spawn(async move { poll_loop(st, schedule, interval).await });
    }
    (
        StatusCode::CREATED,
        Json(serde_json::json!({ "id": schedule_id })),
    )
        .into_response()
}

pub async fn api_delete_schedule(
    State(state): State<AppState>,
    Query(q): Query<ScheduleIdQuery>,
) -> impl IntoResponse {
    let mut store = state.schedules.lock().await;
    store.remove(q.id);
    let _ = store.save(&state.schedules_path);
    StatusCode::NO_CONTENT
}

// ── webhook receivers ─────────────────────────────────────────────────────────

pub async fn handle_github_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    if header_str(&headers, "x-github-event") != "push" {
        return StatusCode::OK;
    }
    let Ok(event) = parse_github_push(&body) else {
        return StatusCode::BAD_REQUEST;
    };
    let sig = header_str(&headers, "x-hub-signature-256");
    dispatch_hmac_webhook(state, event, &body, &sig, is_valid_github_sig).await;
    StatusCode::ACCEPTED
}

pub async fn handle_gitlab_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let event_type = header_str(&headers, "x-gitlab-event");
    if event_type != "Push Hook" && event_type != "Tag Push Hook" {
        return StatusCode::OK;
    }
    let Ok(event) = parse_gitlab_push(&body) else {
        return StatusCode::BAD_REQUEST;
    };
    let token = header_str(&headers, "x-gitlab-token");
    dispatch_token_webhook(state, event, &token).await;
    StatusCode::ACCEPTED
}

pub async fn handle_bitbucket_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let Ok(event) = parse_bitbucket_push(&body) else {
        return StatusCode::BAD_REQUEST;
    };
    let sig = header_str(&headers, "x-hub-signature");
    dispatch_hmac_webhook(state, event, &body, &sig, is_valid_bitbucket_sig).await;
    StatusCode::ACCEPTED
}

// ── dispatch helpers ──────────────────────────────────────────────────────────

async fn dispatch_hmac_webhook<F>(
    state: AppState,
    event: WebhookEvent,
    body: &Bytes,
    sig: &str,
    verify: F,
) where
    F: Fn(&[u8], &str, &str) -> bool,
{
    let store = state.schedules.lock().await;
    let candidates = store.find_matching(&event.repo_url, &event.branch);
    let candidate_count = candidates.len();
    let matching: Vec<ScanSchedule> = candidates
        .into_iter()
        .filter(|s| matches_hmac(s, body, sig, &verify))
        .cloned()
        .collect();
    let valid_sig_count = matching.len();
    drop(store);
    info!(
        repo = %event.repo_url,
        branch = %event.branch,
        matched_schedules = candidate_count,
        valid_signatures = valid_sig_count,
        "inbound HMAC webhook received"
    );
    if candidate_count > 0 && valid_sig_count == 0 {
        info!(
            repo = %event.repo_url,
            branch = %event.branch,
            "webhook HMAC verification failed for all matching schedules — no scan triggered"
        );
    }
    spawn_scans(state, event, matching);
}

async fn dispatch_token_webhook(state: AppState, event: WebhookEvent, token: &str) {
    let store = state.schedules.lock().await;
    let candidates = store.find_matching(&event.repo_url, &event.branch);
    let candidate_count = candidates.len();
    let matching: Vec<ScanSchedule> = candidates
        .into_iter()
        .filter(|s| matches_token(s, token))
        .cloned()
        .collect();
    let valid_token_count = matching.len();
    drop(store);
    info!(
        repo = %event.repo_url,
        branch = %event.branch,
        matched_schedules = candidate_count,
        valid_tokens = valid_token_count,
        "inbound token webhook received"
    );
    if candidate_count > 0 && valid_token_count == 0 {
        info!(
            repo = %event.repo_url,
            branch = %event.branch,
            "webhook token verification failed for all matching schedules — no scan triggered"
        );
    }
    spawn_scans(state, event, matching);
}

fn matches_hmac<F: Fn(&[u8], &str, &str) -> bool>(
    s: &ScanSchedule,
    body: &[u8],
    sig: &str,
    verify: &F,
) -> bool {
    s.webhook_secret
        .as_ref()
        .is_none_or(|secret| verify(body, sig, secret))
}

fn matches_token(s: &ScanSchedule, token: &str) -> bool {
    s.webhook_secret
        .as_ref()
        .is_none_or(|secret| ct_eq(secret, token))
}

fn is_valid_github_sig(body: &[u8], sig: &str, secret: &str) -> bool {
    verify_github_sig(body, sig, secret)
}

fn is_valid_bitbucket_sig(body: &[u8], sig: &str, secret: &str) -> bool {
    verify_bitbucket_sig(body, sig, secret)
}

// Takes owned values so each iteration can move into the async task after cloning.
#[allow(clippy::needless_pass_by_value)]
fn spawn_scans(state: AppState, event: WebhookEvent, schedules: Vec<ScanSchedule>) {
    for schedule in schedules {
        let st = state.clone();
        let ev = event.clone();
        let sc = schedule.clone();
        tokio::spawn(async move { run_scheduled_scan(st, ev, sc).await });
    }
}

// ── scan execution ────────────────────────────────────────────────────────────

async fn run_scheduled_scan(state: AppState, event: WebhookEvent, schedule: ScanSchedule) {
    let repo = event.repo_url.clone();
    let sha = event.commit_sha.clone();
    let sha_for_record = sha.clone();
    let clones_dir = state.git_clones_dir.clone();
    let config = state.base_config.clone();
    let label = schedule.label.clone();
    let label_for_closure = label.clone();
    let sched_id = schedule.id;

    let result = tokio::task::spawn_blocking(move || {
        scan_commit(&repo, &sha, &clones_dir, &config, &label_for_closure)
    })
    .await;

    match result {
        Ok(Ok((run_id, artifacts, run))) => {
            register_artifacts_in_registry(&state, &label, &run, &artifacts).await;
            record_scan_result(&state, sched_id, &sha_for_record, &run_id).await;
            crate::confluence::maybe_auto_post_confluence(&state, sched_id, &run, &run_id).await;
        }
        Ok(Err(e)) => eprintln!("[sloc-webhook] scan failed '{}': {e:#}", schedule.label),
        Err(e) => eprintln!("[sloc-webhook] task panicked: {e}"),
    }
}

async fn record_scan_result(state: &AppState, id: uuid::Uuid, sha: &str, run_id: &str) {
    let mut store = state.schedules.lock().await;
    if let Some(s) = store.by_id_mut(id) {
        s.last_scan_sha = Some(sha.to_owned());
        s.last_scan_at = Some(chrono::Utc::now());
        s.last_run_id = Some(run_id.to_owned());
    }
    let _ = store.save(&state.schedules_path);
}

fn scan_commit(
    repo: &str,
    sha: &str,
    clones_dir: &Path,
    config: &sloc_config::AppConfig,
    label: &str,
) -> anyhow::Result<(String, RunArtifacts, AnalysisRun)> {
    let dest = git_clone_dest(repo, clones_dir);
    clone_or_fetch(repo, &dest)?;
    let wt_path = clones_dir.join(format!("wt-{}", uuid::Uuid::new_v4().simple()));
    create_worktree(&dest, sha, &wt_path)?;
    let result = scan_path_to_artifacts(&wt_path, config, label);
    let _ = destroy_worktree(&dest, &wt_path);
    result
}

// ── polling ───────────────────────────────────────────────────────────────────

pub async fn poll_loop(state: AppState, mut schedule: ScanSchedule, interval_secs: u64) {
    let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
    ticker.tick().await;
    loop {
        ticker.tick().await;
        if let Err(e) = poll_once(&state, &mut schedule).await {
            eprintln!("[sloc-poll] '{}': {e:#}", schedule.label);
        }
    }
}

async fn poll_once(state: &AppState, schedule: &mut ScanSchedule) -> anyhow::Result<()> {
    let repo = schedule.repo_url.clone();
    let branch = schedule.branch.clone();
    let clones_dir = state.git_clones_dir.clone();
    let last_sha = schedule.last_scan_sha.clone().unwrap_or_default();

    let current_sha =
        tokio::task::spawn_blocking(move || fetch_and_resolve_sha(&repo, &branch, &clones_dir))
            .await??;

    if current_sha == last_sha {
        return Ok(());
    }

    let label = schedule.label.clone();
    let config = state.base_config.clone();
    let repo2 = schedule.repo_url.clone();
    let sha = current_sha.clone();
    let clones2 = state.git_clones_dir.clone();

    let (run_id, artifacts, run) =
        tokio::task::spawn_blocking(move || scan_commit(&repo2, &sha, &clones2, &config, &label))
            .await??;

    register_artifacts_in_registry(state, &schedule.label, &run, &artifacts).await;
    schedule.last_scan_sha = Some(current_sha.clone());
    schedule.last_scan_at = Some(chrono::Utc::now());
    schedule.last_run_id = Some(run_id.clone());
    record_scan_result(state, schedule.id, &current_sha, &run_id).await;
    crate::confluence::maybe_auto_post_confluence(state, schedule.id, &run, &run_id).await;
    Ok(())
}

fn fetch_and_resolve_sha(repo: &str, branch: &str, clones_dir: &Path) -> anyhow::Result<String> {
    let dest = git_clone_dest(repo, clones_dir);
    clone_or_fetch(repo, &dest)?;
    get_sha(&dest, &format!("origin/{branch}"))
}

// ── small helpers ─────────────────────────────────────────────────────────────

fn build_schedule(req: CreateScheduleRequest) -> ScanSchedule {
    if req.kind == "poll" {
        ScanSchedule::new_poll(
            req.repo_url,
            req.branch,
            req.interval_secs.unwrap_or(300),
            req.label,
        )
    } else {
        let provider = match req.provider.as_deref() {
            Some("github") => ScanScheduleProvider::GitHub,
            Some("gitlab") => ScanScheduleProvider::GitLab,
            Some("bitbucket") => ScanScheduleProvider::Bitbucket,
            _ => ScanScheduleProvider::Any,
        };
        ScanSchedule::new_webhook(
            req.repo_url,
            req.branch,
            provider,
            req.label,
            req.webhook_secret,
        )
    }
}

fn header_str(headers: &HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned()
}

fn ct_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}
