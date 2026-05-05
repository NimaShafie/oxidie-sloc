// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Nima Shafie <nimzshafie@gmail.com>
//
// Webhook receiver + schedule management for automated SLOC scanning.
// Supports GitHub, GitLab, and Bitbucket push events, plus polling schedules.

use std::path::Path;
use std::time::Duration;

use askama::Template;
use axum::{
    body::Bytes,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Json},
};
use serde::{Deserialize, Serialize};

use sloc_git::{
    clone_or_fetch, create_worktree, destroy_worktree, get_sha, parse_bitbucket_push,
    parse_github_push, parse_gitlab_push,
    webhook::{verify_bitbucket_sig, verify_github_sig},
    ScanSchedule, ScanScheduleKind, ScanScheduleProvider, WebhookEvent,
};

use super::{git_clone_dest, scan_path_to_artifacts, AppState, CspNonce};

// ── request types ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize)]
pub(super) struct CreateScheduleRequest {
    pub label: String,
    pub repo_url: String,
    pub branch: String,
    pub kind: String,
    pub provider: Option<String>,
    pub interval_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ScheduleIdQuery {
    pub id: uuid::Uuid,
}

// ── webhook-setup template ────────────────────────────────────────────────────

#[derive(Template)]
#[template(
    source = r##"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>OxideSLOC — Webhook Setup</title>
  <link rel="icon" type="image/png" href="/images/logo/small-logo.png">
  <style nonce="{{ csp_nonce }}">
    :root{--radius:14px;--bg:#f5efe8;--surface:rgba(255,255,255,0.9);--surface-2:#fbf7f2;--line:#e6d0bf;--line-strong:#d8bfad;--text:#43342d;--muted:#7b675b;--nav:#b85d33;--nav-2:#7a371b;--oxide-2:#b85d33;--shadow:0 8px 24px rgba(77,44,20,0.10);}
    body.dark-theme{--bg:#1b1511;--surface:#261c17;--surface-2:#2d221d;--line:#524238;--text:#f5ece6;--muted:#c7b7aa;--shadow:0 8px 24px rgba(0,0,0,0.32);}
    *{box-sizing:border-box;} html,body{margin:0;min-height:100vh;font-family:Inter,ui-sans-serif,system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);}
    .background-watermarks{position:fixed;inset:0;pointer-events:none;z-index:0;overflow:hidden;}
    .background-watermarks img{position:absolute;opacity:0.16;filter:blur(0.3px);user-select:none;max-width:none;}
    .code-particles{position:fixed;inset:0;pointer-events:none;z-index:0;overflow:hidden;}
    .code-particle{position:absolute;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:11px;font-weight:600;color:var(--oxide-2);opacity:0;white-space:nowrap;user-select:none;animation:floatCode linear infinite;}
    @keyframes floatCode{0%{opacity:0;transform:translateY(0) rotate(var(--rot));}10%{opacity:var(--op);}85%{opacity:var(--op);}100%{opacity:0;transform:translateY(-200px) rotate(var(--rot));}}
    .top-nav{position:sticky;top:0;z-index:30;background:linear-gradient(180deg,var(--nav),var(--nav-2));border-bottom:1px solid rgba(255,255,255,0.12);box-shadow:0 4px 14px rgba(0,0,0,0.18);}
    .top-nav-inner{max-width:1000px;margin:0 auto;padding:4px 24px;min-height:56px;display:flex;align-items:center;gap:14px;}
    .brand{display:flex;align-items:center;gap:12px;text-decoration:none;}
    .brand-logo{width:36px;height:40px;object-fit:contain;}
    .brand-title{color:#fff;font-size:16px;font-weight:800;}.brand-sub{color:rgba(255,255,255,0.75);font-size:12px;}
    .nav-right{margin-left:auto;display:flex;align-items:center;gap:10px;}
    .nav-pill{display:inline-flex;align-items:center;min-height:34px;padding:0 14px;border-radius:999px;border:1px solid rgba(255,255,255,0.18);color:#fff;background:rgba(255,255,255,0.08);font-size:12px;font-weight:700;text-decoration:none;}
    .nav-pill:hover{background:rgba(255,255,255,0.18);}
    .nav-dropdown{position:relative;display:inline-flex;}.nav-dropdown-btn{cursor:pointer;background:rgba(255,255,255,0.08);border:1px solid rgba(255,255,255,0.18);color:#fff;border-radius:999px;padding:0 14px;min-height:34px;font-size:12px;font-weight:700;display:inline-flex;align-items:center;gap:6px;}.nav-dropdown-btn:hover,.nav-dropdown:focus-within .nav-dropdown-btn{background:rgba(255,255,255,0.18);}.nav-dropdown-menu{opacity:0;visibility:hidden;position:absolute;top:calc(100% + 8px);right:0;background:linear-gradient(180deg,var(--nav),var(--nav-2));border:1px solid rgba(255,255,255,0.15);border-radius:12px;min-width:165px;overflow:hidden;box-shadow:0 10px 28px rgba(0,0,0,0.28);z-index:100;transition:opacity 0.13s ease,visibility 0s ease 0.13s;}.nav-dropdown:hover .nav-dropdown-menu,.nav-dropdown:focus-within .nav-dropdown-menu{opacity:1;visibility:visible;transition:opacity 0.13s ease,visibility 0s ease 0s;}.nav-dropdown-menu a{display:flex;align-items:center;gap:9px;padding:11px 16px;color:rgba(255,255,255,0.92);text-decoration:none;font-size:12px;font-weight:700;border-bottom:1px solid rgba(255,255,255,0.10);}.nav-dropdown-menu a:last-child{border-bottom:none;}.nav-dropdown-menu a:hover{background:rgba(255,255,255,0.14);color:#fff;}.nav-dropdown-menu a svg{width:13px;height:13px;stroke:currentColor;fill:none;stroke-width:2;flex:0 0 auto;}
    .page{max-width:1000px;margin:0 auto;padding:32px 24px 60px;position:relative;z-index:1;}
    h1{font-size:26px;font-weight:850;margin:0 0 6px;letter-spacing:-0.03em;}
    .subtitle{color:var(--muted);font-size:14px;margin:0 0 28px;}
    .card{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);padding:24px;box-shadow:var(--shadow);margin-bottom:20px;}
    .card-title{font-size:15px;font-weight:800;margin:0 0 18px;}
    .form-row{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px;}
    @media(max-width:600px){.form-row{grid-template-columns:1fr;}}
    .form-group{display:flex;flex-direction:column;gap:5px;}
    label{font-size:12px;font-weight:700;color:var(--muted);}
    input,select{padding:9px 12px;border-radius:8px;border:1.5px solid var(--line-strong);background:var(--surface-2);color:var(--text);font-size:13px;}
    input:focus,select:focus{outline:none;border-color:var(--oxide-2);}
    .btn{display:inline-flex;align-items:center;gap:7px;padding:9px 18px;border-radius:9px;border:none;cursor:pointer;font-size:13px;font-weight:700;transition:opacity 0.15s;}
    .btn:hover{opacity:0.85;}.btn-primary{background:var(--oxide-2);color:#fff;}.btn-danger{background:#dc2626;color:#fff;}.btn-sm{padding:5px 12px;font-size:12px;border-radius:7px;}
    .schedule-list{display:flex;flex-direction:column;gap:12px;}
    .sched-item{background:var(--surface-2);border:1px solid var(--line);border-radius:10px;padding:16px 20px;}
    .sched-header{display:flex;align-items:center;gap:10px;margin-bottom:8px;}
    .sched-label{font-size:14px;font-weight:800;}
    .sched-badge{font-size:10px;font-weight:700;padding:2px 9px;border-radius:999px;letter-spacing:.05em;}
    .badge-webhook{background:#dbeafe;color:#1d4ed8;}body.dark-theme .badge-webhook{background:#1e3a5f;color:#93c5fd;}
    .badge-poll{background:#dcfce7;color:#166534;}body.dark-theme .badge-poll{background:#14532d;color:#86efac;}
    .sched-meta{font-size:12px;color:var(--muted);display:flex;flex-direction:column;gap:4px;}
    .sched-secret{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:11px;color:var(--oxide-2);background:var(--surface);border:1px solid var(--line);border-radius:6px;padding:2px 7px;}
    .sched-actions{display:flex;gap:8px;margin-top:12px;}
    .url-row{display:flex;align-items:center;gap:8px;margin-bottom:8px;}
    .url-label{font-size:12px;font-weight:700;min-width:80px;color:var(--muted);}
    .url-box{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:11px;background:var(--surface-2);border:1px solid var(--line);border-radius:6px;padding:5px 10px;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text);}
    .copy-btn{padding:4px 10px;font-size:11px;border-radius:6px;border:1px solid var(--line);background:var(--surface);cursor:pointer;font-weight:700;color:var(--muted);}
    .copy-btn:hover{background:var(--line);}
    .status-msg{padding:10px 14px;border-radius:8px;font-size:13px;font-weight:600;margin-top:12px;display:none;}
    .status-ok{background:#dcfce7;color:#166534;}.status-err{background:#fee2e2;color:#991b1b;}
    body.dark-theme .status-ok{background:#14532d;color:#86efac;}body.dark-theme .status-err{background:#450a0a;color:#fca5a5;}
    .empty-state{text-align:center;padding:32px;color:var(--muted);font-size:14px;}
    .theme-toggle{width:34px;height:34px;display:flex;align-items:center;justify-content:center;border-radius:999px;border:1px solid rgba(255,255,255,0.18);background:rgba(255,255,255,0.08);cursor:pointer;}
    .theme-toggle svg{width:16px;height:16px;stroke:#fff;fill:none;stroke-width:1.8;}
    .theme-toggle .icon-sun{display:none;}body.dark-theme .theme-toggle .icon-sun{display:block;}body.dark-theme .theme-toggle .icon-moon{display:none;}
    .wip-overlay{position:fixed;inset:0;z-index:9999;display:flex;flex-direction:column;align-items:center;justify-content:center;background:rgba(0,0,0,0.82);backdrop-filter:blur(3px);}
    .wip-tape-layer{position:absolute;inset:0;overflow:hidden;pointer-events:none;}
    .wip-tape{position:absolute;left:-10%;width:120%;height:52px;transform:rotate(-3deg);box-shadow:0 4px 24px #0009;}
    .wip-tape-1{top:18%;background:repeating-linear-gradient(90deg,#f7c900 0,#f7c900 120px,#1a1a1a 120px,#1a1a1a 240px);opacity:0.95;}
    .wip-tape-2{top:27%;background:repeating-linear-gradient(90deg,#1a1a1a 0,#1a1a1a 120px,#f7c900 120px,#f7c900 240px);opacity:0.92;}
    .wip-tape-3{top:68%;background:repeating-linear-gradient(90deg,#f7c900 0,#f7c900 120px,#1a1a1a 120px,#1a1a1a 240px);opacity:0.95;}
    .wip-tape-4{top:77%;background:repeating-linear-gradient(90deg,#1a1a1a 0,#1a1a1a 120px,#f7c900 120px,#f7c900 240px);opacity:0.92;}
    .wip-card{position:relative;z-index:1;background:#1a1a1a;border:6px solid #f7c900;border-radius:4px;padding:40px 52px;text-align:center;max-width:640px;box-shadow:0 0 80px #f7c90066,0 8px 40px #000c;}
    .wip-icon{font-size:72px;line-height:1;margin-bottom:8px;}
    .wip-title{font-family:'Arial Black',Arial,sans-serif;font-size:32px;font-weight:900;color:#f7c900;letter-spacing:4px;text-transform:uppercase;margin-bottom:6px;text-shadow:0 0 20px #f7c90099;}
    .wip-subtitle{font-family:'Arial Black',Arial,sans-serif;font-size:14px;font-weight:900;color:#f7c900;letter-spacing:6px;text-transform:uppercase;margin-bottom:24px;opacity:0.7;}
    .wip-body{color:#e5e5e5;font-size:16px;line-height:1.6;margin-bottom:28px;}
    .wip-body strong{color:#fff;}
    .wip-proceed-btn{background:#f7c900;color:#1a1a1a;border:none;border-radius:3px;padding:12px 36px;font-size:15px;font-weight:900;letter-spacing:2px;text-transform:uppercase;cursor:pointer;font-family:'Arial Black',Arial,sans-serif;}
  </style>
</head>
<body>
  <div class="background-watermarks" aria-hidden="true">
    <img src="/images/logo/logo-text.png" alt=""><img src="/images/logo/logo-text.png" alt="">
    <img src="/images/logo/logo-text.png" alt=""><img src="/images/logo/logo-text.png" alt="">
    <img src="/images/logo/logo-text.png" alt=""><img src="/images/logo/logo-text.png" alt="">
    <img src="/images/logo/logo-text.png" alt=""><img src="/images/logo/logo-text.png" alt="">
    <img src="/images/logo/logo-text.png" alt=""><img src="/images/logo/logo-text.png" alt="">
    <img src="/images/logo/logo-text.png" alt=""><img src="/images/logo/logo-text.png" alt="">
  </div>
  <div class="code-particles" id="code-particles" aria-hidden="true"></div>
  <nav class="top-nav">
    <div class="top-nav-inner">
      <a class="brand" href="/"><img class="brand-logo" src="/images/logo/small-logo.png" alt="">
        <div><div class="brand-title">OxideSLOC</div><div class="brand-sub">Webhook Setup</div></div></a>
      <div class="nav-right">
        <a class="nav-pill" href="/">Home</a>
        <a class="nav-pill" href="/view-reports">View Reports</a>
        <a class="nav-pill" href="/compare-scans">Compare Scans</a>
        <div class="nav-dropdown">
          <button class="nav-dropdown-btn" type="button">Git Tools <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="6 9 12 15 18 9"></polyline></svg></button>
          <div class="nav-dropdown-menu">
            <a href="/git-browser"><svg viewBox="0 0 24 24"><polyline points="16 18 22 12 16 6"></polyline><polyline points="8 6 2 12 8 18"></polyline></svg>Git Browser</a>
            <a href="/webhook-setup"><svg viewBox="0 0 24 24"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path></svg>Webhooks</a>
          </div>
        </div>
        <button class="theme-toggle" id="themeToggle" type="button" title="Toggle theme">
          <svg class="icon-moon" viewBox="0 0 24 24"><path d="M21 12.79A9 9 0 1 1 11.21 3a7 7 0 0 0 9.79 9.79z"/></svg>
          <svg class="icon-sun" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
        </button>
      </div>
    </div>
  </nav>
  <!-- Police tape full-screen overlay -->
  <div id="wip-overlay" class="wip-overlay">
    <!-- Tape strips -->
    <div class="wip-tape-layer">
      <div class="wip-tape wip-tape-1"></div>
      <div class="wip-tape wip-tape-2"></div>
      <div class="wip-tape wip-tape-3"></div>
      <div class="wip-tape wip-tape-4"></div>
    </div>
    <!-- Center warning card -->
    <div class="wip-card">
      <div class="wip-icon">&#9888;</div>
      <div class="wip-title">CAUTION</div>
      <div class="wip-subtitle">DO NOT RELY ON THIS FEATURE</div>
      <div class="wip-body">
        <strong>Work in progress</strong> — this feature is not fully tested and may not behave as expected.<br>Proceed only if you understand the risks.
      </div>
      <button id="wip-proceed-btn" class="wip-proceed-btn">I UNDERSTAND — PROCEED</button>
    </div>
  </div>

  <div class="page">
    <h1>Automated Scanning</h1>
    <p class="subtitle">Configure webhooks or polling so OxideSLOC automatically scans when a repository is updated.</p>

    <div class="card">
      <div class="card-title">Add Schedule</div>
      <div class="form-row">
        <div class="form-group"><label>Label</label><input id="fLabel" type="text" placeholder="My Repo — main"/></div>
        <div class="form-group"><label>Type</label>
          <select id="fKind">
            <option value="webhook">Webhook (GitHub / GitLab / Bitbucket)</option>
            <option value="poll">Polling (interval-based)</option>
          </select>
        </div>
      </div>
      <div class="form-row">
        <div class="form-group"><label>Repository URL</label><input id="fRepo" type="text" placeholder="https://github.com/owner/repo.git"/></div>
        <div class="form-group"><label>Branch</label><input id="fBranch" type="text" value="main" placeholder="main"/></div>
      </div>
      <div class="form-row" id="providerRow">
        <div class="form-group"><label>Provider</label>
          <select id="fProvider"><option value="github">GitHub</option><option value="gitlab">GitLab</option><option value="bitbucket">Bitbucket</option></select>
        </div>
      </div>
      <div class="form-row" id="pollRow" style="display:none">
        <div class="form-group"><label>Poll Interval (seconds, min 60)</label><input id="fInterval" type="number" min="60" step="60" value="300"/></div>
      </div>
      <div id="addStatus" class="status-msg"></div>
      <button class="btn btn-primary" id="addScheduleBtn" type="button">Add Schedule</button>
    </div>

    <div class="card">
      <div class="card-title">Active Schedules</div>
      <div id="scheduleList" class="schedule-list"><div class="empty-state">Loading…</div></div>
    </div>

    <div class="card">
      <div class="card-title">Webhook Endpoint URLs</div>
      <p style="font-size:13px;color:var(--muted);margin:0 0 16px">Configure these URLs in your provider and use the secret shown on each schedule for HMAC verification.</p>
      <div class="url-row"><span class="url-label">GitHub</span><span id="urlGH" class="url-box">{{ server_url }}/webhooks/github</span><button class="copy-btn" type="button" data-copy-target="urlGH">Copy</button></div>
      <div class="url-row"><span class="url-label">GitLab</span><span id="urlGL" class="url-box">{{ server_url }}/webhooks/gitlab</span><button class="copy-btn" type="button" data-copy-target="urlGL">Copy</button></div>
      <div class="url-row"><span class="url-label">Bitbucket</span><span id="urlBB" class="url-box">{{ server_url }}/webhooks/bitbucket</span><button class="copy-btn" type="button" data-copy-target="urlBB">Copy</button></div>
    </div>
  </div>

  <script nonce="{{ csp_nonce }}">
    (function () {
      function applyTheme() { if (localStorage.getItem('sloc-theme') === 'dark') document.body.classList.add('dark-theme'); }
      function toggleTheme() { var d = document.body.classList.toggle('dark-theme'); localStorage.setItem('sloc-theme', d ? 'dark' : 'light'); }

      function onKindChange() {
        var poll = document.getElementById('fKind').value === 'poll';
        document.getElementById('pollRow').style.display = poll ? 'grid' : 'none';
        document.getElementById('providerRow').style.display = poll ? 'none' : 'grid';
      }

      function showStatus(msg, ok) {
        var el = document.getElementById('addStatus');
        el.style.display = 'block';
        el.className = 'status-msg ' + (ok ? 'status-ok' : 'status-err');
        el.textContent = msg;
      }

      async function addSchedule() {
        var kind = document.getElementById('fKind').value;
        var body = {
          label: document.getElementById('fLabel').value.trim() || 'Unnamed',
          repo_url: document.getElementById('fRepo').value.trim(),
          branch: document.getElementById('fBranch').value.trim() || 'main',
          kind: kind,
          provider: kind === 'webhook' ? document.getElementById('fProvider').value : null,
          interval_secs: kind === 'poll' ? parseInt(document.getElementById('fInterval').value, 10) : null,
        };
        if (!body.repo_url) { showStatus('Repository URL is required.', false); return; }
        var r = await fetch('/api/schedules', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        var data = await r.json();
        if (r.ok) { showStatus('Schedule added.', true); loadSchedules(); }
        else { showStatus(data.error || 'Failed.', false); }
      }

      async function deleteSchedule(id) {
        if (!confirm('Delete this schedule?')) return;
        await fetch('/api/schedules?id=' + encodeURIComponent(id), { method: 'DELETE' });
        loadSchedules();
      }

      async function loadSchedules() {
        var r = await fetch('/api/schedules');
        if (!r.ok) return;
        var data = await r.json();
        var el = document.getElementById('scheduleList');
        var list = data.schedules || [];
        if (!list.length) { el.innerHTML = '<div class="empty-state">No schedules configured yet.</div>'; return; }
        el.innerHTML = list.map(function (s) {
          var badge = s.kind === 'webhook' ? '<span class="sched-badge badge-webhook">Webhook</span>' : '<span class="sched-badge badge-poll">Poll</span>';
          var extra = s.interval_secs ? ' · every ' + s.interval_secs + 's' : (s.provider && s.provider !== 'any' ? ' · ' + esc(s.provider) : '');
          var secret = s.webhook_secret ? '<div>Secret: <span class="sched-secret">' + esc(s.webhook_secret) + '</span></div>' : '';
          var last = s.last_scan_at ? 'Last scanned: ' + new Date(s.last_scan_at).toLocaleString() : 'Not yet scanned';
          return '<div class="sched-item">'
            + '<div class="sched-header">' + badge + '<span class="sched-label">' + esc(s.label) + '</span></div>'
            + '<div class="sched-meta"><div>' + esc(s.repo_url) + ' · <strong>' + esc(s.branch) + '</strong>' + extra + '</div>' + secret + '<div>' + last + '</div></div>'
            + '<div class="sched-actions"><button class="btn btn-danger btn-sm" data-action="delete-schedule" data-id="' + esc(s.id) + '" type="button">Remove</button></div>'
            + '</div>';
        }).join('');
      }

      function copy(id) { navigator.clipboard.writeText(document.getElementById(id).textContent.trim()); }
      function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

      // ── Event wiring ──────────────────────────────────────────────────────────
      document.getElementById('themeToggle').addEventListener('click', toggleTheme);
      document.getElementById('fKind').addEventListener('change', onKindChange);
      document.getElementById('addScheduleBtn').addEventListener('click', addSchedule);

      // Delegation for copy buttons and delete buttons (rendered dynamically)
      document.addEventListener('click', function (e) {
        var copyBtn = e.target.closest('[data-copy-target]');
        if (copyBtn) { copy(copyBtn.dataset.copyTarget); return; }
        var delBtn = e.target.closest('[data-action="delete-schedule"]');
        if (delBtn) { deleteSchedule(delBtn.dataset.id); }
      });

      // ── Background effects ────────────────────────────────────────────────────
      (function randomizeWatermarks() {
        var wms = Array.prototype.slice.call(document.querySelectorAll('.background-watermarks img'));
        if (!wms.length) return;
        var placed = [];
        function tooClose(top, left) {
          for (var i = 0; i < placed.length; i++) {
            if (Math.abs(placed[i][0] - top) < 16 && Math.abs(placed[i][1] - left) < 12) return true;
          }
          return false;
        }
        function pick(leftBand) {
          for (var attempt = 0; attempt < 50; attempt++) {
            var top = Math.random() * 88 + 2, left = leftBand ? Math.random() * 24 + 1 : Math.random() * 24 + 74;
            if (!tooClose(top, left)) { placed.push([top, left]); return [top, left]; }
          }
          var top = Math.random() * 88 + 2, left = leftBand ? Math.random() * 24 + 1 : Math.random() * 24 + 74;
          placed.push([top, left]); return [top, left];
        }
        var half = Math.floor(wms.length / 2);
        wms.forEach(function (img, i) {
          var pos = pick(i < half);
          var size = Math.floor(Math.random() * 100 + 120);
          img.style.cssText = 'width:' + size + 'px;top:' + pos[0].toFixed(1) + '%;left:' + pos[1].toFixed(1) + '%;transform:rotate(' + (Math.random() * 360).toFixed(1) + 'deg);opacity:' + (Math.random() * 0.08 + 0.12).toFixed(2) + ';';
        });
      })();

      (function spawnCodeParticles() {
        var container = document.getElementById('code-particles');
        if (!container) return;
        var snippets = ['1,247 sloc','fn analyze()','code_lines','0 mixed','blanks: 312','// comment','pub fn run','use std::fs','Result<()>','let mut n = 0','git main','#[derive]','impl Scan','3,841 physical','files: 60','450 comments','cargo build','Ok(run)','Vec<String>','match lang','fn main() {','.rs .go .py','sloc_core','render_html','2,163 code'];
        for (var i = 0; i < 38; i++) {
          (function (idx) {
            var el = document.createElement('span');
            el.className = 'code-particle';
            el.textContent = snippets[idx % snippets.length];
            el.style.cssText = 'left:' + (Math.random() * 94 + 2).toFixed(1) + '%;top:' + (Math.random() * 88 + 6).toFixed(1) + '%;--rot:' + (Math.random() * 26 - 13).toFixed(1) + 'deg;--op:' + (Math.random() * 0.09 + 0.06).toFixed(3) + ';animation-duration:' + (Math.random() * 10 + 9).toFixed(1) + 's;animation-delay:-' + (Math.random() * 18).toFixed(1) + 's;';
            container.appendChild(el);
          })(i);
        }
      })();

      document.getElementById('wip-proceed-btn').addEventListener('click', function () {
        document.getElementById('wip-overlay').style.display = 'none';
      });

      applyTheme();
      loadSchedules();
    })();
  </script>
</body>
</html>"##,
    ext = "html"
)]
pub(super) struct WebhookSetupTemplate {
    pub csp_nonce: String,
    pub server_url: String,
}

// ── setup-page handler ────────────────────────────────────────────────────────

pub(super) async fn webhook_setup_handler(
    State(state): State<AppState>,
    axum::extract::Extension(CspNonce(csp_nonce)): axum::extract::Extension<CspNonce>,
) -> impl IntoResponse {
    let server_url = build_server_url(&state);
    let template = WebhookSetupTemplate {
        csp_nonce,
        server_url,
    };
    Html(
        template
            .render()
            .unwrap_or_else(|e| format!("<pre>{e}</pre>")),
    )
}

// ── schedule CRUD ─────────────────────────────────────────────────────────────

pub(super) async fn api_list_schedules(State(state): State<AppState>) -> impl IntoResponse {
    let store = state.schedules.lock().await;
    Json(serde_json::json!({ "schedules": store.schedules }))
}

pub(super) async fn api_create_schedule(
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

pub(super) async fn api_delete_schedule(
    State(state): State<AppState>,
    Query(q): Query<ScheduleIdQuery>,
) -> impl IntoResponse {
    let mut store = state.schedules.lock().await;
    store.remove(q.id);
    let _ = store.save(&state.schedules_path);
    StatusCode::NO_CONTENT
}

// ── webhook receivers ─────────────────────────────────────────────────────────

pub(super) async fn handle_github_webhook(
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

pub(super) async fn handle_gitlab_webhook(
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

pub(super) async fn handle_bitbucket_webhook(
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
    let matching: Vec<ScanSchedule> = store
        .find_matching(&event.repo_url, &event.branch)
        .into_iter()
        .filter(|s| matches_hmac(s, body, sig, &verify))
        .cloned()
        .collect();
    drop(store);
    spawn_scans(state, event, matching);
}

async fn dispatch_token_webhook(state: AppState, event: WebhookEvent, token: &str) {
    let store = state.schedules.lock().await;
    let matching: Vec<ScanSchedule> = store
        .find_matching(&event.repo_url, &event.branch)
        .into_iter()
        .filter(|s| matches_token(s, token))
        .cloned()
        .collect();
    drop(store);
    spawn_scans(state, event, matching);
}

fn matches_hmac<F: Fn(&[u8], &str, &str) -> bool>(
    s: &ScanSchedule,
    body: &[u8],
    sig: &str,
    verify: &F,
) -> bool {
    match &s.webhook_secret {
        None => true,
        Some(secret) => verify(body, sig, secret),
    }
}

fn matches_token(s: &ScanSchedule, token: &str) -> bool {
    match &s.webhook_secret {
        None => true,
        Some(secret) => ct_eq(secret, token),
    }
}

fn is_valid_github_sig(body: &[u8], sig: &str, secret: &str) -> bool {
    verify_github_sig(body, sig, secret)
}

fn is_valid_bitbucket_sig(body: &[u8], sig: &str, secret: &str) -> bool {
    verify_bitbucket_sig(body, sig, secret)
}

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
    let sched_id = schedule.id;

    let result =
        tokio::task::spawn_blocking(move || scan_commit(&repo, &sha, &clones_dir, &config, &label))
            .await;

    match result {
        Ok(Ok(run_id)) => record_scan_result(&state, sched_id, &sha_for_record, &run_id).await,
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
) -> anyhow::Result<String> {
    let dest = git_clone_dest(repo, clones_dir);
    clone_or_fetch(repo, &dest)?;
    let wt_path = clones_dir.join(format!("wt-{}", uuid::Uuid::new_v4().simple()));
    create_worktree(&dest, sha, &wt_path)?;
    let result = scan_path_to_artifacts(&wt_path, config, label);
    let _ = destroy_worktree(&dest, &wt_path);
    result.map(|(run_id, _artifacts, _run)| run_id)
}

// ── polling ───────────────────────────────────────────────────────────────────

pub(crate) async fn poll_loop(state: AppState, mut schedule: ScanSchedule, interval_secs: u64) {
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

    let run_id =
        tokio::task::spawn_blocking(move || scan_commit(&repo2, &sha, &clones2, &config, &label))
            .await??;

    schedule.last_scan_sha = Some(current_sha.clone());
    schedule.last_scan_at = Some(chrono::Utc::now());
    schedule.last_run_id = Some(run_id.clone());
    record_scan_result(state, schedule.id, &current_sha, &run_id).await;
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
        ScanSchedule::new_webhook(req.repo_url, req.branch, provider, req.label)
    }
}

fn build_server_url(state: &AppState) -> String {
    let addr = &state.base_config.web.bind_address;
    if state.tls_enabled {
        format!("https://{addr}")
    } else {
        format!("http://{addr}")
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
