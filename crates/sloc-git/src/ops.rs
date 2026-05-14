// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Nima Shafie <nimzshafie@gmail.com>

use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::{GitCommit, GitRef, GitRefKind, RepoRefs};

// ── low-level git runner ───────────────────────────────────────────────────────

fn run_git(repo: &Path, args: &[&str]) -> Result<String> {
    let mut cmd = std::process::Command::new("git");
    // Opt-in SSL bypass for corporate/internal repos with self-signed certificates.
    // Set SLOC_GIT_SSL_NO_VERIFY=1 in the environment to enable.
    if std::env::var_os("SLOC_GIT_SSL_NO_VERIFY").is_some() {
        cmd.args(["-c", "http.sslVerify=false"]);
    }
    let out = cmd
        .args(args)
        .current_dir(repo)
        .output()
        .context("failed to spawn git process")?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        bail!("git {}: {}", args.first().unwrap_or(&""), stderr.trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

// ── URL normalization ─────────────────────────────────────────────────────────

/// Convert a repository browse URL into a clonable git URL.
///
/// Handles Bitbucket Server/Data Center (`/projects/{PROJ}/repos/{REPO}/...`),
/// GitLab (`/path/repo/-/tree/...`), GitHub (`github.com/{owner}/{repo}/tree/...`),
/// and Bitbucket Cloud (`bitbucket.org/{ws}/{repo}/src/...`). SSH URLs and URLs
/// that already look like clone targets are returned unchanged.
pub fn normalize_git_url(raw: &str) -> String {
    let url = raw.trim();

    // SSH URLs are already clonable — git handles `git@host:path` natively.
    if url.starts_with("git@") || url.starts_with("ssh://") {
        return url.to_owned();
    }

    let scheme = if url.starts_with("https://") {
        "https"
    } else if url.starts_with("http://") {
        "http"
    } else {
        return url.to_owned();
    };

    let authority_and_path = &url[scheme.len() + 3..]; // strip "scheme://"
    let (host, path) = match authority_and_path.find('/') {
        Some(i) => (&authority_and_path[..i], &authority_and_path[i..]),
        None => (authority_and_path, "/"),
    };
    let path = path.trim_end_matches('/');

    // ── Bitbucket Server / Data Center ────────────────────────────────────────
    // Browse URL: /{context}/projects/{PROJECT}/repos/{REPO}[/...]
    // Clone URL:  /{context}/scm/{project_lower}/{repo}.git
    // The Bitbucket context path defaults to "" (root) but some deployments use
    // a prefix (e.g. /bitbucket). We preserve whatever prefix precedes /projects/.
    {
        let path_lower = path.to_lowercase();
        if let Some(proj_pos) = path_lower.find("/projects/") {
            let after = &path[proj_pos + "/projects/".len()..];
            let parts: Vec<&str> = after.splitn(4, '/').collect();
            // parts[0] = PROJECT_KEY, parts[1] = "repos", parts[2] = REPO, parts[3] = rest
            if parts.len() >= 3 && parts[1].eq_ignore_ascii_case("repos") {
                let context = &path[..proj_pos]; // e.g. "" or "/bitbucket"
                let project = parts[0].to_lowercase();
                let repo = parts[2].trim_end_matches(".git");
                return format!("{scheme}://{host}{context}/scm/{project}/{repo}.git");
            }
        }
    }

    // ── GitLab (any host) ─────────────────────────────────────────────────────
    // Browse URL: /path/to/repo/-/tree/branch
    // Clone URL:  /path/to/repo.git
    if let Some(idx) = path.find("/-/") {
        let repo_path = &path[..idx];
        let repo_path = repo_path.trim_end_matches(".git");
        return format!("{scheme}://{host}{repo_path}.git");
    }

    // ── GitHub ────────────────────────────────────────────────────────────────
    // Browse URL: github.com/{owner}/{repo}/{tree|blob|...}/...
    // Clone URL:  github.com/{owner}/{repo}.git
    if host == "github.com" || host.ends_with(".github.com") {
        let p = path.trim_start_matches('/');
        let parts: Vec<&str> = p.splitn(4, '/').collect();
        if parts.len() >= 3
            && matches!(
                parts[2],
                "tree" | "blob" | "commits" | "commit" | "releases" | "tags" | "branches"
            )
        {
            let owner = parts[0];
            let repo = parts[1].trim_end_matches(".git");
            return format!("{scheme}://{host}/{owner}/{repo}.git");
        }
    }

    // ── Bitbucket Cloud ───────────────────────────────────────────────────────
    // Browse URL: bitbucket.org/{workspace}/{repo}/src/...
    // Clone URL:  bitbucket.org/{workspace}/{repo}.git
    if host == "bitbucket.org" {
        let p = path.trim_start_matches('/');
        let parts: Vec<&str> = p.splitn(4, '/').collect();
        if parts.len() >= 3 && parts[2] == "src" {
            let ws = parts[0];
            let repo = parts[1].trim_end_matches(".git");
            return format!("{scheme}://{host}/{ws}/{repo}.git");
        }
    }

    url.to_owned()
}

// ── clone / fetch ─────────────────────────────────────────────────────────────

fn validate_clone_url(url: &str) -> Result<()> {
    let lower = url.to_lowercase();
    let allowed = ["https://", "http://", "git://", "ssh://", "git@"];
    if !allowed.iter().any(|p| lower.starts_with(p)) {
        bail!(
            "git URL rejected: only https://, http://, git://, ssh://, and git@ URLs are \
             permitted (got {url:?})"
        );
    }
    Ok(())
}

/// Clone `url` into `dest`, or fetch all refs if the repo already exists.
///
/// Browse URLs (GitHub, GitLab, Bitbucket web pages) are automatically converted
/// to their corresponding git clone URLs before cloning.
///
/// # Errors
/// Returns an error if the URL is rejected, the clone directory cannot be created,
/// or the underlying `git clone` / `git fetch` command fails.
pub fn clone_or_fetch(url: &str, dest: &Path) -> Result<()> {
    let normalized = normalize_git_url(url);
    let url = normalized.as_str();
    validate_clone_url(url)?;
    if dest.join(".git").exists() {
        run_git(dest, &["fetch", "--all", "--tags", "--prune"])?;
    } else {
        std::fs::create_dir_all(dest).context("failed to create clone directory")?;
        let dest_str = dest.to_str().unwrap_or(".");
        let parent = dest.parent().unwrap_or(dest);
        run_git(
            parent,
            &["clone", "--no-single-branch", "--depth=50", url, dest_str],
        )?;
    }
    Ok(())
}

/// Resolve `ref_name` to its full SHA in `repo`.
///
/// # Errors
/// Returns an error if `git rev-parse` fails (e.g. the ref does not exist).
pub fn get_sha(repo: &Path, ref_name: &str) -> Result<String> {
    run_git(repo, &["rev-parse", ref_name])
}

// ── worktree helpers ──────────────────────────────────────────────────────────

/// Create a detached worktree at `worktree_path` pointing at `ref_name`.
///
/// # Errors
/// Returns an error if `git worktree add` fails.
pub fn create_worktree(repo: &Path, ref_name: &str, worktree_path: &Path) -> Result<()> {
    let wt = worktree_path.to_str().unwrap_or(".");
    run_git(repo, &["worktree", "add", "--detach", wt, ref_name])?;
    Ok(())
}

/// Remove a worktree previously created with [`create_worktree`].
///
/// # Errors
/// This function always succeeds; the underlying git command failure is intentionally ignored.
pub fn destroy_worktree(repo: &Path, worktree_path: &Path) -> Result<()> {
    let wt = worktree_path.to_str().unwrap_or(".");
    let _ = run_git(repo, &["worktree", "remove", "--force", wt]);
    Ok(())
}

// ── ref listing ───────────────────────────────────────────────────────────────

/// Return all branches, tags, and recent commits for `repo`.
///
/// # Errors
/// Returns an error if any underlying git command fails.
pub fn list_refs(repo: &Path) -> Result<RepoRefs> {
    Ok(RepoRefs {
        branches: list_branches(repo)?,
        tags: list_tags(repo)?,
        recent_commits: list_commits(repo, "HEAD", 40)?,
    })
}

fn list_branches(repo: &Path) -> Result<Vec<GitRef>> {
    let fmt = "%(refname:short)|%(objectname:short)|%(creatordate:iso-strict)|%(subject)";
    // Use -r (remote-tracking only) to avoid local/remote duplicates.
    // Strip the leading remote name (e.g. "origin/") from each ref so the
    // displayed name matches what the upstream repository calls the branch.
    let out = run_git(repo, &["branch", "-r", &format!("--format={fmt}")])?;
    let refs = out
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| parse_ref_line(l, GitRefKind::Branch))
        // Drop symbolic HEAD pointers (e.g. origin/HEAD).
        .filter(|r| r.name != "HEAD" && !r.name.ends_with("/HEAD"))
        .map(|mut r| {
            // Strip the remote prefix ("origin/", "upstream/", etc.).
            if let Some(slash) = r.name.find('/') {
                r.name = r.name[slash + 1..].to_owned();
            }
            r
        })
        .collect::<Vec<_>>();
    Ok(refs)
}

fn list_tags(repo: &Path) -> Result<Vec<GitRef>> {
    let fmt = "%(refname:short)|%(objectname:short)|%(creatordate:iso-strict)|%(subject)";
    let out = run_git(
        repo,
        &["tag", "--sort=-creatordate", &format!("--format={fmt}")],
    )?;
    Ok(out
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| parse_ref_line(l, GitRefKind::Tag))
        .collect())
}

fn parse_ref_line(line: &str, kind: GitRefKind) -> GitRef {
    let parts: Vec<&str> = line.splitn(4, '|').collect();
    let name = parts.first().copied().unwrap_or("").to_owned();
    let sha = parts.get(1).copied().unwrap_or("").to_owned();
    let date = parts.get(2).copied().and_then(parse_git_date);
    let message = parts.get(3).map(|s| (*s).to_owned());
    GitRef {
        kind,
        name,
        sha,
        date,
        message,
    }
}

// ── commit listing ────────────────────────────────────────────────────────────

/// Return up to `limit` commits reachable from `ref_name`.
///
/// # Errors
/// Returns an error if `git log` fails.
pub fn list_commits(repo: &Path, ref_name: &str, limit: usize) -> Result<Vec<GitCommit>> {
    let fmt = "%H|%h|%an|%aI|%s";
    let n = format!("-{limit}");
    let out = run_git(repo, &["log", ref_name, &format!("--format={fmt}"), &n])?;
    Ok(out
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(parse_commit_line)
        .collect())
}

fn parse_commit_line(line: &str) -> GitCommit {
    let p: Vec<&str> = line.splitn(5, '|').collect();
    let sha = p.first().copied().unwrap_or("").to_owned();
    let short_sha = p.get(1).copied().unwrap_or("").to_owned();
    let author = p.get(2).copied().unwrap_or("").to_owned();
    let date = p
        .get(3)
        .copied()
        .and_then(parse_git_date)
        .unwrap_or_default();
    let subject = p.get(4).copied().unwrap_or("").to_owned();
    GitCommit {
        sha,
        short_sha,
        author,
        date,
        subject,
    }
}

fn parse_git_date(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|d| d.with_timezone(&chrono::Utc))
}
