# sloc-git

Git CLI wrappers, HMAC webhook verification, and scan-schedule store for [oxide-sloc](https://github.com/oxide-sloc/oxide-sloc).

## Overview

This crate provides all Git integration used by the oxide-sloc workspace:

- **`clone_or_fetch(url, dir)`** — clone a remote repository or fetch the latest changes into an existing local clone
- **`create_worktree` / `destroy_worktree`** — create and clean up Git worktrees for isolated branch scans
- **`get_sha(dir, ref)`** — resolve a branch or tag name to its commit SHA
- **`list_refs(dir)`** — list all branches and tags with their SHAs and dates, returned as `RepoRefs`
- **`list_commits(dir, ref, limit)`** — fetch recent commits as `Vec<GitCommit>`
- **`normalize_git_url(url)`** — normalise SSH and HTTPS Git URLs to a canonical form

### Webhook parsing

- **`parse_github_push` / `parse_gitlab_push` / `parse_bitbucket_push`** — parse provider-specific webhook payloads into a unified `WebhookEvent`
- **HMAC-SHA256 signature verification** via `ring` and `subtle` for constant-time comparison

### Scan scheduling

- **`ScheduleStore`** — JSON-backed store for persisting `ScanSchedule` entries
- **`ScanSchedule`** — cron-style schedule with kind (`Once`, `Hourly`, `Daily`, `Weekly`, `Custom`) and next-run tracking

## Usage

This is an internal crate used by the oxide-sloc workspace. It is not intended for use outside this project. See the [main project](https://github.com/oxide-sloc/oxide-sloc) for documentation and releases.

```toml
# Install the tool instead:
cargo install oxide-sloc
```
