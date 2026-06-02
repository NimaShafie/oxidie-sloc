// SPDX-License-Identifier: AGPL-3.0-or-later
// Unit tests for sloc-git: URL normalization and webhook parsing.

use sloc_git::webhook::verify_github_sig;
use sloc_git::{
    normalize_git_url, parse_bitbucket_push, parse_github_push, parse_gitlab_push, WebhookProvider,
};

// ── normalize_git_url ─────────────────────────────────────────────────────────

#[test]
fn normalize_github_tree_url() {
    let url = "https://github.com/oxide-sloc/oxide-sloc/tree/main";
    let result = normalize_git_url(url);
    assert_eq!(result, "https://github.com/oxide-sloc/oxide-sloc.git");
}

#[test]
fn normalize_github_blob_url() {
    let url = "https://github.com/oxide-sloc/oxide-sloc/blob/main/README.md";
    let result = normalize_git_url(url);
    assert_eq!(result, "https://github.com/oxide-sloc/oxide-sloc.git");
}

#[test]
fn normalize_github_commits_url() {
    let url = "https://github.com/oxide-sloc/oxide-sloc/commits/main";
    let result = normalize_git_url(url);
    assert_eq!(result, "https://github.com/oxide-sloc/oxide-sloc.git");
}

#[test]
fn normalize_gitlab_tree_url() {
    let url = "https://gitlab.com/org/project/-/tree/main";
    let result = normalize_git_url(url);
    assert_eq!(result, "https://gitlab.com/org/project.git");
}

#[test]
fn normalize_gitlab_arbitrary_host() {
    let url = "https://git.example.com/group/repo/-/tree/develop";
    let result = normalize_git_url(url);
    assert_eq!(result, "https://git.example.com/group/repo.git");
}

#[test]
fn normalize_bitbucket_server_browse_url() {
    let url = "https://bitbucket.example.com/context/projects/PROJ/repos/myrepo/browse";
    let result = normalize_git_url(url);
    assert_eq!(
        result,
        "https://bitbucket.example.com/context/scm/proj/myrepo.git"
    );
}

#[test]
fn normalize_bitbucket_cloud_src_url() {
    let url = "https://bitbucket.org/myworkspace/myrepo/src/main/";
    let result = normalize_git_url(url);
    assert_eq!(result, "https://bitbucket.org/myworkspace/myrepo.git");
}

#[test]
fn normalize_ssh_url_passthrough() {
    let url = "git@github.com:oxide-sloc/oxide-sloc.git";
    let result = normalize_git_url(url);
    assert_eq!(result, url, "SSH URLs should pass through unchanged");
}

#[test]
fn normalize_already_clone_url_passthrough() {
    let url = "https://github.com/oxide-sloc/oxide-sloc.git";
    let result = normalize_git_url(url);
    assert_eq!(
        result, url,
        "already-canonical clone URLs should pass through"
    );
}

#[test]
fn normalize_unknown_host_passthrough() {
    let url = "https://internal.example.com/repo";
    let result = normalize_git_url(url);
    assert_eq!(result, url, "unknown hosts should pass through unchanged");
}

#[test]
fn normalize_trims_whitespace() {
    let url = "  https://github.com/oxide-sloc/oxide-sloc/tree/main  ";
    let result = normalize_git_url(url);
    assert_eq!(result, "https://github.com/oxide-sloc/oxide-sloc.git");
}

// ── parse_github_push ─────────────────────────────────────────────────────────

const GITHUB_PUSH: &[u8] = br#"{
  "ref": "refs/heads/main",
  "after": "abc1234def5678abc1234def5678abc1234def56",
  "repository": {
    "clone_url": "https://github.com/org/repo.git"
  },
  "pusher": {
    "name": "alice"
  }
}"#;

#[test]
fn parse_github_push_valid() {
    let event = parse_github_push(GITHUB_PUSH).unwrap();
    assert_eq!(event.provider, WebhookProvider::GitHub);
    assert_eq!(event.branch, "main");
    assert_eq!(event.commit_sha, "abc1234def5678abc1234def5678abc1234def56");
    assert_eq!(event.repo_url, "https://github.com/org/repo.git");
    assert_eq!(event.pusher.as_deref(), Some("alice"));
}

#[test]
fn parse_github_push_strips_refs_heads() {
    let event = parse_github_push(GITHUB_PUSH).unwrap();
    assert_eq!(
        event.branch, "main",
        "refs/heads/ prefix should be stripped"
    );
}

#[test]
fn parse_github_push_missing_ref_errors() {
    let body = br#"{"after":"abc","repository":{"clone_url":"https://github.com/o/r.git"}}"#;
    assert!(parse_github_push(body).is_err());
}

#[test]
fn parse_github_push_malformed_json_errors() {
    assert!(parse_github_push(b"not json {{{").is_err());
}

// ── parse_gitlab_push ─────────────────────────────────────────────────────────

const GITLAB_PUSH: &[u8] = br#"{
  "ref": "refs/heads/develop",
  "checkout_sha": "deadbeef1234567890deadbeef1234567890dead",
  "user_username": "bob",
  "project": {
    "git_http_url": "https://gitlab.com/org/project.git"
  }
}"#;

#[test]
fn parse_gitlab_push_valid() {
    let event = parse_gitlab_push(GITLAB_PUSH).unwrap();
    assert_eq!(event.provider, WebhookProvider::GitLab);
    assert_eq!(event.branch, "develop");
    assert_eq!(event.commit_sha, "deadbeef1234567890deadbeef1234567890dead");
    assert_eq!(event.repo_url, "https://gitlab.com/org/project.git");
    assert_eq!(event.pusher.as_deref(), Some("bob"));
}

#[test]
fn parse_gitlab_push_missing_checkout_sha_errors() {
    let body =
        br#"{"ref":"refs/heads/main","project":{"git_http_url":"https://gitlab.com/o/r.git"}}"#;
    assert!(parse_gitlab_push(body).is_err());
}

// ── parse_bitbucket_push ──────────────────────────────────────────────────────

const BITBUCKET_PUSH: &[u8] = br#"{
  "actor": {"display_name": "carol"},
  "repository": {
    "links": {
      "clone": [
        {"name": "https", "href": "https://bitbucket.org/ws/repo.git"}
      ]
    }
  },
  "push": {
    "changes": [{
      "new": {
        "name": "feature/xyz",
        "target": {"hash": "cafebabe1234567890cafebabe1234567890cafe"}
      }
    }]
  }
}"#;

#[test]
fn parse_bitbucket_push_valid() {
    let event = parse_bitbucket_push(BITBUCKET_PUSH).unwrap();
    assert_eq!(event.provider, WebhookProvider::Bitbucket);
    assert_eq!(event.branch, "feature/xyz");
    assert_eq!(event.commit_sha, "cafebabe1234567890cafebabe1234567890cafe");
    assert_eq!(event.repo_url, "https://bitbucket.org/ws/repo.git");
    assert_eq!(event.pusher.as_deref(), Some("carol"));
}

#[test]
fn parse_bitbucket_push_malformed_json_errors() {
    assert!(parse_bitbucket_push(b"{{invalid").is_err());
}

// ── verify_github_sig ────────────────────────────────────────────────────────

#[test]
fn verify_github_sig_valid() {
    // Pre-computed: HMAC-SHA256("secret", "hello") in hex
    let body = b"hello";
    let secret = "secret";
    // Compute expected sig using ring directly to get a reference value
    use ring::hmac;
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let tag = hmac::sign(&key, body);
    let hex: String = tag.as_ref().iter().fold(String::new(), |mut s, b| {
        use std::fmt::Write;
        write!(s, "{b:02x}").unwrap();
        s
    });
    let sig_header = format!("sha256={hex}");
    assert!(verify_github_sig(body, &sig_header, secret));
}

#[test]
fn verify_github_sig_wrong_prefix_fails() {
    assert!(!verify_github_sig(b"hello", "md5=abcdef", "secret"));
}

#[test]
fn verify_github_sig_tampered_body_fails() {
    use ring::hmac;
    let secret = "secret";
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let tag = hmac::sign(&key, b"hello");
    let hex: String = tag.as_ref().iter().fold(String::new(), |mut s, b| {
        use std::fmt::Write;
        write!(s, "{b:02x}").unwrap();
        s
    });
    let sig_header = format!("sha256={hex}");
    // Wrong body
    assert!(!verify_github_sig(b"tampered", &sig_header, secret));
}

#[test]
fn verify_github_sig_wrong_secret_fails() {
    use ring::hmac;
    let key = hmac::Key::new(hmac::HMAC_SHA256, b"secret");
    let tag = hmac::sign(&key, b"hello");
    let hex: String = tag.as_ref().iter().fold(String::new(), |mut s, b| {
        use std::fmt::Write;
        write!(s, "{b:02x}").unwrap();
        s
    });
    let sig_header = format!("sha256={hex}");
    assert!(!verify_github_sig(b"hello", &sig_header, "wrong-secret"));
}

// ── WebhookEvent serde ────────────────────────────────────────────────────────

#[test]
fn webhook_event_serde_roundtrip() {
    let event = parse_github_push(GITHUB_PUSH).unwrap();
    let json = serde_json::to_string(&event).unwrap();
    let back: sloc_git::WebhookEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back.branch, event.branch);
    assert_eq!(back.commit_sha, event.commit_sha);
    assert_eq!(back.repo_url, event.repo_url);
}
