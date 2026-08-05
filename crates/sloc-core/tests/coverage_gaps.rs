// SPDX-License-Identifier: AGPL-3.0-or-later
// Coverage-gap tests for sloc-core: git-metadata detection over a real repo,
// per-file activity, multi-scan delta classification (added/removed/unchanged),
// store persistence into freshly-created directories, JaCoCo coverage parsing,
// and coverage-file resolution.

use std::path::Path;
use std::process::Command;
use std::sync::{Mutex, MutexGuard, OnceLock};

use sloc_config::AppConfig;
use sloc_core::coverage::{parse_jacoco, resolve_coverage_file};
use sloc_core::{
    BaselineEntry, BaselineStore, CleanupPolicyStore, ScanRegistry, ScanSummarySnapshot,
    WatchedDirsStore, analyze, compute_multi_delta,
};

// Env-mutating tests share one lock so parallel threads never observe each
// other's changes.
static ENV_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();
fn env_lock() -> MutexGuard<'static, ()> {
    ENV_MUTEX
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn git_available() -> bool {
    Command::new("git")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn git(dir: &Path, args: &[&str]) -> bool {
    Command::new("git")
        .args(["-c", "user.email=t@t", "-c", "user.name=Tester"])
        .args(args)
        .current_dir(dir)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn config_for(dir: &Path) -> AppConfig {
    let mut cfg = AppConfig::default();
    cfg.discovery.root_paths = vec![dir.to_path_buf()];
    cfg
}

// ── analyze() over a real git repository ──────────────────────────────────────

/// Analysing a real git checkout populates the git-metadata fields (branch,
/// commit SHA, remote URL) by reading `.git/` directly, and attaches per-file
/// activity when the default 90-day window is on.
#[test]
fn analyze_populates_git_metadata_and_activity() {
    if !git_available() {
        eprintln!("git not available — skipping");
        return;
    }
    let repo = tempfile::tempdir().unwrap();
    let p = repo.path();
    assert!(git(p, &["init"]));
    // A named remote so read_git_remote_url has something to parse.
    assert!(git(
        p,
        &[
            "remote",
            "add",
            "origin",
            "https://example.com/org/repo.git"
        ]
    ));
    std::fs::write(p.join("main.rs"), "fn main() {}\n// a comment\n").unwrap();
    assert!(git(p, &["add", "main.rs"]));
    assert!(git(p, &["commit", "-m", "seed"]));

    let cfg = config_for(p);
    let run = analyze(&cfg, "test", None, None).unwrap();

    assert_eq!(run.summary_totals.files_analyzed, 1);
    assert!(
        run.git_commit_long.as_ref().is_some_and(|s| s.len() >= 40),
        "full commit SHA should be resolved from HEAD ref"
    );
    assert!(
        run.git_commit_short.as_ref().is_some_and(|s| s.len() == 7),
        "short SHA should be 7 chars"
    );
    assert_eq!(
        run.git_remote_url.as_deref(),
        Some("https://example.com/org/repo.git"),
        "origin remote URL should be read from .git/config"
    );
    // Per-file activity: the committed file has one commit recorded.
    let rec = run
        .per_file_records
        .iter()
        .find(|r| r.relative_path.ends_with("main.rs"))
        .expect("main.rs record must exist");
    assert!(
        rec.commit_count.unwrap_or(0) >= 1,
        "committed file should have >=1 commit in the activity window"
    );
    assert!(
        rec.last_commit_date.is_some(),
        "committed file should carry a last-change date"
    );
}

/// A non-git directory still analyses cleanly with empty git metadata (the
/// find_git_dir None fallback).
#[test]
fn analyze_non_git_directory_has_no_git_metadata() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("x.rs"), "fn x() {}\n").unwrap();
    let cfg = config_for(dir.path());
    let run = analyze(&cfg, "test", None, None).unwrap();
    assert_eq!(run.summary_totals.files_analyzed, 1);
    assert!(
        run.git_commit_long.is_none(),
        "a non-repo path should have no commit SHA"
    );
}

/// With the activity window disabled (0), no per-file activity is attached even
/// inside a git repo.
#[test]
fn analyze_activity_window_zero_disables_activity() {
    if !git_available() {
        eprintln!("git not available — skipping");
        return;
    }
    let repo = tempfile::tempdir().unwrap();
    let p = repo.path();
    assert!(git(p, &["init"]));
    std::fs::write(p.join("f.rs"), "fn f() {}\n").unwrap();
    assert!(git(p, &["add", "f.rs"]));
    assert!(git(p, &["commit", "-m", "c"]));

    let mut cfg = config_for(p);
    cfg.analysis.activity_window_days = Some(0);
    let run = analyze(&cfg, "test", None, None).unwrap();
    let rec = &run.per_file_records[0];
    assert!(
        rec.commit_count.is_none(),
        "activity window 0 must not attach commit counts"
    );
}

// ── multi-scan delta classification ───────────────────────────────────────────

/// Produce a genuine AnalysisRun from a directory of source files.
fn analyze_dir(files: &[(&str, &str)]) -> (tempfile::TempDir, sloc_core::AnalysisRun) {
    let dir = tempfile::tempdir().unwrap();
    for (name, body) in files {
        std::fs::write(dir.path().join(name), body).unwrap();
    }
    let cfg = config_for(dir.path());
    let run = analyze(&cfg, "test", None, None).unwrap();
    (dir, run)
}

/// compute_multi_delta across three scans covers every overall-status arm:
/// a file that is added late, one removed midway, one modified, one unchanged.
#[test]
fn multi_delta_classifies_added_removed_modified_unchanged() {
    // Scan 1: stable.rs + removed.rs + grow.rs
    let (_d1, r1) = analyze_dir(&[
        ("stable.rs", "fn s() {}\n"),
        ("removed.rs", "fn r() {}\n"),
        ("grow.rs", "fn g() {}\n"),
    ]);
    // Scan 2: removed.rs gone, grow.rs unchanged, stable.rs unchanged
    let (_d2, r2) = analyze_dir(&[("stable.rs", "fn s() {}\n"), ("grow.rs", "fn g() {}\n")]);
    // Scan 3: grow.rs modified (more code), added.rs appears, stable.rs unchanged
    let (_d3, r3) = analyze_dir(&[
        ("stable.rs", "fn s() {}\n"),
        ("grow.rs", "fn g() {}\nfn g2() {}\nfn g3() {}\n"),
        ("added.rs", "fn a() {}\n"),
    ]);

    let cmp = compute_multi_delta(&[&r1, &r2, &r3]);
    let status_of = |name: &str| -> String {
        cmp.file_matrix
            .iter()
            .find(|f| f.relative_path.ends_with(name))
            .map(|f| f.overall_status.clone())
            .unwrap_or_default()
    };

    assert_eq!(status_of("added.rs"), "added");
    assert_eq!(status_of("removed.rs"), "removed");
    assert_eq!(status_of("grow.rs"), "modified");
    assert_eq!(status_of("stable.rs"), "unchanged");

    // Sequential deltas: two consecutive pairs for three scans.
    assert_eq!(cmp.sequential_deltas.len(), 2);
    assert_eq!(cmp.points.len(), 3);
}

// ── store persistence into freshly-created directories ────────────────────────

#[test]
fn stores_save_into_nonexistent_nested_dir() {
    let root = tempfile::tempdir().unwrap();

    // BaselineStore into a nested path whose parent does not yet exist.
    let bpath = root.path().join("nested/a/baselines.json");
    let mut bstore = BaselineStore::default();
    bstore.set(BaselineEntry {
        name: "main".into(),
        saved_at: chrono::Utc::now(),
        run_id: "run-1".into(),
        summary: ScanSummarySnapshot {
            code_lines: 42,
            ..ScanSummarySnapshot::default()
        },
        json_path: None,
    });
    bstore.save(&bpath).unwrap();
    assert!(bpath.exists(), "baseline file should be created");
    assert_eq!(
        BaselineStore::load(&bpath).baselines["main"]
            .summary
            .code_lines,
        42
    );

    // ScanRegistry into a nested path.
    let rpath = root.path().join("nested/b/registry.json");
    ScanRegistry::default().save(&rpath).unwrap();
    assert!(rpath.exists());

    // WatchedDirsStore into a nested path.
    let wpath = root.path().join("nested/c/watched.json");
    let mut wstore = WatchedDirsStore::default();
    wstore.add(root.path().to_path_buf());
    wstore.save(&wpath).unwrap();
    assert_eq!(WatchedDirsStore::load(&wpath).dirs.len(), 1);

    // CleanupPolicyStore into a nested path.
    let cpath = root.path().join("nested/d/cleanup.json");
    CleanupPolicyStore::default().save(&cpath).unwrap();
    assert!(cpath.exists());
}

// ── coverage parsing / resolution ─────────────────────────────────────────────

const JACOCO: &str = r#"<?xml version="1.0"?>
<report name="app">
  <package name="com/example">
    <sourcefile name="Main.java">
      <counter type="LINE" missed="2" covered="8"/>
      <counter type="METHOD" missed="0" covered="3"/>
      <counter type="BRANCH" missed="1" covered="5"/>
    </sourcefile>
  </package>
  <package name="">
    <sourcefile name="Root.java">
      <counter type="LINE" missed="0" covered="4"/>
    </sourcefile>
  </package>
</report>
"#;

#[test]
fn parse_jacoco_reconstructs_package_paths() {
    let map = parse_jacoco(JACOCO);
    let main = map
        .get(Path::new("com/example/Main.java"))
        .expect("packaged sourcefile path should be reconstructed");
    assert_eq!(main.lines_found, 10, "missed+covered lines");
    assert_eq!(main.lines_hit, 8);
    assert_eq!(main.functions_found, 3);
    assert_eq!(main.branches_found, 6);
    // Empty package name → bare filename.
    assert!(
        map.contains_key(Path::new("Root.java")),
        "empty-package sourcefile keeps its bare name"
    );
}

#[test]
fn resolve_coverage_file_prefers_env_over_config() {
    let _guard = env_lock();
    // SAFETY: single-threaded test guarded by env_lock().
    unsafe { std::env::set_var("SLOC_COVERAGE_FILE", "/tmp/from-env.info") };
    let resolved = resolve_coverage_file(Some(Path::new("/tmp/from-config.info")));
    // SAFETY: single-threaded test guarded by env_lock().
    unsafe { std::env::remove_var("SLOC_COVERAGE_FILE") };
    assert_eq!(
        resolved.as_deref(),
        Some(Path::new("/tmp/from-env.info")),
        "SLOC_COVERAGE_FILE should win over the config path"
    );
}

#[test]
fn resolve_coverage_file_falls_back_to_config_and_none() {
    let _guard = env_lock();
    // SAFETY: single-threaded test guarded by env_lock().
    unsafe { std::env::remove_var("SLOC_COVERAGE_FILE") };
    assert_eq!(
        resolve_coverage_file(Some(Path::new("/tmp/cfg.info"))).as_deref(),
        Some(Path::new("/tmp/cfg.info"))
    );
    assert!(
        resolve_coverage_file(None).is_none(),
        "no env and no config path → None"
    );
}
