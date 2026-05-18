// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Nima Shafie <nimzshafie@gmail.com>
#![allow(clippy::multiple_crate_versions)]

pub mod baseline;
pub mod coverage;
pub mod delta;
pub mod history;
pub use baseline::{check_against_baseline, resolve_baselines_path, BaselineEntry, BaselineStore};
pub use coverage::{aggregate_line_coverage, lookup_coverage, parse_lcov, FileCoverage};
pub use delta::{compute_delta, FileChangeStatus, FileDelta, ScanComparison, SummaryDelta};
pub use history::{RegistryEntry, ScanRegistry, ScanSummarySnapshot, WatchedDirsStore};

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use encoding_rs::{UTF_16BE, UTF_16LE, WINDOWS_1252};
use globset::{Glob, GlobSet, GlobSetBuilder};
use ignore::WalkBuilder;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use sloc_config::{
    AppConfig, BinaryFileBehavior, BlankInBlockCommentPolicy, ContinuationLinePolicy,
    FailureBehavior, MixedLinePolicy,
};
use sloc_languages::{
    analyze_text, detect_language, supported_languages, AnalysisOptions, Language, ParseMode,
    RawLineCounts,
};

// ── Detection sample sizes and thresholds ────────────────────────────────────

/// Maximum number of worker threads used for parallel file analysis.
const MAX_ANALYSIS_THREADS: usize = 16;
/// Fallback thread count when `available_parallelism` is unavailable.
const DEFAULT_ANALYSIS_THREADS: usize = 4;
/// Byte sample used to detect `@generated` markers.
const GENERATED_SAMPLE_BYTES: usize = 1024;
/// Byte sample used to detect minified files via line-length heuristic.
const MINIFIED_SAMPLE_BYTES: usize = 4096;
/// Longest line length above which a file is considered minified.
const MINIFIED_LINE_THRESHOLD: usize = 2000;
/// Byte sample used to detect binary files via null-byte scan.
const BINARY_SAMPLE_BYTES: usize = 8192;

/// Three-way outcome for metadata-level policy checks.
enum MetadataPolicyOutcome {
    /// Skip this file — include the record in output.
    Skip(Box<FileRecord>),
    /// Exclude this file entirely — no record in output (include-glob miss).
    Exclude,
    /// Continue to content checks.
    Continue,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileStatus {
    AnalyzedExact,
    AnalyzedBestEffort,
    SkippedBinary,
    SkippedDecodeError,
    SkippedUnsupported,
    SkippedByPolicy,
    ErrorInternal,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EffectiveCounts {
    pub code_lines: u64,
    pub comment_lines: u64,
    pub blank_lines: u64,
    pub mixed_lines_separate: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolMetadata {
    pub name: String,
    pub version: String,
    pub run_id: String,
    pub timestamp_utc: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentMetadata {
    pub operating_system: String,
    pub architecture: String,
    pub runtime_mode: String,
    pub initiator_username: String,
    pub initiator_hostname: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SummaryTotals {
    pub files_considered: u64,
    pub files_analyzed: u64,
    pub files_skipped: u64,
    pub total_physical_lines: u64,
    pub code_lines: u64,
    pub comment_lines: u64,
    pub blank_lines: u64,
    pub mixed_lines_separate: u64,
    #[serde(default)]
    pub functions: u64,
    #[serde(default)]
    pub classes: u64,
    #[serde(default)]
    pub variables: u64,
    #[serde(default)]
    pub imports: u64,
    #[serde(default)]
    pub test_count: u64,
    /// Lexically detected test assertion call lines across all analyzed files.
    #[serde(default)]
    pub test_assertion_count: u64,
    /// Lexically detected test suite / fixture / group declaration lines across all analyzed files.
    #[serde(default)]
    pub test_suite_count: u64,
    /// Aggregated from LCOV data when provided.
    #[serde(default)]
    pub coverage_lines_found: u64,
    #[serde(default)]
    pub coverage_lines_hit: u64,
    #[serde(default)]
    pub coverage_functions_found: u64,
    #[serde(default)]
    pub coverage_functions_hit: u64,
    #[serde(default)]
    pub coverage_branches_found: u64,
    #[serde(default)]
    pub coverage_branches_hit: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanguageSummary {
    pub language: Language,
    pub files: u64,
    pub total_physical_lines: u64,
    pub code_lines: u64,
    pub comment_lines: u64,
    pub blank_lines: u64,
    pub mixed_lines_separate: u64,
    #[serde(default)]
    pub functions: u64,
    #[serde(default)]
    pub classes: u64,
    #[serde(default)]
    pub variables: u64,
    #[serde(default)]
    pub imports: u64,
    #[serde(default)]
    pub test_count: u64,
    #[serde(default)]
    pub test_assertion_count: u64,
    #[serde(default)]
    pub test_suite_count: u64,
    #[serde(default)]
    pub coverage_lines_found: u64,
    #[serde(default)]
    pub coverage_lines_hit: u64,
    #[serde(default)]
    pub coverage_functions_found: u64,
    #[serde(default)]
    pub coverage_functions_hit: u64,
    #[serde(default)]
    pub coverage_branches_found: u64,
    #[serde(default)]
    pub coverage_branches_hit: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRecord {
    pub path: String,
    pub relative_path: String,
    pub language: Option<Language>,
    pub size_bytes: u64,
    pub detected_encoding: Option<String>,
    pub raw_line_categories: RawLineCounts,
    pub effective_counts: EffectiveCounts,
    pub status: FileStatus,
    pub warnings: Vec<String>,
    pub generated: bool,
    pub minified: bool,
    pub vendor: bool,
    pub parse_mode: Option<ParseMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub submodule: Option<String>,
    /// Line/function/branch coverage from an external LCOV file, when provided.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage: Option<FileCoverage>,
}

/// Per-submodule aggregated stats produced when `submodule_breakdown` is enabled.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmoduleSummary {
    pub name: String,
    pub relative_path: String,
    pub files_analyzed: u64,
    pub total_physical_lines: u64,
    pub code_lines: u64,
    pub comment_lines: u64,
    pub blank_lines: u64,
    pub language_summaries: Vec<LanguageSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisRun {
    pub tool: ToolMetadata,
    pub environment: EnvironmentMetadata,
    pub effective_configuration: AppConfig,
    pub input_roots: Vec<String>,
    pub summary_totals: SummaryTotals,
    pub totals_by_language: Vec<LanguageSummary>,
    pub per_file_records: Vec<FileRecord>,
    pub skipped_file_records: Vec<FileRecord>,
    pub warnings: Vec<String>,
    /// Non-empty only when `discovery.submodule_breakdown` is enabled.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub submodule_summaries: Vec<SubmoduleSummary>,
    /// Short git commit SHA (7 chars) at scan time, if the project is a git repo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_commit_short: Option<String>,
    /// Full git commit SHA at scan time, if the project is a git repo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_commit_long: Option<String>,
    /// Git branch active at scan time, if the project is a git repo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_branch: Option<String>,
    /// Author of the last git commit at scan time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_commit_author: Option<String>,
    /// Comma-separated git tags pointing at HEAD at scan time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_tags: Option<String>,
    /// Nearest ancestor release tag (output of `git describe --tags --abbrev=0`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_nearest_tag: Option<String>,
    /// ISO 8601 author-date of the last git commit at scan time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_commit_date: Option<String>,
}

#[derive(Default)]
struct GitInfo {
    commit_short: Option<String>,
    commit_long: Option<String>,
    branch: Option<String>,
    author: Option<String>,
    tags: Option<String>,
    nearest_tag: Option<String>,
    commit_date: Option<String>,
}

/// Locate the `.git` directory by walking up from `start`.
/// Handles plain repos, worktrees (`.git` is a file with `gitdir:` pointer), and
/// submodules. Returns `None` if no git repo is found.
fn find_git_dir(start: &Path) -> Option<PathBuf> {
    let mut current = Some(start);
    while let Some(dir) = current {
        let candidate = dir.join(".git");
        if candidate.is_dir() {
            return Some(candidate);
        }
        if candidate.is_file() {
            // Worktree / submodule: `.git` file contains "gitdir: <path>".
            // The path uses forward slashes on all platforms (git convention).
            // On Windows it may be an absolute Windows path such as
            // "C:/Users/…/.git/worktrees/name" — Path::new().is_absolute()
            // recognises both "C:/" and "C:\" prefixes on Windows.
            if let Ok(content) = fs::read_to_string(&candidate) {
                if let Some(ptr) = content.trim().strip_prefix("gitdir: ") {
                    // Normalise forward-slash paths to the OS separator so that
                    // Path operations (join, exists, canonicalize) work correctly
                    // on Windows.
                    let ptr_native = ptr.replace('/', std::path::MAIN_SEPARATOR_STR);
                    let resolved = if Path::new(&ptr_native).is_absolute() {
                        PathBuf::from(&ptr_native)
                    } else {
                        dir.join(&ptr_native)
                    };
                    // canonicalize resolves ".." components and symlinks; fall
                    // back to the un-canonicalized path if it fails (e.g. on
                    // some Windows configurations canonicalize returns a UNC
                    // "\\?\" prefix that confuses later path operations).
                    let final_path = resolved.canonicalize().unwrap_or(resolved);
                    if final_path.is_dir() {
                        return Some(final_path);
                    }
                }
            }
        }
        current = dir.parent();
    }
    None
}

/// Resolve a git ref name (e.g. `refs/heads/main`) to a full 40-char commit SHA.
/// Checks loose ref files first, then `packed-refs`.
fn resolve_ref(git_dir: &Path, refname: &str) -> Option<String> {
    // Build the OS-native path to the loose ref file by joining each
    // forward-slash component individually.  This produces the correct
    // separator on every platform without any manual replacement.
    let ref_path = refname
        .split('/')
        .fold(git_dir.to_path_buf(), |p, c| p.join(c));
    if ref_path.exists() {
        let sha = fs::read_to_string(&ref_path)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| s.len() >= 40 && s.chars().all(|c| c.is_ascii_hexdigit()));
        if sha.is_some() {
            return sha;
        }
    }
    // Packed refs: each line is "<sha> <refname>" (lines starting with '#' are
    // comments; lines starting with '^' are peeled tag objects to skip).
    // str::lines() handles both \n and \r\n, so Windows line endings are fine.
    let packed = fs::read_to_string(git_dir.join("packed-refs")).ok()?;
    for line in packed.lines() {
        if line.starts_with('#') || line.starts_with('^') {
            continue;
        }
        let mut cols = line.splitn(2, ' ');
        let sha = cols.next()?;
        let name = cols.next()?.trim();
        if name == refname {
            return Some(sha.to_string());
        }
    }
    None
}

/// Parse the last entry of `.git/logs/HEAD` to get the commit author name and
/// author-date in ISO 8601 format.
///
/// Reflog line format:
/// `<old-sha> <new-sha> Author Name <email> <unix-ts> <tz-offset>\t<message>`
fn parse_last_reflog_entry(git_dir: &Path) -> (Option<String>, Option<String>) {
    let log_path = git_dir.join("logs").join("HEAD");
    let Ok(content) = fs::read_to_string(&log_path) else {
        return (None, None);
    };
    let Some(last) = content.lines().rfind(|l| !l.trim().is_empty()) else {
        return (None, None);
    };

    // Skip the two 40-char SHAs + their separating spaces
    // (an initial commit shows 0000... as old-sha, still 40 chars)
    let Some(after_shas) = last.splitn(3, ' ').nth(2) else {
        return (None, None);
    };

    // Author name ends just before " <email>"
    let author = after_shas.find(" <").map(|i| after_shas[..i].to_string());

    // Timestamp is the number after the closing ">"
    let date = (|| {
        use chrono::TimeZone as _;
        let close = after_shas.find("> ")?;
        let rest = after_shas[close + 2..].trim_start();
        let mut tokens = rest.splitn(3, ' ');
        let unix_str = tokens.next()?;
        let offset_str = tokens.next().map(|s| s.split('\t').next().unwrap_or(s))?;
        let ts: i64 = unix_str.parse().ok()?;
        let dt = chrono::Utc.timestamp_opt(ts, 0).single()?;
        // Format as ISO 8601 with timezone offset, e.g. 2026-05-17T12:51:54-07:00
        let tz_display = if offset_str.len() == 5 {
            format!("{}:{}", &offset_str[..3], &offset_str[3..])
        } else {
            offset_str.to_string()
        };
        Some(format!("{}{}", dt.format("%Y-%m-%dT%H:%M:%S"), tz_display))
    })();

    (author, date)
}

/// Detect git metadata by reading `.git/` files directly — no `git` executable
/// needed. Falls back gracefully for detached HEADs, shallow clones, and missing
/// reflogs.
fn detect_git_for_run(project_path: &Path) -> GitInfo {
    let Some(git_dir) = find_git_dir(project_path) else {
        return GitInfo::default();
    };

    let head_raw = match fs::read_to_string(git_dir.join("HEAD")) {
        Ok(s) => s.trim().to_string(),
        Err(_) => return GitInfo::default(),
    };

    let (branch, commit_long) = if let Some(refname) = head_raw.strip_prefix("ref: ") {
        let branch = refname
            .strip_prefix("refs/heads/")
            .map(|b| b.trim().to_string());
        let sha = resolve_ref(&git_dir, refname.trim());
        (branch, sha)
    } else if head_raw.len() >= 40 && head_raw.chars().all(|c| c.is_ascii_hexdigit()) {
        // Detached HEAD — the HEAD file itself is the commit SHA
        (None, Some(head_raw[..40].to_string()))
    } else {
        (None, None)
    };

    let commit_short = commit_long
        .as_deref()
        .map(|s| s.chars().take(7).collect::<String>());

    let (author, commit_date) = parse_last_reflog_entry(&git_dir);

    // Tags and nearest-tag still require git CLI — try it as a best-effort bonus
    // but don't block on it. If git isn't available these will simply be None.
    let tags = run_git_cmd(project_path, &["tag", "--points-at", "HEAD"]).map(|t| {
        t.lines()
            .filter(|l| !l.is_empty())
            .collect::<Vec<_>>()
            .join(", ")
    });
    let nearest_tag = run_git_cmd(project_path, &["describe", "--tags", "--abbrev=0", "HEAD"]);

    GitInfo {
        commit_short,
        commit_long,
        branch,
        author,
        tags,
        nearest_tag,
        commit_date,
    }
}

/// Run a git command as a best-effort supplemental source.  Not used for the
/// core commit/branch/author fields — those come from direct file reads above.
fn run_git_cmd(dir: &Path, args: &[&str]) -> Option<String> {
    // Try the bare name first (works when git is on PATH), then fall back to
    // absolute paths for service accounts that run with a stripped PATH.
    // Unix paths silently fail on Windows and vice-versa.
    let candidates: &[&str] = &[
        // Works on all platforms when git is on PATH
        "git",
        // Common Linux / macOS install locations
        "/usr/bin/git",
        "/usr/local/bin/git",
        "/opt/homebrew/bin/git",
        // Git for Windows default installation paths
        r"C:\Program Files\Git\cmd\git.exe",
        r"C:\Program Files\Git\bin\git.exe",
        r"C:\Program Files (x86)\Git\cmd\git.exe",
    ];
    for &exe in candidates {
        let result = std::process::Command::new(exe)
            .args(["-c", "safe.directory=*"])
            .args(args)
            .current_dir(dir)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        if result.is_some() {
            return result;
        }
    }
    None
}

fn get_current_username() -> String {
    std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "unknown".to_string())
}

fn get_hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Walk a single directory root and collect file records into the output vectors.
#[allow(clippy::too_many_arguments)]
fn walk_root(
    root: &Path,
    config: &AppConfig,
    include_globs: Option<&GlobSet>,
    exclude_globs: Option<&GlobSet>,
    enabled_languages: Option<&BTreeSet<Language>>,
    seen_paths: &mut HashSet<PathBuf>,
    analyzed: &mut Vec<FileRecord>,
    skipped: &mut Vec<FileRecord>,
    warnings: &mut Vec<String>,
    cancel: Option<&AtomicBool>,
) -> Result<()> {
    let mut builder = WalkBuilder::new(root);
    builder
        .follow_links(config.discovery.follow_symlinks)
        .hidden(config.discovery.ignore_hidden_files)
        .ignore(config.discovery.honor_ignore_files)
        .parents(config.discovery.honor_ignore_files)
        .git_ignore(config.discovery.honor_ignore_files)
        .git_global(config.discovery.honor_ignore_files)
        .git_exclude(config.discovery.honor_ignore_files);

    let paths = collect_walk_paths(&builder, seen_paths, warnings);
    if paths.is_empty() {
        return Ok(());
    }

    let chunk_results = run_parallel_analysis(
        &paths,
        root,
        config,
        include_globs,
        exclude_globs,
        enabled_languages,
        cancel,
    )?;
    merge_chunk_results(chunk_results, analyzed, skipped, warnings)
}

fn collect_walk_paths(
    builder: &WalkBuilder,
    seen_paths: &mut HashSet<PathBuf>,
    warnings: &mut Vec<String>,
) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for entry in builder.build() {
        let entry = match entry {
            Ok(e) => e,
            Err(err) => {
                warnings.push(format!("discovery warning: {err}"));
                continue;
            }
        };
        let path = entry.into_path();
        if path.is_dir() || !seen_paths.insert(path.clone()) {
            continue;
        }
        paths.push(path);
    }
    paths
}

#[allow(clippy::too_many_arguments)]
fn run_parallel_analysis(
    paths: &[PathBuf],
    root: &Path,
    config: &AppConfig,
    include_globs: Option<&GlobSet>,
    exclude_globs: Option<&GlobSet>,
    enabled_languages: Option<&BTreeSet<Language>>,
    cancel: Option<&AtomicBool>,
) -> Result<Vec<Vec<Result<Option<FileRecord>>>>> {
    let thread_count = std::thread::available_parallelism().map_or(DEFAULT_ANALYSIS_THREADS, |n| {
        n.get().min(MAX_ANALYSIS_THREADS)
    });
    let chunk_size = paths.len().div_ceil(thread_count);
    std::thread::scope(|s| -> Result<Vec<Vec<Result<Option<FileRecord>>>>> {
        paths
            .chunks(chunk_size)
            .map(|chunk| {
                s.spawn(move || -> Vec<Result<Option<FileRecord>>> {
                    let mut results = Vec::with_capacity(chunk.len());
                    for path in chunk {
                        if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                            results.push(Err(anyhow::anyhow!("analysis cancelled")));
                            break;
                        }
                        results.push(analyze_candidate_file(
                            path,
                            root,
                            config,
                            include_globs,
                            exclude_globs,
                            enabled_languages,
                        ));
                    }
                    results
                })
            })
            .map(|h| {
                h.join()
                    .map_err(|_| anyhow::anyhow!("analysis thread panicked"))
            })
            .collect()
    })
}

fn merge_chunk_results(
    chunk_results: Vec<Vec<Result<Option<FileRecord>>>>,
    analyzed: &mut Vec<FileRecord>,
    skipped: &mut Vec<FileRecord>,
    warnings: &mut Vec<String>,
) -> Result<()> {
    for chunk in chunk_results {
        for result in chunk {
            if let Some(record) = result? {
                push_record(record, analyzed, skipped, warnings);
            }
        }
    }
    Ok(())
}

/// Label each analyzed file with its submodule and build per-submodule summaries.
fn process_submodules(config: &AppConfig, analyzed: &mut [FileRecord]) -> Vec<SubmoduleSummary> {
    let root = config.discovery.root_paths[0]
        .canonicalize()
        .unwrap_or_else(|_| config.discovery.root_paths[0].clone());
    let submodules = detect_submodules(&root);
    if submodules.is_empty() {
        return Vec::new();
    }

    for file in analyzed.iter_mut() {
        for (name, sub_path) in &submodules {
            let prefix = sub_path.to_string_lossy().replace('\\', "/");
            let rel = &file.relative_path;
            if rel == &prefix || rel.starts_with(&format!("{prefix}/")) {
                file.submodule = Some(name.clone());
                break;
            }
        }
    }

    build_submodule_summaries(analyzed, &submodules)
}

/// Assemble the final `AnalysisRun` from collected records and metadata.
fn assemble_run(
    config: &AppConfig,
    runtime_mode: &str,
    analyzed: Vec<FileRecord>,
    skipped: Vec<FileRecord>,
    warnings: Vec<String>,
    submodule_summaries: Vec<SubmoduleSummary>,
) -> AnalysisRun {
    let summary = build_summary(&analyzed, &skipped);
    let language_summaries = build_language_summaries(&analyzed);

    let first_root = config
        .discovery
        .root_paths
        .first()
        .map(|p| p.canonicalize().unwrap_or_else(|_| p.clone()));
    let git = first_root
        .as_deref()
        .map(detect_git_for_run)
        .unwrap_or_default();

    let now = Utc::now();
    let run_id = {
        let uuid_suffix = Uuid::new_v4().simple().to_string();
        format!("{}-{}", now.format("%Y%m%d-%H%M"), uuid_suffix)
    };

    AnalysisRun {
        tool: ToolMetadata {
            name: "sloc".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            run_id,
            timestamp_utc: now,
        },
        environment: EnvironmentMetadata {
            operating_system: std::env::consts::OS.into(),
            architecture: std::env::consts::ARCH.into(),
            runtime_mode: runtime_mode.into(),
            initiator_username: get_current_username(),
            initiator_hostname: get_hostname(),
        },
        effective_configuration: config.clone(),
        input_roots: config
            .discovery
            .root_paths
            .iter()
            .map(|p| path_to_string(p))
            .collect(),
        summary_totals: summary,
        totals_by_language: language_summaries,
        per_file_records: analyzed,
        skipped_file_records: skipped,
        warnings,
        submodule_summaries,
        git_commit_short: git.commit_short,
        git_commit_long: git.commit_long,
        git_branch: git.branch,
        git_commit_author: git.author,
        git_tags: git.tags,
        git_nearest_tag: git.nearest_tag,
        git_commit_date: git.commit_date,
    }
}

/// # Errors
///
/// Returns an error if the config is invalid, root paths cannot be walked, or any file
/// analysis step fails in a way that cannot be recovered from.
#[allow(clippy::too_many_lines)]
pub fn analyze(
    config: &AppConfig,
    runtime_mode: &str,
    cancel: Option<&AtomicBool>,
) -> Result<AnalysisRun> {
    config.validate()?;

    if config.discovery.root_paths.is_empty() {
        anyhow::bail!("no input paths were provided");
    }

    let include_globs = compile_globset(&config.discovery.include_globs)?;
    let exclude_globs = compile_globset(&config.discovery.exclude_globs)?;
    let enabled_languages = parse_enabled_languages(&config.analysis.enabled_languages)?;

    let mut analyzed = Vec::new();
    let mut skipped = Vec::new();
    let mut warnings = Vec::new();
    let mut seen_paths = HashSet::new();

    for root in &config.discovery.root_paths {
        if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
            anyhow::bail!("analysis cancelled");
        }

        let root = root.canonicalize().unwrap_or_else(|_| root.clone());

        if root.is_file() {
            if let Some(record) = analyze_candidate_file(
                &root,
                root.parent().unwrap_or_else(|| Path::new(".")),
                config,
                include_globs.as_ref(),
                exclude_globs.as_ref(),
                enabled_languages.as_ref(),
            )? {
                push_record(record, &mut analyzed, &mut skipped, &mut warnings);
            }
            continue;
        }

        walk_root(
            &root,
            config,
            include_globs.as_ref(),
            exclude_globs.as_ref(),
            enabled_languages.as_ref(),
            &mut seen_paths,
            &mut analyzed,
            &mut skipped,
            &mut warnings,
            cancel,
        )?;
    }

    analyzed.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
    skipped.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));

    // Submodule detection: label each file with its submodule and build per-submodule summaries.
    let submodule_summaries = if config.discovery.submodule_breakdown {
        process_submodules(config, &mut analyzed)
    } else {
        Vec::new()
    };

    attach_coverage(config, &mut analyzed, &mut warnings);

    Ok(assemble_run(
        config,
        runtime_mode,
        analyzed,
        skipped,
        warnings,
        submodule_summaries,
    ))
}

fn attach_coverage(config: &AppConfig, analyzed: &mut [FileRecord], warnings: &mut Vec<String>) {
    let Some(cov_path) = coverage::resolve_coverage_file(config.analysis.coverage_file.as_deref())
    else {
        return;
    };
    match fs::read_to_string(&cov_path) {
        Ok(content) => {
            let cov_map = coverage::parse_coverage_auto(&cov_path, &content);
            for record in analyzed.iter_mut() {
                record.coverage =
                    coverage::lookup_coverage(&cov_map, &record.relative_path).cloned();
            }
        }
        Err(e) => {
            warnings.push(format!(
                "coverage file '{}' could not be read: {e}",
                cov_path.display()
            ));
        }
    }
}

fn push_record(
    record: FileRecord,
    analyzed: &mut Vec<FileRecord>,
    skipped: &mut Vec<FileRecord>,
    warnings: &mut Vec<String>,
) {
    warnings.extend(
        record
            .warnings
            .iter()
            .map(|warning| format!("{}: {warning}", record.relative_path)),
    );

    match record.status {
        FileStatus::AnalyzedExact | FileStatus::AnalyzedBestEffort => analyzed.push(record),
        _ => skipped.push(record),
    }
}

/// Convenience wrapper: build a boxed `Skip` outcome with a single-item warning message.
#[inline]
fn skip_with_reason(
    path: &Path,
    root: &Path,
    size: u64,
    reason: impl Into<String>,
) -> MetadataPolicyOutcome {
    MetadataPolicyOutcome::Skip(Box::new(skipped_record(
        path,
        root,
        size,
        FileStatus::SkippedByPolicy,
        vec![reason.into()],
    )))
}

/// Apply metadata-level policy checks (symlink, name, dir exclusion, size, globs, lockfile).
/// Returns `Skip(record)` to skip, `Exclude` to omit from output entirely (include-glob miss),
/// or `Continue` to proceed to content checks.
#[allow(clippy::too_many_arguments)]
fn check_metadata_policy(
    path: &Path,
    root: &Path,
    relative_path: &str,
    metadata: &fs::Metadata,
    config: &AppConfig,
    include_globs: Option<&GlobSet>,
    exclude_globs: Option<&GlobSet>,
) -> MetadataPolicyOutcome {
    let size = metadata.len();

    if metadata.file_type().is_symlink() && !config.discovery.follow_symlinks {
        return skip_with_reason(path, root, size, "symlink skipped by policy");
    }
    if file_name_eq(path, ".gitignore") {
        return skip_with_reason(path, root, size, ".gitignore is always excluded");
    }
    if is_excluded_dir_path(path, &config.discovery.excluded_directories) {
        return skip_with_reason(path, root, size, "path matched excluded directory setting");
    }
    if size > config.discovery.max_file_size_bytes {
        return skip_with_reason(
            path,
            root,
            size,
            format!(
                "file exceeded max_file_size_bytes ({})",
                config.discovery.max_file_size_bytes
            ),
        );
    }
    if let Some(globs) = include_globs {
        if !globs.is_match(Path::new(relative_path)) && !globs.is_match(path) {
            return MetadataPolicyOutcome::Exclude;
        }
    }
    if let Some(globs) = exclude_globs {
        if globs.is_match(Path::new(relative_path)) || globs.is_match(path) {
            return skip_with_reason(path, root, size, "path matched exclude glob");
        }
    }
    if is_known_lockfile(path) && !config.analysis.include_lockfiles {
        return skip_with_reason(path, root, size, "lockfile skipped by default policy");
    }

    MetadataPolicyOutcome::Continue
}

struct ContentPolicyResult {
    vendor: bool,
    generated: bool,
    minified: bool,
    skip_record: Option<FileRecord>,
}

/// Apply content-level policy checks (vendor, generated, minified).
/// `skip_record` is `Some` when the file should be skipped.
fn check_content_policy(
    path: &Path,
    root: &Path,
    size_bytes: u64,
    bytes: &[u8],
    config: &AppConfig,
) -> ContentPolicyResult {
    let vendor = is_vendor_path(path);
    if vendor && config.analysis.vendor_directory_detection {
        return ContentPolicyResult {
            vendor,
            generated: false,
            minified: false,
            skip_record: Some(skipped_record(
                path,
                root,
                size_bytes,
                FileStatus::SkippedByPolicy,
                vec!["vendor file skipped by policy".into()],
            )),
        };
    }

    let generated = config.analysis.generated_file_detection && looks_generated(path, bytes);
    if generated {
        return ContentPolicyResult {
            vendor,
            generated,
            minified: false,
            skip_record: Some(skipped_record(
                path,
                root,
                size_bytes,
                FileStatus::SkippedByPolicy,
                vec!["generated file skipped by policy".into()],
            )),
        };
    }

    let minified = config.analysis.minified_file_detection && looks_minified(path, bytes);
    if minified {
        return ContentPolicyResult {
            vendor,
            generated,
            minified,
            skip_record: Some(skipped_record(
                path,
                root,
                size_bytes,
                FileStatus::SkippedByPolicy,
                vec!["minified file skipped by policy".into()],
            )),
        };
    }

    ContentPolicyResult {
        vendor,
        generated,
        minified,
        skip_record: None,
    }
}

/// Decode file bytes to a UTF-8 string, handling binary detection and decode failures.
fn decode_file_contents(
    path: &Path,
    root: &Path,
    size_bytes: u64,
    bytes: &[u8],
    config: &AppConfig,
) -> Result<Option<(String, String, Vec<String>)>> {
    if is_binary(bytes) {
        return match config.analysis.binary_file_behavior {
            BinaryFileBehavior::Skip => Ok(None),
            BinaryFileBehavior::Fail => {
                anyhow::bail!("binary file encountered: {}", path.display())
            }
        };
    }

    match decode_bytes(bytes) {
        Ok(result) => Ok(Some(result)),
        Err(err) => match config.analysis.decode_failure_behavior {
            FailureBehavior::WarnSkip => {
                // Caller will handle the None as a SkippedDecodeError record.
                // We use a sentinel: return Ok(None) but encode the error into a field.
                // Instead, propagate as a skipped record via the caller.
                let _ = (path, root, size_bytes); // suppress unused warnings
                Err(anyhow::anyhow!("__decode_warn__: {err}"))
            }
            FailureBehavior::Fail => {
                anyhow::bail!("decode failure for {}: {err}", path.display())
            }
        },
    }
}

#[allow(clippy::too_many_lines)]
fn analyze_candidate_file(
    path: &Path,
    root: &Path,
    config: &AppConfig,
    include_globs: Option<&GlobSet>,
    exclude_globs: Option<&GlobSet>,
    enabled_languages: Option<&BTreeSet<Language>>,
) -> Result<Option<FileRecord>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) => {
            return Ok(Some(skipped_record(
                path,
                root,
                0,
                FileStatus::ErrorInternal,
                vec![format!("failed to read metadata: {err}")],
            )));
        }
    };

    let relative_path = relative_path_string(path, root);

    // Metadata-level policy checks.
    match check_metadata_policy(
        path,
        root,
        &relative_path,
        &metadata,
        config,
        include_globs,
        exclude_globs,
    ) {
        MetadataPolicyOutcome::Skip(record) => return Ok(Some(*record)),
        MetadataPolicyOutcome::Exclude => return Ok(None),
        MetadataPolicyOutcome::Continue => {}
    }

    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) => {
            return Ok(Some(skipped_record(
                path,
                root,
                metadata.len(),
                FileStatus::ErrorInternal,
                vec![format!("failed to read file: {err}")],
            )));
        }
    };

    // Content-level policy checks (vendor, generated, minified).
    let content_policy = check_content_policy(path, root, metadata.len(), &bytes, config);
    if let Some(record) = content_policy.skip_record {
        return Ok(Some(record));
    }
    let (vendor, generated, minified) = (
        content_policy.vendor,
        content_policy.generated,
        content_policy.minified,
    );

    // Decode content, handling binary and decode failures.
    let (text, encoding, decode_warnings) =
        match decode_file_contents(path, root, metadata.len(), &bytes, config) {
            Ok(Some(result)) => result,
            Ok(None) => {
                return Ok(Some(skipped_record(
                    path,
                    root,
                    metadata.len(),
                    FileStatus::SkippedBinary,
                    vec!["binary file skipped by default".into()],
                )));
            }
            Err(err) => {
                let msg = err.to_string();
                if let Some(warn_msg) = msg.strip_prefix("__decode_warn__: ") {
                    return Ok(Some(skipped_record(
                        path,
                        root,
                        metadata.len(),
                        FileStatus::SkippedDecodeError,
                        vec![warn_msg.to_string()],
                    )));
                }
                return Err(err);
            }
        };

    let first_line = text.lines().next();
    let language = detect_language(
        path,
        first_line,
        &config.analysis.extension_overrides,
        config.analysis.shebang_detection,
    );

    let Some(language) = language else {
        return Ok(Some(skipped_record(
            path,
            root,
            metadata.len(),
            FileStatus::SkippedUnsupported,
            vec!["unsupported or undetected language".into()],
        )));
    };

    if let Some(enabled) = enabled_languages {
        if !enabled.contains(&language) {
            return Ok(Some(skipped_record(
                path,
                root,
                metadata.len(),
                FileStatus::SkippedByPolicy,
                vec![format!(
                    "language {} disabled by configuration",
                    language.display_name()
                )],
            )));
        }
    }

    let ieee_opts = AnalysisOptions {
        blank_in_block_comment_as_comment: config.analysis.blank_in_block_comment_policy
            == BlankInBlockCommentPolicy::CountAsComment,
        collapse_continuation_lines: config.analysis.continuation_line_policy
            == ContinuationLinePolicy::CollapseToLogical,
    };
    let analysis = analyze_text(language, &text, ieee_opts);
    let effective_counts = compute_effective_counts(
        &analysis.raw,
        config.analysis.mixed_line_policy,
        config.analysis.python_docstrings_as_comments,
        config.analysis.count_compiler_directives,
    );

    let mut warnings = decode_warnings;
    warnings.extend(analysis.warnings.clone());

    Ok(Some(FileRecord {
        path: path_to_string(path),
        relative_path,
        language: Some(language),
        size_bytes: metadata.len(),
        detected_encoding: Some(encoding),
        raw_line_categories: analysis.raw,
        effective_counts,
        status: match analysis.parse_mode {
            ParseMode::Lexical | ParseMode::TreeSitter => FileStatus::AnalyzedExact,
            ParseMode::LexicalBestEffort => FileStatus::AnalyzedBestEffort,
        },
        warnings,
        generated,
        minified,
        vendor,
        parse_mode: Some(analysis.parse_mode),
        submodule: None,
        coverage: None,
    }))
}

const fn compute_effective_counts(
    raw: &RawLineCounts,
    mixed_line_policy: MixedLinePolicy,
    python_docstrings_as_comments: bool,
    count_compiler_directives: bool,
) -> EffectiveCounts {
    let mut effective = EffectiveCounts {
        code_lines: raw.code_only_lines,
        comment_lines: raw.single_comment_only_lines + raw.multi_comment_only_lines,
        blank_lines: raw.blank_only_lines,
        mixed_lines_separate: 0,
    };

    if python_docstrings_as_comments {
        effective.comment_lines += raw.docstring_comment_lines;
    } else {
        effective.code_lines += raw.docstring_comment_lines;
    }

    let mixed_total = raw.mixed_code_single_comment_lines + raw.mixed_code_multi_comment_lines;
    match mixed_line_policy {
        MixedLinePolicy::CodeOnly => effective.code_lines += mixed_total,
        MixedLinePolicy::CodeAndComment => {
            effective.code_lines += mixed_total;
            effective.comment_lines += mixed_total;
        }
        MixedLinePolicy::CommentOnly => effective.comment_lines += mixed_total,
        MixedLinePolicy::SeparateMixedCategory => effective.mixed_lines_separate += mixed_total,
    }

    // IEEE 1045-1992 §4.2: optionally exclude preprocessor/compiler directives from code SLOC.
    // compiler_directive_lines is a subset of code_only_lines, so subtract it directly.
    if !count_compiler_directives {
        effective.code_lines = effective
            .code_lines
            .saturating_sub(raw.compiler_directive_lines);
    }

    effective
}

fn build_summary(analyzed: &[FileRecord], skipped: &[FileRecord]) -> SummaryTotals {
    let mut summary = SummaryTotals {
        files_considered: (analyzed.len() + skipped.len()) as u64,
        files_analyzed: analyzed.len() as u64,
        files_skipped: skipped.len() as u64,
        ..Default::default()
    };

    for record in analyzed {
        summary.total_physical_lines += record.raw_line_categories.total_physical_lines;
        summary.code_lines += record.effective_counts.code_lines;
        summary.comment_lines += record.effective_counts.comment_lines;
        summary.blank_lines += record.effective_counts.blank_lines;
        summary.mixed_lines_separate += record.effective_counts.mixed_lines_separate;
        summary.functions += record.raw_line_categories.functions;
        summary.classes += record.raw_line_categories.classes;
        summary.variables += record.raw_line_categories.variables;
        summary.imports += record.raw_line_categories.imports;
        summary.test_count += record.raw_line_categories.test_count;
        summary.test_assertion_count += record.raw_line_categories.test_assertion_count;
        summary.test_suite_count += record.raw_line_categories.test_suite_count;
        if let Some(cov) = &record.coverage {
            summary.coverage_lines_found += u64::from(cov.lines_found);
            summary.coverage_lines_hit += u64::from(cov.lines_hit);
            summary.coverage_functions_found += u64::from(cov.functions_found);
            summary.coverage_functions_hit += u64::from(cov.functions_hit);
            summary.coverage_branches_found += u64::from(cov.branches_found);
            summary.coverage_branches_hit += u64::from(cov.branches_hit);
        }
    }

    summary
}

/// Construct a zero-filled `LanguageSummary` for the given language.
const fn zeroed_summary(language: Language) -> LanguageSummary {
    LanguageSummary {
        language,
        files: 0,
        total_physical_lines: 0,
        code_lines: 0,
        comment_lines: 0,
        blank_lines: 0,
        mixed_lines_separate: 0,
        functions: 0,
        classes: 0,
        variables: 0,
        imports: 0,
        test_count: 0,
        test_assertion_count: 0,
        test_suite_count: 0,
        coverage_lines_found: 0,
        coverage_lines_hit: 0,
        coverage_functions_found: 0,
        coverage_functions_hit: 0,
        coverage_branches_found: 0,
        coverage_branches_hit: 0,
    }
}

/// Accumulate all per-file counters from `record` into an existing `LanguageSummary`.
fn accumulate_record_into_summary(entry: &mut LanguageSummary, record: &FileRecord) {
    entry.files += 1;
    let r = &record.raw_line_categories;
    entry.total_physical_lines += r.total_physical_lines;
    entry.code_lines += record.effective_counts.code_lines;
    entry.comment_lines += record.effective_counts.comment_lines;
    entry.blank_lines += record.effective_counts.blank_lines;
    entry.mixed_lines_separate += record.effective_counts.mixed_lines_separate;
    entry.functions += r.functions;
    entry.classes += r.classes;
    entry.variables += r.variables;
    entry.imports += r.imports;
    entry.test_count += r.test_count;
    entry.test_assertion_count += r.test_assertion_count;
    entry.test_suite_count += r.test_suite_count;
    if let Some(cov) = &record.coverage {
        entry.coverage_lines_found += u64::from(cov.lines_found);
        entry.coverage_lines_hit += u64::from(cov.lines_hit);
        entry.coverage_functions_found += u64::from(cov.functions_found);
        entry.coverage_functions_hit += u64::from(cov.functions_hit);
        entry.coverage_branches_found += u64::from(cov.branches_found);
        entry.coverage_branches_hit += u64::from(cov.branches_hit);
    }
}

fn build_language_summaries(analyzed: &[FileRecord]) -> Vec<LanguageSummary> {
    let mut by_language: BTreeMap<Language, LanguageSummary> = BTreeMap::new();
    for record in analyzed {
        let Some(language) = record.language else {
            continue;
        };
        let entry = by_language
            .entry(language)
            .or_insert_with(|| zeroed_summary(language));
        accumulate_record_into_summary(entry, record);
    }
    by_language.into_values().collect()
}

fn skipped_record(
    path: &Path,
    root: &Path,
    size_bytes: u64,
    status: FileStatus,
    warnings: Vec<String>,
) -> FileRecord {
    FileRecord {
        path: path_to_string(path),
        relative_path: relative_path_string(path, root),
        language: None,
        size_bytes,
        detected_encoding: None,
        raw_line_categories: RawLineCounts::default(),
        effective_counts: EffectiveCounts::default(),
        status,
        warnings,
        generated: false,
        minified: false,
        vendor: false,
        parse_mode: None,
        submodule: None,
        coverage: None,
    }
}

fn relative_path_string(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn path_to_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

/// Parse `.gitmodules` in `root` and return `(name, relative_path)` for each submodule found.
#[must_use]
pub fn detect_submodules(root: &Path) -> Vec<(String, PathBuf)> {
    let gitmodules = root.join(".gitmodules");
    if !gitmodules.is_file() {
        return Vec::new();
    }
    let Ok(content) = fs::read_to_string(&gitmodules) else {
        return Vec::new();
    };

    let mut result = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_path: Option<PathBuf> = None;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("[submodule \"") && trimmed.ends_with("\"]") {
            if let (Some(name), Some(path)) = (current_name.take(), current_path.take()) {
                result.push((name, path));
            }
            let name = trimmed["[submodule \"".len()..trimmed.len() - 2].to_string();
            current_name = Some(name);
        } else if let Some(rest) = trimmed.strip_prefix("path") {
            if let Some(eq_pos) = rest.find('=') {
                let path_str = rest[eq_pos + 1..].trim();
                current_path = Some(PathBuf::from(path_str));
            }
        }
    }
    if let (Some(name), Some(path)) = (current_name, current_path) {
        result.push((name, path));
    }

    result
}

fn build_submodule_summaries(
    analyzed: &[FileRecord],
    submodules: &[(String, PathBuf)],
) -> Vec<SubmoduleSummary> {
    submodules
        .iter()
        .map(|(name, path)| {
            let files: Vec<&FileRecord> = analyzed
                .iter()
                .filter(|f| f.submodule.as_deref() == Some(name.as_str()))
                .collect();

            let files_analyzed = files.len() as u64;
            let total_physical_lines = files
                .iter()
                .map(|f| f.raw_line_categories.total_physical_lines)
                .sum();
            let code_lines = files.iter().map(|f| f.effective_counts.code_lines).sum();
            let comment_lines = files.iter().map(|f| f.effective_counts.comment_lines).sum();
            let blank_lines = files.iter().map(|f| f.effective_counts.blank_lines).sum();
            let language_summaries = build_language_summaries_from_slice(&files);

            SubmoduleSummary {
                name: name.clone(),
                relative_path: path.to_string_lossy().replace('\\', "/"),
                files_analyzed,
                total_physical_lines,
                code_lines,
                comment_lines,
                blank_lines,
                language_summaries,
            }
        })
        .filter(|s| s.files_analyzed > 0)
        .collect()
}

fn build_language_summaries_from_slice(files: &[&FileRecord]) -> Vec<LanguageSummary> {
    let mut map: BTreeMap<String, LanguageSummary> = BTreeMap::new();
    for file in files {
        let Some(lang) = file.language else { continue };
        let entry = map
            .entry(lang.display_name().to_string())
            .or_insert_with(|| zeroed_summary(lang));
        accumulate_record_into_summary(entry, file);
    }
    map.into_values().collect()
}

fn file_name_eq(path: &Path, expected: &str) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == expected)
}

fn is_excluded_dir_path(path: &Path, excluded_dirs: &[String]) -> bool {
    path.components().any(|component| {
        component
            .as_os_str()
            .to_str()
            .is_some_and(|part| excluded_dirs.iter().any(|excluded| excluded == part))
    })
}

fn is_vendor_path(path: &Path) -> bool {
    path.components().any(|component| {
        component
            .as_os_str()
            .to_str()
            .is_some_and(|part| matches!(part, "vendor" | "node_modules" | "packages"))
    })
}

fn is_known_lockfile(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            matches!(
                name,
                "Cargo.lock"
                    | "package-lock.json"
                    | "yarn.lock"
                    | "pnpm-lock.yaml"
                    | "Pipfile.lock"
                    | "poetry.lock"
                    | "composer.lock"
            )
        })
}

fn looks_generated(path: &Path, bytes: &[u8]) -> bool {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    if file_name.contains(".generated.") || file_name.contains(".g.") {
        return true;
    }

    let sample = String::from_utf8_lossy(&bytes[..bytes.len().min(GENERATED_SAMPLE_BYTES)])
        .to_ascii_lowercase();
    sample.contains("@generated") || sample.contains("generated by")
}

fn looks_minified(path: &Path, bytes: &[u8]) -> bool {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    if file_name.contains(".min.") {
        return true;
    }

    let sample = String::from_utf8_lossy(&bytes[..bytes.len().min(MINIFIED_SAMPLE_BYTES)]);
    let longest_line = sample.lines().map(str::len).max().unwrap_or(0);
    let whitespace = sample.chars().filter(|c| c.is_whitespace()).count();
    longest_line > MINIFIED_LINE_THRESHOLD && whitespace * 100 < sample.len().max(1)
}

fn is_binary(bytes: &[u8]) -> bool {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF])
        || bytes.starts_with(&[0xFF, 0xFE])
        || bytes.starts_with(&[0xFE, 0xFF])
    {
        return false;
    }

    let sample = &bytes[..bytes.len().min(BINARY_SAMPLE_BYTES)];
    sample.contains(&0)
}

/// Decode a BOM-stripped UTF-16 byte slice using the given encoding.
/// Returns `(text, encoding_label, warnings)`.
fn decode_utf16_bom(
    bom_stripped: &[u8],
    encoding: &'static encoding_rs::Encoding,
    label: &str,
) -> (String, String, Vec<String>) {
    let (cow, _, had_errors) = encoding.decode(bom_stripped);
    let mut warnings = Vec::new();
    if had_errors {
        warnings.push(format!("{label} decode contained replacement characters"));
    }
    (cow.into_owned(), label.into(), warnings)
}

fn decode_bytes(bytes: &[u8]) -> std::result::Result<(String, String, Vec<String>), String> {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        let text = String::from_utf8(bytes[3..].to_vec()).map_err(|err| err.to_string())?;
        return Ok((text, "utf-8-bom".into(), vec![]));
    }
    if bytes.starts_with(&[0xFF, 0xFE]) {
        return Ok(decode_utf16_bom(&bytes[2..], UTF_16LE, "utf-16le"));
    }
    if bytes.starts_with(&[0xFE, 0xFF]) {
        return Ok(decode_utf16_bom(&bytes[2..], UTF_16BE, "utf-16be"));
    }

    // Multiple statements in the else branch make map_or_else awkward here.
    #[allow(clippy::option_if_let_else)]
    if let Ok(text) = String::from_utf8(bytes.to_vec()) {
        Ok((text, "utf-8".into(), vec![]))
    } else {
        let (cow, _, had_errors) = WINDOWS_1252.decode(bytes);
        let mut warnings = vec!["decoded using windows-1252 fallback".into()];
        if had_errors {
            warnings.push("fallback decode contained replacement characters".into());
        }
        Ok((cow.into_owned(), "windows-1252".into(), warnings))
    }
}

fn compile_globset(patterns: &[String]) -> Result<Option<GlobSet>> {
    if patterns.is_empty() {
        return Ok(None);
    }

    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        builder
            .add(Glob::new(pattern).with_context(|| format!("invalid glob pattern: {pattern}"))?);
    }
    Ok(Some(
        builder.build().context("failed to compile glob filters")?,
    ))
}

fn parse_enabled_languages(enabled: &[String]) -> Result<Option<BTreeSet<Language>>> {
    if enabled.is_empty() {
        return Ok(None);
    }

    let supported = supported_languages();
    let mut set = BTreeSet::new();
    for name in enabled {
        let language = Language::from_name(name)
            .with_context(|| format!("unsupported language in config: {name}"))?;
        if !supported.contains(&language) {
            anyhow::bail!("language {name} is not supported in this build");
        }
        set.insert(language);
    }
    Ok(Some(set))
}

/// # Errors
///
/// Returns an error if serialization fails or the output file cannot be written.
pub fn write_json(run: &AnalysisRun, output_path: &Path) -> Result<()> {
    let json = serde_json::to_string_pretty(run).context("failed to serialize analysis run")?;
    fs::write(output_path, json)
        .with_context(|| format!("failed to write JSON output to {}", output_path.display()))
}

/// # Errors
///
/// Returns an error if the file cannot be read or the JSON cannot be parsed.
pub fn read_json(path: &Path) -> Result<AnalysisRun> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read result file {}", path.display()))?;
    serde_json::from_str(&contents)
        .with_context(|| format!("failed to parse JSON result {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_counts_respect_code_only_policy() {
        let raw = RawLineCounts {
            code_only_lines: 2,
            single_comment_only_lines: 1,
            mixed_code_single_comment_lines: 3,
            docstring_comment_lines: 2,
            ..RawLineCounts::default()
        };
        let counts = compute_effective_counts(&raw, MixedLinePolicy::CodeOnly, true, true);
        assert_eq!(counts.code_lines, 5);
        assert_eq!(counts.comment_lines, 3);
    }

    #[test]
    fn effective_counts_can_separate_mixed() {
        let raw = RawLineCounts {
            mixed_code_single_comment_lines: 2,
            mixed_code_multi_comment_lines: 1,
            ..RawLineCounts::default()
        };
        let counts =
            compute_effective_counts(&raw, MixedLinePolicy::SeparateMixedCategory, true, true);
        assert_eq!(counts.mixed_lines_separate, 3);
        assert_eq!(counts.code_lines, 0);
        assert_eq!(counts.comment_lines, 0);
    }

    #[test]
    fn windows_1252_fallback_decodes() {
        let bytes = vec![0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x96, 0x57];
        let (text, encoding, warnings) = decode_bytes(&bytes).unwrap();
        assert_eq!(encoding, "windows-1252");
        assert!(text.contains('–'));
        assert!(!warnings.is_empty());
    }
}
