// SPDX-License-Identifier: AGPL-3.0-or-later
// Integration and unit tests for sloc-core submodules.

use std::collections::BTreeMap;
use std::path::PathBuf;

use chrono::Utc;
use sloc_config::AppConfig;
use sloc_core::{
    aggregate_line_coverage, check_against_baseline, compute_delta, lookup_coverage, parse_lcov,
    BaselineEntry, BaselineStore, CleanupPolicyStore, EffectiveCounts, EnvironmentMetadata,
    FileRecord, FileStatus, LanguageSummary, RegistryEntry, ScanRegistry, ScanSummarySnapshot,
    SummaryTotals, ToolMetadata, WatchedDirsStore,
};
use sloc_core::{AnalysisRun, FileCoverage};
use sloc_languages::{Language, RawLineCounts};

// ── Test fixture helpers ──────────────────────────────────────────────────────

fn make_file_record(path: &str, code: u64) -> FileRecord {
    FileRecord {
        path: path.into(),
        relative_path: path.into(),
        language: Some(Language::Rust),
        size_bytes: code * 20,
        detected_encoding: Some("utf-8".into()),
        raw_line_categories: RawLineCounts {
            total_physical_lines: code + 2,
            code_only_lines: code,
            blank_only_lines: 1,
            single_comment_only_lines: 1,
            ..RawLineCounts::default()
        },
        effective_counts: EffectiveCounts {
            code_lines: code,
            comment_lines: 1,
            blank_lines: 1,
            mixed_lines_separate: 0,
        },
        status: FileStatus::AnalyzedExact,
        warnings: vec![],
        generated: false,
        minified: false,
        vendor: false,
        parse_mode: Some(sloc_languages::ParseMode::Lexical),
        submodule: None,
        coverage: None,
        style_analysis: None,
    }
}

fn make_lang_summary(code: u64) -> LanguageSummary {
    LanguageSummary {
        language: Language::Rust,
        files: 1,
        total_physical_lines: code + 2,
        code_lines: code,
        comment_lines: 1,
        blank_lines: 1,
        mixed_lines_separate: 0,
        functions: 1,
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

fn make_run_with_files(files: Vec<(&str, u64)>) -> AnalysisRun {
    let code_total: u64 = files.iter().map(|(_, c)| c).sum();
    let records: Vec<FileRecord> = files.iter().map(|(p, c)| make_file_record(p, *c)).collect();
    AnalysisRun {
        tool: ToolMetadata {
            name: "sloc".into(),
            version: "1.0.0".into(),
            run_id: uuid::Uuid::new_v4().to_string(),
            timestamp_utc: Utc::now(),
        },
        environment: EnvironmentMetadata {
            operating_system: "linux".into(),
            architecture: "x86_64".into(),
            runtime_mode: "test".into(),
            initiator_username: "test".into(),
            initiator_hostname: "host".into(),
            ci_name: None,
        },
        effective_configuration: AppConfig::default(),
        input_roots: vec!["/tmp/test".into()],
        summary_totals: SummaryTotals {
            files_analyzed: files.len() as u64,
            code_lines: code_total,
            ..SummaryTotals::default()
        },
        totals_by_language: if files.is_empty() {
            vec![]
        } else {
            vec![make_lang_summary(code_total)]
        },
        per_file_records: records,
        skipped_file_records: vec![],
        warnings: vec![],
        submodule_summaries: vec![],
        git_commit_short: None,
        git_branch: None,
        git_commit_long: None,
        git_commit_author: None,
        git_tags: None,
        git_nearest_tag: None,
        git_commit_date: None,
        git_remote_url: None,
        style_summary: None,
    }
}

fn snapshot(code: u64) -> ScanSummarySnapshot {
    ScanSummarySnapshot {
        files_analyzed: 1,
        code_lines: code,
        ..ScanSummarySnapshot::default()
    }
}

// ── LCOV parser ───────────────────────────────────────────────────────────────

const LCOV_SINGLE: &str = "\
SF:src/lib.rs
FN:1,main
FNDA:1,main
FNF:1
FNH:1
DA:1,1
DA:2,0
DA:3,1
LF:3
LH:2
BRF:0
BRH:0
end_of_record
";

const LCOV_TWO_FILES: &str = "\
SF:src/lib.rs
LF:5
LH:4
FNF:1
FNH:1
BRF:0
BRH:0
end_of_record
SF:src/main.rs
LF:3
LH:2
FNF:0
FNH:0
BRF:0
BRH:0
end_of_record
";

#[test]
fn parse_lcov_single_record() {
    let map = parse_lcov(LCOV_SINGLE);
    assert_eq!(map.len(), 1);
    let entry = map.get(std::path::Path::new("src/lib.rs")).unwrap();
    assert_eq!(entry.lines_found, 3);
    assert_eq!(entry.lines_hit, 2);
    assert_eq!(entry.functions_found, 1);
    assert_eq!(entry.functions_hit, 1);
}

#[test]
fn parse_lcov_empty_input() {
    let map = parse_lcov("");
    assert!(map.is_empty());
}

#[test]
fn parse_lcov_two_files() {
    let map = parse_lcov(LCOV_TWO_FILES);
    assert_eq!(map.len(), 2);
    assert!(map.contains_key(std::path::Path::new("src/lib.rs")));
    assert!(map.contains_key(std::path::Path::new("src/main.rs")));
}

#[test]
fn lookup_coverage_exact_match() {
    let map = parse_lcov(LCOV_SINGLE);
    let cov = lookup_coverage(&map, "src/lib.rs");
    assert!(cov.is_some());
    assert_eq!(cov.unwrap().lines_found, 3);
}

#[test]
fn lookup_coverage_suffix_match() {
    // LCOV may store absolute paths; lookup by relative suffix
    let mut map = std::collections::HashMap::new();
    map.insert(
        std::path::PathBuf::from("/home/user/project/src/lib.rs"),
        FileCoverage {
            lines_found: 10,
            lines_hit: 8,
            functions_found: 2,
            functions_hit: 2,
            branches_found: 0,
            branches_hit: 0,
        },
    );
    let cov = lookup_coverage(&map, "src/lib.rs");
    assert!(cov.is_some(), "suffix match should work");
    assert_eq!(cov.unwrap().lines_found, 10);
}

#[test]
fn lookup_coverage_no_match() {
    let map = parse_lcov(LCOV_SINGLE);
    let cov = lookup_coverage(&map, "nonexistent.rs");
    assert!(cov.is_none());
}

#[test]
fn aggregate_line_coverage_sums_records() {
    let cov_a = FileCoverage {
        lines_found: 10,
        lines_hit: 8,
        functions_found: 2,
        functions_hit: 2,
        branches_found: 0,
        branches_hit: 0,
    };
    let cov_b = FileCoverage {
        lines_found: 5,
        lines_hit: 3,
        functions_found: 1,
        functions_hit: 1,
        branches_found: 0,
        branches_hit: 0,
    };
    let refs: Vec<&FileCoverage> = vec![&cov_a, &cov_b];
    let pct = aggregate_line_coverage(&refs);
    // (8+3)/(10+5) = 73.3%
    assert!(pct.is_some());
    let pct = pct.unwrap();
    assert!((pct - 73.333).abs() < 0.5, "expected ~73.3%, got {pct}");
}

#[test]
fn aggregate_line_coverage_none_when_no_coverage() {
    let refs: Vec<&FileCoverage> = vec![];
    let pct = aggregate_line_coverage(&refs);
    assert!(pct.is_none());
}

// ── Delta ─────────────────────────────────────────────────────────────────────

#[test]
fn compute_delta_empty_vs_empty() {
    let base = make_run_with_files(vec![]);
    let current = make_run_with_files(vec![]);
    let cmp = compute_delta(&base, &current);
    assert_eq!(cmp.summary.code_lines_delta, 0);
    assert_eq!(cmp.summary.files_analyzed_delta, 0);
    assert!(cmp.file_deltas.is_empty());
}

#[test]
fn compute_delta_added_file() {
    let base = make_run_with_files(vec![]);
    let current = make_run_with_files(vec![("src/new.rs", 50)]);
    let cmp = compute_delta(&base, &current);
    assert_eq!(cmp.summary.code_lines_delta, 50);
    assert_eq!(cmp.summary.files_analyzed_delta, 1);
    assert_eq!(cmp.file_deltas.len(), 1);
    assert_eq!(
        cmp.file_deltas[0].status,
        sloc_core::FileChangeStatus::Added
    );
}

#[test]
fn compute_delta_removed_file() {
    let base = make_run_with_files(vec![("src/old.rs", 30)]);
    let current = make_run_with_files(vec![]);
    let cmp = compute_delta(&base, &current);
    assert_eq!(cmp.summary.code_lines_delta, -30);
    assert_eq!(
        cmp.file_deltas[0].status,
        sloc_core::FileChangeStatus::Removed
    );
}

#[test]
fn compute_delta_unchanged_file() {
    let base = make_run_with_files(vec![("src/lib.rs", 20)]);
    let current = make_run_with_files(vec![("src/lib.rs", 20)]);
    let cmp = compute_delta(&base, &current);
    assert_eq!(cmp.summary.code_lines_delta, 0);
    assert_eq!(
        cmp.file_deltas[0].status,
        sloc_core::FileChangeStatus::Unchanged
    );
}

#[test]
fn compute_delta_modified_file_grown() {
    let base = make_run_with_files(vec![("src/lib.rs", 20)]);
    let current = make_run_with_files(vec![("src/lib.rs", 35)]);
    let cmp = compute_delta(&base, &current);
    assert_eq!(cmp.summary.code_lines_delta, 15);
    assert_eq!(
        cmp.file_deltas[0].status,
        sloc_core::FileChangeStatus::Modified
    );
}

#[test]
fn compute_delta_modified_file_shrunk() {
    let base = make_run_with_files(vec![("src/lib.rs", 40)]);
    let current = make_run_with_files(vec![("src/lib.rs", 25)]);
    let cmp = compute_delta(&base, &current);
    assert_eq!(cmp.summary.code_lines_delta, -15);
}

// ── Baseline store ────────────────────────────────────────────────────────────

#[test]
fn baseline_store_empty_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("baselines.json");
    let store = BaselineStore::default();
    store.save(&path).unwrap();
    let loaded = BaselineStore::load(&path);
    assert!(loaded.baselines.is_empty());
}

#[test]
fn baseline_store_entry_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("baselines.json");
    let mut store = BaselineStore::default();
    store.set(BaselineEntry {
        name: "main".into(),
        saved_at: Utc::now(),
        run_id: "run-abc".into(),
        summary: snapshot(500),
        json_path: None,
    });
    store.save(&path).unwrap();
    let loaded = BaselineStore::load(&path);
    assert!(loaded.baselines.contains_key("main"));
    assert_eq!(loaded.baselines["main"].summary.code_lines, 500);
}

#[test]
fn baseline_store_load_missing_returns_default() {
    let store = BaselineStore::load(std::path::Path::new("/nonexistent/baselines.json"));
    assert!(store.baselines.is_empty());
}

#[test]
fn check_against_baseline_no_entries_errors() {
    let store = BaselineStore::default();
    let result = check_against_baseline(&store, "main", 100, None);
    assert!(result.is_err());
}

#[test]
fn check_against_baseline_under_budget() {
    let mut store = BaselineStore::default();
    store.set(BaselineEntry {
        name: "main".into(),
        saved_at: Utc::now(),
        run_id: "run-1".into(),
        summary: snapshot(100),
        json_path: None,
    });
    let result = check_against_baseline(&store, "main", 110, Some(20.0)).unwrap();
    assert!(!result.exceeded);
    assert_eq!(result.current_code_lines, 110);
}

#[test]
fn check_against_baseline_over_budget() {
    let mut store = BaselineStore::default();
    store.set(BaselineEntry {
        name: "main".into(),
        saved_at: Utc::now(),
        run_id: "run-1".into(),
        summary: snapshot(100),
        json_path: None,
    });
    // 50% growth exceeds 10% threshold
    let result = check_against_baseline(&store, "main", 150, Some(10.0)).unwrap();
    assert!(result.exceeded);
}

// ── ScanRegistry ──────────────────────────────────────────────────────────────

fn make_registry_entry(run_id: &str) -> RegistryEntry {
    RegistryEntry {
        run_id: run_id.into(),
        timestamp_utc: Utc::now(),
        project_label: "test".into(),
        input_roots: vec!["/tmp/test".into()],
        json_path: None,
        html_path: None,
        pdf_path: None,
        csv_path: None,
        xlsx_path: None,
        summary: snapshot(100),
        git_branch: None,
        git_commit: None,
        git_author: None,
        git_tags: None,
        git_nearest_tag: None,
        git_commit_date: None,
    }
}

#[test]
fn scan_registry_empty_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("registry.json");
    let registry = ScanRegistry::default();
    registry.save(&path).unwrap();
    let loaded = ScanRegistry::load(&path);
    assert!(loaded.entries.is_empty());
}

#[test]
fn scan_registry_add_and_load() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("registry.json");
    let mut registry = ScanRegistry::default();
    registry.add_entry(make_registry_entry("run-1"));
    registry.save(&path).unwrap();
    let loaded = ScanRegistry::load(&path);
    assert_eq!(loaded.entries.len(), 1);
    assert_eq!(loaded.entries[0].run_id, "run-1");
}

#[test]
fn scan_registry_deduplicates_run_id() {
    let mut registry = ScanRegistry::default();
    registry.add_entry(make_registry_entry("run-1"));
    registry.add_entry(make_registry_entry("run-1")); // same run_id
    assert_eq!(registry.entries.len(), 1);
}

#[test]
fn scan_registry_find_by_run_id() {
    let mut registry = ScanRegistry::default();
    registry.add_entry(make_registry_entry("run-abc"));
    let found = registry.find_by_run_id("run-abc");
    assert!(found.is_some());
    let missing = registry.find_by_run_id("run-xyz");
    assert!(missing.is_none());
}

#[test]
fn scan_registry_load_missing_returns_default() {
    let reg = ScanRegistry::load(std::path::Path::new("/nonexistent/registry.json"));
    assert!(reg.entries.is_empty());
}

// ── CleanupPolicyStore ────────────────────────────────────────────────────────

#[test]
fn cleanup_policy_store_load_missing_returns_default() {
    let store = CleanupPolicyStore::load(std::path::Path::new("/nonexistent/cleanup.json"));
    assert!(store.policy.is_none());
    assert!(store.last_run_at.is_none());
}

// ── WatchedDirsStore ─────────────────────────────────────────────────────────

#[test]
fn watched_dirs_store_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("watched.json");
    let mut store = WatchedDirsStore::default();
    store.add(PathBuf::from("/tmp/project-a"));
    store.save(&path).unwrap();
    let loaded = WatchedDirsStore::load(&path);
    assert_eq!(loaded.dirs.len(), 1);
    assert_eq!(loaded.dirs[0], PathBuf::from("/tmp/project-a"));
}

#[test]
fn watched_dirs_no_duplicates() {
    let mut store = WatchedDirsStore::default();
    store.add(PathBuf::from("/tmp/project"));
    store.add(PathBuf::from("/tmp/project")); // duplicate
    assert_eq!(store.dirs.len(), 1);
}

// ── analyze() integration (tempfile) ─────────────────────────────────────────

use sloc_core::analyze;

fn analysis_config_for(dir: &std::path::Path) -> AppConfig {
    let mut cfg = AppConfig::default();
    cfg.discovery.root_paths = vec![dir.to_path_buf()];
    cfg
}

#[test]
fn analyze_single_rust_file() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("lib.rs"), "fn main() {}\n// comment\n").unwrap();
    let cfg = analysis_config_for(dir.path());
    let run = analyze(&cfg, "test", None, None).unwrap();
    assert_eq!(run.summary_totals.files_analyzed, 1);
    assert!(run.summary_totals.code_lines > 0);
}

#[test]
fn analyze_empty_directory() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = analysis_config_for(dir.path());
    let run = analyze(&cfg, "test", None, None).unwrap();
    assert_eq!(run.summary_totals.files_analyzed, 0);
    assert!(run.per_file_records.is_empty());
}

#[test]
fn analyze_skips_lockfile_by_default() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("Cargo.lock"),
        "[package]\nname = \"test\"\n",
    )
    .unwrap();
    let cfg = analysis_config_for(dir.path());
    let run = analyze(&cfg, "test", None, None).unwrap();
    assert_eq!(
        run.summary_totals.files_analyzed, 0,
        "Cargo.lock should be skipped"
    );
    assert_eq!(run.summary_totals.files_skipped, 1);
}

#[test]
fn analyze_skips_vendor_path() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("vendor")).unwrap();
    std::fs::write(dir.path().join("vendor").join("dep.rs"), "fn foo() {}").unwrap();
    let cfg = analysis_config_for(dir.path());
    let run = analyze(&cfg, "test", None, None).unwrap();
    assert_eq!(
        run.summary_totals.files_analyzed, 0,
        "vendor/ files should be skipped"
    );
}

#[test]
fn analyze_detects_binary_file() {
    let dir = tempfile::tempdir().unwrap();
    let mut data = b"hello world".to_vec();
    data.push(0x00);
    data.extend_from_slice(b" more data");
    std::fs::write(dir.path().join("binary.rs"), &data).unwrap();
    let cfg = analysis_config_for(dir.path());
    let run = analyze(&cfg, "test", None, None).unwrap();
    assert_eq!(
        run.summary_totals.files_analyzed, 0,
        "binary file should not be analyzed"
    );
    assert_eq!(run.summary_totals.files_skipped, 1);
}

#[test]
fn analyze_multiple_files() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.rs"), "fn a() {}\n").unwrap();
    std::fs::write(dir.path().join("b.rs"), "fn b() {}\nfn c() {}\n").unwrap();
    let cfg = analysis_config_for(dir.path());
    let run = analyze(&cfg, "test", None, None).unwrap();
    assert_eq!(run.summary_totals.files_analyzed, 2);
    assert!(run.summary_totals.code_lines >= 2);
}

#[test]
fn analyze_respects_max_file_size() {
    let dir = tempfile::tempdir().unwrap();
    let big_content = "x".repeat(200_000);
    std::fs::write(dir.path().join("big.rs"), &big_content).unwrap();
    let mut cfg = analysis_config_for(dir.path());
    cfg.discovery.max_file_size_bytes = 100;
    let run = analyze(&cfg, "test", None, None).unwrap();
    assert_eq!(
        run.summary_totals.files_analyzed, 0,
        "oversized file should be skipped"
    );
    assert_eq!(run.summary_totals.files_skipped, 1);
}
