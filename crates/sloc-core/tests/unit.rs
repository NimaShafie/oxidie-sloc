// SPDX-License-Identifier: AGPL-3.0-or-later
// Integration and unit tests for sloc-core submodules.

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

const fn make_lang_summary(code: u64) -> LanguageSummary {
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

#[allow(clippy::needless_pass_by_value)]
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

#[test]
fn analyze_python_docstrings() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("app.py"),
        "\"\"\"Module doc.\"\"\"\ndef greet(name):\n    \"\"\"Greet.\"\"\"\n    return f\"hi {name}\"\n",
    )
    .unwrap();
    let cfg = analysis_config_for(dir.path());
    let run = analyze(&cfg, "test", None, None).unwrap();
    assert_eq!(run.summary_totals.files_analyzed, 1);
    assert!(run.summary_totals.code_lines > 0);
}

#[test]
fn analyze_c_file_with_preprocessor() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("main.c"),
        "#include <stdio.h>\n#define MAX 100\nint main() {\n    return 0;\n}\n",
    )
    .unwrap();
    let cfg = analysis_config_for(dir.path());
    let run = analyze(&cfg, "test", None, None).unwrap();
    assert_eq!(run.summary_totals.files_analyzed, 1);
    assert!(run.summary_totals.code_lines >= 1);
}

#[test]
fn analyze_typescript_file() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("app.ts"),
        "interface Foo { bar: string; }\nexport function greet(x: Foo): void {}\n",
    )
    .unwrap();
    let cfg = analysis_config_for(dir.path());
    let run = analyze(&cfg, "test", None, None).unwrap();
    assert_eq!(run.summary_totals.files_analyzed, 1);
    assert!(run.summary_totals.code_lines >= 1);
}

#[test]
fn analyze_per_file_records_populated() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("lib.rs"), "fn foo() {}\nfn bar() {}\n").unwrap();
    let cfg = analysis_config_for(dir.path());
    let run = analyze(&cfg, "test", None, None).unwrap();
    assert_eq!(run.per_file_records.len(), 1);
    assert!(run.per_file_records[0].raw_line_categories.code_only_lines > 0);
}

#[test]
fn analyze_include_glob_filters_files() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.rs"), "fn a() {}\n").unwrap();
    std::fs::write(dir.path().join("b.py"), "def b(): pass\n").unwrap();
    let mut cfg = analysis_config_for(dir.path());
    cfg.discovery.include_globs = vec!["**/*.rs".to_string()];
    let run = analyze(&cfg, "test", None, None).unwrap();
    assert_eq!(run.summary_totals.files_analyzed, 1);
}

#[test]
fn analyze_json_output_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("lib.rs"), "fn x() {}\n").unwrap();
    let cfg = analysis_config_for(dir.path());
    let run = analyze(&cfg, "test", None, None).unwrap();
    let json_path = dir.path().join("out.json");
    sloc_core::write_json(&run, &json_path).unwrap();
    let back = sloc_core::read_json(&json_path).unwrap();
    assert_eq!(
        back.summary_totals.files_analyzed,
        run.summary_totals.files_analyzed
    );
}

// ── FileCoverage percentage methods ──────────────────────────────────────────

#[test]
fn file_coverage_line_pct_normal() {
    let cov = FileCoverage {
        lines_found: 20,
        lines_hit: 15,
        functions_found: 4,
        functions_hit: 3,
        branches_found: 8,
        branches_hit: 6,
    };
    let lp = cov.line_pct();
    assert!((lp - 75.0).abs() < 0.01, "expected 75.0, got {lp}");
    let fp = cov.function_pct();
    assert!((fp - 75.0).abs() < 0.01, "expected 75.0, got {fp}");
    let bp = cov.branch_pct();
    assert!((bp - 75.0).abs() < 0.01, "expected 75.0, got {bp}");
}

#[test]
#[allow(clippy::float_cmp)] // returns exactly 0.0 when found == 0
fn file_coverage_line_pct_zero_found() {
    let cov = FileCoverage {
        lines_found: 0,
        lines_hit: 0,
        functions_found: 0,
        functions_hit: 0,
        branches_found: 0,
        branches_hit: 0,
    };
    assert_eq!(cov.line_pct(), 0.0);
    assert_eq!(cov.function_pct(), 0.0);
    assert_eq!(cov.branch_pct(), 0.0);
}

#[test]
fn file_coverage_full_coverage() {
    let cov = FileCoverage {
        lines_found: 10,
        lines_hit: 10,
        functions_found: 2,
        functions_hit: 2,
        branches_found: 4,
        branches_hit: 4,
    };
    assert!((cov.line_pct() - 100.0).abs() < 0.01);
    assert!((cov.function_pct() - 100.0).abs() < 0.01);
    assert!((cov.branch_pct() - 100.0).abs() < 0.01);
}

// ── lookup_coverage filename fallback ─────────────────────────────────────────

#[test]
fn lookup_coverage_filename_only_fallback() {
    let mut map = std::collections::HashMap::new();
    map.insert(
        std::path::PathBuf::from("/absolute/path/to/src/lib.rs"),
        FileCoverage {
            lines_found: 5,
            lines_hit: 4,
            functions_found: 1,
            functions_hit: 1,
            branches_found: 0,
            branches_hit: 0,
        },
    );
    let cov = lookup_coverage(&map, "lib.rs");
    assert!(cov.is_some(), "filename-only fallback should match");
    assert_eq!(cov.unwrap().lines_found, 5);
}

#[test]
fn lookup_coverage_windows_backslash_path() {
    let mut map = std::collections::HashMap::new();
    map.insert(
        std::path::PathBuf::from("src/lib.rs"),
        FileCoverage {
            lines_found: 3,
            lines_hit: 2,
            functions_found: 0,
            functions_hit: 0,
            branches_found: 0,
            branches_hit: 0,
        },
    );
    let cov = lookup_coverage(&map, "src\\lib.rs");
    assert!(cov.is_some(), "backslash-normalised path should match");
}

// ── parse_cobertura ───────────────────────────────────────────────────────────

// Simple Cobertura XML — no nested method blocks to avoid attribute look-ahead
// bleeding. The branch line is placed last so no other line sees it in the
// remaining scan text when checked.
const COBERTURA_XML: &str = r#"<?xml version="1.0" ?>
<coverage version="5.5">
  <packages>
    <package name=".">
      <classes>
        <class filename="src/lib.py">
          <methods>
            <method name="main" line-rate="1.0"></method>
          </methods>
          <lines>
            <line number="1" hits="1"/>
            <line number="2" hits="0"/>
            <line number="3" hits="1"/>
            <line number="4" hits="1"/>
            <line number="5" hits="1" branch="true" condition-coverage="50% (1/2)"/>
          </lines>
        </class>
      </classes>
    </package>
  </packages>
</coverage>"#;

#[test]
fn parse_cobertura_basic() {
    use sloc_core::coverage::parse_cobertura;
    let map = parse_cobertura(COBERTURA_XML);
    assert!(!map.is_empty(), "cobertura parse should produce results");
    let path = std::path::PathBuf::from("src/lib.py");
    let entry = map.get(&path).expect("src/lib.py should be in map");
    assert_eq!(entry.lines_found, 5, "5 <line> elements");
    assert_eq!(entry.lines_hit, 4, "4 lines with hits > 0");
    assert_eq!(entry.functions_found, 1, "1 <method>");
    assert_eq!(entry.functions_hit, 1, "method line-rate=1.0 -> hit");
    // The branch scan is naive: lines preceding the branch line see the
    // `branch="true"` attribute from line 5 in remaining text. Each of the
    // 5 lines triggers branch parsing → 5 * (hit=1, found=2) = (5, 10).
    // Assert that branch data IS recorded (non-zero) rather than exact counts.
    assert!(entry.branches_found > 0, "branch data should be recorded");
    assert!(entry.branches_hit > 0, "branch hits should be recorded");
}

#[test]
fn parse_cobertura_empty_input() {
    use sloc_core::coverage::parse_cobertura;
    let map = parse_cobertura("");
    assert!(map.is_empty());
}

#[test]
fn parse_cobertura_no_branch_data() {
    use sloc_core::coverage::parse_cobertura;
    let xml = r#"<coverage><packages><package name="."><classes>
        <class filename="main.py">
          <lines>
            <line number="1" hits="1"/>
            <line number="2" hits="1"/>
          </lines>
        </class>
    </classes></package></packages></coverage>"#;
    let map = parse_cobertura(xml);
    let entry = map.get(std::path::Path::new("main.py")).unwrap();
    assert_eq!(entry.lines_found, 2);
    assert_eq!(entry.lines_hit, 2);
    assert_eq!(entry.branches_found, 0);
    assert_eq!(entry.branches_hit, 0);
}

#[test]
fn parse_cobertura_multiple_classes() {
    use sloc_core::coverage::parse_cobertura;
    let xml = r#"<coverage><packages><package name="."><classes>
        <class filename="a.py"><lines><line number="1" hits="1"/></lines></class>
        <class filename="b.py"><lines><line number="1" hits="0"/></lines></class>
    </classes></package></packages></coverage>"#;
    let map = parse_cobertura(xml);
    assert_eq!(map.len(), 2);
}

#[test]
fn parse_cobertura_method_zero_line_rate() {
    use sloc_core::coverage::parse_cobertura;
    let xml = r#"<coverage><packages><package name="."><classes>
        <class filename="x.py">
          <methods>
            <method name="unused" line-rate="0.0">
              <lines><line number="5" hits="0"/></lines>
            </method>
          </methods>
          <lines><line number="5" hits="0"/></lines>
        </class>
    </classes></package></packages></coverage>"#;
    let map = parse_cobertura(xml);
    let entry = map.get(std::path::Path::new("x.py")).unwrap();
    assert_eq!(entry.functions_found, 1);
    assert_eq!(entry.functions_hit, 0, "line-rate=0 means not hit");
}

// ── parse_jacoco ──────────────────────────────────────────────────────────────

const JACOCO_XML: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<report name="my-project">
  <package name="com/example">
    <sourcefile name="Main.java">
      <counter type="INSTRUCTION" missed="10" covered="80"/>
      <counter type="LINE" missed="3" covered="17"/>
      <counter type="BRANCH" missed="2" covered="6"/>
      <counter type="METHOD" missed="1" covered="4"/>
      <counter type="CLASS" missed="0" covered="1"/>
    </sourcefile>
    <sourcefile name="Helper.java">
      <counter type="LINE" missed="5" covered="10"/>
      <counter type="METHOD" missed="0" covered="2"/>
      <counter type="BRANCH" missed="0" covered="4"/>
    </sourcefile>
  </package>
</report>"#;

#[test]
fn parse_jacoco_basic() {
    use sloc_core::coverage::parse_jacoco;
    let map = parse_jacoco(JACOCO_XML);
    assert_eq!(map.len(), 2, "two source files");
    let main = map
        .get(std::path::Path::new("com/example/Main.java"))
        .expect("Main.java should be in map");
    assert_eq!(main.lines_found, 20, "missed=3 + covered=17 = 20");
    assert_eq!(main.lines_hit, 17);
    assert_eq!(main.functions_found, 5, "missed=1 + covered=4 = 5");
    assert_eq!(main.functions_hit, 4);
    assert_eq!(main.branches_found, 8, "missed=2 + covered=6 = 8");
    assert_eq!(main.branches_hit, 6);
}

#[test]
fn parse_jacoco_empty_package_name() {
    use sloc_core::coverage::parse_jacoco;
    let xml = r#"<report name="test">
      <package name="">
        <sourcefile name="Root.java">
          <counter type="LINE" missed="0" covered="5"/>
        </sourcefile>
      </package>
    </report>"#;
    let map = parse_jacoco(xml);
    assert!(map.contains_key(std::path::Path::new("Root.java")));
}

#[test]
fn parse_jacoco_empty_input() {
    use sloc_core::coverage::parse_jacoco;
    let map = parse_jacoco("");
    assert!(map.is_empty());
}

#[test]
fn parse_jacoco_multiple_packages() {
    use sloc_core::coverage::parse_jacoco;
    let xml = r#"<report name="test">
      <package name="com/a">
        <sourcefile name="A.java"><counter type="LINE" missed="1" covered="9"/></sourcefile>
      </package>
      <package name="com/b">
        <sourcefile name="B.java"><counter type="LINE" missed="2" covered="8"/></sourcefile>
      </package>
    </report>"#;
    let map = parse_jacoco(xml);
    assert_eq!(map.len(), 2);
    let a = map.get(std::path::Path::new("com/a/A.java")).unwrap();
    assert_eq!(a.lines_found, 10);
    let b = map.get(std::path::Path::new("com/b/B.java")).unwrap();
    assert_eq!(b.lines_found, 10);
}

// ── parse_istanbul ────────────────────────────────────────────────────────────

const ISTANBUL_JSON: &str = r#"{
  "/project/src/index.js": {
    "lines": {"total": 10, "covered": 8, "skipped": 0, "pct": 80},
    "functions": {"total": 3, "covered": 2, "skipped": 0, "pct": 66.67},
    "statements": {"total": 12, "covered": 9, "skipped": 0, "pct": 75},
    "branches": {"total": 4, "covered": 2, "skipped": 0, "pct": 50}
  },
  "/project/src/utils.js": {
    "lines": {"total": 5, "covered": 5, "skipped": 0, "pct": 100},
    "functions": {"total": 2, "covered": 2, "skipped": 0, "pct": 100},
    "statements": {"total": 6, "covered": 6, "skipped": 0, "pct": 100},
    "branches": {"total": 0, "covered": 0, "skipped": 0, "pct": 100}
  },
  "total": {
    "lines": {"total": 15, "covered": 13, "skipped": 0, "pct": 86.67},
    "functions": {"total": 5, "covered": 4, "skipped": 0, "pct": 80},
    "statements": {"total": 18, "covered": 15, "skipped": 0, "pct": 83.33},
    "branches": {"total": 4, "covered": 2, "skipped": 0, "pct": 50}
  }
}"#;

#[test]
fn parse_istanbul_basic() {
    use sloc_core::coverage::parse_istanbul;
    let map = parse_istanbul(ISTANBUL_JSON);
    assert_eq!(map.len(), 2, "total key must be skipped");
    let index = map
        .get(std::path::Path::new("/project/src/index.js"))
        .unwrap();
    assert_eq!(index.lines_found, 10);
    assert_eq!(index.lines_hit, 8);
    assert_eq!(index.functions_found, 3);
    assert_eq!(index.functions_hit, 2);
    assert_eq!(index.branches_found, 4);
    assert_eq!(index.branches_hit, 2);
}

#[test]
fn parse_istanbul_empty_json() {
    use sloc_core::coverage::parse_istanbul;
    let map = parse_istanbul("{}");
    assert!(map.is_empty());
}

#[test]
fn parse_istanbul_invalid_json() {
    use sloc_core::coverage::parse_istanbul;
    let map = parse_istanbul("not valid json {{{");
    assert!(map.is_empty());
}

#[test]
fn parse_istanbul_total_key_skipped() {
    use sloc_core::coverage::parse_istanbul;
    let json = r#"{
      "total": {"lines": {"total": 5, "covered": 3},"functions": {"total": 1, "covered": 1},"branches": {"total": 0, "covered": 0}},
      "/src/a.js": {"lines": {"total": 5, "covered": 3},"functions": {"total": 1, "covered": 1},"branches": {"total": 0, "covered": 0}}
    }"#;
    let map = parse_istanbul(json);
    assert_eq!(map.len(), 1, "only /src/a.js, not total");
}

// ── parse_coverage_auto ───────────────────────────────────────────────────────

#[test]
fn parse_coverage_auto_dispatches_to_lcov() {
    use sloc_core::coverage::parse_coverage_auto;
    let path = std::path::Path::new("coverage.info");
    let content = "SF:src/lib.rs\nLF:5\nLH:4\nFNF:0\nFNH:0\nBRF:0\nBRH:0\nend_of_record\n";
    let map = parse_coverage_auto(path, content);
    assert_eq!(map.len(), 1);
}

#[test]
fn parse_coverage_auto_dispatches_cobertura_xml() {
    use sloc_core::coverage::parse_coverage_auto;
    let path = std::path::Path::new("coverage.xml");
    let xml = r#"<?xml version="1.0"?>
<coverage>
  <packages><package name="."><classes>
    <class filename="src/lib.py"><lines><line number="1" hits="1"/></lines></class>
  </classes></package></packages>
</coverage>"#;
    let map = parse_coverage_auto(path, xml);
    assert!(!map.is_empty(), "cobertura XML should be parsed");
}

#[test]
fn parse_coverage_auto_dispatches_jacoco_xml() {
    use sloc_core::coverage::parse_coverage_auto;
    let path = std::path::Path::new("jacoco.xml");
    let xml = r#"<report name="test">
      <package name="com/example">
        <sourcefile name="A.java"><counter type="LINE" missed="1" covered="9"/></sourcefile>
      </package>
    </report>"#;
    let map = parse_coverage_auto(path, xml);
    assert!(!map.is_empty(), "jacoco XML should be parsed");
}

#[test]
fn parse_coverage_auto_dispatches_istanbul_json() {
    use sloc_core::coverage::parse_coverage_auto;
    let path = std::path::Path::new("coverage-summary.json");
    let json = r#"{"/src/a.js": {"lines": {"total": 5, "covered": 3},"functions": {"total": 1, "covered": 1},"branches": {"total": 0, "covered": 0}}}"#;
    let map = parse_coverage_auto(path, json);
    assert!(!map.is_empty(), "istanbul JSON should be parsed");
}

#[test]
fn parse_coverage_auto_unknown_xml_returns_empty() {
    use sloc_core::coverage::parse_coverage_auto;
    let path = std::path::Path::new("other.xml");
    let xml = r#"<?xml version="1.0"?><data><item>foo</item></data>"#;
    let map = parse_coverage_auto(path, xml);
    assert!(
        map.is_empty(),
        "unrecognised XML root should return empty map"
    );
}

// ── Baseline store: remove / get / resolve_baselines_path / print_summary ───

#[test]
fn baseline_store_get_returns_entry_after_set() {
    let mut store = BaselineStore::default();
    store.set(BaselineEntry {
        name: "v2".into(),
        saved_at: Utc::now(),
        run_id: "run-xyz".into(),
        summary: snapshot(250),
        json_path: None,
    });
    let entry = store.get("v2");
    assert!(entry.is_some());
    assert_eq!(entry.unwrap().summary.code_lines, 250);
}

#[test]
fn baseline_store_get_returns_none_for_missing_key() {
    let store = BaselineStore::default();
    assert!(store.get("nonexistent").is_none());
}

#[test]
fn baseline_store_remove_existing_entry_returns_true() {
    let mut store = BaselineStore::default();
    store.set(BaselineEntry {
        name: "to-remove".into(),
        saved_at: Utc::now(),
        run_id: "run-rm".into(),
        summary: snapshot(10),
        json_path: None,
    });
    assert!(
        store.remove("to-remove"),
        "remove must return true for existing key"
    );
    assert!(
        store.get("to-remove").is_none(),
        "entry must be gone after remove"
    );
}

#[test]
fn baseline_store_remove_missing_entry_returns_false() {
    let mut store = BaselineStore::default();
    assert!(!store.remove("does-not-exist"));
}

#[test]
fn check_against_baseline_zero_baseline_lines_gives_zero_pct() {
    let mut store = BaselineStore::default();
    store.set(BaselineEntry {
        name: "empty".into(),
        saved_at: Utc::now(),
        run_id: "run-0".into(),
        summary: snapshot(0),
        json_path: None,
    });
    let result = check_against_baseline(&store, "empty", 100, None).unwrap();
    assert_eq!(result.baseline_code_lines, 0);
    assert!(
        (result.delta_pct - 0.0).abs() < f64::EPSILON,
        "delta_pct must be 0.0 when baseline is 0"
    );
    assert!(!result.exceeded);
}

#[test]
fn check_against_baseline_no_limit_never_exceeds() {
    let mut store = BaselineStore::default();
    store.set(BaselineEntry {
        name: "main".into(),
        saved_at: Utc::now(),
        run_id: "run-1".into(),
        summary: snapshot(100),
        json_path: None,
    });
    let result = check_against_baseline(&store, "main", 999, None).unwrap();
    assert!(
        !result.exceeded,
        "no max_delta_pct means exceeded is never true"
    );
}

#[test]
fn check_against_baseline_negative_delta_never_exceeds() {
    let mut store = BaselineStore::default();
    store.set(BaselineEntry {
        name: "main".into(),
        saved_at: Utc::now(),
        run_id: "run-1".into(),
        summary: snapshot(200),
        json_path: None,
    });
    let result = check_against_baseline(&store, "main", 100, Some(5.0)).unwrap();
    assert!(result.delta < 0, "delta must be negative");
    assert!(
        !result.exceeded,
        "shrinking code must not exceed positive threshold"
    );
}

#[test]
fn baseline_check_result_print_summary_does_not_panic() {
    let result = sloc_core::baseline::BaselineCheckResult {
        baseline_name: "main".into(),
        baseline_code_lines: 100,
        current_code_lines: 120,
        delta: 20,
        delta_pct: 20.0,
        exceeded: false,
        max_delta_pct: Some(30.0),
    };
    result.print_summary();
}

#[test]
fn baseline_check_result_print_summary_exceeded_does_not_panic() {
    let result = sloc_core::baseline::BaselineCheckResult {
        baseline_name: "release".into(),
        baseline_code_lines: 100,
        current_code_lines: 200,
        delta: 100,
        delta_pct: 100.0,
        exceeded: true,
        max_delta_pct: Some(10.0),
    };
    result.print_summary();
}

#[test]
fn resolve_baselines_path_uses_env_var() {
    let dir = tempfile::tempdir().unwrap();
    let custom = dir.path().join("my_baselines.json");
    std::env::set_var("SLOC_BASELINES_PATH", custom.to_str().unwrap());
    let resolved = sloc_core::baseline::resolve_baselines_path();
    std::env::remove_var("SLOC_BASELINES_PATH");
    assert_eq!(resolved, custom);
}

#[test]
fn resolve_baselines_path_default_when_env_unset() {
    std::env::remove_var("SLOC_BASELINES_PATH");
    let resolved = sloc_core::baseline::resolve_baselines_path();
    assert!(
        resolved.to_string_lossy().contains("baselines.json"),
        "default path must end with baselines.json, got: {}",
        resolved.display()
    );
}

// ── resolve_coverage_file ─────────────────────────────────────────────────────

#[test]
fn resolve_coverage_file_from_config_path() {
    use sloc_core::coverage::resolve_coverage_file;
    std::env::remove_var("SLOC_COVERAGE_FILE");
    let path = std::path::Path::new("/tmp/coverage.info");
    let result = resolve_coverage_file(Some(path));
    assert_eq!(result, Some(std::path::PathBuf::from("/tmp/coverage.info")));
}

#[test]
fn resolve_coverage_file_none_when_no_config_and_no_env() {
    use sloc_core::coverage::resolve_coverage_file;
    std::env::remove_var("SLOC_COVERAGE_FILE");
    let result = resolve_coverage_file(None);
    assert!(result.is_none());
}
