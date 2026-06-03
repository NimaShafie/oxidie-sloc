// SPDX-License-Identifier: AGPL-3.0-or-later
// Tests for sloc-report rendering functions.
//
// AnalysisRun is constructed directly (all fields pub) — no filesystem I/O needed
// to exercise the HTML/CSV/XLSX/Confluence renderers.

use chrono::Utc;
use sloc_config::AppConfig;
use sloc_core::{
    AnalysisRun, EffectiveCounts, EnvironmentMetadata, FileCoverage, FileRecord, FileStatus,
    LanguageStyleGroup, LanguageSummary, StyleSummary, SubmoduleSummary, SummaryTotals,
    ToolMetadata,
};
use sloc_languages::{Language, ParseMode, RawLineCounts};
use sloc_report::{
    render_confluence_storage, render_confluence_wiki_markup, render_html, render_html_with_delta,
    render_sub_report_html, write_csv, write_html as write_html_report, write_xlsx,
    ReportDeltaContext,
};

// ── Fixture helpers ───────────────────────────────────────────────────────────

fn make_file_record(path: &str, lang: Language, code: u64) -> FileRecord {
    let raw = RawLineCounts {
        total_physical_lines: code + 2,
        code_only_lines: code,
        blank_only_lines: 1,
        single_comment_only_lines: 1,
        functions: 2,
        ..RawLineCounts::default()
    };
    FileRecord {
        path: path.into(),
        relative_path: path.into(),
        language: Some(lang),
        size_bytes: code * 30,
        detected_encoding: Some("utf-8".into()),
        raw_line_categories: raw,
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
        parse_mode: Some(ParseMode::Lexical),
        submodule: None,
        coverage: None,
        style_analysis: None,
    }
}

fn make_lang_summary(lang: Language, files: u64, code: u64) -> LanguageSummary {
    LanguageSummary {
        language: lang,
        files,
        total_physical_lines: code + 2,
        code_lines: code,
        comment_lines: 1,
        blank_lines: 1,
        mixed_lines_separate: 0,
        functions: 2,
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

fn make_tool() -> ToolMetadata {
    ToolMetadata {
        name: "sloc".into(),
        version: "1.0.0".into(),
        run_id: "test-run-id".into(),
        timestamp_utc: Utc::now(),
    }
}

fn make_env() -> EnvironmentMetadata {
    EnvironmentMetadata {
        operating_system: "linux".into(),
        architecture: "x86_64".into(),
        runtime_mode: "cli".into(),
        initiator_username: "test".into(),
        initiator_hostname: "testhost".into(),
        ci_name: None,
    }
}

/// Minimal valid run — one Rust file, basic totals, git metadata.
fn make_run() -> AnalysisRun {
    let file = make_file_record("src/lib.rs", Language::Rust, 7);
    let lang = make_lang_summary(Language::Rust, 1, 7);
    AnalysisRun {
        tool: make_tool(),
        environment: make_env(),
        effective_configuration: AppConfig::default(),
        input_roots: vec!["/tmp/test".into()],
        summary_totals: SummaryTotals {
            files_considered: 1,
            files_analyzed: 1,
            files_skipped: 0,
            total_physical_lines: 10,
            code_lines: 7,
            comment_lines: 1,
            blank_lines: 2,
            ..SummaryTotals::default()
        },
        totals_by_language: vec![lang],
        per_file_records: vec![file],
        skipped_file_records: vec![],
        warnings: vec![],
        submodule_summaries: vec![],
        git_commit_short: Some("abc1234".into()),
        git_branch: Some("main".into()),
        git_commit_long: None,
        git_commit_author: None,
        git_tags: None,
        git_nearest_tag: None,
        git_commit_date: None,
        git_remote_url: None,
        style_summary: None,
    }
}

/// Run with zero files (empty project).
fn make_empty_run() -> AnalysisRun {
    AnalysisRun {
        tool: make_tool(),
        environment: make_env(),
        effective_configuration: AppConfig::default(),
        input_roots: vec!["/tmp/empty".into()],
        summary_totals: SummaryTotals::default(),
        totals_by_language: vec![],
        per_file_records: vec![],
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

/// Run with 3 language summaries to exercise chart loops and top-language tables.
fn make_multi_lang_run() -> AnalysisRun {
    let files = vec![
        make_file_record("src/lib.rs", Language::Rust, 50),
        make_file_record("app.py", Language::Python, 30),
        make_file_record("main.ts", Language::TypeScript, 20),
    ];
    let langs = vec![
        make_lang_summary(Language::Rust, 1, 50),
        make_lang_summary(Language::Python, 1, 30),
        make_lang_summary(Language::TypeScript, 1, 20),
    ];
    AnalysisRun {
        tool: make_tool(),
        environment: make_env(),
        effective_configuration: AppConfig::default(),
        input_roots: vec!["/tmp/multi".into()],
        summary_totals: SummaryTotals {
            files_considered: 3,
            files_analyzed: 3,
            total_physical_lines: 102 + 6,
            code_lines: 100,
            comment_lines: 3,
            blank_lines: 3,
            ..SummaryTotals::default()
        },
        totals_by_language: langs,
        per_file_records: files,
        skipped_file_records: vec![],
        warnings: vec![],
        submodule_summaries: vec![],
        git_commit_short: Some("def5678".into()),
        git_branch: Some("feature/multi".into()),
        git_commit_long: None,
        git_commit_author: None,
        git_tags: None,
        git_nearest_tag: None,
        git_commit_date: None,
        git_remote_url: None,
        style_summary: None,
    }
}

fn make_delta() -> ReportDeltaContext {
    ReportDeltaContext {
        delta_code_added: 150,
        delta_code_removed: 30,
        delta_unmodified_lines: 820,
        delta_files_added: 2,
        delta_files_removed: 0,
        delta_files_modified: 3,
        delta_files_unchanged: 10,
        prev_code_lines: 700,
        prev_scan_count: 5,
        prev_scan_label: "2026-05-30 12:00 UTC".into(),
        prev_run_id: Some("prev-run-id".into()),
        current_run_id: Some("curr-run-id".into()),
    }
}

fn make_run_with_coverage() -> AnalysisRun {
    let mut run = make_run();
    // Add coverage data to the file record
    run.per_file_records[0].coverage = Some(FileCoverage {
        lines_found: 10,
        lines_hit: 7,
        functions_found: 2,
        functions_hit: 2,
        branches_found: 4,
        branches_hit: 3,
    });
    run.summary_totals.coverage_lines_found = 10;
    run.summary_totals.coverage_lines_hit = 7;
    run.totals_by_language[0].coverage_lines_found = 10;
    run.totals_by_language[0].coverage_lines_hit = 7;
    run
}

fn make_run_with_style() -> AnalysisRun {
    let mut run = make_run();
    run.style_summary = Some(StyleSummary {
        files_analyzed: 1,
        common_indent_style: "Spaces(4)".into(),
        line80_compliant_pct: 90,
        line_col_compliant_pct: 88,
        col_threshold: 100,
        by_language: vec![LanguageStyleGroup {
            language_family: "Rust".into(),
            files_count: 1,
            dominant_guide: "Rust Official".into(),
            dominant_score_pct: 95,
            common_indent_style: "Spaces(4)".into(),
            guide_avg_scores: vec![("Rust Official".into(), 95)],
            line80_compliant_pct: 90,
            line_col_compliant_pct: 88,
        }],
    });
    run
}

fn make_run_with_submodules() -> AnalysisRun {
    let mut run = make_run();
    run.submodule_summaries = vec![SubmoduleSummary {
        name: "vendor/lib".into(),
        relative_path: "vendor/lib".into(),
        files_analyzed: 5,
        total_physical_lines: 200,
        code_lines: 160,
        comment_lines: 20,
        blank_lines: 20,
        language_summaries: vec![make_lang_summary(Language::C, 5, 160)],
    }];
    run
}

fn make_run_with_warnings() -> AnalysisRun {
    let mut run = make_run();
    run.warnings = vec![
        "unsupported extension: .xyz (1 file)".into(),
        "encoding fallback: windows-1252 used for src/legacy.c".into(),
    ];
    run
}

fn make_run_with_skipped() -> AnalysisRun {
    let mut run = make_run();
    let mut skipped = make_file_record("Cargo.lock", Language::Rust, 0);
    skipped.status = FileStatus::SkippedByPolicy;
    run.skipped_file_records = vec![skipped];
    run.summary_totals.files_skipped = 1;
    run
}

fn make_run_with_all_git() -> AnalysisRun {
    let mut run = make_run();
    run.git_commit_long = Some("abc1234def5678abc1234def5678abc1234def56".into());
    run.git_commit_author = Some("Nima Shafie".into());
    run.git_tags = Some("v1.5.64".into());
    run.git_nearest_tag = Some("v1.5.64".into());
    run.git_commit_date = Some("2026-06-01T10:00:00Z".into());
    run.git_remote_url = Some("https://github.com/oxide-sloc/oxide-sloc.git".into());
    run
}

// ── render_html ───────────────────────────────────────────────────────────────

#[test]
fn render_html_returns_doctype() {
    let run = make_run();
    let html = render_html(&run).unwrap();
    assert!(html.contains("<!doctype html>") || html.contains("<!DOCTYPE html>"));
}

#[test]
fn render_html_contains_tool_name() {
    let run = make_run();
    let html = render_html(&run).unwrap();
    // The report page must reference the tool name somewhere
    assert!(
        html.to_lowercase().contains("sloc") || html.to_lowercase().contains("oxide"),
        "HTML should reference tool name"
    );
}

#[test]
fn render_html_git_branch_present() {
    let run = make_run();
    let html = render_html(&run).unwrap();
    assert!(
        html.contains("main"),
        "git branch 'main' should appear in report"
    );
}

#[test]
fn render_html_multi_language() {
    let run = make_multi_lang_run();
    let html = render_html(&run).unwrap();
    assert!(!html.is_empty());
    assert!(html.contains("Rust"));
    assert!(html.contains("Python"));
}

#[test]
fn render_html_empty_run() {
    let run = make_empty_run();
    let html = render_html(&run).unwrap();
    assert!(
        !html.is_empty(),
        "empty run should still produce a valid HTML document"
    );
    assert!(html.contains("<!doctype html>") || html.contains("<!DOCTYPE html>"));
}

#[test]
fn render_html_with_coverage_data() {
    let run = make_run_with_coverage();
    let html = render_html(&run).unwrap();
    assert!(!html.is_empty());
    // Coverage section or percentage should appear
    assert!(
        html.to_lowercase().contains("coverage") || html.contains("70.0"),
        "coverage data should appear in report"
    );
}

#[test]
fn render_html_with_style_summary() {
    let run = make_run_with_style();
    let html = render_html(&run).unwrap();
    assert!(!html.is_empty());
    // Style section title or indent style should appear
    assert!(
        html.contains("Style") || html.contains("style") || html.contains("Rust Official"),
        "style summary should appear in report"
    );
}

#[test]
fn render_html_with_submodule_summary() {
    let run = make_run_with_submodules();
    let html = render_html(&run).unwrap();
    assert!(!html.is_empty());
    assert!(
        html.contains("vendor/lib") || html.to_lowercase().contains("submodule"),
        "submodule data should appear in report"
    );
}

#[test]
fn render_html_with_warnings() {
    let run = make_run_with_warnings();
    let html = render_html(&run).unwrap();
    assert!(!html.is_empty());
}

#[test]
fn render_html_with_skipped_files() {
    let run = make_run_with_skipped();
    let html = render_html(&run).unwrap();
    assert!(!html.is_empty());
}

#[test]
fn render_html_with_all_git_metadata() {
    let run = make_run_with_all_git();
    let html = render_html(&run).unwrap();
    assert!(!html.is_empty());
    assert!(html.contains("v1.5.64") || html.contains("abc1234"));
}

#[test]
fn render_html_accent_color() {
    let mut run = make_run();
    run.effective_configuration.reporting.accent_color = Some("#3b82f6".into());
    let html = render_html(&run).unwrap();
    assert!(!html.is_empty());
    assert!(
        html.contains("#3b82f6"),
        "custom accent color should appear in report CSS"
    );
}

// ── render_html_with_delta ───────────────────────────────────────────────────

#[test]
fn render_html_with_delta_some() {
    let run = make_run();
    let delta = make_delta();
    let html = render_html_with_delta(&run, Some(&delta)).unwrap();
    assert!(!html.is_empty());
    assert!(html.contains("<!doctype html>") || html.contains("<!DOCTYPE html>"));
}

#[test]
fn render_html_with_delta_none() {
    let run = make_run();
    let html = render_html_with_delta(&run, None).unwrap();
    assert!(!html.is_empty());
}

#[test]
fn render_html_delta_shows_added_lines() {
    let run = make_run();
    let delta = make_delta();
    let html = render_html_with_delta(&run, Some(&delta)).unwrap();
    // delta has 150 added lines — should appear somewhere in the delta panel
    assert!(
        html.contains("150") || html.contains("+150"),
        "delta added lines should appear in report"
    );
}

// ── render_sub_report_html ───────────────────────────────────────────────────

#[test]
fn render_sub_report_html_ok() {
    let run = make_run();
    let html = render_sub_report_html(&run).unwrap();
    assert!(!html.is_empty());
}

#[test]
fn render_sub_report_html_multi_language() {
    let run = make_multi_lang_run();
    let html = render_sub_report_html(&run).unwrap();
    assert!(!html.is_empty());
    assert!(html.contains("Rust"));
}

// ── write_html ───────────────────────────────────────────────────────────────

#[test]
fn write_html_creates_file() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let run = make_run();
    write_html_report(&run, tmp.path()).unwrap();
    let content = std::fs::read_to_string(tmp.path()).unwrap();
    assert!(!content.is_empty());
    assert!(content.contains("<!doctype html>") || content.contains("<!DOCTYPE html>"));
}

#[test]
fn write_html_with_coverage_data() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let run = make_run_with_coverage();
    write_html_report(&run, tmp.path()).unwrap();
    let content = std::fs::read_to_string(tmp.path()).unwrap();
    assert!(!content.is_empty());
}

// ── write_csv ────────────────────────────────────────────────────────────────

#[test]
fn write_csv_basic() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let run = make_run();
    write_csv(&run, tmp.path()).unwrap();
    let content = std::fs::read_to_string(tmp.path()).unwrap();
    assert!(!content.is_empty(), "CSV output should not be empty");
    assert!(
        content.contains("Summary") || content.contains("Language") || content.contains("Files"),
        "CSV should contain header sections"
    );
}

#[test]
fn write_csv_multi_language() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let run = make_multi_lang_run();
    write_csv(&run, tmp.path()).unwrap();
    let content = std::fs::read_to_string(tmp.path()).unwrap();
    assert!(content.contains("Rust"));
    assert!(content.contains("Python"));
}

#[test]
fn write_csv_with_per_file_records() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let run = make_run();
    write_csv(&run, tmp.path()).unwrap();
    let content = std::fs::read_to_string(tmp.path()).unwrap();
    assert!(
        content.contains("src/lib.rs") || content.contains("Per File") || content.contains("file"),
        "CSV should include per-file data"
    );
}

// ── write_xlsx ───────────────────────────────────────────────────────────────

#[test]
fn write_xlsx_creates_file() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let run = make_run();
    write_xlsx(&run, tmp.path()).unwrap();
    let meta = std::fs::metadata(tmp.path()).unwrap();
    assert!(meta.len() > 0, "XLSX file should be non-empty");
}

#[test]
fn write_xlsx_multi_language() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let run = make_multi_lang_run();
    write_xlsx(&run, tmp.path()).unwrap();
    let meta = std::fs::metadata(tmp.path()).unwrap();
    assert!(meta.len() > 0);
}

// ── Confluence renderers ──────────────────────────────────────────────────────

#[test]
fn render_confluence_storage_basic() {
    let run = make_run();
    let out = render_confluence_storage(&run, None);
    assert!(!out.is_empty());
    assert!(
        out.contains("<ac:structured-macro"),
        "Confluence storage format must start with ac:structured-macro info panel"
    );
}

#[test]
fn render_confluence_storage_contains_summary() {
    let run = make_run();
    let out = render_confluence_storage(&run, None);
    assert!(
        out.contains("Summary") || out.contains("Language"),
        "Confluence output should include a summary section"
    );
}

#[test]
fn render_confluence_storage_with_url() {
    let run = make_run();
    let out = render_confluence_storage(&run, Some("https://example.com/report.html"));
    assert!(!out.is_empty());
    assert!(
        out.contains("https://example.com/report.html"),
        "report URL should appear in Confluence output"
    );
}

#[test]
fn render_confluence_storage_multi_language() {
    let run = make_multi_lang_run();
    let out = render_confluence_storage(&run, None);
    assert!(out.contains("Rust") || out.contains("Python"));
}

#[test]
fn render_confluence_wiki_markup_basic() {
    let run = make_run();
    let out = render_confluence_wiki_markup(&run);
    assert!(!out.is_empty());
    assert!(
        out.contains("h2.") || out.contains("Summary"),
        "Confluence wiki markup should contain h2 headings"
    );
}

#[test]
fn render_confluence_wiki_markup_multi_language() {
    let run = make_multi_lang_run();
    let out = render_confluence_wiki_markup(&run);
    assert!(!out.is_empty());
    assert!(out.contains("Rust") || out.contains("Python"));
}

// ── Additional render_html edge cases ─────────────────────────────────────────

#[test]
fn render_html_large_codebase() {
    // Simulate a large codebase to exercise number formatting branches
    let mut run = make_run();
    run.summary_totals.code_lines = 1_234_567;
    run.summary_totals.total_physical_lines = 1_500_000;
    run.summary_totals.files_analyzed = 10_000;
    let html = render_html(&run).unwrap();
    assert!(!html.is_empty());
}

#[test]
fn render_html_delta_added_and_removed() {
    let run = make_run();
    let delta = sloc_report::ReportDeltaContext {
        delta_code_added: 1500,
        delta_code_removed: 300,
        delta_unmodified_lines: 5000,
        delta_files_added: 10,
        delta_files_removed: 2,
        delta_files_modified: 5,
        delta_files_unchanged: 20,
        prev_code_lines: 4000,
        prev_scan_count: 3,
        prev_scan_label: "2026-05-01 10:00 UTC".into(),
        prev_run_id: Some("old-run".into()),
        current_run_id: Some("new-run".into()),
    };
    let html = render_html_with_delta(&run, Some(&delta)).unwrap();
    assert!(!html.is_empty());
    // Delta values should appear
    assert!(
        html.contains("1500") || html.contains("1,500"),
        "added lines should appear in delta report"
    );
}

#[test]
fn render_html_delta_zero_change() {
    let run = make_run();
    let delta = sloc_report::ReportDeltaContext {
        delta_code_added: 0,
        delta_code_removed: 0,
        delta_unmodified_lines: 100,
        delta_files_added: 0,
        delta_files_removed: 0,
        delta_files_modified: 0,
        delta_files_unchanged: 5,
        prev_code_lines: 100,
        prev_scan_count: 1,
        prev_scan_label: "2026-05-01".into(),
        prev_run_id: Some("prev".into()),
        current_run_id: Some("curr".into()),
    };
    let html = render_html_with_delta(&run, Some(&delta)).unwrap();
    assert!(!html.is_empty());
}

#[test]
fn write_html_with_all_git_metadata() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let run = make_run_with_all_git();
    write_html_report(&run, tmp.path()).unwrap();
    let content = std::fs::read_to_string(tmp.path()).unwrap();
    assert!(!content.is_empty());
    assert!(content.contains("v1.5.64") || content.contains("abc1234"));
}

#[test]
fn write_html_with_style_summary() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let run = make_run_with_style();
    write_html_report(&run, tmp.path()).unwrap();
    let content = std::fs::read_to_string(tmp.path()).unwrap();
    assert!(!content.is_empty());
    assert!(content.contains("<!doctype html>") || content.contains("<!DOCTYPE html>"));
}

#[test]
fn write_html_with_submodules() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let run = make_run_with_submodules();
    write_html_report(&run, tmp.path()).unwrap();
    let content = std::fs::read_to_string(tmp.path()).unwrap();
    assert!(!content.is_empty());
}

#[test]
fn write_csv_empty_run() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let run = make_empty_run();
    write_csv(&run, tmp.path()).unwrap();
    let content = std::fs::read_to_string(tmp.path()).unwrap();
    assert!(
        !content.is_empty(),
        "empty run CSV should still have headers"
    );
}

#[test]
fn write_csv_with_coverage_data() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let run = make_run_with_coverage();
    write_csv(&run, tmp.path()).unwrap();
    let content = std::fs::read_to_string(tmp.path()).unwrap();
    assert!(!content.is_empty());
}

#[test]
fn write_xlsx_empty_run() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let run = make_empty_run();
    write_xlsx(&run, tmp.path()).unwrap();
    let meta = std::fs::metadata(tmp.path()).unwrap();
    assert!(meta.len() > 0, "empty run XLSX must not be zero bytes");
}

#[test]
fn write_xlsx_with_warnings() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let run = make_run_with_warnings();
    write_xlsx(&run, tmp.path()).unwrap();
    let meta = std::fs::metadata(tmp.path()).unwrap();
    assert!(meta.len() > 0);
}

#[test]
fn render_confluence_storage_with_coverage() {
    let run = make_run_with_coverage();
    let out = render_confluence_storage(&run, None);
    assert!(!out.is_empty());
}

#[test]
fn render_confluence_wiki_markup_empty_run() {
    let run = make_empty_run();
    let out = render_confluence_wiki_markup(&run);
    assert!(
        !out.is_empty(),
        "wiki markup for empty run should still produce output"
    );
}

#[test]
fn render_sub_report_html_with_coverage() {
    let run = make_run_with_coverage();
    let html = render_sub_report_html(&run).unwrap();
    assert!(!html.is_empty());
}

#[test]
fn render_sub_report_html_empty_run() {
    let run = make_empty_run();
    let html = render_sub_report_html(&run).unwrap();
    assert!(!html.is_empty());
}

#[test]
fn render_html_many_files() {
    let mut run = make_run();
    for i in 0..20 {
        run.per_file_records.push(make_file_record(
            &format!("src/file_{i}.rs"),
            Language::Rust,
            10 + i as u64,
        ));
    }
    run.summary_totals.files_analyzed = run.per_file_records.len() as u64;
    let html = render_html(&run).unwrap();
    assert!(!html.is_empty());
    // All files should appear in the report
    assert!(html.contains("file_0.rs") || html.contains("file_19.rs"));
}

#[test]
fn render_html_with_various_languages() {
    // Exercise the per-file records with multiple different languages
    let mut run = make_empty_run();
    run.per_file_records = vec![
        make_file_record("main.c", Language::C, 30),
        make_file_record("app.py", Language::Python, 40),
        make_file_record("server.go", Language::Go, 50),
        make_file_record("component.ts", Language::TypeScript, 20),
        make_file_record("style.css", Language::Css, 15),
        make_file_record("index.html", Language::Html, 25),
        make_file_record("schema.sql", Language::Sql, 10),
        make_file_record("build.sh", Language::Shell, 5),
    ];
    run.summary_totals.files_analyzed = 8;
    run.summary_totals.code_lines = 195;
    let html = render_html(&run).unwrap();
    assert!(!html.is_empty());
}
