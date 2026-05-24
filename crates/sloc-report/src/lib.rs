// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Nima Shafie <nimzshafie@gmail.com>
#![allow(clippy::multiple_crate_versions)]

use std::collections::BTreeMap;
use std::fmt::Write as FmtWrite;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use askama::Template;
use chrono::{DateTime, FixedOffset, Utc};
use sloc_core::{AnalysisRun, FileRecord, SummaryTotals};

// Embed logo images at compile time so every generated HTML report is fully
// self-contained.  Server-relative paths like /images/logo/... break when the
// HTML is rendered by Chrome via file:// (PDF export) or opened from disk.
static LOGO_TEXT_PNG: &[u8] = include_bytes!("../assets/logo/logo-text.png");
static SMALL_LOGO_PNG: &[u8] = include_bytes!("../assets/logo/small-logo.png");
static CHART_JS: &str = include_str!("../assets/chart.min.js");

fn png_data_uri(bytes: &[u8]) -> String {
    format!("data:image/png;base64,{}", base64_encode(bytes))
}

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = if chunk.len() > 1 {
            u32::from(chunk[1])
        } else {
            0
        };
        let b2 = if chunk.len() > 2 {
            u32::from(chunk[2])
        } else {
            0
        };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(CHARS[((n >> 18) & 63) as usize] as char);
        out.push(CHARS[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            CHARS[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            CHARS[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Render a full standalone HTML report for the given analysis run.
///
/// # Errors
///
/// Returns an error if template rendering or configuration serialization fails.
pub fn render_html(run: &AnalysisRun) -> Result<String> {
    render_html_inner(run, false)
}

/// Render an embedded sub-report HTML fragment for the given analysis run.
///
/// # Errors
///
/// Returns an error if template rendering or configuration serialization fails.
pub fn render_sub_report_html(run: &AnalysisRun) -> Result<String> {
    render_html_inner(run, true)
}

fn load_custom_logo(path: &std::path::Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let mime = if ext == "svg" {
        "image/svg+xml"
    } else {
        "image/png"
    };
    Some(format!("data:{mime};base64,{}", base64_encode(&bytes)))
}

// ── Chart JSON builders ───────────────────────────────────────────────────────

/// Escape a string for safe embedding inside a JSON string literal.
fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn build_lang_chart_json(run: &AnalysisRun) -> String {
    let entries: Vec<String> = run
        .totals_by_language
        .iter()
        .take(12)
        .map(|l| {
            format!(
                r#"{{"lang":"{}","code":{},"comments":{},"blanks":{},"functions":{},"classes":{},"variables":{},"imports":{},"tests":{},"files":{}}}"#,
                json_escape(l.language.display_name()),
                l.code_lines, l.comment_lines, l.blank_lines,
                l.functions, l.classes, l.variables, l.imports,
                l.test_count, l.files,
            )
        })
        .collect();
    format!("[{}]", entries.join(","))
}

fn build_submodule_chart_json(run: &AnalysisRun) -> String {
    let entries: Vec<String> = run
        .submodule_summaries
        .iter()
        .map(|s| {
            format!(
                r#"{{"name":"{}","path":"{}","code":{},"comment":{},"blank":{},"physical":{},"files":{}}}"#,
                json_escape(&s.name), json_escape(&s.relative_path),
                s.code_lines, s.comment_lines, s.blank_lines,
                s.total_physical_lines, s.files_analyzed,
            )
        })
        .collect();
    format!("[{}]", entries.join(","))
}

fn build_scatter_chart_json(run: &AnalysisRun) -> String {
    let entries: Vec<String> = run
        .totals_by_language
        .iter()
        .map(|l| {
            format!(
                r#"{{"lang":"{}","files":{},"code":{},"physical":{}}}"#,
                json_escape(l.language.display_name()),
                l.files,
                l.code_lines,
                l.total_physical_lines,
            )
        })
        .collect();
    format!("[{}]", entries.join(","))
}

fn build_semantic_chart_json(run: &AnalysisRun) -> String {
    let entries: Vec<String> = run
        .totals_by_language
        .iter()
        .filter(|l| l.functions > 0 || l.classes > 0 || l.variables > 0 || l.imports > 0 || l.test_count > 0)
        .map(|l| {
            format!(
                r#"{{"lang":"{}","functions":{},"classes":{},"variables":{},"imports":{},"tests":{}}}"#,
                json_escape(l.language.display_name()),
                l.functions, l.classes, l.variables, l.imports, l.test_count,
            )
        })
        .collect();
    format!("[{}]", entries.join(","))
}

fn build_file_size_histogram_json(run: &AnalysisRun) -> String {
    // Buckets: Tiny <50, Small 50-199, Medium 200-499, Large 500-999, Huge >=1000
    let labels = [
        ("Tiny (<50)", 0u64, 49u64),
        ("Small (50-199)", 50, 199),
        ("Medium (200-499)", 200, 499),
        ("Large (500-999)", 500, 999),
        ("Huge (>=1000)", 1000, u64::MAX),
    ];
    let mut counts = [0u64; 5];
    for f in &run.per_file_records {
        let cl = f.effective_counts.code_lines;
        for (i, &(_, lo, hi)) in labels.iter().enumerate() {
            if cl >= lo && cl <= hi {
                counts[i] += 1;
                break;
            }
        }
    }
    let entries: Vec<String> = labels
        .iter()
        .zip(counts.iter())
        .map(|((label, _, _), count)| {
            format!(r#"{{"label":"{}","count":{}}}"#, json_escape(label), count)
        })
        .collect();
    format!("[{}]", entries.join(","))
}

// ── Coverage / density helpers ────────────────────────────────────────────────

// ratio/percentage display, precision loss acceptable
#[allow(clippy::cast_precision_loss)]
fn coverage_pct_str(hit: u64, found: u64) -> String {
    if found > 0 {
        format!("{:.1}", hit as f64 / found as f64 * 100.0)
    } else {
        String::new()
    }
}

// ratio/percentage display, precision loss acceptable
#[allow(clippy::cast_precision_loss)]
fn coverage_class(hit: u64, found: u64) -> String {
    if found > 0 {
        let pct = hit as f64 / found as f64 * 100.0;
        if pct >= 80.0 {
            "good"
        } else if pct >= 60.0 {
            "warn"
        } else {
            "danger"
        }
    } else {
        "muted"
    }
    .to_string()
}

// ratio display, precision loss acceptable
#[allow(clippy::cast_precision_loss)]
fn format_test_density(code_lines: u64, test_count: u64) -> String {
    if code_lines > 0 && test_count > 0 {
        format!("{:.1}", test_count as f64 / code_lines as f64 * 1000.0)
    } else {
        String::from("0.0")
    }
}

// ── Main renderer ─────────────────────────────────────────────────────────────

#[allow(clippy::too_many_lines)] // large HTML renderer; splitting would obscure the template structure
fn render_html_inner(run: &AnalysisRun, is_sub_report: bool) -> Result<String> {
    let config_json = serde_json::to_string_pretty(&run.effective_configuration)
        .context("failed to serialize effective configuration")?;

    let warning_summary_rows = summarize_warnings(&run.warnings);
    let warning_opportunity_rows = build_support_opportunities(&run.warnings);

    let logo_text_uri = png_data_uri(LOGO_TEXT_PNG);
    let small_logo_uri = png_data_uri(SMALL_LOGO_PNG);

    let rep = &run.effective_configuration.reporting;
    let custom_logo_uri = rep.logo_path.as_deref().and_then(load_custom_logo);
    let company_name = rep.company_name.clone();
    let accent_hex = rep.accent_color.clone();
    let report_header_footer = rep.report_header_footer.clone();

    let totals = &run.summary_totals;

    let template = ReportTemplate {
        // Empty nonce for disk-saved reports; patch_html_nonce replaces it
        // with the request nonce when serving from the web server.
        nonce: String::new(),
        title: rep.report_title.clone(),
        browser_title: format!("Oxide-SLOC | {}", rep.report_title),
        scan_performed_by: format!(
            "{} / {}",
            run.environment.initiator_username, run.environment.initiator_hostname
        ),
        scan_time_pst: to_pst_display(run.tool.timestamp_utc),
        tool_version: run.tool.version.clone(),
        is_sub_report,
        run,
        language_rows: run
            .totals_by_language
            .iter()
            .map(|row| LanguageRow {
                language: row.language.display_name().to_string(),
                files: row.files,
                total_physical_lines: row.total_physical_lines,
                code_lines: row.code_lines,
                comment_lines: row.comment_lines,
                blank_lines: row.blank_lines,
                mixed_lines_separate: row.mixed_lines_separate,
                functions: row.functions,
                classes: row.classes,
                variables: row.variables,
                imports: row.imports,
                test_count: row.test_count,
                test_assertion_count: row.test_assertion_count,
                test_suite_count: row.test_suite_count,
                test_density_str: if row.code_lines > 0 {
                    // ratio display, precision loss acceptable
                    #[allow(clippy::cast_precision_loss)]
                    let density = row.test_count as f64 / row.code_lines as f64 * 1000.0;
                    format!("{density:.1}")
                } else {
                    "—".to_string()
                },
            })
            .collect(),
        file_rows: run.per_file_records.iter().map(file_row_view).collect(),
        skipped_rows: run.skipped_file_records.iter().map(file_row_view).collect(),
        config_json,
        lang_chart_json: build_lang_chart_json(run),
        submodule_chart_json: build_submodule_chart_json(run),
        scatter_chart_json: build_scatter_chart_json(run),
        semantic_chart_json: build_semantic_chart_json(run),
        file_size_histogram_json: build_file_size_histogram_json(run),
        has_submodule_data: !run.submodule_summaries.is_empty(),
        has_semantic_data: run
            .totals_by_language
            .iter()
            .any(|l| l.functions > 0 || l.classes > 0 || l.test_count > 0),
        has_coverage_data: run.per_file_records.iter().any(|f| f.coverage.is_some()),
        has_fn_coverage: totals.coverage_functions_found > 0,
        has_branch_coverage: totals.coverage_branches_found > 0,
        test_files_count: run
            .per_file_records
            .iter()
            .filter(|f| f.raw_line_categories.test_count > 0)
            .count() as u64,
        test_assertion_count: totals.test_assertion_count,
        test_suite_count: totals.test_suite_count,
        test_density: format_test_density(totals.code_lines, totals.test_count),
        most_tested_lang: run
            .totals_by_language
            .iter()
            .filter(|l| l.test_count > 0)
            .max_by_key(|l| l.test_count)
            .map_or_else(
                || "\u{2014}".to_string(),
                |l| l.language.display_name().to_string(),
            ),
        langs_with_tests: run
            .totals_by_language
            .iter()
            .filter(|l| l.test_count > 0)
            .count(),
        cov_line_pct: coverage_pct_str(totals.coverage_lines_hit, totals.coverage_lines_found),
        cov_fn_pct: coverage_pct_str(
            totals.coverage_functions_hit,
            totals.coverage_functions_found,
        ),
        cov_branch_pct: coverage_pct_str(
            totals.coverage_branches_hit,
            totals.coverage_branches_found,
        ),
        cov_line_class: coverage_class(totals.coverage_lines_hit, totals.coverage_lines_found),
        cov_fn_class: coverage_class(
            totals.coverage_functions_hit,
            totals.coverage_functions_found,
        ),
        cov_branch_class: coverage_class(
            totals.coverage_branches_hit,
            totals.coverage_branches_found,
        ),
        has_run_warnings: !run.warnings.is_empty(),
        warning_count: run.warnings.len(),
        warning_summary_rows,
        warning_opportunity_rows,
        warning_console_full: build_warning_console(&run.warnings),
        logo_text_uri,
        small_logo_uri,
        custom_logo_uri,
        company_name,
        accent_hex,
        report_header_footer,
        chart_js: CHART_JS,
        run_id_short: run
            .tool
            .run_id
            .split('-')
            .next_back()
            .unwrap_or(&run.tool.run_id)
            .chars()
            .take(7)
            .collect(),
    };

    template.render().context("failed to render HTML report")
}

/// Render an HTML report and write it to `output_path`.
///
/// # Errors
///
/// Returns an error if rendering fails or the file cannot be written.
pub fn write_html(run: &AnalysisRun, output_path: &Path) -> Result<()> {
    let html = render_html(run)?;
    fs::write(output_path, html)
        .with_context(|| format!("failed to write HTML report to {}", output_path.display()))
}

/// Use Chrome `DevTools` Protocol to render `html_path` as a PDF at `output_path`.
///
/// Launches a headless Chromium-based browser at A4-landscape viewport (1122 × 794 px),
/// waits up to 15 s for all Chart.js canvases to signal readiness via
/// `window.oxSlocChartsReady`, then captures the page using `Page.printToPDF` via CDP.
fn write_pdf_via_cdp(html_path: &Path, output_path: &Path) -> Result<()> {
    use headless_chrome::types::PrintToPdfOptions;
    use headless_chrome::{Browser, LaunchOptions};

    let browser_path = discover_browser().context(
        "no supported Chromium-based browser found; \
         set SLOC_BROWSER/BROWSER or install Chrome, Chromium, Edge, Brave, Vivaldi, or Opera",
    )?;
    eprintln!("[oxide-sloc][pdf] browser = {}", browser_path.display());

    let no_sandbox = std::env::var("SLOC_BROWSER_NOSANDBOX").as_deref() == Ok("1");
    if no_sandbox {
        eprintln!("[oxide-sloc][pdf] --no-sandbox enabled via SLOC_BROWSER_NOSANDBOX=1");
    }

    let browser = if no_sandbox {
        Browser::new(LaunchOptions {
            headless: true,
            path: Some(browser_path),
            window_size: Some((1122, 794)),
            sandbox: false,
            ..Default::default()
        })
        .context("failed to launch browser via CDP (no-sandbox)")?
    } else {
        // Try with sandbox first; on VMs/containers without user namespaces, retry without.
        match Browser::new(LaunchOptions {
            headless: true,
            path: Some(browser_path.clone()),
            window_size: Some((1122, 794)),
            sandbox: true,
            ..Default::default()
        }) {
            Ok(b) => b,
            Err(e) => {
                eprintln!(
                    "[oxide-sloc][pdf] sandboxed launch failed ({e:#}), retrying with --no-sandbox"
                );
                Browser::new(LaunchOptions {
                    headless: true,
                    path: Some(browser_path),
                    window_size: Some((1122, 794)),
                    sandbox: false,
                    ..Default::default()
                })
                .context(
                    "failed to launch browser via CDP (sandboxed and no-sandbox both failed)",
                )?
            }
        }
    };

    let tab = browser.new_tab().context("failed to open browser tab")?;

    let html_for_url = PathBuf::from(
        html_path
            .to_string_lossy()
            .trim_start_matches(r"\\?\")
            .to_string(),
    );
    let url = file_url(&html_for_url);
    eprintln!("[oxide-sloc][pdf] url = {url}");

    tab.navigate_to(&url)
        .context("failed to navigate browser to HTML file")?;
    tab.wait_until_navigated()
        .context("browser navigation did not complete")?;

    // Poll until the Chart.js init IIFE sets window.oxSlocChartsReady = true (max 15 s).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        if let Ok(r) = tab.evaluate("!!window.oxSlocChartsReady", false) {
            if matches!(r.value, Some(serde_json::Value::Bool(true))) {
                break;
            }
        }
        if std::time::Instant::now() >= deadline {
            eprintln!("[oxide-sloc][pdf] chart readiness timed out — capturing anyway");
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }

    // Read the user-configured report identification banner from the DOM (set in step 3 of
    // the scan configuration as `report_header_footer`).  When present, pass it as Chrome's
    // native per-page header/footer templates so it appears in the margin on every PDF page.
    let banner_text: Option<String> = tab
        .evaluate(
            "(function(){\
               var el=document.querySelector('.report-id-banner');\
               return el?el.textContent.trim():null;\
             })()",
            false,
        )
        .ok()
        .and_then(|r| r.value)
        .and_then(|v| match v {
            serde_json::Value::String(s) if !s.is_empty() => Some(s),
            _ => None,
        });

    if let Some(ref t) = banner_text {
        eprintln!("[oxide-sloc][pdf] report banner detected: {t}");
    }

    let has_banner = banner_text.is_some();

    // Build Chrome header/footer HTML templates from the banner text.
    // The template is rendered in the margin area; `font-size` must be set explicitly.
    let make_banner_tmpl = |text: &str| -> String {
        let escaped = text
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;");
        format!(
            r#"<div style="font-size:10px;width:100%;text-align:center;\
color:#fff;background:#b35428;padding:5px 0;\
font-family:sans-serif;font-weight:700;letter-spacing:0.05em;\
-webkit-print-color-adjust:exact;print-color-adjust:exact;">{escaped}</div>"#
        )
    };

    let (header_tmpl, footer_tmpl) = match &banner_text {
        Some(t) => (Some(make_banner_tmpl(t)), Some(make_banner_tmpl(t))),
        None => (None, None),
    };

    let pdf_bytes = tab
        .print_to_pdf(Some(PrintToPdfOptions {
            landscape: Some(true),
            print_background: Some(true),
            scale: Some(0.82),
            paper_width: Some(11.69), // A4 landscape width (inches)
            paper_height: Some(8.27), // A4 landscape height (inches)
            // When a banner is present widen the top/bottom margins so Chrome's
            // header/footer templates render fully without overlapping content.
            margin_top: Some(if has_banner { 0.55 } else { 0.35 }),
            margin_bottom: Some(if has_banner { 0.45 } else { 0.35 }),
            margin_left: Some(0.5),
            margin_right: Some(0.5),
            prefer_css_page_size: Some(false),
            display_header_footer: if has_banner { Some(true) } else { None },
            header_template: header_tmpl,
            footer_template: footer_tmpl,
            ..Default::default()
        }))
        .context("browser failed to generate PDF")?;

    fs::write(output_path, &pdf_bytes)
        .with_context(|| format!("failed to write PDF to {}", output_path.display()))?;

    eprintln!("[oxide-sloc][pdf] wrote {} bytes", pdf_bytes.len());
    Ok(())
}

/// Locate the `wkhtmltopdf` binary on Linux and Windows.
///
/// Search order:
/// 1. `wkhtmltopdf` / `wkhtmltopdf.exe` anywhere in `$PATH` (covers Linux packages and
///    Windows installs that add the bin dir to the system PATH).
/// 2. Windows-only: standard MSI install locations under `Program Files` and
///    `Program Files (x86)`.
/// 3. Linux-only: absolute paths that package managers commonly use but that may not be
///    on the service account's `$PATH`.
fn discover_wkhtmltopdf() -> Option<PathBuf> {
    if let Some(p) = which_in_path("wkhtmltopdf") {
        return Some(p);
    }

    #[cfg(windows)]
    {
        for var in ["ProgramFiles", "ProgramFiles(x86)"] {
            if let Ok(base) = std::env::var(var) {
                let candidate = PathBuf::from(base)
                    .join("wkhtmltopdf")
                    .join("bin")
                    .join("wkhtmltopdf.exe");
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
    }

    #[cfg(not(windows))]
    for p in [
        "/usr/bin/wkhtmltopdf",
        "/usr/local/bin/wkhtmltopdf",
        "/opt/wkhtmltopdf/bin/wkhtmltopdf",
        "/snap/bin/wkhtmltopdf",
    ] {
        let candidate = PathBuf::from(p);
        if candidate.is_file() {
            return Some(candidate);
        }
    }

    None
}

/// Generate a PDF using `wkhtmltopdf` when no Chromium-based browser is available.
///
/// Works on both Linux and Windows:
/// - Linux: install via `dnf install wkhtmltopdf` (RHEL/CentOS) or `apt install wkhtmltopdf`
/// - Windows: install the MSI from <https://wkhtmltopdf.org/downloads.html>; the installer
///   adds `wkhtmltopdf.exe` to `Program Files\wkhtmltopdf\bin\` which is checked automatically.
fn write_pdf_via_wkhtmltopdf(html_path: &Path, pdf_path: &Path) -> Result<()> {
    eprintln!("[oxide-sloc][pdf] trying wkhtmltopdf fallback");

    let exe = discover_wkhtmltopdf().context(
        "wkhtmltopdf not found. \
         Linux: install via 'dnf install wkhtmltopdf' or 'apt install wkhtmltopdf'. \
         Windows: install the MSI from https://wkhtmltopdf.org/downloads.html. \
         Alternatively, set SLOC_BROWSER to a Chromium-based browser executable.",
    )?;
    eprintln!("[oxide-sloc][pdf] wkhtmltopdf = {}", exe.display());

    // Strip the extended-length prefix on Windows (\\?\) so wkhtmltopdf can parse the path.
    let html_normalized = PathBuf::from(
        html_path
            .to_string_lossy()
            .trim_start_matches(r"\\?\")
            .to_string(),
    );
    // file_url() handles Windows drive letters (C:\ → /C:/) and encodes special chars.
    let html_url = file_url(&html_normalized);
    eprintln!("[oxide-sloc][pdf] wkhtmltopdf url = {html_url}");

    let pdf_str = pdf_path
        .to_str()
        .context("PDF output path contains non-UTF-8 characters")?;

    let output = std::process::Command::new(&exe)
        .args([
            "--enable-javascript",
            "--javascript-delay",
            "2000",
            "--quiet",
            "--orientation",
            "Landscape",
            "--page-size",
            "A4",
            "--margin-top",
            "9",
            "--margin-bottom",
            "9",
            "--margin-left",
            "13",
            "--margin-right",
            "13",
            "--print-media-type",
            &html_url,
            pdf_str,
        ])
        .output()
        .with_context(|| format!("failed to launch wkhtmltopdf at {}", exe.display()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("wkhtmltopdf exited with {}: {stderr}", output.status);
    }

    if !pdf_path.exists() {
        anyhow::bail!(
            "wkhtmltopdf exited successfully but {} was not created",
            pdf_path.display()
        );
    }

    eprintln!("[oxide-sloc][pdf] wkhtmltopdf wrote {}", pdf_path.display());
    Ok(())
}

struct PdfCtx<'a> {
    layer: &'a printpdf::PdfLayerReference,
    font_reg: &'a printpdf::IndirectFontRef,
    font_bold: &'a printpdf::IndirectFontRef,
    w: f32,
    margin: f32,
    row_h: f32,
    tbl_hdr_h: f32,
}

#[allow(clippy::cast_precision_loss)]
fn pdf_render_page1_header(
    ctx: &PdfCtx<'_>,
    run: &AnalysisRun,
    ts: &str,
    title: &str,
    h: f32,
    hdr_h: f32,
    banner: Option<&str>,
) -> f32 {
    use printpdf::{Color, Mm, Rgb};
    let hdr_y = h - hdr_h;
    pdf_fill_rect(
        ctx.layer,
        0.0,
        hdr_y,
        ctx.w,
        hdr_h,
        Rgb::new(0.098, 0.11, 0.15, None),
    );
    ctx.layer
        .set_fill_color(Color::Rgb(Rgb::new(1.0, 1.0, 1.0, None)));
    ctx.layer.use_text(
        "oxide-sloc",
        13.0,
        Mm(ctx.margin),
        Mm(hdr_y + 4.5),
        ctx.font_bold,
    );
    ctx.layer
        .set_fill_color(Color::Rgb(Rgb::new(0.72, 0.72, 0.72, None)));
    ctx.layer.use_text(
        "Code Metrics Report",
        9.5,
        Mm(54.0),
        Mm(hdr_y + 5.0),
        ctx.font_reg,
    );
    ctx.layer.use_text(
        pdf_safe_str(ts),
        8.0,
        Mm(ctx.w - 70.0),
        Mm(hdr_y + 5.0),
        ctx.font_reg,
    );
    // Report identification banner — white bold, centered between the two header items.
    if let Some(text) = banner {
        let safe = pdf_trunc(&pdf_safe_str(text), 40);
        // Approximate half-width at 9pt bold Helvetica (~0.97 mm per char) for centering.
        let text_x = (ctx.w / 2.0 - safe.len() as f32 * 0.97).max(95.0);
        ctx.layer
            .set_fill_color(Color::Rgb(Rgb::new(0.7, 0.33, 0.16, None)));
        ctx.layer
            .use_text(safe, 9.0, Mm(text_x), Mm(hdr_y + 4.5), ctx.font_bold);
    }
    let title_text_y = hdr_y - 5.5;
    ctx.layer
        .set_fill_color(Color::Rgb(Rgb::new(0.098, 0.11, 0.15, None)));
    ctx.layer.use_text(
        pdf_trunc(title, 55),
        9.5,
        Mm(ctx.margin),
        Mm(title_text_y),
        ctx.font_bold,
    );
    {
        let mut git_parts: Vec<String> = vec![];
        if let Some(ref b) = run.git_branch {
            git_parts.push(format!("Branch: {}", pdf_safe_str(b)));
        }
        if let Some(ref c) = run.git_commit_short {
            git_parts.push(format!("Commit: {}", pdf_safe_str(c)));
        }
        if let Some(ref t) = run.git_nearest_tag {
            git_parts.push(format!("Tag: {}", pdf_safe_str(t)));
        }
        if !git_parts.is_empty() {
            ctx.layer
                .set_fill_color(Color::Rgb(Rgb::new(0.35, 0.45, 0.35, None)));
            ctx.layer.use_text(
                pdf_trunc(&git_parts.join("  |  "), 70),
                7.5,
                Mm(ctx.w / 2.0),
                Mm(title_text_y),
                ctx.font_reg,
            );
        }
    }
    let roots_text_y = title_text_y - 5.0;
    let roots: String = run
        .input_roots
        .iter()
        .map(|r| pdf_safe_str(r))
        .collect::<Vec<_>>()
        .join("  ");
    ctx.layer
        .set_fill_color(Color::Rgb(Rgb::new(0.4, 0.4, 0.4, None)));
    ctx.layer.use_text(
        pdf_trunc(&roots, 85),
        6.5,
        Mm(ctx.margin),
        Mm(roots_text_y),
        ctx.font_reg,
    );
    {
        let env_str = format!(
            "OS: {} {}  |  User: {}  |  Host: {}  |  Mode: {}",
            pdf_safe_str(&run.environment.operating_system),
            pdf_safe_str(&run.environment.architecture),
            pdf_safe_str(&run.environment.initiator_username),
            pdf_safe_str(&run.environment.initiator_hostname),
            pdf_safe_str(&run.environment.runtime_mode),
        );
        ctx.layer.use_text(
            pdf_trunc(&env_str, 100),
            6.5,
            Mm(ctx.w / 2.0),
            Mm(roots_text_y),
            ctx.font_reg,
        );
    }
    roots_text_y
}

#[allow(clippy::cast_precision_loss)]
fn pdf_render_summary_chips(ctx: &PdfCtx<'_>, run: &AnalysisRun, roots_text_y: f32) -> f32 {
    use printpdf::{Color, Mm, Rgb};
    let tot = &run.summary_totals;
    let chip_gap: f32 = 5.0;
    let chip_w = 3.0f32.mul_add(-chip_gap, 2.0f32.mul_add(-ctx.margin, ctx.w)) / 4.0;
    let chip_h: f32 = 17.0;
    let row1_bot = roots_text_y - 4.0 - chip_h;
    let row1: [(&str, u64); 4] = [
        ("Code Lines", tot.code_lines),
        ("Comment Lines", tot.comment_lines),
        ("Blank Lines", tot.blank_lines),
        ("Physical Lines", tot.total_physical_lines),
    ];
    for (i, (label, value)) in row1.iter().enumerate() {
        let cx = (i as f32).mul_add(chip_w + chip_gap, ctx.margin);
        pdf_fill_rect(
            ctx.layer,
            cx,
            row1_bot,
            chip_w,
            chip_h,
            Rgb::new(0.945, 0.925, 0.90, None),
        );
        ctx.layer
            .set_fill_color(Color::Rgb(Rgb::new(0.7, 0.33, 0.16, None)));
        ctx.layer.use_text(
            pdf_fmt_num(*value),
            13.0,
            Mm(cx + 4.0),
            Mm(row1_bot + 9.0),
            ctx.font_bold,
        );
        ctx.layer
            .set_fill_color(Color::Rgb(Rgb::new(0.45, 0.45, 0.45, None)));
        ctx.layer.use_text(
            pdf_safe_str(label),
            6.5,
            Mm(cx + 4.0),
            Mm(row1_bot + 3.0),
            ctx.font_reg,
        );
        let exact = pdf_fmt_full(*value);
        let exact_x = ((exact.len() as f32).mul_add(-1.1, cx + chip_w) - 1.5).max(cx + 4.0);
        ctx.layer
            .set_fill_color(Color::Rgb(Rgb::new(0.55, 0.55, 0.55, None)));
        ctx.layer
            .use_text(exact, 5.5, Mm(exact_x), Mm(row1_bot + 1.5), ctx.font_reg);
    }
    let row2_bot = row1_bot - 3.0 - chip_h;
    let row2_4th = if tot.test_count > 0 {
        ("Test Methods", tot.test_count)
    } else if tot.classes > 0 {
        ("Classes", tot.classes)
    } else {
        ("Mixed Lines", tot.mixed_lines_separate)
    };
    let row2: [(&str, u64); 4] = [
        ("Files Analyzed", tot.files_analyzed),
        ("Files Skipped", tot.files_skipped),
        ("Functions", tot.functions),
        row2_4th,
    ];
    for (i, (label, value)) in row2.iter().enumerate() {
        let cx = (i as f32).mul_add(chip_w + chip_gap, ctx.margin);
        pdf_fill_rect(
            ctx.layer,
            cx,
            row2_bot,
            chip_w,
            chip_h,
            Rgb::new(0.91, 0.92, 0.96, None),
        );
        ctx.layer
            .set_fill_color(Color::Rgb(Rgb::new(0.15, 0.25, 0.55, None)));
        ctx.layer.use_text(
            pdf_fmt_num(*value),
            13.0,
            Mm(cx + 4.0),
            Mm(row2_bot + 9.0),
            ctx.font_bold,
        );
        ctx.layer
            .set_fill_color(Color::Rgb(Rgb::new(0.35, 0.35, 0.45, None)));
        ctx.layer.use_text(
            pdf_safe_str(label),
            6.5,
            Mm(cx + 4.0),
            Mm(row2_bot + 3.0),
            ctx.font_reg,
        );
        let exact = pdf_fmt_full(*value);
        let exact_x = ((exact.len() as f32).mul_add(-1.1, cx + chip_w) - 1.5).max(cx + 4.0);
        ctx.layer
            .set_fill_color(Color::Rgb(Rgb::new(0.45, 0.45, 0.60, None)));
        ctx.layer
            .use_text(exact, 5.5, Mm(exact_x), Mm(row2_bot + 1.5), ctx.font_reg);
    }
    row2_bot
}

#[allow(clippy::cast_precision_loss)]
fn pdf_info_parts_stats(tot: &SummaryTotals) -> Vec<String> {
    let total = tot.total_physical_lines.max(1) as f64;
    let code_pct = tot.code_lines as f64 / total * 100.0;
    let cmt_pct = tot.comment_lines as f64 / total * 100.0;
    let blank_pct = tot.blank_lines as f64 / total * 100.0;
    let mixed_pct = tot.mixed_lines_separate as f64 / total * 100.0;
    let mut parts = vec![
        format!("Code {code_pct:.1}%"),
        format!("Comments {cmt_pct:.1}%"),
        format!("Blank {blank_pct:.1}%"),
    ];
    if tot.mixed_lines_separate > 0 {
        parts.push(format!(
            "Mixed {mixed_pct:.1}% ({} lines)",
            pdf_fmt_full(tot.mixed_lines_separate)
        ));
    }
    if tot.imports > 0 {
        parts.push(format!("Imports: {}", pdf_fmt_full(tot.imports)));
    }
    if tot.variables > 0 {
        parts.push(format!("Variables: {}", pdf_fmt_full(tot.variables)));
    }
    if tot.classes > 0 {
        parts.push(format!("Classes: {}", pdf_fmt_full(tot.classes)));
    }
    parts
}

fn pdf_info_parts_git(run: &AnalysisRun) -> Vec<String> {
    let mut parts: Vec<String> = Vec::new();
    if let Some(ref b) = run.git_branch {
        parts.push(format!("Branch: {}", pdf_safe_str(b)));
    }
    if let Some(ref c) = run.git_commit_short {
        parts.push(format!("Commit: {}", pdf_safe_str(c)));
    }
    if let Some(ref t) = run.git_nearest_tag {
        parts.push(format!("Nearest Tag: {}", pdf_safe_str(t)));
    }
    if let Some(ref a) = run.git_commit_author {
        parts.push(format!("Author: {}", pdf_safe_str(a)));
    }
    if let Some(ref d) = run.git_commit_date {
        parts.push(format!("Commit Date: {}", pdf_safe_str(d)));
    }
    parts
}

#[allow(clippy::cast_precision_loss)]
fn pdf_info_parts_tests(tot: &SummaryTotals) -> Vec<String> {
    let mut tc: Vec<String> = Vec::new();
    if tot.test_count > 0 {
        tc.push(format!("Tests: {}", pdf_fmt_full(tot.test_count)));
    }
    if tot.test_assertion_count > 0 {
        tc.push(format!(
            "Assertions: {}",
            pdf_fmt_full(tot.test_assertion_count)
        ));
    }
    if tot.test_suite_count > 0 {
        tc.push(format!("Suites: {}", pdf_fmt_full(tot.test_suite_count)));
    }
    if tot.coverage_lines_found > 0 {
        tc.push(format!(
            "Line Cov: {:.1}% ({}/{})",
            tot.coverage_lines_hit as f64 / tot.coverage_lines_found as f64 * 100.0,
            pdf_fmt_full(tot.coverage_lines_hit),
            pdf_fmt_full(tot.coverage_lines_found)
        ));
    }
    if tot.coverage_functions_found > 0 {
        tc.push(format!(
            "Func Cov: {:.1}%",
            tot.coverage_functions_hit as f64 / tot.coverage_functions_found as f64 * 100.0
        ));
    }
    if tot.coverage_branches_found > 0 {
        tc.push(format!(
            "Branch Cov: {:.1}%",
            tot.coverage_branches_hit as f64 / tot.coverage_branches_found as f64 * 100.0
        ));
    }
    tc
}

fn pdf_info_emit_line(ctx: &PdfCtx<'_>, y: f32, r: f32, g: f32, b: f32, text: &str) -> f32 {
    use printpdf::{Color, Mm, Rgb};
    ctx.layer
        .set_fill_color(Color::Rgb(Rgb::new(r, g, b, None)));
    ctx.layer.use_text(
        pdf_trunc(text, 165),
        7.0,
        Mm(ctx.margin),
        Mm(y),
        ctx.font_reg,
    );
    y - 5.0
}

fn pdf_render_info_lines(ctx: &PdfCtx<'_>, run: &AnalysisRun, row2_bot: f32) -> f32 {
    let tot = &run.summary_totals;
    let mut y = row2_bot - 6.5;
    let stats = pdf_info_parts_stats(tot);
    y = pdf_info_emit_line(ctx, y, 0.15, 0.15, 0.15, &stats.join("  |  "));
    let git = pdf_info_parts_git(run);
    if !git.is_empty() {
        y = pdf_info_emit_line(ctx, y, 0.10, 0.35, 0.15, &git.join("  |  "));
    }
    let tests = pdf_info_parts_tests(tot);
    if !tests.is_empty() {
        y = pdf_info_emit_line(ctx, y, 0.15, 0.15, 0.50, &tests.join("  |  "));
    }
    y
}

#[allow(clippy::cast_precision_loss)]
fn pdf_table_render_section(
    ctx: &PdfCtx<'_>,
    x: f32,
    top: f32,
    w: f32,
    lbl_frac: f32,
    title: &str,
    rows: &[(&str, String)],
) {
    use printpdf::{Color, Mm, Rgb};
    pdf_fill_rect(
        ctx.layer,
        x,
        top - ctx.tbl_hdr_h,
        w,
        ctx.tbl_hdr_h,
        Rgb::new(0.098, 0.11, 0.15, None),
    );
    ctx.layer
        .set_fill_color(Color::Rgb(Rgb::new(1.0, 1.0, 1.0, None)));
    ctx.layer.use_text(
        title,
        7.0,
        Mm(x + 2.0),
        Mm(top - ctx.tbl_hdr_h + 1.5),
        ctx.font_bold,
    );
    let y = top - ctx.tbl_hdr_h;
    for (ri, (lbl, val)) in rows.iter().enumerate() {
        let ry = ((ri + 1) as f32).mul_add(-ctx.row_h, y);
        let bg = if ri % 2 == 0 {
            Rgb::new(0.975, 0.965, 0.95, None)
        } else {
            Rgb::new(1.0, 1.0, 1.0, None)
        };
        pdf_fill_rect(ctx.layer, x, ry, w, ctx.row_h, bg);
        ctx.layer
            .set_fill_color(Color::Rgb(Rgb::new(0.12, 0.12, 0.12, None)));
        ctx.layer
            .use_text(*lbl, 6.5, Mm(x + 2.0), Mm(ry + 1.5), ctx.font_reg);
        let is_dash = val == "--";
        let val_rgb = if is_dash {
            Rgb::new(0.55, 0.55, 0.55, None)
        } else {
            Rgb::new(0.12, 0.12, 0.12, None)
        };
        let val_font = if is_dash { ctx.font_reg } else { ctx.font_bold };
        ctx.layer.set_fill_color(Color::Rgb(val_rgb));
        ctx.layer.use_text(
            val.as_str(),
            6.5,
            Mm(x + w * lbl_frac + 2.0),
            Mm(ry + 1.5),
            val_font,
        );
    }
}

#[allow(clippy::cast_precision_loss)]
fn pdf_render_metric_tables(ctx: &PdfCtx<'_>, run: &AnalysisRun, tbl_top: f32) {
    let tot = &run.summary_totals;
    let half_w = (2.0f32.mul_add(-ctx.margin, ctx.w) - 4.0) / 2.0;
    let left_x = ctx.margin;
    let right_x = ctx.margin + half_w + 4.0;
    let lbl_frac: f32 = 0.68;

    let files_rows: [(&str, String); 4] = [
        ("Files analyzed", pdf_fmt_full(tot.files_analyzed)),
        ("Files skipped", pdf_fmt_full(tot.files_skipped)),
        ("Files modified", "--".to_string()),
        ("Files unchanged", "--".to_string()),
    ];
    pdf_table_render_section(ctx, left_x, tbl_top, half_w, lbl_frac, "FILES", &files_rows);

    let lc_rows: [(&str, String); 5] = [
        ("Physical lines", pdf_fmt_full(tot.total_physical_lines)),
        ("Code lines", pdf_fmt_full(tot.code_lines)),
        ("Comment lines", pdf_fmt_full(tot.comment_lines)),
        ("Blank lines", pdf_fmt_full(tot.blank_lines)),
        ("Mixed (separate)", pdf_fmt_full(tot.mixed_lines_separate)),
    ];
    let lc_top = tbl_top - ctx.tbl_hdr_h - (files_rows.len() as f32).mul_add(ctx.row_h, 3.0);
    pdf_table_render_section(
        ctx,
        left_x,
        lc_top,
        half_w,
        lbl_frac,
        "LINE COUNTS",
        &lc_rows,
    );

    let cs_rows: [(&str, String); 4] = [
        ("Functions", pdf_fmt_full(tot.functions)),
        ("Classes / Types", pdf_fmt_full(tot.classes)),
        ("Variables", pdf_fmt_full(tot.variables)),
        ("Imports", pdf_fmt_full(tot.imports)),
    ];
    pdf_table_render_section(
        ctx,
        right_x,
        tbl_top,
        half_w,
        lbl_frac,
        "CODE STRUCTURE",
        &cs_rows,
    );

    let lcs_rows: [(&str, String); 4] = [
        ("Lines added", "--".to_string()),
        ("Lines removed", "--".to_string()),
        ("Lines modified (net)", "--".to_string()),
        ("Lines unmodified", "--".to_string()),
    ];
    let lcs_top = tbl_top - ctx.tbl_hdr_h - (cs_rows.len() as f32).mul_add(ctx.row_h, 3.0);
    pdf_table_render_section(
        ctx,
        right_x,
        lcs_top,
        half_w,
        lbl_frac,
        "LINE CHANGE SUMMARY",
        &lcs_rows,
    );
}

fn pdf_render_page1_footer(
    ctx: &PdfCtx<'_>,
    run: &AnalysisRun,
    footer_h: f32,
    version: &str,
    banner: Option<&str>,
) {
    use printpdf::{Color, Mm, Rgb};
    pdf_fill_rect(
        ctx.layer,
        0.0,
        0.0,
        ctx.w,
        footer_h,
        Rgb::new(0.93, 0.91, 0.87, None),
    );
    ctx.layer
        .set_fill_color(Color::Rgb(Rgb::new(0.4, 0.4, 0.4, None)));
    // Left section.
    ctx.layer.use_text(
        format!("oxide-sloc v{version}  |  AGPL-3.0-or-later"),
        6.5,
        Mm(ctx.margin),
        Mm(3.0),
        ctx.font_reg,
    );
    // Right section — github.com and Run ID, right-aligned (~1.27 mm per char at 6.5 pt).
    let right_text = format!(
        "github.com/oxide-sloc/oxide-sloc  |  Run ID: {}",
        pdf_safe_str(&run.tool.run_id[..run.tool.run_id.len().min(20)])
    );
    let right_x = (ctx.w - ctx.margin - right_text.len() as f32 * 1.27).max(ctx.margin + 80.0);
    ctx.layer
        .use_text(right_text, 6.5, Mm(right_x), Mm(3.0), ctx.font_reg);
    // Center section — banner text, no background, oxide brand color, bold.
    if let Some(text) = banner {
        let safe = pdf_trunc(&pdf_safe_str(text), 40);
        // Same per-char width as the header banner (0.97 mm at 9pt bold Helvetica).
        let text_x = (ctx.w / 2.0 - safe.len() as f32 * 0.97).max(ctx.margin + 50.0);
        ctx.layer
            .set_fill_color(Color::Rgb(Rgb::new(0.7, 0.33, 0.16, None)));
        ctx.layer
            .use_text(safe, 9.0, Mm(text_x), Mm(2.6), ctx.font_bold);
    }
}

// PDF per-file page renderer — all layout params are distinct and cannot be bundled further
// without an opaque config struct that would obscure the call site in write_pdf_from_run.
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::too_many_arguments
)]
fn pdf_render_per_file_pages(
    doc: &printpdf::PdfDocumentReference,
    font_reg: &printpdf::IndirectFontRef,
    font_bold: &printpdf::IndirectFontRef,
    run: &AnalysisRun,
    w: f32,
    h: f32,
    margin: f32,
    footer_h: f32,
    row_h: f32,
    tbl_hdr_h: f32,
    title: &str,
    ts: &str,
    version: &str,
    banner: Option<&str>,
) {
    use printpdf::{Color, Mm, Rgb};
    const HDR2_H: f32 = 8.0;
    const SUB_H: f32 = 5.5;
    // File column gets ~136 mm; numeric columns compressed to minimum readable width.
    // Column widths: File=136, Lang=14, Phys=12, Code=10, Comments=13, Blank=10, Mixed=10,
    //   Functions=13, Classes=11, Variables=13, Imports=11, Tests=10, Assertions=14  → total 277 mm
    let col_x: [f32; 13] = [
        10.0, 146.0, 160.0, 172.0, 182.0, 195.0, 205.0, 215.0, 228.0, 239.0, 252.0, 263.0, 273.0,
    ];
    let col_labels: [&str; 13] = [
        "File",
        "Language",
        "Physical",
        "Code",
        "Comments",
        "Blank",
        "Mixed",
        "Functions",
        "Classes",
        "Variables",
        "Imports",
        "Tests",
        "Assertions",
    ];
    let rows_per_page = ((h - HDR2_H - SUB_H - tbl_hdr_h - footer_h) / row_h).floor() as usize;
    let total_files = run.per_file_records.len();
    let page_count = total_files.div_ceil(rows_per_page);

    for page_idx in 0..page_count {
        let (pf_page, pf_layer_idx) = doc.add_page(Mm(w), Mm(h), "Content");
        let pf_layer = doc.get_page(pf_page).get_layer(pf_layer_idx);
        let pf_hdr_top = h - HDR2_H;
        pdf_fill_rect(
            &pf_layer,
            0.0,
            pf_hdr_top,
            w,
            HDR2_H,
            Rgb::new(0.098, 0.11, 0.15, None),
        );
        pf_layer.set_fill_color(Color::Rgb(Rgb::new(1.0, 1.0, 1.0, None)));
        pf_layer.use_text(
            "oxide-sloc",
            9.0,
            Mm(margin),
            Mm(pf_hdr_top + 2.5),
            font_bold,
        );
        pf_layer.set_fill_color(Color::Rgb(Rgb::new(0.72, 0.72, 0.72, None)));
        pf_layer.use_text(
            "Per-File Detail",
            8.0,
            Mm(46.0),
            Mm(pf_hdr_top + 2.5),
            font_reg,
        );
        pf_layer.use_text(
            format!("Page {} of {}", page_idx + 2, page_count + 1),
            7.0,
            Mm(w - 40.0),
            Mm(pf_hdr_top + 2.5),
            font_reg,
        );
        // Report identification banner — white bold, centered in the per-file page header.
        if let Some(text) = banner {
            let safe = pdf_trunc(&pdf_safe_str(text), 40);
            let text_x = (w / 2.0 - safe.len() as f32 * 0.97).max(80.0);
            pf_layer.set_fill_color(Color::Rgb(Rgb::new(0.7, 0.33, 0.16, None)));
            pf_layer.use_text(safe, 9.0, Mm(text_x), Mm(pf_hdr_top + 2.5), font_bold);
        }
        let sub_top = pf_hdr_top - SUB_H;
        pdf_fill_rect(
            &pf_layer,
            0.0,
            sub_top,
            w,
            SUB_H,
            Rgb::new(0.94, 0.93, 0.91, None),
        );
        pf_layer.set_fill_color(Color::Rgb(Rgb::new(0.3, 0.3, 0.3, None)));
        pf_layer.use_text(
            pdf_trunc(title, 55),
            6.5,
            Mm(margin),
            Mm(sub_top + 1.0),
            font_reg,
        );
        pf_layer.use_text(
            format!("{total_files} files  |  {ts}"),
            6.5,
            Mm(w - 80.0),
            Mm(sub_top + 1.0),
            font_reg,
        );
        let pf_tbl_top = sub_top;
        pdf_fill_rect(
            &pf_layer,
            margin,
            pf_tbl_top - tbl_hdr_h,
            2.0f32.mul_add(-margin, w),
            tbl_hdr_h,
            Rgb::new(0.098, 0.11, 0.15, None),
        );
        pf_layer.set_fill_color(Color::Rgb(Rgb::new(1.0, 1.0, 1.0, None)));
        for (i, lbl) in col_labels.iter().enumerate() {
            pf_layer.use_text(
                *lbl,
                5.0,
                Mm(col_x[i] + 0.5),
                Mm(pf_tbl_top - tbl_hdr_h + 1.5),
                font_bold,
            );
        }
        let start = page_idx * rows_per_page;
        let end = (start + rows_per_page).min(total_files);
        for (ri, rec) in run.per_file_records[start..end].iter().enumerate() {
            let ry = ((ri + 1) as f32).mul_add(-row_h, pf_tbl_top - tbl_hdr_h);
            let bg = if ri % 2 == 0 {
                Rgb::new(0.975, 0.965, 0.95, None)
            } else {
                Rgb::new(1.0, 1.0, 1.0, None)
            };
            pdf_fill_rect(&pf_layer, margin, ry, 2.0f32.mul_add(-margin, w), row_h, bg);
            pf_layer.set_fill_color(Color::Rgb(Rgb::new(0.12, 0.12, 0.12, None)));
            let file_str = pdf_safe_str(&rec.relative_path);
            let lang_str = rec
                .language
                .as_ref()
                .map_or_else(|| "--".to_string(), |l| l.display_name().to_string());
            let raw = &rec.raw_line_categories;
            let eff = &rec.effective_counts;
            let cells = [
                pdf_trunc_end(&file_str, 110),
                lang_str,
                pdf_fmt_full(raw.total_physical_lines),
                pdf_fmt_full(eff.code_lines),
                pdf_fmt_full(eff.comment_lines),
                pdf_fmt_full(eff.blank_lines),
                pdf_fmt_full(eff.mixed_lines_separate),
                pdf_fmt_full(raw.functions),
                pdf_fmt_full(raw.classes),
                pdf_fmt_full(raw.variables),
                pdf_fmt_full(raw.imports),
                pdf_fmt_full(raw.test_count),
                pdf_fmt_full(raw.test_assertion_count),
            ];
            for (ci, cell) in cells.iter().enumerate() {
                pf_layer.use_text(
                    cell.clone(),
                    5.5,
                    Mm(col_x[ci] + 0.5),
                    Mm(ry + 1.0),
                    font_reg,
                );
            }
        }
        pdf_fill_rect(
            &pf_layer,
            0.0,
            0.0,
            w,
            footer_h,
            Rgb::new(0.93, 0.91, 0.87, None),
        );
        pf_layer.set_fill_color(Color::Rgb(Rgb::new(0.4, 0.4, 0.4, None)));
        // Left section.
        pf_layer.use_text(
            format!("oxide-sloc v{version}  |  AGPL-3.0-or-later"),
            6.5,
            Mm(margin),
            Mm(3.0),
            font_reg,
        );
        // Right section — github.com and Run ID, right-aligned (~1.27 mm per char at 6.5 pt).
        let right_text = format!(
            "github.com/oxide-sloc/oxide-sloc  |  Run ID: {}",
            pdf_safe_str(&run.tool.run_id[..run.tool.run_id.len().min(20)])
        );
        let right_x = (w - margin - right_text.len() as f32 * 1.27).max(margin + 80.0);
        pf_layer.use_text(right_text, 6.5, Mm(right_x), Mm(3.0), font_reg);
        // Center section — banner text, no background, oxide brand color, bold.
        if let Some(text) = banner {
            let safe = pdf_trunc(&pdf_safe_str(text), 40);
            // Same per-char width as the header banner (0.97 mm at 9pt bold Helvetica).
            let text_x = (w / 2.0 - safe.len() as f32 * 0.97).max(margin + 50.0);
            pf_layer.set_fill_color(Color::Rgb(Rgb::new(0.7, 0.33, 0.16, None)));
            pf_layer.use_text(safe, 9.0, Mm(text_x), Mm(2.6), font_bold);
        }
    }
}

/// Generate a PDF summary report from `AnalysisRun` data using the pure-Rust `printpdf` crate.
///
/// No external tools (Chrome, wkhtmltopdf) are required — this path is always available on
/// both Windows and Linux server deployments.
///
/// # Errors
///
/// Returns an error if the output directory cannot be created or the PDF file cannot be written.
// Casts throughout are for PDF layout coordinates and percentage ratios; precision loss is fine.
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
pub fn write_pdf_from_run(run: &AnalysisRun, pdf_path: &Path) -> Result<()> {
    use printpdf::{BuiltinFont, Mm, PdfDocument};
    use std::fs::File;
    use std::io::BufWriter;

    const W: f32 = 297.0;
    const H: f32 = 210.0;
    const MARGIN: f32 = 10.0;
    const FOOTER_H: f32 = 10.0;
    const HDR_H: f32 = 13.5;
    const ROW_H: f32 = 5.5;
    const TBL_HDR_H: f32 = 6.0;

    if let Some(parent) = pdf_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create PDF directory {}", parent.display()))?;
    }

    let title = pdf_safe_str(&run.effective_configuration.reporting.report_title);
    let ts = run
        .tool
        .timestamp_utc
        .format("%Y-%m-%d %H:%M UTC")
        .to_string();
    let version = env!("CARGO_PKG_VERSION");
    let banner = run
        .effective_configuration
        .reporting
        .report_header_footer
        .as_deref();

    let (doc, page1, layer1) =
        PdfDocument::new(format!("oxide-sloc: {title}"), Mm(W), Mm(H), "Content");
    let font_reg = doc
        .add_builtin_font(BuiltinFont::Helvetica)
        .map_err(|e| anyhow::anyhow!("printpdf font error: {e}"))?;
    let font_bold = doc
        .add_builtin_font(BuiltinFont::HelveticaBold)
        .map_err(|e| anyhow::anyhow!("printpdf font error: {e}"))?;
    let layer = doc.get_page(page1).get_layer(layer1);

    let ctx = PdfCtx {
        layer: &layer,
        font_reg: &font_reg,
        font_bold: &font_bold,
        w: W,
        margin: MARGIN,
        row_h: ROW_H,
        tbl_hdr_h: TBL_HDR_H,
    };
    let roots_text_y = pdf_render_page1_header(&ctx, run, &ts, &title, H, HDR_H, banner);
    let row2_bot = pdf_render_summary_chips(&ctx, run, roots_text_y);
    let info_y = pdf_render_info_lines(&ctx, run, row2_bot);
    pdf_render_metric_tables(&ctx, run, info_y - 4.0);
    pdf_render_page1_footer(&ctx, run, FOOTER_H, version, banner);

    if !run.per_file_records.is_empty() {
        pdf_render_per_file_pages(
            &doc, &font_reg, &font_bold, run, W, H, MARGIN, FOOTER_H, ROW_H, TBL_HDR_H, &title,
            &ts, version, banner,
        );
    }

    doc.save(&mut BufWriter::new(File::create(pdf_path).with_context(
        || format!("cannot create PDF at {}", pdf_path.display()),
    )?))
    .map_err(|e| anyhow::anyhow!("printpdf save error: {e}"))?;

    Ok(())
}

fn pdf_fill_rect(
    layer: &printpdf::PdfLayerReference,
    x: f32,
    y: f32,
    w: f32,
    h: f32,
    color: printpdf::Rgb,
) {
    use printpdf::path::{PaintMode, WindingOrder};
    use printpdf::{Color, Mm, Point, Polygon};
    layer.set_fill_color(Color::Rgb(color));
    layer.add_polygon(Polygon {
        rings: vec![vec![
            (Point::new(Mm(x), Mm(y)), false),
            (Point::new(Mm(x + w), Mm(y)), false),
            (Point::new(Mm(x + w), Mm(y + h)), false),
            (Point::new(Mm(x), Mm(y + h)), false),
        ]],
        mode: PaintMode::Fill,
        winding_order: WindingOrder::NonZero,
    });
}

fn pdf_safe_str(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii() && !c.is_ascii_control() {
                c
            } else {
                '?'
            }
        })
        .collect()
}

fn pdf_trunc(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max.saturating_sub(3)])
    }
}

// Show the tail of a string — prepend "..." when truncated so the meaningful end is visible.
// Used for file paths where the filename/leaf matters more than the leading directories.
fn pdf_trunc_end(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("...{}", &s[s.len() - max.saturating_sub(3)..])
    }
}

#[allow(clippy::cast_precision_loss)] // formatting large numbers; sub-million precision doesn't matter
fn pdf_fmt_num(n: u64) -> String {
    if n >= 1_000_000 {
        let m = n as f64 / 1_000_000.0;
        let s = format!("{m:.1}M");
        #[allow(clippy::case_sensitive_file_extension_comparisons)]
        // not a file path; ".0M" is a number suffix
        if s.ends_with(".0M") {
            format!("{}M", n / 1_000_000)
        } else {
            s
        }
    } else if n >= 10_000 {
        format!("{}K", n / 1_000)
    } else if n >= 1_000 {
        format!("{},{:03}", n / 1_000, n % 1_000)
    } else {
        n.to_string()
    }
}

fn pdf_fmt_full(n: u64) -> String {
    // Comma-separated full number: 15319 → "15,319", 1374 → "1,374"
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, ch) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out.chars().rev().collect()
}

/// Launch a headless Chromium-based browser to print `html_path` as a PDF to `pdf_path`.
///
/// Tries CDP (headless Chrome) first; falls back to `wkhtmltopdf` when no Chromium-based
/// browser is found on the server.
///
/// # Errors
///
/// Returns an error if no PDF tool (Chromium or wkhtmltopdf) is available, the tool fails
/// to start, or the PDF file is not produced within the timeout.
pub fn write_pdf_from_html(html_path: &Path, pdf_path: &Path) -> Result<()> {
    eprintln!("[oxide-sloc][pdf] starting");

    let absolute_html = html_path
        .canonicalize()
        .with_context(|| format!("failed to canonicalize {}", html_path.display()))?;
    eprintln!("[oxide-sloc][pdf] html = {}", absolute_html.display());

    let absolute_pdf = if pdf_path.is_absolute() {
        pdf_path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("failed to resolve current working directory")?
            .join(pdf_path)
    };
    eprintln!("[oxide-sloc][pdf] pdf = {}", absolute_pdf.display());

    if let Some(parent) = absolute_pdf.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!("failed to create PDF output directory {}", parent.display())
        })?;
    }

    match write_pdf_via_cdp(&absolute_html, &absolute_pdf) {
        Ok(()) => {}
        Err(cdp_err) => {
            eprintln!("[oxide-sloc][pdf] CDP failed ({cdp_err:#}), trying wkhtmltopdf fallback");
            write_pdf_via_wkhtmltopdf(&absolute_html, &absolute_pdf).with_context(|| {
                format!(
                    "PDF generation failed via both CDP ({cdp_err:#}) and wkhtmltopdf. \
                     Install a Chromium-based browser (Chrome, Edge, Brave) or wkhtmltopdf \
                     on the server, or set SLOC_BROWSER to the browser executable path."
                )
            })?;
        }
    }

    eprintln!("[oxide-sloc][pdf] done");
    Ok(())
}

fn normalize_browser_env_path(raw: &str) -> PathBuf {
    let trimmed = raw.trim();
    #[cfg(windows)]
    {
        let bytes = trimmed.as_bytes();
        if bytes.len() >= 3
            && bytes[0] == b'/'
            && bytes[2] == b'/'
            && bytes[1].is_ascii_alphabetic()
        {
            let drive = (bytes[1] as char).to_ascii_uppercase();
            let rest = &trimmed[3..];
            return PathBuf::from(format!("{drive}:/{rest}"));
        }
    }
    PathBuf::from(trimmed)
}

fn discover_browser_from_env() -> Option<PathBuf> {
    for var_name in ["SLOC_BROWSER", "BROWSER"] {
        if let Ok(path) = std::env::var(var_name) {
            let candidate = normalize_browser_env_path(&path);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn discover_browser() -> Option<PathBuf> {
    if let Some(p) = discover_browser_from_env() {
        return Some(p);
    }

    let names = [
        "chromium",
        "chromium-browser",
        "google-chrome",
        "google-chrome-stable",
        "microsoft-edge",
        "msedge",
        "brave",
        "brave-browser",
        "vivaldi",
        "opera",
        "opera-stable",
    ];

    for name in names {
        if let Some(path) = which_in_path(name) {
            return Some(path);
        }
    }

    #[cfg(windows)]
    {
        for candidate in windows_browser_candidates() {
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    // Absolute path fallbacks for Linux servers where the browser may not be
    // in $PATH (e.g. installed via snap, flatpak, or a minimal systemd service env).
    #[cfg(not(windows))]
    {
        for candidate in linux_browser_candidates() {
            if candidate.is_file() {
                return Some(candidate);
            }
        }

        // Final fallback: ask the shell's `which` so we catch browsers installed
        // in non-standard locations that weren't found via PATH or static paths.
        if let Some(path) = which_subprocess(&[
            "chromium-browser",
            "chromium",
            "google-chrome",
            "google-chrome-stable",
            "microsoft-edge",
            "brave-browser",
        ]) {
            return Some(path);
        }
    }

    None
}

#[cfg(windows)]
fn windows_browser_candidates() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    let program_files = std::env::var_os("ProgramFiles");
    let program_files_x86 = std::env::var_os("ProgramFiles(x86)");
    let local_app_data = std::env::var_os("LocalAppData");

    for base in [program_files, program_files_x86].into_iter().flatten() {
        let base = PathBuf::from(base);

        paths.push(base.join("Google/Chrome/Application/chrome.exe"));
        paths.push(base.join("Microsoft/Edge/Application/msedge.exe"));
        paths.push(base.join("BraveSoftware/Brave-Browser/Application/brave.exe"));
        paths.push(base.join("Vivaldi/Application/vivaldi.exe"));
        paths.push(base.join("Opera/launcher.exe"));
        paths.push(base.join("Opera GX/launcher.exe"));
    }

    if let Some(base) = local_app_data {
        let base = PathBuf::from(base);

        paths.push(base.join("Google/Chrome/Application/chrome.exe"));
        paths.push(base.join("Microsoft/Edge/Application/msedge.exe"));
        paths.push(base.join("BraveSoftware/Brave-Browser/Application/brave.exe"));
        paths.push(base.join("Vivaldi/Application/vivaldi.exe"));
        paths.push(base.join("Programs/Opera/launcher.exe"));
        paths.push(base.join("Programs/Opera GX/launcher.exe"));
    }

    paths
}

#[cfg(not(windows))]
fn linux_browser_candidates() -> Vec<PathBuf> {
    vec![
        // snap (Ubuntu, common on servers)
        PathBuf::from("/snap/bin/chromium"),
        PathBuf::from("/snap/bin/chromium-browser"),
        // standard apt/dnf paths
        PathBuf::from("/usr/bin/chromium"),
        PathBuf::from("/usr/bin/chromium-browser"),
        PathBuf::from("/usr/bin/google-chrome"),
        PathBuf::from("/usr/bin/google-chrome-stable"),
        PathBuf::from("/usr/bin/microsoft-edge"),
        PathBuf::from("/usr/bin/microsoft-edge-stable"),
        PathBuf::from("/usr/bin/brave-browser"),
        PathBuf::from("/usr/bin/brave-browser-stable"),
        // package-managed library locations (Ubuntu 20.04, Debian)
        PathBuf::from("/usr/lib/chromium-browser/chromium-browser"),
        PathBuf::from("/usr/lib/chromium/chromium"),
        PathBuf::from("/usr/lib/chromium/chrome"),
        // manual / opt installs
        PathBuf::from("/opt/google/chrome/google-chrome"),
        PathBuf::from("/opt/google/chrome-beta/google-chrome"),
        PathBuf::from("/opt/google/chrome-unstable/google-chrome"),
        // local installs
        PathBuf::from("/usr/local/bin/chromium"),
        PathBuf::from("/usr/local/bin/chromium-browser"),
        PathBuf::from("/usr/local/bin/google-chrome"),
        // flatpak wrapper scripts
        PathBuf::from("/var/lib/flatpak/exports/bin/org.chromium.Chromium"),
        PathBuf::from("/usr/share/flatpak/exports/bin/org.chromium.Chromium"),
    ]
}

/// Ask the shell for a browser that may be in PATH but not in the hardcoded list above.
/// Used as a last resort when all static-path checks have failed.
#[cfg(not(windows))]
fn which_subprocess(names: &[&str]) -> Option<PathBuf> {
    for name in names {
        if let Ok(out) = std::process::Command::new("which").arg(name).output() {
            if out.status.success() {
                let s = String::from_utf8_lossy(&out.stdout);
                let path = PathBuf::from(s.trim());
                if path.is_file() {
                    return Some(path);
                }
            }
        }
    }
    None
}

fn which_in_path(exe: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(exe);
        if candidate.is_file() {
            return Some(candidate);
        }
        #[cfg(windows)]
        {
            let candidate = dir.join(format!("{exe}.exe"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn file_url(path: &Path) -> String {
    let raw = path.to_string_lossy().replace('\\', "/");
    let normalized = if raw.starts_with('/') {
        raw
    } else {
        format!("/{raw}")
    };

    let mut encoded = String::with_capacity(normalized.len() + 8);
    for byte in normalized.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'/' | b'-' | b'_' | b'.' | b'~' | b':' => {
                encoded.push(byte as char);
            }
            _ => {
                let _ = write!(encoded, "%{byte:02X}");
            }
        }
    }

    format!("file://{encoded}")
}

fn file_row_view(file: &FileRecord) -> FileRow {
    FileRow {
        relative_path: file.relative_path.clone(),
        language: file.language.map_or_else(
            || "-".into(),
            |language| language.display_name().to_string(),
        ),
        total_physical_lines: file.raw_line_categories.total_physical_lines,
        code_lines: file.effective_counts.code_lines,
        comment_lines: file.effective_counts.comment_lines,
        blank_lines: file.effective_counts.blank_lines,
        mixed_lines_separate: file.effective_counts.mixed_lines_separate,
        functions: file.raw_line_categories.functions,
        classes: file.raw_line_categories.classes,
        variables: file.raw_line_categories.variables,
        imports: file.raw_line_categories.imports,
        test_count: file.raw_line_categories.test_count,
        test_assertion_count: file.raw_line_categories.test_assertion_count,
        test_suite_count: file.raw_line_categories.test_suite_count,
        line_cov_pct: file
            .coverage
            .as_ref()
            .map(|c| format!("{:.1}", c.line_pct()))
            .unwrap_or_default(),
        fn_cov_pct: file
            .coverage
            .as_ref()
            .filter(|c| c.functions_found > 0)
            .map(|c| format!("{:.1}", c.function_pct()))
            .unwrap_or_default(),
        status: format!("{:?}", file.status),
        status_class: format!("{:?}", file.status).to_ascii_lowercase(),
        warnings: if file.warnings.is_empty() {
            String::new()
        } else {
            file.warnings.join("; ")
        },
    }
}

fn is_pacific_dst_report(dt: DateTime<Utc>) -> bool {
    use chrono::{Datelike, NaiveDate, NaiveTime, TimeZone, Weekday};
    let year = dt.year();
    let nth_sun = |month: u32, n: u32, hour: u32| {
        let mut count = 0u32;
        let mut day = 1u32;
        loop {
            let d = NaiveDate::from_ymd_opt(year, month, day).expect("valid");
            if d.weekday() == Weekday::Sun {
                count += 1;
                if count == n {
                    return Utc.from_utc_datetime(
                        &d.and_time(NaiveTime::from_hms_opt(hour, 0, 0).expect("valid")),
                    );
                }
            }
            day += 1;
        }
    };
    let dst_start = nth_sun(3, 2, 10);
    let dst_end = nth_sun(11, 1, 9);
    dt >= dst_start && dt < dst_end
}

fn to_pst_display(dt: DateTime<Utc>) -> String {
    let (offset, label) = if is_pacific_dst_report(dt) {
        (
            FixedOffset::west_opt(7 * 3600).expect("valid PDT offset"),
            "PDT",
        )
    } else {
        (
            FixedOffset::west_opt(8 * 3600).expect("valid PST offset"),
            "PST",
        )
    };
    format!(
        "{} {label}",
        dt.with_timezone(&offset).format("%Y-%m-%d %H:%M:%S")
    )
}

fn build_warning_console(warnings: &[String]) -> String {
    if warnings.is_empty() {
        return "No top-level warnings.".to_string();
    }

    warnings
        .iter()
        .enumerate()
        .map(|(index, warning)| {
            format!(
                "[{index:03}] {warning}",
                index = index + 1,
                warning = warning
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn summarize_warnings(warnings: &[String]) -> Vec<WarningSummaryRow> {
    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    for warning in warnings {
        let key = if warning.contains("unsupported or undetected language") {
            "Unsupported or undetected text formats"
        } else if warning.contains("file exceeded max_file_size_bytes") {
            "Large files skipped by size limit"
        } else if warning.contains("binary file skipped by default") {
            "Binary assets skipped"
        } else if warning.contains("minified file skipped by policy") {
            "Minified files skipped by policy"
        } else if warning.contains("vendor file skipped by policy") {
            "Vendor files skipped by policy"
        } else if warning.contains("best effort") || warning.contains("unclosed string literal") {
            "Best-effort parse results"
        } else {
            "Other warnings"
        };
        *counts.entry(key).or_default() += 1;
    }

    counts
        .into_iter()
        .map(|(label, count)| {
            let (tone_class, detail) = match label {
                "Unsupported or undetected text formats" => (
                    "tone-neutral",
                    "These are usually docs, manifests, templates, or formats that have not been promoted into first-class analyzers yet.",
                ),
                "Large files skipped by size limit" => (
                    "tone-warn",
                    "Artifacts and archives larger than the configured cap were skipped intentionally to keep runs fast and predictable.",
                ),
                "Binary assets skipped" => (
                    "tone-neutral",
                    "Binary bundles are excluded from source counting unless you explicitly opt into them.",
                ),
                "Minified files skipped by policy" => (
                    "tone-warn",
                    "Generated and minified assets are being filtered out to avoid inflating code totals.",
                ),
                "Vendor files skipped by policy" => (
                    "tone-neutral",
                    "Vendored third-party code is being excluded so the report stays focused on repository-owned source.",
                ),
                "Best-effort parse results" => (
                    "tone-danger",
                    "These files were analyzed, but the parser hit malformed or ambiguous content and fell back to a best-effort count.",
                ),
                _ => (
                    "tone-danger",
                    "Warnings in this bucket need manual review because they do not match one of the common policy-based skip reasons.",
                ),
            };

            WarningSummaryRow {
                label: label.to_string(),
                count,
                tone_class: tone_class.to_string(),
                detail: detail.to_string(),
            }
        })
        .collect()
}

/// Classify an unsupported-language warning path into a named bucket.
fn classify_unsupported_path(path: &str) -> &'static str {
    let ext_lc = Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();

    if ext_lc == "md"
        || path.ends_with("README")
        || path.ends_with("README.md")
        || path.ends_with("LICENSE")
    {
        "Documentation / text"
    } else if ext_lc == "json" || path.ends_with(".spdx.json") || path.ends_with("devkit.json") {
        "JSON manifests and config"
    } else if ext_lc == "toml"
        || path.ends_with("MANIFEST.in")
        || path.ends_with("requirements.txt")
    {
        "Project metadata and packaging"
    } else if ext_lc == "html" {
        "HTML templates"
    } else if ext_lc == "txt" {
        "Plain text assets"
    } else if ext_lc.is_empty() {
        "Extensionless or custom text files"
    } else {
        "Other unsupported text formats"
    }
}

/// Map a bucket label to its recommendation string.
fn bucket_recommendation(label: &str) -> String {
    match label {
        "Documentation / text" => "These files are documentation, not source code. Add a docs/text exclude glob (e.g. **/*.md) or mark them as non-source in your config so they stop generating warnings.".to_string(),
        "JSON manifests and config" => "JSON config and manifest files are not source code. Exclude them with an ignore glob (e.g. **/*.json) or add them to excluded_directories so they are silently skipped.".to_string(),
        "Project metadata and packaging" => "TOML, requirements.txt, and MANIFEST.in files describe package metadata — not source. Add an exclude glob such as **/*.toml or list them in excluded_directories to suppress these warnings.".to_string(),
        "HTML templates" => "HTML is already a supported language. These files may have unusual extensions or be in a directory that is being excluded. Check that the files have a .html extension and are not inside an excluded path.".to_string(),
        "Plain text assets" => "Plain .txt files are not analyzed by default. If they contain source, rename them with a source extension. Otherwise add **/*.txt to your exclude globs.".to_string(),
        "Extensionless or custom text files" => "Files without an extension cannot be auto-detected. Add a shebang line (e.g. #!/usr/bin/env python3) so oxide-sloc can identify the language, or add an explicit language override in your config.".to_string(),
        _ => "Files in this group were not recognized. Check the file extensions and either add an exclude glob to silence the warning or open an issue to request analyzer support.".to_string(),
    }
}

/// Short human-readable description of what each bucket means.
fn bucket_description(label: &str) -> String {
    match label {
        "Documentation / text" => {
            "README, LICENSE, and markdown files — not source code.".to_string()
        }
        "JSON manifests and config" => {
            "JSON configuration or manifest files (package.json, lockfiles, etc.).".to_string()
        }
        "Project metadata and packaging" => {
            "TOML, requirements.txt, and MANIFEST.in files that describe package metadata."
                .to_string()
        }
        "HTML templates" => {
            "HTML files not covered by the built-in HTML analyzer (unexpected extension or path)."
                .to_string()
        }
        "Plain text assets" => "Plain .txt files that have no analyzable structure.".to_string(),
        "Extensionless or custom text files" => {
            "Files with no extension that could not be language-detected.".to_string()
        }
        _ => "Files with an unrecognized extension or format.".to_string(),
    }
}

fn build_support_opportunities(warnings: &[String]) -> Vec<WarningOpportunityRow> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut examples: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for warning in warnings {
        if !warning.contains("unsupported or undetected language") {
            continue;
        }

        let path = warning
            .split_once(':')
            .map(|(path, _)| path.trim())
            .unwrap_or_default();
        if path.is_empty() {
            continue;
        }

        let bucket = classify_unsupported_path(path);
        *counts.entry(bucket.to_string()).or_default() += 1;

        let ex = examples.entry(bucket.to_string()).or_default();
        if ex.len() < 3 {
            let basename = Path::new(path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(path)
                .to_string();
            if !ex.contains(&basename) {
                ex.push(basename);
            }
        }
    }

    let mut rows = counts.into_iter().collect::<Vec<_>>();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    rows.into_iter()
        .map(|(label, count)| {
            let recommendation = bucket_recommendation(&label);
            let bucket_description = bucket_description(&label);
            let example_files = examples.remove(&label).unwrap_or_default();
            WarningOpportunityRow {
                label,
                count,
                recommendation,
                example_files,
                bucket_description,
            }
        })
        .collect()
}

#[derive(Debug, Clone)]
struct LanguageRow {
    language: String,
    files: u64,
    total_physical_lines: u64,
    code_lines: u64,
    comment_lines: u64,
    blank_lines: u64,
    mixed_lines_separate: u64,
    functions: u64,
    classes: u64,
    variables: u64,
    imports: u64,
    test_count: u64,
    test_assertion_count: u64,
    test_suite_count: u64,
    test_density_str: String,
}

#[derive(Debug, Clone)]
struct FileRow {
    relative_path: String,
    language: String,
    total_physical_lines: u64,
    code_lines: u64,
    comment_lines: u64,
    blank_lines: u64,
    mixed_lines_separate: u64,
    functions: u64,
    classes: u64,
    variables: u64,
    imports: u64,
    test_count: u64,
    test_assertion_count: u64,
    test_suite_count: u64,
    /// Line coverage percentage, e.g. "96.7" — empty string when no coverage data.
    line_cov_pct: String,
    /// Function coverage percentage — empty string when no coverage data.
    fn_cov_pct: String,
    status: String,
    status_class: String,
    warnings: String,
}

#[derive(Debug, Clone)]
struct WarningSummaryRow {
    label: String,
    count: usize,
    tone_class: String,
    detail: String,
}

#[derive(Debug, Clone)]
struct WarningOpportunityRow {
    label: String,
    count: usize,
    recommendation: String,
    /// Up to 3 example file names (basename only) that triggered this bucket.
    example_files: Vec<String>,
    /// Short description of what this bucket means for the user.
    bucket_description: String,
}

#[derive(Template)]
#[template(
    source = r##"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{{ browser_title }}</title>
  <link rel="icon" href="{{ small_logo_uri }}" type="image/png" />
  <style nonce="{{ nonce }}">
    :root {
      --radius: 18px;
      --bg: #f5efe8;
      --surface: rgba(255,255,255,0.82);
      --surface-2: #fbf7f2;
      --surface-3: #efe6dc;
      --line: #e6d0bf;
      --line-strong: #dcb89f;
      --text: #43342d;
      --muted: #7b675b;
      --muted-2: #a08777;
      --nav: #b85d33;
      --nav-2: #7a371b;
      --accent: #6f9bff;
      --accent-2: #4a78ee;
      --oxide: #d37a4c;
      --oxide-2: #b35428;
      --shadow: 0 18px 42px rgba(77, 44, 20, 0.12);
      --shadow-strong: 0 22px 48px rgba(77, 44, 20, 0.16);
      --good-bg: #e8f5ed;
      --good-text: #1a8f47;
      --warn-bg: #fff4dc;
      --warn-text: #9a6d00;
      --danger-bg: #fdebec;
      --danger-text: #cc4b4b;
      --info-bg: #eef3ff;
      --info-text: #4467d8;
    }
    {% if let Some(hex) = accent_hex %}
    :root, body.dark-theme { --accent: {{ hex }}; --accent-2: {{ hex }}; }
    {% endif %}
    body.dark-theme {
      --bg: #1b1511;
      --surface: #261c17;
      --surface-2: #2d221d;
      --surface-3: #372922;
      --line: #524238;
      --line-strong: #6c5649;
      --text: #f5ece6;
      --muted: #c7b7aa;
      --muted-2: #aa9485;
      --nav: #b85d33;
      --nav-2: #7a371b;
      --accent: #6f9bff;
      --accent-2: #4a78ee;
      --oxide: #d37a4c;
      --oxide-2: #b35428;
      --shadow: 0 18px 42px rgba(0,0,0,0.28);
      --shadow-strong: 0 22px 48px rgba(0,0,0,0.34);
      --good-bg: #163927;
      --good-text: #8fe2a8;
      --warn-bg: #3c2d11;
      --warn-text: #f3cb75;
      --danger-bg: #3d1f1f;
      --danger-text: #ff9f9f;
      --info-bg: #1c2847;
      --info-text: #a9c1ff;
    }
    * { box-sizing: border-box; }
    html, body { margin: 0; min-height: 100vh; font-family: Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background: var(--bg); color: var(--text); }
    body { overflow-x: hidden; transition: background 0.18s ease, color 0.18s ease; }
    .top-nav { position: sticky; top: 0; z-index: 30; background: linear-gradient(180deg, var(--nav), var(--nav-2)); border-bottom: 1px solid rgba(255,255,255,0.12); box-shadow: 0 4px 14px rgba(0,0,0,0.18); }
    .top-nav-inner { max-width: 1720px; margin: 0 auto; padding: 4px 24px; min-height: 56px; display: grid; grid-template-columns: auto 1fr auto; align-items: center; gap: 18px; }
    .brand { display: flex; align-items: center; gap: 14px; min-width: 0; text-decoration: none; flex: 0 0 auto; }
    .brand-logo { width: 42px; height: 46px; object-fit: contain; flex: 0 0 auto; filter: drop-shadow(0 4px 10px rgba(0,0,0,0.22)); }
    .background-watermarks { position: fixed; inset: 0; pointer-events: none; z-index: 0; overflow: hidden; }
    .background-watermarks img { position: absolute; opacity: 0.15; filter: blur(0.3px); user-select: none; max-width: none; }
    .brand-copy { display: flex; flex-direction: column; justify-content: center; min-width: 0; }
    .brand-title { margin: 0; color: #fff; font-size: 17px; font-weight: 800; line-height: 1.1; }
    .brand-subtitle { color: rgba(255,255,255,0.85); font-size: 12px; line-height: 1.2; margin-top: 2px; }
    .nav-project-slot { display:flex; justify-content:center; min-width:0; }
    .nav-project-pill, .nav-pill, .theme-toggle, .header-button {
      display: inline-flex; align-items: center; gap: 8px; min-height: 38px; padding: 0 14px; border-radius: 999px; border: 1px solid rgba(255,255,255,0.18); color: #fff; background: rgba(255,255,255,0.10); font-size: 12px; font-weight: 700; box-shadow: inset 0 1px 0 rgba(255,255,255,0.08);
    }
    .nav-project-pill { pointer-events: auto; width: 100%; max-width: 280px; justify-content: center; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .nav-project-label { color: rgba(255,255,255,0.78); text-transform: uppercase; letter-spacing: 0.08em; font-size: 11px; font-weight: 800; }
    .nav-project-value { min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
    .nav-status { display:flex; align-items:center; justify-content:flex-end; gap:10px; flex-wrap:nowrap; min-width:0; }
    @media (max-width: 1400px) { .nav-status { gap: 6px; } .header-button, .theme-toggle { padding: 0 10px; } }
    @media (max-width: 1150px) { .nav-status { gap: 4px; } .header-button, .theme-toggle { padding: 0 8px; font-size: 11px; min-height: 34px; } .brand-subtitle { display: none; } }
    .theme-toggle, .header-button { cursor:pointer; background: rgba(255,255,255,0.08); text-decoration:none; }
    .theme-toggle { width: 38px; justify-content:center; padding:0; }
    .nav-dropdown-wrap { position: relative; }
    .nav-dropdown-wrap::after { content: ''; position: absolute; left: 0; right: 0; bottom: -6px; height: 6px; }
    .nav-dropdown-trigger { }
    .nav-dropdown-menu { display: none; position: absolute; top: 100%; right: 0; background: var(--nav-2); border: 1px solid rgba(255,255,255,0.15); border-radius: 10px; min-width: 140px; padding: 6px; z-index: 50; box-shadow: 0 8px 24px rgba(0,0,0,0.28); }
    .nav-dropdown-wrap:hover .nav-dropdown-menu, .nav-dropdown-wrap:focus-within .nav-dropdown-menu { display: flex; flex-direction: column; gap: 2px; }
    .nav-dropdown-item { display: block; width: 100%; padding: 8px 12px; border: none; border-radius: 7px; background: transparent; color: #fff; font-size: 13px; font-weight: 700; text-align: left; cursor: pointer; }
    .nav-dropdown-item:hover { background: rgba(255,255,255,0.12); }
    .theme-toggle svg { width: 18px; height: 18px; stroke: currentColor; fill: none; stroke-width: 1.8; }
    .theme-toggle .icon-sun { display:none; }
    body.dark-theme .theme-toggle .icon-sun { display:block; }
    body.dark-theme .theme-toggle .icon-moon { display:none; }
    .settings-modal{position:fixed;z-index:9999;background:var(--surface);border:1px solid var(--line-strong);border-radius:14px;box-shadow:0 12px 36px rgba(0,0,0,0.22);min-width:260px;max-width:320px;opacity:0;pointer-events:none;transform:translateY(-8px) scale(0.97);transition:opacity 0.18s ease,transform 0.18s ease;overflow:hidden;}
    .settings-modal.open{opacity:1;pointer-events:auto;transform:translateY(0) scale(1);}
    .settings-modal-header{display:flex;align-items:center;justify-content:space-between;padding:14px 16px 10px;border-bottom:1px solid var(--line);font-size:13px;font-weight:800;color:var(--text);}
    .settings-close{background:none;border:none;cursor:pointer;width:24px;height:24px;display:flex;align-items:center;justify-content:center;color:var(--muted);border-radius:6px;padding:0;}
    .settings-close:hover{color:var(--text);background:var(--surface-2);}
    .settings-close svg{width:14px;height:14px;stroke:currentColor;fill:none;stroke-width:2.5;}
    .settings-modal-body{padding:14px 16px 16px;}
    .settings-modal-label{font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:0.08em;color:var(--muted-2);margin-bottom:10px;}
    .scheme-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:8px;}
    .scheme-swatch{display:flex;flex-direction:column;align-items:center;gap:5px;background:none;border:1.5px solid var(--line);border-radius:10px;cursor:pointer;padding:7px 4px 6px;transition:border-color 0.15s ease,transform 0.12s ease;}
    .scheme-swatch:hover{border-color:var(--line-strong);transform:translateY(-1px);}
    .scheme-swatch.active{border-color:#6f9bff;box-shadow:0 0 0 2px rgba(111,155,255,0.25);}
    .scheme-preview{width:28px;height:28px;border-radius:7px;flex-shrink:0;}
    .scheme-label{font-size:9px;font-weight:700;color:var(--muted-2);white-space:nowrap;}
    .tz-select{width:100%;padding:6px 8px;border:1px solid var(--line);border-radius:8px;background:var(--surface-2);color:var(--text);font-size:12px;font-weight:600;cursor:pointer;outline:none;box-sizing:border-box;}
    .tz-select:focus{border-color:var(--oxide);}
    .page { max-width: 1720px; margin: 0 auto; padding: 32px 24px 40px; }
    .summary-grid { display:grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap:10px; }
    .panel, .metric, .warning-card { background: var(--surface); border: 1px solid var(--line); border-radius: var(--radius); box-shadow: var(--shadow); }
    .panel { padding: 20px; }
    .metric { padding: 11px 12px 20px; position: relative; cursor: help; transition: transform 0.15s ease, box-shadow 0.15s ease; min-height: 70px; }
    .metric:hover { transform: translateY(-3px); box-shadow: var(--shadow-strong); }
    .metric-label { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.07em; color: var(--muted); }
    .section-kicker { font-size: 10px; font-weight: 800; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted-2); }
    .metric-value { margin-top: 6px; }
    .metric-big { display:block; font-size: 20px; font-weight: 900; color: var(--oxide); line-height: 1.15; letter-spacing: -0.02em; }
    .metric-exact { position: absolute; bottom: 6px; right: 10px; font-size: 12px; font-weight: 600; color: var(--muted); font-family: ui-monospace, monospace; }
    .metric-tooltip { position: absolute; bottom: calc(100% + 10px); left: 50%; transform: translateX(-50%); background: var(--text); color: var(--bg); padding: 8px 12px; border-radius: 10px; font-size: 12px; font-weight: 500; line-height: 1.45; white-space: normal; max-width: 220px; text-align: center; pointer-events: none; opacity: 0; transition: opacity 0.18s ease; z-index: 100; box-shadow: 0 4px 14px rgba(0,0,0,0.22); }
    .metric-tooltip::after { content: ''; position: absolute; top: 100%; left: 50%; transform: translateX(-50%); border: 5px solid transparent; border-top-color: var(--text); }
    .metric:hover .metric-tooltip { opacity: 1; }
    .hero { padding: 24px 24px 20px; margin-bottom: 18px; background: linear-gradient(150deg, rgba(111,155,255,0.06) 0%, transparent 55%), var(--surface); border-top: 3px solid var(--accent); }
    .hero-top { display:flex; justify-content:space-between; align-items:flex-start; gap:16px; }
    .hero h1 { margin:0 0 8px; font-size: 28px; letter-spacing: -0.04em; }
    .run-id-row { display:grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap:10px; margin-top:16px; }
    @media(max-width:960px) { .run-id-row { grid-template-columns: 1fr 1fr; } }
    @media(max-width:560px) { .run-id-row { grid-template-columns: 1fr; } }
    .run-id-chip { display:flex; flex-direction:column; gap:5px; padding:12px 14px; border-radius:10px; background:var(--surface-2); border:1px solid var(--line); border-left:3px solid var(--accent); color:var(--text); position:relative; cursor:default; transition:transform 0.18s ease, box-shadow 0.18s ease; }
    .run-id-chip[data-copy] { cursor:pointer; }
    .run-id-chip:hover { transform:translateY(-3px); box-shadow:0 8px 24px rgba(0,0,0,0.15); z-index:10; }
    .run-id-chip.muted-chip { border-left-color:var(--line-strong); }
    .run-id-chip-label { font-size:10px; font-weight:900; text-transform:uppercase; letter-spacing:0.1em; color:var(--accent); }
    .run-id-chip.muted-chip .run-id-chip-label { color:var(--muted-2); }
    .run-id-chip-value { font-family:ui-monospace,monospace; font-size:12px; font-weight:700; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
    .run-id-chip.muted-chip .run-id-chip-value { color:var(--muted); font-style:italic; }
    .chip-tooltip { position:absolute; top:calc(100% + 8px); left:50%; transform:translateX(-50%); background:var(--text); color:var(--bg); padding:6px 11px; border-radius:8px; font-size:11px; font-weight:500; white-space:nowrap; pointer-events:none; opacity:0; transition:opacity 0.18s ease; z-index:200; box-shadow:0 4px 16px rgba(0,0,0,0.25); line-height:1.4; }
    .chip-tooltip::before { content:''; position:absolute; bottom:100%; left:50%; transform:translateX(-50%); border:5px solid transparent; border-bottom-color:var(--text); }
    .run-id-chip:hover .chip-tooltip { opacity:1; }
    .chip-copy-icon { display:inline-block; margin-left:5px; font-size:10px; opacity:0.55; vertical-align:middle; }
    .chip-label-icon { display:inline-block; vertical-align:middle; margin-right:3px; margin-top:-1px; opacity:0.8; }
    .run-id-short-badge { font-family:ui-monospace,monospace; font-size:13px; font-weight:700; color:var(--muted); background:var(--surface-2); border:1px solid var(--line); border-radius:6px; padding:2px 8px; letter-spacing:0.04em; white-space:nowrap; vertical-align:middle; }
    body.dark-theme .run-id-short-badge { color:var(--muted-2); }
    .author-handle { font-size:11px; font-weight:600; color:var(--muted-2); margin-left:1.5em; font-family:ui-monospace,monospace; }
    @keyframes chip-flash { 0%{background:var(--accent);color:#fff;} 80%{background:var(--accent);color:#fff;} 100%{background:var(--surface-2);color:var(--text);} }
    .chip-copied-flash { animation:chip-flash 0.9s ease forwards; }
    .subtitle { margin: 10px 0 0; color: var(--muted); font-size: 16px; line-height: 1.65; }
    .meta { display:flex; flex-wrap:wrap; align-items:center; gap:0; margin:14px 0 20px; padding:10px 0; border-top:1px solid var(--line); border-bottom:1px solid var(--line); width:100%; }
    .meta-chip { flex:1; display:inline-flex; align-items:center; justify-content:center; gap:5px; padding:0 10px; font-size:13px; font-weight:500; color:var(--muted); border-right:1px solid var(--line); line-height:1.8; }
    .meta-chip:last-child { border-right:none; }
    .meta-chip b { color:var(--text); font-weight:700; }
    .soft-chip { display:inline-flex; align-items:center; min-height:32px; padding:0 12px; border-radius:999px; border:1px solid var(--line); background:var(--surface-2); color:var(--text); font-size:13px; font-weight:700; }
    .toolbar { display:flex; flex-wrap:wrap; justify-content:space-between; gap: 12px; align-items: center; margin-bottom: 16px; }
    .toolbar-left { display:flex; gap:10px; align-items:center; flex-wrap:wrap; }
    .search { min-width: 280px; padding: 10px 12px; border-radius: 10px; border:1px solid var(--line-strong); background: var(--surface-2); color:var(--text); }
    .pill-row { display:flex; gap:8px; flex-wrap:wrap; }
    .pill { padding: 6px 10px; border-radius: 999px; border:1px solid var(--line); background: var(--surface-2); font-size: 12px; font-weight: 700; }
    .pill.good { background: var(--good-bg); color: var(--good-text); }
    .pill.info { background: var(--info-bg); color: var(--info-text); }
    .export-group { display:flex; gap:6px; align-items:center; }
    .export-btn { display:inline-flex; align-items:center; gap:5px; padding:6px 12px; border-radius:8px; border:1px solid var(--line-strong); background:var(--surface-2); color:var(--text); font-size:12px; font-weight:700; cursor:pointer; white-space:nowrap; }
    .export-btn:hover { background:var(--accent); color:#fff; border-color:var(--accent); }
    .page-size-row { display:flex; align-items:center; gap:6px; }
    .page-size-label { font-size:13px; color:var(--muted); font-weight:600; }
    .page-size-select { padding:5px 10px; border-radius:8px; border:1px solid var(--line-strong); background:var(--surface-2); color:var(--text); font-size:13px; font-weight:700; cursor:pointer; }
    .page-count-label { font-size:12px; color:var(--muted); white-space:nowrap; }
    .pagination-bar { display:flex; align-items:center; justify-content:center; gap:14px; padding:10px 0 2px; }
    .pager-btn { padding:6px 16px; border-radius:8px; border:1px solid var(--line-strong); background:var(--surface-2); color:var(--text); font-size:13px; font-weight:700; cursor:pointer; transition:background .15s,color .15s; }
    .pager-btn:hover:not(:disabled) { background:var(--accent); color:#fff; border-color:var(--accent); }
    .pager-btn:disabled { opacity:.4; cursor:default; }
    .pager-info { font-size:13px; color:var(--muted); font-weight:600; min-width:180px; text-align:center; }
    .table-shell { border: 1px solid var(--line); border-radius: 16px; overflow: auto; background: var(--surface-2); max-height: 900px; }
    /* Clip wrapper: hides the scrollbar track that hangs 8px past the right edge */
    .table-shell-clip { overflow: hidden !important; max-height: none !important; }
    /* Skipped-files scroll pane: auto so no phantom space when content is short */
    #skipped-shell { overflow-y: auto; overflow-x: hidden; scrollbar-width: thin; scrollbar-color: var(--line-strong) var(--surface-2); }
    #per-file-table tbody tr:last-child td, #skipped-table tbody tr:last-child td { border-bottom: none; }
    #skipped-shell::-webkit-scrollbar { width: 8px; }
    #skipped-shell::-webkit-scrollbar-track { background: var(--surface-2); }
    #skipped-shell::-webkit-scrollbar-thumb { background: var(--line-strong); border-radius: 4px; }
    table { width: 100%; border-collapse: collapse; font-size: 14px; }
    th, td { text-align: left; padding: 11px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
    th { color: var(--muted); font-weight: 800; background: var(--surface-2); cursor: pointer; position: sticky; top: 0; z-index: 1; white-space: nowrap; }
    /* Per-file detail table — auto layout so File column sizes to content */
    .table-resizable { table-layout: auto; }
    .table-resizable th { position: sticky; top: 0; z-index: 2; overflow: hidden; white-space: nowrap; min-width: 52px; }
    .table-resizable td { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .table-resizable td.mono { overflow: visible; text-overflow: unset; white-space: nowrap; }
    #skipped-table { table-layout: fixed; width: 100%; }
    #skipped-table th, #skipped-table td { padding: 7px 8px; }
    #skipped-table td:first-child { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    /* Column resize handle */
    .col-resize-handle { position: absolute; top: 0; right: 0; bottom: 0; width: 6px; cursor: col-resize; z-index: 10; }
    .col-resize-handle:hover, .col-resize-handle.dragging { background: rgba(211,122,76,0.3); }
    #per-file-table { table-layout: fixed; width: 100%; min-width: 0; }
    #per-file-table th, #per-file-table td { padding: 8px 6px; }
    /* File column: pinned, truncates long paths */
    #per-file-table th:first-child { position: sticky; top: 0; left: 0; z-index: 3; width: 26%; background: var(--surface-2); padding: 8px 6px; overflow: hidden; text-overflow: ellipsis; }
    #per-file-table td:first-child { position: sticky; left: 0; z-index: 1; background: var(--surface-2); padding: 8px 6px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    #per-file-table th:nth-child(2) { width: 6%; }
    /* 12 numeric columns share the remaining 68%: 26+6+12×5.67≈98% total */
    #per-file-table th:nth-child(n+3) { width: 5.67%; }
    /* Override mono class overflow so file paths truncate */
    #per-file-table td.mono { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    #per-file-table tbody tr:hover td:first-child { background: rgba(255,247,238,0.6); }
    body.dark-theme #per-file-table tbody tr:hover td:first-child { background: rgba(255,255,255,0.03); }
    /* Language breakdown: fixed layout keeps every column at its declared width */
    #lang-breakdown-table { table-layout: fixed; width: 100%; }
    #lang-breakdown-table th:first-child { width: 18%; }
    #lang-breakdown-table td { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 0; }
    /* Skipped table: extend truncation to all cells, not just the first column */
    #skipped-table td { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 0; }
    /* Support opportunities table: fixed layout so Category/Count columns don't grow */
    .support-table { table-layout: fixed; width: 100%; }
    .support-table th:first-child { width: 20%; }
    .support-table th:nth-child(2) { width: 6%; }
    .support-table th:nth-child(3) { width: 24%; }
    .support-table td { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 0; vertical-align: top; padding-top: 10px; padding-bottom: 10px; }
    /* Description and example columns must wrap — content can be long */
    .support-table td:nth-child(3) { white-space: normal; overflow: visible; text-overflow: unset; max-width: none; line-height: 1.45; }
    .support-table td:last-child { white-space: normal; overflow: visible; text-overflow: unset; max-width: none; }
    .support-example-file { display: inline-block; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 11px; padding: 1px 6px; background: var(--surface); border: 1px solid var(--line); border-radius: 4px; margin-bottom: 2px; word-break: break-all; }
    .support-recommendation { color: var(--muted); font-size: 11px; margin: 6px 0 0; line-height: 1.5; }
    .num-col { text-align: right !important; }
    tbody tr:hover { background: rgba(255, 247, 238, 0.6); }
    body.dark-theme tbody tr:hover { background: rgba(255,255,255,0.03); }
    tr:last-child td { border-bottom: none; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
    .small { color: var(--muted); font-size: 13px; }
    .status-tag { display:inline-flex; align-items:center; padding: 4px 8px; border-radius: 999px; border:1px solid var(--line); background: var(--surface-2); font-size: 12px; font-weight: 700; }
    .status-analyzedexact { background: var(--good-bg); color: var(--good-text); border-color: rgba(28,135,70,0.18); }
    .status-analyzedbesteffort, .status-skippedbypolicy { background: var(--warn-bg); color: var(--warn-text); border-color: rgba(146,96,0,0.18); }
    .status-skippedunsupported, .status-skippedbinary { background: var(--danger-bg); color: var(--danger-text); border-color: rgba(179,59,59,0.18); }
    .stack { display:grid; gap:22px; }
    .summary-strip { display:grid; grid-template-columns:repeat(4,1fr); gap:14px; margin-bottom:18px; }
    @media(max-width:800px) { .summary-strip { grid-template-columns:repeat(2,1fr) !important; } }
    .test-density-row { display:flex; align-items:center; gap:12px; margin-bottom:16px; padding:10px 16px; border-radius:10px; background:var(--surface-2); border:1px solid var(--line); }
    .test-density-num { font-size:22px; font-weight:900; color:var(--oxide); line-height:1; }
    .test-density-meta { display:flex; flex-direction:column; gap:2px; }
    .test-density-label { font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:.07em; color:var(--muted); }
    .test-density-sub { font-size:11px; color:var(--muted-2); }
    .test-density-badge { margin-left:auto; padding:4px 12px; border-radius:999px; font-size:12px; font-weight:700; }
    .test-density-badge.good { background:var(--good-bg); color:var(--good-text); }
    .test-density-badge.warn { background:var(--warn-bg); color:var(--warn-text); }
    .test-density-badge.danger { background:var(--danger-bg); color:var(--danger-text); }
    .info-callout { display:flex; align-items:flex-start; gap:10px; margin-top:14px; padding:11px 14px; border-radius:10px; background:var(--info-bg); border:1px solid rgba(68,103,216,0.18); color:var(--info-text); font-size:13px; line-height:1.5; }
    .info-callout-icon { flex:0 0 auto; font-size:15px; margin-top:1px; }
    .info-callout code { background:rgba(68,103,216,0.12); border-radius:4px; padding:1px 5px; font-size:12px; }
    body.dark-theme .info-callout { background:rgba(100,130,255,0.09); border-color:rgba(100,130,255,0.22); }
    .empty-state-row td { text-align:center; padding:20px; color:var(--muted-2); font-size:13px; font-style:italic; }
    .cov-gauge-row { display:grid; grid-template-columns:repeat(3,1fr); gap:16px; margin-bottom:18px; }
    @media(max-width:700px) { .cov-gauge-row { grid-template-columns:1fr; } }
    .cov-gauge-card { background:var(--surface); border:1px solid var(--line); border-radius:12px; padding:18px 20px; display:flex; flex-direction:column; gap:8px; transition:transform .2s ease,box-shadow .2s ease; min-width:0; }
    .cov-gauge-card:hover { transform:translateY(-3px); box-shadow:0 10px 28px rgba(77,44,20,0.15); }
    .cov-gauge-label { font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:.07em; color:var(--muted); }
    .cov-gauge-val { font-size:32px; font-weight:900; line-height:1; }
    .cov-gauge-track { height:8px; border-radius:4px; background:var(--line); overflow:hidden; }
    .cov-gauge-fill { height:100%; border-radius:4px; transition:width .5s ease; }
    .cov-gauge-sub { font-size:11px; color:var(--muted); }
    .stat-chip { background:var(--surface); border:1px solid var(--line); border-radius:12px; padding:14px 16px; position:relative; cursor:default; transition:transform .2s ease,box-shadow .2s ease; }
    .stat-chip:hover { transform:translateY(-4px); box-shadow:0 12px 32px rgba(77,44,20,0.2); z-index:10; }
    .stat-chip-val { font-size:20px; font-weight:900; color:var(--oxide); }
    .stat-chip-label { font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:.07em; color:var(--muted); margin-top:4px; }
    .stat-chip-tip { position:absolute; top:calc(100% + 10px); left:50%; transform:translateX(-50%); background:var(--text); color:var(--bg); padding:7px 12px; border-radius:8px; font-size:11px; font-weight:500; line-height:1.4; white-space:nowrap; pointer-events:none; opacity:0; transition:opacity .2s ease; z-index:200; box-shadow:0 4px 14px rgba(0,0,0,0.2); }
    .stat-chip-tip::after { content:''; position:absolute; bottom:100%; left:50%; transform:translateX(-50%); border:5px solid transparent; border-bottom-color:var(--text); }
    .stat-chip:hover .stat-chip-tip { opacity:1; }
    .stat-chip-exact { position:absolute; bottom:6px; right:10px; font-size:12px; font-weight:600; color:var(--muted); font-variant-numeric:tabular-nums; line-height:1; }
    .report-stack { display:grid; gap: 18px; align-items:start; }
    pre { background: var(--surface-2); border: 1px solid var(--line); border-radius: 16px; padding: 16px; overflow: auto; font-size: 12px; color: var(--text); }
    .warn-list { margin: 0; padding-left: 18px; line-height: 1.6; }
    .sort-indicator { color: var(--muted-2); font-size: 11px; margin-left: 6px; }
    .warning-grid { display:grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; }
    .warning-card { padding: 10px 12px; }
    .warning-card h3 { margin: 0 0 4px; font-size: 12px; font-weight: 700; }
    .warning-card .count { font-size: 16px; font-weight: 800; margin-bottom: 4px; }
    .tone-neutral .count { color: var(--text); }
    .tone-warn .count { color: var(--warn-text); }
    .tone-danger .count { color: var(--danger-text); }
    .tone-neutral .warning-count { color: var(--oxide); }
    .tone-warn .warning-count { color: var(--warn-text); }
    .tone-danger .warning-count { color: var(--danger-text); }
    .support-note { color: var(--muted); font-size: 11px; line-height: 1.45; }
    .support-table th { cursor: default; }
    details { border: 1px solid var(--line); border-radius: 14px; background: var(--surface-2); }
    summary { cursor: pointer; padding: 14px 16px; font-weight: 700; }
    details > div { padding: 0 16px 16px; }
    .warning-console { margin: 0; padding: 14px 16px; border-radius: 12px; border:1px solid var(--line); background: #16120f; color: #d4f0d0; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; white-space: pre-wrap; line-height: 1.55; max-height: 260px; overflow: auto; }
    .warning-console-actions { display:flex; gap:10px; flex-wrap:wrap; margin-top: 12px; }
    .warning-console.hidden { display:none; }
    @media (max-width: 1200px) {
      .summary-grid, .warning-grid { grid-template-columns: 1fr 1fr; }
    }
    @media (max-width: 960px) {
      .top-nav-inner { grid-template-columns: 1fr; }
      .nav-project-slot, .nav-status { justify-content:flex-start; }
      .summary-grid, .warning-grid, .report-stack { grid-template-columns: 1fr; }
      .hero-top { flex-direction: column; }
      .search { min-width: 100%; width: 100%; }
    }
    /* ── Report header / footer identification banner ─────────────────── */
    .report-id-banner { background: var(--nav); color: #fff; font-size: 11px; font-weight: 700; letter-spacing: 0.05em; text-align: center; height: 27px; line-height: 27px; padding: 0 16px; position: fixed; top: 0; left: 0; right: 0; z-index: 32; width: 100%; }
    .report-id-footer-banner { background: var(--nav); color: #fff; font-size: 11px; font-weight: 700; letter-spacing: 0.05em; text-align: center; height: 27px; line-height: 27px; padding: 0 16px; position: fixed; bottom: 0; left: 0; right: 0; z-index: 32; width: 100%; }
    body.has-report-banner .top-nav { top: 27px; }
    body.has-report-banner { padding-bottom: 27px; }
    /* ── Print & PDF export ──────────────────────────────────────────── */
    @page { size: A4 landscape; margin: 0.35in 0.5in; }

    @media print {
      *, *::before, *::after {
        -webkit-print-color-adjust: exact !important;
        print-color-adjust: exact !important;
        box-sizing: border-box !important;
      }

      html, body {
        background: #f5efe8 !important;
        min-height: auto !important;
        width: 100% !important;
      }

      /* Report id banner — fixed position repeats the banner on every printed page */
      .report-id-banner { position: fixed !important; top: 0 !important; left: 0 !important; right: 0 !important; width: 100% !important; padding: 3px 12px !important; font-size: 10px !important; background: #3d3d3d !important; color: #fff !important; z-index: 9999 !important; }
      .report-id-footer-banner { display: block !important; position: fixed !important; bottom: 0 !important; left: 0 !important; right: 0 !important; width: 100% !important; padding: 3px 12px !important; font-size: 10px !important; margin-top: 0 !important; background: #3d3d3d !important; color: #fff !important; z-index: 9999 !important; }
      body.has-report-banner .top-nav { top: 0 !important; }
      body.has-report-banner { padding-bottom: 0 !important; }
      /* Hide interactive UI-chrome; keep section heading text visible */
      .top-nav, .hero-actions,
      .background-watermarks,
      .header-button, .theme-toggle,
      .nav-dropdown-wrap, .config-actions,
      .warnings-show-link, .warning-console-actions,
      .toolbar .pill-row, .toolbar .export-group,
      input[type="search"], button { display: none !important; }
      /* Show toolbar as a plain block so h2 headings are visible */
      .toolbar { display: block !important; margin-bottom: 8px !important; }
      .toolbar-left { display: block !important; }

      /* Remove page-level layout constraints */
      .page {
        max-width: none !important;
        width: 100% !important;
        padding: 0 !important;
        margin: 0 !important;
      }

      .panel, .hero, .section,
      .saved-report-shell, .saved-panel, .report-shell, .stack {
        max-width: none !important;
        width: 100% !important;
        box-shadow: none !important;
        border: 1px solid #ddd !important;
        border-radius: 10px !important;
        margin-bottom: 10px !important;
        overflow: visible !important;
      }

      /* Force grids to their full-width column counts regardless of viewport */
      .summary-grid {
        display: grid !important;
        grid-template-columns: repeat(5, minmax(0, 1fr)) !important;
        gap: 10px !important;
      }

      .warning-grid {
        display: grid !important;
        grid-template-columns: repeat(3, minmax(0, 1fr)) !important;
        gap: 8px !important;
      }

      .report-stack {
        display: grid !important;
        gap: 12px !important;
        align-items: start !important;
      }

      /* Metric cards */
      .metric {
        box-shadow: none !important;
        border: 1px solid #e0d0c0 !important;
        border-radius: 8px !important;
        break-inside: avoid !important;
        padding: 10px 12px 22px !important;
        min-height: 0 !important;
      }

      .metric-big { font-size: 20px !important; }
      .metric-exact { font-size: 10px !important; bottom: 5px !important; right: 8px !important; }
      .metric-label { font-size: 10px !important; }

      /* Page break control — small atomic cards stay together; large panels
         and tables flow freely so they never force blank pages. */
      .metric, .warning-card, .run-id-chip { break-inside: avoid !important; }
      .hero, .panel, .stack { break-inside: auto !important; }
      section { break-inside: auto !important; }
      /* Keep each chart panel whole — browser moves it to the next page rather than
         slicing through the middle of a canvas. */
      .chart-section { break-inside: avoid !important; }
      /* Keep the summary grid on the same page as the hero header when possible */
      .summary-grid { break-before: avoid !important; }
      /* Section headings never orphan at the bottom of a page */
      h2, h3 { break-after: avoid !important; orphans: 3; widows: 3; }
      /* Keep the first few rows of a table with the header */
      thead { break-after: avoid !important; }

      /* Language charts — table layout is inherently side-by-side */
      #lang-overview-charts table { display: inline-table !important; }
      #lang-overview-charts td { vertical-align: top !important; }

      /* Tables */
      .table-shell {
        max-height: none !important;
        overflow: visible !important;
        width: 100% !important;
        break-inside: auto !important;
      }

      table {
        width: 100% !important;
        table-layout: auto !important;
        font-size: 10px !important;
        border-collapse: collapse !important;
        orphans: 4 !important;
        widows: 4 !important;
      }

      /* Remove the screen-layout min-width so tables scale to page width */
      #per-file-table, #skipped-table { min-width: 0 !important; }
      /* Release sticky column positioning (not meaningful on paper) */
      #per-file-table th:first-child,
      #per-file-table td:first-child { position: static !important; }
      /* Show ALL rows — JS pagination hides rows via inline style; !important overrides it */
      #per-file-table tbody tr, #skipped-table tbody tr { display: table-row !important; }
      /* Hide pagination controls — not interactive in PDF */
      .page-size-row, .pagination-bar { display: none !important; }

      thead { display: table-header-group; }
      tr { break-inside: avoid !important; }

      th {
        position: relative !important;
        font-size: 9px !important;
        font-weight: 700 !important;
        color: #333 !important;
        padding: 5px 8px !important;
        background: rgba(211,122,76,0.18) !important;
        white-space: normal !important;
      }
      /* Resize handles are screen-only — hide them in print */
      .col-resize-handle { display: none !important; }
      /* Sort indicators are redundant on paper */
      .sort-indicator { display: none !important; }

      td {
        white-space: normal !important;
        overflow-wrap: anywhere !important;
        word-break: break-word !important;
        padding: 5px 8px !important;
        font-size: 10px !important;
        border-bottom: 1px solid #e8d8c8 !important;
      }

      pre, code {
        white-space: pre-wrap !important;
        overflow-wrap: anywhere !important;
        word-break: break-word !important;
        font-size: 9px !important;
        max-height: none !important;
      }

      .warning-card {
        box-shadow: none !important;
        border: 1px solid #ddd !important;
        break-inside: avoid !important;
        padding: 10px !important;
      }

      .hero-top { flex-direction: row !important; }

      .run-id-row { flex-wrap: wrap !important; gap: 4px !important; }
      .run-id-chip { font-size: 9px !important; padding: 4px 8px !important; border-left-width: 2px !important; }
      .meta { flex-wrap: wrap !important; gap: 0 !important; padding: 4px 0 !important; border-top: 1px solid #ccc !important; border-bottom: 1px solid #ccc !important; width: 100% !important; }
      .meta-chip { flex: 1 !important; justify-content: center !important; font-size: 9px !important; padding: 0 8px !important; border-right: 1px solid #ccc !important; }
      .meta-chip:last-child { border-right: none !important; }

      .report-footer {
        border-top: 1px solid #ccc !important;
        margin-top: 12px !important;
        font-size: 10px !important;
      }

      /* Collapse all <details> in print except the warnings block */
      details { border: 1px solid #ddd !important; border-radius: 8px !important; }
      details > summary { display: block !important; font-size: 10px !important; }
      details > div { display: none !important; }
      .warning-console { display: none !important; }
      .warning-console-actions { display: none !important; }
      /* Always expand the run-warnings details in PDF */
      details.warnings-details > div { display: block !important; }
      details.warnings-details .warning-console {
        display: block !important;
        max-height: none !important;
        overflow: visible !important;
        font-size: 8px !important;
        white-space: pre-wrap !important;
        word-break: break-all !important;
      }
      details.warnings-details .code-block-toolbar { display: none !important; }

      /* Pill badges */
      .pill { font-size: 9px !important; padding: 2px 6px !important; min-height: auto !important; }

      /* Support opportunities table */
      .support-table td:first-child { font-weight: 600; font-size: 10px !important; }

      /* Hide canvas-based interactive chart sections; replaced by pre-rendered variants */
      .chart-section { display: none !important; }
      .charts-grid   { display: none !important; }
      /* Pre-rendered chart variants — no forced page break; flow naturally after hero section */
      .pdf-variants-root { display: block !important; padding: 0 !important; }
      .pdf-variant-group { break-inside: auto !important; margin-bottom: 8px !important; background: #faf6f0 !important; border: 1px solid #e0d0c0 !important; border-radius: 10px !important; padding: 10px 12px !important; }
      .pdf-variant-group-title { break-after: avoid !important; font-size: 12px !important; font-weight: 800 !important; color: #3d2d26 !important; margin: 0 0 6px !important; padding-bottom: 4px !important; border-bottom: 2px solid #d37a4c !important; }
      .pdf-variant-grid { display: grid !important; grid-template-columns: 1fr 1fr !important; gap: 6px !important; }
      /* Single-column chart (scatter, etc.) — centre and constrain width in print */
      .pdf-variant-grid.single-col { grid-template-columns: 1fr !important; }
      .pdf-variant-grid.single-col .pdf-variant-panel { max-width: 62% !important; margin: 0 auto !important; }
      .pdf-variant-panel { break-inside: avoid !important; }
      .pdf-variant-label { font-size: 9px !important; font-weight: 700 !important; text-transform: uppercase !important; letter-spacing: .06em !important; color: #7b675b !important; margin: 0 0 2px !important; }
      .pdf-variant-img { width: 100% !important; height: auto !important; display: block !important; border-radius: 5px !important; border: 1px solid #ddd !important; }
    }


    .warnings-show-link {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 8px 12px;
      border-radius: 10px;
      border: 1px solid rgba(111, 144, 255, 0.35);
      background: #eef3ff;
      color: #2f5fe3 !important;
      font-weight: 800;
      text-decoration: none;
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.45);
    }

    body.dark-theme .warnings-show-link {
      background: #1c2847;
      color: #a9c1ff !important;
      border-color: rgba(169, 193, 255, 0.32);
    }

    .effective-config-note {
      margin: 8px 0 0;
      color: var(--muted);
      font-size: 14px;
      line-height: 1.6;
    }
    .config-actions { display: flex; gap: 8px; flex-shrink: 0; }
    .config-pre-wrap { position: relative; }
    .config-pre { margin: 0; background: #16120f; color: #d4f0d0; border: 1px solid var(--line); border-radius: 10px; padding: 14px 16px; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; line-height: 1.5; overflow: auto; resize: vertical; max-height: 320px; min-height: 100px; white-space: pre; }
    body.dark-theme .config-pre { background: #0e0c0a; color: #b8f0b8; }
    .code-block-toolbar { display:flex; justify-content:flex-end; margin-bottom:6px; }
    .code-copy-btn { background: var(--surface); border: 1px solid var(--line); color: var(--text); border-radius: 7px; padding: 4px 12px; font-size: 11px; font-weight: 700; cursor: pointer; transition: background 0.15s ease; }
    .code-copy-btn:hover { background: var(--line); }
    body.dark-theme .code-copy-btn { background: #1e1a16; border-color: rgba(255,255,255,0.18); color: #d4f0d0; }
    body.dark-theme .code-copy-btn:hover { background: rgba(255,255,255,0.12); }


    .page {
      position: relative;
      z-index: 1;
    }
    .report-footer { margin-top: 32px; padding: 14px 24px; border-top: 1px solid var(--line); text-align: center; color: var(--muted); font-size: 12px; font-weight: 600; }

    /* ── Chart controls & containers ───────────────────────────────────── */
    .chart-section { }
    .chart-controls { display:flex; gap:12px; align-items:center; flex-wrap:wrap; margin-bottom:14px; }
    .chart-controls label { font-size:13px; font-weight:700; color:var(--muted); display:flex; align-items:center; gap:6px; }
    .chart-select { background:var(--surface-2); border:1px solid var(--line-strong); border-radius:8px; padding:5px 10px; color:var(--text); font-size:13px; font-weight:600; cursor:pointer; outline:none; appearance:auto; }
    .chart-select:focus { border-color:var(--accent); }
    .chart-expand-btn { background:none; border:1px solid var(--line-strong); border-radius:6px; cursor:pointer; color:var(--muted); padding:4px 10px; font-size:13px; line-height:1; transition:background .13s,color .13s; }
    .chart-expand-btn:hover { background:var(--surface-2); color:var(--text); }
    .chart-modal-overlay { position:fixed; inset:0; background:rgba(0,0,0,0.55); z-index:9999; display:flex; align-items:center; justify-content:center; padding:24px; box-sizing:border-box; }
    .chart-modal { background:var(--bg); border-radius:16px; padding:24px 28px; max-width:1000px; width:100%; max-height:88vh; overflow-y:auto; position:relative; box-shadow:0 24px 80px rgba(0,0,0,0.3); }
    .chart-modal-title { font-size:15px; font-weight:800; text-transform:uppercase; letter-spacing:.05em; color:var(--text); margin:0 0 2px; display:block; }
    .chart-modal-subtitle { font-size:13px; font-weight:600; color:var(--muted); margin:0 0 16px; display:block; letter-spacing:.02em; }
    .chart-modal-close { position:absolute; top:14px; right:18px; background:none; border:none; font-size:22px; cursor:pointer; color:var(--text); line-height:1; padding:0; }
    .chart-modal-close:hover { opacity:.7; }
    body.dark-theme .chart-modal { background:var(--surface); }
    .chart-container { width:100%; overflow:visible; }
    .charts-grid { display:grid; grid-template-columns:1fr 1fr; gap:18px; align-items:stretch; }
    .charts-grid > .panel { margin:0; display:flex; flex-direction:column; }
    .charts-grid .chart-section > div { display:flex; flex-direction:column; flex:1; }
    .charts-grid .chart-container { flex:1; min-height:180px; }
    .chart-pre { min-height:100px; }
    @media (max-width:820px) { .charts-grid { grid-template-columns:1fr; } }
    .r-lang-overview { display:flex; gap:40px; align-items:flex-start; justify-content:center; flex-wrap:wrap; padding:8px 0 16px; }
    .r-lang-overview-cell { display:flex; flex-direction:column; align-items:center; gap:8px; flex:1 1 280px; max-width:480px; }
    .r-lang-overview-cell p { margin:0; font-size:11px; font-weight:800; text-transform:uppercase; letter-spacing:.08em; color:var(--muted-2); text-align:center; }
    .r-lang-overview svg { display:block; max-width:100%; height:auto; }
    .rchit { cursor:pointer; transition:opacity .17s,filter .17s; }
    .rchit:hover { opacity:.75; filter:brightness(1.14); }
    #r-tt { display:none; position:fixed; background:rgba(15,10,6,.95); color:#fff; border-radius:10px; padding:8px 13px; font-size:12px; line-height:1.5; pointer-events:none; z-index:10001; box-shadow:0 4px 20px rgba(0,0,0,.32); border:1px solid rgba(255,255,255,.1); max-width:240px; white-space:nowrap; }
    .chart-tab-bar { display:flex; gap:6px; margin-bottom:12px; flex-wrap:wrap; }
    .chart-tab { padding:5px 16px; border-radius:999px; border:1px solid var(--line-strong); background:var(--surface-2); color:var(--muted); font-size:12px; font-weight:700; cursor:pointer; transition:background 0.12s,color 0.12s,border-color 0.12s; }
    .chart-tab:hover { background:var(--surface-3); color:var(--text); }
    .chart-tab.active { background:var(--accent); color:#fff; border-color:var(--accent); }
    .chart-locked-card { display:none; padding:20px 24px; border-radius:14px; background:var(--info-bg); border:1px solid rgba(111,144,255,0.28); color:var(--info-text); font-size:14px; line-height:1.6; }
    .chart-locked-card a { color:var(--accent-2); font-weight:700; }
    .chart-locked-card h3 { margin:0 0 6px; font-size:15px; }

    /* Print: hide interactive controls; keep SVGs; show locked card for history mode */
    @media print {
      .chart-controls, .chart-tab-bar { display:none !important; }
      /* Single-column grid: each chart gets full page width, renders shorter, fits on one page */
      .charts-grid { grid-template-columns: 1fr !important; gap: 10px !important; }
      /* Cap canvas height so a single chart never overflows a landscape page */
      canvas { max-width: 100% !important; max-height: 280px !important; }
      .chart-container { width: 100% !important; overflow: visible !important; }
      .chart-container svg { max-height:300px !important; }
      /* chart-locked-card: do NOT force display:block — let JS-set visibility carry
         into print (hidden in normal mode; visible only when history mode is active).
         When it does show, use readable dark text instead of accent blue. */
      .chart-locked-card { background:#f0f0f0 !important; border:1px solid #bbb !important; color:#333 !important; font-size:11px !important; padding:10px 14px !important; border-radius:8px !important; }
      .chart-locked-card h3 { color:#222 !important; font-size:13px !important; }
      .chart-locked-card a, .chart-locked-card strong { color:#1a4fa0 !important; }
      .chart-locked-card code { background:rgba(0,0,0,0.08) !important; padding:1px 4px !important; border-radius:3px !important; }
    }

    /* PDF-only chart variants container — hidden on screen, rendered in print */
    .pdf-variants-root{display:none;}
    .pdf-variant-group{margin-bottom:12px;background:#faf6f0;border:1px solid #e0d0c0;border-radius:10px;padding:12px 14px;}
    .pdf-variant-group-title{font-size:15px;font-weight:800;color:#3d2d26;margin:0 0 8px;padding-bottom:5px;border-bottom:2px solid #d37a4c;}
    .pdf-variant-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;}
    /* Solo charts (one per row) — constrained width, centred */
    .pdf-variant-grid.single-col{grid-template-columns:1fr;}
    .pdf-variant-grid.single-col .pdf-variant-panel{max-width:62%;margin:0 auto;}
    .pdf-variant-label{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:#7b675b;margin:0 0 3px;}
    .pdf-variant-img{width:100%;height:auto;display:block;border-radius:6px;border:1px solid #ddd;}

    #rpt-loading-overlay{position:fixed;inset:0;z-index:9999;background:var(--bg,#f5f0eb);display:flex;align-items:center;justify-content:center;transition:opacity .6s cubic-bezier(.4,0,.2,1);}
    #rpt-loading-overlay.fade-out{opacity:0;pointer-events:none;}
    .rpt-load-card{display:flex;flex-direction:column;align-items:center;gap:28px;padding:52px 96px;min-width:320px;background:linear-gradient(155deg,rgba(255,254,251,.96) 0%,rgba(255,246,236,.9) 100%);border:1px solid rgba(196,110,40,.13);border-radius:28px;box-shadow:0 0 0 1px rgba(255,255,255,.75) inset,0 8px 72px rgba(150,80,20,.09),0 2px 16px rgba(0,0,0,.06);animation:rpt-card-in .55s cubic-bezier(.22,.68,0,1.12) both;}
    @keyframes rpt-card-in{from{opacity:0;transform:translateY(14px) scale(.95);}to{opacity:1;transform:none;}}
    .rpt-load-logo{width:52px;height:52px;object-fit:contain;filter:drop-shadow(0 3px 10px rgba(150,80,20,.22));animation:rpt-logo-in .5s cubic-bezier(.22,.68,0,1.2) .08s both,rpt-logo-bounce 1.8s cubic-bezier(.36,.07,.19,.97) .6s infinite;}
    @keyframes rpt-logo-in{from{opacity:0;transform:scale(.75);}to{opacity:1;transform:none;}}
    @keyframes rpt-logo-bounce{0%,100%{transform:translateY(0) scale(1);filter:drop-shadow(0 3px 10px rgba(150,80,20,.22));}40%{transform:translateY(-10px) scale(1.05);filter:drop-shadow(0 12px 16px rgba(150,80,20,.14));}55%{transform:translateY(-8px) scale(1.04);}70%{transform:translateY(0) scale(.97);filter:drop-shadow(0 2px 6px rgba(150,80,20,.28));}80%{transform:translateY(-3px) scale(1.01);}90%{transform:translateY(0) scale(.99);}}
    .rpt-spinner-wrap{position:relative;width:62px;height:62px;}
    .rpt-spinner-track{position:absolute;inset:0;border-radius:50%;border:3px solid rgba(196,92,16,.1);}
    .rpt-spinner{position:absolute;inset:0;border-radius:50%;background:conic-gradient(from 0deg,rgba(196,92,16,0) 0%,rgba(196,92,16,.2) 38%,#c45c10 100%);animation:rpt-spin 1.1s cubic-bezier(.4,0,.6,1) infinite;-webkit-mask:radial-gradient(farthest-side,transparent calc(100% - 4px),#fff calc(100% - 3px));mask:radial-gradient(farthest-side,transparent calc(100% - 4px),#fff calc(100% - 3px));}
    @keyframes rpt-spin{to{transform:rotate(360deg);}}
    .rpt-load-divider{width:36px;height:1px;background:linear-gradient(90deg,transparent,rgba(196,92,16,.18),transparent);}
    .rpt-loading-text{font-size:13px;font-weight:500;color:var(--muted,#8a7060);letter-spacing:.06em;display:flex;align-items:baseline;gap:2px;}
    .rpt-dot{display:inline-block;animation:rpt-bounce 1.7s ease-in-out infinite;opacity:0;}
    .rpt-dot:nth-child(2){animation-delay:.28s;}
    .rpt-dot:nth-child(3){animation-delay:.56s;}
    @keyframes rpt-bounce{0%,60%,100%{opacity:0;transform:translateY(0);}30%{opacity:1;transform:translateY(-4px);}}
    body.dark-theme #rpt-loading-overlay{background:var(--bg,#1a1410);}
    body.dark-theme .rpt-load-card{background:linear-gradient(155deg,rgba(40,21,10,.9) 0%,rgba(28,13,4,.94) 100%);border-color:rgba(200,120,50,.13);box-shadow:0 0 0 1px rgba(255,200,140,.04) inset,0 8px 72px rgba(0,0,0,.48),0 2px 16px rgba(0,0,0,.32);}
    body.dark-theme .rpt-spinner-track{border-color:rgba(196,92,16,.16);}
    body.dark-theme .rpt-load-divider{background:linear-gradient(90deg,transparent,rgba(196,92,16,.22),transparent);}
</style>
<script nonce="{{ nonce }}">{{ chart_js|safe }}</script>
</head>
<body{% if report_header_footer.is_some() %} class="has-report-banner"{% endif %}>
  <div id="rpt-loading-overlay" aria-live="polite" aria-label="Loading report">
    <div class="rpt-load-card">
      <img src="{{ small_logo_uri }}" alt="oxide-sloc" class="rpt-load-logo" />
      <div class="rpt-spinner-wrap">
        <div class="rpt-spinner-track"></div>
        <div class="rpt-spinner"></div>
      </div>
      <div class="rpt-load-divider"></div>
      <div class="rpt-loading-text">Loading report<span class="rpt-dot">.</span><span class="rpt-dot">.</span><span class="rpt-dot">.</span></div>
    </div>
  </div>
  <div class="background-watermarks" aria-hidden="true">
    <img src="{{ logo_text_uri }}" alt="" />
    <img src="{{ logo_text_uri }}" alt="" />
    <img src="{{ logo_text_uri }}" alt="" />
    <img src="{{ logo_text_uri }}" alt="" />
    <img src="{{ logo_text_uri }}" alt="" />
    <img src="{{ logo_text_uri }}" alt="" />
    <img src="{{ logo_text_uri }}" alt="" />
    <img src="{{ logo_text_uri }}" alt="" />
    <img src="{{ logo_text_uri }}" alt="" />
    <img src="{{ logo_text_uri }}" alt="" />
    <img src="{{ logo_text_uri }}" alt="" />
    <img src="{{ logo_text_uri }}" alt="" />
  </div>
  {% if let Some(banner) = report_header_footer %}
  <div class="report-id-banner" aria-label="Report identification">{{ banner|e }}</div>
  {% endif %}
  <div class="top-nav">
    <div class="top-nav-inner">
      <a class="brand" href="/" onclick="if(location.protocol==='file:'){event.preventDefault();}">
        {% if let Some(uri) = custom_logo_uri %}
        <img class="brand-logo" src="{{ uri }}" alt="logo" />
        {% else %}
        <img class="brand-logo" src="{{ small_logo_uri }}" alt="OxideSLOC logo" />
        {% endif %}
        <div class="brand-copy">
          {% if let Some(name) = company_name %}
          <div class="brand-title">{{ name }}</div>
          {% else %}
          <div class="brand-title">OxideSLOC</div>
          {% endif %}
          <div class="brand-subtitle">Saved HTML report</div>
        </div>
      </a>
      <div class="nav-project-slot">
        <div class="nav-project-pill"><span class="nav-project-label">REPORT</span><span class="nav-project-value">{{ title }}</span></div>
      </div>
      <div class="nav-status">
        <button type="button" class="header-button" data-copy-link>Copy link</button>
        <button type="button" class="header-button" data-share-report>Share</button>
        <div class="nav-dropdown-wrap">
          <button type="button" class="header-button nav-dropdown-trigger" aria-haspopup="true">Export ▾</button>
          <div class="nav-dropdown-menu">
            <button type="button" class="nav-dropdown-item" data-export-csv>Export CSV</button>
            <button type="button" class="nav-dropdown-item" data-export-xls>Export Excel</button>
          </div>
        </div>
        <a id="nav-view-pdf-btn" href="/runs/pdf/{{ run.tool.run_id }}" target="_blank" rel="noopener" class="header-button" style="text-decoration:none;">View PDF</a>
        <button type="button" class="header-button" data-print-report>Save / Print</button>
        <button type="button" class="theme-toggle" id="settings-btn" aria-label="Color scheme" title="Color scheme settings">
          <svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>
        </button>
        <button type="button" class="theme-toggle" data-theme-toggle aria-label="Toggle theme" title="Toggle theme">
          <svg class="icon-moon" viewBox="0 0 24 24" aria-hidden="true"><path d="M20 15.5A8.5 8.5 0 1 1 12.5 4 6.7 6.7 0 0 0 20 15.5Z"></path></svg>
          <svg class="icon-sun" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4.2"></circle><path d="M12 2.5v2.2M12 19.3v2.2M21.5 12h-2.2M4.7 12H2.5M18.9 5.1l-1.6 1.6M6.7 17.3l-1.6 1.6M18.9 18.9l-1.6-1.6M6.7 6.7 5.1 5.1"></path></svg>
        </button>
      </div>
    </div>
  </div>

  <div class="page">
    <section class="hero panel">
      <div class="hero-top">
        <div>
          <div class="section-kicker">Saved report artifact</div>
          <div style="display:flex;align-items:baseline;gap:18px;flex-wrap:wrap;">
            <h1>{{ title }}</h1>
            <span class="run-id-short-badge" title="Short run ID — matches the ID shown in View Reports">{{ run_id_short }}</span>
          </div>
        </div>
      </div>
      <div class="run-id-row">
            <span class="run-id-chip" data-copy="{{ run.tool.run_id }}">
              <span class="run-id-chip-label"><svg class="chip-label-icon" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="4" y1="9" x2="20" y2="9"/><line x1="4" y1="15" x2="20" y2="15"/><line x1="10" y1="3" x2="8" y2="21"/><line x1="16" y1="3" x2="14" y2="21"/></svg>Run ID</span>
              <span class="run-id-chip-value">{{ run.tool.run_id }}</span>
              <span class="chip-tooltip">Unique identifier for this analysis run — click to copy</span>
            </span>
            {% if let Some(long_commit) = run.git_commit_long %}
            <span class="run-id-chip" data-copy="{{ long_commit }}">
              <span class="run-id-chip-label"><svg class="chip-label-icon" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><circle cx="12" cy="12" r="4"/><line x1="1" y1="12" x2="7" y2="12"/><line x1="17" y1="12" x2="23" y2="12"/></svg>Git Commit</span>
              <span class="run-id-chip-value">{{ long_commit }}</span>
              <span class="chip-tooltip">Full commit SHA for the scanned state — click to copy</span>
            </span>
            {% else %}
            <span class="run-id-chip muted-chip">
              <span class="run-id-chip-label"><svg class="chip-label-icon" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><circle cx="12" cy="12" r="4"/><line x1="1" y1="12" x2="7" y2="12"/><line x1="17" y1="12" x2="23" y2="12"/></svg>Git Commit</span>
              <span class="run-id-chip-value">Not detected</span>
              <span class="chip-tooltip">No Git commit SHA was found for this scan</span>
            </span>
            {% endif %}
            {% if let Some(branch) = run.git_branch %}
            <span class="run-id-chip">
              <span class="run-id-chip-label"><svg class="chip-label-icon" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="6" y1="3" x2="6" y2="15"/><circle cx="18" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><path d="M18 9a9 9 0 0 1-9 9"/></svg>Branch</span>
              <span class="run-id-chip-value">{{ branch }}</span>
              <span class="chip-tooltip">Git branch scanned for this report</span>
            </span>
            {% else %}
            <span class="run-id-chip muted-chip">
              <span class="run-id-chip-label"><svg class="chip-label-icon" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="6" y1="3" x2="6" y2="15"/><circle cx="18" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><path d="M18 9a9 9 0 0 1-9 9"/></svg>Branch</span>
              <span class="run-id-chip-value">Not detected</span>
              <span class="chip-tooltip">No Git branch was found for this scan</span>
            </span>
            {% endif %}
            {% if let Some(author) = run.git_commit_author %}
            <span class="run-id-chip" data-author="{{ author }}">
              <span class="run-id-chip-label"><svg class="chip-label-icon" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>Last Commit By</span>
              <span class="run-id-chip-value">{{ author }}<span class="author-handle"></span></span>
              <span class="chip-tooltip">Author of the most recent commit in this repository</span>
            </span>
            {% else %}
            <span class="run-id-chip muted-chip">
              <span class="run-id-chip-label"><svg class="chip-label-icon" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>Last Commit By</span>
              <span class="run-id-chip-value">Not detected</span>
              <span class="chip-tooltip">No commit author was found for this scan</span>
            </span>
            {% endif %}
      </div>

      <div class="meta">
        <span class="meta-chip">Scan by <b>{{ scan_performed_by }}</b></span>
        <span class="meta-chip">Scanned <b>{{ scan_time_pst }}</b></span>
        <span class="meta-chip">OS <b>{{ run.environment.operating_system }} / {{ run.environment.architecture }}</b></span>
        <span class="meta-chip">Files analyzed <b>{{ run.summary_totals.files_analyzed }}</b></span>
        <span class="meta-chip">Files skipped <b>{{ run.summary_totals.files_skipped }}</b></span>
      </div>

      <div class="summary-grid">
        <div class="metric" data-metric-value="{{ run.summary_totals.total_physical_lines }}"><div class="metric-tooltip">Total lines across all analyzed files, including code, comments, and blank lines.</div><div class="metric-label">Physical lines</div><div class="metric-value"><span class="metric-big"></span></div><span class="metric-exact"></span></div>
        <div class="metric" data-metric-value="{{ run.summary_totals.code_lines }}"><div class="metric-tooltip">Lines containing executable source code, excluding comments and blanks.</div><div class="metric-label">Code</div><div class="metric-value"><span class="metric-big"></span></div><span class="metric-exact"></span></div>
        <div class="metric" data-metric-value="{{ run.summary_totals.comment_lines }}"><div class="metric-tooltip">Lines consisting entirely of comments or inline documentation.</div><div class="metric-label">Comments</div><div class="metric-value"><span class="metric-big"></span></div><span class="metric-exact"></span></div>
        <div class="metric" data-metric-value="{{ run.summary_totals.blank_lines }}"><div class="metric-tooltip">Empty or whitespace-only lines used for readability and spacing.</div><div class="metric-label">Blank</div><div class="metric-value"><span class="metric-big"></span></div><span class="metric-exact"></span></div>
        <div class="metric" data-metric-value="{{ run.summary_totals.mixed_lines_separate }}"><div class="metric-tooltip">Lines that contain both code and a trailing comment, counted separately per the mixed-line policy.</div><div class="metric-label">Mixed separate</div><div class="metric-value"><span class="metric-big"></span></div><span class="metric-exact"></span></div>
        <div class="metric" data-metric-value="{{ run.summary_totals.functions }}"><div class="metric-tooltip">Best-effort count of function/method definitions detected across all source files.</div><div class="metric-label">Functions</div><div class="metric-value"><span class="metric-big"></span></div><span class="metric-exact"></span></div>
        <div class="metric" data-metric-value="{{ run.summary_totals.classes }}"><div class="metric-tooltip">Best-effort count of class, struct, interface, and type definitions.</div><div class="metric-label">Classes / Types</div><div class="metric-value"><span class="metric-big"></span></div><span class="metric-exact"></span></div>
        <div class="metric" data-metric-value="{{ run.summary_totals.variables }}"><div class="metric-tooltip">Best-effort count of variable and constant declarations.</div><div class="metric-label">Variables</div><div class="metric-value"><span class="metric-big"></span></div><span class="metric-exact"></span></div>
        <div class="metric" data-metric-value="{{ run.summary_totals.imports }}"><div class="metric-tooltip">Best-effort count of import, include, and module-use statements.</div><div class="metric-label">Imports</div><div class="metric-value"><span class="metric-big"></span></div><span class="metric-exact"></span></div>
        <div class="metric" data-metric-value="{{ run.summary_totals.test_count }}"><div class="metric-tooltip">Best-effort count of test cases detected by framework pattern (GTest, PyTest, JUnit, etc.).</div><div class="metric-label">Tests</div><div class="metric-value"><span class="metric-big"></span></div><span class="metric-exact"></span></div>
        <div class="metric" data-metric-density><div class="metric-tooltip">Percentage of physical lines that contain executable source code — higher means a leaner, code-dense codebase.</div><div class="metric-label">Code density</div><div class="metric-value"><span class="metric-big"></span></div><span class="metric-exact"></span></div>
        <div class="metric" data-metric-value="{{ run.summary_totals.files_analyzed }}"><div class="metric-tooltip">Total number of source files included in this analysis.</div><div class="metric-label">Files analyzed</div><div class="metric-value"><span class="metric-big"></span></div><span class="metric-exact"></span></div>
      </div>
    </section>

    <!-- ── PDF-only pre-rendered chart variants (hidden on screen) ─────── -->
    <div id="pdf-variants" class="pdf-variants-root"></div>

    <div class="report-stack">
      <!-- ── Chart row 1: Overview + Composition ───────────────────────── -->
      <div class="charts-grid">
        <section class="panel stack chart-section">
          <div>
            <div class="toolbar">
              <div class="toolbar-left"><h2>Project Overview</h2></div>
              <button class="chart-expand-btn" id="overview-expand-btn" title="View full chart" aria-label="Expand chart">&#x2922; Full View</button>
            </div>
            <div class="chart-pre">
            <p style="margin:0 0 14px;color:var(--muted);font-size:13px;line-height:1.6;">A configurable cartesian view of your codebase. Choose what to show on each axis. Historical modes (commits, tags, releases) require the web UI.</p>
            <div class="chart-controls">
              <label>Y Axis:
                <select class="chart-select" id="overview-y-axis">
                  <option value="code">Code Lines</option>
                  <option value="comments">Comment Lines</option>
                  <option value="blanks">Blank Lines</option>
                  <option value="physical">Total Physical Lines</option>
                  <option value="files">File Count</option>
                </select>
              </label>
              <label>X Axis / Mode:
                <select class="chart-select" id="overview-x-mode">
                  <option value="languages">Languages</option>
                  {% if has_submodule_data %}<option value="submodules">Submodules</option>{% endif %}
                  <option value="history-commits">Per Commit (Web UI)</option>
                  <option value="history-tags">Per Tag (Web UI)</option>
                  <option value="history-releases">Per Release (Web UI)</option>
                  <option value="history-repos">Other Repos (Web UI)</option>
                </select>
              </label>
            </div>
            </div>
            <div id="overview-chart" class="chart-container"><div id="canvas-proj-wrap" style="position:relative;min-height:150px;"><canvas id="canvas-proj"></canvas></div></div>
            <div class="chart-locked-card" id="overview-chart-locked">
              <h3>Historical trend requires the web UI</h3>
              <p style="margin:0">Run <code>oxide-sloc serve</code> and navigate to <strong>/trend-reports</strong> to view per-commit, per-tag, per-release, and cross-repo comparisons on an interactive timeline chart. The web UI stores scan history and can plot any metric over time.</p>
            </div>
          </div>
        </section>

        <section class="panel stack chart-section">
          <div>
            <div class="toolbar">
              <div class="toolbar-left"><h2>Language Composition</h2></div>
              <button class="chart-expand-btn" id="comp-expand-btn" title="View full chart" aria-label="Expand chart">&#x2922; Full View</button>
            </div>
            <div class="chart-pre">
            <p style="margin:0 0 14px;color:var(--muted);font-size:13px;">Code, comments, and blank lines as a percentage of total physical lines per language.</p>
            <div class="chart-tab-bar">
              <button type="button" class="chart-tab active" data-comp-tab="absolute">Absolute Lines</button>
              <button type="button" class="chart-tab" data-comp-tab="pct">Composition %</button>
            </div>
            </div>
            <div id="composition-chart" class="chart-container"><div id="canvas-comp-wrap" style="position:relative;min-height:150px;"><canvas id="canvas-comp"></canvas></div></div>
          </div>
        </section>
      </div>

      <!-- ── Chart row 2: Scatter + Semantic ───────────────────────────── -->
      <div class="charts-grid">
        <section class="panel stack chart-section">
          <div>
            <div class="toolbar">
              <div class="toolbar-left"><h2>File Count vs SLOC</h2></div>
              <button class="chart-expand-btn" id="scatter-expand-btn" title="View full chart" aria-label="Expand chart">&#x2922; Full View</button>
            </div>
            <p style="margin:0 0 14px;color:var(--muted);font-size:13px;">Each bubble is a language. X&nbsp;=&nbsp;files analyzed, Y&nbsp;=&nbsp;code lines, bubble size&nbsp;∝&nbsp;total physical lines.</p>
            <div id="scatter-chart" class="chart-container" style="position:relative;height:324px;"><canvas id="canvas-scatter"></canvas></div>
          </div>
        </section>

        <section class="panel stack chart-section">
          <div>
            <div class="toolbar">
              <div class="toolbar-left"><h2>Semantic Metrics</h2></div>
              {% if has_semantic_data %}
              <button class="chart-expand-btn" id="semantic-expand-btn" title="View full chart" aria-label="Expand chart">&#x2922; Full View</button>
              {% endif %}
            </div>
            <p style="margin:0 0 14px;color:var(--muted);font-size:13px;">Detected structural elements per language. Select a metric to explore.</p>
            {% if has_semantic_data %}
            <div class="chart-controls">
              <label>Metric:
                <select class="chart-select" id="semantic-metric">
                  <option value="functions">Functions</option>
                  <option value="classes">Classes / Types</option>
                  <option value="variables">Variables</option>
                  <option value="imports">Imports</option>
                  <option value="tests">Tests</option>
                </select>
              </label>
            </div>
            <div id="semantic-chart" class="chart-container" style="position:relative;height:234px;"><canvas id="canvas-semantic"></canvas></div>
            {% else %}
            <div style="display:flex;align-items:center;justify-content:center;height:200px;color:var(--muted);font-size:13px;text-align:center;line-height:1.6;">
              <div>No structural metrics detected for this scan.<br>Semantic analysis covers languages with function/class detection<br>(e.g., Go, Python, Rust, Java, C++).</div>
            </div>
            {% endif %}
          </div>
        </section>
        <section class="panel stack chart-section">
          <div>
            <div class="toolbar">
              <div class="toolbar-left"><h2>Comment Density</h2></div>
              <button class="chart-expand-btn" id="density-expand-btn" title="View full chart" aria-label="Expand chart">&#x2922; Full View</button>
            </div>
            <p style="margin:0 0 14px;color:var(--muted);font-size:13px;">Comments as a percentage of significant lines (code + comments) per language — a proxy for documentation coverage.</p>
            <div id="density-chart" class="chart-container" style="position:relative;min-height:150px;"><canvas id="canvas-density"></canvas></div>
          </div>
        </section>

        <section class="panel stack chart-section">
          <div>
            <div class="toolbar">
              <div class="toolbar-left"><h2>File Size Distribution</h2></div>
              <button class="chart-expand-btn" id="filesize-expand-btn" title="View full chart" aria-label="Expand chart">&#x2922; Full View</button>
            </div>
            <p style="margin:0 0 14px;color:var(--muted);font-size:13px;">Number of files in each SLOC bucket — a quick view of whether the codebase favours small focused modules or large files.</p>
            <div id="filesize-chart" class="chart-container" style="position:relative;min-height:150px;"><canvas id="canvas-filesize"></canvas></div>
          </div>
        </section>
      </div>

      <!-- ── Tests & Coverage ──────────────────────────────────────────── -->
      <section class="panel stack">
        <div>
          <div class="toolbar">
            <div class="toolbar-left"><h2>Tests &amp; Coverage</h2></div>
            {% if has_coverage_data %}<div class="pill-row"><span class="pill good">LCOV coverage data present</span></div>{% endif %}
          </div>
          <div class="summary-strip">
            <div class="stat-chip">
              <div class="stat-chip-val" data-fmt="{{ run.summary_totals.test_count }}">{{ run.summary_totals.test_count }}</div>
              <div class="stat-chip-label">Test Functions</div>
              <div class="stat-chip-tip">Lexically detected test case / function definitions (GTest, PyTest, JUnit, Unity, etc.)</div>
              <span class="stat-chip-exact">{{ run.summary_totals.test_count }}</span>
            </div>
            <div class="stat-chip">
              <div class="stat-chip-val" data-fmt="{{ test_assertion_count }}">{{ test_assertion_count }}</div>
              <div class="stat-chip-label">Assertions</div>
              <div class="stat-chip-tip">Test assertion call lines (ASSERT_EQ, EXPECT_TRUE, assertEquals, Assert.AreEqual, assert_eq!, etc.)</div>
              <span class="stat-chip-exact">{{ test_assertion_count }}</span>
            </div>
            <div class="stat-chip">
              <div class="stat-chip-val" data-fmt="{{ test_suite_count }}">{{ test_suite_count }}</div>
              <div class="stat-chip-label">Test Suites</div>
              <div class="stat-chip-tip">Test suite / fixture / group declarations (TEST_GROUP, BOOST_AUTO_TEST_SUITE, [TestClass], etc.)</div>
              <span class="stat-chip-exact">{{ test_suite_count }}</span>
            </div>
            <div class="stat-chip">
              <div class="stat-chip-val">{{ test_files_count }} / {{ run.summary_totals.files_analyzed }}</div>
              <div class="stat-chip-label">Test Files</div>
              <div class="stat-chip-tip">Files containing at least one detected test definition out of total analyzed files</div>
            </div>
          </div>
          <div class="summary-strip" style="margin-top:0;">
            <div class="stat-chip">
              <div class="stat-chip-val">{{ test_density }}</div>
              <div class="stat-chip-label">Tests per 1K SLOC</div>
              <div class="stat-chip-tip">Workspace-wide test density: test functions ÷ code lines × 1000</div>
            </div>
            <div class="stat-chip">
              <div class="stat-chip-val" style="font-size:15px;word-break:break-word;line-height:1.2;">{{ most_tested_lang }}</div>
              <div class="stat-chip-label">Most Tested Language</div>
              <div class="stat-chip-tip">Language with the highest absolute test function count</div>
            </div>
            <div class="stat-chip">
              <div class="stat-chip-val">{{ langs_with_tests }}</div>
              <div class="stat-chip-label">Languages with Tests</div>
              <div class="stat-chip-tip">Number of distinct languages where test definitions were detected</div>
            </div>
            <div class="stat-chip">
              {% if has_coverage_data %}<div class="stat-chip-val">{{ cov_line_pct }}%</div>{% else %}<div class="stat-chip-val" style="color:var(--muted);">&mdash;</div>{% endif %}
              <div class="stat-chip-label">Line Coverage</div>
              <div class="stat-chip-tip">Overall line coverage from LCOV data — run with --lcov-path to populate</div>
            </div>
          </div>
          {% if has_coverage_data %}
          <div class="cov-gauge-row">
            <div class="cov-gauge-card">
              <div class="cov-gauge-label">Line Coverage</div>
              <div class="cov-gauge-val" style="color:var(--{{ cov_line_class }}-text);">{{ cov_line_pct }}%</div>
              <div class="cov-gauge-track"><div class="cov-gauge-fill" style="width:{{ cov_line_pct }}%;background:var(--{{ cov_line_class }}-text);"></div></div>
              <div class="cov-gauge-sub">Lines hit / instrumented</div>
            </div>
            {% if has_fn_coverage %}
            <div class="cov-gauge-card">
              <div class="cov-gauge-label">Function Coverage</div>
              <div class="cov-gauge-val" style="color:var(--{{ cov_fn_class }}-text);">{{ cov_fn_pct }}%</div>
              <div class="cov-gauge-track"><div class="cov-gauge-fill" style="width:{{ cov_fn_pct }}%;background:var(--{{ cov_fn_class }}-text);"></div></div>
              <div class="cov-gauge-sub">Functions hit / found</div>
            </div>
            {% endif %}
            {% if has_branch_coverage %}
            <div class="cov-gauge-card">
              <div class="cov-gauge-label">Branch Coverage</div>
              <div class="cov-gauge-val" style="color:var(--{{ cov_branch_class }}-text);">{{ cov_branch_pct }}%</div>
              <div class="cov-gauge-track"><div class="cov-gauge-fill" style="width:{{ cov_branch_pct }}%;background:var(--{{ cov_branch_class }}-text);"></div></div>
              <div class="cov-gauge-sub">Branches hit / found</div>
            </div>
            {% endif %}
          </div>
          {% endif %}
          <div class="table-shell" style="margin-top:16px;">
            <table data-sort-table style="min-width:560px;">
              <thead>
                <tr>
                  <th data-sort-type="text">Language</th>
                  <th data-sort-type="number">Test Fns</th>
                  <th data-sort-type="number">Assertions</th>
                  <th data-sort-type="number">Suites</th>
                  <th data-sort-type="text">Density (per 1K SLOC)</th>
                </tr>
              </thead>
              <tbody>
                {% for row in language_rows %}
                {% if row.test_count > 0 || row.test_assertion_count > 0 %}
                <tr>
                  <td>{{ row.language }}</td>
                  <td>{{ row.test_count }}</td>
                  <td>{{ row.test_assertion_count }}</td>
                  <td>{{ row.test_suite_count }}</td>
                  <td>{{ row.test_density_str }}</td>
                </tr>
                {% endif %}
                {% endfor %}
                {% if run.summary_totals.test_count == 0 && test_assertion_count == 0 %}
                <tr class="empty-state-row"><td colspan="5">No test functions or assertions detected in this scan</td></tr>
                {% endif %}
              </tbody>
            </table>
          </div>
          {% if !has_coverage_data %}
          <div class="info-callout">
            <span class="info-callout-icon">&#x2139;&#xFE0F;</span>
            <span>No LCOV coverage data provided. Re-run with <code>--lcov-path coverage.info</code> to see line, function, and branch coverage here.</span>
          </div>
          {% endif %}
        </div>
      </section>

      <!-- ── Submodule Breakdown (2-column, conditional) ─────────────── -->
      {% if has_submodule_data %}
      <div class="charts-grid">
        <section class="panel stack chart-section">
          <div>
            <div class="toolbar">
              <div class="toolbar-left"><h2>Submodule Breakdown</h2></div>
              <button class="chart-expand-btn" id="sub-expand-btn" title="View full chart" aria-label="Expand chart">&#x2922; Full View</button>
            </div>
            <div class="chart-controls">
              <label>Y Axis:
                <select class="chart-select" id="sub-y-axis">
                  <option value="code">Code Lines</option>
                  <option value="comment">Comment Lines</option>
                  <option value="blank">Blank Lines</option>
                  <option value="physical">Total Physical Lines</option>
                  <option value="files">File Count</option>
                </select>
              </label>
              <label>Sort:
                <select class="chart-select" id="sub-sort">
                  <option value="desc">Value ↓</option>
                  <option value="asc">Value ↑</option>
                  <option value="name">Name A→Z</option>
                </select>
              </label>
            </div>
            <div id="submodule-chart" class="chart-container"><div id="canvas-sub-wrap" style="position:relative;min-height:150px;"><canvas id="canvas-sub"></canvas></div></div>
          </div>
        </section>
        <section class="panel stack chart-section">
          <div>
            <div class="toolbar">
              <div class="toolbar-left"><h2>Submodule Composition</h2></div>
              <button class="chart-expand-btn" id="sub-comp-expand-btn" title="View full chart" aria-label="Expand chart">&#x2922; Full View</button>
            </div>
            <p style="margin:0 0 14px;color:var(--muted);font-size:13px;">Code vs comments vs blank lines per submodule — bar width reflects relative size.</p>
            <div id="submodule-donut" style="width:100%;padding:4px 0;overflow:hidden;"></div>
          </div>
        </section>
      </div>
      {% endif %}

      <section class="panel stack">
        <div>
          <div class="toolbar"><div class="toolbar-left"><h2>Language breakdown</h2></div><button class="chart-expand-btn" id="lang-overview-expand-btn" title="View full chart" aria-label="Expand charts">&#x2922; Full View</button><div class="pill-row"><span class="pill good">Click any column header to sort</span></div></div>
          <div id="report-lang-overview" style="margin:0 0 16px;"></div>
          <div class="table-shell">
            <table id="lang-breakdown-table" data-sort-table>
              <thead>
                <tr>
                  <th data-sort-type="text">Language</th>
                  <th data-sort-type="number">Files</th>
                  <th data-sort-type="number">Physical</th>
                  <th data-sort-type="number">Code</th>
                  <th data-sort-type="number">Comments</th>
                  <th data-sort-type="number">Blank</th>
                  <th data-sort-type="number">Mixed separate</th>
                  <th data-sort-type="number">Functions</th>
                  <th data-sort-type="number">Classes</th>
                  <th data-sort-type="number">Variables</th>
                  <th data-sort-type="number">Imports</th>
                  <th data-sort-type="number">Tests</th>
                  <th data-sort-type="number">Assertions</th>
                  <th data-sort-type="number">Suites</th>
                </tr>
              </thead>
              <tbody>
                {% for row in language_rows %}
                <tr>
                  <td title="{{ row.language }}">{{ row.language }}</td>
                  <td>{{ row.files }}</td>
                  <td>{{ row.total_physical_lines }}</td>
                  <td>{{ row.code_lines }}</td>
                  <td>{{ row.comment_lines }}</td>
                  <td>{{ row.blank_lines }}</td>
                  <td>{{ row.mixed_lines_separate }}</td>
                  <td>{{ row.functions }}</td>
                  <td>{{ row.classes }}</td>
                  <td>{{ row.variables }}</td>
                  <td>{{ row.imports }}</td>
                  <td>{{ row.test_count }}</td>
                  <td>{{ row.test_assertion_count }}</td>
                  <td>{{ row.test_suite_count }}</td>
                </tr>
                {% endfor %}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <section class="panel stack">
        <div class="toolbar"><div class="toolbar-left"><h2>Per-file detail</h2><input id="per-file-search" class="search" type="search" placeholder="Filter files, languages, status, warnings..." /><div class="page-size-row"><label class="page-size-label">Show:</label><select id="per-file-page-size" class="page-size-select"><option value="20" selected>20</option><option value="50">50</option><option value="100">100</option><option value="all">All</option></select><span id="per-file-count-label" class="page-count-label"></span></div></div><div class="pill-row"><span class="pill good">Counts shown as analyzed by the selected policy</span><div class="export-group"><button class="export-btn" data-reset-table title="Reset scroll and column layout">&#8635; Reset</button><button class="export-btn" data-export-csv>&#8595; CSV</button><button class="export-btn" data-export-xls>&#8595; Excel</button></div></div></div>
        <div class="table-shell table-shell-clip">
        <div id="per-file-shell">
          <table id="per-file-table" data-sort-table class="table-resizable">
            <colgroup>
              <col><col><col><col><col><col><col><col><col><col><col><col><col><col>
            </colgroup>
            <thead>
              <tr>
                <th data-sort-type="text">File<div class="col-resize-handle"></div></th>
                <th data-sort-type="text">Language<div class="col-resize-handle"></div></th>
                <th data-sort-type="number" class="num-col">Physical<div class="col-resize-handle"></div></th>
                <th data-sort-type="number" class="num-col">Code<div class="col-resize-handle"></div></th>
                <th data-sort-type="number" class="num-col">Comments<div class="col-resize-handle"></div></th>
                <th data-sort-type="number" class="num-col">Blank<div class="col-resize-handle"></div></th>
                <th data-sort-type="number" class="num-col">Mixed<div class="col-resize-handle"></div></th>
                <th data-sort-type="number" class="num-col">Functions<div class="col-resize-handle"></div></th>
                <th data-sort-type="number" class="num-col">Classes<div class="col-resize-handle"></div></th>
                <th data-sort-type="number" class="num-col">Variables<div class="col-resize-handle"></div></th>
                <th data-sort-type="number" class="num-col">Imports<div class="col-resize-handle"></div></th>
                <th data-sort-type="number" class="num-col">Tests<div class="col-resize-handle"></div></th>
                <th data-sort-type="number" class="num-col">Assertions<div class="col-resize-handle"></div></th>
                <th data-sort-type="number" class="num-col">Suites<div class="col-resize-handle"></div></th>
                {% if has_coverage_data %}<th data-sort-type="text" class="num-col">Line Cov %<div class="col-resize-handle"></div></th><th data-sort-type="text" class="num-col">Fn Cov %<div class="col-resize-handle"></div></th>{% endif %}
              </tr>
            </thead>
            <tbody>
              {% for row in file_rows %}
              <tr>
                <td class="mono" title="{{ row.relative_path }}">{{ row.relative_path }}</td>
                <td title="{{ row.language }}">{{ row.language }}</td>
                <td class="num-col">{{ row.total_physical_lines }}</td>
                <td class="num-col">{{ row.code_lines }}</td>
                <td class="num-col">{{ row.comment_lines }}</td>
                <td class="num-col">{{ row.blank_lines }}</td>
                <td class="num-col">{{ row.mixed_lines_separate }}</td>
                <td class="num-col">{{ row.functions }}</td>
                <td class="num-col">{{ row.classes }}</td>
                <td class="num-col">{{ row.variables }}</td>
                <td class="num-col">{{ row.imports }}</td>
                <td class="num-col">{{ row.test_count }}</td>
                <td class="num-col">{{ row.test_assertion_count }}</td>
                <td class="num-col">{{ row.test_suite_count }}</td>
                {% if has_coverage_data %}<td class="num-col">{{ row.line_cov_pct }}</td><td class="num-col">{{ row.fn_cov_pct }}</td>{% endif %}
              </tr>
              {% endfor %}
            </tbody>
          </table>
        </div>
        </div>
        <div id="per-file-pagination" class="pagination-bar">
          <button id="pf-prev" class="pager-btn" disabled>&#8592; Prev</button>
          <span id="pf-page-info" class="pager-info"></span>
          <button id="pf-next" class="pager-btn">Next &#8594;</button>
        </div>
      </section>

      <section class="panel stack">
        <div class="toolbar"><div class="toolbar-left"><h2>Skipped files</h2><input id="skipped-search" class="search" type="search" placeholder="Filter skipped files, reasons, warnings..." /><div class="page-size-row"><label class="page-size-label">Show:</label><select id="skipped-page-size" class="page-size-select"><option value="20" selected>20</option><option value="50">50</option><option value="100">100</option><option value="all">All</option></select><span id="skipped-count-label" class="page-count-label"></span></div></div><div class="export-group"><button class="export-btn" id="skipped-export-csv">&#8595; CSV</button><button class="export-btn" id="skipped-export-xls">&#8595; Excel</button></div></div>
        <div class="table-shell table-shell-clip" style="margin-top:6px;">
        <div id="skipped-shell">
          <table id="skipped-table" data-sort-table class="table-resizable">
            <thead>
              <tr>
                <th data-sort-type="text" style="width:42%">File</th>
                <th data-sort-type="text" style="width:20%">Status</th>
                <th data-sort-type="text" style="width:38%">Warnings</th>
              </tr>
            </thead>
            <tbody>
              {% for row in skipped_rows %}
              <tr>
                <td class="mono" title="{{ row.relative_path }}">{{ row.relative_path }}</td>
                <td><span class="status-tag status-{{ row.status_class }}">{{ row.status }}</span></td>
                <td class="small" title="{{ row.warnings }}">{{ row.warnings }}</td>
              </tr>
              {% endfor %}
            </tbody>
          </table>
        </div>
        </div>
        <div id="skipped-pagination" class="pagination-bar">
          <button id="sk-prev" class="pager-btn" disabled>&#8592; Prev</button>
          <span id="sk-page-info" class="pager-info"></span>
          <button id="sk-next" class="pager-btn">Next &#8594;</button>
        </div>
      </section>

      <section class="panel stack">
        <div>
          <div class="toolbar">
            <div class="toolbar-left"><h2>Diagnostics &amp; Configuration</h2></div>
            {% if !is_sub_report && has_run_warnings %}<div class="pill-row"><span class="pill info" style="font-size:11px;min-height:26px;">{{ warning_count }} total warnings</span></div>{% endif %}
          </div>
          <p class="effective-config-note">Warning summary, support improvement opportunities, raw diagnostic output, and the exact configuration in effect for this scan.</p>
        </div>

        {% if !is_sub_report %}
        <div style="margin-top:-14px;">
          <h3 style="margin:0 0 4px;">Warnings overview</h3>
          <p class="support-note">Warning categories produced during the scan. Each row shows the warning type, how many files were affected, and what it means for your results.</p>
          {% if !has_run_warnings %}
            <div class="pill good">No top-level warnings.</div>
          {% else %}
            <div class="table-shell">
              <table class="support-table">
                <thead>
                  <tr><th style="width:30%;">Category</th><th style="width:8%;">Count</th><th>What this means</th></tr>
                </thead>
                <tbody>
                  {% for row in warning_summary_rows %}
                  <tr class="{{ row.tone_class }}">
                    <td style="font-weight:700;" title="{{ row.label }}">{{ row.label }}</td>
                    <td class="warning-count" style="font-weight:800;">{{ row.count }}</td>
                    <td class="small" style="color:var(--muted);">{{ row.detail }}</td>
                  </tr>
                  {% endfor %}
                </tbody>
              </table>
            </div>
          {% endif %}
        </div>

        <div>
          <h3 style="margin:0 0 4px;">Skipped file categories</h3>
          <p class="support-note">Files that were not analyzed, grouped by category. Each row shows what the files are, how many were skipped, example file names, and how to silence or fix the warning.</p>
          {% if warning_opportunity_rows.is_empty() %}
            <div class="pill good">No unsupported text-format buckets detected.</div>
          {% else %}
          <div class="table-shell">
            <table class="support-table">
              <thead>
                <tr><th style="width:20%;">Category</th><th style="width:6%;">Count</th><th style="width:24%;">What these files are</th><th>Example files &amp; how to fix</th></tr>
              </thead>
              <tbody>
                {% for row in warning_opportunity_rows %}
                <tr>
                  <td style="font-weight:700;" title="{{ row.label }}">{{ row.label }}</td>
                  <td style="font-weight:800;color:var(--oxide);">{{ row.count }}</td>
                  <td class="small" style="color:var(--muted);">{{ row.bucket_description }}</td>
                  <td>
                    {% if !row.example_files.is_empty() %}
                    <div style="margin-bottom:6px;">
                      {% for f in row.example_files %}<span class="support-example-file">{{ f }}</span> {% endfor %}
                      {% if row.count > row.example_files.len() %}<span style="font-size:11px;color:var(--muted);font-style:italic;">+{{ row.count - row.example_files.len() }} more</span>{% endif %}
                    </div>
                    {% endif %}
                    <p class="support-recommendation">{{ row.recommendation }}</p>
                  </td>
                </tr>
                {% endfor %}
              </tbody>
            </table>
          </div>
          {% endif %}
        </div>

        <div>
          <details open class="warnings-details">
            <summary>Detailed run warnings ({{ warning_count }})</summary>
            <div>
              <p style="font-size:13px;color:var(--muted);margin:0 0 10px;">Raw warning messages emitted during the scan — unsupported file formats, encoding fallbacks, binary detections, and per-file parse issues. Scroll to see all warnings. High counts typically indicate many non-code assets (JSON configs, docs, lockfiles) in the scanned directory.</p>
              {% if !has_run_warnings %}
                <div class="pill good">No top-level warnings.</div>
              {% else %}
                <div class="code-block-toolbar">
                  <button type="button" class="code-copy-btn" id="warning-console-copy-btn" aria-label="Copy warnings">Copy</button>
                </div>
                <pre class="warning-console" id="warning-console-full" style="max-height:210px;">{{ warning_console_full }}</pre>
              {% endif %}
            </div>
          </details>
        </div>
        {% endif %}

        <div>
          <details open>
            <summary style="display:flex;align-items:center;justify-content:space-between;gap:12px;">
              <span>Effective configuration</span>
              <span class="config-actions" style="display:flex;gap:8px;">
                <button type="button" class="header-button" data-copy-config>Copy</button>
                <button type="button" class="header-button" data-download-config>Download</button>
              </span>
            </summary>
            <div>
              <p style="font-size:13px;color:var(--muted);margin:0 0 10px;">The merged, fully-resolved configuration snapshot used for this scan — includes all CLI overrides applied on top of the base config file. Use this to replay the exact run or verify what settings were active.</p>
              <div class="config-pre-wrap">
                <div class="code-block-toolbar">
                  <button type="button" class="code-copy-btn" id="config-inline-copy-btn" aria-label="Copy configuration">Copy</button>
                </div>
                <pre class="config-pre" id="config-json-block">{{ config_json }}</pre>
              </div>
            </div>
          </details>
        </div>
      </section>
    </div>
  </div>

  <div id="r-tt" aria-hidden="true"></div>
  <script nonce="{{ nonce }}">
    // Hide "View PDF" button when the report is opened as a local file (not from web server)
    (function () {
      var pdfBtn = document.getElementById('nav-view-pdf-btn');
      if (pdfBtn && window.location.protocol === 'file:') {
        pdfBtn.style.display = 'none';
      }
    })();

    (function () {
      var body = document.body;
      var storageKey = 'oxide-sloc-theme';
      var themeToggle = document.querySelector('[data-theme-toggle]');
      var copyLinkButtons = Array.prototype.slice.call(document.querySelectorAll('[data-copy-link]'));
      var shareButtons = Array.prototype.slice.call(document.querySelectorAll('[data-share-report]'));
      var printButtons = Array.prototype.slice.call(document.querySelectorAll('[data-print-report]'));

      function applyTheme(theme) {
        body.classList.toggle('dark-theme', theme === 'dark');
      }

      function currentTheme() {
        return body.classList.contains('dark-theme') ? 'dark' : 'light';
      }

      try {
        var saved = localStorage.getItem(storageKey);
        if (saved === 'dark' || saved === 'light') {
          applyTheme(saved);
        }
      } catch (e) {}

      if (themeToggle) {
        themeToggle.addEventListener('click', function () {
          var next = currentTheme() === 'dark' ? 'light' : 'dark';
          applyTheme(next);
          try { localStorage.setItem(storageKey, next); } catch (e) {}
        });
      }

      function copyText(value) {
        if (!value) return;
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(value).catch(function () {});
        }
      }

      copyLinkButtons.forEach(function (button) {
        button.addEventListener('click', function () {
          copyText(window.location.href);
        });
      });

      shareButtons.forEach(function (button) {
        button.addEventListener('click', function () {
          if (navigator.share) {
            navigator.share({ title: document.title, url: window.location.href }).catch(function () {});
          } else {
            copyText(window.location.href);
          }
        });
      });

      printButtons.forEach(function (button) {
        button.addEventListener('click', function () {
          window.print();
        });
      });

      var copyConfigBtn = document.querySelector('[data-copy-config]');
      var downloadConfigBtn = document.querySelector('[data-download-config]');
      var configBlock = document.getElementById('config-json-block');
      var inlineCopyBtn = document.getElementById('config-inline-copy-btn');
      function handleConfigCopy(btn) {
        if (!btn || !configBlock) return;
        btn.addEventListener('click', function (e) {
          e.stopPropagation();
          copyText(configBlock.textContent);
          var orig = btn.textContent;
          btn.textContent = 'Copied!';
          setTimeout(function () { btn.textContent = orig; }, 1600);
        });
      }
      handleConfigCopy(copyConfigBtn);
      handleConfigCopy(inlineCopyBtn);

      var warnCopyBtn = document.getElementById('warning-console-copy-btn');
      var warnBlock = document.getElementById('warning-console-full');
      if (warnCopyBtn && warnBlock) {
        warnCopyBtn.addEventListener('click', function () {
          copyText(warnBlock.textContent);
          var orig = warnCopyBtn.textContent;
          warnCopyBtn.textContent = 'Copied!';
          setTimeout(function () { warnCopyBtn.textContent = orig; }, 1600);
        });
      }

      if (downloadConfigBtn && configBlock) {
        downloadConfigBtn.addEventListener('click', function (e) {
          e.stopPropagation();
          var blob = new Blob([configBlock.textContent], { type: 'application/json' });
          var url = URL.createObjectURL(blob);
          var a = document.createElement('a');
          a.href = url; a.download = 'effective-config.json';
          document.body.appendChild(a); a.click();
          document.body.removeChild(a);
          setTimeout(function () { URL.revokeObjectURL(url); }, 200);
        });
      }

      function detectType(value) {
        return /^-?\d+(?:\.\d+)?$/.test(value.trim()) ? parseFloat(value) : value.toLowerCase();
      }

      document.querySelectorAll('[data-sort-table]').forEach(function (table) {
        var headers = Array.prototype.slice.call(table.querySelectorAll('th'));
        headers.forEach(function (th, idx) {
          var direction = 1;
          var marker = document.createElement('span');
          marker.className = 'sort-indicator';
          marker.textContent = ' ↕';
          th.appendChild(marker);
          th.addEventListener('click', function (e) {
            if (e.target.closest && e.target.closest('.col-resize-handle')) return;
            var tbody = table.tBodies[0];
            var rows = Array.prototype.slice.call(tbody.querySelectorAll('tr'));
            rows.sort(function (a, b) {
              var av = detectType((a.children[idx].textContent || '').trim());
              var bv = detectType((b.children[idx].textContent || '').trim());
              if (av < bv) return -1 * direction;
              if (av > bv) return 1 * direction;
              return 0;
            });
            rows.forEach(function (row) { tbody.appendChild(row); });
            direction = direction * -1;
            table.dispatchEvent(new CustomEvent('sloc-sorted'));
          });
        });
      });

      // ── Column resize for per-file-table ─────────────────────────────────────
      (function() {
        var table = document.getElementById('per-file-table');
        if (!table) return;
        var cols = Array.prototype.slice.call(table.querySelectorAll('col'));
        var ths = Array.prototype.slice.call(table.querySelectorAll('thead th'));
        ths.forEach(function(th, i) {
          var handle = th.querySelector('.col-resize-handle');
          if (!handle || !cols[i]) return;
          var startX, startW;
          handle.addEventListener('mousedown', function(e) {
            e.stopPropagation(); e.preventDefault();
            startX = e.clientX; startW = cols[i].offsetWidth || th.offsetWidth;
            handle.classList.add('dragging');
            function onMove(e) { cols[i].style.width = Math.max(40, startW + e.clientX - startX) + 'px'; }
            function onUp() { handle.classList.remove('dragging'); document.removeEventListener('mousemove', onMove); document.removeEventListener('mouseup', onUp); }
            document.addEventListener('mousemove', onMove);
            document.addEventListener('mouseup', onUp);
          });
        });
      })();

      document.querySelectorAll('[data-table-filter]').forEach(function (input) {
        var table = document.getElementById(input.getAttribute('data-table-filter'));
        if (!table) return;
        var filterTimer = null;
        var rowCache = null;
        input.addEventListener('input', function () {
          clearTimeout(filterTimer);
          var q = input.value.toLowerCase();
          filterTimer = setTimeout(function () {
            if (!rowCache) {
              rowCache = Array.prototype.map.call(table.tBodies[0].rows, function (row) {
                return { row: row, text: row.textContent.toLowerCase() };
              });
            }
            rowCache.forEach(function (item) {
              item.row.style.display = q === '' || item.text.indexOf(q) >= 0 ? '' : 'none';
            });
          }, 200);
        });
      });

      // ── Per-file table pagination ─────────────────────────────────────────────
      (function () {
        var table = document.getElementById('per-file-table');
        if (!table) return;
        var tbody = table.tBodies[0];
        var searchInput = document.getElementById('per-file-search');
        var pageSizeSelect = document.getElementById('per-file-page-size');
        var prevBtn = document.getElementById('pf-prev');
        var nextBtn = document.getElementById('pf-next');
        var pageInfo = document.getElementById('pf-page-info');
        var countLabel = document.getElementById('per-file-count-label');
        var filteredRows = [];
        var currentPage = 1;
        var totalAll = tbody.rows.length;

        function getPageSize() {
          var v = pageSizeSelect ? pageSizeSelect.value : '20';
          return v === 'all' ? Infinity : parseInt(v, 10);
        }

        function applyFilter() {
          var q = searchInput ? searchInput.value.toLowerCase() : '';
          var rows = Array.prototype.slice.call(tbody.rows);
          filteredRows = q === '' ? rows : rows.filter(function (row) {
            return row.textContent.toLowerCase().indexOf(q) >= 0;
          });
          currentPage = 1;
          render();
        }

        function render() {
          var ps = getPageSize();
          var total = filteredRows.length;
          var totalPages = ps === Infinity ? 1 : Math.max(1, Math.ceil(total / ps));
          if (currentPage > totalPages) currentPage = totalPages;
          if (currentPage < 1) currentPage = 1;
          var start = ps === Infinity ? 0 : (currentPage - 1) * ps;
          var end = ps === Infinity ? total : Math.min(start + ps, total);
          Array.prototype.forEach.call(tbody.rows, function (row) { row.style.display = 'none'; });
          for (var i = start; i < end; i++) { filteredRows[i].style.display = ''; }
          if (pageInfo) {
            if (total === 0) {
              pageInfo.textContent = 'No results';
            } else if (ps === Infinity) {
              pageInfo.textContent = 'All ' + total.toLocaleString() + ' files';
            } else {
              pageInfo.textContent = (start + 1) + '–' + end + ' of ' + total.toLocaleString() + ' files';
            }
          }
          if (countLabel) {
            countLabel.textContent = (total < totalAll && total > 0) ? '(' + total.toLocaleString() + ' matching)' : '';
          }
          if (prevBtn) prevBtn.disabled = currentPage <= 1 || ps === Infinity;
          if (nextBtn) nextBtn.disabled = currentPage >= totalPages || ps === Infinity;
        }

        if (searchInput) {
          var filterTimer = null;
          searchInput.addEventListener('input', function () {
            clearTimeout(filterTimer);
            filterTimer = setTimeout(applyFilter, 200);
          });
        }
        if (pageSizeSelect) {
          pageSizeSelect.addEventListener('change', function () { currentPage = 1; render(); });
        }
        if (prevBtn) {
          prevBtn.addEventListener('click', function () { if (currentPage > 1) { currentPage--; render(); } });
        }
        if (nextBtn) {
          nextBtn.addEventListener('click', function () {
            var ps = getPageSize();
            var totalPages = ps === Infinity ? 1 : Math.ceil(filteredRows.length / ps);
            if (currentPage < totalPages) { currentPage++; render(); }
          });
        }
        table.addEventListener('sloc-sorted', function () { applyFilter(); });
        window._pfPaginationReset = function () { currentPage = 1; applyFilter(); };
        applyFilter();
      })();

      // ── Skipped-files table pagination ───────────────────────────────────────
      (function () {
        var table = document.getElementById('skipped-table');
        if (!table) return;
        var tbody = table.tBodies[0];
        var searchInput = document.getElementById('skipped-search');
        var pageSizeSelect = document.getElementById('skipped-page-size');
        var prevBtn = document.getElementById('sk-prev');
        var nextBtn = document.getElementById('sk-next');
        var pageInfo = document.getElementById('sk-page-info');
        var countLabel = document.getElementById('skipped-count-label');
        var filteredRows = [];
        var currentPage = 1;
        var totalAll = tbody.rows.length;

        function getPageSize() {
          var v = pageSizeSelect ? pageSizeSelect.value : '20';
          return v === 'all' ? Infinity : parseInt(v, 10);
        }

        function applyFilter() {
          var q = searchInput ? searchInput.value.toLowerCase() : '';
          var rows = Array.prototype.slice.call(tbody.rows);
          filteredRows = q === '' ? rows : rows.filter(function (row) {
            return row.textContent.toLowerCase().indexOf(q) >= 0;
          });
          currentPage = 1;
          render();
        }

        function render() {
          var ps = getPageSize();
          var total = filteredRows.length;
          var totalPages = ps === Infinity ? 1 : Math.max(1, Math.ceil(total / ps));
          if (currentPage > totalPages) currentPage = totalPages;
          if (currentPage < 1) currentPage = 1;
          var start = ps === Infinity ? 0 : (currentPage - 1) * ps;
          var end = ps === Infinity ? total : Math.min(start + ps, total);
          Array.prototype.forEach.call(tbody.rows, function (row) { row.style.display = 'none'; });
          for (var i = start; i < end; i++) { filteredRows[i].style.display = ''; }
          if (pageInfo) {
            if (total === 0) {
              pageInfo.textContent = 'No results';
            } else if (ps === Infinity) {
              pageInfo.textContent = 'All ' + total.toLocaleString() + ' files';
            } else {
              pageInfo.textContent = (start + 1) + '–' + end + ' of ' + total.toLocaleString() + ' files';
            }
          }
          if (countLabel) {
            countLabel.textContent = (total < totalAll && total > 0) ? '(' + total.toLocaleString() + ' matching)' : '';
          }
          if (prevBtn) prevBtn.disabled = currentPage <= 1 || ps === Infinity;
          if (nextBtn) nextBtn.disabled = currentPage >= totalPages || ps === Infinity;
        }

        if (searchInput) {
          var filterTimer = null;
          searchInput.addEventListener('input', function () {
            clearTimeout(filterTimer);
            filterTimer = setTimeout(applyFilter, 200);
          });
        }
        if (pageSizeSelect) {
          pageSizeSelect.addEventListener('change', function () { currentPage = 1; render(); });
        }
        if (prevBtn) {
          prevBtn.addEventListener('click', function () { if (currentPage > 1) { currentPage--; render(); } });
        }
        if (nextBtn) {
          nextBtn.addEventListener('click', function () {
            var ps = getPageSize();
            var totalPages = ps === Infinity ? 1 : Math.ceil(filteredRows.length / ps);
            if (currentPage < totalPages) { currentPage++; render(); }
          });
        }
        table.addEventListener('sloc-sorted', function () { applyFilter(); });
        applyFilter();
      })();
    })();

    (function randomizeWatermarks() {
      var wms = Array.prototype.slice.call(document.querySelectorAll('.background-watermarks img'));
      if (!wms.length) return;
      var placed = [];
      function tooClose(t, l) {
        for (var i = 0; i < placed.length; i++) {
          var dt = Math.abs(placed[i][0] - t);
          var dl = Math.abs(placed[i][1] - l);
          if (dt < 18 && dl < 18) return true;
        }
        return false;
      }
      function pick(leftBias) {
        for (var attempt = 0; attempt < 40; attempt++) {
          var t = Math.random() * 90;
          var l = leftBias ? Math.random() * 50 : 40 + Math.random() * 55;
          if (!tooClose(t, l)) { placed.push([t, l]); return [t, l]; }
        }
        var fb = [Math.random() * 90, Math.random() * 95];
        placed.push(fb);
        return fb;
      }
      var half = Math.floor(wms.length / 2);
      wms.forEach(function (img, i) {
        var pos = pick(i < half);
        var sz = Math.floor(Math.random() * 80 + 110);
        var rot = (Math.random() * 360).toFixed(1);
        var op = (Math.random() * 0.07 + 0.10).toFixed(2);
        img.style.cssText = 'width:' + sz + 'px;top:' + pos[0].toFixed(1) + '%;left:' + pos[1].toFixed(1) + '%;transform:rotate(' + rot + 'deg);opacity:' + op + ';';
      });
    })();
    // ── Metric number formatting ─────────────────────────────────────────────
    (function () {
      function fmtBig(n) {
        if (n >= 1e6) return (n / 1e6).toFixed(1).replace(/\.0$/, '') + 'M';
        if (n >= 1e4) return (n / 1e3).toFixed(1).replace(/\.0$/, '') + 'K';
        return n.toLocaleString();
      }
      function fmtExact(n) { return n.toLocaleString(); }
      document.querySelectorAll('[data-metric-value]').forEach(function (el) {
        var n = parseInt(el.getAttribute('data-metric-value'), 10);
        if (isNaN(n)) return;
        var big = el.querySelector('.metric-big');
        var exact = el.querySelector('.metric-exact');
        if (big) big.textContent = fmtBig(n);
        if (exact) exact.textContent = n >= 1e4 ? fmtExact(n) : '';
      });
      var densityCard = document.querySelector('[data-metric-density]');
      if (densityCard) {
        var phys = 0, code = 0;
        document.querySelectorAll('[data-metric-value]').forEach(function (el) {
          var lbl = el.querySelector('.metric-label');
          if (!lbl) return;
          var t = lbl.textContent.trim().toLowerCase();
          var v = parseInt(el.getAttribute('data-metric-value'), 10) || 0;
          if (t === 'physical lines') phys = v;
          if (t === 'code') code = v;
        });
        var pct = phys > 0 ? (code / phys * 100) : 0;
        var big = densityCard.querySelector('.metric-big');
        var exact = densityCard.querySelector('.metric-exact');
        if (big) big.textContent = pct.toFixed(1) + '%';
        if (exact) exact.textContent = '';
      }
      (function(){var ov=document.getElementById('rpt-loading-overlay');if(ov){ov.classList.add('fade-out');setTimeout(function(){if(ov.parentNode)ov.parentNode.removeChild(ov);},450);}})();
    })();
    // ── Info chip interactivity ───────────────────────────────────────────────
    (function() {
      document.querySelectorAll('.run-id-chip[data-copy]').forEach(function(chip) {
        chip.addEventListener('click', function() {
          var val = chip.getAttribute('data-copy');
          var tt = chip.querySelector('.chip-tooltip');
          var orig = tt ? tt.textContent : '';
          if (!navigator.clipboard) return;
          navigator.clipboard.writeText(val).then(function() {
            chip.classList.add('chip-copied-flash');
            if (tt) tt.textContent = 'Copied!';
            setTimeout(function() {
              chip.classList.remove('chip-copied-flash');
              if (tt) tt.textContent = orig;
            }, 1100);
          });
        });
      });
      document.querySelectorAll('.run-id-chip[data-author]').forEach(function(chip) {
        var author = chip.getAttribute('data-author');
        var el = chip.querySelector('.author-handle');
        if (el) el.textContent = '/' + author.replace(/\s+/g, '');
      });
    })();
    // ── Export helpers ────────────────────────────────────────────────────────
    function _slocUnh(s){var e=document.createElement('div');e.innerHTML=s;return e.textContent;}
    var _SLOC_META={runId:"{{ run.tool.run_id }}",gitCommit:"{% if let Some(c) = run.git_commit_long %}{{ c }}{% else %}(not detected){% endif %}",branch:_slocUnh("{% if let Some(b) = run.git_branch %}{{ b }}{% else %}(not detected){% endif %}"),lastCommitBy:_slocUnh("{% if let Some(a) = run.git_commit_author %}{{ a }}{% else %}(not detected){% endif %}"),scanBy:_slocUnh("{{ scan_performed_by }}"),scanned:"{{ scan_time_pst }}",os:"{{ run.environment.operating_system }} / {{ run.environment.architecture }}",filesAnalyzed:{{ run.summary_totals.files_analyzed }},filesSkipped:{{ run.summary_totals.files_skipped }},physicalLines:{{ run.summary_totals.total_physical_lines }},codeLines:{{ run.summary_totals.code_lines }},commentLines:{{ run.summary_totals.comment_lines }},blankLines:{{ run.summary_totals.blank_lines }},mixedSeparate:{{ run.summary_totals.mixed_lines_separate }},functions:{{ run.summary_totals.functions }},classes:{{ run.summary_totals.classes }},variables:{{ run.summary_totals.variables }},imports:{{ run.summary_totals.imports }},tests:{{ run.summary_totals.test_count }},toolVersion:"{{ tool_version }}"};
    function slocEscXml(v){return String(v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
    function slocEscCsv(v){var s=String(v);return(s.indexOf(',')>=0||s.indexOf('"')>=0||s.indexOf('\n')>=0)?'"'+s.replace(/"/g,'""')+'"':s;}
    function slocDownload(data,name,mime){var b=new Blob([data],{type:mime});var u=URL.createObjectURL(b);var a=document.createElement('a');a.href=u;a.download=name;document.body.appendChild(a);a.click();document.body.removeChild(a);setTimeout(function(){URL.revokeObjectURL(u);},200);}
    function slocCsv(fname,hdrs,rows){slocDownload([hdrs.map(slocEscCsv).join(',')].concat(rows.map(function(r){return r.map(slocEscCsv).join(',');})).join('\r\n'),fname,'text/csv;charset=utf-8;');}
    function slocXls(fname,sheet,hdrs,rows){var enc=new TextEncoder();var CT=[];for(var _n=0;_n<256;_n++){var _c=_n;for(var _k=0;_k<8;_k++)_c=_c&1?0xEDB88320^(_c>>>1):_c>>>1;CT[_n]=_c;}function crc32(d){var v=0xFFFFFFFF;for(var i=0;i<d.length;i++)v=CT[(v^d[i])&0xFF]^(v>>>8);return(v^0xFFFFFFFF)>>>0;}function u2(n){return[n&0xFF,(n>>8)&0xFF];}function u4(n){return[n&0xFF,(n>>8)&0xFF,(n>>16)&0xFF,(n>>24)&0xFF];}function xe(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}var ss=[],si={};function S(v){v=String(v==null?'':v);if(!(v in si)){si[v]=ss.length;ss.push(v);}return si[v];}function colRef(c,r){var s='',n=c+1;while(n>0){n--;s=String.fromCharCode(65+(n%26))+s;n=Math.floor(n/26);}return s+r;}var rx='<row r="1">';hdrs.forEach(function(h,c){rx+='<c r="'+colRef(c,1)+'" t="s" s="1"><v>'+S(h)+'</v></c>';});rx+='</row>';rows.forEach(function(row,ri){var rn=ri+2;rx+='<row r="'+rn+'">';row.forEach(function(cell,c){var ref=colRef(c,rn);var num=c>=2&&cell!==''&&cell!=null&&!isNaN(Number(cell));rx+=num?'<c r="'+ref+'" s="2"><v>'+xe(cell)+'</v></c>':'<c r="'+ref+'" t="s"><v>'+S(cell)+'</v></c>';});rx+='</row>';});var ox='http://schemas.openxmlformats.org/',pns=ox+'package/2006/',ons=ox+'officeDocument/2006/',sns=ox+'spreadsheetml/2006/main';var ssXml='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><sst xmlns="'+sns+'" count="'+ss.length+'" uniqueCount="'+ss.length+'">'+ss.map(function(v){return'<si><t xml:space="preserve">'+xe(v)+'</t></si>';}).join('')+'</sst>';var wsh='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="'+sns+'"><sheetViews><sheetView workbookViewId="0"/></sheetViews><sheetFormatPr defaultRowHeight="15"/><sheetData>'+rx+'</sheetData></worksheet>';var stl='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="'+sns+'"><fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><sz val="11"/><b/><name val="Calibri"/></font></fonts><fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills><borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="3"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment horizontal="right"/></xf></cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>';var F={'[Content_Types].xml':'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="'+pns+'content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/><Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/></Types>','_rels/.rels':'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="'+pns+'relationships"><Relationship Id="rId1" Type="'+ons+'relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>','xl/workbook.xml':'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="'+sns+'" xmlns:r="'+ons+'relationships"><sheets><sheet name="'+xe(sheet)+'" sheetId="1" r:id="rId1"/></sheets></workbook>','xl/_rels/workbook.xml.rels':'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="'+pns+'relationships"><Relationship Id="rId1" Type="'+ons+'relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="'+ons+'relationships/styles" Target="styles.xml"/><Relationship Id="rId3" Type="'+ons+'relationships/sharedStrings" Target="sharedStrings.xml"/></Relationships>','xl/styles.xml':stl,'xl/sharedStrings.xml':ssXml,'xl/worksheets/sheet1.xml':wsh};var order=['[Content_Types].xml','_rels/.rels','xl/workbook.xml','xl/_rels/workbook.xml.rels','xl/styles.xml','xl/sharedStrings.xml','xl/worksheets/sheet1.xml'];var zparts=[],zcds=[],zoff=0,znf=0;order.forEach(function(name){var nb=enc.encode(name),db=enc.encode(F[name]),sz=db.length,cr=crc32(db);var lha=[0x50,0x4B,0x03,0x04,0x14,0,0,0,0,0,0,0,0,0].concat(u4(cr)).concat(u4(sz)).concat(u4(sz)).concat(u2(nb.length)).concat([0,0]);var entry=new Uint8Array(lha.length+nb.length+sz);entry.set(new Uint8Array(lha),0);entry.set(nb,lha.length);entry.set(db,lha.length+nb.length);zparts.push(entry);var cda=[0x50,0x4B,0x01,0x02,0x14,0,0x14,0,0,0,0,0,0,0,0,0].concat(u4(cr)).concat(u4(sz)).concat(u4(sz)).concat(u2(nb.length)).concat([0,0,0,0,0,0,0,0,0,0,0,0]).concat(u4(zoff));var cde=new Uint8Array(cda.length+nb.length);cde.set(new Uint8Array(cda),0);cde.set(nb,cda.length);zcds.push(cde);zoff+=entry.length;znf++;});var cdSz=zcds.reduce(function(a,c){return a+c.length;},0);var ea=[0x50,0x4B,0x05,0x06,0,0,0,0].concat(u2(znf)).concat(u2(znf)).concat(u4(cdSz)).concat(u4(zoff)).concat([0,0]);var tot=zoff+cdSz+ea.length,zout=new Uint8Array(tot),zpos=0;zparts.forEach(function(p){zout.set(p,zpos);zpos+=p.length;});zcds.forEach(function(c){zout.set(c,zpos);zpos+=c.length;});zout.set(new Uint8Array(ea),zpos);slocDownload(zout,fname,'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');}
    function slocXlsMulti(fname,sheets){
      var enc=new TextEncoder();
      var CT=[];
      for(var _n=0;_n<256;_n++){var _c=_n;for(var _k=0;_k<8;_k++)_c=_c&1?0xEDB88320^(_c>>>1):_c>>>1;CT[_n]=_c;}
      function crc32(d){var v=0xFFFFFFFF;for(var i=0;i<d.length;i++)v=CT[(v^d[i])&0xFF]^(v>>>8);return(v^0xFFFFFFFF)>>>0;}
      function u2(n){return[n&0xFF,(n>>8)&0xFF];}
      function u4(n){return[n&0xFF,(n>>8)&0xFF,(n>>16)&0xFF,(n>>24)&0xFF];}
      function xe(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
      var ss=[],si={};
      function S(v){v=String(v==null?'':v);if(!(v in si)){si[v]=ss.length;ss.push(v);}return si[v];}
      function colRef(c,r){var s='',n=c+1;while(n>0){n--;s=String.fromCharCode(65+(n%26))+s;n=Math.floor(n/26);}return s+r;}
      var ox='http://schemas.openxmlformats.org/',pns=ox+'package/2006/',ons=ox+'officeDocument/2006/',sns=ox+'spreadsheetml/2006/main';
      // Style indices: 0=normal 1=col-header(orange-fill/white-bold) 2=number(#,##0/right) 3=section(cream-fill/orange-bold) 4=bold-label
      var stl='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="'+sns+'">'
        +'<numFmts count="1"><numFmt numFmtId="164" formatCode="#,##0"/></numFmts>'
        +'<fonts count="3">'
          +'<font><sz val="11"/><name val="Calibri"/></font>'
          +'<font><sz val="11"/><b/><color rgb="FFFFFFFF"/><name val="Calibri"/></font>'
          +'<font><sz val="11"/><b/><color rgb="FFC45C10"/><name val="Calibri"/></font>'
        +'</fonts>'
        +'<fills count="4">'
          +'<fill><patternFill patternType="none"/></fill>'
          +'<fill><patternFill patternType="gray125"/></fill>'
          +'<fill><patternFill patternType="solid"><fgColor rgb="FFC45C10"/><bgColor indexed="64"/></patternFill></fill>'
          +'<fill><patternFill patternType="solid"><fgColor rgb="FFFAF0E6"/><bgColor indexed="64"/></patternFill></fill>'
        +'</fills>'
        +'<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
        +'<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
        +'<cellXfs count="5">'
          +'<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
          +'<xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/>'
          +'<xf numFmtId="164" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1" applyAlignment="1"><alignment horizontal="right"/></xf>'
          +'<xf numFmtId="0" fontId="2" fillId="3" borderId="0" xfId="0" applyFont="1" applyFill="1"/>'
          +'<xf numFmtId="0" fontId="2" fillId="0" borderId="0" xfId="0" applyFont="1"/>'
        +'</cellXfs>'
        +'<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
        +'</styleSheet>';
      var wsXmls=[];
      sheets.forEach(function(sh){
        var rx='<row r="1">';
        sh.hdrs.forEach(function(h,c){rx+='<c r="'+colRef(c,1)+'" t="s" s="1"><v>'+S(h)+'</v></c>';});
        rx+='</row>';
        var rn=2;
        sh.rows.forEach(function(row){
          if(!row||row.length===0){rx+='<row r="'+rn+'"/>';rn++;return;}
          if(row.length===1&&row[0]&&typeof row[0]==='object'&&row[0]._sec){
            rx+='<row r="'+rn+'">';
            rx+='<c r="'+colRef(0,rn)+'" t="s" s="3"><v>'+S(row[0].v)+'</v></c>';
            for(var ec=1;ec<sh.hdrs.length;ec++){rx+='<c r="'+colRef(ec,rn)+'" s="3"/>';}
            rx+='</row>';rn++;return;
          }
          rx+='<row r="'+rn+'">';
          row.forEach(function(cell,c){
            var ref=colRef(c,rn);
            if(cell===null||cell===undefined||cell===''){rx+='<c r="'+ref+'"/>';return;}
            if(typeof cell==='object'&&cell!==null){
              var cv=cell.v,cs=cell.s!=null?cell.s:0;
              if(typeof cv==='number'){rx+='<c r="'+ref+'" s="'+cs+'"><v>'+xe(cv)+'</v></c>';}
              else{rx+='<c r="'+ref+'" t="s" s="'+cs+'"><v>'+S(cv)+'</v></c>';}
              return;
            }
            if(typeof cell==='number'){rx+='<c r="'+ref+'" s="2"><v>'+xe(cell)+'</v></c>';return;}
            rx+='<c r="'+ref+'" t="s"><v>'+S(cell)+'</v></c>';
          });
          rx+='</row>';rn++;
        });
        var cw='';
        if(sh.colWidths&&sh.colWidths.length>0){
          cw='<cols>';
          sh.colWidths.forEach(function(w,i){cw+='<col min="'+(i+1)+'" max="'+(i+1)+'" width="'+w+'" customWidth="1"/>';});
          cw+='</cols>';
        }
        wsXmls.push('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="'+sns+'">'
          +'<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>'
          +'<sheetFormatPr defaultRowHeight="15"/>'+cw+'<sheetData>'+rx+'</sheetData></worksheet>');
      });
      var ssXml='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><sst xmlns="'+sns+'" count="'+ss.length+'" uniqueCount="'+ss.length+'">'+ss.map(function(v){return'<si><t xml:space="preserve">'+xe(v)+'</t></si>';}).join('')+'</sst>';
      var ctOver=sheets.map(function(_,i){return'<Override PartName="/xl/worksheets/sheet'+(i+1)+'.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>';}).join('');
      var ctXml='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="'+pns+'content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'+ctOver+'<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/><Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/></Types>';
      var wbSh=sheets.map(function(sh,i){return'<sheet name="'+xe(sh.name)+'" sheetId="'+(i+1)+'" r:id="rId'+(i+1)+'"/>';}).join('');
      var wbXml='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="'+sns+'" xmlns:r="'+ons+'relationships"><sheets>'+wbSh+'</sheets></workbook>';
      var wbR=sheets.map(function(_,i){return'<Relationship Id="rId'+(i+1)+'" Type="'+ons+'relationships/worksheet" Target="worksheets/sheet'+(i+1)+'.xml"/>';}).join('');
      wbR+='<Relationship Id="rId'+(sheets.length+1)+'" Type="'+ons+'relationships/styles" Target="styles.xml"/>'
        +'<Relationship Id="rId'+(sheets.length+2)+'" Type="'+ons+'relationships/sharedStrings" Target="sharedStrings.xml"/>';
      var wbRXml='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="'+pns+'relationships">'+wbR+'</Relationships>';
      var F={'[Content_Types].xml':ctXml,'_rels/.rels':'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="'+pns+'relationships"><Relationship Id="rId1" Type="'+ons+'relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>','xl/workbook.xml':wbXml,'xl/_rels/workbook.xml.rels':wbRXml,'xl/styles.xml':stl,'xl/sharedStrings.xml':ssXml};
      var order=['[Content_Types].xml','_rels/.rels','xl/workbook.xml','xl/_rels/workbook.xml.rels','xl/styles.xml','xl/sharedStrings.xml'];
      sheets.forEach(function(_,i){var k='xl/worksheets/sheet'+(i+1)+'.xml';F[k]=wsXmls[i];order.push(k);});
      var zparts=[],zcds=[],zoff=0,znf=0;
      order.forEach(function(name){var nb=enc.encode(name),db=enc.encode(F[name]),sz=db.length,cr=crc32(db);var lha=[0x50,0x4B,0x03,0x04,0x14,0,0,0,0,0,0,0,0,0].concat(u4(cr)).concat(u4(sz)).concat(u4(sz)).concat(u2(nb.length)).concat([0,0]);var entry=new Uint8Array(lha.length+nb.length+sz);entry.set(new Uint8Array(lha),0);entry.set(nb,lha.length);entry.set(db,lha.length+nb.length);zparts.push(entry);var cda=[0x50,0x4B,0x01,0x02,0x14,0,0x14,0,0,0,0,0,0,0,0,0].concat(u4(cr)).concat(u4(sz)).concat(u4(sz)).concat(u2(nb.length)).concat([0,0,0,0,0,0,0,0,0,0,0,0]).concat(u4(zoff));var cde=new Uint8Array(cda.length+nb.length);cde.set(new Uint8Array(cda),0);cde.set(nb,cda.length);zcds.push(cde);zoff+=entry.length;znf++;});
      var cdSz=zcds.reduce(function(a,c){return a+c.length;},0);
      var ea=[0x50,0x4B,0x05,0x06,0,0,0,0].concat(u2(znf)).concat(u2(znf)).concat(u4(cdSz)).concat(u4(zoff)).concat([0,0]);
      var tot=zoff+cdSz+ea.length,zout=new Uint8Array(tot),zpos=0;
      zparts.forEach(function(p){zout.set(p,zpos);zpos+=p.length;});
      zcds.forEach(function(c){zout.set(c,zpos);zpos+=c.length;});
      zout.set(new Uint8Array(ea),zpos);
      slocDownload(zout,fname,'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    }
    window.resetPerFileTable = function() {
      var tbl = document.getElementById('per-file-table');
      if (!tbl) return;
      var shell = tbl.closest('.table-shell');
      if (shell) shell.scrollLeft = 0;
      Array.prototype.slice.call(tbl.querySelectorAll('th')).forEach(function(th) { th.style.width = ''; });
      Array.prototype.slice.call(tbl.querySelectorAll('col')).forEach(function(c) { c.style.width = ''; });
      if (window._pfPaginationReset) window._pfPaginationReset();
      var si = document.getElementById('per-file-search');
      if (si) si.value = '';
    };
    var _rh=['File','Language','Physical Lines','Code Lines','Comments','Blank','Mixed Separate','Functions','Classes','Variables','Imports'];
    var _titleSlug="{{ title }}".replace(/[^a-zA-Z0-9\-]/g,'_').replace(/_+/g,'_').replace(/^_+|_+$/g,'');
    var _commitSlug="{% if let Some(c) = run.git_commit_short %}{{ c }}{% endif %}";
    var _exportSlug='per-file_'+_titleSlug+(_commitSlug?'_'+_commitSlug:'');
    function getReportExportRows(){var r=[];document.querySelectorAll('#per-file-table tbody tr').forEach(function(tr){var tds=tr.querySelectorAll('td');if(tds.length<11)return;r.push([tds[0].textContent.trim(),tds[1].textContent.trim(),tds[2].textContent.trim(),tds[3].textContent.trim(),tds[4].textContent.trim(),tds[5].textContent.trim(),tds[6].textContent.trim(),tds[7].textContent.trim(),tds[8].textContent.trim(),tds[9].textContent.trim(),tds[10].textContent.trim()]);});return r;}
    window.exportReportCsv=function(){slocCsv(_exportSlug+'.csv',_rh,getReportExportRows());};
    window.exportReportXls=function(){
      var fname='report_'+_titleSlug+(_commitSlug?'_'+_commitSlug:'')+'.xlsx';
      function sec(v){return[{_sec:true,v:v}];}
      function B(v){return{v:v,s:4};}
      function N(v){return{v:typeof v==='number'?v:Number(v),s:2};}
      var dens=_SLOC_META.physicalLines>0?(_SLOC_META.codeLines/_SLOC_META.physicalLines*100).toFixed(1)+'%':'0%';
      var sumRows=[
        sec('RUN INFORMATION'),
        [B('Run ID'),_SLOC_META.runId,''],
        [B('Git Commit'),_SLOC_META.gitCommit,''],
        [B('Branch'),_SLOC_META.branch,''],
        [B('Last Commit By'),_SLOC_META.lastCommitBy,''],
        [B('Scan By'),_SLOC_META.scanBy,''],
        [B('Scanned'),_SLOC_META.scanned,''],
        [B('OS'),_SLOC_META.os,''],
        [B('Files Analyzed'),N(_SLOC_META.filesAnalyzed),'Total source files included in this analysis'],
        [B('Files Skipped'),N(_SLOC_META.filesSkipped),'Files excluded (binary, unsupported, or policy-filtered)'],
        [],
        sec('CODE METRICS'),
        [B('Physical Lines'),N(_SLOC_META.physicalLines),'Total lines including code, comments, and blanks'],
        [B('Code Lines'),N(_SLOC_META.codeLines),'Lines containing executable source code'],
        [B('Comments'),N(_SLOC_META.commentLines),'Lines consisting entirely of comments or documentation'],
        [B('Blank Lines'),N(_SLOC_META.blankLines),'Empty or whitespace-only lines'],
        [B('Mixed Separate'),N(_SLOC_META.mixedSeparate),'Lines with both code and trailing comment, counted separately'],
        [B('Functions'),N(_SLOC_META.functions),'Best-effort count of function/method definitions'],
        [B('Classes / Types'),N(_SLOC_META.classes),'Best-effort count of class, struct, interface definitions'],
        [B('Variables'),N(_SLOC_META.variables),'Best-effort count of variable and constant declarations'],
        [B('Imports'),N(_SLOC_META.imports),'Best-effort count of import, include, module-use statements'],
        [B('Tests'),N(_SLOC_META.tests),'Best-effort count of test cases (GTest, PyTest, JUnit, etc.)'],
        [B('Code Density'),dens,'Percentage of physical lines that contain executable source code'],
        [B('Tool Version'),'oxide-sloc '+_SLOC_META.toolVersion,''],
      ];
      var langHdrs=['Language','Files','Physical Lines','Code Lines','Comments','Blank Lines','Mixed','Functions','Classes','Variables','Imports','Tests','Assertions','Suites'];
      var langRows=[];
      document.querySelectorAll('#lang-breakdown-table tbody tr').forEach(function(tr){
        var tds=tr.querySelectorAll('td');
        var row=[];
        Array.prototype.forEach.call(tds,function(td,i){var v=td.textContent.trim();row.push(i>0&&v!==''&&!isNaN(Number(v))?Number(v):v);});
        langRows.push(row);
      });
      var pfHdrs=['File','Language','Physical Lines','Code Lines','Comments','Blank','Mixed','Functions','Classes','Variables','Imports','Tests','Assertions','Suites'];
      var pfRows=[];
      document.querySelectorAll('#per-file-table tbody tr').forEach(function(tr){
        var tds=tr.querySelectorAll('td');
        if(tds.length<11)return;
        var row=[];
        Array.prototype.forEach.call(tds,function(td,i){var v=td.textContent.trim();row.push(i>=2&&v!==''&&!isNaN(Number(v))?Number(v):v);});
        pfRows.push(row);
      });
      var skHdrs=['File','Status','Warnings'];
      var skRows=[];
      document.querySelectorAll('#skipped-table tbody tr').forEach(function(tr){
        var tds=tr.querySelectorAll('td');
        if(tds.length<3)return;
        skRows.push([tds[0].textContent.trim(),tds[1].textContent.trim(),tds[2].textContent.trim()]);
      });
      slocXlsMulti(fname,[
        {name:'Summary',hdrs:['Field / Metric','Value','Description'],rows:sumRows,colWidths:[22,45,55]},
        {name:'Language Breakdown',hdrs:langHdrs,rows:langRows,colWidths:[16,8,14,12,12,12,8,10,10,10,10,8,10,8]},
        {name:'Per-File Detail',hdrs:pfHdrs,rows:pfRows,colWidths:[50,12,12,12,12,10,8,10,10,10,10,8,10,8]},
        {name:'Skipped Files',hdrs:skHdrs,rows:skRows,colWidths:[60,25,50]}
      ]);
    };
    Array.prototype.slice.call(document.querySelectorAll('[data-export-csv]')).forEach(function(btn){btn.addEventListener('click',function(){slocCsv(_exportSlug+'.csv',_rh,getReportExportRows());});});
    Array.prototype.slice.call(document.querySelectorAll('[data-export-xls]')).forEach(function(btn){btn.addEventListener('click',window.exportReportXls);});
    Array.prototype.slice.call(document.querySelectorAll('[data-reset-table]')).forEach(function(btn){btn.addEventListener('click',window.resetPerFileTable);});
    var _skippedRh=['File','Status','Warnings'];
    var _skippedSlug='skipped_'+_titleSlug+(_commitSlug?'_'+_commitSlug:'');
    function getSkippedExportRows(){var r=[];document.querySelectorAll('#skipped-table tbody tr').forEach(function(tr){var tds=tr.querySelectorAll('td');if(tds.length<3)return;r.push([tds[0].textContent.trim(),tds[1].textContent.trim(),tds[2].textContent.trim()]);});return r;}
    (function(){var b=document.getElementById('skipped-export-csv');if(b)b.addEventListener('click',function(){slocCsv(_skippedSlug+'.csv',_skippedRh,getSkippedExportRows());});})();
    (function(){var b=document.getElementById('skipped-export-xls');if(b)b.addEventListener('click',function(){slocXls(_skippedSlug+'.xlsx','Skipped Files',_skippedRh,getSkippedExportRows());});})();
    // ── Chart.js initialization ───────────────────────────────────────────────
    // Deferred so the browser can repaint (dismiss the loading overlay) before
    // the canvas/SVG chart work blocks the main thread.
    requestAnimationFrame(function() {
    (function() {
      var D = {{ lang_chart_json|safe }};
      var SUB_D = {{ submodule_chart_json|safe }};
      var SCAT_D = {{ scatter_chart_json|safe }};
      var SEM_D = {{ semantic_chart_json|safe }};
      var HIST_D = {{ file_size_histogram_json|safe }};
      if (!D || !D.length) return;

      var PALETTE = ['#C45C10','#2A6846','#4472C4','#805099','#D4A017','#B23030',
                     '#2E75B6','#70AD47','#FF9900','#9E480E','#636363','#156082',
                     '#D0743C','#5BA8A0','#8B3A8B','#3D7A3D','#AA5500','#005599'];
      var OX = '#C45C10', GN = '#2A6846', GY = '#BBBBBB';
      var ALL_CHARTS = [];

      function fmt(n) {
        var v = Number(n), a = Math.abs(v);
        if (a >= 1e6) return (v/1e6).toFixed(1).replace(/\.0$/,'') + 'M';
        if (a >= 1e4) return Math.round(v/1e3) + 'K';
        return v.toLocaleString();
      }
      function isDark() { return document.body.classList.contains('dark-theme'); }
      function clr() {
        return isDark()
          ? { text: '#d4c5b8', grid: 'rgba(255,255,255,0.10)' }
          : { text: '#43342d', grid: '#e6d0bf' };
      }
      // Inline Chart.js plugin: draws a permanent value label on each bar / bubble.
      // fmtFn(rawValue, datasetIndex, pointIndex) → string | null
      // anchor: 'top' = above vertical bar, 'end' = right of horizontal bar, 'bubble' = above bubble
      function makeDlPlugin(fmtFn, anchor) {
        return {
          afterDatasetsDraw: function(chart) {
            var ctx = chart.ctx;
            var tc = clr().text;
            chart.data.datasets.forEach(function(ds, di) {
              var meta = chart.getDatasetMeta(di);
              meta.data.forEach(function(el, idx) {
                var label = fmtFn(ds.data[idx], di, idx);
                if (label == null || label === '') return;
                ctx.save();
                ctx.font = '600 11px Inter,ui-sans-serif,sans-serif';
                ctx.fillStyle = tc;
                if (anchor === 'top') {
                  ctx.textAlign = 'center';
                  ctx.textBaseline = 'bottom';
                  ctx.fillText(String(label), el.x, el.y - 3);
                } else if (anchor === 'end') {
                  ctx.textAlign = 'left';
                  ctx.textBaseline = 'middle';
                  ctx.fillText(String(label), el.x + 5, el.y);
                } else {
                  ctx.textAlign = 'center';
                  ctx.textBaseline = 'bottom';
                  var r = (el.options && el.options.radius) ? el.options.radius : 10;
                  ctx.fillText(String(label), el.x, el.y - r - 3);
                }
                ctx.restore();
              });
            });
          }
        };
      }
      function makeStackedEndPlugin(fmtFn) {
        return {
          afterDatasetsDraw: function(chart) {
            var ctx = chart.ctx;
            var tc = clr().text;
            var nDs = chart.data.datasets.length;
            if (nDs === 0) return;
            var lastMeta = chart.getDatasetMeta(nDs - 1);
            lastMeta.data.forEach(function(el, idx) {
              var total = 0;
              chart.data.datasets.forEach(function(ds) { total += ds.data[idx] || 0; });
              var label = fmtFn(total, idx);
              if (label == null || label === '') return;
              ctx.save();
              ctx.font = '600 11px Inter,ui-sans-serif,sans-serif';
              ctx.fillStyle = tc;
              ctx.textAlign = 'left';
              ctx.textBaseline = 'middle';
              ctx.fillText(String(label), el.x + 5, el.y);
              ctx.restore();
            });
          }
        };
      }

      // ── Language overview: SVG donut + horizontal stacked bars ───────────────
      (function() {
        var el = document.getElementById('report-lang-overview');
        if (!el || !D || !D.length) return;
        var FONT = 'Inter,ui-sans-serif,system-ui,-apple-system,sans-serif';
        function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
        function px(n){return Math.round(n);}
        function tt(label,val){return ' class="rchit" data-ttl="'+String(label).replace(/&/g,'&amp;').replace(/"/g,'&quot;')+'" data-ttv="'+String(val).replace(/&/g,'&amp;').replace(/"/g,'&quot;')+'"';}
        var tot = D.reduce(function(a,d){return a+d.code;},0)||1;
        // Donut — height matches the stacked-bar chart so both panels align
        var rHb_d=28;
        var DH=Math.max(220,D.length*rHb_d+32);
        var cx=100,cy=Math.round(DH/2),Ro=88,Ri=48,legX=204,DW=360;
        var legCount=D.length;
        var legSpacing=Math.max(12,Math.min(22,Math.floor((DH-30)/Math.max(legCount,1))));
        var legYStart=Math.round((DH-legCount*legSpacing)/2);
        var ds='<svg viewBox="0 0 '+DW+' '+DH+'" width="'+DW+'" height="'+DH+'" style="display:block;max-width:100%;" xmlns="http://www.w3.org/2000/svg">';
        if(D.length===1){
          var rm=Math.round((Ro+Ri)/2),rsw=Ro-Ri;
          ds+='<circle'+tt(D[0].lang,fmt(D[0].code)+' code lines')+' cx="'+cx+'" cy="'+cy+'" r="'+rm+'" fill="none" stroke="'+PALETTE[0]+'" stroke-width="'+rsw+'"/>';
        } else {
          var ang=-Math.PI/2;
          D.forEach(function(d,i){
            var sw=Math.min(d.code/tot*2*Math.PI,2*Math.PI-0.001),a2=ang+sw;
            var x1=cx+Ro*Math.cos(ang),y1=cy+Ro*Math.sin(ang);
            var x2=cx+Ro*Math.cos(a2),y2=cy+Ro*Math.sin(a2);
            var xi1=cx+Ri*Math.cos(a2),yi1=cy+Ri*Math.sin(a2);
            var xi2=cx+Ri*Math.cos(ang),yi2=cy+Ri*Math.sin(ang);
            var pct=Math.round(d.code/tot*100);
            ds+='<path'+tt(d.lang,fmt(d.code)+' code lines ('+pct+'%)')+' d="M'+px(x1)+','+px(y1)+' A'+Ro+','+Ro+' 0 '+(sw>Math.PI?1:0)+',1 '+px(x2)+','+px(y2)+' L'+px(xi1)+','+px(yi1)+' A'+Ri+','+Ri+' 0 '+(sw>Math.PI?1:0)+',0 '+px(xi2)+','+px(yi2)+' Z" fill="'+(PALETTE[i%PALETTE.length])+'" stroke="white" stroke-width="2"/>';
            ang+=sw;
          });
        }
        ds+='<text x="'+cx+'" y="'+(cy-7)+'" text-anchor="middle" font-family="'+FONT+'" font-size="21" font-weight="800" fill="#43342d">'+fmt(tot)+'</text>';
        ds+='<text x="'+cx+'" y="'+(cy+14)+'" text-anchor="middle" font-family="'+FONT+'" font-size="11" fill="#7b675b">code lines</text>';
        D.forEach(function(d,i){
          var ly=legYStart+i*legSpacing;
          ds+='<rect x="'+legX+'" y="'+ly+'" width="11" height="11" rx="2" fill="'+(PALETTE[i%PALETTE.length])+'"/>';
          ds+='<text x="'+(legX+16)+'" y="'+(ly+10)+'" font-family="'+FONT+'" font-size="'+Math.min(11,legSpacing-2)+'" fill="#43342d">'+esc(d.lang)+'</text>';
        });
        ds+='</svg>';
        // Horizontal stacked-bar chart
        var maxT=Math.max.apply(null,D.map(function(d){return d.code+d.comments+d.blanks;}))||1;
        var LW=108,BW=260,rHb=28,bH=20,SH=D.length*rHb+32,svgW=LW+BW+68;
        var bs='<svg viewBox="0 0 '+svgW+' '+SH+'" width="'+svgW+'" height="'+SH+'" style="display:block;max-width:100%;" xmlns="http://www.w3.org/2000/svg">';
        D.forEach(function(d,i){
          var y=6+i*rHb,x=LW;
          var cW=d.code/maxT*BW,cmW=d.comments/maxT*BW,blW=d.blanks/maxT*BW;
          bs+='<text x="'+(LW-6)+'" y="'+(y+bH/2+4)+'" text-anchor="end" font-family="'+FONT+'" font-size="11" fill="#43342d">'+esc(d.lang)+'</text>';
          if(cW>0.5)bs+='<rect'+tt(d.lang+' Code',fmt(d.code)+' lines')+' x="'+px(x)+'" y="'+y+'" width="'+px(cW)+'" height="'+bH+'" fill="'+OX+'"/>';x+=cW;
          if(cmW>0.5)bs+='<rect'+tt(d.lang+' Comments',fmt(d.comments)+' lines')+' x="'+px(x)+'" y="'+y+'" width="'+px(cmW)+'" height="'+bH+'" fill="'+GN+'"/>';x+=cmW;
          if(blW>0.5)bs+='<rect'+tt(d.lang+' Blank',fmt(d.blanks)+' lines')+' x="'+px(x)+'" y="'+y+'" width="'+px(blW)+'" height="'+bH+'" fill="'+GY+'"/>';
          bs+='<text x="'+(LW+BW+5)+'" y="'+(y+bH/2+4)+'" font-family="'+FONT+'" font-size="11" fill="#7b675b">'+fmt(d.code+d.comments+d.blanks)+'</text>';
        });
        var ly=SH-14;
        bs+='<rect x="'+LW+'" y="'+ly+'" width="9" height="9" fill="'+OX+'"/><text x="'+(LW+13)+'" y="'+(ly+9)+'" font-family="'+FONT+'" font-size="10" font-weight="700" fill="#43342d">Code</text>';
        bs+='<rect x="'+(LW+54)+'" y="'+ly+'" width="9" height="9" fill="'+GN+'"/><text x="'+(LW+67)+'" y="'+(ly+9)+'" font-family="'+FONT+'" font-size="10" font-weight="700" fill="#43342d">Comments</text>';
        bs+='<rect x="'+(LW+152)+'" y="'+ly+'" width="9" height="9" fill="'+GY+'"/><text x="'+(LW+165)+'" y="'+(ly+9)+'" font-family="'+FONT+'" font-size="10" font-weight="700" fill="#43342d">Blanks</text>';
        bs+='</svg>';
        el.innerHTML='<div class="r-lang-overview">'+
          '<div class="r-lang-overview-cell"><p>Code Lines by Language</p>'+ds+'</div>'+
          '<div class="r-lang-overview-cell" style="flex:2 1 340px;"><p>Line Mix per Language</p>'+bs+'</div>'+
        '</div>';
      })();

      // ── Project Overview bar ─────────────────────────────────────────────────
      var projChart = null;
      (function() {
        var ySel = document.getElementById('overview-y-axis');
        var xSel = document.getElementById('overview-x-mode');
        var el = document.getElementById('overview-chart');
        var lockedEl = document.getElementById('overview-chart-locked');
        var wrap = document.getElementById('canvas-proj-wrap');
        var canvas = document.getElementById('canvas-proj');
        if (!canvas || !ySel || !xSel) return;
        var Y_LABELS = { code:'Code Lines', comments:'Comment Lines', blanks:'Blank Lines',
                         physical:'Physical Lines', files:'Files', comment:'Comment Lines', blank:'Blank Lines' };
        function getData() {
          var yKey = ySel.value, mode = xSel.value;
          var src = mode === 'submodules' ? SUB_D : D;
          var lKey = mode === 'submodules' ? 'name' : 'lang';
          var sorted = src.slice().sort(function(a,b){ return (b[yKey]||0)-(a[yKey]||0); });
          return { sorted: sorted, lKey: lKey, yKey: yKey, yLabel: Y_LABELS[yKey]||yKey };
        }
        function renderOverview() {
          var mode = xSel.value, isHist = mode.indexOf('history') === 0;
          if (el) el.style.display = isHist ? 'none' : 'block';
          if (lockedEl) lockedEl.style.display = isHist ? 'block' : 'none';
          if (isHist) return;
          var r = getData();
          var c = clr();
          if (wrap) wrap.style.height = Math.max(90, Math.min(432, r.sorted.length * 29 + 36)) + 'px';
          if (projChart) {
            projChart.data.labels = r.sorted.map(function(d){return d[r.lKey];});
            projChart.data.datasets[0].data = r.sorted.map(function(d){return d[r.yKey]||0;});
            projChart.data.datasets[0].backgroundColor = r.sorted.map(function(_,i){return PALETTE[i%PALETTE.length];});
            projChart.data.datasets[0].label = r.yLabel;
            projChart.options.scales.x.title.text = r.yLabel;
            projChart.update('none'); return;
          }
          projChart = new Chart(canvas, {
            type: 'bar',
            data: {
              labels: r.sorted.map(function(d){return d[r.lKey];}),
              datasets: [{ label: r.yLabel,
                data: r.sorted.map(function(d){return d[r.yKey]||0;}),
                backgroundColor: r.sorted.map(function(_,i){return PALETTE[i%PALETTE.length];}),
                borderRadius: 3 }]
            },
            options: {
              indexAxis: 'y', responsive: true, maintainAspectRatio: false,
              animation: { duration: 500, easing: 'easeOutQuart' },
              layout: { padding: { right: 64 } },
              scales: {
                x: { grid: { color: c.grid }, ticks: { color: c.text, callback: function(v){return fmt(v);} },
                     title: { display: true, text: r.yLabel, color: c.text } },
                y: { grid: { display: false }, ticks: { color: c.text } }
              },
              plugins: {
                legend: { display: false },
                tooltip: {
                  callbacks: {
                    title: function(items) { return items.length ? items[0].label : ''; },
                    label: function(ctx) {
                      return '  ' + ctx.dataset.label + ': ' + Number(ctx.parsed.x).toLocaleString();
                    }
                  }
                }
              }
            },
            plugins: [makeDlPlugin(function(v){ return fmt(v||0); }, 'end')]
          });
          ALL_CHARTS.push(projChart);
        }
        ySel.addEventListener('change', renderOverview);
        xSel.addEventListener('change', renderOverview);
        renderOverview();

        var overviewExpandBtn = document.getElementById('overview-expand-btn');
        if (overviewExpandBtn) {
          overviewExpandBtn.addEventListener('click', function() {
            var r = getData();
            var n = r.sorted.length || 1;
            var maxH = Math.max(400, Math.floor(window.innerHeight * 0.82) - 130);
            var modalH = Math.min(Math.max(480, n * 29 + 96), maxH);
            var overlay = document.createElement('div');
            overlay.className = 'chart-modal-overlay';
            overlay.innerHTML = '<div class="chart-modal" style="max-width:1320px;">'
              + '<button class="chart-modal-close" aria-label="Close">&times;</button>'
              + '<span class="chart-modal-title">Project Overview — Full View</span>'
              + '<div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:14px;">'
              + '<label style="font-size:13px;font-weight:700;color:var(--muted);display:flex;align-items:center;gap:6px;">Y Axis:'
              + '<select id="ov-modal-y" class="chart-select">'
              + '<option value="code">Code Lines</option>'
              + '<option value="comments">Comment Lines</option>'
              + '<option value="blanks">Blank Lines</option>'
              + '<option value="physical">Total Physical Lines</option>'
              + '<option value="files">File Count</option>'
              + '</select></label>'
              + (SUB_D && SUB_D.length ? '<label style="font-size:13px;font-weight:700;color:var(--muted);display:flex;align-items:center;gap:6px;">X Axis:'
              + '<select id="ov-modal-x" class="chart-select">'
              + '<option value="languages">Languages</option>'
              + '<option value="submodules">Submodules</option>'
              + '</select></label>' : '')
              + '</div>'
              + '<div style="position:relative;height:' + modalH + 'px;width:100%;"><canvas id="canvas-proj-modal"></canvas></div></div>';
            document.body.appendChild(overlay);
            overlay.querySelector('.chart-modal-close').addEventListener('click', function() { document.body.removeChild(overlay); });
            overlay.addEventListener('click', function(e) { if (e.target === overlay) document.body.removeChild(overlay); });
            var Y_LABELS = { code:'Code Lines', comments:'Comment Lines', blanks:'Blank Lines', physical:'Physical Lines', files:'Files' };
            var modalYSel = document.getElementById('ov-modal-y');
            var modalXSel = document.getElementById('ov-modal-x');
            if (modalYSel) modalYSel.value = ySel ? ySel.value : 'code';
            if (modalXSel && xSel) modalXSel.value = (xSel.value === 'languages' || xSel.value === 'submodules') ? xSel.value : 'languages';
            var modalCanvas = document.getElementById('canvas-proj-modal');
            if (!modalCanvas) return;
            var c = clr();
            function getModalData() {
              var yKey = modalYSel ? modalYSel.value : 'code';
              var mode = modalXSel ? modalXSel.value : 'languages';
              var src = mode === 'submodules' ? SUB_D : D;
              var lKey = mode === 'submodules' ? 'name' : 'lang';
              var sorted = src.slice().sort(function(a,b){ return (b[yKey]||0)-(a[yKey]||0); });
              return { sorted: sorted, lKey: lKey, yKey: yKey, yLabel: Y_LABELS[yKey]||yKey };
            }
            var ovModalChart = null;
            function renderOverviewModal() {
              var r2 = getModalData();
              if (ovModalChart) {
                ovModalChart.data.labels = r2.sorted.map(function(d){return d[r2.lKey];});
                ovModalChart.data.datasets[0].data = r2.sorted.map(function(d){return d[r2.yKey]||0;});
                ovModalChart.data.datasets[0].backgroundColor = r2.sorted.map(function(_,i){return PALETTE[i%PALETTE.length];});
                ovModalChart.data.datasets[0].label = r2.yLabel;
                ovModalChart.options.scales.x.title.text = r2.yLabel;
                ovModalChart.update('none'); return;
              }
              ovModalChart = new Chart(modalCanvas, {
                type: 'bar',
                data: {
                  labels: r2.sorted.map(function(d){return d[r2.lKey];}),
                  datasets: [{ label: r2.yLabel,
                    data: r2.sorted.map(function(d){return d[r2.yKey]||0;}),
                    backgroundColor: r2.sorted.map(function(_,i){return PALETTE[i%PALETTE.length];}),
                    borderRadius: 3 }]
                },
                options: {
                  indexAxis: 'y', responsive: true, maintainAspectRatio: false,
                  layout: { padding: { right: 64 } },
                  scales: {
                    x: { grid:{color:c.grid}, ticks:{color:c.text, callback:function(v){return fmt(v);}},
                         title:{display:true, text:r2.yLabel, color:c.text} },
                    y: { grid:{display:false}, ticks:{color:c.text} }
                  },
                  plugins: {
                    legend:{display:false},
                    tooltip:{callbacks:{
                      title:function(items){return items.length?items[0].label:'';},
                      label:function(ctx){return '  '+ctx.dataset.label+': '+Number(ctx.parsed.x).toLocaleString();}
                    }}
                  }
                },
                plugins: [makeDlPlugin(function(v){ return fmt(v||0); }, 'end')]
              });
            }
            renderOverviewModal();
            if (modalYSel) modalYSel.addEventListener('change', renderOverviewModal);
            if (modalXSel) modalXSel.addEventListener('change', renderOverviewModal);
          });
        }
      })();

      // ── Language Composition ─────────────────────────────────────────────────
      var compChart = null;
      (function() {
        var wrap = document.getElementById('canvas-comp-wrap');
        var canvas = document.getElementById('canvas-comp');
        if (!canvas) return;
        var data = D.slice(0, 15);
        var compMode = 'absolute';
        if (wrap) wrap.style.height = Math.max(90, Math.min(432, data.length * 25 + 44)) + 'px';
        function renderComp() {
          var c = clr(), isPct = compMode === 'pct';
          var tot = function(d){ return (d.code||0)+(d.comments||0)+(d.blanks||0)||1; };
          var codeD = data.map(function(d){ return isPct ? (d.code||0)/tot(d)*100 : d.code||0; });
          var cmD   = data.map(function(d){ return isPct ? (d.comments||0)/tot(d)*100 : d.comments||0; });
          var blD   = data.map(function(d){ return isPct ? (d.blanks||0)/tot(d)*100 : d.blanks||0; });
          var tickCb = isPct ? function(v){return v.toFixed(0)+'%';} : function(v){return fmt(v);};
          if (compChart) {
            compChart.data.datasets[0].data = codeD;
            compChart.data.datasets[1].data = cmD;
            compChart.data.datasets[2].data = blD;
            compChart.options.scales.x.ticks.callback = tickCb;
            compChart.update('none'); return;
          }
          compChart = new Chart(canvas, {
            type: 'bar',
            data: {
              labels: data.map(function(d){ return d.lang; }),
              datasets: [
                { label:'Code',     data: codeD, backgroundColor: OX, borderRadius: 3 },
                { label:'Comments', data: cmD,   backgroundColor: GN, borderRadius: 3 },
                { label:'Blanks',   data: blD,   backgroundColor: GY, borderRadius: 3 }
              ]
            },
            options: {
              indexAxis: 'y', responsive: true, maintainAspectRatio: false,
              animation: { duration: 500, easing: 'easeOutQuart' },
              layout: { padding: { right: 64 } },
              scales: {
                x: { stacked: true, grid: { color: c.grid }, ticks: { color: c.text, callback: tickCb } },
                y: { stacked: true, grid: { display: false }, ticks: { color: c.text } }
              },
              plugins: {
                legend: { position: 'bottom', labels: { color: c.text } },
                tooltip: {
                  mode: 'index', axis: 'y', intersect: false,
                  callbacks: {
                    title: function(items) { return items.length ? items[0].label : ''; },
                    label: function(ctx) {
                      var val = isPct
                        ? '  ' + ctx.dataset.label + ': ' + ctx.parsed.x.toFixed(1) + '% of physical lines'
                        : '  ' + ctx.dataset.label + ': ' + fmt(ctx.parsed.x) + ' lines';
                      return val;
                    },
                    footer: function(items) {
                      if (isPct) return '';
                      var tot2 = items.reduce(function(s,i){return s+(i.parsed.x||0);},0);
                      return 'Total: ' + Number(tot2).toLocaleString() + ' lines';
                    }
                  }
                }
              }
            },
            plugins: [makeStackedEndPlugin(function(total) {
              if (compMode === 'pct') return '';
              return fmt(Math.round(total));
            })]
          });
          ALL_CHARTS.push(compChart);
        }
        document.querySelectorAll('[data-comp-tab]').forEach(function(btn){
          btn.addEventListener('click', function(){
            document.querySelectorAll('[data-comp-tab]').forEach(function(b){b.classList.remove('active');});
            btn.classList.add('active');
            compMode = btn.getAttribute('data-comp-tab');
            renderComp();
          });
        });
        renderComp();
      })();

      // ── Scatter / Bubble chart ────────────────────────────────────────────────
      (function() {
        var canvas = document.getElementById('canvas-scatter');
        if (!canvas || !SCAT_D || !SCAT_D.length) return;
        var maxP = Math.max.apply(null, SCAT_D.map(function(d){return d.physical;})) || 1;
        var c = clr();
        var chart = new Chart(canvas, {
          type: 'bubble',
          data: {
            datasets: SCAT_D.map(function(d, i) {
              return {
                label: d.lang,
                data: [{ x: d.files, y: d.code, r: Math.max(5, Math.round(Math.sqrt(d.physical/maxP)*20)) }],
                backgroundColor: PALETTE[i % PALETTE.length] + 'b8',
                borderColor: PALETTE[i % PALETTE.length], borderWidth: 1,
                hoverBorderWidth: 2
              };
            })
          },
          options: {
            responsive: true, maintainAspectRatio: false,
            animation: { duration: 500, easing: 'easeOutQuart' },
            layout: { padding: { top: 18 } },
            scales: {
              x: { grid: { color: c.grid }, ticks: { color: c.text },
                   title: { display: true, text: 'Files Analyzed', color: c.text } },
              y: { grid: { color: c.grid }, ticks: { color: c.text, callback: function(v){return fmt(v);} },
                   title: { display: true, text: 'Code Lines', color: c.text } }
            },
            plugins: {
              legend: { position: 'right', labels: { color: c.text } },
              tooltip: {
                callbacks: {
                  title: function(items) { return items.length ? items[0].dataset.label : ''; },
                  label: function(ctx){
                    var d = SCAT_D[ctx.datasetIndex];
                    return [
                      '  Files analyzed: ' + fmt(d.files),
                      '  Code lines: ' + Number(d.code).toLocaleString(),
                      '  Physical lines: ' + Number(d.physical).toLocaleString()
                    ];
                  }
                }
              }
            }
          },
          plugins: [makeDlPlugin(function(raw, di) {
            return SCAT_D[di] ? SCAT_D[di].lang : '';
          }, 'bubble')]
        });
        ALL_CHARTS.push(chart);
      })();

      // ── Submodule breakdown ──────────────────────────────────────────────────
      var subChart = null;
      (function() {
        if (!SUB_D || !SUB_D.length) return;
        var subYSel = document.getElementById('sub-y-axis');
        var subSortSel = document.getElementById('sub-sort');
        var wrap = document.getElementById('canvas-sub-wrap');
        var canvas = document.getElementById('canvas-sub');
        if (!canvas) return;
        var Y_LABELS = { code:'Code Lines', comment:'Comment Lines', blank:'Blank Lines',
                         physical:'Physical Lines', files:'Files' };
        var SUB_COLS = { code:OX, comment:GN, blank:GY, physical:'#4472C4', files:'#805099' };
        function renderSubmodule() {
          var yKey = subYSel ? subYSel.value : 'code';
          var sortMode = subSortSel ? subSortSel.value : 'desc';
          var data = SUB_D.slice();
          if (sortMode==='desc') data.sort(function(a,b){return (b[yKey]||0)-(a[yKey]||0);});
          else if (sortMode==='asc') data.sort(function(a,b){return (a[yKey]||0)-(b[yKey]||0);});
          else data.sort(function(a,b){return a.name.localeCompare(b.name);});
          data = data.slice(0, 30);
          var c = clr();
          var col = SUB_COLS[yKey] || OX;
          if (wrap) wrap.style.height = Math.max(90, Math.min(540, data.length * 25 + 36)) + 'px';
          if (subChart) {
            subChart.data.labels = data.map(function(d){return d.name;});
            subChart.data.datasets[0].data = data.map(function(d){return d[yKey]||0;});
            subChart.data.datasets[0].backgroundColor = col;
            subChart.data.datasets[0].label = Y_LABELS[yKey]||yKey;
            subChart.options.scales.x.title.text = Y_LABELS[yKey]||yKey;
            subChart.update('none'); return;
          }
          subChart = new Chart(canvas, {
            type: 'bar',
            data: {
              labels: data.map(function(d){return d.name;}),
              datasets: [{ label: Y_LABELS[yKey]||yKey,
                data: data.map(function(d){return d[yKey]||0;}),
                backgroundColor: col, borderRadius: 3 }]
            },
            options: {
              indexAxis: 'y', responsive: true, maintainAspectRatio: false,
              animation: { duration: 500, easing: 'easeOutQuart' },
              scales: {
                x: { grid: { color: c.grid }, ticks: { color: c.text, callback: function(v){return fmt(v);} },
                     title: { display: true, text: Y_LABELS[yKey]||yKey, color: c.text } },
                y: { grid: { display: false }, ticks: { color: c.text } }
              },
              plugins: {
                legend: { display: false },
                tooltip: {
                  callbacks: {
                    title: function(items) { return items.length ? items[0].label : ''; },
                    label: function(ctx){
                      var d = data[ctx.dataIndex] || {};
                      return [
                        '  Code: ' + Number(d.code||0).toLocaleString(),
                        '  Comments: ' + Number(d.comment||0).toLocaleString(),
                        '  Blanks: ' + Number(d.blank||0).toLocaleString(),
                        '  Physical: ' + Number(d.physical||0).toLocaleString(),
                        '  Files: ' + fmt(d.files||0)
                      ];
                    }
                  }
                }
              }
            }
          });
          ALL_CHARTS.push(subChart);
        }
        if (subYSel) subYSel.addEventListener('change', renderSubmodule);
        if (subSortSel) subSortSel.addEventListener('change', renderSubmodule);
        renderSubmodule();
      })();

      // ── Submodule composition: stacked-bar (code / comments / blank) ─────────
      (function() {
        var el = document.getElementById('submodule-donut');
        if (!el || !SUB_D || !SUB_D.length) return;
        var FONT = 'Inter,ui-sans-serif,system-ui,-apple-system,sans-serif';
        function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
        var data = SUB_D.slice().sort(function(a,b){return ((b.code||0)+(b.comment||0)+(b.blank||0))-((a.code||0)+(a.comment||0)+(a.blank||0));}).slice(0,15);
        var maxT = Math.max.apply(null, data.map(function(d){return (d.code||0)+(d.comment||0)+(d.blank||0);})) || 1;
        // Match Breakdown chart height so both panels grow at the same rate.
        var wrapH = Math.max(150, Math.min(540, data.length * 25 + 36));
        var bH = Math.max(18, Math.min(62, Math.round((wrapH - 38) / data.length * 0.72)));
        var LW = 84;
        el.style.minHeight = wrapH + 'px';
        el.style.display = 'flex';
        el.style.flexDirection = 'column';
        el.style.justifyContent = 'center';
        var s = '<div style="width:100%;font-family:'+FONT+';padding:4px 0;">';
        data.forEach(function(d,i){
          var tot2 = (d.code||0)+(d.comment||0)+(d.blank||0);
          var pct = Math.round(tot2/maxT*1000)/10;
          var name = d.name.length > 12 ? d.name.slice(0,11)+'…' : d.name;
          var ttPct = Math.round(tot2/maxT*100);
          s += '<div style="display:flex;align-items:center;margin-bottom:'+(i<data.length-1?'5':'0')+'px;">';
          s += '<span style="width:'+LW+'px;flex-shrink:0;text-align:right;padding-right:7px;font-size:11px;color:#43342d;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="'+esc(d.name)+'">'+esc(name)+'</span>';
          s += '<div style="flex:1;">';
          s += '<div style="width:'+pct+'%;height:'+bH+'px;display:flex;border-radius:3px;overflow:hidden;min-width:2px;">';
          if((d.code||0)>0) s += '<div style="flex:'+(d.code||0)+';background:'+OX+';" data-ttl="'+esc(d.name)+' — Code" data-ttv="'+fmt(d.code||0)+' lines ('+ttPct+'% of largest)"></div>';
          if((d.comment||0)>0) s += '<div style="flex:'+(d.comment||0)+';background:'+GN+';" data-ttl="'+esc(d.name)+' — Comments" data-ttv="'+fmt(d.comment||0)+' lines"></div>';
          if((d.blank||0)>0) s += '<div style="flex:'+(d.blank||0)+';background:'+GY+';" data-ttl="'+esc(d.name)+' — Blank" data-ttv="'+fmt(d.blank||0)+' lines"></div>';
          s += '</div>';
          s += '</div>';
          s += '<span style="width:44px;flex-shrink:0;padding-left:5px;font-size:10px;color:#7b675b;font-variant-numeric:tabular-nums;">'+fmt(tot2)+'</span>';
          s += '</div>';
        });
        s += '<div style="display:flex;align-items:center;gap:14px;margin-top:10px;padding-left:'+(LW+1)+'px;font-size:11px;font-weight:700;color:#43342d;">';
        s += '<span style="display:flex;align-items:center;gap:4px;"><span style="display:inline-block;width:9px;height:9px;background:'+OX+';border-radius:1px;flex-shrink:0;"></span>Code</span>';
        s += '<span style="display:flex;align-items:center;gap:4px;"><span style="display:inline-block;width:9px;height:9px;background:'+GN+';border-radius:1px;flex-shrink:0;"></span>Comments</span>';
        s += '<span style="display:flex;align-items:center;gap:4px;"><span style="display:inline-block;width:9px;height:9px;background:'+GY+';border-radius:1px;flex-shrink:0;"></span>Blank</span>';
        s += '</div>';
        s += '</div>';
        el.innerHTML = s;
      })();

      // ── Semantic Metrics ─────────────────────────────────────────────────────
      (function() {
        if (!SEM_D || !SEM_D.length) return;
        var semSel = document.getElementById('semantic-metric');
        var canvas = document.getElementById('canvas-semantic');
        if (!canvas) return;
        var SEM_LABELS = { functions:'Functions', classes:'Classes / Types', variables:'Variables',
                           imports:'Imports', tests:'Tests' };
        var SEM_COLS = { functions:OX, classes:'#4472C4', variables:GN, imports:'#805099', tests:'#B23030' };
        var semChart = null;
        function renderSemantic() {
          var mKey = semSel ? semSel.value : 'functions';
          var data = SEM_D.slice().sort(function(a,b){return (b[mKey]||0)-(a[mKey]||0);}).slice(0,15);
          var c = clr();
          var col = SEM_COLS[mKey] || OX;
          if (semChart) {
            semChart.data.labels = data.map(function(d){return d.lang;});
            semChart.data.datasets[0].data = data.map(function(d){return d[mKey]||0;});
            semChart.data.datasets[0].backgroundColor = col;
            semChart.data.datasets[0].label = SEM_LABELS[mKey]||mKey;
            semChart.update('none'); return;
          }
          semChart = new Chart(canvas, {
            type: 'bar',
            data: {
              labels: data.map(function(d){return d.lang;}),
              datasets: [{ label: SEM_LABELS[mKey]||mKey,
                data: data.map(function(d){return d[mKey]||0;}),
                backgroundColor: col, borderRadius: 4 }]
            },
            options: {
              responsive: true, maintainAspectRatio: false,
              animation: { duration: 500, easing: 'easeOutQuart' },
              layout: { padding: { top: 18 } },
              scales: {
                x: { grid: { display: false }, ticks: { color: c.text } },
                y: { grid: { color: c.grid }, ticks: { color: c.text, callback: function(v){return fmt(v);} } }
              },
              plugins: {
                legend: { display: false },
                tooltip: {
                  callbacks: {
                    title: function(items) { return items.length ? items[0].label : ''; },
                    label: function(ctx) {
                      var d = data[ctx.dataIndex] || {};
                      var lines = ['  ' + (SEM_LABELS[mKey]||mKey) + ': ' + Number(ctx.parsed.y).toLocaleString()];
                      var others = Object.keys(SEM_LABELS).filter(function(k){ return k !== mKey && (d[k]||0) > 0; });
                      others.forEach(function(k) {
                        lines.push('  ' + SEM_LABELS[k] + ': ' + Number(d[k]||0).toLocaleString());
                      });
                      return lines;
                    }
                  }
                }
              }
            },
            plugins: [makeDlPlugin(function(v) { return fmt(v || 0); }, 'top')]
          });
          ALL_CHARTS.push(semChart);
        }
        if (semSel) semSel.addEventListener('change', renderSemantic);
        renderSemantic();

        var semExpandBtn = document.getElementById('semantic-expand-btn');
        if (semExpandBtn) {
          semExpandBtn.addEventListener('click', function() {
            var mKey = semSel ? semSel.value : 'functions';
            var n = SEM_D.length || 1;
            var maxH = Math.max(400, Math.floor(window.innerHeight * 0.82) - 130);
            var modalH = Math.min(Math.max(400, n * 46 + 96), maxH);
            var overlay = document.createElement('div');
            overlay.className = 'chart-modal-overlay';
            var semLabels2 = { functions:'Functions', classes:'Classes / Types', variables:'Variables' };
            var semSubtitle2 = semLabels2[mKey] || mKey;
            overlay.innerHTML = '<div class="chart-modal" style="max-width:1320px;"><button class="chart-modal-close" aria-label="Close">&times;</button><span class="chart-modal-title">Semantic Metrics — Full View</span><span class="chart-modal-subtitle">' + semSubtitle2 + '</span><div style="position:relative;height:' + modalH + 'px;width:100%;"><canvas id="canvas-semantic-modal"></canvas></div></div>';
            document.body.appendChild(overlay);
            overlay.querySelector('.chart-modal-close').addEventListener('click', function() { document.body.removeChild(overlay); });
            overlay.addEventListener('click', function(e) { if (e.target === overlay) document.body.removeChild(overlay); });
            var modalCanvas = document.getElementById('canvas-semantic-modal');
            if (modalCanvas) {
              var data = SEM_D.slice().sort(function(a,b){return (b[mKey]||0)-(a[mKey]||0);});
              var c = clr();
              var col = SEM_COLS[mKey] || OX;
              new Chart(modalCanvas, {
                type: 'bar',
                data: {
                  labels: data.map(function(d){return d.lang;}),
                  datasets: [{ label: SEM_LABELS[mKey]||mKey, data: data.map(function(d){return d[mKey]||0;}),
                    backgroundColor: col, borderRadius: 4 }]
                },
                options: {
                  responsive: true, maintainAspectRatio: false,
                  layout: { padding: { top: 18 } },
                  scales: {
                    x: { grid: { display: false }, ticks: { color: c.text } },
                    y: { grid: { color: c.grid }, ticks: { color: c.text, callback: function(v){return fmt(v);} } }
                  },
                  plugins: { legend: { display: false }, tooltip: { callbacks: {
                    title: function(items){return items.length?items[0].label:'';},
                    label: function(ctx){ return '  '+(SEM_LABELS[mKey]||mKey)+': '+Number(ctx.parsed.y).toLocaleString(); }
                  }}}
                },
                plugins: [makeDlPlugin(function(v) { return fmt(v || 0); }, 'top')]
              });
            }
          });
        }
      })();

      // ── Comment Density: comments / (code + comments) per language ──────────
      (function() {
        var canvas = document.getElementById('canvas-density');
        if (!canvas || !D || !D.length) return;
        var data = D.slice().sort(function(a,b){
          var da=(a.comments||0)/Math.max((a.code||0)+(a.comments||0),1);
          var db=(b.comments||0)/Math.max((b.code||0)+(b.comments||0),1);
          return db-da;
        });
        var labels = data.map(function(d){return d.lang;});
        var densities = data.map(function(d){
          var sig=(d.code||0)+(d.comments||0);
          return sig>0?Math.round((d.comments||0)/sig*1000)/10:0;
        });
        var wrap = canvas.parentElement;
        if (wrap) wrap.style.height = Math.max(150, Math.min(500, data.length*29+36))+'px';
        var c = clr();
        var densChart = new Chart(canvas, {
          type: 'bar',
          data: {
            labels: labels,
            datasets: [{ label: 'Comment %',
              data: densities,
              backgroundColor: data.map(function(_,i){return PALETTE[i%PALETTE.length];}),
              borderRadius: 4
            }]
          },
          options: {
            indexAxis: 'y', responsive: true, maintainAspectRatio: false,
            animation: { duration: 500, easing: 'easeOutQuart' },
            layout: { padding: { right: 42 } },
            scales: {
              x: { min: 0, max: 100,
                   grid: { color: c.grid },
                   ticks: { color: c.text, callback: function(v){return v+'%';} },
                   title: { display: true, text: 'Comment %', color: c.text } },
              y: { grid: { display: false }, ticks: { color: c.text } }
            },
            plugins: {
              legend: { display: false },
              tooltip: { callbacks: {
                title: function(items){return items.length?items[0].label:'';},
                label: function(ctx){
                  var d=data[ctx.dataIndex]||{};
                  var sig=(d.code||0)+(d.comments||0);
                  return ['  Comment ratio: '+ctx.parsed.x+'%',
                          '  Comments: '+Number(d.comments||0).toLocaleString(),
                          '  Significant lines: '+Number(sig).toLocaleString()];
                }
              }}
            }
          },
          plugins: [makeDlPlugin(function(v) { return (v || 0) + '%'; }, 'end')]
        });
        ALL_CHARTS.push(densChart);
      })();

      // ── File Size Distribution histogram ──────────────────────────────────────
      (function() {
        var canvas = document.getElementById('canvas-filesize');
        if (!canvas || !HIST_D || !HIST_D.length) return;
        var labels = HIST_D.map(function(d){return d.label;});
        var counts = HIST_D.map(function(d){return d.count||0;});
        var total = counts.reduce(function(a,b){return a+b;},0);
        var c = clr();
        var fsChart = new Chart(canvas, {
          type: 'bar',
          data: {
            labels: labels,
            datasets: [{ label: 'Files',
              data: counts,
              backgroundColor: ['#2A6846','#4472C4','#C45C10','#D4A017','#B23030'],
              borderRadius: 6
            }]
          },
          options: {
            responsive: true, maintainAspectRatio: false,
            animation: { duration: 500, easing: 'easeOutQuart' },
            layout: { padding: { top: 18 } },
            scales: {
              x: { grid: { display: false }, ticks: { color: c.text, font: { size: 11 } } },
              y: { beginAtZero: true,
                   grid: { color: c.grid },
                   ticks: { color: c.text, precision: 0 },
                   title: { display: true, text: 'File Count', color: c.text } }
            },
            plugins: {
              legend: { display: false },
              tooltip: { callbacks: {
                label: function(ctx) {
                  var n = ctx.parsed.y;
                  var pct = total > 0 ? Math.round(n/total*1000)/10 : 0;
                  return ['  Files: '+n, '  Share: '+pct+'%'];
                }
              }}
            }
          },
          plugins: [makeDlPlugin(function(v) { return fmt(v || 0); }, 'top')]
        });
        ALL_CHARTS.push(fsChart);
      })();

      // ── Expand button handlers ────────────────────────────────────────────────
      (function() {
        function makeOverlay(title, h, subtitle) {
          var overlay = document.createElement('div');
          overlay.className = 'chart-modal-overlay';
          var maxH = Math.max(400, Math.floor(window.innerHeight * 0.82) - 130);
          var hAttr = 'height:' + Math.min(h || 696, maxH) + 'px;';
          var subHtml = subtitle ? '<span class="chart-modal-subtitle">' + subtitle + '</span>' : '';
          overlay.innerHTML = '<div class="chart-modal" style="max-width:1320px;"><button class="chart-modal-close" aria-label="Close">&times;</button><span class="chart-modal-title">' + title + '</span>' + subHtml + '<div style="position:relative;width:100%;' + hAttr + '"><canvas id="modal-expand-canvas"></canvas></div></div>';
          document.body.appendChild(overlay);
          overlay.querySelector('.chart-modal-close').addEventListener('click', function(){ document.body.removeChild(overlay); });
          overlay.addEventListener('click', function(e){ if(e.target === overlay) document.body.removeChild(overlay); });
          return document.getElementById('modal-expand-canvas');
        }

        // Language Composition
        (function(){
          var btn = document.getElementById('comp-expand-btn');
          if(!btn) return;
          btn.addEventListener('click', function(){
            var activeTab = document.querySelector('[data-comp-tab].active');
            var compMode = activeTab ? activeTab.getAttribute('data-comp-tab') : 'absolute';
            var compLabel = compMode === 'pct' ? 'Composition %' : 'Absolute Lines';
            var canvas = makeOverlay('Language Composition — Full View', undefined, compLabel);
            if(!canvas) return;
            var data = D.slice(0, 15);
            var c = clr(), isPct = compMode === 'pct';
            var tot = function(d){ return (d.code||0)+(d.comments||0)+(d.blanks||0)||1; };
            var codeD = data.map(function(d){ return isPct ? (d.code||0)/tot(d)*100 : d.code||0; });
            var cmD   = data.map(function(d){ return isPct ? (d.comments||0)/tot(d)*100 : d.comments||0; });
            var blD   = data.map(function(d){ return isPct ? (d.blanks||0)/tot(d)*100 : d.blanks||0; });
            var tickCb = isPct ? function(v){return v.toFixed(0)+'%';} : function(v){return fmt(v);};
            new Chart(canvas, {
              type: 'bar',
              data: {
                labels: data.map(function(d){ return d.lang; }),
                datasets: [
                  { label:'Code',     data: codeD, backgroundColor: OX, borderRadius: 3 },
                  { label:'Comments', data: cmD,   backgroundColor: GN, borderRadius: 3 },
                  { label:'Blanks',   data: blD,   backgroundColor: GY, borderRadius: 3 }
                ]
              },
              options: {
                indexAxis: 'y', responsive: true, maintainAspectRatio: false,
                layout: { padding: { right: 64 } },
                scales: {
                  x: { stacked: true, grid: { color: c.grid }, ticks: { color: c.text, callback: tickCb } },
                  y: { stacked: true, grid: { display: false }, ticks: { color: c.text } }
                },
                plugins: { legend: { position: 'bottom', labels: { color: c.text } } }
              },
              plugins: [makeStackedEndPlugin(function(total) {
                if (isPct) return '';
                return fmt(Math.round(total));
              })]
            });
          });
        })();

        // File Count vs SLOC (Scatter)
        (function(){
          var btn = document.getElementById('scatter-expand-btn');
          if(!btn || !SCAT_D || !SCAT_D.length) return;
          btn.addEventListener('click', function(){
            var canvas = makeOverlay('File Count vs SLOC — Full View', undefined, 'File count vs SLOC per language');
            if(!canvas) return;
            var maxP = Math.max.apply(null, SCAT_D.map(function(d){return d.physical;})) || 1;
            var c = clr();
            new Chart(canvas, {
              type: 'bubble',
              data: {
                datasets: SCAT_D.map(function(d, i) {
                  return {
                    label: d.lang,
                    data: [{ x: d.files, y: d.code, r: Math.max(5, Math.round(Math.sqrt(d.physical/maxP)*20)) }],
                    backgroundColor: PALETTE[i % PALETTE.length] + 'b8',
                    borderColor: PALETTE[i % PALETTE.length], borderWidth: 1
                  };
                })
              },
              options: {
                responsive: true, maintainAspectRatio: false,
                scales: {
                  x: { grid: { color: c.grid }, ticks: { color: c.text }, title: { display: true, text: 'Files Analyzed', color: c.text } },
                  y: { grid: { color: c.grid }, ticks: { color: c.text, callback: function(v){return fmt(v);} }, title: { display: true, text: 'Code Lines', color: c.text } }
                },
                plugins: {
                  legend: { position: 'right', labels: { color: c.text } },
                  tooltip: { callbacks: {
                    title: function(items){ return items.length ? items[0].dataset.label : ''; },
                    label: function(ctx){ var d = SCAT_D[ctx.datasetIndex]; return ['  Files: '+fmt(d.files), '  Code: '+Number(d.code).toLocaleString()]; }
                  }}
                }
              },
              plugins: [makeDlPlugin(function(raw, di) {
                return SCAT_D[di] ? SCAT_D[di].lang : '';
              }, 'bubble')]
            });
          });
        })();

        // Comment Density
        (function(){
          var btn = document.getElementById('density-expand-btn');
          if(!btn) return;
          btn.addEventListener('click', function(){
            var data = D.slice().sort(function(a,b){
              var da=(a.comments||0)/Math.max((a.code||0)+(a.comments||0),1);
              var db=(b.comments||0)/Math.max((b.code||0)+(b.comments||0),1);
              return db-da;
            });
            var h = Math.min(Math.max(672, data.length * 46 + 96), Math.max(400, Math.floor(window.innerHeight * 0.82) - 130));
            var canvas = makeOverlay('Comment Density — Full View', h, 'Comment ratio per language');
            if(!canvas) return;
            var densities = data.map(function(d){ var sig=(d.code||0)+(d.comments||0); return sig>0?Math.round((d.comments||0)/sig*1000)/10:0; });
            var c = clr();
            new Chart(canvas, {
              type: 'bar',
              data: {
                labels: data.map(function(d){return d.lang;}),
                datasets: [{ label: 'Comment %', data: densities,
                  backgroundColor: data.map(function(_,i){return PALETTE[i%PALETTE.length];}), borderRadius: 4 }]
              },
              options: {
                indexAxis: 'y', responsive: true, maintainAspectRatio: false,
                layout: { padding: { right: 42 } },
                scales: {
                  x: { min:0, max:100, grid:{color:c.grid}, ticks:{color:c.text, callback:function(v){return v+'%';}} },
                  y: { grid:{display:false}, ticks:{color:c.text} }
                },
                plugins: { legend:{display:false}, tooltip:{callbacks:{label:function(ctx){return '  Comment %: '+ctx.parsed.x.toFixed(1)+'%';}}} }
              },
              plugins: [makeDlPlugin(function(v) { return (v || 0) + '%'; }, 'end')]
            });
          });
        })();

        // File Size Distribution
        (function(){
          var btn = document.getElementById('filesize-expand-btn');
          if(!btn || !HIST_D || !HIST_D.length) return;
          btn.addEventListener('click', function(){
            var canvas = makeOverlay('File Size Distribution — Full View', undefined, 'File count per SLOC bucket');
            if(!canvas) return;
            var labels = HIST_D.map(function(d){return d.label;});
            var counts = HIST_D.map(function(d){return d.count||0;});
            var total = counts.reduce(function(a,b){return a+b;},0);
            var c = clr();
            new Chart(canvas, {
              type: 'bar',
              data: {
                labels: labels,
                datasets: [{ label: 'Files', data: counts,
                  backgroundColor: ['#2A6846','#4472C4','#C45C10','#D4A017','#B23030'], borderRadius: 6 }]
              },
              options: {
                responsive: true, maintainAspectRatio: false,
                layout: { padding: { top: 18 } },
                scales: {
                  x: { grid:{display:false}, ticks:{color:c.text} },
                  y: { beginAtZero:true, grid:{color:c.grid}, ticks:{color:c.text, precision:0}, title:{display:true, text:'File Count', color:c.text} }
                },
                plugins: { legend:{display:false}, tooltip:{callbacks:{label:function(ctx){ var pct=total>0?Math.round(ctx.parsed.y/total*1000)/10:0; return ['  Files: '+ctx.parsed.y, '  Share: '+pct+'%']; }}} }
              },
              plugins: [makeDlPlugin(function(v) { return fmt(v || 0); }, 'top')]
            });
          });
        })();

        // Submodule Breakdown
        (function(){
          var btn = document.getElementById('sub-expand-btn');
          if(!btn || !SUB_D || !SUB_D.length) return;
          btn.addEventListener('click', function(){
            var subYSel = document.getElementById('sub-y-axis');
            var subSortSel = document.getElementById('sub-sort');
            var yKey = subYSel ? subYSel.value : 'code';
            var sortMode = subSortSel ? subSortSel.value : 'desc';
            var data = SUB_D.slice();
            if(sortMode==='desc') data.sort(function(a,b){return (b[yKey]||0)-(a[yKey]||0);});
            else if(sortMode==='asc') data.sort(function(a,b){return (a[yKey]||0)-(b[yKey]||0);});
            else data.sort(function(a,b){return a.name.localeCompare(b.name);});
            data = data.slice(0, 30);
            var Y_LABELS = { code:'Code Lines', comment:'Comment Lines', blank:'Blank Lines', physical:'Physical Lines', files:'Files' };
            var SUB_COLS = { code:OX, comment:GN, blank:GY, physical:'#4472C4', files:'#805099' };
            var h = Math.min(Math.max(672, data.length * 36 + 96), Math.max(400, Math.floor(window.innerHeight * 0.82) - 130));
            var subMetricLabels = { code:'Code Lines', comment:'Comment Lines', blank:'Blank Lines', physical:'Physical Lines', files:'Files' };
            var subSortLabels = { desc:'Value ↓', asc:'Value ↑', name:'Name A→Z' };
            var subLabel = (subMetricLabels[yKey]||yKey) + ' · ' + (subSortLabels[sortMode]||sortMode);
            var canvas = makeOverlay('Submodule Breakdown — Full View', h, subLabel);
            if(!canvas) return;
            var c = clr();
            new Chart(canvas, {
              type: 'bar',
              data: {
                labels: data.map(function(d){return d.name;}),
                datasets: [{ label: Y_LABELS[yKey]||yKey, data: data.map(function(d){return d[yKey]||0;}),
                  backgroundColor: SUB_COLS[yKey]||OX, borderRadius: 3 }]
              },
              options: {
                indexAxis: 'y', responsive: true, maintainAspectRatio: false,
                layout: { padding: { right: 64 } },
                scales: {
                  x: { grid:{color:c.grid}, ticks:{color:c.text, callback:function(v){return fmt(v);}}, title:{display:true, text:Y_LABELS[yKey]||yKey, color:c.text} },
                  y: { grid:{display:false}, ticks:{color:c.text} }
                },
                plugins: { legend:{display:false} }
              },
              plugins: [makeDlPlugin(function(v) { return fmt(v || 0); }, 'end')]
            });
          });
        })();

        // Submodule Composition (SVG-based — clone and display)
        (function(){
          var btn = document.getElementById('sub-comp-expand-btn');
          if(!btn) return;
          btn.addEventListener('click', function(){
            var src = document.getElementById('submodule-donut');
            if(!src) return;
            var overlay = document.createElement('div');
            overlay.className = 'chart-modal-overlay';
            overlay.innerHTML = '<div class="chart-modal"><button class="chart-modal-close" aria-label="Close">&times;</button><span class="chart-modal-title">Submodule Composition — Full View</span><span class="chart-modal-subtitle">Code vs comments vs blank per submodule</span><div id="sub-comp-modal-wrap" style="width:100%;overflow:hidden;"></div></div>';
            document.body.appendChild(overlay);
            overlay.querySelector('.chart-modal-close').addEventListener('click', function(){ document.body.removeChild(overlay); });
            overlay.addEventListener('click', function(e){ if(e.target===overlay) document.body.removeChild(overlay); });
            var wrap = document.getElementById('sub-comp-modal-wrap');
            if(wrap) { wrap.innerHTML = src.innerHTML; }
          });
        })();

        // Language overview (donut + line-mix) — clone both SVGs side-by-side
        (function(){
          var btn = document.getElementById('lang-overview-expand-btn');
          if(!btn) return;
          btn.addEventListener('click', function(){
            var src = document.getElementById('report-lang-overview');
            if(!src) return;
            var overlay = document.createElement('div');
            overlay.className = 'chart-modal-overlay';
            overlay.innerHTML = '<div class="chart-modal" style="max-width:1320px;"><button class="chart-modal-close" aria-label="Close">&times;</button><span class="chart-modal-title">Language Breakdown — Full View</span><span class="chart-modal-subtitle">All languages — click any column header to sort</span><div id="lang-overview-modal-wrap" style="width:100%;overflow:auto;"></div></div>';
            document.body.appendChild(overlay);
            overlay.querySelector('.chart-modal-close').addEventListener('click', function(){ document.body.removeChild(overlay); });
            overlay.addEventListener('click', function(e){ if(e.target===overlay) document.body.removeChild(overlay); });
            var wrap = document.getElementById('lang-overview-modal-wrap');
            if(wrap) { wrap.innerHTML = src.innerHTML; }
          });
        })();
      })();

      // ── Dark mode sync ────────────────────────────────────────────────────────
      document.querySelectorAll('[data-theme-toggle]').forEach(function(btn) {
        btn.addEventListener('click', function() {
          setTimeout(function() {
            var c = clr();
            ALL_CHARTS.forEach(function(chart) {
              if (chart.options.scales) {
                Object.keys(chart.options.scales).forEach(function(k) {
                  var ax = chart.options.scales[k];
                  if (ax.grid) ax.grid.color = c.grid;
                  if (ax.ticks) ax.ticks.color = c.text;
                  if (ax.title) ax.title.color = c.text;
                });
              }
              if (chart.options.plugins && chart.options.plugins.legend && chart.options.plugins.legend.labels)
                chart.options.plugins.legend.labels.color = c.text;
              chart.update('none');
            });
          }, 60);
        });
      });

      // ── Pre-render all chart variants for PDF export ──────────────────────────
      (function() {
        var root = document.getElementById('pdf-variants');
        if (!root) return;

        // Plugin: fill a light background behind every off-screen chart so the PNG
        // is opaque — without this Chart.js canvases are transparent and render as
        // blank white boxes in print.
        var PDF_BG = {
          id: 'pdfBg',
          beforeDraw: function(ch) {
            var ctx = ch.canvas.getContext('2d');
            ctx.save();
            ctx.globalCompositeOperation = 'destination-over';
            ctx.fillStyle = '#faf6f0';
            ctx.fillRect(0, 0, ch.canvas.width, ch.canvas.height);
            ctx.restore();
          }
        };

        // Off-screen Chart.js render → PNG data-URL → destroy chart
        function snap(type, data, opts, w, h) {
          var c = document.createElement('canvas');
          c.width = w || 900; c.height = h || 280;
          var ch = new Chart(c, {
            type: type, data: data,
            options: Object.assign({}, opts, {
              animation: false, responsive: false, devicePixelRatio: 1,
              // Breathing room so labels never clip at the canvas edge
              layout: { padding: { top: 10, right: 18, bottom: 10, left: 10 } }
            }),
            plugins: [PDF_BG]
          });
          var png = c.toDataURL('image/png');
          ch.destroy();
          return png;
        }

        function mkPanel(label, imgSrc) {
          var d = document.createElement('div'); d.className = 'pdf-variant-panel';
          if (label) {
            var lbl = document.createElement('div');
            lbl.className = 'pdf-variant-label'; lbl.textContent = label;
            d.appendChild(lbl);
          }
          if (imgSrc) {
            var img = document.createElement('img');
            img.className = 'pdf-variant-img'; img.src = imgSrc;
            d.appendChild(img);
          }
          return d;
        }

        function mkGroup(title) {
          var g = document.createElement('div'); g.className = 'pdf-variant-group';
          var h = document.createElement('h2'); h.className = 'pdf-variant-group-title'; h.textContent = title;
          g.appendChild(h);
          var grid = document.createElement('div'); grid.className = 'pdf-variant-grid';
          g.appendChild(grid);
          return { group: g, grid: grid };
        }

        var tc = '#43342d', gc = 'rgba(0,0,0,0.07)';

        // ── Project Overview — 4 Y-axis variants ─────────────────────────────────
        var pgProj = mkGroup('Project Overview');
        var projVariants = [
          { label:'Code Lines',     fn:function(d){return d.code||0;} },
          { label:'Comment Lines',  fn:function(d){return d.comments||0;} },
          { label:'Physical Lines', fn:function(d){return (d.code||0)+(d.comments||0)+(d.blanks||0);} },
          { label:'File Count',     fn:function(d){return d.files||0;} }
        ];
        projVariants.forEach(function(y) {
          var sorted = D.slice().sort(function(a,b){return y.fn(b)-y.fn(a);});
          var h = Math.max(110, Math.min(360, sorted.length*18+40));
          var png = snap('bar', {
            labels: sorted.map(function(d){return d.lang;}),
            datasets:[{ label:y.label, data:sorted.map(y.fn),
                        backgroundColor:sorted.map(function(_,i){return PALETTE[i%PALETTE.length];}), borderRadius:3 }]
          }, {
            indexAxis:'y',
            scales:{
              x:{grid:{color:gc},ticks:{color:tc,callback:function(v){return fmt(v);}},title:{display:true,text:y.label,color:tc}},
              y:{grid:{display:false},ticks:{color:tc}}
            },
            plugins:{legend:{display:false}}
          }, 900, h);
          pgProj.grid.appendChild(mkPanel(y.label, png));
        });
        root.appendChild(pgProj.group);

        // ── Language Composition — Absolute Lines + Composition % ────────────────
        var pgComp = mkGroup('Language Composition');
        var cData = D.slice(0,15);
        var totFn = function(d){return (d.code||0)+(d.comments||0)+(d.blanks||0)||1;};
        var compH = Math.max(110, Math.min(340, cData.length*18+50));
        [{id:'absolute',label:'Absolute Lines',isPct:false},{id:'pct',label:'Composition %',isPct:true}]
          .forEach(function(m) {
            var pct = m.isPct;
            var png = snap('bar', {
              labels: cData.map(function(d){return d.lang;}),
              datasets:[
                {label:'Code',     data:cData.map(function(d){return pct?(d.code||0)/totFn(d)*100:d.code||0;}),    backgroundColor:OX,borderRadius:3},
                {label:'Comments', data:cData.map(function(d){return pct?(d.comments||0)/totFn(d)*100:d.comments||0;}),backgroundColor:GN,borderRadius:3},
                {label:'Blanks',   data:cData.map(function(d){return pct?(d.blanks||0)/totFn(d)*100:d.blanks||0;}),  backgroundColor:GY,borderRadius:3}
              ]
            }, {
              indexAxis:'y',
              scales:{
                x:{stacked:true,grid:{color:gc},ticks:{color:tc,callback:pct?function(v){return v.toFixed(0)+'%';}:function(v){return fmt(v);}}},
                y:{stacked:true,grid:{display:false},ticks:{color:tc}}
              },
              plugins:{legend:{position:'bottom',labels:{color:tc}}}
            }, 900, compH);
            pgComp.grid.appendChild(mkPanel(m.label, png));
          });
        root.appendChild(pgComp.group);

        // ── File Count vs SLOC — render off-screen (bubble chart, single-col centred) ─
        if (SCAT_D && SCAT_D.length) {
          var pgScat = mkGroup('File Count vs SLOC');
          pgScat.grid.classList.add('single-col'); // CSS class drives centering in print
          var maxP = Math.max.apply(null, SCAT_D.map(function(d){return d.physical||0;})) || 1;
          var scatPng = snap('bubble', {
            datasets: SCAT_D.map(function(d, i) {
              return {
                label: d.lang,
                data: [{ x: d.files, y: d.code, r: Math.max(5, Math.round(Math.sqrt((d.physical||0)/maxP)*20)) }],
                backgroundColor: PALETTE[i % PALETTE.length] + 'b8',
                borderColor: PALETTE[i % PALETTE.length], borderWidth: 1
              };
            })
          }, {
            scales: {
              x: { grid:{color:gc}, ticks:{color:tc}, title:{display:true, text:'Files Analyzed', color:tc} },
              y: { grid:{color:gc}, ticks:{color:tc, callback:function(v){return fmt(v);}}, title:{display:true, text:'Code Lines', color:tc} }
            },
            plugins: { legend:{position:'right', labels:{color:tc, boxWidth:12}} }
          }, 900, 260);
          pgScat.grid.appendChild(mkPanel('Files × Code Lines (bubble size ∝ physical lines)', scatPng));
          root.appendChild(pgScat.group);
        }

        // ── Semantic Metrics — up to 5 metrics, skip empty ones ─────────────────
        if (SEM_D && SEM_D.length) {
          var pgSem = mkGroup('Semantic Metrics');
          var SL={functions:'Functions',classes:'Classes / Types',variables:'Variables',imports:'Imports',tests:'Tests'};
          var SC={functions:OX,classes:'#4472C4',variables:GN,imports:'#805099',tests:'#B23030'};
          Object.keys(SL).forEach(function(mKey) {
            var data = SEM_D.slice().sort(function(a,b){return (b[mKey]||0)-(a[mKey]||0);}).slice(0,15);
            if (!data.some(function(d){return (d[mKey]||0)>0;})) return;
            var semH = 210; // vertical bar — fixed height; width drives layout, not row count
            var png = snap('bar', {
              labels: data.map(function(d){return d.lang;}),
              datasets:[{label:SL[mKey],data:data.map(function(d){return d[mKey]||0;}),backgroundColor:SC[mKey],borderRadius:4}]
            }, {
              scales:{
                x:{grid:{display:false},ticks:{color:tc}},
                y:{grid:{color:gc},ticks:{color:tc,callback:function(v){return fmt(v);}}}
              },
              plugins:{legend:{display:false}}
            }, 900, semH);
            pgSem.grid.appendChild(mkPanel(SL[mKey], png));
          });
          root.appendChild(pgSem.group);
        }

        // ── Submodule Breakdown — 3 Y-axis variants + donut SVG clone ────────────
        if (SUB_D && SUB_D.length) {
          var pgSub = mkGroup('Submodule Breakdown');
          [{key:'code',label:'Code Lines',col:OX},{key:'comment',label:'Comment Lines',col:GN},{key:'files',label:'File Count',col:'#805099'}]
            .forEach(function(y) {
              var data = SUB_D.slice().sort(function(a,b){return (b[y.key]||0)-(a[y.key]||0);}).slice(0,30);
              if (!data.length) return;
              var subH = Math.max(100, Math.min(420, data.length*16+30));
              var png = snap('bar', {
                labels: data.map(function(d){return d.name;}),
                datasets:[{label:y.label,data:data.map(function(d){return d[y.key]||0;}),backgroundColor:y.col,borderRadius:3}]
              }, {
                indexAxis:'y',
                scales:{
                  x:{grid:{color:gc},ticks:{color:tc,callback:function(v){return fmt(v);}},title:{display:true,text:y.label,color:tc}},
                  y:{grid:{display:false},ticks:{color:tc}}
                },
                plugins:{legend:{display:false}}
              }, 900, subH);
              pgSub.grid.appendChild(mkPanel(y.label, png));
            });
          var donutEl = document.getElementById('submodule-donut');
          if (donutEl && donutEl.innerHTML.trim()) {
            var dp = document.createElement('div'); dp.className = 'pdf-variant-panel';
            var dl = document.createElement('div'); dl.className = 'pdf-variant-label'; dl.textContent = 'Distribution';
            dp.appendChild(dl);
            var dw = document.createElement('div'); dw.style.cssText = 'display:flex;justify-content:center;';
            dw.innerHTML = donutEl.innerHTML; dp.appendChild(dw);
            pgSub.grid.appendChild(dp);
          }
          root.appendChild(pgSub.group);
        }
      })();
    })();
    window.oxSlocChartsReady = true;
    }); // end requestAnimationFrame
    // ── SVG tooltip delegation ───────────────────────────────────────────────
    (function(){
      var tt = document.getElementById('r-tt');
      if (!tt) return;
      function escH(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
      function show(e, html) { tt.innerHTML=html; tt.style.display='block'; move(e); }
      function hide() { tt.style.display='none'; }
      function move(e) {
        var x=e.clientX+16, y=e.clientY-12;
        var r=tt.getBoundingClientRect();
        if (x+r.width>window.innerWidth-8) x=e.clientX-r.width-8;
        if (y+r.height>window.innerHeight-8) y=e.clientY-r.height-8;
        tt.style.left=x+'px'; tt.style.top=y+'px';
      }
      document.addEventListener('mouseover', function(e) {
        var t=e.target;
        while(t&&t.getAttribute){
          var l=t.getAttribute('data-ttl');
          if(l!==null){ show(e,'<strong>'+escH(l)+'</strong><br>'+escH(t.getAttribute('data-ttv')||'')); return; }
          t=t.parentNode;
        }
      });
      document.addEventListener('mouseout', function(e) {
        var t=e.target;
        while(t&&t.getAttribute){
          if(t.getAttribute('data-ttl')!==null){ hide(); return; }
          t=t.parentNode;
        }
      });
      document.addEventListener('mousemove', function(e) {
        if(tt.style.display!=='none') move(e);
      });
    })();
    // Auto-populate title on any td that is visually truncated but has no explicit title
    requestAnimationFrame(function() {
      document.querySelectorAll('td').forEach(function(td) {
        if (!td.title && td.scrollWidth > td.clientWidth) {
          td.title = td.textContent.trim();
        }
      });
    });

  </script>
  <script nonce="{{ nonce }}">
  (function(){
    var S=[{n:'Classic',a:'#b85d33',b:'#7a371b'},{n:'Navy',a:'#283790',b:'#1e1e24'},{n:'Ember',a:'#ce5d3d',b:'#1e1e24'},{n:'Ocean',a:'#1f439b',b:'#1e1e24'},{n:'Royal',a:'#003184',b:'#1e1e24'}];
    function ap(s){document.documentElement.style.setProperty('--nav',s.a);document.documentElement.style.setProperty('--nav-2',s.b);try{localStorage.setItem('sloc-ns',JSON.stringify(s));}catch(e){}document.querySelectorAll('.scheme-swatch').forEach(function(x){x.classList.toggle('active',x.dataset.n===s.n);});}
    try{var sv=JSON.parse(localStorage.getItem('sloc-ns'));if(sv&&sv.a){ap(sv);}else{ap(S[0]);}}catch(e){ap(S[0]);}
    function init(){
      var btn=document.getElementById('settings-btn');if(!btn)return;
      var m=document.createElement('div');m.id='settings-modal';m.className='settings-modal';
      m.innerHTML='<div class="settings-modal-header"><span>Appearance</span><button type="button" class="settings-close" id="settings-close" aria-label="Close"><svg viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button></div><div class="settings-modal-body"><div class="settings-modal-label">Navigation color scheme</div><div class="scheme-grid" id="scheme-grid"></div><div style="margin-top:12px;border-top:1px solid var(--line);padding-top:12px;"><div class="settings-modal-label" style="margin-bottom:8px;">Timestamp timezone</div><select class="tz-select" id="tz-select"><option value="America/Los_Angeles">Pacific (PT)</option><option value="America/Denver">Mountain (MT)</option><option value="America/Chicago">Central (CT)</option><option value="America/New_York">Eastern (ET)</option><option value="America/Anchorage">Alaska (AT)</option><option value="Pacific/Honolulu">Hawaii (HT)</option></select></div></div>';
      document.body.appendChild(m);
      var g=document.getElementById('scheme-grid');
      if(g)S.forEach(function(s){var el=document.createElement('button');el.type='button';el.className='scheme-swatch';el.dataset.n=s.n;el.title=s.n;var p=document.createElement('div');p.className='scheme-preview';p.style.background='linear-gradient(135deg,'+s.a+','+s.b+')';var l=document.createElement('span');l.className='scheme-label';l.textContent=s.n;el.appendChild(p);el.appendChild(l);try{var c=JSON.parse(localStorage.getItem('sloc-ns'));if(c&&c.n===s.n)el.classList.add('active');}catch(e){}el.addEventListener('click',function(){ap(s);});g.appendChild(el);});
      var cl=document.getElementById('settings-close');
      window.tzAbbr=function(z){return{'America/Los_Angeles':'PT','America/Denver':'MT','America/Chicago':'CT','America/New_York':'ET','America/Anchorage':'AT','Pacific/Honolulu':'HT'}[z]||'PT';};window.fmtTz=function(ms,tz){var d=new Date(ms);if(isNaN(d.getTime()))return'';try{var pts=new Intl.DateTimeFormat('en-US',{timeZone:tz,year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',hour12:false}).formatToParts(d);var v={};pts.forEach(function(p){v[p.type]=p.value;});return v.year+'-'+v.month+'-'+v.day+' '+v.hour+':'+v.minute+' '+window.tzAbbr(tz);}catch(e){return'';}};window.applyTz=function(tz){try{localStorage.setItem('sloc-tz',tz);}catch(e){}document.querySelectorAll('[data-utc-ms]').forEach(function(el){var ms=parseInt(el.getAttribute('data-utc-ms'),10);if(!isNaN(ms))el.textContent=window.fmtTz(ms,tz);});};var tzSel=document.getElementById('tz-select');var storedTz;try{storedTz=localStorage.getItem('sloc-tz')||'America/Los_Angeles';}catch(e){storedTz='America/Los_Angeles';}if(tzSel){tzSel.value=storedTz;tzSel.addEventListener('change',function(){window.applyTz(this.value);});}window.applyTz(storedTz);
      btn.addEventListener('click',function(e){e.stopPropagation();var r=btn.getBoundingClientRect();m.style.top=(r.bottom+6)+'px';m.style.right=(window.innerWidth-r.right)+'px';m.classList.toggle('open');});
      if(cl)cl.addEventListener('click',function(){m.classList.remove('open');});
      document.addEventListener('click',function(e){if(!m.contains(e.target)&&e.target!==btn)m.classList.remove('open');});
    }
    if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init);else init();
  }());
  </script>
  <script>
  (function(){
    var params=new URLSearchParams(location.search);
    if(params.get('autoprint')!=='1')return;
    var overlay=document.createElement('div');
    overlay.id='autoprint-overlay';
    overlay.style.cssText='position:fixed;inset:0;z-index:99999;background:var(--bg,#fff);display:flex;flex-direction:column;align-items:center;justify-content:center;gap:16px;';
    overlay.innerHTML='<div style="font-size:20px;font-weight:800;color:var(--text,#1a1a1a);">Preparing PDF…</div>'
      +'<div style="font-size:13px;color:var(--muted,#666);">Use your browser’s print dialog → <strong>Save as PDF</strong>.</div>'
      +'<div style="width:200px;height:4px;border-radius:2px;background:rgba(0,0,0,0.1);overflow:hidden;">'
      +'<div id="autoprint-bar" style="height:100%;width:0%;background:#e07b3a;transition:width 1.5s ease;border-radius:2px;"></div></div>';
    document.body.appendChild(overlay);
    setTimeout(function(){var b=document.getElementById('autoprint-bar');if(b)b.style.width='80%';},50);
    var deadline=Date.now()+12000;
    function tryPrint(){
      if(window.oxSlocChartsReady||Date.now()>deadline){
        var b=document.getElementById('autoprint-bar');
        if(b)b.style.width='100%';
        setTimeout(function(){
          overlay.style.display='none';
          window.print();
        },350);
      } else {
        setTimeout(tryPrint,150);
      }
    }
    if(document.readyState==='loading'){
      document.addEventListener('DOMContentLoaded',function(){setTimeout(tryPrint,250);});
    } else {
      setTimeout(tryPrint,250);
    }
    window.addEventListener('afterprint',function(){overlay.remove();});
  }());
  </script>
  <footer class="report-footer">oxide-sloc v{{ tool_version }}</footer>
  {% if let Some(banner) = report_header_footer %}
  <div class="report-id-footer-banner" aria-label="Report identification">{{ banner|e }}</div>
  {% endif %}
</body>
</html>"##,
    ext = "html"
)]
// Template structs need many bool fields to pass Askama rendering flags.
#[allow(clippy::struct_excessive_bools)]
struct ReportTemplate<'a> {
    nonce: String,
    title: String,
    browser_title: String,
    scan_performed_by: String,
    scan_time_pst: String,
    tool_version: String,
    is_sub_report: bool,
    run: &'a AnalysisRun,
    language_rows: Vec<LanguageRow>,
    file_rows: Vec<FileRow>,
    skipped_rows: Vec<FileRow>,
    config_json: String,
    lang_chart_json: String,
    submodule_chart_json: String,
    scatter_chart_json: String,
    semantic_chart_json: String,
    file_size_histogram_json: String,
    has_submodule_data: bool,
    has_semantic_data: bool,
    has_coverage_data: bool,
    has_fn_coverage: bool,
    has_branch_coverage: bool,
    test_files_count: u64,
    test_assertion_count: u64,
    test_suite_count: u64,
    test_density: String,
    most_tested_lang: String,
    langs_with_tests: usize,
    cov_line_pct: String,
    cov_fn_pct: String,
    cov_branch_pct: String,
    cov_line_class: String,
    cov_fn_class: String,
    cov_branch_class: String,
    has_run_warnings: bool,
    warning_count: usize,
    warning_summary_rows: Vec<WarningSummaryRow>,
    warning_opportunity_rows: Vec<WarningOpportunityRow>,
    warning_console_full: String,
    logo_text_uri: String,
    small_logo_uri: String,
    /// Data-URI for a custom logo, or None to show the default `OxideSLOC` logo.
    custom_logo_uri: Option<String>,
    /// Optional company/team name shown instead of "`OxideSLOC`" in the nav header.
    company_name: Option<String>,
    /// CSS hex accent colour override (e.g. `#3b82f6`), or None for the default.
    accent_hex: Option<String>,
    /// Text for the header/footer identification banner on every report page.
    report_header_footer: Option<String>,
    chart_js: &'static str,
    run_id_short: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// CSV export
// ─────────────────────────────────────────────────────────────────────────────

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Write a two-section CSV: language summary followed by per-file detail.
///
/// # Errors
///
/// Returns an error if the file cannot be written.
pub fn write_csv(run: &AnalysisRun, path: &Path) -> Result<()> {
    let mut out = String::new();

    // ── Section 1: Summary ──────────────────────────────────────────────────
    out.push_str("# Summary\r\n");
    out.push_str("Metric,Value\r\n");
    let _ = write!(out, "Run ID,{}\r\n", csv_escape(&run.tool.run_id));
    let _ = write!(
        out,
        "Timestamp,{}\r\n",
        csv_escape(
            &run.tool
                .timestamp_utc
                .format("%Y-%m-%d %H:%M:%S UTC")
                .to_string()
        )
    );
    let _ = write!(
        out,
        "Report Title,{}\r\n",
        csv_escape(&run.effective_configuration.reporting.report_title)
    );
    let _ = write!(
        out,
        "Files Analyzed,{}\r\n",
        run.summary_totals.files_analyzed
    );
    let _ = write!(
        out,
        "Files Skipped,{}\r\n",
        run.summary_totals.files_skipped
    );
    let _ = write!(
        out,
        "Physical Lines,{}\r\n",
        run.summary_totals.total_physical_lines
    );
    let _ = write!(out, "Code Lines,{}\r\n", run.summary_totals.code_lines);
    let _ = write!(
        out,
        "Comment Lines,{}\r\n",
        run.summary_totals.comment_lines
    );
    let _ = write!(out, "Blank Lines,{}\r\n", run.summary_totals.blank_lines);
    let _ = write!(
        out,
        "Mixed Lines (separate),{}\r\n",
        run.summary_totals.mixed_lines_separate
    );

    // ── Section 2: Language breakdown ───────────────────────────────────────
    out.push_str("\r\n# By Language\r\n");
    out.push_str(
        "Language,Files,Physical Lines,Code Lines,Comment Lines,Blank Lines,Mixed Lines\r\n",
    );
    for lang in &run.totals_by_language {
        let _ = write!(
            out,
            "{},{},{},{},{},{},{}\r\n",
            csv_escape(lang.language.display_name()),
            lang.files,
            lang.total_physical_lines,
            lang.code_lines,
            lang.comment_lines,
            lang.blank_lines,
            lang.mixed_lines_separate,
        );
    }

    // ── Section 3: Per-file detail (if present) ─────────────────────────────
    if !run.per_file_records.is_empty() {
        out.push_str("\r\n# Per File\r\n");
        out.push_str(
            "Path,Language,Size (bytes),Code Lines,Comment Lines,Blank Lines,Physical Lines,Generated,Minified,Vendor\r\n",
        );
        for rec in &run.per_file_records {
            let _ = write!(
                out,
                "{},{},{},{},{},{},{},{},{},{}\r\n",
                csv_escape(&rec.relative_path),
                csv_escape(
                    &rec.language
                        .map(|l| l.display_name().to_string())
                        .unwrap_or_default()
                ),
                rec.size_bytes,
                rec.effective_counts.code_lines,
                rec.effective_counts.comment_lines,
                rec.effective_counts.blank_lines,
                rec.raw_line_categories.total_physical_lines,
                rec.generated,
                rec.minified,
                rec.vendor,
            );
        }
    }

    fs::write(path, out).with_context(|| format!("failed to write CSV to {}", path.display()))
}

/// Write a diff/delta as CSV.
///
/// # Errors
///
/// Returns an error if the file cannot be written.
pub fn write_diff_csv(cmp: &sloc_core::ScanComparison, path: &Path) -> Result<()> {
    let s = &cmp.summary;
    let mut out = String::new();

    out.push_str("# Diff Summary\r\n");
    out.push_str("Metric,Value\r\n");
    let _ = write!(out, "Baseline Run,{}\r\n", csv_escape(&s.baseline_run_id));
    let _ = write!(out, "Current Run,{}\r\n", csv_escape(&s.current_run_id));
    let _ = write!(out, "Files Added,{}\r\n", cmp.files_added);
    let _ = write!(out, "Files Removed,{}\r\n", cmp.files_removed);
    let _ = write!(out, "Files Modified,{}\r\n", cmp.files_modified);
    let _ = write!(out, "Files Unchanged,{}\r\n", cmp.files_unchanged);
    let _ = write!(out, "Code Δ,{}\r\n", s.code_lines_delta);
    let _ = write!(out, "Comment Δ,{}\r\n", s.comment_lines_delta);
    let _ = write!(out, "Blank Δ,{}\r\n", s.blank_lines_delta);
    let _ = write!(out, "Total Δ,{}\r\n", s.total_lines_delta);

    out.push_str("\r\n# File Deltas\r\n");
    out.push_str("Status,Path,Language,Baseline Code,Current Code,Code Δ,Baseline Comment,Current Comment,Comment Δ,Baseline Blank,Current Blank,Blank Δ,Total Δ\r\n");
    for f in &cmp.file_deltas {
        let status = match f.status {
            sloc_core::FileChangeStatus::Added => "Added",
            sloc_core::FileChangeStatus::Removed => "Removed",
            sloc_core::FileChangeStatus::Modified => "Modified",
            sloc_core::FileChangeStatus::Unchanged => "Unchanged",
        };
        let _ = write!(
            out,
            "{},{},{},{},{},{},{},{},{},{},{},{},{}\r\n",
            status,
            csv_escape(&f.relative_path),
            csv_escape(f.language.as_deref().unwrap_or("")),
            f.baseline_code,
            f.current_code,
            f.code_delta,
            f.baseline_comment,
            f.current_comment,
            f.comment_delta,
            f.baseline_blank,
            f.current_blank,
            f.blank_delta,
            f.total_delta,
        );
    }

    fs::write(path, out).with_context(|| format!("failed to write diff CSV to {}", path.display()))
}

// ─────────────────────────────────────────────────────────────────────────────
// XLSX export — self-contained, no external crates required.
//
// An .xlsx file is a ZIP archive containing a set of XML files.  We write the
// ZIP with the STORE (uncompressed) method so we only need a CRC-32 routine
// and straightforward byte-level framing — both implemented inline below.
// ─────────────────────────────────────────────────────────────────────────────

fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xffff_ffff;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 == 0 {
                crc >> 1
            } else {
                (crc >> 1) ^ 0xedb8_8320
            };
        }
    }
    !crc
}

struct ZipEntry {
    name: Vec<u8>,
    data: Vec<u8>,
    crc: u32,
    offset: u32,
}

#[allow(clippy::cast_possible_truncation)] // deliberate ZIP format construction: sizes are bounded by caller
fn zip_add(entries: &mut Vec<ZipEntry>, buf: &mut Vec<u8>, name: &str, data: Vec<u8>) {
    let crc = crc32(&data);
    let offset = buf.len() as u32;
    let name_bytes = name.as_bytes().to_vec();
    let size = data.len() as u32;

    // Local file header (signature 0x04034b50)
    buf.extend_from_slice(&0x0403_4b50_u32.to_le_bytes());
    buf.extend_from_slice(&20u16.to_le_bytes()); // version needed
    buf.extend_from_slice(&0u16.to_le_bytes()); // flags
    buf.extend_from_slice(&0u16.to_le_bytes()); // compression: STORE
    buf.extend_from_slice(&0u16.to_le_bytes()); // mod time
    buf.extend_from_slice(&0u16.to_le_bytes()); // mod date
    buf.extend_from_slice(&crc.to_le_bytes());
    buf.extend_from_slice(&size.to_le_bytes()); // compressed size
    buf.extend_from_slice(&size.to_le_bytes()); // uncompressed size
    buf.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes()); // extra field length
    buf.extend_from_slice(&name_bytes);
    buf.extend_from_slice(&data);

    entries.push(ZipEntry {
        name: name_bytes,
        data,
        crc,
        offset,
    });
}

#[allow(clippy::cast_possible_truncation)] // deliberate ZIP format construction: sizes are bounded by ZIP spec limits
fn zip_finish(mut buf: Vec<u8>, entries: &[ZipEntry]) -> Vec<u8> {
    let central_start = buf.len() as u32;

    for e in entries {
        let size = e.data.len() as u32;
        buf.extend_from_slice(&0x0201_4b50_u32.to_le_bytes()); // central dir sig
        buf.extend_from_slice(&20u16.to_le_bytes()); // version made by
        buf.extend_from_slice(&20u16.to_le_bytes()); // version needed
        buf.extend_from_slice(&0u16.to_le_bytes()); // flags
        buf.extend_from_slice(&0u16.to_le_bytes()); // compression: STORE
        buf.extend_from_slice(&0u16.to_le_bytes()); // mod time
        buf.extend_from_slice(&0u16.to_le_bytes()); // mod date
        buf.extend_from_slice(&e.crc.to_le_bytes());
        buf.extend_from_slice(&size.to_le_bytes());
        buf.extend_from_slice(&size.to_le_bytes());
        buf.extend_from_slice(&(e.name.len() as u16).to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // extra
        buf.extend_from_slice(&0u16.to_le_bytes()); // comment
        buf.extend_from_slice(&0u16.to_le_bytes()); // disk start
        buf.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        buf.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        buf.extend_from_slice(&e.offset.to_le_bytes());
        buf.extend_from_slice(&e.name);
    }

    let central_size = buf.len() as u32 - central_start;
    let n = entries.len() as u16;

    // End of central directory record
    buf.extend_from_slice(&0x0605_4b50_u32.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes()); // disk number
    buf.extend_from_slice(&0u16.to_le_bytes()); // disk with central dir
    buf.extend_from_slice(&n.to_le_bytes()); // entries on this disk
    buf.extend_from_slice(&n.to_le_bytes()); // total entries
    buf.extend_from_slice(&central_size.to_le_bytes());
    buf.extend_from_slice(&central_start.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes()); // comment length

    buf
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Build a worksheet XML with the given header row and data rows.
// ── XLSX style-index constants ──────────────────────────────────────────────
// Indices into the <cellXfs> table in styles.xml.
// 0 = default (unused placeholder)
// 1 = HEADER   bold white text, navy fill (#283790), all-side thin border, centered
// 2 = BODY     normal text, white fill, thin border
// 3 = BODY_ALT normal text, cream fill (#F5EFE8), thin border  (alternating rows)
// 4 = NUM      #,##0, right-aligned, white fill, thin border
// 5 = NUM_ALT  #,##0, right-aligned, cream fill, thin border   (alternating rows)
// 6 = KV_KEY   bold navy text (#283790), warm-surface fill (#FBF7F2), thin border
// 7 = KV_VAL   normal text, white fill, thin border  (key-value sheets: Summary)
const XLS_HEADER: u32 = 1;
const XLS_BODY: u32 = 2;
const XLS_BODY_ALT: u32 = 3;
const XLS_NUM: u32 = 4;
const XLS_NUM_ALT: u32 = 5;
const XLS_KV_KEY: u32 = 6;
const XLS_KV_VAL: u32 = 7;

struct XlSheet<'a> {
    name: &'a str,
    tab_color: &'a str, // AARRGGBB hex without '#', e.g. "FF283790"
    headers: &'a [&'a str],
    rows: Vec<Vec<String>>,
    col_widths: Vec<f64>, // per-column character widths; last entry used for overflow cols
    is_kv: bool,          // key-value layout (Summary): col A = key style, no autofilter
}

#[allow(clippy::cast_possible_truncation)] // n % 26 fits in u8 by construction
fn xl_col_name(idx: usize) -> String {
    let mut n = idx + 1;
    let mut s = String::new();
    while n > 0 {
        n -= 1;
        s.insert(0, char::from(b'A' + (n % 26) as u8));
        n /= 26;
    }
    s
}

const fn xl_styles() -> &'static str {
    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<styleSheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\">\
<numFmts count=\"1\">\
<numFmt numFmtId=\"164\" formatCode=\"#,##0\"/>\
</numFmts>\
<fonts count=\"3\">\
<font><sz val=\"11\"/><name val=\"Calibri\"/></font>\
<font><b/><sz val=\"11\"/><color rgb=\"FFFFFFFF\"/><name val=\"Calibri\"/></font>\
<font><b/><sz val=\"11\"/><color rgb=\"FF283790\"/><name val=\"Calibri\"/></font>\
</fonts>\
<fills count=\"5\">\
<fill><patternFill patternType=\"none\"/></fill>\
<fill><patternFill patternType=\"gray125\"/></fill>\
<fill><patternFill patternType=\"solid\"><fgColor rgb=\"FF283790\"/><bgColor indexed=\"64\"/></patternFill></fill>\
<fill><patternFill patternType=\"solid\"><fgColor rgb=\"FFF5EFE8\"/><bgColor indexed=\"64\"/></patternFill></fill>\
<fill><patternFill patternType=\"solid\"><fgColor rgb=\"FFFBF7F2\"/><bgColor indexed=\"64\"/></patternFill></fill>\
</fills>\
<borders count=\"2\">\
<border><left/><right/><top/><bottom/><diagonal/></border>\
<border>\
<left style=\"thin\"><color rgb=\"FFD0B8A0\"/></left>\
<right style=\"thin\"><color rgb=\"FFD0B8A0\"/></right>\
<top style=\"thin\"><color rgb=\"FFD0B8A0\"/></top>\
<bottom style=\"thin\"><color rgb=\"FFD0B8A0\"/></bottom>\
<diagonal/>\
</border>\
</borders>\
<cellStyleXfs count=\"1\"><xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"0\"/></cellStyleXfs>\
<cellXfs count=\"8\">\
<xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"0\" xfId=\"0\"/>\
<xf numFmtId=\"0\" fontId=\"1\" fillId=\"2\" borderId=\"1\" xfId=\"0\" \
applyFont=\"1\" applyFill=\"1\" applyBorder=\"1\" applyAlignment=\"1\">\
<alignment horizontal=\"center\" vertical=\"center\"/></xf>\
<xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"1\" xfId=\"0\" applyBorder=\"1\"/>\
<xf numFmtId=\"0\" fontId=\"0\" fillId=\"3\" borderId=\"1\" xfId=\"0\" applyFill=\"1\" applyBorder=\"1\"/>\
<xf numFmtId=\"164\" fontId=\"0\" fillId=\"0\" borderId=\"1\" xfId=\"0\" \
applyNumberFormat=\"1\" applyBorder=\"1\" applyAlignment=\"1\">\
<alignment horizontal=\"right\"/></xf>\
<xf numFmtId=\"164\" fontId=\"0\" fillId=\"3\" borderId=\"1\" xfId=\"0\" \
applyNumberFormat=\"1\" applyFill=\"1\" applyBorder=\"1\" applyAlignment=\"1\">\
<alignment horizontal=\"right\"/></xf>\
<xf numFmtId=\"0\" fontId=\"2\" fillId=\"4\" borderId=\"1\" xfId=\"0\" \
applyFont=\"1\" applyFill=\"1\" applyBorder=\"1\"/>\
<xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"1\" xfId=\"0\" applyBorder=\"1\"/>\
</cellXfs>\
</styleSheet>"
}

fn xl_sheet_xml(sheet: &XlSheet<'_>) -> Vec<u8> {
    let ncols = sheet.headers.len();
    let ndata = sheet.rows.len();
    let last_col = xl_col_name(ncols.saturating_sub(1));
    let last_row = ndata + 1;
    let range = format!("A1:{last_col}{last_row}");

    let mut xml = String::with_capacity(4096 + ndata * 256);
    let _ = write!(
        xml,
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
         <worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\">\n\
         <sheetPr><tabColor rgb=\"{tc}\"/></sheetPr>\n\
         <dimension ref=\"{rng}\"/>\n\
         <sheetViews><sheetView workbookViewId=\"0\">\
         <pane ySplit=\"1\" topLeftCell=\"A2\" activePane=\"bottomLeft\" state=\"frozen\"/>\
         <selection pane=\"bottomLeft\" activeCell=\"A2\" sqref=\"A2\"/>\
         </sheetView></sheetViews>\n\
         <sheetFormatPr defaultRowHeight=\"15\"/>\n",
        tc = sheet.tab_color,
        rng = range,
    );

    xl_write_col_widths(&mut xml, &sheet.col_widths, ncols);
    xml.push_str("<sheetData>\n");
    xl_write_header_row(&mut xml, sheet.headers);
    xl_write_data_rows(&mut xml, &sheet.rows, sheet.is_kv);
    xml.push_str("</sheetData>\n");
    if !sheet.is_kv && ncols > 0 {
        let _ = writeln!(xml, "<autoFilter ref=\"{range}\"/>");
    }
    xml.push_str("</worksheet>");
    xml.into_bytes()
}

fn xl_write_col_widths(xml: &mut String, col_widths: &[f64], ncols: usize) {
    if col_widths.is_empty() {
        return;
    }
    let default_w = *col_widths.last().unwrap_or(&10.0);
    xml.push_str("<cols>\n");
    for ci in 0..ncols {
        let w = col_widths.get(ci).copied().unwrap_or(default_w);
        let _ = writeln!(
            xml,
            "  <col min=\"{n}\" max=\"{n}\" width=\"{w:.1}\" customWidth=\"1\"/>",
            n = ci + 1
        );
    }
    xml.push_str("</cols>\n");
}

fn xl_write_header_row(xml: &mut String, headers: &[&str]) {
    let _ = write!(xml, "<row r=\"1\" ht=\"18\" customHeight=\"1\">");
    for (ci, &h) in headers.iter().enumerate() {
        let _ = write!(
            xml,
            "<c r=\"{}1\" t=\"inlineStr\" s=\"{}\"><is><t>{}</t></is></c>",
            xl_col_name(ci),
            XLS_HEADER,
            xml_escape(h),
        );
    }
    xml.push_str("</row>\n");
}

const fn xl_cell_style(is_kv: bool, ci: usize, is_num: bool, is_alt: bool) -> u32 {
    if is_kv {
        if ci == 0 {
            XLS_KV_KEY
        } else if is_num {
            XLS_NUM
        } else {
            XLS_KV_VAL
        }
    } else if is_num {
        if is_alt {
            XLS_NUM_ALT
        } else {
            XLS_NUM
        }
    } else if is_alt {
        XLS_BODY_ALT
    } else {
        XLS_BODY
    }
}

fn xl_write_data_rows(xml: &mut String, rows: &[Vec<String>], is_kv: bool) {
    for (ri, row) in rows.iter().enumerate() {
        let row_num = ri + 2;
        let is_alt = ri % 2 == 1;
        let _ = write!(xml, "<row r=\"{row_num}\">");
        for (ci, cell) in row.iter().enumerate() {
            let cell_ref = format!("{}{}", xl_col_name(ci), row_num);
            let is_num = !cell.is_empty() && cell.parse::<f64>().is_ok();
            let s = xl_cell_style(is_kv, ci, is_num, is_alt);
            if is_num {
                let _ = write!(
                    xml,
                    "<c r=\"{cell_ref}\" s=\"{s}\"><v>{}</v></c>",
                    xml_escape(cell)
                );
            } else {
                let _ = write!(
                    xml,
                    "<c r=\"{cell_ref}\" t=\"inlineStr\" s=\"{s}\"><is><t>{}</t></is></c>",
                    xml_escape(cell),
                );
            }
        }
        xml.push_str("</row>\n");
    }
}

fn build_xlsx(sheets: &[XlSheet<'_>]) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    let mut entries: Vec<ZipEntry> = Vec::new();

    // ── [Content_Types].xml ─────────────────────────────────────────────────
    let mut ct = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n");
    ct.push_str("<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\n");
    ct.push_str("  <Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>\n");
    ct.push_str("  <Default Extension=\"xml\" ContentType=\"application/xml\"/>\n");
    ct.push_str("  <Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml\"/>\n");
    ct.push_str("  <Override PartName=\"/xl/styles.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml\"/>\n");
    for (i, _) in sheets.iter().enumerate() {
        let _ = writeln!(
            ct,
            "  <Override PartName=\"/xl/worksheets/sheet{}.xml\" \
             ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/>",
            i + 1
        );
    }
    ct.push_str("</Types>");
    zip_add(
        &mut entries,
        &mut buf,
        "[Content_Types].xml",
        ct.into_bytes(),
    );

    // ── _rels/.rels ─────────────────────────────────────────────────────────
    let rels = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n\
<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\n\
  <Relationship Id=\"rId1\" \
  Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" \
  Target=\"xl/workbook.xml\"/>\n\
</Relationships>";
    zip_add(
        &mut entries,
        &mut buf,
        "_rels/.rels",
        rels.as_bytes().to_vec(),
    );

    // ── xl/workbook.xml ──────────────────────────────────────────────────────
    let mut wb = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n");
    wb.push_str(
        "<workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" \
         xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\">\n",
    );
    wb.push_str("  <sheets>\n");
    for (i, sheet) in sheets.iter().enumerate() {
        let _ = writeln!(
            wb,
            "    <sheet name=\"{}\" sheetId=\"{}\" r:id=\"rId{}\"/>",
            xml_escape(sheet.name),
            i + 1,
            i + 1
        );
    }
    wb.push_str("  </sheets>\n</workbook>");
    zip_add(&mut entries, &mut buf, "xl/workbook.xml", wb.into_bytes());

    // ── xl/_rels/workbook.xml.rels ───────────────────────────────────────────
    let mut wbr = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n");
    wbr.push_str(
        "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\n",
    );
    for (i, _) in sheets.iter().enumerate() {
        let _ = writeln!(
            wbr,
            "  <Relationship Id=\"rId{}\" \
             Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" \
             Target=\"worksheets/sheet{}.xml\"/>",
            i + 1,
            i + 1
        );
    }
    let _ = writeln!(
        wbr,
        "  <Relationship Id=\"rId{}\" \
         Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles\" \
         Target=\"styles.xml\"/>",
        sheets.len() + 1
    );
    wbr.push_str("</Relationships>");
    zip_add(
        &mut entries,
        &mut buf,
        "xl/_rels/workbook.xml.rels",
        wbr.into_bytes(),
    );

    // ── xl/styles.xml ───────────────────────────────────────────────────────
    zip_add(
        &mut entries,
        &mut buf,
        "xl/styles.xml",
        xl_styles().as_bytes().to_vec(),
    );

    // ── worksheets ───────────────────────────────────────────────────────────
    for (i, sheet) in sheets.iter().enumerate() {
        let sheet_xml = xl_sheet_xml(sheet);
        let name = format!("xl/worksheets/sheet{}.xml", i + 1);
        zip_add(&mut entries, &mut buf, &name, sheet_xml);
    }

    zip_finish(buf, &entries)
}

/// Write an analysis run as a multi-sheet Excel workbook.
///
/// # Errors
///
/// Returns an error if the file cannot be written.
#[allow(clippy::too_many_lines)]
pub fn write_xlsx(run: &AnalysisRun, path: &Path) -> Result<()> {
    // Sheet 1 — Summary
    let summary_rows: Vec<Vec<String>> = vec![
        vec!["Run ID".into(), run.tool.run_id.clone()],
        vec![
            "Timestamp".into(),
            run.tool
                .timestamp_utc
                .format("%Y-%m-%d %H:%M:%S UTC")
                .to_string(),
        ],
        vec![
            "Report Title".into(),
            run.effective_configuration.reporting.report_title.clone(),
        ],
        vec![
            "Files Analyzed".into(),
            run.summary_totals.files_analyzed.to_string(),
        ],
        vec![
            "Files Skipped".into(),
            run.summary_totals.files_skipped.to_string(),
        ],
        vec![
            "Physical Lines".into(),
            run.summary_totals.total_physical_lines.to_string(),
        ],
        vec![
            "Code Lines".into(),
            run.summary_totals.code_lines.to_string(),
        ],
        vec![
            "Comment Lines".into(),
            run.summary_totals.comment_lines.to_string(),
        ],
        vec![
            "Blank Lines".into(),
            run.summary_totals.blank_lines.to_string(),
        ],
        vec![
            "Mixed Lines (separate)".into(),
            run.summary_totals.mixed_lines_separate.to_string(),
        ],
    ];

    // Sheet 2 — By Language
    let lang_rows: Vec<Vec<String>> = run
        .totals_by_language
        .iter()
        .map(|l| {
            vec![
                l.language.display_name().to_string(),
                l.files.to_string(),
                l.total_physical_lines.to_string(),
                l.code_lines.to_string(),
                l.comment_lines.to_string(),
                l.blank_lines.to_string(),
                l.mixed_lines_separate.to_string(),
            ]
        })
        .collect();

    // Sheet 3 — Per File
    let file_rows: Vec<Vec<String>> = run
        .per_file_records
        .iter()
        .map(|r| {
            vec![
                r.relative_path.clone(),
                r.language
                    .map(|l| l.display_name().to_string())
                    .unwrap_or_default(),
                r.size_bytes.to_string(),
                r.effective_counts.code_lines.to_string(),
                r.effective_counts.comment_lines.to_string(),
                r.effective_counts.blank_lines.to_string(),
                r.raw_line_categories.total_physical_lines.to_string(),
                r.generated.to_string(),
                r.minified.to_string(),
                r.vendor.to_string(),
            ]
        })
        .collect();

    // Sheet 4 — Skipped Files
    let skipped_rows: Vec<Vec<String>> = run
        .skipped_file_records
        .iter()
        .map(|r| {
            vec![
                r.relative_path.clone(),
                format!("{:?}", r.status),
                r.size_bytes.to_string(),
            ]
        })
        .collect();

    let summary_hdrs: &[&str] = &["Metric", "Value"];
    let lang_hdrs: &[&str] = &[
        "Language",
        "Files",
        "Physical Lines",
        "Code Lines",
        "Comments",
        "Blank",
        "Mixed",
    ];
    let file_hdrs: &[&str] = &[
        "Path",
        "Language",
        "Size (bytes)",
        "Code Lines",
        "Comments",
        "Blank Lines",
        "Physical Lines",
        "Generated",
        "Minified",
        "Vendor",
    ];
    let skipped_hdrs: &[&str] = &["Path", "Status", "Size (bytes)"];

    let sheets = vec![
        XlSheet {
            name: "Summary",
            tab_color: "FF283790",
            headers: summary_hdrs,
            rows: summary_rows,
            col_widths: vec![26.0, 44.0],
            is_kv: true,
        },
        XlSheet {
            name: "By Language",
            tab_color: "FFB85D33",
            headers: lang_hdrs,
            rows: lang_rows,
            col_widths: vec![20.0, 9.0, 15.0, 13.0, 13.0, 11.0, 11.0],
            is_kv: false,
        },
        XlSheet {
            name: "Per File",
            tab_color: "FF2A6846",
            headers: file_hdrs,
            rows: file_rows,
            col_widths: vec![48.0, 14.0, 13.0, 13.0, 11.0, 11.0, 15.0, 11.0, 11.0, 9.0],
            is_kv: false,
        },
        XlSheet {
            name: "Skipped",
            tab_color: "FF7B675B",
            headers: skipped_hdrs,
            rows: skipped_rows,
            col_widths: vec![52.0, 24.0, 13.0],
            is_kv: false,
        },
    ];

    let bytes = build_xlsx(&sheets);
    fs::write(path, bytes).with_context(|| format!("failed to write XLSX to {}", path.display()))
}

/// Write a diff comparison as an Excel workbook.
///
/// # Errors
///
/// Returns an error if the file cannot be written.
pub fn write_diff_xlsx(cmp: &sloc_core::ScanComparison, path: &Path) -> Result<()> {
    let s = &cmp.summary;

    let summary_rows: Vec<Vec<String>> = vec![
        vec!["Baseline Run".into(), s.baseline_run_id.clone()],
        vec!["Current Run".into(), s.current_run_id.clone()],
        vec!["Files Added".into(), cmp.files_added.to_string()],
        vec!["Files Removed".into(), cmp.files_removed.to_string()],
        vec!["Files Modified".into(), cmp.files_modified.to_string()],
        vec!["Files Unchanged".into(), cmp.files_unchanged.to_string()],
        vec!["Code Δ".into(), s.code_lines_delta.to_string()],
        vec!["Comment Δ".into(), s.comment_lines_delta.to_string()],
        vec!["Blank Δ".into(), s.blank_lines_delta.to_string()],
        vec!["Total Δ".into(), s.total_lines_delta.to_string()],
    ];

    let delta_rows: Vec<Vec<String>> = cmp
        .file_deltas
        .iter()
        .map(|f| {
            let status = match f.status {
                sloc_core::FileChangeStatus::Added => "Added",
                sloc_core::FileChangeStatus::Removed => "Removed",
                sloc_core::FileChangeStatus::Modified => "Modified",
                sloc_core::FileChangeStatus::Unchanged => "Unchanged",
            };
            vec![
                status.to_string(),
                f.relative_path.clone(),
                f.language.clone().unwrap_or_default(),
                f.baseline_code.to_string(),
                f.current_code.to_string(),
                f.code_delta.to_string(),
                f.baseline_comment.to_string(),
                f.current_comment.to_string(),
                f.comment_delta.to_string(),
                f.total_delta.to_string(),
            ]
        })
        .collect();

    let summary_hdrs: &[&str] = &["Metric", "Value"];
    let delta_hdrs: &[&str] = &[
        "Status",
        "Path",
        "Language",
        "Baseline Code",
        "Current Code",
        "Code Δ",
        "Baseline Comment",
        "Current Comment",
        "Comment Δ",
        "Total Δ",
    ];

    let sheets = vec![
        XlSheet {
            name: "Diff Summary",
            tab_color: "FF283790",
            headers: summary_hdrs,
            rows: summary_rows,
            col_widths: vec![26.0, 44.0],
            is_kv: true,
        },
        XlSheet {
            name: "File Deltas",
            tab_color: "FFB85D33",
            headers: delta_hdrs,
            rows: delta_rows,
            col_widths: vec![12.0, 48.0, 16.0, 14.0, 14.0, 11.0, 14.0, 14.0, 11.0, 11.0],
            is_kv: false,
        },
    ];

    let bytes = build_xlsx(&sheets);
    fs::write(path, bytes)
        .with_context(|| format!("failed to write diff XLSX to {}", path.display()))
}

// ── Confluence rendering ────────────────────────────────────────────────────

fn html_esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Generates Confluence storage-format XHTML for a scan result page.
/// Includes an info panel, summary stats, per-language table, and an optional
/// link back to the full oxide-sloc HTML report.
#[must_use]
pub fn render_confluence_storage(run: &AnalysisRun, report_url: Option<&str>) -> String {
    let mut out = String::with_capacity(8192);

    let project = run.effective_configuration.reporting.report_title.as_str();
    let branch = run.git_branch.as_deref().unwrap_or("—");
    let commit = run.git_commit_short.as_deref().unwrap_or("—");
    let scanned = run
        .tool
        .timestamp_utc
        .format("%Y-%m-%d %H:%M UTC")
        .to_string();

    // Info panel macro
    out.push_str(
        "<ac:structured-macro ac:name=\"info\" ac:schema-version=\"1\">\
         <ac:rich-text-body><p>",
    );
    let _ = write!(
        out,
        "<strong>Project:</strong> {proj} &nbsp;·&nbsp; \
         <strong>Branch:</strong> {branch} &nbsp;·&nbsp; \
         <strong>Commit:</strong> {commit} &nbsp;·&nbsp; \
         <strong>Scanned:</strong> {scanned}",
        proj = html_esc(project),
        branch = html_esc(branch),
        commit = html_esc(commit),
        scanned = html_esc(&scanned),
    );
    out.push_str("</p></ac:rich-text-body></ac:structured-macro>");

    // Summary stats table
    out.push_str("<h2>Summary</h2>");
    out.push_str(
        "<table><thead><tr>\
         <th>Files Analyzed</th><th>Code Lines</th><th>Comment Lines</th>\
         <th>Blank Lines</th><th>Languages</th>\
         </tr></thead><tbody><tr>",
    );
    let t = &run.summary_totals;
    let _ = write!(
        out,
        "<td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td>",
        t.files_analyzed,
        t.code_lines,
        t.comment_lines,
        t.blank_lines,
        run.totals_by_language.len(),
    );
    out.push_str("</tr></tbody></table>");

    // Per-language breakdown table
    if !run.totals_by_language.is_empty() {
        out.push_str("<h2>Language Breakdown</h2>");
        out.push_str(
            "<table><thead><tr>\
             <th>Language</th><th>Files</th><th>Code</th><th>Comments</th><th>Blank</th>\
             </tr></thead><tbody>",
        );
        for lang in &run.totals_by_language {
            let _ = write!(
                out,
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_esc(lang.language.display_name()),
                lang.files,
                lang.code_lines,
                lang.comment_lines,
                lang.blank_lines,
            );
        }
        out.push_str("</tbody></table>");
    }

    // Link back to full report
    if let Some(url) = report_url {
        let _ = write!(
            out,
            "<p><strong>Full interactive report:</strong> \
             <a href=\"{url}\">{url_disp}</a></p>",
            url = html_esc(url),
            url_disp = html_esc(url),
        );
    }

    out
}

/// Generates Confluence wiki markup (legacy syntax) for copy/paste into a
/// Confluence page editor.
#[must_use]
pub fn render_confluence_wiki_markup(run: &AnalysisRun) -> String {
    let mut out = String::with_capacity(4096);

    let project = run.effective_configuration.reporting.report_title.as_str();
    let branch = run.git_branch.as_deref().unwrap_or("—");
    let commit = run.git_commit_short.as_deref().unwrap_or("—");
    let scanned = run
        .tool
        .timestamp_utc
        .format("%Y-%m-%d %H:%M UTC")
        .to_string();

    let _ = writeln!(out, "{{info}}");
    let _ = writeln!(
        out,
        "Project: {project}  ·  Branch: {branch}  ·  Commit: {commit}  ·  Scanned: {scanned}"
    );
    let _ = writeln!(out, "{{info}}");
    out.push('\n');

    let t = &run.summary_totals;
    let _ = writeln!(out, "h2. Summary");
    let _ = writeln!(
        out,
        "||Files Analyzed||Code Lines||Comment Lines||Blank Lines||Languages||"
    );
    let _ = writeln!(
        out,
        "|{}|{}|{}|{}|{}|",
        t.files_analyzed,
        t.code_lines,
        t.comment_lines,
        t.blank_lines,
        run.totals_by_language.len(),
    );
    out.push('\n');

    if !run.totals_by_language.is_empty() {
        let _ = writeln!(out, "h2. Language Breakdown");
        let _ = writeln!(out, "||Language||Files||Code||Comments||Blank||");
        for lang in &run.totals_by_language {
            let _ = writeln!(
                out,
                "|{}|{}|{}|{}|{}|",
                lang.language.display_name(),
                lang.files,
                lang.code_lines,
                lang.comment_lines,
                lang.blank_lines,
            );
        }
        out.push('\n');
    }

    let _ = writeln!(
        out,
        "*Total:* {} code lines · {} files · {} languages",
        t.code_lines,
        t.files_analyzed,
        run.totals_by_language.len(),
    );

    out
}
