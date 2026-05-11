// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Nima Shafie <nimzshafie@gmail.com>

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, ValueEnum, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MixedLinePolicy {
    #[default]
    CodeOnly,
    CodeAndComment,
    CommentOnly,
    SeparateMixedCategory,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum BinaryFileBehavior {
    #[default]
    Skip,
    Fail,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum FailureBehavior {
    #[default]
    WarnSkip,
    Fail,
}

/// IEEE 1045-1992: how backslash line continuations are handled for physical SLOC counting.
///
/// Physical SLOC (the default) counts each physical line. Logical mode collapses a
/// backslash-continued sequence into a single counted line, which is useful when measuring
/// logical statements (e.g., multi-line C preprocessor macros).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, ValueEnum, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ContinuationLinePolicy {
    #[default]
    /// Count each physical line separately — the IEEE 1045-1992 default for physical SLOC.
    EachPhysicalLine,
    /// Collapse backslash-continued physical lines into a single logical line.
    CollapseToLogical,
}

/// IEEE 1045-1992: how blank lines that fall inside a block comment are classified.
///
/// The standard aligns with counting them as comment lines (they are part of the comment
/// body). The `CountAsBlank` variant preserves the legacy behaviour if required.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, ValueEnum, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum BlankInBlockCommentPolicy {
    #[default]
    /// Blank lines inside /* */ (or equivalent) blocks count as comment lines — IEEE aligned.
    CountAsComment,
    /// Blank lines inside block comments count as blank lines.
    CountAsBlank,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    pub root_paths: Vec<PathBuf>,
    pub include_globs: Vec<String>,
    pub exclude_globs: Vec<String>,
    pub excluded_directories: Vec<String>,
    pub honor_ignore_files: bool,
    pub ignore_hidden_files: bool,
    pub follow_symlinks: bool,
    pub max_file_size_bytes: u64,
    pub parallelism_limit: Option<usize>,
    /// When true, detect .gitmodules and produce a per-submodule summary alongside the overall run.
    #[serde(default = "default_true")]
    pub submodule_breakdown: bool,
    #[serde(default)]
    pub allowed_scan_roots: Vec<PathBuf>,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            root_paths: Vec::new(),
            include_globs: Vec::new(),
            exclude_globs: Vec::new(),
            excluded_directories: vec![".git".into(), "node_modules".into(), "target".into()],
            honor_ignore_files: true,
            ignore_hidden_files: true,
            follow_symlinks: false,
            max_file_size_bytes: 2 * 1024 * 1024,
            parallelism_limit: None,
            submodule_breakdown: true,
            allowed_scan_roots: Vec::new(),
        }
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisConfig {
    pub enabled_languages: Vec<String>,
    pub extension_overrides: BTreeMap<String, String>,
    pub shebang_detection: bool,
    pub mixed_line_policy: MixedLinePolicy,
    pub python_docstrings_as_comments: bool,
    pub generated_file_detection: bool,
    pub minified_file_detection: bool,
    pub vendor_directory_detection: bool,
    pub include_lockfiles: bool,
    pub binary_file_behavior: BinaryFileBehavior,
    pub decode_failure_behavior: FailureBehavior,
    pub parse_failure_behavior: FailureBehavior,
    /// IEEE 1045-1992: how backslash line continuations (C macros, shell, Makefile) are counted.
    #[serde(default)]
    pub continuation_line_policy: ContinuationLinePolicy,
    /// IEEE 1045-1992: whether blank lines inside block comments count as comment lines.
    #[serde(default)]
    pub blank_in_block_comment_policy: BlankInBlockCommentPolicy,
    /// IEEE 1045-1992 §4.2: when false, preprocessor/compiler directives (#include, #define,
    /// etc.) are excluded from code SLOC and tracked separately in `compiler_directive_lines`.
    /// Applies to C, C++, and Objective-C. Default: true (directives count toward code SLOC).
    #[serde(default = "default_true")]
    pub count_compiler_directives: bool,
    /// Optional SLOC budget thresholds. When set, `--fail-on-budget` exits non-zero if
    /// any threshold is exceeded. Configured under `[analysis.budget]` in the TOML.
    #[serde(default)]
    pub budget: Option<BudgetConfig>,
    /// Path to an LCOV `.info` file produced by lcov, gcov, cargo-llvm-cov, etc.
    /// When set, oxide-sloc attaches per-file line/function coverage to each `FileRecord`.
    /// Can also be set via the `SLOC_COVERAGE_FILE` environment variable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage_file: Option<PathBuf>,
}

const fn default_true() -> bool {
    true
}

/// Validates that `s` is a CSS hex colour: `#RGB` or `#RRGGBB`.
pub fn validate_hex_color(s: &str) -> Result<()> {
    let hex = s
        .strip_prefix('#')
        .ok_or_else(|| anyhow::anyhow!("must start with '#'"))?;
    if !matches!(hex.len(), 3 | 6) || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("must be a 3- or 6-digit hex colour (e.g. #3b82f6)");
    }
    Ok(())
}

/// Per-language and total SLOC thresholds. Used with `--fail-on-budget` in CI.
///
/// Keys in `per_language` are case-insensitive language display names
/// (e.g. `"rust"`, `"typescript"`). Zero means unlimited.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BudgetConfig {
    /// Maximum total code lines across all languages (0 = unlimited).
    #[serde(default)]
    pub total_max: u64,
    /// Per-language code-line ceilings. Key is the language display name, lowercase.
    #[serde(default)]
    pub per_language: BTreeMap<String, u64>,
}

impl BudgetConfig {
    /// Returns `true` if no limits are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.total_max == 0 && self.per_language.is_empty()
    }

    /// # Errors
    ///
    /// Returns an error if any budget threshold is zero (which would always fail).
    pub fn validate(&self) -> Result<()> {
        for (lang, &limit) in &self.per_language {
            if limit == 0 {
                anyhow::bail!("per_language[\"{lang}\"] limit must be > 0");
            }
        }
        Ok(())
    }
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            enabled_languages: Vec::new(),
            extension_overrides: BTreeMap::new(),
            shebang_detection: true,
            mixed_line_policy: MixedLinePolicy::CodeOnly,
            python_docstrings_as_comments: true,
            generated_file_detection: true,
            minified_file_detection: true,
            vendor_directory_detection: true,
            include_lockfiles: false,
            binary_file_behavior: BinaryFileBehavior::Skip,
            decode_failure_behavior: FailureBehavior::WarnSkip,
            parse_failure_behavior: FailureBehavior::WarnSkip,
            continuation_line_policy: ContinuationLinePolicy::EachPhysicalLine,
            blank_in_block_comment_policy: BlankInBlockCommentPolicy::CountAsComment,
            count_compiler_directives: true,
            budget: None,
            coverage_file: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportingConfig {
    pub report_title: String,
    pub output_formats: Vec<String>,
    pub include_summary_charts: bool,
    pub include_skipped_files_section: bool,
    pub include_warnings_section: bool,
    pub theme: String,
    /// Optional company or team name shown in the report header instead of "`OxideSLOC`".
    #[serde(default)]
    pub company_name: Option<String>,
    /// Path to a PNG/SVG logo file to embed in the report header.
    /// If unset, the default `OxideSLOC` logo is used.
    #[serde(default)]
    pub logo_path: Option<std::path::PathBuf>,
    /// CSS hex colour (e.g. `#3b82f6`) used as the primary accent throughout the report.
    /// Must start with `#` and be a valid 3- or 6-digit hex colour.
    #[serde(default)]
    pub accent_color: Option<String>,
    /// Text printed in a header and footer strip on every page of the HTML/PDF report.
    /// Use for company name, project identifier, or scanner identification.
    #[serde(default)]
    pub report_header_footer: Option<String>,
}

impl Default for ReportingConfig {
    fn default() -> Self {
        Self {
            report_title: "OxideSLOC Report".into(),
            output_formats: vec!["cli".into(), "json".into(), "html".into()],
            include_summary_charts: true,
            include_skipped_files_section: true,
            include_warnings_section: true,
            theme: "auto".into(),
            company_name: None,
            logo_path: None,
            accent_color: None,
            report_header_footer: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebConfig {
    pub bind_address: String,
    /// When true the server binds to 0.0.0.0 by default, suppresses browser
    /// auto-open, and disables desktop-only routes (pick-directory, open-path).
    #[serde(default)]
    pub server_mode: bool,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            bind_address: "127.0.0.1:4317".into(),
            server_mode: false,
        }
    }
}

/// A named configuration profile.  All sub-config sections are optional; any
/// present section *replaces* the corresponding base config section in full.
/// Commonly used to represent different scanning contexts in the same repo
/// (e.g. `[profile.frontend]`, `[profile.backend]`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProfileConfig {
    #[serde(default)]
    pub discovery: Option<DiscoveryConfig>,
    #[serde(default)]
    pub analysis: Option<AnalysisConfig>,
    #[serde(default)]
    pub reporting: Option<ReportingConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfig {
    pub discovery: DiscoveryConfig,
    pub analysis: AnalysisConfig,
    pub reporting: ReportingConfig,
    pub web: WebConfig,
    /// Named profiles that override base config sections when selected via `--profile`.
    #[serde(default)]
    pub profiles: BTreeMap<String, ProfileConfig>,
}

impl AppConfig {
    /// Apply the named profile overrides on top of this config.
    ///
    /// # Errors
    ///
    /// Returns an error if no profile with that name exists or if the resulting
    /// config fails validation.
    pub fn apply_profile(&mut self, name: &str) -> Result<()> {
        let profile = self
            .profiles
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("profile '{name}' not found in config"))?
            .clone();
        if let Some(d) = profile.discovery {
            self.discovery = d;
        }
        if let Some(a) = profile.analysis {
            self.analysis = a;
        }
        if let Some(r) = profile.reporting {
            self.reporting = r;
        }
        self.validate()
    }
}

impl AppConfig {
    /// # Errors
    ///
    /// Returns an error if the file cannot be read, the TOML cannot be parsed, or the
    /// resulting config fails validation.
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read config file {}", path.display()))?;
        let config: Self = toml::from_str(&raw)
            .with_context(|| format!("failed to parse TOML config {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    /// # Errors
    ///
    /// Returns an error if any configuration field contains an invalid value.
    pub fn validate(&self) -> Result<()> {
        if self.discovery.max_file_size_bytes == 0 {
            anyhow::bail!("discovery.max_file_size_bytes must be greater than zero");
        }

        if self.web.bind_address.trim().is_empty() {
            anyhow::bail!("web.bind_address must not be empty");
        }

        if let Some(color) = &self.reporting.accent_color {
            validate_hex_color(color)
                .with_context(|| format!("reporting.accent_color is invalid: {color}"))?;
        }

        if let Some(budget) = &self.analysis.budget {
            budget.validate().context("analysis.budget is invalid")?;
        }

        Ok(())
    }
}
