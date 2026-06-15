// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Nima Shafie <nimzshafie@gmail.com>

//! Shared types, helpers, and scoring utilities for all language style analysers.

use serde::{Deserialize, Serialize};

// ─── Common signal enums ──────────────────────────────────────────────────────

/// Detected leading-whitespace style.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum IndentStyle {
    Tabs,
    Spaces2,
    Spaces4,
    Spaces8,
    Mixed,
    #[default]
    Unknown,
}

impl IndentStyle {
    #[must_use]
    pub const fn display(self) -> &'static str {
        match self {
            Self::Tabs => "Tabs",
            Self::Spaces2 => "2-Space",
            Self::Spaces4 => "4-Space",
            Self::Spaces8 => "8-Space",
            Self::Mixed => "Mixed",
            Self::Unknown => "\u{2014}",
        }
    }
}

// ─── Output types ─────────────────────────────────────────────────────────────

/// An observable style signal specific to a language.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StyleSignal {
    /// Human-readable signal name, e.g. `"Quote Style"`.
    pub name: String,
    /// Detected value, e.g. `"Double quotes"`.
    pub value: String,
}

/// Adherence percentage for one named style guide.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StyleGuideScore {
    pub name: String,
    /// Key characteristics used in scoring (shown as a tooltip).
    pub description: String,
    /// Computed adherence, 0-100.
    pub score_pct: u8,
}

/// Generic style analysis result — works for any supported language.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StyleAnalysis {
    /// Language family label, e.g. `"C / C++"`, `"Python"`.
    pub language_family: String,

    // ── Common measured metrics ───────────────────────────────────────────
    pub indent_style: IndentStyle,
    pub tab_indented_lines: u32,
    pub space2_indented_lines: u32,
    pub space4_indented_lines: u32,
    pub lines_over_80: u32,
    pub lines_over_100: u32,
    pub lines_over_120: u32,
    pub max_line_length: u32,
    pub total_lines: u32,

    /// Language-specific observable signals for display.
    pub signals: Vec<StyleSignal>,

    // ── Style-guide scores ────────────────────────────────────────────────
    pub guide_scores: Vec<StyleGuideScore>,
    pub dominant_guide: String,
    pub dominant_score_pct: u8,
}

// ─── Shared scan helpers ──────────────────────────────────────────────────────

/// Classify one line's leading whitespace into the three indent counters.
pub fn scan_indent(line: &str, tabs: &mut u32, sp2: &mut u32, sp4: &mut u32) {
    let Some(first) = line.chars().next() else {
        return;
    };
    if first == '\t' {
        *tabs += 1;
        return;
    }
    if first != ' ' {
        return;
    }
    let leading = line.bytes().take_while(|&b| b == b' ').count();
    if leading == 0 {
        return;
    }
    if leading % 4 == 0 {
        *sp4 += 1;
    } else if leading % 2 == 0 {
        *sp2 += 1;
    }
}

/// Classify accumulated indent counts into a dominant style.
#[must_use]
pub fn classify_indent(tabs: u32, sp2: u32, sp4: u32) -> IndentStyle {
    let total = tabs + sp2 + sp4;
    if total == 0 {
        return IndentStyle::Unknown;
    }
    let tab_pct = f64::from(tabs) / f64::from(total);
    let s2_pct = f64::from(sp2) / f64::from(total);
    let s4_pct = f64::from(sp4) / f64::from(total);
    if tab_pct >= 0.60 {
        return IndentStyle::Tabs;
    }
    if s4_pct >= 0.60 {
        return IndentStyle::Spaces4;
    }
    if s2_pct >= 0.60 {
        return IndentStyle::Spaces2;
    }
    if sp4 > sp2 * 2 && sp4 > tabs {
        return IndentStyle::Spaces4;
    }
    if sp2 > sp4 && sp2 > tabs {
        return IndentStyle::Spaces2;
    }
    IndentStyle::Mixed
}

// ─── Scoring helpers ──────────────────────────────────────────────────────────

/// Weighted average of feature values; each entry is (weight, value ∈ [0,1]).
#[must_use]
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // clamped 0..=100
pub fn weighted_score(features: &[(f32, f32)]) -> u8 {
    let s: f32 = features.iter().map(|(w, v)| w * v).sum();
    (s * 100.0).round().clamp(0.0, 100.0) as u8
}

#[must_use]
pub const fn score_indent_2(s: IndentStyle) -> f32 {
    match s {
        IndentStyle::Spaces2 => 1.0,
        IndentStyle::Mixed => 0.35,
        _ => 0.05,
    }
}

#[must_use]
pub const fn score_indent_4(s: IndentStyle) -> f32 {
    match s {
        IndentStyle::Spaces4 => 1.0,
        IndentStyle::Mixed => 0.35,
        _ => 0.05,
    }
}

#[must_use]
pub const fn score_indent_tabs(s: IndentStyle) -> f32 {
    match s {
        IndentStyle::Tabs => 1.0,
        IndentStyle::Mixed => 0.20,
        _ => 0.05,
    }
}

/// Score compliance with an 80-column limit.
#[must_use]
pub fn score_line80(over: u32, total: u32) -> f32 {
    if total == 0 {
        return 1.0;
    }
    let p = f64::from(over) / f64::from(total);
    if p < 0.02 {
        1.00
    } else if p < 0.08 {
        0.75
    } else if p < 0.20 {
        0.45
    } else {
        0.10
    }
}

/// Score compliance with a 88-column limit (Black).
#[must_use]
pub fn score_line88(over88: u32, total: u32) -> f32 {
    score_line_n(over88, total)
}

/// Score compliance with a 100-column limit.
#[must_use]
pub fn score_line100(over100: u32, total: u32) -> f32 {
    score_line_n(over100, total)
}

/// Score compliance with a 120-column limit.
#[must_use]
pub fn score_line120(over120: u32, total: u32) -> f32 {
    score_line_n(over120, total)
}

#[must_use]
pub fn score_line_n(over: u32, total: u32) -> f32 {
    if total == 0 {
        return 1.0;
    }
    let p = f64::from(over) / f64::from(total);
    if p < 0.03 {
        1.00
    } else if p < 0.10 {
        0.75
    } else if p < 0.25 {
        0.45
    } else {
        0.10
    }
}

/// Count lines over a given length threshold.
#[must_use]
pub fn count_over(lines: &[&str], limit: usize) -> u32 {
    u32::try_from(lines.iter().filter(|l| l.len() > limit).count()).unwrap_or(u32::MAX)
}

// ─── Shared analysis helpers ──────────────────────────────────────────────────

/// Return the guide with the highest score, or `("Unknown", 0)` for an empty slice.
#[must_use]
pub fn top_guide(scores: &[StyleGuideScore]) -> (String, u8) {
    scores
        .iter()
        .max_by_key(|s| s.score_pct)
        .map_or_else(|| ("Unknown".into(), 0), |s| (s.name.clone(), s.score_pct))
}

// ─── Base metrics ─────────────────────────────────────────────────────────────

/// Metrics computed identically across every language analyser.
pub struct BaseMetrics {
    pub tabs: u32,
    pub sp2: u32,
    pub sp4: u32,
    pub over80: u32,
    pub over100: u32,
    pub over120: u32,
    pub max_len: u32,
    pub total: u32,
}

/// Single-pass scan that fills all language-neutral metrics.
#[must_use]
pub fn scan_base_metrics(lines: &[&str]) -> BaseMetrics {
    let over80 = count_over(lines, 80);
    let over100 = count_over(lines, 100);
    let over120 = count_over(lines, 120);
    let max_len = lines
        .iter()
        .map(|l| u32::try_from(l.len()).unwrap_or(u32::MAX))
        .max()
        .unwrap_or(0);
    let total = u32::try_from(lines.len()).unwrap_or(u32::MAX);
    let mut tabs = 0u32;
    let mut sp2 = 0u32;
    let mut sp4 = 0u32;
    for line in lines {
        scan_indent(line, &mut tabs, &mut sp2, &mut sp4);
    }
    BaseMetrics {
        tabs,
        sp2,
        sp4,
        over80,
        over100,
        over120,
        max_len,
        total,
    }
}

/// Count the first quote character (`'` or `"`) on a line.
/// At most one counter is incremented per call.
pub fn count_first_quote(trimmed: &str, single_q: &mut u32, double_q: &mut u32) {
    for ch in trimmed.chars() {
        if ch == '\'' {
            *single_q += 1;
            break;
        }
        if ch == '"' {
            *double_q += 1;
            break;
        }
    }
}

// ─── Shared brace-style helpers ───────────────────────────────────────────────

/// Brace placement style shared across C, C++, Java, C#, and similar languages.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BraceStyle {
    Attach,
    Allman,
    Mixed,
    Unknown,
}

impl BraceStyle {
    #[must_use]
    pub const fn display(self) -> &'static str {
        match self {
            Self::Attach => "K&R / Attach",
            Self::Allman => "Allman",
            Self::Mixed => "Mixed",
            Self::Unknown => "\u{2014}",
        }
    }
}

/// Classify accumulated allman/attach counts into a dominant brace style.
#[must_use]
pub fn classify_brace(allman: u32, attach: u32) -> BraceStyle {
    let t = allman + attach;
    if t == 0 {
        return BraceStyle::Unknown;
    }
    let a = f64::from(allman) / f64::from(t);
    let k = f64::from(attach) / f64::from(t);
    if a >= 0.65 {
        BraceStyle::Allman
    } else if k >= 0.65 {
        BraceStyle::Attach
    } else {
        BraceStyle::Mixed
    }
}

/// Score compliance with K&R / attach brace style.
#[must_use]
pub const fn score_attach_brace(b: BraceStyle) -> f32 {
    match b {
        BraceStyle::Attach => 1.0,
        BraceStyle::Mixed => 0.40,
        BraceStyle::Allman => 0.05,
        BraceStyle::Unknown => 0.50,
    }
}

/// Score compliance with Allman brace style.
#[must_use]
pub const fn score_allman_brace(b: BraceStyle) -> f32 {
    match b {
        BraceStyle::Allman => 1.0,
        BraceStyle::Mixed => 0.40,
        BraceStyle::Attach => 0.05,
        BraceStyle::Unknown => 0.50,
    }
}

impl StyleAnalysis {
    /// Construct a `StyleAnalysis` from base metrics, signals, and guide scores.
    /// Computes `dominant_guide` / `dominant_score_pct` internally.
    #[must_use]
    pub fn assemble(
        language_family: &str,
        indent: IndentStyle,
        m: &BaseMetrics,
        signals: Vec<StyleSignal>,
        guides: Vec<StyleGuideScore>,
    ) -> Self {
        let (dominant, dominant_pct) = top_guide(&guides);
        Self {
            language_family: language_family.into(),
            indent_style: indent,
            tab_indented_lines: m.tabs,
            space2_indented_lines: m.sp2,
            space4_indented_lines: m.sp4,
            lines_over_80: m.over80,
            lines_over_100: m.over100,
            lines_over_120: m.over120,
            max_line_length: m.max_len,
            total_lines: m.total,
            signals,
            guide_scores: guides,
            dominant_guide: dominant,
            dominant_score_pct: dominant_pct,
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── IndentStyle::display ─────────────────────────────────────────────────

    #[test]
    fn indent_style_display_all_variants() {
        assert_eq!(IndentStyle::Tabs.display(), "Tabs");
        assert_eq!(IndentStyle::Spaces2.display(), "2-Space");
        assert_eq!(IndentStyle::Spaces4.display(), "4-Space");
        assert_eq!(IndentStyle::Spaces8.display(), "8-Space");
        assert_eq!(IndentStyle::Mixed.display(), "Mixed");
        // Unknown renders as em-dash
        assert!(!IndentStyle::Unknown.display().is_empty());
    }

    // ── scan_indent ──────────────────────────────────────────────────────────

    #[test]
    fn scan_indent_tab_line() {
        let mut tabs = 0u32;
        let mut sp2 = 0u32;
        let mut sp4 = 0u32;
        scan_indent("\treturn x;", &mut tabs, &mut sp2, &mut sp4);
        assert_eq!(tabs, 1);
        assert_eq!(sp2, 0);
        assert_eq!(sp4, 0);
    }

    #[test]
    fn scan_indent_two_space_line() {
        let mut tabs = 0u32;
        let mut sp2 = 0u32;
        let mut sp4 = 0u32;
        scan_indent("  let x = 1;", &mut tabs, &mut sp2, &mut sp4);
        assert_eq!(tabs, 0);
        assert_eq!(sp2, 1);
        assert_eq!(sp4, 0);
    }

    #[test]
    fn scan_indent_four_space_line() {
        let mut tabs = 0u32;
        let mut sp2 = 0u32;
        let mut sp4 = 0u32;
        scan_indent("    let x = 1;", &mut tabs, &mut sp2, &mut sp4);
        assert_eq!(tabs, 0);
        assert_eq!(sp2, 0);
        assert_eq!(sp4, 1);
    }

    #[test]
    fn scan_indent_eight_space_line() {
        let mut tabs = 0u32;
        let mut sp2 = 0u32;
        let mut sp4 = 0u32;
        scan_indent("        let x = 1;", &mut tabs, &mut sp2, &mut sp4);
        // 8 spaces: 8 % 4 == 0, so counts as sp4
        assert_eq!(sp4, 1);
    }

    #[test]
    fn scan_indent_empty_line_no_change() {
        let mut tabs = 0u32;
        let mut sp2 = 0u32;
        let mut sp4 = 0u32;
        scan_indent("", &mut tabs, &mut sp2, &mut sp4);
        assert_eq!(tabs, 0);
        assert_eq!(sp2, 0);
        assert_eq!(sp4, 0);
    }

    #[test]
    fn scan_indent_no_leading_whitespace() {
        let mut tabs = 0u32;
        let mut sp2 = 0u32;
        let mut sp4 = 0u32;
        scan_indent("let x = 1;", &mut tabs, &mut sp2, &mut sp4);
        assert_eq!(tabs, 0);
        assert_eq!(sp2, 0);
        assert_eq!(sp4, 0);
    }

    #[test]
    fn scan_indent_three_spaces_not_counted() {
        // 3 spaces: not divisible by 2 or 4 → nothing incremented
        let mut tabs = 0u32;
        let mut sp2 = 0u32;
        let mut sp4 = 0u32;
        scan_indent("   let x = 1;", &mut tabs, &mut sp2, &mut sp4);
        assert_eq!(tabs, 0);
        assert_eq!(sp2, 0);
        assert_eq!(sp4, 0);
    }

    // ── classify_indent ──────────────────────────────────────────────────────

    #[test]
    fn classify_indent_all_zero_returns_unknown() {
        assert_eq!(classify_indent(0, 0, 0), IndentStyle::Unknown);
    }

    #[test]
    fn classify_indent_dominant_tabs() {
        // 10 tabs, 1 sp2, 1 sp4 → 83% tabs → Tabs
        assert_eq!(classify_indent(10, 1, 1), IndentStyle::Tabs);
    }

    #[test]
    fn classify_indent_dominant_spaces4() {
        assert_eq!(classify_indent(0, 0, 10), IndentStyle::Spaces4);
    }

    #[test]
    fn classify_indent_dominant_spaces2() {
        assert_eq!(classify_indent(0, 10, 0), IndentStyle::Spaces2);
    }

    #[test]
    fn classify_indent_mixed_when_evenly_split() {
        // No clear dominant
        assert_eq!(classify_indent(3, 3, 3), IndentStyle::Mixed);
    }

    #[test]
    fn classify_indent_spaces4_when_sp4_greatly_exceeds_sp2() {
        // sp4 > sp2*2 and sp4 > tabs → Spaces4
        assert_eq!(classify_indent(0, 1, 10), IndentStyle::Spaces4);
    }

    #[test]
    fn classify_indent_spaces2_when_sp2_exceeds_others() {
        // sp2 > sp4 and sp2 > tabs but not 60% threshold
        assert_eq!(classify_indent(0, 5, 2), IndentStyle::Spaces2);
    }

    // ── score_indent helpers ─────────────────────────────────────────────────

    #[test]
    fn score_indent_2_perfect() {
        assert!((super::score_indent_2(IndentStyle::Spaces2) - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn score_indent_2_mixed() {
        assert!((super::score_indent_2(IndentStyle::Mixed) - 0.35).abs() < 0.01);
    }

    #[test]
    fn score_indent_4_perfect() {
        assert!((super::score_indent_4(IndentStyle::Spaces4) - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn score_indent_tabs_perfect() {
        assert!((super::score_indent_tabs(IndentStyle::Tabs) - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn score_indent_tabs_mixed() {
        assert!((super::score_indent_tabs(IndentStyle::Mixed) - 0.20).abs() < 0.01);
    }

    // ── score_line80 ─────────────────────────────────────────────────────────

    #[test]
    fn score_line80_zero_total_is_perfect() {
        assert!((score_line80(0, 0) - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn score_line80_very_few_violations() {
        // < 2% over 80 → 1.0
        let score = score_line80(1, 100);
        assert!((score - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn score_line80_some_violations() {
        // 5% → between 0.02 and 0.08 → 0.75
        let score = score_line80(5, 100);
        assert!((score - 0.75).abs() < 0.01);
    }

    #[test]
    fn score_line80_many_violations() {
        // 15% → between 0.08 and 0.20 → 0.45
        let score = score_line80(15, 100);
        assert!((score - 0.45).abs() < 0.01);
    }

    #[test]
    fn score_line80_excessive_violations() {
        // 30% → >= 0.20 → 0.10
        let score = score_line80(30, 100);
        assert!((score - 0.10).abs() < 0.01);
    }

    // ── score_line_n variants ────────────────────────────────────────────────

    #[test]
    fn score_line_n_zero_total_is_perfect() {
        assert!((score_line_n(0, 0) - 1.0).abs() < f32::EPSILON);
        assert!((score_line100(0, 0) - 1.0).abs() < f32::EPSILON);
        assert!((score_line120(0, 0) - 1.0).abs() < f32::EPSILON);
        assert!((score_line88(0, 0) - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn score_line_n_low_violations_is_perfect() {
        // < 3% → 1.0
        let score = score_line_n(2, 100);
        assert!((score - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn score_line_n_moderate_violations() {
        // 7% → between 0.03 and 0.10 → 0.75
        let score = score_line_n(7, 100);
        assert!((score - 0.75).abs() < 0.01);
    }

    #[test]
    fn score_line_n_high_violations() {
        // 15% → between 0.10 and 0.25 → 0.45
        let score = score_line_n(15, 100);
        assert!((score - 0.45).abs() < 0.01);
    }

    #[test]
    fn score_line_n_very_high_violations() {
        // 30% → >= 0.25 → 0.10
        let score = score_line_n(30, 100);
        assert!((score - 0.10).abs() < 0.01);
    }

    // ── count_over ───────────────────────────────────────────────────────────

    #[test]
    fn count_over_counts_lines_exceeding_limit() {
        let lines = vec![
            "short",
            "a longer line that exceeds eighty characters in total when measured carefully",
            "tiny",
        ];
        let count = count_over(&lines, 20);
        assert_eq!(count, 1);
    }

    #[test]
    fn count_over_none_exceeding_returns_zero() {
        let lines = vec!["hi", "ok", "yes"];
        assert_eq!(count_over(&lines, 80), 0);
    }

    #[test]
    fn count_over_empty_slice_returns_zero() {
        assert_eq!(count_over(&[], 80), 0);
    }

    // ── top_guide ────────────────────────────────────────────────────────────

    #[test]
    fn top_guide_returns_highest_scoring_guide() {
        let guides = vec![
            StyleGuideScore {
                name: "A".into(),
                description: String::new(),
                score_pct: 70,
            },
            StyleGuideScore {
                name: "B".into(),
                description: String::new(),
                score_pct: 95,
            },
            StyleGuideScore {
                name: "C".into(),
                description: String::new(),
                score_pct: 80,
            },
        ];
        let (name, score) = top_guide(&guides);
        assert_eq!(name, "B");
        assert_eq!(score, 95);
    }

    #[test]
    fn top_guide_empty_slice_returns_unknown() {
        let (name, score) = top_guide(&[]);
        assert_eq!(name, "Unknown");
        assert_eq!(score, 0);
    }

    // ── scan_base_metrics ────────────────────────────────────────────────────

    #[test]
    fn scan_base_metrics_all_fields() {
        let lines = vec![
            "    let x = 1;",      // 4-space indent
            "\tlet y = 2;",        // tab indent
            "  return z;",         // 2-space indent
            "x".repeat(90).leak(), // > 80 chars
            "short",
        ];
        let m = scan_base_metrics(&lines);
        assert_eq!(m.total, 5);
        assert!(m.tabs >= 1);
        assert!(m.sp4 >= 1);
        assert!(m.sp2 >= 1);
        assert!(m.over80 >= 1);
        assert_eq!(m.over100, 0);
        assert_eq!(m.over120, 0);
        assert!(m.max_len >= 90);
    }

    #[test]
    fn scan_base_metrics_empty_input() {
        let m = scan_base_metrics(&[]);
        assert_eq!(m.total, 0);
        assert_eq!(m.max_len, 0);
    }

    // ── count_first_quote ────────────────────────────────────────────────────

    #[test]
    fn count_first_quote_single_quote_counted() {
        let mut sq = 0u32;
        let mut dq = 0u32;
        count_first_quote("let x = 'hello';", &mut sq, &mut dq);
        assert_eq!(sq, 1);
        assert_eq!(dq, 0);
    }

    #[test]
    fn count_first_quote_double_quote_counted() {
        let mut sq = 0u32;
        let mut dq = 0u32;
        count_first_quote("let x = \"hello\";", &mut sq, &mut dq);
        assert_eq!(sq, 0);
        assert_eq!(dq, 1);
    }

    #[test]
    fn count_first_quote_no_quote_no_change() {
        let mut sq = 0u32;
        let mut dq = 0u32;
        count_first_quote("let x = 42;", &mut sq, &mut dq);
        assert_eq!(sq, 0);
        assert_eq!(dq, 0);
    }

    #[test]
    fn count_first_quote_only_increments_first_found() {
        // Line has single quote first, then double → only single counted
        let mut sq = 0u32;
        let mut dq = 0u32;
        count_first_quote("'a' + \"b\"", &mut sq, &mut dq);
        assert_eq!(sq, 1);
        assert_eq!(dq, 0);
    }

    // ── BraceStyle::display ──────────────────────────────────────────────────

    #[test]
    fn brace_style_display_all_variants() {
        assert_eq!(BraceStyle::Attach.display(), "K&R / Attach");
        assert_eq!(BraceStyle::Allman.display(), "Allman");
        assert_eq!(BraceStyle::Mixed.display(), "Mixed");
        assert!(!BraceStyle::Unknown.display().is_empty());
    }

    // ── classify_brace ───────────────────────────────────────────────────────

    #[test]
    fn classify_brace_unknown_when_both_zero() {
        assert!(matches!(classify_brace(0, 0), BraceStyle::Unknown));
    }

    #[test]
    fn classify_brace_allman_dominant() {
        // 7 allman vs 3 attach → 70% allman → Allman
        assert!(matches!(classify_brace(7, 3), BraceStyle::Allman));
    }

    #[test]
    fn classify_brace_attach_dominant() {
        assert!(matches!(classify_brace(2, 8), BraceStyle::Attach));
    }

    #[test]
    fn classify_brace_mixed_when_even() {
        assert!(matches!(classify_brace(5, 5), BraceStyle::Mixed));
    }

    // ── score_attach_brace and score_allman_brace ────────────────────────────

    #[test]
    fn score_attach_brace_all_variants() {
        assert!((score_attach_brace(BraceStyle::Attach) - 1.0).abs() < f32::EPSILON);
        assert!((score_attach_brace(BraceStyle::Mixed) - 0.40).abs() < 0.01);
        assert!((score_attach_brace(BraceStyle::Allman) - 0.05).abs() < 0.01);
        assert!((score_attach_brace(BraceStyle::Unknown) - 0.50).abs() < 0.01);
    }

    #[test]
    fn score_allman_brace_all_variants() {
        assert!((score_allman_brace(BraceStyle::Allman) - 1.0).abs() < f32::EPSILON);
        assert!((score_allman_brace(BraceStyle::Mixed) - 0.40).abs() < 0.01);
        assert!((score_allman_brace(BraceStyle::Attach) - 0.05).abs() < 0.01);
        assert!((score_allman_brace(BraceStyle::Unknown) - 0.50).abs() < 0.01);
    }

    // ── weighted_score ───────────────────────────────────────────────────────

    #[test]
    fn weighted_score_single_feature_perfect() {
        let score = weighted_score(&[(1.0, 1.0)]);
        assert_eq!(score, 100);
    }

    #[test]
    fn weighted_score_single_feature_zero() {
        let score = weighted_score(&[(1.0, 0.0)]);
        assert_eq!(score, 0);
    }

    #[test]
    fn weighted_score_mixed_features() {
        // 0.5 * 1.0 + 0.5 * 0.0 = 0.5 → 50%
        let score = weighted_score(&[(0.5, 1.0), (0.5, 0.0)]);
        assert_eq!(score, 50);
    }

    #[test]
    fn weighted_score_clamped_to_100() {
        // Weight sum > 1.0 would push above 100 but it is clamped
        let score = weighted_score(&[(2.0, 1.0)]);
        assert_eq!(score, 100);
    }

    #[test]
    fn weighted_score_empty_features_is_zero() {
        assert_eq!(weighted_score(&[]), 0);
    }

    // ── StyleAnalysis::assemble ──────────────────────────────────────────────

    #[test]
    fn style_analysis_assemble_sets_dominant_guide() {
        let m = scan_base_metrics(&["    let x = 1;", "\tlet y = 2;"]);
        let indent = classify_indent(m.tabs, m.sp2, m.sp4);
        let guides = vec![
            StyleGuideScore {
                name: "Guide A".into(),
                description: "desc".into(),
                score_pct: 60,
            },
            StyleGuideScore {
                name: "Guide B".into(),
                description: "desc".into(),
                score_pct: 85,
            },
        ];
        let analysis = StyleAnalysis::assemble("TestLang", indent, &m, vec![], guides);
        assert_eq!(analysis.language_family, "TestLang");
        assert_eq!(analysis.dominant_guide, "Guide B");
        assert_eq!(analysis.dominant_score_pct, 85);
        assert_eq!(analysis.total_lines, 2);
    }
}
