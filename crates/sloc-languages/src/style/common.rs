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
