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
    pub fn display(self) -> &'static str {
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
    let first = match line.chars().next() {
        Some(c) => c,
        None => return,
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
pub fn classify_indent(tabs: u32, sp2: u32, sp4: u32) -> IndentStyle {
    let total = tabs + sp2 + sp4;
    if total == 0 {
        return IndentStyle::Unknown;
    }
    let tab_pct = tabs as f32 / total as f32;
    let s2_pct = sp2 as f32 / total as f32;
    let s4_pct = sp4 as f32 / total as f32;
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
pub fn weighted_score(features: &[(f32, f32)]) -> u8 {
    let s: f32 = features.iter().map(|(w, v)| w * v).sum();
    (s * 100.0).round().clamp(0.0, 100.0) as u8
}

pub fn score_indent_2(s: IndentStyle) -> f32 {
    match s {
        IndentStyle::Spaces2 => 1.0,
        IndentStyle::Mixed => 0.35,
        _ => 0.05,
    }
}

pub fn score_indent_4(s: IndentStyle) -> f32 {
    match s {
        IndentStyle::Spaces4 => 1.0,
        IndentStyle::Mixed => 0.35,
        _ => 0.05,
    }
}

pub fn score_indent_tabs(s: IndentStyle) -> f32 {
    match s {
        IndentStyle::Tabs => 1.0,
        IndentStyle::Mixed => 0.20,
        _ => 0.05,
    }
}

/// Score compliance with an 80-column limit.
pub fn score_line80(over: u32, total: u32) -> f32 {
    if total == 0 {
        return 1.0;
    }
    let p = over as f32 / total as f32;
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
pub fn score_line88(over88: u32, total: u32) -> f32 {
    score_line_n(over88, total)
}

/// Score compliance with a 100-column limit.
pub fn score_line100(over100: u32, total: u32) -> f32 {
    score_line_n(over100, total)
}

/// Score compliance with a 120-column limit.
pub fn score_line120(over120: u32, total: u32) -> f32 {
    score_line_n(over120, total)
}

fn score_line_n(over: u32, total: u32) -> f32 {
    if total == 0 {
        return 1.0;
    }
    let p = over as f32 / total as f32;
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
pub fn count_over(lines: &[&str], limit: usize) -> u32 {
    lines.iter().filter(|l| l.len() > limit).count() as u32
}
