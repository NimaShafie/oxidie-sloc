// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Nima Shafie <nimzshafie@gmail.com>

//! Style-guide analysis for Ruby.
//! Guides: RuboCop (community), Airbnb Ruby, Standard Ruby.

use super::common::{
    classify_indent, count_first_quote, count_over, scan_indent, score_indent_2, score_line100,
    score_line120, score_line80, top_guide, weighted_score, StyleAnalysis, StyleGuideScore,
    StyleSignal,
};

pub fn analyze(text: &str) -> StyleAnalysis {
    let lines: Vec<&str> = text.lines().collect();
    let mut tabs = 0u32;
    let mut sp2 = 0u32;
    let mut sp4 = 0u32;
    let mut single_q = 0u32;
    let mut double_q = 0u32;
    let mut frozen_literal = false;
    let mut total = 0u32;

    let over80 = count_over(&lines, 80);
    let over100 = count_over(&lines, 100);
    let over120 = count_over(&lines, 120);
    let max_len = lines.iter().map(|l| l.len() as u32).max().unwrap_or(0);

    for line in &lines {
        total += 1;
        scan_ruby_line(
            line,
            &mut tabs,
            &mut sp2,
            &mut sp4,
            &mut single_q,
            &mut double_q,
            &mut frozen_literal,
        );
    }

    let indent = classify_indent(tabs, sp2, sp4);
    let uses_single = single_q as f32 / (single_q + double_q).max(1) as f32 >= 0.60;
    let uses_double = double_q as f32 / (single_q + double_q).max(1) as f32 >= 0.60;

    let guides = score_ruby(
        indent,
        over80,
        over100,
        over120,
        total,
        uses_single,
        uses_double,
    );
    let (dominant, dominant_pct) = top_guide(&guides);

    let quote_str = if uses_single {
        "Single quotes"
    } else if uses_double {
        "Double quotes"
    } else {
        "Mixed"
    };

    let mut signals = vec![
        StyleSignal {
            name: "Quote Style".into(),
            value: quote_str.into(),
        },
        StyleSignal {
            name: "Max Line Length".into(),
            value: format!("{max_len} chars"),
        },
    ];
    if frozen_literal {
        signals.push(StyleSignal {
            name: "Frozen String Literal".into(),
            value: "# frozen_string_literal: true".into(),
        });
    }

    StyleAnalysis {
        language_family: "Ruby".into(),
        indent_style: indent,
        tab_indented_lines: tabs,
        space2_indented_lines: sp2,
        space4_indented_lines: sp4,
        lines_over_80: over80,
        lines_over_100: over100,
        lines_over_120: over120,
        max_line_length: max_len,
        total_lines: total,
        signals,
        guide_scores: guides,
        dominant_guide: dominant,
        dominant_score_pct: dominant_pct,
    }
}

/// Scan one line, updating all per-line counters.
fn scan_ruby_line(
    line: &str,
    tabs: &mut u32,
    sp2: &mut u32,
    sp4: &mut u32,
    single_q: &mut u32,
    double_q: &mut u32,
    frozen_literal: &mut bool,
) {
    scan_indent(line, tabs, sp2, sp4);
    let trimmed = line.trim();
    if trimmed == "# frozen_string_literal: true" {
        *frozen_literal = true;
    }
    if !trimmed.starts_with('#') {
        count_first_quote(trimmed, single_q, double_q);
    }
}

fn score_ruby(
    ind: super::common::IndentStyle,
    over80: u32,
    over100: u32,
    over120: u32,
    total: u32,
    uses_single: bool,
    _uses_double: bool,
) -> Vec<StyleGuideScore> {
    let i2 = score_indent_2(ind);
    let l80 = score_line80(over80, total);
    let l100 = score_line100(over100, total);
    let l120 = score_line120(over120, total);
    let sq = if uses_single { 1.0_f32 } else { 0.0 };

    vec![
        StyleGuideScore {
            name: "RuboCop".into(),
            description: "2-space | 120-col | single quotes".into(),
            score_pct: weighted_score(&[(0.30, i2), (0.40, l120), (0.30, sq)]),
        },
        StyleGuideScore {
            name: "Airbnb Ruby".into(),
            description: "2-space | 100-col | single quotes".into(),
            score_pct: weighted_score(&[(0.30, i2), (0.40, l100), (0.30, sq)]),
        },
        StyleGuideScore {
            name: "Standard Ruby".into(),
            description: "2-space | 80-col | single quotes".into(),
            score_pct: weighted_score(&[(0.30, i2), (0.40, l80), (0.30, sq)]),
        },
    ]
}
