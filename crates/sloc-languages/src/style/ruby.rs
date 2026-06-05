// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Nima Shafie <nimzshafie@gmail.com>

//! Style-guide analysis for Ruby.
//! Guides: `RuboCop` (community), Airbnb Ruby, Standard Ruby.

use super::common::{
    classify_indent, count_first_quote, scan_base_metrics, score_indent_2, score_line100,
    score_line120, score_line80, weighted_score, StyleAnalysis, StyleGuideScore, StyleSignal,
};

pub fn analyze(text: &str) -> StyleAnalysis {
    let lines: Vec<&str> = text.lines().collect();
    let m = scan_base_metrics(&lines);

    let mut single_q = 0u32;
    let mut double_q = 0u32;
    let mut frozen_literal = false;

    for line in &lines {
        scan_ruby_signals(line, &mut single_q, &mut double_q, &mut frozen_literal);
    }

    let indent = classify_indent(m.tabs, m.sp2, m.sp4);
    let uses_single = f64::from(single_q) / f64::from((single_q + double_q).max(1)) >= 0.60;
    let uses_double = f64::from(double_q) / f64::from((single_q + double_q).max(1)) >= 0.60;

    let guides = score_ruby(
        indent,
        m.over80,
        m.over100,
        m.over120,
        m.total,
        uses_single,
        uses_double,
    );

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
            value: format!("{} chars", m.max_len),
        },
    ];
    if frozen_literal {
        signals.push(StyleSignal {
            name: "Frozen String Literal".into(),
            value: "# frozen_string_literal: true".into(),
        });
    }

    StyleAnalysis::assemble("Ruby", indent, &m, signals, guides)
}

/// Scan one line for Ruby-specific signals (quotes and frozen literal comment).
fn scan_ruby_signals(
    line: &str,
    single_q: &mut u32,
    double_q: &mut u32,
    frozen_literal: &mut bool,
) {
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
