// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Nima Shafie <nimzshafie@gmail.com>

//! Style-guide analysis for Python.
//! Guides: PEP 8, Black, Google Python.

use super::common::{
    StyleAnalysis, StyleGuideScore, StyleSignal, classify_indent, count_first_quote, count_over,
    scan_base_metrics, score_indent_4, score_line_n, score_line80, score_line88, weighted_score,
};

pub fn analyze(text: &str) -> StyleAnalysis {
    let lines: Vec<&str> = text.lines().collect();
    let m = scan_base_metrics(&lines);
    let over88 = count_over(&lines, 88);
    let over99 = count_over(&lines, 99);

    let mut single_q = 0u32;
    let mut double_q = 0u32;
    let mut type_hints = 0u32;

    for line in &lines {
        let trimmed = line.trim();
        count_first_quote(trimmed, &mut single_q, &mut double_q);
        if has_type_hints(trimmed) {
            type_hints += 1;
        }
    }

    let indent = classify_indent(m.tabs, m.sp2, m.sp4);

    let quote_val = if single_q == 0 && double_q == 0 {
        "\u{2014}"
    } else if f64::from(double_q) / f64::from(single_q + double_q) >= 0.70 {
        "Double quotes"
    } else if f64::from(single_q) / f64::from(single_q + double_q) >= 0.70 {
        "Single quotes"
    } else {
        "Mixed"
    };

    let guides = score_guides(
        indent, m.over80, over88, over99, m.total, double_q, single_q, type_hints,
    );

    let signals = vec![
        StyleSignal {
            name: "Quote Style".into(),
            value: quote_val.into(),
        },
        StyleSignal {
            name: "Type Hints".into(),
            value: if type_hints > 0 {
                format!("{type_hints} annotated function(s)")
            } else {
                "None detected".into()
            },
        },
        StyleSignal {
            name: "Max Line Length".into(),
            value: format!("{} chars", m.max_len),
        },
    ];

    StyleAnalysis::assemble("Python", indent, &m, signals, guides)
}

fn has_type_hints(trimmed: &str) -> bool {
    (trimmed.starts_with("def ") || trimmed.starts_with("async def "))
        && (trimmed.contains(": ") || trimmed.contains("->"))
}

#[allow(clippy::cast_precision_loss)] // counts bounded well within f32 precision
fn score_double_quotes(double: u32, single: u32) -> f32 {
    let t = double + single;
    if t == 0 {
        0.50
    } else {
        double as f32 / t as f32
    }
}

#[allow(clippy::too_many_arguments)]
fn score_guides(
    ind: super::common::IndentStyle,
    over80: u32,
    over88: u32,
    over99: u32,
    total: u32,
    double_q: u32,
    single_q: u32,
    _type_hints: u32,
) -> Vec<StyleGuideScore> {
    let l79 = score_line80(over80, total);
    let l88 = score_line88(over88, total);
    let l80 = score_line80(over80, total);
    let l99 = score_line_n(over99, total);
    let i4 = score_indent_4(ind);
    let dq = score_double_quotes(double_q, single_q);

    vec![
        StyleGuideScore {
            name: "PEP 8".into(),
            description: "4-space | 79-col | style guide standard".into(),
            score_pct: weighted_score(&[(0.40, i4), (0.40, l79), (0.20, 0.70)]),
        },
        StyleGuideScore {
            name: "Black".into(),
            description: "4-space | 88-col | double quotes (enforced)".into(),
            score_pct: weighted_score(&[(0.35, i4), (0.35, l88), (0.30, dq)]),
        },
        StyleGuideScore {
            name: "Google Python".into(),
            description: "4-space | 80-col | double quotes preferred".into(),
            score_pct: weighted_score(&[(0.35, i4), (0.35, l80), (0.20, dq), (0.10, 0.70)]),
        },
        StyleGuideScore {
            name: "PEP 8 (99-col)".into(),
            description: "4-space | 99-col | relaxed line limit variant".into(),
            score_pct: weighted_score(&[(0.40, i4), (0.40, l99), (0.20, 0.70)]),
        },
    ]
}
