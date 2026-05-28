// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Nima Shafie <nimzshafie@gmail.com>

//! Style-guide analysis for JavaScript and TypeScript.
//! JS guides: Airbnb, Google, Standard.js, Prettier.
//! TS guides: Airbnb TS, Google TS, Angular, Microsoft TS.

use super::common::{
    classify_indent, count_first_quote, count_over, scan_indent, score_indent_2, score_indent_4,
    score_line100, score_line120, score_line80, score_line_n, top_guide, weighted_score,
    StyleAnalysis, StyleGuideScore, StyleSignal,
};
use crate::Language;

// ─── Per-line accumulator ─────────────────────────────────────────────────────

#[derive(Default)]
struct JsCounts {
    tabs: u32,
    sp2: u32,
    sp4: u32,
    semicolons: u32,
    no_semicolons: u32,
    single_q: u32,
    double_q: u32,
    var_count: u32,
    let_const: u32,
    arrow_fns: u32,
    total: u32,
}

/// Returns true when a trimmed line looks like a statement end but has no semicolon.
fn is_statement_line(trimmed: &str) -> bool {
    !trimmed.is_empty()
        && !trimmed.ends_with('{')
        && !trimmed.ends_with('}')
        && !trimmed.ends_with(',')
        && !trimmed.ends_with('(')
        && !trimmed.ends_with(')')
        && !trimmed.ends_with(':')
        && trimmed.len() > 3
}

fn scan_js_line(line: &str, c: &mut JsCounts) {
    c.total += 1;
    scan_indent(line, &mut c.tabs, &mut c.sp2, &mut c.sp4);
    let trimmed = line.trim();
    if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*') {
        return;
    }
    if trimmed.ends_with(';') {
        c.semicolons += 1;
    } else if is_statement_line(trimmed) {
        c.no_semicolons += 1;
    }
    count_first_quote(trimmed, &mut c.single_q, &mut c.double_q);
    if trimmed.starts_with("var ") {
        c.var_count += 1;
    }
    if trimmed.starts_with("let ") || trimmed.starts_with("const ") {
        c.let_const += 1;
    }
    if trimmed.contains("=>") {
        c.arrow_fns += 1;
    }
}

// ─── Public entry point ───────────────────────────────────────────────────────

pub fn analyze(language: Language, text: &str) -> StyleAnalysis {
    let is_ts = matches!(language, Language::TypeScript);
    let lines: Vec<&str> = text.lines().collect();
    let mut c = JsCounts::default();

    let over80 = count_over(&lines, 80);
    let over100 = count_over(&lines, 100);
    let over120 = count_over(&lines, 120);
    let over140 = count_over(&lines, 140);
    let max_len = lines.iter().map(|l| l.len() as u32).max().unwrap_or(0);

    for line in &lines {
        scan_js_line(line, &mut c);
    }

    let indent = classify_indent(c.tabs, c.sp2, c.sp4);
    let uses_semis = c.semicolons as f32 / (c.semicolons + c.no_semicolons).max(1) as f32 >= 0.60;
    let uses_single = c.single_q as f32 / (c.single_q + c.double_q).max(1) as f32 >= 0.60;
    let uses_double = c.double_q as f32 / (c.single_q + c.double_q).max(1) as f32 >= 0.60;
    let modern_vars = c.var_count == 0
        || (c.let_const as f32 / (c.var_count + c.let_const).max(1) as f32 >= 0.80);

    let quote_str = if uses_single {
        "Single quotes"
    } else if uses_double {
        "Double quotes"
    } else {
        "Mixed"
    };
    let semi_str = if uses_semis {
        "Semicolons used"
    } else {
        "No semicolons"
    };
    let var_str = if c.var_count == 0 {
        "let / const only"
    } else {
        "var present"
    };

    let guides = if is_ts {
        score_ts(
            indent,
            over80,
            over100,
            over120,
            over140,
            c.total,
            uses_semis,
            uses_single,
        )
    } else {
        score_js(
            indent,
            over80,
            over100,
            c.total,
            uses_semis,
            uses_single,
            uses_double,
            modern_vars,
        )
    };
    let (dominant, dominant_pct) = top_guide(&guides);

    let mut signals = vec![
        StyleSignal {
            name: "Quote Style".into(),
            value: quote_str.into(),
        },
        StyleSignal {
            name: "Semicolons".into(),
            value: semi_str.into(),
        },
        StyleSignal {
            name: "Variable Declarations".into(),
            value: var_str.into(),
        },
    ];
    if c.arrow_fns > 0 {
        signals.push(StyleSignal {
            name: "Arrow Functions".into(),
            value: format!("{} detected", c.arrow_fns),
        });
    }

    StyleAnalysis {
        language_family: if is_ts { "TypeScript" } else { "JavaScript" }.into(),
        indent_style: indent,
        tab_indented_lines: c.tabs,
        space2_indented_lines: c.sp2,
        space4_indented_lines: c.sp4,
        lines_over_80: over80,
        lines_over_100: over100,
        lines_over_120: over120,
        max_line_length: max_len,
        total_lines: c.total,
        signals,
        guide_scores: guides,
        dominant_guide: dominant,
        dominant_score_pct: dominant_pct,
    }
}

// ─── Scoring ──────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn score_js(
    ind: super::common::IndentStyle,
    over80: u32,
    over100: u32,
    total: u32,
    semis: bool,
    single: bool,
    double: bool,
    modern_vars: bool,
) -> Vec<StyleGuideScore> {
    let i2 = score_indent_2(ind);
    let l80 = score_line80(over80, total);
    let l100 = score_line100(over100, total);
    let sf = if semis { 1.0_f32 } else { 0.0 };
    let nsf = if !semis { 1.0_f32 } else { 0.0 };
    let sq = if single { 1.0_f32 } else { 0.0 };
    let dq = if double { 1.0_f32 } else { 0.0 };
    let mv = if modern_vars { 1.0_f32 } else { 0.30 };

    vec![
        StyleGuideScore {
            name: "Airbnb".into(),
            description: "2-space | 100-col | semicolons | single quotes | no var".into(),
            score_pct: weighted_score(&[
                (0.20, i2),
                (0.20, l100),
                (0.20, sf),
                (0.20, sq),
                (0.20, mv),
            ]),
        },
        StyleGuideScore {
            name: "Google JS".into(),
            description: "2-space | 80-col | semicolons | single quotes".into(),
            score_pct: weighted_score(&[(0.25, i2), (0.25, l80), (0.25, sf), (0.25, sq)]),
        },
        StyleGuideScore {
            name: "Standard.js".into(),
            description: "2-space | no semicolons | single quotes".into(),
            score_pct: weighted_score(&[(0.30, i2), (0.30, nsf), (0.25, sq), (0.15, mv)]),
        },
        StyleGuideScore {
            name: "Prettier".into(),
            description: "2-space | 80-col | semicolons | double quotes".into(),
            score_pct: weighted_score(&[(0.25, i2), (0.25, l80), (0.25, sf), (0.25, dq)]),
        },
    ]
}

#[allow(clippy::too_many_arguments)]
fn score_ts(
    ind: super::common::IndentStyle,
    over80: u32,
    over100: u32,
    over120: u32,
    over140: u32,
    total: u32,
    semis: bool,
    single: bool,
) -> Vec<StyleGuideScore> {
    let i2 = score_indent_2(ind);
    let i4 = score_indent_4(ind);
    let l80 = score_line80(over80, total);
    let l100 = score_line100(over100, total);
    let l120 = score_line120(over120, total);
    let l140 = score_line_n(over140, total);
    let sf = if semis { 1.0_f32 } else { 0.0 };
    let sq = if single { 1.0_f32 } else { 0.0 };

    vec![
        StyleGuideScore {
            name: "Airbnb TS".into(),
            description: "2-space | 100-col | semicolons | single quotes".into(),
            score_pct: weighted_score(&[(0.25, i2), (0.25, l100), (0.25, sf), (0.25, sq)]),
        },
        StyleGuideScore {
            name: "Google TS".into(),
            description: "2-space | 80-col | semicolons | single quotes".into(),
            score_pct: weighted_score(&[(0.25, i2), (0.25, l80), (0.25, sf), (0.25, sq)]),
        },
        StyleGuideScore {
            name: "Angular".into(),
            description: "2-space | 140-col | semicolons | single quotes".into(),
            score_pct: weighted_score(&[(0.25, i2), (0.25, l140), (0.25, sf), (0.25, sq)]),
        },
        StyleGuideScore {
            name: "Microsoft TS".into(),
            description: "4-space | 120-col | semicolons".into(),
            score_pct: weighted_score(&[(0.35, i4), (0.35, l120), (0.30, sf)]),
        },
    ]
}
