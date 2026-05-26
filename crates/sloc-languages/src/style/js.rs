// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Nima Shafie <nimzshafie@gmail.com>

//! Style-guide analysis for JavaScript and TypeScript.
//! JS guides: Airbnb, Google, Standard.js, Prettier.
//! TS guides: Airbnb TS, Google TS, Angular, Microsoft TS.

use super::common::*;
use crate::Language;

pub fn analyze(language: Language, text: &str) -> StyleAnalysis {
    let is_ts = matches!(language, Language::TypeScript);
    let lines: Vec<&str> = text.lines().collect();
    let mut tabs = 0u32;
    let mut sp2 = 0u32;
    let mut sp4 = 0u32;
    let mut semicolons = 0u32;
    let mut no_semicolons = 0u32;
    let mut single_q = 0u32;
    let mut double_q = 0u32;
    let mut var_count = 0u32;
    let mut let_const = 0u32;
    let mut arrow_fns = 0u32;
    let mut total = 0u32;

    let over80 = count_over(&lines, 80);
    let over100 = count_over(&lines, 100);
    let over120 = count_over(&lines, 120);
    let over140 = count_over(&lines, 140);
    let max_len = lines.iter().map(|l| l.len() as u32).max().unwrap_or(0);

    for line in &lines {
        total += 1;
        let trimmed = line.trim();
        scan_indent(line, &mut tabs, &mut sp2, &mut sp4);

        if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*') {
            continue;
        }

        // Semicolons at end of statement lines
        if trimmed.ends_with(';') {
            semicolons += 1;
        } else if !trimmed.is_empty()
            && !trimmed.ends_with('{')
            && !trimmed.ends_with('}')
            && !trimmed.ends_with(',')
            && !trimmed.ends_with('(')
            && !trimmed.ends_with(')')
            && !trimmed.ends_with(':')
            && trimmed.len() > 3
        {
            no_semicolons += 1;
        }

        // Quote style (first quote character wins per line)
        for ch in trimmed.chars() {
            if ch == '\'' {
                single_q += 1;
                break;
            }
            if ch == '"' && !trimmed.starts_with("//") {
                double_q += 1;
                break;
            }
        }

        // var vs let/const
        if trimmed.starts_with("var ") {
            var_count += 1;
        }
        if trimmed.starts_with("let ") || trimmed.starts_with("const ") {
            let_const += 1;
        }

        // Arrow functions
        if trimmed.contains("=>") {
            arrow_fns += 1;
        }
    }

    let indent = classify_indent(tabs, sp2, sp4);
    let uses_semis = semicolons as f32 / (semicolons + no_semicolons).max(1) as f32 >= 0.60;
    let uses_single = single_q as f32 / (single_q + double_q).max(1) as f32 >= 0.60;
    let uses_double = double_q as f32 / (single_q + double_q).max(1) as f32 >= 0.60;
    let modern_vars =
        var_count == 0 || (let_const as f32 / (var_count + let_const).max(1) as f32 >= 0.80);

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
    let var_str = if var_count == 0 {
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
            total,
            uses_semis,
            uses_single,
            uses_double,
        )
    } else {
        score_js(
            indent,
            over80,
            over100,
            total,
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
    if arrow_fns > 0 {
        signals.push(StyleSignal {
            name: "Arrow Functions".into(),
            value: format!("{arrow_fns} detected"),
        });
    }

    let lang_family = if is_ts { "TypeScript" } else { "JavaScript" };

    StyleAnalysis {
        language_family: lang_family.into(),
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

fn top_guide(scores: &[StyleGuideScore]) -> (String, u8) {
    scores
        .iter()
        .max_by_key(|s| s.score_pct)
        .map(|s| (s.name.clone(), s.score_pct))
        .unwrap_or_else(|| ("Unknown".into(), 0))
}

#[allow(clippy::too_many_arguments)]
fn score_js(
    ind: IndentStyle,
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

    // Airbnb: 2-space, 100-col, semicolons, single quotes, no var
    let airbnb = weighted_score(&[(0.20, i2), (0.20, l100), (0.20, sf), (0.20, sq), (0.20, mv)]);
    // Google: 2-space, 80-col, semicolons, single quotes
    let google = weighted_score(&[(0.25, i2), (0.25, l80), (0.25, sf), (0.25, sq)]);
    // Standard.js: 2-space, no semicolons, single quotes
    let standard = weighted_score(&[(0.30, i2), (0.30, nsf), (0.25, sq), (0.15, mv)]);
    // Prettier: 2-space, 80-col, semicolons, double quotes
    let prettier = weighted_score(&[(0.25, i2), (0.25, l80), (0.25, sf), (0.25, dq)]);

    vec![
        StyleGuideScore {
            name: "Airbnb".into(),
            description: "2-space | 100-col | semicolons | single quotes | no var".into(),
            score_pct: airbnb,
        },
        StyleGuideScore {
            name: "Google JS".into(),
            description: "2-space | 80-col | semicolons | single quotes".into(),
            score_pct: google,
        },
        StyleGuideScore {
            name: "Standard.js".into(),
            description: "2-space | no semicolons | single quotes".into(),
            score_pct: standard,
        },
        StyleGuideScore {
            name: "Prettier".into(),
            description: "2-space | 80-col | semicolons | double quotes".into(),
            score_pct: prettier,
        },
    ]
}

#[allow(clippy::too_many_arguments)]
fn score_ts(
    ind: IndentStyle,
    over80: u32,
    over100: u32,
    over120: u32,
    over140: u32,
    total: u32,
    semis: bool,
    single: bool,
    _double: bool,
) -> Vec<StyleGuideScore> {
    let i2 = score_indent_2(ind);
    let i4 = score_indent_4(ind);
    let l80 = score_line80(over80, total);
    let l100 = score_line100(over100, total);
    let l120 = score_line120(over120, total);
    let l140 = score_line_n_local(over140, total);
    let sf = if semis { 1.0_f32 } else { 0.0 };
    let sq = if single { 1.0_f32 } else { 0.0 };

    // Airbnb TS: 2-space, 100-col, semis, single
    let airbnb = weighted_score(&[(0.25, i2), (0.25, l100), (0.25, sf), (0.25, sq)]);
    // Google TS: 2-space, 80-col, semis, single
    let google = weighted_score(&[(0.25, i2), (0.25, l80), (0.25, sf), (0.25, sq)]);
    // Angular: 2-space, 140-col, semis, single
    let angular = weighted_score(&[(0.25, i2), (0.25, l140), (0.25, sf), (0.25, sq)]);
    // Microsoft TS: 4-space, 120-col, semis
    let microsoft = weighted_score(&[(0.35, i4), (0.35, l120), (0.30, sf)]);

    vec![
        StyleGuideScore {
            name: "Airbnb TS".into(),
            description: "2-space | 100-col | semicolons | single quotes".into(),
            score_pct: airbnb,
        },
        StyleGuideScore {
            name: "Google TS".into(),
            description: "2-space | 80-col | semicolons | single quotes".into(),
            score_pct: google,
        },
        StyleGuideScore {
            name: "Angular".into(),
            description: "2-space | 140-col | semicolons | single quotes".into(),
            score_pct: angular,
        },
        StyleGuideScore {
            name: "Microsoft TS".into(),
            description: "4-space | 120-col | semicolons".into(),
            score_pct: microsoft,
        },
    ]
}

fn score_line_n_local(over: u32, total: u32) -> f32 {
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
