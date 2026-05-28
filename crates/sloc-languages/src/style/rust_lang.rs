// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Nima Shafie <nimzshafie@gmail.com>

//! Style-guide analysis for Rust.
//! Guides: Official rustfmt defaults, Mozilla Rust, Rust API Guidelines.

use super::common::*;

pub fn analyze(text: &str) -> StyleAnalysis {
    let lines: Vec<&str> = text.lines().collect();
    let mut tabs = 0u32;
    let mut sp2 = 0u32;
    let mut sp4 = 0u32;
    let mut trailing_commas = 0u32;
    let mut snake_case_fn = 0u32;
    let mut camel_case_fn = 0u32;
    let mut total = 0u32;

    let over80 = count_over(&lines, 80);
    let over100 = count_over(&lines, 100);
    let over120 = count_over(&lines, 120);
    let max_len = lines.iter().map(|l| l.len() as u32).max().unwrap_or(0);

    for line in &lines {
        total += 1;
        let trimmed = line.trim();
        scan_indent(line, &mut tabs, &mut sp2, &mut sp4);

        if trimmed.starts_with("//") {
            continue;
        }

        // Trailing commas in multi-line constructs
        if trimmed == "," || trimmed.ends_with(',') && !trimmed.ends_with(",,") {
            trailing_commas += 1;
        }

        // fn naming convention
        if let Some(rest) = trimmed.strip_prefix("fn ") {
            let name = rest.split('(').next().unwrap_or("").trim();
            if name.contains('_') && name == name.to_lowercase() {
                snake_case_fn += 1;
            } else if name.chars().next().is_some_and(|c| c.is_uppercase()) {
                camel_case_fn += 1;
            }
        }
    }

    let indent = classify_indent(tabs, sp2, sp4);

    let guides = score_rust(indent, over80, over100, over120, total, trailing_commas);
    let (dominant, dominant_pct) = top_guide(&guides);

    let signals = vec![
        StyleSignal {
            name: "Indentation".into(),
            value: indent.display().into(),
        },
        StyleSignal {
            name: "Function Naming".into(),
            value: if snake_case_fn + camel_case_fn == 0 {
                "\u{2014}".into()
            } else if snake_case_fn >= camel_case_fn {
                "snake_case (idiomatic)".into()
            } else {
                "CamelCase (non-idiomatic)".into()
            },
        },
        StyleSignal {
            name: "Max Line Length".into(),
            value: format!("{max_len} chars"),
        },
    ];

    StyleAnalysis {
        language_family: "Rust".into(),
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

fn score_rust(
    ind: IndentStyle,
    over80: u32,
    over100: u32,
    over120: u32,
    total: u32,
    trailing_commas: u32,
) -> Vec<StyleGuideScore> {
    let i4 = score_indent_4(ind);
    let l100 = score_line100(over100, total);
    let l80 = score_line80(over80, total);
    let l120 = score_line120(over120, total);
    let tc = if total == 0 {
        0.50_f32
    } else {
        let ratio = trailing_commas as f32 / total as f32;
        if ratio > 0.02 {
            1.0
        } else if ratio > 0.005 {
            0.70
        } else {
            0.30
        }
    };

    // Official rustfmt: 4-space, 100-col, trailing commas in multi-line
    let rustfmt = weighted_score(&[(0.40, i4), (0.40, l100), (0.20, tc)]);
    // Mozilla Rust: 4-space, 100-col (historically 99)
    let mozilla = weighted_score(&[(0.40, i4), (0.40, l100), (0.20, 0.70)]);
    // Rust API Guidelines: 4-space, 80-col
    let api_guidelines = weighted_score(&[(0.50, i4), (0.35, l80), (0.15, tc)]);
    // Oxide/stricter: 4-space, 120-col
    let relaxed = weighted_score(&[(0.50, i4), (0.50, l120)]);

    vec![
        StyleGuideScore {
            name: "rustfmt defaults".into(),
            description: "4-space | 100-col | trailing commas".into(),
            score_pct: rustfmt,
        },
        StyleGuideScore {
            name: "Mozilla Rust".into(),
            description: "4-space | 100-col".into(),
            score_pct: mozilla,
        },
        StyleGuideScore {
            name: "Rust API Guidelines".into(),
            description: "4-space | 80-col".into(),
            score_pct: api_guidelines,
        },
        StyleGuideScore {
            name: "Relaxed (120-col)".into(),
            description: "4-space | 120-col".into(),
            score_pct: relaxed,
        },
    ]
}
