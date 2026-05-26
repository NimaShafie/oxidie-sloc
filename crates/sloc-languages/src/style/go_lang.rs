// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Nima Shafie <nimzshafie@gmail.com>

//! Style-guide analysis for Go.
//! Guides: Effective Go / gofmt, Uber Go, Google Go.

use super::common::*;

pub fn analyze(text: &str) -> StyleAnalysis {
    let lines: Vec<&str> = text.lines().collect();
    let mut tabs = 0u32;
    let mut sp2 = 0u32;
    let mut sp4 = 0u32;
    let mut short_decl = 0u32; // :=
    let mut var_decl = 0u32; // var x =
    let mut error_returns = 0u32; // lines containing "return err" or "return nil, err"
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

        if trimmed.contains(":=") {
            short_decl += 1;
        }
        if trimmed.starts_with("var ") {
            var_decl += 1;
        }
        if trimmed.contains("return err") || trimmed.contains("return nil, err") {
            error_returns += 1;
        }
    }

    let indent = classify_indent(tabs, sp2, sp4);
    let uses_short_decl = short_decl > var_decl;

    let guides = score_go(indent, over80, over100, over120, total);
    let (dominant, dominant_pct) = top_guide(&guides);

    let signals = vec![
        StyleSignal {
            name: "Indentation".into(),
            value: indent.display().into(),
        },
        StyleSignal {
            name: "Variable Declarations".into(),
            value: if short_decl + var_decl == 0 {
                "\u{2014}".into()
            } else if uses_short_decl {
                format!(":= preferred ({short_decl} uses)")
            } else {
                format!("var preferred ({var_decl} uses)")
            },
        },
        StyleSignal {
            name: "Error Handling".into(),
            value: if error_returns > 0 {
                format!("{error_returns} early return(s)")
            } else {
                "None detected".into()
            },
        },
        StyleSignal {
            name: "Max Line Length".into(),
            value: format!("{max_len} chars"),
        },
    ];

    StyleAnalysis {
        language_family: "Go".into(),
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

fn score_go(
    ind: IndentStyle,
    over80: u32,
    over100: u32,
    over120: u32,
    total: u32,
) -> Vec<StyleGuideScore> {
    let it = score_indent_tabs(ind);
    let l80 = score_line80(over80, total);
    let l100 = score_line100(over100, total);
    let l120 = score_line120(over120, total);

    // Effective Go / gofmt: tabs, ~80-col (gofmt doesn't hard-limit, but idiom is ~80)
    let effective_go = weighted_score(&[(0.60, it), (0.40, l80)]);
    // Uber Go: tabs, 99-col recommended (they use 120 max)
    let uber = weighted_score(&[(0.50, it), (0.30, l120), (0.20, l100)]);
    // Google Go: tabs, 80-col
    let google = weighted_score(&[(0.55, it), (0.45, l80)]);

    vec![
        StyleGuideScore {
            name: "Effective Go".into(),
            description: "tabs | ~80-col | gofmt standard".into(),
            score_pct: effective_go,
        },
        StyleGuideScore {
            name: "Uber Go".into(),
            description: "tabs | 120-col max".into(),
            score_pct: uber,
        },
        StyleGuideScore {
            name: "Google Go".into(),
            description: "tabs | 80-col".into(),
            score_pct: google,
        },
    ]
}
