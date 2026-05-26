// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Nima Shafie <nimzshafie@gmail.com>

//! Style-guide analysis for Python.
//! Guides: PEP 8, Black, Google Python.

use super::common::*;

pub fn analyze(text: &str) -> StyleAnalysis {
    let lines: Vec<&str> = text.lines().collect();
    let mut tabs = 0u32;
    let mut sp2 = 0u32;
    let mut sp4 = 0u32;
    let mut single_q = 0u32;
    let mut double_q = 0u32;
    let mut type_hints = 0u32;
    let mut total = 0u32;

    let over80 = count_over(&lines, 80);
    let over88 = count_over(&lines, 88);
    let over99 = count_over(&lines, 99);
    let over100 = count_over(&lines, 100);
    let over120 = count_over(&lines, 120);
    let max_len = lines.iter().map(|l| l.len() as u32).max().unwrap_or(0);

    for line in &lines {
        total += 1;
        let trimmed = line.trim();
        scan_indent(line, &mut tabs, &mut sp2, &mut sp4);

        // Quote style: count string literal opens (simple heuristic)
        for ch in trimmed.chars() {
            if ch == '\'' {
                single_q += 1;
                break;
            }
            if ch == '"' {
                double_q += 1;
                break;
            }
        }

        // Type hints: function signatures like `def f(x: int)` or `-> Type`
        if (trimmed.starts_with("def ") || trimmed.starts_with("async def "))
            && (trimmed.contains(": ") || trimmed.contains("->"))
        {
            type_hints += 1;
        }
    }

    let indent = classify_indent(tabs, sp2, sp4);

    // Quote style
    let quote_val = if single_q == 0 && double_q == 0 {
        "\u{2014}"
    } else if double_q as f32 / (single_q + double_q) as f32 >= 0.70 {
        "Double quotes"
    } else if single_q as f32 / (single_q + double_q) as f32 >= 0.70 {
        "Single quotes"
    } else {
        "Mixed"
    };

    let guides = score_guides(
        indent, over80, over88, over99, total, double_q, single_q, type_hints,
    );
    let (dominant, dominant_pct) = top_guide(&guides);

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
            value: format!("{max_len} chars"),
        },
    ];

    StyleAnalysis {
        language_family: "Python".into(),
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

fn score_double_quotes(double: u32, single: u32) -> f32 {
    let t = double + single;
    if t == 0 {
        return 0.50;
    }
    double as f32 / t as f32
}

fn score_single_quotes(double: u32, single: u32) -> f32 {
    let t = double + single;
    if t == 0 {
        return 0.50;
    }
    single as f32 / t as f32
}

fn top_guide(scores: &[StyleGuideScore]) -> (String, u8) {
    scores
        .iter()
        .max_by_key(|s| s.score_pct)
        .map(|s| (s.name.clone(), s.score_pct))
        .unwrap_or_else(|| ("Unknown".into(), 0))
}

#[allow(clippy::too_many_arguments)]
fn score_guides(
    ind: IndentStyle,
    over80: u32,
    over88: u32,
    over99: u32,
    total: u32,
    double_q: u32,
    single_q: u32,
    _type_hints: u32,
) -> Vec<StyleGuideScore> {
    let l79 = score_line80(over80, total); // PEP 8 uses 79-col; close enough to 80
    let l88 = score_line88(over88, total);
    let l80 = score_line80(over80, total);
    let l99 = score_line_n_pub(over99, total);
    let i4 = score_indent_4(ind);
    let dq = score_double_quotes(double_q, single_q);
    let _sq = score_single_quotes(double_q, single_q);

    // PEP 8: 4-space, 79-col, either quote style (slight preference for neither)
    let pep8 = weighted_score(&[(0.40, i4), (0.40, l79), (0.20, 0.70)]);

    // Black: 4-space, 88-col, double quotes (enforced by formatter)
    let black = weighted_score(&[(0.35, i4), (0.35, l88), (0.30, dq)]);

    // Google Python: 4-space, 80-col, allows both quotes (slight preference for double)
    let google = weighted_score(&[(0.35, i4), (0.35, l80), (0.20, dq), (0.10, 0.70)]);

    // PEP 8 (relaxed/99-col): 4-space, 99-col, either quote style
    let pep8_relaxed = weighted_score(&[(0.40, i4), (0.40, l99), (0.20, 0.70)]);

    vec![
        StyleGuideScore {
            name: "PEP 8".into(),
            description: "4-space | 79-col | style guide standard".into(),
            score_pct: pep8,
        },
        StyleGuideScore {
            name: "Black".into(),
            description: "4-space | 88-col | double quotes (enforced)".into(),
            score_pct: black,
        },
        StyleGuideScore {
            name: "Google Python".into(),
            description: "4-space | 80-col | double quotes preferred".into(),
            score_pct: google,
        },
        StyleGuideScore {
            name: "PEP 8 (99-col)".into(),
            description: "4-space | 99-col | relaxed line limit variant".into(),
            score_pct: pep8_relaxed,
        },
    ]
}

fn score_line_n_pub(over: u32, total: u32) -> f32 {
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
