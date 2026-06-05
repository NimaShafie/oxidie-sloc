// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Nima Shafie <nimzshafie@gmail.com>

//! Style-guide analysis for Go.
//! Guides: Effective Go / gofmt, Uber Go, Google Go.

use super::common::{
    classify_indent, scan_base_metrics, score_indent_tabs, score_line100, score_line120,
    score_line80, weighted_score, IndentStyle, StyleAnalysis, StyleGuideScore, StyleSignal,
};

pub fn analyze(text: &str) -> StyleAnalysis {
    let lines: Vec<&str> = text.lines().collect();
    let m = scan_base_metrics(&lines);

    let mut short_decl = 0u32; // :=
    let mut var_decl = 0u32; // var x =
    let mut error_returns = 0u32; // lines containing "return err" or "return nil, err"

    for line in &lines {
        let trimmed = line.trim();
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

    let indent = classify_indent(m.tabs, m.sp2, m.sp4);
    let uses_short_decl = short_decl > var_decl;

    let guides = score_go(indent, m.over80, m.over100, m.over120, m.total);

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
            value: format!("{} chars", m.max_len),
        },
    ];

    StyleAnalysis::assemble("Go", indent, &m, signals, guides)
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
