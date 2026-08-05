// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Nima Shafie <nimzshafie@gmail.com>

//! Style-guide analysis for Rust.
//! Guides: Official rustfmt defaults, Mozilla Rust, Rust API Guidelines.

use super::common::{
    IndentStyle, StyleAnalysis, StyleGuideScore, StyleSignal, classify_indent, scan_base_metrics,
    score_indent_4, score_line80, score_line100, score_line120, weighted_score,
};

pub fn analyze(text: &str) -> StyleAnalysis {
    let lines: Vec<&str> = text.lines().collect();
    let m = scan_base_metrics(&lines);

    let mut trailing_commas = 0u32;
    let mut snake_case_fn = 0u32;
    let mut camel_case_fn = 0u32;

    for line in &lines {
        let trimmed = line.trim();
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
            } else if name.chars().next().is_some_and(char::is_uppercase) {
                camel_case_fn += 1;
            }
        }
    }

    let indent = classify_indent(m.tabs, m.sp2, m.sp4);
    let guides = score_rust(
        indent,
        m.over80,
        m.over100,
        m.over120,
        m.total,
        trailing_commas,
    );

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
            value: format!("{} chars", m.max_len),
        },
    ];

    StyleAnalysis::assemble("Rust", indent, &m, signals, guides)
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
        let ratio = f64::from(trailing_commas) / f64::from(total);
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
