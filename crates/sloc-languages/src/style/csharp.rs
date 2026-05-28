// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Nima Shafie <nimzshafie@gmail.com>

//! Style-guide analysis for C# and F#.
//! C# guides: Microsoft (.NET), Google C#, StyleCop.
//! F# guides: Microsoft F#, FSharp.Formatting.

use super::common::{
    classify_brace, classify_indent, count_over, scan_indent, score_allman_brace,
    score_attach_brace, score_indent_4, score_line100, score_line120, score_line80, top_guide,
    weighted_score, BraceStyle, StyleAnalysis, StyleGuideScore, StyleSignal,
};
use crate::Language;

pub fn analyze(language: Language, text: &str) -> StyleAnalysis {
    let lines: Vec<&str> = text.lines().collect();
    let mut tabs = 0u32;
    let mut sp2 = 0u32;
    let mut sp4 = 0u32;
    let mut allman = 0u32;
    let mut attach = 0u32;
    let mut var_count = 0u32;
    let mut explicit_type = 0u32;
    let mut total = 0u32;

    let over80 = count_over(&lines, 80);
    let over100 = count_over(&lines, 100);
    let over120 = count_over(&lines, 120);
    let max_len = lines.iter().map(|l| l.len() as u32).max().unwrap_or(0);

    for line in &lines {
        total += 1;
        let trimmed = line.trim();
        scan_indent(line, &mut tabs, &mut sp2, &mut sp4);

        if trimmed == "{" {
            allman += 1;
        } else if trimmed.ends_with(" {") || trimmed.ends_with(") {") {
            attach += 1;
        }

        if trimmed.starts_with("var ") {
            var_count += 1;
        }
        for kw in &[
            "int ",
            "string ",
            "bool ",
            "double ",
            "float ",
            "List<",
            "IEnumerable<",
            "Dictionary<",
            "Task<",
            "Task ",
            "void ",
            "object ",
        ] {
            if trimmed.starts_with(kw) {
                explicit_type += 1;
                break;
            }
        }
    }

    let indent = classify_indent(tabs, sp2, sp4);
    let brace = classify_brace(allman, attach);
    let prefers_var = var_count > explicit_type;

    let (guides, lang_family) = match language {
        Language::FSharp => (score_fsharp(indent, over80, over100, total), "F#"),
        _ => (
            score_csharp(indent, brace, over80, over100, over120, total, prefers_var),
            "C#",
        ),
    };

    let (dominant, dominant_pct) = top_guide(&guides);

    let signals = vec![
        StyleSignal {
            name: "Brace Style".into(),
            value: brace_display(brace).into(),
        },
        StyleSignal {
            name: "Type Inference".into(),
            value: if var_count + explicit_type == 0 {
                "\u{2014}".into()
            } else if prefers_var {
                format!("var preferred ({var_count} uses)")
            } else {
                format!("explicit types ({explicit_type} uses)")
            },
        },
        StyleSignal {
            name: "Max Line Length".into(),
            value: format!("{max_len} chars"),
        },
    ];

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

fn brace_display(b: BraceStyle) -> &'static str {
    match b {
        BraceStyle::Allman => "Allman (new line)",
        BraceStyle::Attach => "K&R / Attach",
        BraceStyle::Mixed => "Mixed",
        BraceStyle::Unknown => "\u{2014}",
    }
}

fn score_csharp(
    ind: super::common::IndentStyle,
    brace: BraceStyle,
    over80: u32,
    over100: u32,
    over120: u32,
    total: u32,
    _prefers_var: bool,
) -> Vec<StyleGuideScore> {
    let i4 = score_indent_4(ind);
    let l80 = score_line80(over80, total);
    let l100 = score_line100(over100, total);
    let l120 = score_line120(over120, total);
    let all = score_allman_brace(brace);
    let att = score_attach_brace(brace);

    vec![
        StyleGuideScore {
            name: "Microsoft .NET".into(),
            description: "4-space | Allman braces | 120-col".into(),
            score_pct: weighted_score(&[(0.35, i4), (0.40, all), (0.25, l120)]),
        },
        StyleGuideScore {
            name: "Google C#".into(),
            description: "4-space | K&R braces | 100-col".into(),
            score_pct: weighted_score(&[(0.35, i4), (0.35, att), (0.30, l100)]),
        },
        StyleGuideScore {
            name: "StyleCop".into(),
            description: "4-space | Allman braces | 80-col".into(),
            score_pct: weighted_score(&[(0.35, i4), (0.35, all), (0.30, l80)]),
        },
    ]
}

fn score_fsharp(
    ind: super::common::IndentStyle,
    over80: u32,
    over100: u32,
    total: u32,
) -> Vec<StyleGuideScore> {
    let i4 = score_indent_4(ind);
    let l80 = score_line80(over80, total);
    let l100 = score_line100(over100, total);

    vec![
        StyleGuideScore {
            name: "Microsoft F#".into(),
            description: "4-space | 100-col".into(),
            score_pct: weighted_score(&[(0.50, i4), (0.50, l100)]),
        },
        StyleGuideScore {
            name: "FSharp.Formatting".into(),
            description: "4-space | 80-col".into(),
            score_pct: weighted_score(&[(0.50, i4), (0.50, l80)]),
        },
    ]
}
