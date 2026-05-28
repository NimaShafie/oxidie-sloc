// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Nima Shafie <nimzshafie@gmail.com>

//! Style-guide analysis for C# and F#.
//! C# guides: Microsoft (.NET), Google C#, StyleCop.
//! F# guides: Microsoft F#, FSharp.Formatting.

use super::common::{
    classify_brace, classify_indent, scan_base_metrics, score_allman_brace, score_attach_brace,
    score_indent_4, score_line100, score_line120, score_line80, weighted_score, BraceStyle,
    StyleAnalysis, StyleGuideScore, StyleSignal,
};
use crate::Language;

pub fn analyze(language: Language, text: &str) -> StyleAnalysis {
    let lines: Vec<&str> = text.lines().collect();
    let m = scan_base_metrics(&lines);

    let mut allman = 0u32;
    let mut attach = 0u32;
    let mut var_count = 0u32;
    let mut explicit_type = 0u32;

    for line in &lines {
        let trimmed = line.trim();
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

    let indent = classify_indent(m.tabs, m.sp2, m.sp4);
    let brace = classify_brace(allman, attach);
    let prefers_var = var_count > explicit_type;

    let (guides, lang_family) = match language {
        Language::FSharp => (score_fsharp(indent, m.over80, m.over100, m.total), "F#"),
        _ => (
            score_csharp(
                indent,
                brace,
                m.over80,
                m.over100,
                m.over120,
                m.total,
                prefers_var,
            ),
            "C#",
        ),
    };

    let signals = vec![
        StyleSignal {
            name: "Brace Style".into(),
            value: brace.display().into(),
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
            value: format!("{} chars", m.max_len),
        },
    ];

    StyleAnalysis::assemble(lang_family, indent, &m, signals, guides)
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
