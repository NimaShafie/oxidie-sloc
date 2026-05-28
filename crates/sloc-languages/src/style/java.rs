// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Nima Shafie <nimzshafie@gmail.com>

//! Style-guide analysis for Java, Kotlin, Groovy, and Scala.
//! Java guides: Google Java, Oracle/Sun, Spring Framework.
//! Kotlin guides: JetBrains, Android, Google Kotlin.

use super::common::{
    classify_brace, classify_indent, scan_base_metrics, score_attach_brace, score_indent_2,
    score_indent_4, score_line100, score_line120, score_line80, weighted_score, BraceStyle,
    StyleAnalysis, StyleGuideScore, StyleSignal,
};
use crate::Language;

pub fn analyze(language: Language, text: &str) -> StyleAnalysis {
    let lines: Vec<&str> = text.lines().collect();
    let m = scan_base_metrics(&lines);

    let mut allman = 0u32;
    let mut attach = 0u32;
    let mut wildcard_imports = 0u32;

    for line in &lines {
        let trimmed = line.trim();
        if trimmed == "{" {
            allman += 1;
        } else if trimmed.ends_with(" {") || trimmed.ends_with(") {") {
            attach += 1;
        }
        if trimmed.starts_with("import ") && trimmed.ends_with(".*;") {
            wildcard_imports += 1;
        }
    }

    let indent = classify_indent(m.tabs, m.sp2, m.sp4);
    let brace = classify_brace(allman, attach);
    let no_wildcard = wildcard_imports == 0;

    let (guides, lang_family) = match language {
        Language::Kotlin => (score_kotlin(indent, m.over80, m.over100, m.total), "Kotlin"),
        Language::Groovy => (score_groovy(indent, m.over80, m.over100, m.total), "Groovy"),
        Language::Scala => (score_scala(indent, m.over80, m.over100, m.total), "Scala"),
        _ => (
            score_java(
                indent,
                brace,
                m.over80,
                m.over100,
                m.over120,
                m.total,
                no_wildcard,
            ),
            "Java",
        ),
    };

    let signals = vec![
        StyleSignal {
            name: "Brace Style".into(),
            value: brace.display().into(),
        },
        StyleSignal {
            name: "Wildcard Imports".into(),
            value: if no_wildcard {
                "None".into()
            } else {
                format!("{wildcard_imports} found")
            },
        },
        StyleSignal {
            name: "Max Line Length".into(),
            value: format!("{} chars", m.max_len),
        },
    ];

    StyleAnalysis::assemble(lang_family, indent, &m, signals, guides)
}

fn score_java(
    ind: super::common::IndentStyle,
    brace: BraceStyle,
    over80: u32,
    over100: u32,
    over120: u32,
    total: u32,
    no_wildcard: bool,
) -> Vec<StyleGuideScore> {
    let i2 = score_indent_2(ind);
    let i4 = score_indent_4(ind);
    let l80 = score_line80(over80, total);
    let l100 = score_line100(over100, total);
    let l120 = score_line120(over120, total);
    let att = score_attach_brace(brace);
    let nw = if no_wildcard { 1.0_f32 } else { 0.20 };

    vec![
        StyleGuideScore {
            name: "Google Java".into(),
            description: "2-space | 100-col | K&R | no wildcard imports".into(),
            score_pct: weighted_score(&[(0.25, i2), (0.25, l100), (0.25, att), (0.25, nw)]),
        },
        StyleGuideScore {
            name: "Oracle/Sun".into(),
            description: "4-space | 80-col | K&R braces".into(),
            score_pct: weighted_score(&[(0.35, i4), (0.35, l80), (0.30, att)]),
        },
        StyleGuideScore {
            name: "Spring".into(),
            description: "4-space | 120-col | K&R braces".into(),
            score_pct: weighted_score(&[(0.35, i4), (0.35, l120), (0.30, att)]),
        },
    ]
}

fn score_kotlin(
    ind: super::common::IndentStyle,
    over80: u32,
    over100: u32,
    total: u32,
) -> Vec<StyleGuideScore> {
    let i4 = score_indent_4(ind);
    let l100 = score_line100(over100, total);
    let l80 = score_line80(over80, total);

    vec![
        StyleGuideScore {
            name: "JetBrains".into(),
            description: "4-space | 100-col".into(),
            score_pct: weighted_score(&[(0.50, i4), (0.50, l100)]),
        },
        StyleGuideScore {
            name: "Android".into(),
            description: "4-space | 100-col".into(),
            score_pct: weighted_score(&[(0.50, i4), (0.50, l100)]),
        },
        StyleGuideScore {
            name: "Google Kotlin".into(),
            description: "4-space | 80-col".into(),
            score_pct: weighted_score(&[(0.50, i4), (0.50, l80)]),
        },
    ]
}

fn score_groovy(
    ind: super::common::IndentStyle,
    over80: u32,
    over100: u32,
    total: u32,
) -> Vec<StyleGuideScore> {
    let i4 = score_indent_4(ind);
    let l100 = score_line100(over100, total);
    let l80 = score_line80(over80, total);

    vec![
        StyleGuideScore {
            name: "Apache Groovy".into(),
            description: "4-space | 80-col".into(),
            score_pct: weighted_score(&[(0.50, i4), (0.50, l80)]),
        },
        StyleGuideScore {
            name: "Gradle DSL".into(),
            description: "4-space | 100-col".into(),
            score_pct: weighted_score(&[(0.50, i4), (0.50, l100)]),
        },
    ]
}

fn score_scala(
    ind: super::common::IndentStyle,
    over80: u32,
    over100: u32,
    total: u32,
) -> Vec<StyleGuideScore> {
    let i2 = score_indent_2(ind);
    let i4 = score_indent_4(ind);
    let l80 = score_line80(over80, total);
    let l100 = score_line100(over100, total);

    vec![
        StyleGuideScore {
            name: "Scala Style Guide".into(),
            description: "2-space | 80-col".into(),
            score_pct: weighted_score(&[(0.50, i2), (0.50, l80)]),
        },
        StyleGuideScore {
            name: "Lightbend".into(),
            description: "2-space | 100-col".into(),
            score_pct: weighted_score(&[(0.50, i2), (0.50, l100)]),
        },
        StyleGuideScore {
            name: "Spark".into(),
            description: "4-space | 100-col".into(),
            score_pct: weighted_score(&[(0.50, i4), (0.50, l100)]),
        },
    ]
}
