// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Nima Shafie <nimzshafie@gmail.com>

//! Style-guide analysis for Java, Kotlin, Groovy, and Scala.
//! Java guides: Google Java, Oracle/Sun, Spring Framework.
//! Kotlin guides: JetBrains, Android, Google Kotlin.

use super::common::*;
use crate::Language;

/// K&R / Allman brace detection (same heuristics as C++).
#[derive(Clone, Copy, PartialEq)]
enum BraceStyle {
    Attach,
    Allman,
    Mixed,
    Unknown,
}

pub fn analyze(language: Language, text: &str) -> StyleAnalysis {
    let lines: Vec<&str> = text.lines().collect();
    let mut tabs = 0u32;
    let mut sp2 = 0u32;
    let mut sp4 = 0u32;
    let mut allman = 0u32;
    let mut attach = 0u32;
    let mut wildcard_imports = 0u32;
    let mut total = 0u32;

    let over80 = count_over(&lines, 80);
    let over100 = count_over(&lines, 100);
    let over120 = count_over(&lines, 120);
    let max_len = lines.iter().map(|l| l.len() as u32).max().unwrap_or(0);

    for line in &lines {
        total += 1;
        let trimmed = line.trim();
        scan_indent(line, &mut tabs, &mut sp2, &mut sp4);

        // Brace style
        if trimmed == "{" {
            allman += 1;
        } else if trimmed.ends_with(" {") || trimmed.ends_with(") {") {
            attach += 1;
        }

        // Wildcard imports
        if trimmed.starts_with("import ") && trimmed.ends_with(".*;") {
            wildcard_imports += 1;
        }
    }

    let indent = classify_indent(tabs, sp2, sp4);
    let brace = classify_brace(allman, attach);
    let no_wildcard = wildcard_imports == 0;

    let (guides, lang_family) = match language {
        Language::Kotlin => {
            let g = score_kotlin(indent, over80, over100, total);
            (g, "Kotlin")
        }
        Language::Groovy => {
            let g = score_groovy(indent, over80, over100, total);
            (g, "Groovy")
        }
        Language::Scala => {
            let g = score_scala(indent, over80, over100, total);
            (g, "Scala")
        }
        _ => {
            let g = score_java(indent, brace, over80, over100, over120, total, no_wildcard);
            (g, "Java")
        }
    };

    let (dominant, dominant_pct) = top_guide(&guides);

    let signals = vec![
        StyleSignal {
            name: "Brace Style".into(),
            value: brace_display(brace).into(),
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

fn classify_brace(allman: u32, attach: u32) -> BraceStyle {
    let t = allman + attach;
    if t == 0 {
        return BraceStyle::Unknown;
    }
    let a = allman as f32 / t as f32;
    let k = attach as f32 / t as f32;
    if a >= 0.65 {
        BraceStyle::Allman
    } else if k >= 0.65 {
        BraceStyle::Attach
    } else {
        BraceStyle::Mixed
    }
}

fn brace_display(b: BraceStyle) -> &'static str {
    match b {
        BraceStyle::Attach => "K&R / Attach",
        BraceStyle::Allman => "Allman",
        BraceStyle::Mixed => "Mixed",
        BraceStyle::Unknown => "\u{2014}",
    }
}

fn score_attach(b: BraceStyle) -> f32 {
    match b {
        BraceStyle::Attach => 1.0,
        BraceStyle::Mixed => 0.40,
        BraceStyle::Allman => 0.05,
        BraceStyle::Unknown => 0.50,
    }
}

fn top_guide(scores: &[StyleGuideScore]) -> (String, u8) {
    scores
        .iter()
        .max_by_key(|s| s.score_pct)
        .map(|s| (s.name.clone(), s.score_pct))
        .unwrap_or_else(|| ("Unknown".into(), 0))
}

fn score_java(
    ind: IndentStyle,
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
    let att = score_attach(brace);
    let nw = if no_wildcard { 1.0_f32 } else { 0.20 };

    // Google Java: 2-space, 100-col, K&R, no wildcard imports
    let google = weighted_score(&[(0.25, i2), (0.25, l100), (0.25, att), (0.25, nw)]);
    // Oracle/Sun: 4-space, 80-col, K&R
    let oracle = weighted_score(&[(0.35, i4), (0.35, l80), (0.30, att)]);
    // Spring Framework: 4-space, 120-col, K&R
    let spring = weighted_score(&[(0.35, i4), (0.35, l120), (0.30, att)]);

    vec![
        StyleGuideScore {
            name: "Google Java".into(),
            description: "2-space | 100-col | K&R | no wildcard imports".into(),
            score_pct: google,
        },
        StyleGuideScore {
            name: "Oracle/Sun".into(),
            description: "4-space | 80-col | K&R braces".into(),
            score_pct: oracle,
        },
        StyleGuideScore {
            name: "Spring".into(),
            description: "4-space | 120-col | K&R braces".into(),
            score_pct: spring,
        },
    ]
}

fn score_kotlin(ind: IndentStyle, over80: u32, over100: u32, total: u32) -> Vec<StyleGuideScore> {
    let i4 = score_indent_4(ind);
    let l100 = score_line100(over100, total);
    let l80 = score_line80(over80, total);

    // JetBrains: 4-space, 100-col
    let jetbrains = weighted_score(&[(0.50, i4), (0.50, l100)]);
    // Android: 4-space, 100-col (same)
    let android = weighted_score(&[(0.50, i4), (0.50, l100)]);
    // Google Kotlin: 4-space, 100-col
    let google = weighted_score(&[(0.50, i4), (0.50, l80)]);

    vec![
        StyleGuideScore {
            name: "JetBrains".into(),
            description: "4-space | 100-col".into(),
            score_pct: jetbrains,
        },
        StyleGuideScore {
            name: "Android".into(),
            description: "4-space | 100-col".into(),
            score_pct: android,
        },
        StyleGuideScore {
            name: "Google Kotlin".into(),
            description: "4-space | 80-col".into(),
            score_pct: google,
        },
    ]
}

fn score_groovy(ind: IndentStyle, over80: u32, over100: u32, total: u32) -> Vec<StyleGuideScore> {
    let i4 = score_indent_4(ind);
    let l100 = score_line100(over100, total);
    let l80 = score_line80(over80, total);

    let apache = weighted_score(&[(0.50, i4), (0.50, l80)]);
    let gradle = weighted_score(&[(0.50, i4), (0.50, l100)]);

    vec![
        StyleGuideScore {
            name: "Apache Groovy".into(),
            description: "4-space | 80-col".into(),
            score_pct: apache,
        },
        StyleGuideScore {
            name: "Gradle DSL".into(),
            description: "4-space | 100-col".into(),
            score_pct: gradle,
        },
    ]
}

fn score_scala(ind: IndentStyle, over80: u32, over100: u32, total: u32) -> Vec<StyleGuideScore> {
    let i2 = score_indent_2(ind);
    let i4 = score_indent_4(ind);
    let l80 = score_line80(over80, total);
    let l100 = score_line100(over100, total);

    // Scala Style Guide: 2-space, 80-col
    let scala = weighted_score(&[(0.50, i2), (0.50, l80)]);
    // Typesafe/Lightbend: 2-space, 100-col
    let lightbend = weighted_score(&[(0.50, i2), (0.50, l100)]);
    // Spark style: 4-space, 100-col
    let spark = weighted_score(&[(0.50, i4), (0.50, l100)]);

    vec![
        StyleGuideScore {
            name: "Scala Style Guide".into(),
            description: "2-space | 80-col".into(),
            score_pct: scala,
        },
        StyleGuideScore {
            name: "Lightbend".into(),
            description: "2-space | 100-col".into(),
            score_pct: lightbend,
        },
        StyleGuideScore {
            name: "Spark".into(),
            description: "4-space | 100-col".into(),
            score_pct: spark,
        },
    ]
}
