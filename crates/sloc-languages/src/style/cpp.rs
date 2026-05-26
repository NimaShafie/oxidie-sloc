// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Nima Shafie <nimzshafie@gmail.com>

//! Style-guide analysis for C, C++, and Objective-C.
//! Guides: LLVM, Google, Mozilla, Microsoft, WebKit.

use super::common::*;

/// Brace placement.
#[derive(Clone, Copy, PartialEq, Eq)]
enum BraceStyle {
    Attach,
    Allman,
    Mixed,
    Unknown,
}

/// Pointer/reference declarator alignment.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PointerStyle {
    WithType,
    WithName,
    Mixed,
    Unknown,
}

pub fn analyze(text: &str) -> StyleAnalysis {
    let lines: Vec<&str> = text.lines().collect();
    let mut tabs = 0u32;
    let mut sp2 = 0u32;
    let mut sp4 = 0u32;
    let mut allman = 0u32;
    let mut attach = 0u32;
    let mut ptr_type = 0u32;
    let mut ptr_name = 0u32;
    let mut space_paren = 0u32;
    let mut nospace_paren = 0u32;
    let mut pragma_once = false;
    let mut total = 0u32;

    let over80 = count_over(&lines, 80);
    let over100 = count_over(&lines, 100);
    let over120 = count_over(&lines, 120);
    let max_len = lines.iter().map(|l| l.len() as u32).max().unwrap_or(0);

    for line in &lines {
        total += 1;
        let trimmed = line.trim();
        if trimmed == "#pragma once" {
            pragma_once = true;
        }
        scan_indent(line, &mut tabs, &mut sp2, &mut sp4);
        scan_braces(trimmed, &mut allman, &mut attach);
        scan_paren(trimmed, &mut space_paren, &mut nospace_paren);
        scan_ptr(trimmed, &mut ptr_type, &mut ptr_name);
    }

    let indent = classify_indent(tabs, sp2, sp4);
    let brace = classify_brace(allman, attach);
    let ptr = classify_ptr(ptr_type, ptr_name);

    let guides = score_guides(
        indent,
        brace,
        ptr,
        over80,
        over100,
        total,
        space_paren,
        nospace_paren,
    );
    let (dominant, dominant_pct) = top_guide(&guides);

    let mut signals = vec![
        StyleSignal {
            name: "Brace Style".into(),
            value: brace_display(brace).into(),
        },
        StyleSignal {
            name: "Pointer Style".into(),
            value: ptr_display(ptr).into(),
        },
        StyleSignal {
            name: "Space Before Paren".into(),
            value: paren_display(space_paren, nospace_paren).into(),
        },
    ];
    if pragma_once {
        signals.push(StyleSignal {
            name: "Include Guard".into(),
            value: "#pragma once".into(),
        });
    }

    StyleAnalysis {
        language_family: "C / C++".into(),
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

fn scan_braces(trimmed: &str, allman: &mut u32, attach: &mut u32) {
    if trimmed == "{" {
        *allman += 1;
        return;
    }
    if trimmed.ends_with(" {") || trimmed.ends_with("\t{") {
        let head = trimmed[..trimmed.len() - 2].trim_end();
        if !head.is_empty() && is_block_head(head) {
            *attach += 1;
        }
    }
}

fn is_block_head(head: &str) -> bool {
    if head.ends_with(')')
        || head.ends_with("else")
        || head.ends_with("try")
        || head.ends_with("do")
        || head.ends_with("noexcept")
        || head.ends_with("const")
        || head.ends_with("override")
    {
        return true;
    }
    for kw in &["class ", "struct ", "enum ", "namespace ", "extern "] {
        if head.contains(kw) {
            return true;
        }
    }
    false
}

fn scan_paren(trimmed: &str, with_sp: &mut u32, no_sp: &mut u32) {
    static W: &[&str] = &[
        "if (",
        "} else if (",
        "while (",
        "for (",
        "switch (",
        "catch (",
    ];
    static N: &[&str] = &["if(", "while(", "for(", "switch(", "catch("];
    if W.iter().any(|kw| trimmed.contains(kw)) {
        *with_sp += 1;
    }
    if N.iter().any(|kw| trimmed.contains(kw)) {
        *no_sp += 1;
    }
}

fn scan_ptr(trimmed: &str, with_type: &mut u32, with_name: &mut u32) {
    if trimmed.starts_with("//")
        || trimmed.starts_with('*')
        || trimmed.starts_with("/*")
        || trimmed.starts_with('#')
    {
        return;
    }
    let bytes = trimmed.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    let mut in_str = false;
    let mut in_char = false;
    while i < len {
        let b = bytes[i];
        if b == b'"' && !in_char && (i == 0 || bytes[i - 1] != b'\\') {
            in_str = !in_str;
        }
        if b == b'\'' && !in_str && (i == 0 || bytes[i - 1] != b'\\') {
            in_char = !in_char;
        }
        if in_str || in_char {
            i += 1;
            continue;
        }
        if b == b'*' || b == b'&' {
            if i + 1 < len && (bytes[i + 1] == b'*' || bytes[i + 1] == b'&') {
                i += 2;
                continue;
            }
            if i + 1 < len && (bytes[i + 1] == b'=' || bytes[i + 1] == b'/' || bytes[i + 1] == b'>')
            {
                i += 2;
                continue;
            }
            if i > 0 && (bytes[i - 1] == b'=' || bytes[i - 1] == b'/' || bytes[i - 1] == b'-') {
                i += 1;
                continue;
            }
            let pre_word = i > 0 && (bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_');
            let pre_space = i > 0 && bytes[i - 1] == b' ';
            let post_word =
                i + 1 < len && (bytes[i + 1].is_ascii_alphanumeric() || bytes[i + 1] == b'_');
            let post_space = i + 1 < len && bytes[i + 1] == b' ';
            if pre_word && (post_word || post_space) {
                *with_type += 1;
            } else if pre_space && post_word {
                *with_name += 1;
            }
        }
        i += 1;
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

fn classify_ptr(with_type: u32, with_name: u32) -> PointerStyle {
    let t = with_type + with_name;
    if t == 0 {
        return PointerStyle::Unknown;
    }
    let tp = with_type as f32 / t as f32;
    let np = with_name as f32 / t as f32;
    if tp >= 0.65 {
        PointerStyle::WithType
    } else if np >= 0.65 {
        PointerStyle::WithName
    } else {
        PointerStyle::Mixed
    }
}

fn brace_display(s: BraceStyle) -> &'static str {
    match s {
        BraceStyle::Attach => "K&R / Attach",
        BraceStyle::Allman => "Allman",
        BraceStyle::Mixed => "Mixed",
        BraceStyle::Unknown => "\u{2014}",
    }
}

fn ptr_display(s: PointerStyle) -> &'static str {
    match s {
        PointerStyle::WithType => "Type* var",
        PointerStyle::WithName => "Type *var",
        PointerStyle::Mixed => "Mixed",
        PointerStyle::Unknown => "\u{2014}",
    }
}

fn paren_display(with_sp: u32, no_sp: u32) -> &'static str {
    let t = with_sp + no_sp;
    if t == 0 {
        return "\u{2014}";
    }
    if with_sp as f32 / t as f32 >= 0.70 {
        "space before '('"
    } else {
        "no space before '('"
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

fn score_allman(b: BraceStyle) -> f32 {
    match b {
        BraceStyle::Allman => 1.0,
        BraceStyle::Mixed => 0.40,
        BraceStyle::Attach => 0.05,
        BraceStyle::Unknown => 0.50,
    }
}

fn score_ptr_type(p: PointerStyle) -> f32 {
    match p {
        PointerStyle::WithType => 1.0,
        PointerStyle::Mixed => 0.40,
        PointerStyle::Unknown => 0.50,
        _ => 0.05,
    }
}

fn score_ptr_name(p: PointerStyle) -> f32 {
    match p {
        PointerStyle::WithName => 1.0,
        PointerStyle::Mixed => 0.40,
        PointerStyle::Unknown => 0.50,
        _ => 0.05,
    }
}

fn score_sp(with: u32, no: u32) -> f32 {
    let t = with + no;
    if t == 0 {
        0.50
    } else {
        with as f32 / t as f32
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
fn score_guides(
    ind: IndentStyle,
    brace: BraceStyle,
    ptr: PointerStyle,
    over80: u32,
    over100: u32,
    total: u32,
    sp: u32,
    no_sp: u32,
) -> Vec<StyleGuideScore> {
    let l80 = score_line80(over80, total);
    let l100 = score_line100(over100, total);
    let att = score_attach(brace);
    let all = score_allman(brace);
    let pt = score_ptr_type(ptr);
    let pn = score_ptr_name(ptr);
    let spc = score_sp(sp, no_sp);

    let llvm = weighted_score(&[
        (0.28, score_indent_2(ind)),
        (0.20, l80),
        (0.24, att),
        (0.15, pn),
        (0.13, spc),
    ]);
    let google = weighted_score(&[
        (0.25, score_indent_2(ind)),
        (0.20, l80),
        (0.25, att),
        (0.18, pt),
        (0.12, spc),
    ]);
    let moz_brace = match brace {
        BraceStyle::Attach => 0.60,
        BraceStyle::Allman => 0.45,
        BraceStyle::Mixed => 0.80,
        BraceStyle::Unknown => 0.50,
    };
    let mozilla = weighted_score(&[
        (0.28, score_indent_4(ind)),
        (0.20, l80),
        (0.22, moz_brace),
        (0.18, pt),
        (0.12, spc),
    ]);
    let microsoft = weighted_score(&[
        (0.32, score_indent_4(ind)),
        (0.36, all),
        (0.16, l100),
        (0.16, pn),
    ]);
    let webkit = weighted_score(&[
        (0.28, score_indent_4(ind)),
        (0.20, l80),
        (0.24, att),
        (0.16, pt),
        (0.12, spc),
    ]);

    vec![
        StyleGuideScore {
            name: "LLVM".into(),
            description: "2-space | 80-col | K&R | *var".into(),
            score_pct: llvm,
        },
        StyleGuideScore {
            name: "Google".into(),
            description: "2-space | 80-col | K&R | Type*".into(),
            score_pct: google,
        },
        StyleGuideScore {
            name: "Mozilla".into(),
            description: "4-space | 80-col | mixed braces | Type*".into(),
            score_pct: mozilla,
        },
        StyleGuideScore {
            name: "Microsoft".into(),
            description: "4-space | Allman | 100-col | *var".into(),
            score_pct: microsoft,
        },
        StyleGuideScore {
            name: "WebKit".into(),
            description: "4-space | 80-col | K&R | Type*".into(),
            score_pct: webkit,
        },
    ]
}
