// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Nima Shafie <nimzshafie@gmail.com>

//! Style-guide analysis for C, C++, and Objective-C.
//! Guides: LLVM, Google, Mozilla, Microsoft, `WebKit`.

use super::common::{
    classify_brace, classify_indent, scan_base_metrics, score_allman_brace, score_attach_brace,
    score_indent_2, score_indent_4, score_line100, score_line80, weighted_score, BraceStyle,
    IndentStyle, StyleAnalysis, StyleGuideScore, StyleSignal,
};

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
    let m = scan_base_metrics(&lines);

    let mut allman = 0u32;
    let mut attach = 0u32;
    let mut ptr_type = 0u32;
    let mut ptr_name = 0u32;
    let mut space_paren = 0u32;
    let mut nospace_paren = 0u32;
    let mut pragma_once = false;

    for line in &lines {
        let trimmed = line.trim();
        if trimmed == "#pragma once" {
            pragma_once = true;
        }
        scan_braces(trimmed, &mut allman, &mut attach);
        scan_paren(trimmed, &mut space_paren, &mut nospace_paren);
        scan_ptr(trimmed, &mut ptr_type, &mut ptr_name);
    }

    let indent = classify_indent(m.tabs, m.sp2, m.sp4);
    let brace = classify_brace(allman, attach);
    let ptr = classify_ptr(ptr_type, ptr_name);

    let guides = score_guides(
        indent,
        brace,
        ptr,
        m.over80,
        m.over100,
        m.total,
        space_paren,
        nospace_paren,
    );

    let mut signals = vec![
        StyleSignal {
            name: "Brace Style".into(),
            value: brace.display().into(),
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

    StyleAnalysis::assemble("C / C++", indent, &m, signals, guides)
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

// ─── Pointer-style scanner (cognitive complexity ≤ 15) ────────────────────────

enum PtrToken {
    Skip2,
    Skip1,
    WithType,
    WithName,
    Unclassified,
}

/// Toggle string/char literal state for byte `b` at index `i`; returns true when inside a literal.
fn step_quote_state(b: u8, i: usize, bytes: &[u8], in_str: &mut bool, in_char: &mut bool) -> bool {
    let not_escaped = i == 0 || bytes[i - 1] != b'\\';
    if b == b'"' && !*in_char && not_escaped {
        *in_str = !*in_str;
    }
    if b == b'\'' && !*in_str && not_escaped {
        *in_char = !*in_char;
    }
    *in_str || *in_char
}

/// Classify a `*` or `&` token at position `i` without nested branching.
fn classify_ptr_token(bytes: &[u8], i: usize) -> PtrToken {
    let len = bytes.len();
    let nx = (i + 1 < len).then(|| bytes[i + 1]);
    let pv = i.checked_sub(1).map(|p| bytes[p]);
    if matches!(nx, Some(b'*' | b'&' | b'=' | b'/' | b'>')) {
        return PtrToken::Skip2;
    }
    if matches!(pv, Some(b'=' | b'/' | b'-')) {
        return PtrToken::Skip1;
    }
    let pre_word = pv.is_some_and(|p| p.is_ascii_alphanumeric() || p == b'_');
    let pre_space = pv == Some(b' ');
    let post_word = nx.is_some_and(|n| n.is_ascii_alphanumeric() || n == b'_');
    let post_space = nx == Some(b' ');
    if pre_word && (post_word || post_space) {
        PtrToken::WithType
    } else if pre_space && post_word {
        PtrToken::WithName
    } else {
        PtrToken::Unclassified
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
        if step_quote_state(b, i, bytes, &mut in_str, &mut in_char) {
            i += 1;
            continue;
        }
        if b == b'*' || b == b'&' {
            match classify_ptr_token(bytes, i) {
                PtrToken::Skip2 => {
                    i += 2;
                    continue;
                }
                PtrToken::WithType => *with_type += 1,
                PtrToken::WithName => *with_name += 1,
                PtrToken::Skip1 | PtrToken::Unclassified => {}
            }
        }
        i += 1;
    }
}

// ─── Classifiers ──────────────────────────────────────────────────────────────

fn classify_ptr(with_type: u32, with_name: u32) -> PointerStyle {
    let t = with_type + with_name;
    if t == 0 {
        return PointerStyle::Unknown;
    }
    let tp = f64::from(with_type) / f64::from(t);
    let np = f64::from(with_name) / f64::from(t);
    if tp >= 0.65 {
        PointerStyle::WithType
    } else if np >= 0.65 {
        PointerStyle::WithName
    } else {
        PointerStyle::Mixed
    }
}

#[must_use]
const fn ptr_display(s: PointerStyle) -> &'static str {
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
    if f64::from(with_sp) / f64::from(t) >= 0.70 {
        "space before '('"
    } else {
        "no space before '('"
    }
}

#[must_use]
const fn score_ptr_type(p: PointerStyle) -> f32 {
    match p {
        PointerStyle::WithType => 1.0,
        PointerStyle::Mixed => 0.40,
        PointerStyle::Unknown => 0.50,
        PointerStyle::WithName => 0.05,
    }
}

#[must_use]
const fn score_ptr_name(p: PointerStyle) -> f32 {
    match p {
        PointerStyle::WithName => 1.0,
        PointerStyle::Mixed => 0.40,
        PointerStyle::Unknown => 0.50,
        PointerStyle::WithType => 0.05,
    }
}

#[allow(clippy::cast_precision_loss)] // counts bounded well within f32 precision
fn score_sp(with: u32, no: u32) -> f32 {
    let t = with + no;
    if t == 0 {
        0.50
    } else {
        with as f32 / t as f32
    }
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
    let att = score_attach_brace(brace);
    let all = score_allman_brace(brace);
    let pt = score_ptr_type(ptr);
    let pn = score_ptr_name(ptr);
    let spc = score_sp(sp, no_sp);

    let moz_brace = match brace {
        BraceStyle::Attach => 0.60,
        BraceStyle::Allman => 0.45,
        BraceStyle::Mixed => 0.80,
        BraceStyle::Unknown => 0.50,
    };

    vec![
        StyleGuideScore {
            name: "LLVM".into(),
            description: "2-space | 80-col | K&R | *var".into(),
            score_pct: weighted_score(&[
                (0.28, score_indent_2(ind)),
                (0.20, l80),
                (0.24, att),
                (0.15, pn),
                (0.13, spc),
            ]),
        },
        StyleGuideScore {
            name: "Google".into(),
            description: "2-space | 80-col | K&R | Type*".into(),
            score_pct: weighted_score(&[
                (0.25, score_indent_2(ind)),
                (0.20, l80),
                (0.25, att),
                (0.18, pt),
                (0.12, spc),
            ]),
        },
        StyleGuideScore {
            name: "Mozilla".into(),
            description: "4-space | 80-col | mixed braces | Type*".into(),
            score_pct: weighted_score(&[
                (0.28, score_indent_4(ind)),
                (0.20, l80),
                (0.22, moz_brace),
                (0.18, pt),
                (0.12, spc),
            ]),
        },
        StyleGuideScore {
            name: "Microsoft".into(),
            description: "4-space | Allman | 100-col | *var".into(),
            score_pct: weighted_score(&[
                (0.32, score_indent_4(ind)),
                (0.36, all),
                (0.16, l100),
                (0.16, pn),
            ]),
        },
        StyleGuideScore {
            name: "WebKit".into(),
            description: "4-space | 80-col | K&R | Type*".into(),
            score_pct: weighted_score(&[
                (0.28, score_indent_4(ind)),
                (0.20, l80),
                (0.24, att),
                (0.16, pt),
                (0.12, spc),
            ]),
        },
    ]
}
