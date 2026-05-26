// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Nima Shafie <nimzshafie@gmail.com>

//! Lexical style-guide adherence analysis for C and C++ source files.
//!
//! The analyser scans each file character-by-character and tallies observable
//! style signals: indentation type/width, brace placement, pointer-declarator
//! alignment, control-flow spacing, and line-length compliance.  These raw
//! counts are then scored against five well-known style guides (LLVM, Google,
//! Mozilla, Microsoft, WebKit) to produce per-file adherence percentages.
//!
//! All analysis is purely lexical — no AST is built — so results are
//! approximate.  The intent is to give a quick directional signal, not an
//! exact conformance report.

use serde::{Deserialize, Serialize};

// ─── Observable style signals ────────────────────────────────────────────────

/// Detected leading-whitespace style.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum IndentStyle {
    Tabs,
    Spaces2,
    Spaces4,
    Spaces8,
    Mixed,
    #[default]
    Unknown,
}

impl IndentStyle {
    pub fn display(self) -> &'static str {
        match self {
            Self::Tabs => "Tabs",
            Self::Spaces2 => "2-Space",
            Self::Spaces4 => "4-Space",
            Self::Spaces8 => "8-Space",
            Self::Mixed => "Mixed",
            Self::Unknown => "—",
        }
    }
}

/// Detected opening-brace placement style.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BraceStyle {
    /// K&R / Attach — `{` on the same line as the preceding statement.
    Attach,
    /// Allman / "Broken" — `{` on its own line.
    Allman,
    Mixed,
    #[default]
    Unknown,
}

impl BraceStyle {
    pub fn display(self) -> &'static str {
        match self {
            Self::Attach => "K&R / Attach",
            Self::Allman => "Allman",
            Self::Mixed => "Mixed",
            Self::Unknown => "—",
        }
    }
}

/// Detected pointer / reference declarator alignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PointerStyle {
    /// `Type* var` — `*` glued to the type keyword.
    WithType,
    /// `Type *var` — `*` glued to the variable name.
    WithName,
    /// `Type * var` — `*` in the middle (both sides spaced).
    Middle,
    Mixed,
    #[default]
    Unknown,
}

impl PointerStyle {
    pub fn display(self) -> &'static str {
        match self {
            Self::WithType => "Type* var",
            Self::WithName => "Type *var",
            Self::Middle => "Type * var",
            Self::Mixed => "Mixed",
            Self::Unknown => "—",
        }
    }
}

// ─── Output types ─────────────────────────────────────────────────────────────

/// Adherence percentage for one named style guide.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StyleGuideScore {
    /// Short guide name, e.g. `"LLVM"`, `"Google"`.
    pub name: String,
    /// Key characteristics used in scoring.
    pub description: String,
    /// Computed adherence, 0–100.
    pub score_pct: u8,
}

/// Full lexical style analysis result for a single C/C++ file.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CppStyleAnalysis {
    // ── classified styles ──────────────────────────────────────────────────
    pub indent_style: IndentStyle,
    pub brace_style: BraceStyle,
    pub pointer_style: PointerStyle,

    // ── raw signal counts ─────────────────────────────────────────────────
    pub tab_indented_lines: u32,
    pub space2_indented_lines: u32,
    pub space4_indented_lines: u32,
    pub allman_braces: u32,
    pub attach_braces: u32,
    pub ptr_with_type: u32,
    pub ptr_with_name: u32,
    pub ptr_middle: u32,
    pub space_before_paren: u32,
    pub no_space_before_paren: u32,
    pub lines_over_80: u32,
    pub lines_over_100: u32,
    pub max_line_length: u32,
    pub total_lines: u32,
    pub has_pragma_once: bool,

    // ── style-guide scores ────────────────────────────────────────────────
    pub guide_scores: Vec<StyleGuideScore>,
    /// Name of the guide with the highest adherence score.
    pub dominant_guide: String,
    /// Adherence percentage of the dominant guide (0–100).
    pub dominant_score_pct: u8,
}

// ─── Public entry point ───────────────────────────────────────────────────────

/// Analyse `text` for C/C++ coding-style signals and return a scored result.
#[must_use]
pub fn analyze_cpp_style(text: &str) -> CppStyleAnalysis {
    let mut tab_lines = 0u32;
    let mut sp2_lines = 0u32;
    let mut sp4_lines = 0u32;
    let mut allman = 0u32;
    let mut attach = 0u32;
    let mut ptr_type = 0u32;
    let mut ptr_name = 0u32;
    let mut ptr_mid = 0u32;
    let mut space_paren = 0u32;
    let mut nospace_paren = 0u32;
    let mut over_80 = 0u32;
    let mut over_100 = 0u32;
    let mut max_len = 0u32;
    let mut pragma_once = false;
    let mut total = 0u32;

    let lines: Vec<&str> = text.lines().collect();

    for line in &lines {
        total += 1;

        // Line length (byte count — acceptable approximation for ASCII-dominant code)
        let len = line.len() as u32;
        if len > max_len {
            max_len = len;
        }
        if len > 80 {
            over_80 += 1;
        }
        if len > 100 {
            over_100 += 1;
        }

        let trimmed = line.trim();

        // #pragma once
        if trimmed == "#pragma once" {
            pragma_once = true;
        }

        // ── Indentation ──────────────────────────────────────────────────
        scan_indent(line, &mut tab_lines, &mut sp2_lines, &mut sp4_lines);

        // ── Brace placement ──────────────────────────────────────────────
        scan_braces(trimmed, &mut allman, &mut attach);

        // ── Control-flow spacing ─────────────────────────────────────────
        scan_paren_spacing(trimmed, &mut space_paren, &mut nospace_paren);

        // ── Pointer/reference declarator alignment ────────────────────────
        scan_pointer_style(trimmed, &mut ptr_type, &mut ptr_name, &mut ptr_mid);
    }

    let indent_style = classify_indent(tab_lines, sp2_lines, sp4_lines);
    let brace_style = classify_braces(allman, attach);
    let pointer_style = classify_pointers(ptr_type, ptr_name, ptr_mid);

    let guide_scores = compute_guide_scores(
        indent_style,
        brace_style,
        pointer_style,
        over_80,
        over_100,
        total,
        space_paren,
        nospace_paren,
    );

    let (dominant_guide, dominant_score_pct) = guide_scores
        .iter()
        .max_by_key(|s| s.score_pct)
        .map(|s| (s.name.clone(), s.score_pct))
        .unwrap_or_else(|| (String::from("Unknown"), 0));

    CppStyleAnalysis {
        indent_style,
        brace_style,
        pointer_style,
        tab_indented_lines: tab_lines,
        space2_indented_lines: sp2_lines,
        space4_indented_lines: sp4_lines,
        allman_braces: allman,
        attach_braces: attach,
        ptr_with_type: ptr_type,
        ptr_with_name: ptr_name,
        ptr_middle: ptr_mid,
        space_before_paren: space_paren,
        no_space_before_paren: nospace_paren,
        lines_over_80: over_80,
        lines_over_100: over_100,
        max_line_length: max_len,
        total_lines: total,
        has_pragma_once: pragma_once,
        guide_scores,
        dominant_guide,
        dominant_score_pct,
    }
}

// ─── Signal scanners ──────────────────────────────────────────────────────────

fn scan_indent(line: &str, tabs: &mut u32, sp2: &mut u32, sp4: &mut u32) {
    let first = match line.chars().next() {
        Some(c) => c,
        None => return,
    };
    if first == '\t' {
        *tabs += 1;
        return;
    }
    if first != ' ' {
        return; // non-blank, non-indented line — skip
    }
    let leading = line.bytes().take_while(|&b| b == b' ').count();
    if leading == 0 {
        return;
    }
    // Classify by the base indent unit inferred from the count.
    // 4-space code will have lines indented 4, 8, 12 … spaces (all divisible by 4).
    // 2-space code will have lines indented 2, 4, 6 … spaces.
    // Lines at depth > 1 in 4-space code are also divisible by 4 so they count for sp4.
    // Lines at depth 1 in 2-space code show as 2, which is only divisible by 2 (not 4).
    if leading % 4 == 0 {
        *sp4 += 1;
    } else if leading % 2 == 0 {
        *sp2 += 1;
    }
    // Odd leading-space counts are usually alignment padding — ignore.
}

fn scan_braces(trimmed: &str, allman: &mut u32, attach: &mut u32) {
    // Allman: the entire (trimmed) line is just `{`
    if trimmed == "{" {
        *allman += 1;
        return;
    }
    // Attach: line ends with ` {` and has content before it that suggests
    // a control/function/class head.
    if trimmed.ends_with(" {") || trimmed.ends_with("\t{") {
        let head = &trimmed[..trimmed.len() - 2];
        if !head.is_empty() && looks_like_block_head(head) {
            *attach += 1;
        }
    }
}

/// Returns `true` when `head` (the text before a trailing ` {`) looks like it
/// opens a block rather than being an expression assignment or initialiser.
fn looks_like_block_head(head: &str) -> bool {
    let head = head.trim_end();
    // ends with `)` (function/control-flow), `else`, `try`, `do`, `noexcept`, etc.
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
    // class / struct / enum / namespace / extern "C" blocks
    for kw in &["class ", "struct ", "enum ", "namespace ", "extern "] {
        if head.contains(kw) {
            return true;
        }
    }
    false
}

fn scan_paren_spacing(trimmed: &str, with_space: &mut u32, no_space: &mut u32) {
    static WITH: &[&str] = &[
        "if (",
        "} else if (",
        "while (",
        "for (",
        "switch (",
        "catch (",
    ];
    static WITHOUT: &[&str] = &["if(", "while(", "for(", "switch(", "catch("];

    let mut found_with = false;
    let mut found_without = false;

    for kw in WITH {
        if trimmed.starts_with(kw) || trimmed.contains(kw) {
            found_with = true;
            break;
        }
    }
    for kw in WITHOUT {
        if trimmed.starts_with(kw) || trimmed.contains(kw) {
            found_without = true;
            break;
        }
    }

    if found_with {
        *with_space += 1;
    }
    if found_without {
        *no_space += 1;
    }
}

/// Scan a single (trimmed) line for pointer/reference declarator patterns.
///
/// We look for `*` and `&` characters whose neighbourhood suggests a
/// type-qualifier context rather than a dereference or multiplication.
fn scan_pointer_style(trimmed: &str, with_type: &mut u32, with_name: &mut u32, _middle: &mut u32) {
    // Skip comment lines and preprocessor directives — they produce false positives.
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
            // Skip doubled `**` / `&&`
            if i + 1 < len && (bytes[i + 1] == b'*' || bytes[i + 1] == b'&') {
                i += 2;
                continue;
            }
            // Skip compound-assignment tokens `*=` `&=` `->` `/*` `*/`
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

            // `Type*var` or `Type* var` → with_type
            if pre_word && (post_word || post_space) {
                *with_type += 1;
            }
            // ` *var` → with_name
            else if pre_space && post_word {
                *with_name += 1;
            }
            // ` * ` → middle (we tally this but don't increment _middle to avoid
            // false positives from multiplication; the classify_pointers function
            // treats "unknown" neutrally)
        }

        i += 1;
    }
}

// ─── Classifiers ─────────────────────────────────────────────────────────────

fn classify_indent(tabs: u32, sp2: u32, sp4: u32) -> IndentStyle {
    let total = tabs + sp2 + sp4;
    if total == 0 {
        return IndentStyle::Unknown;
    }

    let tab_pct = tabs as f32 / total as f32;
    let s2_pct = sp2 as f32 / total as f32;
    let s4_pct = sp4 as f32 / total as f32;

    if tab_pct >= 0.60 {
        return IndentStyle::Tabs;
    }
    if s4_pct >= 0.60 {
        return IndentStyle::Spaces4;
    }
    if s2_pct >= 0.60 {
        return IndentStyle::Spaces2;
    }

    // Disambiguate 4-space vs 2-space when both are present.
    // In a 4-space codebase, deeply-nested lines appear as sp4 while 2-level lines
    // also appear in sp4; sp2 only shows up for 1-level nesting in a 2-space codebase.
    // Heuristic: if sp4 > sp2*2, the base unit is likely 4 spaces.
    if sp4 > sp2 * 2 && sp4 > tabs {
        return IndentStyle::Spaces4;
    }
    if sp2 > sp4 && sp2 > tabs {
        return IndentStyle::Spaces2;
    }

    IndentStyle::Mixed
}

fn classify_braces(allman: u32, attach: u32) -> BraceStyle {
    let total = allman + attach;
    if total == 0 {
        return BraceStyle::Unknown;
    }
    let a_pct = allman as f32 / total as f32;
    let k_pct = attach as f32 / total as f32;
    if a_pct >= 0.65 {
        BraceStyle::Allman
    } else if k_pct >= 0.65 {
        BraceStyle::Attach
    } else {
        BraceStyle::Mixed
    }
}

fn classify_pointers(with_type: u32, with_name: u32, _middle: u32) -> PointerStyle {
    let total = with_type + with_name;
    if total == 0 {
        return PointerStyle::Unknown;
    }
    let t = with_type as f32 / total as f32;
    let n = with_name as f32 / total as f32;
    if t >= 0.65 {
        PointerStyle::WithType
    } else if n >= 0.65 {
        PointerStyle::WithName
    } else {
        PointerStyle::Mixed
    }
}

// ─── Scoring helpers ─────────────────────────────────────────────────────────

/// Compute a 0–100 score from weighted feature values.
/// Each pair is (weight, value) where value is in [0.0, 1.0].
fn weighted_score(features: &[(f32, f32)]) -> u8 {
    let s: f32 = features.iter().map(|(w, v)| w * v).sum();
    (s * 100.0).round().clamp(0.0, 100.0) as u8
}

fn score_indent_2(s: IndentStyle) -> f32 {
    match s {
        IndentStyle::Spaces2 => 1.0,
        IndentStyle::Mixed => 0.35,
        _ => 0.05,
    }
}

fn score_indent_4(s: IndentStyle) -> f32 {
    match s {
        IndentStyle::Spaces4 => 1.0,
        IndentStyle::Mixed => 0.35,
        _ => 0.05,
    }
}

/// Score line-length compliance for an 80-column limit.
fn score_line80(over: u32, total: u32) -> f32 {
    if total == 0 {
        return 1.0;
    }
    let pct = over as f32 / total as f32;
    if pct < 0.02 {
        1.00
    } else if pct < 0.08 {
        0.75
    } else if pct < 0.20 {
        0.45
    } else if pct < 0.40 {
        0.20
    } else {
        0.05
    }
}

/// Score line-length compliance for a 100-column limit.
fn score_line100(over: u32, total: u32) -> f32 {
    if total == 0 {
        return 1.0;
    }
    let pct = over as f32 / total as f32;
    if pct < 0.03 {
        1.00
    } else if pct < 0.10 {
        0.75
    } else if pct < 0.25 {
        0.45
    } else {
        0.10
    }
}

fn score_attach(s: BraceStyle) -> f32 {
    match s {
        BraceStyle::Attach => 1.0,
        BraceStyle::Mixed => 0.40,
        BraceStyle::Allman => 0.05,
        BraceStyle::Unknown => 0.50,
    }
}

fn score_allman(s: BraceStyle) -> f32 {
    match s {
        BraceStyle::Allman => 1.0,
        BraceStyle::Mixed => 0.40,
        BraceStyle::Attach => 0.05,
        BraceStyle::Unknown => 0.50,
    }
}

fn score_ptr(detected: PointerStyle, expected: PointerStyle) -> f32 {
    if detected == expected {
        return 1.0;
    }
    match detected {
        PointerStyle::Mixed => 0.40,
        PointerStyle::Unknown => 0.50,
        _ => 0.05,
    }
}

fn score_space_paren(with_space: u32, no_space: u32) -> f32 {
    let total = with_space + no_space;
    if total == 0 {
        return 0.50;
    }
    with_space as f32 / total as f32
}

// ─── Guide score table ────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn compute_guide_scores(
    indent: IndentStyle,
    braces: BraceStyle,
    ptrs: PointerStyle,
    over_80: u32,
    over_100: u32,
    total: u32,
    space_paren: u32,
    no_space_paren: u32,
) -> Vec<StyleGuideScore> {
    let l80 = score_line80(over_80, total);
    let l100 = score_line100(over_100, total);
    let att = score_attach(braces);
    let all = score_allman(braces);
    let pt = score_ptr(ptrs, PointerStyle::WithType);
    let pn = score_ptr(ptrs, PointerStyle::WithName);
    let sp = score_space_paren(space_paren, no_space_paren);

    // LLVM: 2-space, 80-col, K&R braces, `*var` pointer, space-before-paren
    let llvm = weighted_score(&[
        (0.28, score_indent_2(indent)),
        (0.20, l80),
        (0.24, att),
        (0.15, pn),
        (0.13, sp),
    ]);

    // Google: 2-space, 80-col, K&R braces, `Type*` pointer, space-before-paren
    let google = weighted_score(&[
        (0.25, score_indent_2(indent)),
        (0.20, l80),
        (0.25, att),
        (0.18, pt),
        (0.12, sp),
    ]);

    // Mozilla: 4-space, 80-col, mixed braces (partial credit for both), `Type*`
    let moz_brace = match braces {
        BraceStyle::Attach => 0.60,
        BraceStyle::Allman => 0.45,
        BraceStyle::Mixed => 0.80,
        BraceStyle::Unknown => 0.50,
    };
    let mozilla = weighted_score(&[
        (0.28, score_indent_4(indent)),
        (0.20, l80),
        (0.22, moz_brace),
        (0.18, pt),
        (0.12, sp),
    ]);

    // Microsoft: 4-space, Allman braces, lenient line length (100-col), `*var`
    let microsoft = weighted_score(&[
        (0.32, score_indent_4(indent)),
        (0.36, all),
        (0.16, l100),
        (0.16, pn),
    ]);

    // WebKit: 4-space, 80-col, K&R braces, `Type*`, space-before-paren
    let webkit = weighted_score(&[
        (0.28, score_indent_4(indent)),
        (0.20, l80),
        (0.24, att),
        (0.16, pt),
        (0.12, sp),
    ]);

    vec![
        StyleGuideScore {
            name: "LLVM".to_string(),
            description: "2-space indent \u{00b7} 80-col \u{00b7} K&R braces \u{00b7} *var pointer"
                .to_string(),
            score_pct: llvm,
        },
        StyleGuideScore {
            name: "Google".to_string(),
            description:
                "2-space indent \u{00b7} 80-col \u{00b7} K&R braces \u{00b7} Type* pointer"
                    .to_string(),
            score_pct: google,
        },
        StyleGuideScore {
            name: "Mozilla".to_string(),
            description:
                "4-space indent \u{00b7} 80-col \u{00b7} mixed braces \u{00b7} Type* pointer"
                    .to_string(),
            score_pct: mozilla,
        },
        StyleGuideScore {
            name: "Microsoft".to_string(),
            description:
                "4-space indent \u{00b7} Allman braces \u{00b7} 100-col \u{00b7} *var pointer"
                    .to_string(),
            score_pct: microsoft,
        },
        StyleGuideScore {
            name: "WebKit".to_string(),
            description:
                "4-space indent \u{00b7} 80-col \u{00b7} K&R braces \u{00b7} Type* pointer"
                    .to_string(),
            score_pct: webkit,
        },
    ]
}
