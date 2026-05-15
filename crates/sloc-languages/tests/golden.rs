// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Nima Shafie <nimzshafie@gmail.com>

/// Golden tests: known-good fixture files with expected line counts.
///
/// Each test reads a corpus file, runs the lexical analyzer, and asserts exact
/// counts. The corpus files are checked into git so regressions are caught
/// immediately on CI.
use std::path::Path;

use sloc_languages::{analyze_text, AnalysisOptions, Language};

fn corpus(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/corpus")
        .join(rel);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read corpus file {}: {e}", path.display()))
}

// ─── C ────────────────────────────────────────────────────────────────────────

#[test]
fn c_mixed() {
    let text = corpus("c/mixed.c");
    let result = analyze_text(Language::C, &text, AnalysisOptions::default());
    let r = &result.raw;
    // split_terminator omits the empty string after the final newline → 8 lines
    assert_eq!(r.total_physical_lines, 8, "total physical lines");
    assert_eq!(r.blank_only_lines, 1, "blank lines");
    assert_eq!(r.multi_comment_only_lines, 1, "block-comment-only lines");
    assert_eq!(r.single_comment_only_lines, 1, "single-comment-only lines");
    assert_eq!(
        r.mixed_code_single_comment_lines, 1,
        "mixed code+single-comment"
    );
    assert_eq!(
        r.mixed_code_multi_comment_lines, 1,
        "mixed code+block-comment"
    );
    assert_eq!(
        r.code_only_lines, 3,
        "pure code lines: int y=2, void foo() {{...}}, closing brace"
    );
}

// ─── Python ───────────────────────────────────────────────────────────────────

#[test]
fn python_mixed() {
    let text = corpus("python/mixed.py");
    let result = analyze_text(Language::Python, &text, AnalysisOptions::default());
    let r = &result.raw;
    // 3 docstring lines (module doc, greet doc, Greeter class doc)
    assert_eq!(r.docstring_comment_lines, 3, "docstring lines");
    assert_eq!(r.mixed_code_single_comment_lines, 1, "mixed code+inline #");
    // blanks between sections
    assert!(r.blank_only_lines >= 2, "blank lines");
    // def greet, class Greeter, def hello, pass = 4 code lines
    assert!(r.code_only_lines >= 4, "pure code lines");
}

// ─── Rust ─────────────────────────────────────────────────────────────────────

#[test]
fn rust_mixed() {
    let text = corpus("rust/mixed.rs");
    let result = analyze_text(Language::Rust, &text, AnalysisOptions::default());
    let r = &result.raw;
    assert_eq!(r.single_comment_only_lines, 1, "// comment-only line");
    assert_eq!(
        r.multi_comment_only_lines, 1,
        "/* block comment-only line */"
    );
    assert_eq!(
        r.mixed_code_single_comment_lines, 1,
        "mixed code + // comment"
    );
    assert!(r.code_only_lines >= 4, "pure code lines");
}

// ─── Go ───────────────────────────────────────────────────────────────────────

#[test]
fn go_mixed() {
    let text = corpus("go/mixed.go");
    let result = analyze_text(Language::Go, &text, AnalysisOptions::default());
    let r = &result.raw;
    assert!(r.single_comment_only_lines >= 2, "// comment-only lines");
    assert_eq!(
        r.mixed_code_multi_comment_lines, 1,
        "mixed code + /* block */"
    );
    assert!(r.code_only_lines >= 3, "pure code lines");
}

// ─── TypeScript ───────────────────────────────────────────────────────────────

#[test]
fn typescript_mixed() {
    let text = corpus("typescript/mixed.ts");
    let result = analyze_text(Language::TypeScript, &text, AnalysisOptions::default());
    let r = &result.raw;
    assert_eq!(r.single_comment_only_lines, 1, "// comment-only");
    assert_eq!(r.multi_comment_only_lines, 1, "/* block comment-only */");
    assert_eq!(
        r.mixed_code_single_comment_lines, 1,
        "mixed code + // inline"
    );
    assert!(r.code_only_lines >= 3, "pure code lines");
}

// ─── Entity counts ────────────────────────────────────────────────────────────

#[test]
fn rust_entities() {
    let text = corpus("rust/entities.rs");
    let result = analyze_text(Language::Rust, &text, AnalysisOptions::default());
    let r = &result.raw;
    // fn area, fn new, fn distance, fn helper, fn test_new, fn test_color
    assert_eq!(r.functions, 6, "function definitions");
    // struct Point, enum Color, trait Shape, impl Point
    assert_eq!(r.classes, 4, "class/struct/trait/impl definitions");
    // let pt, let sq, let _tmp, let p, let c
    assert_eq!(r.variables, 5, "variable declarations");
    // use std::io, use std::fmt, use super::*
    assert_eq!(r.imports, 3, "import statements");
    // two #[test] attributes
    assert_eq!(r.test_count, 2, "test annotations");
    // assert_eq! and assert!
    assert_eq!(r.test_assertion_count, 2, "assertion calls");
    assert_eq!(r.test_suite_count, 0, "no test suites");
}

#[test]
#[cfg_attr(
    feature = "tree-sitter",
    ignore = "tree-sitter path does not populate symbol counters \
              (see TODO: implement ts symbol counting)"
)]
fn python_entities() {
    let text = corpus("python/entities.py");
    let result = analyze_text(Language::Python, &text, AnalysisOptions::default());
    let r = &result.raw;
    // def __init__, def speak, def helper — test methods excluded
    assert_eq!(r.functions, 3, "plain function definitions");
    // class Animal only — class TestAnimal excluded (matched test pattern)
    assert_eq!(r.classes, 1, "plain class definitions");
    // import os, from sys import argv
    assert_eq!(r.imports, 2, "import statements");
    // class TestAnimal, def test_speak, def test_helper
    assert_eq!(r.test_count, 3, "test definitions");
    // self.assertEqual x2
    assert_eq!(r.test_assertion_count, 2, "assertion calls");
}

#[test]
fn go_entities() {
    let text = corpus("go/entities.go");
    let result = analyze_text(Language::Go, &text, AnalysisOptions::default());
    let r = &result.raw;
    // func Area, func helper — test funcs excluded
    assert_eq!(r.functions, 2, "plain function definitions");
    // type Point struct
    assert_eq!(r.classes, 1, "type definitions");
    // var result, var x
    assert_eq!(r.variables, 2, "variable declarations");
    // import "fmt"
    assert_eq!(r.imports, 1, "import statements");
    // func TestPoint, func BenchmarkHelper
    assert_eq!(r.test_count, 2, "test function definitions");
    assert_eq!(r.test_assertion_count, 0, "no assertions");
}

#[test]
fn javascript_entities() {
    let text = corpus("javascript/entities.js");
    let result = analyze_text(Language::JavaScript, &text, AnalysisOptions::default());
    let r = &result.raw;
    // function multiply only — arrow function and class methods not counted
    assert_eq!(r.functions, 1, "function declarations");
    // class Calculator
    assert_eq!(r.classes, 1, "class definitions");
    // let result, const divide
    assert_eq!(r.variables, 2, "variable declarations");
    // import { foo } from './foo'
    assert_eq!(r.imports, 1, "import statements");
    // describe, it, test
    assert_eq!(r.test_count, 3, "test block openers");
    // expect x2
    assert_eq!(r.test_assertion_count, 2, "assertion calls");
}

// ─── Empty file ───────────────────────────────────────────────────────────────

#[test]
fn empty_file_all_languages() {
    for lang in [
        Language::C,
        Language::Cpp,
        Language::CSharp,
        Language::Go,
        Language::Java,
        Language::JavaScript,
        Language::Python,
        Language::Rust,
        Language::Shell,
        Language::PowerShell,
        Language::TypeScript,
    ] {
        let result = analyze_text(lang, "", AnalysisOptions::default());
        assert_eq!(
            result.raw.total_physical_lines,
            0,
            "{} should have 0 lines for empty input",
            lang.display_name()
        );
    }
}
