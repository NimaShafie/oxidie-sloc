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
        // Extended languages
        Language::Assembly,
        Language::Clojure,
        Language::Css,
        Language::Dart,
        Language::Dockerfile,
        Language::Elixir,
        Language::Erlang,
        Language::FSharp,
        Language::Groovy,
        Language::Haskell,
        Language::Html,
        Language::Julia,
        Language::Kotlin,
        Language::Lua,
        Language::Makefile,
        Language::Nim,
        Language::ObjectiveC,
        Language::Ocaml,
        Language::Perl,
        Language::Php,
        Language::R,
        Language::Ruby,
        Language::Scala,
        Language::Scss,
        Language::Sql,
        Language::Svelte,
        Language::Swift,
        Language::Vue,
        Language::Xml,
        Language::Zig,
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

// ─── Basic corpus: extended languages ────────────────────────────────────────

#[test]
fn assembly_basic() {
    let text = corpus("assembly/basic.asm");
    let r = &analyze_text(Language::Assembly, &text, AnalysisOptions::default()).raw;
    assert!(r.total_physical_lines >= 3);
    assert!(r.code_only_lines >= 1, "should detect code lines");
    assert!(r.single_comment_only_lines >= 1, "should detect ; comments");
}

#[test]
fn clojure_basic() {
    let text = corpus("clojure/basic.clj");
    let r = &analyze_text(Language::Clojure, &text, AnalysisOptions::default()).raw;
    assert!(r.total_physical_lines >= 3);
    assert!(r.code_only_lines >= 1);
    assert!(
        r.single_comment_only_lines >= 1,
        "should detect ;; comments"
    );
}

#[test]
fn css_basic() {
    let text = corpus("css/basic.css");
    let r = &analyze_text(Language::Css, &text, AnalysisOptions::default()).raw;
    assert!(r.total_physical_lines >= 3);
    assert!(r.code_only_lines >= 1);
    assert!(
        r.multi_comment_only_lines >= 1,
        "should detect /* */ block comments"
    );
}

#[test]
fn dart_basic() {
    let text = corpus("dart/basic.dart");
    let r = &analyze_text(Language::Dart, &text, AnalysisOptions::default()).raw;
    assert!(r.total_physical_lines >= 3);
    assert!(r.code_only_lines >= 1);
    assert!(r.single_comment_only_lines >= 1);
}

#[test]
fn dockerfile_basic() {
    let text = corpus("dockerfile/basic.dockerfile");
    let r = &analyze_text(Language::Dockerfile, &text, AnalysisOptions::default()).raw;
    assert!(r.total_physical_lines >= 3);
    assert!(r.code_only_lines >= 1);
    assert!(r.single_comment_only_lines >= 1, "should detect # comments");
}

#[test]
fn elixir_basic() {
    let text = corpus("elixir/basic.ex");
    let r = &analyze_text(Language::Elixir, &text, AnalysisOptions::default()).raw;
    assert!(r.total_physical_lines >= 3);
    assert!(r.code_only_lines >= 1);
    assert!(r.single_comment_only_lines >= 1);
}

#[test]
fn erlang_basic() {
    let text = corpus("erlang/basic.erl");
    let r = &analyze_text(Language::Erlang, &text, AnalysisOptions::default()).raw;
    assert!(r.total_physical_lines >= 3);
    assert!(r.code_only_lines >= 1);
    assert!(r.single_comment_only_lines >= 1, "should detect % comments");
}

#[test]
fn fsharp_basic() {
    let text = corpus("fsharp/basic.fs");
    let r = &analyze_text(Language::FSharp, &text, AnalysisOptions::default()).raw;
    assert!(r.total_physical_lines >= 3);
    assert!(r.code_only_lines >= 1);
    assert!(r.single_comment_only_lines >= 1);
}

#[test]
fn groovy_basic() {
    let text = corpus("groovy/basic.groovy");
    let r = &analyze_text(Language::Groovy, &text, AnalysisOptions::default()).raw;
    assert!(r.total_physical_lines >= 3);
    assert!(r.code_only_lines >= 1);
    assert!(r.single_comment_only_lines >= 1);
}

#[test]
fn haskell_basic() {
    let text = corpus("haskell/basic.hs");
    let r = &analyze_text(Language::Haskell, &text, AnalysisOptions::default()).raw;
    assert!(r.total_physical_lines >= 3);
    assert!(r.code_only_lines >= 1);
    assert!(
        r.single_comment_only_lines >= 1,
        "should detect -- comments"
    );
}

#[test]
fn html_basic() {
    let text = corpus("html/basic.html");
    let r = &analyze_text(Language::Html, &text, AnalysisOptions::default()).raw;
    assert!(r.total_physical_lines >= 3);
    assert!(r.code_only_lines >= 1);
    assert!(
        r.multi_comment_only_lines >= 1,
        "should detect <!-- --> comments"
    );
}

#[test]
fn julia_basic() {
    let text = corpus("julia/basic.jl");
    let r = &analyze_text(Language::Julia, &text, AnalysisOptions::default()).raw;
    assert!(r.total_physical_lines >= 3);
    assert!(r.code_only_lines >= 1);
    assert!(r.single_comment_only_lines >= 1);
}

#[test]
fn kotlin_basic() {
    let text = corpus("kotlin/basic.kt");
    let r = &analyze_text(Language::Kotlin, &text, AnalysisOptions::default()).raw;
    assert!(r.total_physical_lines >= 3);
    assert!(r.code_only_lines >= 1);
    assert!(r.single_comment_only_lines >= 1);
}

#[test]
fn lua_basic() {
    let text = corpus("lua/basic.lua");
    let r = &analyze_text(Language::Lua, &text, AnalysisOptions::default()).raw;
    assert!(r.total_physical_lines >= 3);
    assert!(r.code_only_lines >= 1);
    assert!(
        r.single_comment_only_lines >= 1,
        "should detect -- comments"
    );
}

#[test]
fn makefile_basic() {
    let text = corpus("makefile/basic.mk");
    let r = &analyze_text(Language::Makefile, &text, AnalysisOptions::default()).raw;
    assert!(r.total_physical_lines >= 3);
    assert!(r.code_only_lines >= 1);
    assert!(r.single_comment_only_lines >= 1, "should detect # comments");
}

#[test]
fn nim_basic() {
    let text = corpus("nim/basic.nim");
    let r = &analyze_text(Language::Nim, &text, AnalysisOptions::default()).raw;
    assert!(r.total_physical_lines >= 3);
    assert!(r.code_only_lines >= 1);
    assert!(r.single_comment_only_lines >= 1);
}

#[test]
fn objectivec_basic() {
    let text = corpus("objectivec/basic.m");
    let r = &analyze_text(Language::ObjectiveC, &text, AnalysisOptions::default()).raw;
    assert!(r.total_physical_lines >= 3);
    assert!(r.code_only_lines >= 1);
    assert!(r.single_comment_only_lines >= 1);
}

#[test]
fn ocaml_basic() {
    let text = corpus("ocaml/basic.ml");
    let r = &analyze_text(Language::Ocaml, &text, AnalysisOptions::default()).raw;
    assert!(r.total_physical_lines >= 3);
    assert!(r.code_only_lines >= 1);
    assert!(
        r.multi_comment_only_lines >= 1,
        "should detect (* *) block comments"
    );
}

#[test]
fn perl_basic() {
    let text = corpus("perl/basic.pl");
    let r = &analyze_text(Language::Perl, &text, AnalysisOptions::default()).raw;
    assert!(r.total_physical_lines >= 3);
    assert!(r.code_only_lines >= 1);
    assert!(r.single_comment_only_lines >= 1);
}

#[test]
fn php_basic() {
    let text = corpus("php/basic.php");
    let r = &analyze_text(Language::Php, &text, AnalysisOptions::default()).raw;
    assert!(r.total_physical_lines >= 3);
    assert!(r.code_only_lines >= 1);
    assert!(r.single_comment_only_lines >= 1);
}

#[test]
fn r_basic() {
    let text = corpus("r/basic.r");
    let r = &analyze_text(Language::R, &text, AnalysisOptions::default()).raw;
    assert!(r.total_physical_lines >= 3);
    assert!(r.code_only_lines >= 1);
    assert!(r.single_comment_only_lines >= 1);
}

#[test]
fn ruby_basic() {
    let text = corpus("ruby/basic.rb");
    let r = &analyze_text(Language::Ruby, &text, AnalysisOptions::default()).raw;
    assert!(r.total_physical_lines >= 3);
    assert!(r.code_only_lines >= 1);
    assert!(r.single_comment_only_lines >= 1);
}

#[test]
fn scala_basic() {
    let text = corpus("scala/basic.scala");
    let r = &analyze_text(Language::Scala, &text, AnalysisOptions::default()).raw;
    assert!(r.total_physical_lines >= 3);
    assert!(r.code_only_lines >= 1);
    assert!(r.single_comment_only_lines >= 1);
}

#[test]
fn scss_basic() {
    let text = corpus("scss/basic.scss");
    let r = &analyze_text(Language::Scss, &text, AnalysisOptions::default()).raw;
    assert!(r.total_physical_lines >= 3);
    assert!(r.code_only_lines >= 1);
}

#[test]
fn sql_basic() {
    let text = corpus("sql/basic.sql");
    let r = &analyze_text(Language::Sql, &text, AnalysisOptions::default()).raw;
    assert!(r.total_physical_lines >= 3);
    assert!(r.code_only_lines >= 1);
    assert!(
        r.single_comment_only_lines >= 1,
        "should detect -- comments"
    );
}

#[test]
fn svelte_basic() {
    let text = corpus("svelte/basic.svelte");
    let r = &analyze_text(Language::Svelte, &text, AnalysisOptions::default()).raw;
    assert!(r.total_physical_lines >= 3);
    assert!(r.code_only_lines >= 1);
}

#[test]
fn swift_basic() {
    let text = corpus("swift/basic.swift");
    let r = &analyze_text(Language::Swift, &text, AnalysisOptions::default()).raw;
    assert!(r.total_physical_lines >= 3);
    assert!(r.code_only_lines >= 1);
    assert!(r.single_comment_only_lines >= 1);
}

#[test]
fn vue_basic() {
    let text = corpus("vue/basic.vue");
    let r = &analyze_text(Language::Vue, &text, AnalysisOptions::default()).raw;
    assert!(r.total_physical_lines >= 3);
    assert!(r.code_only_lines >= 1);
}

#[test]
fn xml_basic() {
    let text = corpus("xml/basic.xml");
    let r = &analyze_text(Language::Xml, &text, AnalysisOptions::default()).raw;
    assert!(r.total_physical_lines >= 3);
    assert!(r.code_only_lines >= 1);
    assert!(
        r.multi_comment_only_lines >= 1,
        "should detect <!-- --> comments"
    );
}

#[test]
fn zig_basic() {
    let text = corpus("zig/basic.zig");
    let r = &analyze_text(Language::Zig, &text, AnalysisOptions::default()).raw;
    assert!(r.total_physical_lines >= 3);
    assert!(r.code_only_lines >= 1);
    assert!(r.single_comment_only_lines >= 1);
}

#[test]
fn cpp_basic() {
    let text = corpus("cpp/basic.cpp");
    let r = &analyze_text(Language::Cpp, &text, AnalysisOptions::default()).raw;
    assert!(r.total_physical_lines >= 3);
    assert!(r.code_only_lines >= 1);
    assert!(r.single_comment_only_lines >= 1);
}

#[test]
fn csharp_basic() {
    let text = corpus("csharp/basic.cs");
    let r = &analyze_text(Language::CSharp, &text, AnalysisOptions::default()).raw;
    assert!(r.total_physical_lines >= 3);
    assert!(r.code_only_lines >= 1);
    assert!(r.single_comment_only_lines >= 1);
}

#[test]
fn java_basic() {
    let text = corpus("java/basic.java");
    let r = &analyze_text(Language::Java, &text, AnalysisOptions::default()).raw;
    assert!(r.total_physical_lines >= 3);
    assert!(r.code_only_lines >= 1);
    assert!(r.single_comment_only_lines >= 1);
}

#[test]
fn shell_basic() {
    let text = corpus("shell/basic.sh");
    let r = &analyze_text(Language::Shell, &text, AnalysisOptions::default()).raw;
    assert!(r.total_physical_lines >= 3);
    assert!(r.code_only_lines >= 1);
    assert!(r.single_comment_only_lines >= 1);
}

#[test]
fn powershell_basic() {
    let text = corpus("powershell/basic.ps1");
    let r = &analyze_text(Language::PowerShell, &text, AnalysisOptions::default()).raw;
    assert!(r.total_physical_lines >= 3);
    assert!(r.code_only_lines >= 1);
    assert!(r.single_comment_only_lines >= 1);
}
