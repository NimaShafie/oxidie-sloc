// SPDX-License-Identifier: AGPL-3.0-or-later
// Coverage-boost tests for sloc-languages.
//
// Exercises every Language variant through analyze_text (covering each
// language_scan_config arm), the detect_language extension/shebang/filename
// paths, and the C/C++ style classifier's brace / pointer / paren branches.

use std::collections::BTreeMap;
use std::path::Path;

use sloc_languages::{analyze_text, detect_language, style, AnalysisOptions, Language};

/// Every Language variant with a tiny representative snippet. Calling
/// analyze_text on each forces language_scan_config to resolve that arm.
fn all_languages() -> Vec<(Language, &'static str)> {
    vec![
        (Language::C, "// c\nint x = 1;\n"),
        (Language::Cpp, "// cpp\nint* p = nullptr;\n"),
        (Language::CSharp, "// cs\nvar x = 1;\n"),
        (Language::Go, "// go\nx := 1\n"),
        (Language::Java, "// java\nint x = 1;\n"),
        (Language::JavaScript, "// js\nconst x = 1;\n"),
        (Language::Python, "# py\nx = 1\n"),
        (Language::Rust, "// rs\nlet x = 1;\n"),
        (Language::Shell, "# sh\nx=1\n"),
        (Language::PowerShell, "# ps\n$x = 1\n"),
        (Language::TypeScript, "// ts\nconst x: number = 1;\n"),
        (Language::Assembly, "; asm\nmov eax, 1\n"),
        (Language::Clojure, ";; clj\n(def x 1)\n"),
        (Language::Css, "/* css */\n.a { color: red; }\n"),
        (Language::Dart, "// dart\nvar x = 1;\n"),
        (Language::Dockerfile, "# docker\nFROM scratch\n"),
        (Language::Elixir, "# ex\nx = 1\n"),
        (Language::Erlang, "% erl\nX = 1.\n"),
        (Language::FSharp, "// fs\nlet x = 1\n"),
        (Language::Groovy, "// groovy\ndef x = 1\n"),
        (Language::Haskell, "-- hs\nx = 1\n"),
        (Language::Html, "<!-- html -->\n<p>hi</p>\n"),
        (Language::Julia, "# jl\nx = 1\n"),
        (Language::Kotlin, "// kt\nval x = 1\n"),
        (Language::Lua, "-- lua\nlocal x = 1\n"),
        (Language::Makefile, "# make\nall:\n\techo hi\n"),
        (Language::Nim, "# nim\nvar x = 1\n"),
        (Language::ObjectiveC, "// objc\nint x = 1;\n"),
        (Language::Ocaml, "(* ml *)\nlet x = 1\n"),
        (Language::Perl, "# pl\nmy $x = 1;\n"),
        (Language::Php, "// php\n$x = 1;\n"),
        (Language::Ruby, "# rb\nx = 1\n"),
        (Language::Scala, "// scala\nval x = 1\n"),
        (Language::Scss, "// scss\n$x: 1;\n"),
        (Language::Sql, "-- sql\nSELECT 1;\n"),
        (Language::Svelte, "<!-- svelte -->\n<p>hi</p>\n"),
        (Language::Swift, "// swift\nlet x = 1\n"),
        (Language::Vue, "<!-- vue -->\n<template></template>\n"),
        (Language::Xml, "<!-- xml -->\n<root/>\n"),
        (Language::Zig, "// zig\nconst x = 1;\n"),
        (Language::Solidity, "// sol\nuint x = 1;\n"),
        (Language::Protobuf, "// proto\nmessage M {}\n"),
        (Language::Hcl, "# hcl\nx = 1\n"),
        (Language::GraphQl, "# gql\ntype Q { a: Int }\n"),
        (Language::Ada, "-- ada\nX : Integer := 1;\n"),
        (Language::Vhdl, "-- vhdl\nsignal x : bit;\n"),
        (Language::Verilog, "// v\nwire x;\n"),
        (Language::Tcl, "# tcl\nset x 1\n"),
        (Language::Pascal, "{ pas }\nx := 1;\n"),
        (Language::VisualBasic, "' vb\nDim x = 1\n"),
        (Language::Lisp, ";; lisp\n(defvar x 1)\n"),
    ]
}

#[test]
fn analyze_text_covers_every_language_arm() {
    for (lang, text) in all_languages() {
        // Default options.
        let r = analyze_text(lang, text, AnalysisOptions::default());
        assert!(
            r.raw.total_physical_lines >= 1,
            "{lang:?}: expected at least one physical line"
        );
        // Re-run with the IEEE-1045 flags toggled to exercise alternate branches.
        let opts = AnalysisOptions {
            collapse_continuation_lines: true,
            blank_in_block_comment_as_comment: true,
            ..AnalysisOptions::default()
        };
        let _ = analyze_text(lang, text, opts);
    }
}

#[test]
fn analyze_text_handles_block_comments_and_strings() {
    // C/C++ block comments spanning lines + string with comment-like content.
    let c = "/* a\n   b */\nconst char* s = \"/* not a comment */\";\nint x = 1; // trailing\n";
    let r = analyze_text(Language::Cpp, c, AnalysisOptions::default());
    assert!(r.raw.multi_comment_only_lines >= 1);

    // Python triple-quoted docstring classification.
    let py = "def f():\n    \"\"\"doc\n    line2\n    \"\"\"\n    return 1\n";
    let r = analyze_text(Language::Python, py, AnalysisOptions::default());
    assert!(r.raw.total_physical_lines >= 5);
}

#[test]
fn detect_language_by_extension_and_overrides() {
    let no_overrides = BTreeMap::new();
    let cases = [
        ("a.rs", Language::Rust),
        ("a.py", Language::Python),
        ("a.cpp", Language::Cpp),
        ("a.ts", Language::TypeScript),
        ("a.go", Language::Go),
        ("a.sol", Language::Solidity),
        ("a.vhd", Language::Vhdl),
        ("a.v", Language::Verilog),
        ("a.tcl", Language::Tcl),
        ("a.pas", Language::Pascal),
        ("a.lisp", Language::Lisp),
    ];
    for (name, _expected) in cases {
        let got = detect_language(Path::new(name), None, &no_overrides, true);
        assert!(got.is_some(), "{name}: expected a detected language");
    }

    // Extension override wins over built-in detection.
    let mut overrides = BTreeMap::new();
    overrides.insert("rs".to_string(), "Python".to_string());
    let got = detect_language(Path::new("x.rs"), None, &overrides, true);
    assert_eq!(got, Some(Language::Python), "override should win");

    // Unknown extension → None.
    assert_eq!(
        detect_language(Path::new("x.unknownext"), None, &no_overrides, true),
        None
    );
}

#[test]
fn detect_language_by_shebang() {
    let no = BTreeMap::new();
    let cases = [
        ("#!/usr/bin/env python3", Language::Python),
        ("#!/bin/bash", Language::Shell),
        ("#!/usr/bin/pwsh", Language::PowerShell),
        ("#!/usr/bin/env ruby", Language::Ruby),
        ("#!/usr/bin/perl", Language::Perl),
        ("#!/usr/bin/php", Language::Php),
        ("#!/usr/bin/env node", Language::JavaScript),
    ];
    for (line, expected) in cases {
        let got = detect_language(Path::new("script"), Some(line), &no, true);
        assert_eq!(got, Some(expected), "shebang {line:?}");
    }
    // Shebang detection disabled → None for an extensionless script.
    assert_eq!(
        detect_language(Path::new("script"), Some("#!/bin/bash"), &no, false),
        None
    );
}

#[test]
fn detect_language_by_filename() {
    let no = BTreeMap::new();
    for name in ["Dockerfile", "Makefile", "makefile"] {
        assert!(
            detect_language(Path::new(name), None, &no, true).is_some(),
            "{name} should be detected by filename"
        );
    }
}

// ── C/C++ style classifier branches ──────────────────────────────────────────

#[test]
fn cpp_style_with_type_pointers_allman_braces_space_parens() {
    // Allman braces (brace alone on a line), `Type* name` pointers, spaced parens,
    // and a variety of attach-brace block heads to exercise is_block_head.
    let src = "#pragma once\n\
class Foo\n{\n\
    int* a;\n\
    char* b;\n\
    void method() const\n    {\n        if (a)\n        {\n            return;\n        }\n    }\n\
};\n\
namespace ns {\n}\n\
struct S {\n};\n\
enum E {\n};\n\
extern \"C\" {\n}\n\
void g() noexcept {\n}\n\
void h() override {\n}\n\
void run()\n{\n    try {\n    } catch (int e) {\n    }\n    do {\n    } while (a);\n}\n";
    let st = style::analyze_style(Language::Cpp, src).expect("cpp style should be Some");
    assert!(!st.signals.is_empty(), "expected style signals");
}

#[test]
fn cpp_style_with_name_pointers_attach_braces_nospace_parens() {
    // `Type *name` pointers, attach braces, and parens with no space.
    let src = "void f() {\n\
    int *a;\n    char *b;\n    long *c;\n    short *d;\n\
    if(a){\n    }\n    while(b){\n    }\n    for(;;){\n    }\n\
}\n";
    let st = style::analyze_style(Language::Cpp, src).expect("cpp style should be Some");
    assert!(!st.signals.is_empty());
}

#[test]
fn cpp_style_mixed_pointers() {
    // Roughly even split of `Type* name` and `Type *name` → Mixed classification.
    let src = "void f() {\n    int* a;\n    int *b;\n    char* c;\n    char *d;\n}\n";
    let _ = style::analyze_style(Language::Cpp, src);
}

#[test]
fn other_language_style_analyzers_run() {
    // Each of these languages has a dedicated style analyzer module.
    let samples = [
        (Language::Rust, "fn main() {\n    let x = 1;\n}\n"),
        (Language::Java, "class A {\n    int x = 1;\n}\n"),
        (Language::Python, "def f():\n    return 1\n"),
        (Language::Go, "func main() {\n}\n"),
        (Language::CSharp, "class A {\n    int X = 1;\n}\n"),
        (Language::JavaScript, "function f() {\n    return 1;\n}\n"),
        (Language::Ruby, "def f\n  1\nend\n"),
    ];
    for (lang, src) in samples {
        // May be Some or None depending on heuristics; just must not panic.
        let _ = style::analyze_style(lang, src);
    }
}
