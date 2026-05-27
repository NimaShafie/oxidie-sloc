// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Nima Shafie <nimzshafie@gmail.com>
//
// Fuzz target: exercises the lexical state machine for every supported language.
// Run with: cargo fuzz run fuzz_analyze_text

#![no_main]

use libfuzzer_sys::fuzz_target;
use sloc_languages::{analyze_text, AnalysisOptions, Language};

// All supported languages in a fixed array so the fuzzer can index into it.
const LANGUAGES: &[Language] = &[
    Language::Assembly,
    Language::C,
    Language::Clojure,
    Language::Cpp,
    Language::CSharp,
    Language::Css,
    Language::Dart,
    Language::Dockerfile,
    Language::Elixir,
    Language::Erlang,
    Language::FSharp,
    Language::Go,
    Language::Groovy,
    Language::Haskell,
    Language::Html,
    Language::Java,
    Language::JavaScript,
    Language::Julia,
    Language::Kotlin,
    Language::Lua,
    Language::Makefile,
    Language::Nim,
    Language::ObjectiveC,
    Language::Ocaml,
    Language::Perl,
    Language::Php,
    Language::PowerShell,
    Language::Python,
    Language::R,
    Language::Ruby,
    Language::Rust,
    Language::Scala,
    Language::Scss,
    Language::Shell,
    Language::Sql,
    Language::Svelte,
    Language::Swift,
    Language::TypeScript,
    Language::Vue,
    Language::Xml,
    Language::Zig,
];

fuzz_target!(|data: &[u8]| {
    // Need at least 2 bytes: one to select options, one to select language.
    if data.len() < 2 {
        return;
    }

    let (header, body) = data.split_at(2);

    // Decode as UTF-8; skip inputs that aren't valid UTF-8 so the fuzzer focuses
    // on exercising the state machine rather than the caller's encoding layer.
    let text = match std::str::from_utf8(body) {
        Ok(s) => s,
        Err(_) => return,
    };

    let lang_idx = (header[0] as usize) % LANGUAGES.len();
    let language = LANGUAGES[lang_idx];

    let options = AnalysisOptions {
        blank_in_block_comment_as_comment: header[1] & 0x01 != 0,
        collapse_continuation_lines: header[1] & 0x02 != 0,
    };

    // Must not panic for any valid UTF-8 input.
    let _ = analyze_text(language, text, options);
});
