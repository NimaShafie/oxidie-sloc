// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Nima Shafie <nimzshafie@gmail.com>

//! Multi-language style-guide analysis.
//! Dispatch entry: `analyze_style(language, text) -> Option<StyleAnalysis>`.

pub mod common;
mod cpp;
mod csharp;
mod go_lang;
mod java;
mod js;
mod python;
mod ruby;
mod rust_lang;

pub use common::{IndentStyle, StyleAnalysis, StyleGuideScore, StyleSignal};

use crate::Language;

/// Run style analysis for the given language and source text.
/// Returns `None` for languages where no style guide heuristics are defined.
pub fn analyze_style(language: Language, text: &str) -> Option<StyleAnalysis> {
    match language {
        // C family
        Language::C | Language::Cpp | Language::ObjectiveC => Some(cpp::analyze(text)),

        // Python
        Language::Python => Some(python::analyze(text)),

        // JavaScript / TypeScript
        Language::JavaScript | Language::TypeScript => Some(js::analyze(language, text)),

        // JVM family
        Language::Java | Language::Kotlin | Language::Groovy | Language::Scala => {
            Some(java::analyze(language, text))
        }

        // C# / F#
        Language::CSharp | Language::FSharp => Some(csharp::analyze(language, text)),

        // Go
        Language::Go => Some(go_lang::analyze(text)),

        // Rust
        Language::Rust => Some(rust_lang::analyze(text)),

        // Ruby
        Language::Ruby => Some(ruby::analyze(text)),

        // All other languages: no style heuristics yet
        _ => None,
    }
}
