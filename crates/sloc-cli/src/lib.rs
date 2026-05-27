// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Nima Shafie <nimzshafie@gmail.com>

//! # oxide-sloc
//!
//! **Cross-platform source line analysis tool** implementing IEEE 1045-1992 SLOC
//! metrics, unit-test detection, and coverage reporting.
//!
//! ## Overview
//!
//! `oxide-sloc` is a binary crate — its primary interface is the `oxide-sloc`
//! executable. All analytical logic lives in focused library crates that are
//! published separately on crates.io for programmatic use:
//!
//! | Crate | Purpose |
//! |---|---|
//! | [`sloc-config`](https://docs.rs/sloc-config) | Configuration schema and TOML parsing |
//! | [`sloc-languages`](https://docs.rs/sloc-languages) | Language detection and lexical line analyzers |
//! | [`sloc-core`](https://docs.rs/sloc-core) | File discovery, decoding, and aggregation engine |
//! | [`sloc-report`](https://docs.rs/sloc-report) | HTML rendering and PDF export |
//! | [`sloc-git`](https://docs.rs/sloc-git) | Git CLI wrappers and webhook parsing |
//! | [`sloc-web`](https://docs.rs/sloc-web) | Axum web server and form handlers |
//!
//! ## Quick Start
//!
//! ```text
//! # Start the web UI  →  http://127.0.0.1:4317
//! oxide-sloc
//!
//! # Analyze a directory
//! oxide-sloc analyze ./my-repo --plain
//!
//! # Produce JSON + HTML report
//! oxide-sloc analyze ./my-repo --json-out result.json --html-out result.html
//!
//! # Re-render a saved result as PDF
//! oxide-sloc report result.json --pdf-out result.pdf
//!
//! # Compare two scans
//! oxide-sloc diff baseline.json current.json
//! ```
//!
//! ## Delivery surfaces
//!
//! | Surface | How to reach it |
//! |---|---|
//! | Web UI | `oxide-sloc` (no arguments) or `oxide-sloc serve` |
//! | CLI | `oxide-sloc analyze` / `report` / `diff` / `init` / `send` |
//! | HTML report | `--html-out <file>` on `analyze` |
//! | PDF report | `--pdf-out <file>` on `analyze` or `report` |
//! | JSON artifact | `--json-out <file>` on `analyze` |
//!
//! ## Supported languages
//!
//! 41 languages: Assembly, C, C++, C#, Clojure, CSS, Dart, Dockerfile, Elixir,
//! Erlang, F#, Go, Groovy, Haskell, HTML, Java, JavaScript, Julia, Kotlin, Lua,
//! Makefile, Nim, Objective-C, OCaml, Perl, PHP, PowerShell, Python, R, Ruby,
//! Rust, Scala, SCSS/Sass, Shell, SQL, Svelte, Swift, TypeScript, Vue, XML/SVG,
//! and Zig.
//!
//! ## Installation
//!
//! ```text
//! cargo install oxide-sloc
//! ```
//!
//! Or clone the repository and run `bash scripts/run.sh` for a fully offline,
//! no-Rust-required install (all dependencies are vendored in the repo).
//!
//! See the [repository README](https://github.com/oxide-sloc/oxide-sloc) for full
//! documentation.
