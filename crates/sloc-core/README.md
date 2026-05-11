# sloc-core

Core analysis engine for [oxide-sloc](https://github.com/oxide-sloc/oxide-sloc) — a local code analysis tool.

## Overview

This crate is the main entry point for analysis:

- **`analyze(config) -> Result<AnalysisRun>`** — file discovery, byte decoding (UTF-8 → UTF-16 → Windows-1252 fallback), language detection, per-file SLOC analysis, and aggregation
- **`AnalysisRun`** — canonical serializable result; read/write via `write_json` / `read_json`; includes `summary_totals.test_count`, `test_assertion_count`, `test_suite_count`, per-language equivalents, and optional per-file `coverage` (LCOV line-hit data)
- **`FileRecord`** — per-file details including effective counts after policy application
- Binary detection via long-line + low-whitespace heuristic
- Generated/vendor/lockfile skip logic
- Git submodule discovery and per-submodule breakdown
- **Multi-format coverage parsing** (`coverage.rs`): `parse_coverage_auto(path, content)` auto-detects the format by file extension and content sniff, then dispatches to `parse_lcov`, `parse_cobertura` (Cobertura XML / pytest-cov / Maven), `parse_jacoco` (JaCoCo XML / Gradle / Maven), or `parse_istanbul` (Istanbul/NYC JSON / Jest). `lookup_coverage` matches per-file paths with three fallback strategies; `aggregate_line_coverage` produces a weighted-average percentage.

## Usage

This is an internal crate used by the oxide-sloc workspace. It is not intended for use outside this project. See the [main project](https://github.com/oxide-sloc/oxide-sloc) for documentation and releases.

```toml
# Install the tool instead:
cargo install oxide-sloc
```
