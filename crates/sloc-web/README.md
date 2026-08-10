# sloc-web

Axum web server and UI for [oxide-sloc](https://github.com/oxide-sloc/oxide-sloc) — a local code analysis tool.

<!-- Absolute URL for crates.io; falls back to the in-repo copy when viewed offline. -->
<img alt="View Reports — full scan history with branch, commit, and submodule breakdown" src="https://raw.githubusercontent.com/oxide-sloc/oxide-sloc/main/docs/screenshots/view-reports.png" onerror="this.onerror=null;this.src='../../docs/screenshots/view-reports.png'">

## Overview

This crate runs the localhost web UI:

- **`serve(config) -> Result<()>`** — starts an Axum HTTP/HTTPS server (default port 4317)
- **Routes**: `GET /`, `POST /analyze`, `GET /preview`, `GET /pick-directory`, `GET /runs/{artifact}/{run_id}`, `GET /view-reports`, `GET /compare-scans`, `GET /test-metrics`, `GET /trend-reports`, `GET /embed/summary`, `GET /api/suggest-coverage`, `GET /healthz`
- **Rate limiting and auth**: IP sliding-window rate limiter (60 req/60 s), optional bearer-token auth (`SLOC_API_KEY`), optional TLS (`SLOC_TLS_CERT` / `SLOC_TLS_KEY`), CORS, response headers
- **Native file picker** via `rfd` — works on Windows and Linux; accepts LCOV, Cobertura XML, JaCoCo XML, and Istanbul/NYC JSON coverage files
- **Test Metrics** (`/test-metrics`) — four-chip summary strip (density, most-tested language, languages with tests, line coverage %); animated `cov-gauge-card` components per language; multi-format coverage auto-detection via `parse_coverage_auto()`
- **Trend Reports** (`/trend-reports`) — sortable columns (click header to toggle ↕/↑/↓), column-resize handles, and client-side filter row; stat chips for total scans, latest metric, net change, and project count
- **`/api/suggest-coverage`** — inspects project root for build files (`Cargo.toml`, `pom.xml`, `build.gradle`, `package.json`, etc.) and returns the recommended coverage-generation command
- Artifacts persisted to disk with UUID-based run IDs; artifact URLs use segment order `{artifact}/{run_id}`

## Usage

This is an internal crate used by the oxide-sloc workspace. It is not intended for use outside this project. See the [main project](https://github.com/oxide-sloc/oxide-sloc) for documentation and releases.

```toml
# Install the tool instead:
cargo install oxide-sloc
```
