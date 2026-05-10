# sloc-web

Axum web server and UI for [oxide-sloc](https://github.com/oxide-sloc/oxide-sloc) — a local code analysis tool.

## Overview

This crate runs the localhost web UI:

- **`serve(config) -> Result<()>`** — starts an Axum HTTP/HTTPS server (default port 4317)
- **Routes**: `GET /`, `POST /analyze`, `GET /preview`, `GET /pick-directory`, `GET /runs/:id/:artifact`, `GET /view-reports`, `GET /compare-scans`, `GET /test-metrics`, `GET /trend-reports`, `GET /embed/summary`, `GET /healthz`
- **Rate limiting and auth**: IP sliding-window rate limiter (60 req/60 s), optional bearer-token auth (`SLOC_API_KEY`), optional TLS (`SLOC_TLS_CERT` / `SLOC_TLS_KEY`), CORS, response headers
- **Native file picker** via `rfd` — works on Windows and Linux
- **Test Metrics** (`/test-metrics`) — lexical test-count charts, test-to-code density, and optional LCOV line-coverage aggregation per language
- Artifacts persisted to disk with UUID-based run IDs

## Usage

This is an internal crate used by the oxide-sloc workspace. It is not intended for use outside this project. See the [main project](https://github.com/oxide-sloc/oxide-sloc) for documentation and releases.

```toml
# Install the tool instead:
cargo install oxide-sloc
```
