# oxide-sloc

[![CI](https://github.com/oxide-sloc/oxide-sloc/actions/workflows/ci.yml/badge.svg)](https://github.com/oxide-sloc/oxide-sloc/actions/workflows/ci.yml)
[![Release](https://github.com/oxide-sloc/oxide-sloc/actions/workflows/release.yml/badge.svg)](https://github.com/oxide-sloc/oxide-sloc/actions/workflows/release.yml)
[![Docker](https://github.com/oxide-sloc/oxide-sloc/actions/workflows/docker.yml/badge.svg)](https://github.com/oxide-sloc/oxide-sloc/actions/workflows/docker.yml)
[![Latest Release](https://img.shields.io/github/v/release/oxide-sloc/oxide-sloc?label=release&color=blue)](https://github.com/oxide-sloc/oxide-sloc/releases/latest)
[![crates.io](https://badgen.net/crates/v/oxide-sloc?label=crates.io&color=orange)](https://crates.io/crates/oxide-sloc)
[![codecov](https://codecov.io/gh/oxide-sloc/oxide-sloc/branch/main/graph/badge.svg)](https://codecov.io/gh/oxide-sloc/oxide-sloc)
[![License: AGPL-3.0-or-later](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue.svg)](./LICENSE)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/12976/badge)](https://www.bestpractices.dev/en/projects/12976)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/oxide-sloc/oxide-sloc/badge)](https://securityscorecards.dev/viewer/?uri=github.com/oxide-sloc/oxide-sloc)
[![docs.rs](https://img.shields.io/docsrs/oxide-sloc)](https://docs.rs/oxide-sloc)
[![MCP Server](https://img.shields.io/badge/MCP-server-orange)](./mcp.json)

**oxide-sloc** is a Rust-based local code analysis tool — IEEE 1045-1992 SLOC analysis, unit test detection, and coverage reporting.

## Quick Start

```bash
bash scripts/run.sh   # installs on first run, then opens http://127.0.0.1:4317
```

| Platform | What happens |
|---|---|
| **Windows 10/11** (Git Bash) | Extracts pre-built binary from `dist/` — no Rust required |
| **Linux — Rust installed** | Builds offline from committed `vendor.tar.xz` |
| **Linux — no Rust, toolchain committed** | Bootstraps Rust from `toolchain/` archives, builds offline |
| **Linux — online** | `bash scripts/internal/install.sh --online` downloads the release binary |
| **Air-gapped** | See [`docs/airgap.md`](./docs/airgap.md) |

## Features

- **CLI + web UI** — `analyze / report / diff / serve / send / init` commands; guided 4-step web flow with Quick Scan
- **IEEE 1045-1992 physical SLOC** — configurable mixed-line, continuation-line, compiler-directive, and blank-in-comment policies; symbol counting (functions, classes, variables, imports)
- **Deep metrics** — COCOMO I effort/cost estimate, approximate cyclomatic complexity (branch-keyword count), ULOC / DRYness, and duplicate-file detection on every run
- **Git Hotspots** — ranks refactor candidates by `code lines × commit activity` over a configurable window (90 days by default); per-file commit counts and last-changed dates from a single `git log` pass
- **Test Metrics** — lexical test function detection across 60 languages; test-to-code density; multi-format coverage import (LCOV, Cobertura XML, JaCoCo XML, coverage.py JSON, Istanbul/NYC JSON)
- **Flexible output** — HTML reports, PDF, CSV, and 4-sheet Excel export; re-render any saved JSON
- **Git integration** — branch/tag/commit browser, GitHub/GitLab/Bitbucket webhooks and polling, submodule breakdown
- **CI/CD** — GitHub Actions, Jenkins, GitLab CI; JSON metrics API, SVG badge endpoint, embeddable widget, SMTP/webhook delivery
- **Offline-first** — vendored deps, Chart.js compiled in, no CDN calls; Docker on GHCR; LAN server mode with API key auth and optional TLS

## Why oxide-sloc vs cloc / tokei / scc?

| Capability | oxide-sloc | cloc | tokei | scc |
|---|---|---|---|---|
| Languages | 60 | 250+ | 240+ | 240+ |
| Web UI + HTML/PDF reports | ✓ | — | — | — |
| MCP server (AI agent tools) | ✓ | — | — | — |
| Test function detection | ✓ | — | — | — |
| Trend / history tracking | ✓ | — | — | — |
| Coverage file import | ✓ | — | — | — |
| Git Hotspots (churn × size) | ✓ | — | — | — |
| COCOMO + complexity¹ + DRYness | ✓ | — | — | ✓ |
| IEEE 1045-1992 compliance | ✓ | partial | — | — |
| REST API + SVG badge | ✓ | — | — | — |
| Git webhook integration | ✓ | — | — | — |
| CI/CD marketplace action | ✓ | — | — | — |
| Offline / air-gapped build | ✓ | — | — | — |

¹ Complexity is a lexical approximation — a sum of branch/decision keywords (`if`, `for`, `while`, `||`, `&&`, …) per code line, not a control-flow-graph McCabe computation.

cloc, tokei, and scc win on raw language count and throughput for pure line-counting pipelines.
oxide-sloc is the right choice when you need analysis depth, visual reports, history, or
AI-native integration — particularly as an MCP tool callable by Claude, Copilot, and other agents.

---

## Screenshots

![Home — navigation hub with quick-launch cards for every feature](https://raw.githubusercontent.com/oxide-sloc/oxide-sloc/main/docs/screenshots/home-page.png)

| View Reports | Scan Delta |
|---|---|
| ![View Reports](https://raw.githubusercontent.com/oxide-sloc/oxide-sloc/main/docs/screenshots/view-reports.png) | ![Scan Delta](https://raw.githubusercontent.com/oxide-sloc/oxide-sloc/main/docs/screenshots/compare-delta.png) |
| **Trend Reports** | **Test Metrics** |
| ![Trend Reports](https://raw.githubusercontent.com/oxide-sloc/oxide-sloc/main/docs/screenshots/trend-reports.png) | ![Test Metrics](https://raw.githubusercontent.com/oxide-sloc/oxide-sloc/main/docs/screenshots/test-metrics.png) |
| **PDF Report** | **Excel Export** |
| ![PDF Report](https://raw.githubusercontent.com/oxide-sloc/oxide-sloc/main/docs/screenshots/report-pdf.png) | ![Excel Export](https://raw.githubusercontent.com/oxide-sloc/oxide-sloc/main/docs/screenshots/export-excel.png) |

![Per-run report — summary stat chips, export options, and submodule breakdown](https://raw.githubusercontent.com/oxide-sloc/oxide-sloc/main/docs/screenshots/report-summary.png)

---

## Installation

### Package managers

| Manager | Command | Platform |
|---|---|---|
| **winget** | `winget install NimaShafie.OxideSLOC` | Windows |
| **Chocolatey** | `choco install oxide-sloc` | Windows |
| **Scoop** | `scoop bucket add oxide-sloc https://github.com/oxide-sloc/scoop-oxide-sloc && scoop install oxide-sloc` | Windows |
| **Homebrew** | `brew tap oxide-sloc/oxide-sloc && brew install oxide-sloc` | macOS / Linux |
| **Nix** | `nix run github:oxide-sloc/oxide-sloc` | Linux / macOS |
| **cargo** | `cargo install oxide-sloc --locked` | Any |
| **DEB / RPM** | Download from [Releases](https://github.com/oxide-sloc/oxide-sloc/releases) | Ubuntu / RHEL |

### Docker

```bash
export SLOC_API_KEY=$(openssl rand -hex 32)
docker compose up
```

```bash
# CLI via Docker
docker run --rm -v /path/to/your/repo:/repo:ro \
  ghcr.io/nimashafie/oxide-sloc:latest analyze /repo --plain
```

Set `SLOC_API_KEY`, `SLOC_ALLOWED_ROOTS`, and `SLOC_TLS_CERT`/`SLOC_TLS_KEY` as needed. See [`docs/server-deployment.md`](./docs/server-deployment.md).

---

## Usage

### CLI

```bash
# Analyze — common forms
oxide-sloc analyze ./my-repo                            # colored summary
oxide-sloc analyze ./my-repo --plain                    # machine-readable key=value (CI-friendly)
oxide-sloc analyze ./my-repo -j out.json -H out.html -c out.csv -x out.xlsx
oxide-sloc analyze ./my-repo --per-file
oxide-sloc analyze ./my-repo --fail-on-warnings --fail-below 10000
oxide-sloc analyze ./my-repo --enabled-language rust --enabled-language python
oxide-sloc analyze ./my-repo --submodule-breakdown
oxide-sloc analyze ./my-repo --per-file --activity-window 90    # Git Hotspots (0 disables)

# Other commands
oxide-sloc report result.json -H report.html --pdf-out report.pdf
oxide-sloc diff baseline.json current.json -j delta.json
oxide-sloc serve                                        # http://127.0.0.1:4317
oxide-sloc init                                         # creates .oxide-sloc.toml
oxide-sloc send result.json --smtp-to team@example.com --smtp-host smtp.example.com
```

Run `oxide-sloc <command> --help` for the full flag list.

### Web UI

```bash
oxide-sloc serve   # → http://127.0.0.1:4317
```

A guided 4-step flow: select project → counting rules → outputs → review & run. **Quick Scan** submits from step 1 with all defaults. Reports include a ranked **Git Hotspots** table (when run against a git repo) alongside the SLOC, complexity, and COCOMO breakdowns.

Additional pages: **Test Metrics** (`/test-metrics`), **Trend Reports** (`/trend-reports`), **Compare Scans** (`/compare-scans`), and the **Git Browser** (`/git-browser`) for scanning any branch, tag, or commit.

### Configuration

```bash
oxide-sloc init    # generates .oxide-sloc.toml with all options documented inline
```

IEEE 1045-1992 counting parameters — `mixed_line_policy`, `continuation_line_policy`, `blank_in_block_comment_policy`, `count_compiler_directives` — are configurable via TOML or CLI flags. CLI flags always override config file values.

---

## Supported Languages (60)

Ada, Assembly, Awk, C, C++, C#, Clojure, CMake, Crystal, CSS, D, Dart, Dockerfile, Elixir, Elm, Erlang, F#, Fortran, GLSL/HLSL, Go, GraphQL, Groovy, Haskell, HCL/Terraform, HTML, Java, JavaScript, Julia, Kotlin, Lisp/Scheme, Lua, Makefile, Nim, Nix, Objective-C, OCaml, Pascal/Delphi, Perl, PHP, PowerShell, Protocol Buffers, Python, R, Ruby, Rust, Scala, SCSS/Sass, Shell, Solidity, SQL, Svelte, Swift, Tcl, TypeScript, Verilog/SystemVerilog, VHDL, Visual Basic, Vue, XML/SVG, Zig.

> TOML, Markdown, and YAML are intentionally not supported — no meaningful SLOC metric applies.

---

## Metrics API

| Endpoint | Description |
|---|---|
| `GET /api/metrics/latest` | Metrics for the most recent scan |
| `GET /api/metrics/:run_id` | Metrics for a specific run |
| `GET /api/project-history?path=<dir>` | Scan history for a project root |
| `GET /badge/:metric` | SVG badge (`code-lines`, `files`, `comment-lines`, `blank-lines`) |
| `GET /embed/summary` | Embeddable HTML widget |
| `GET /healthz` | Health check |

Full OpenAPI 3.1 spec: `GET /api/openapi.yaml` or [`docs/openapi.yaml`](./docs/openapi.yaml).

```markdown
![Code Lines](http://your-host:4317/badge/code-lines)
```

---

## CI/CD

| Platform | File |
|---|---|
| GitHub Actions | `ci/sloc-github-action.yml` — copy to `.github/workflows/` |
| GitHub Marketplace | `uses: NimaShafie/oxide-sloc@main` (see [`action.yml`](./action.yml)) |
| Jenkins | `testing/examples/jenkins/Jenkinsfile` |
| GitLab CI | `ci/sloc-gitlab.yml` — include via `include:` |
| Bitbucket Pipelines | `testing/examples/bitbucket/bitbucket-pipelines.yml` |
| Azure Pipelines | `testing/examples/azure/azure-pipelines.yml` |

**Marketplace action:**

```yaml
- uses: NimaShafie/oxide-sloc@main
  id: sloc
  with:
    path: .
    html-out: sloc-out/report.html
- run: echo "Code lines ${{ steps.sloc.outputs.code-lines }}"
```

For Jenkins/GitLab setup, Confluence publishing, and artifact repository integration, see [`docs/ci-integrations.md`](./docs/ci-integrations.md).

---

## LAN Server

```bash
bash scripts/serve-server.sh              # open, prints every LAN address
bash scripts/serve-server.sh --with-auth  # generates a session key, requires login
```

See [`docs/server-deployment.md`](./docs/server-deployment.md) for persistent deployments, TLS, and firewall configuration.

---

## Development

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo build --workspace
cargo test --workspace
cargo run -p oxide-sloc -- serve    # http://127.0.0.1:4317
```

---

## Repository Layout

```
crates/
  sloc-cli/         # CLI entry point and commands (binary: oxide-sloc)
  sloc-config/      # Config schema and TOML parsing
  sloc-core/        # File discovery, decoding, aggregation, delta engine, COCOMO/hotspots
  sloc-git/         # Git CLI wrappers, webhook parsing, scan-schedule store
  sloc-languages/   # Language detection, lexical analyzers, symbol counting
  sloc-report/      # HTML rendering, PDF/CSV/Excel export
  sloc-web/         # Axum web server, metrics API, badge endpoint
  sloc-mcp/         # MCP stdio server for AI agent integration
ci/                 # CI scripts + config presets
docs/               # airgap.md, ci-integrations.md, server-deployment.md, openapi.yaml
dist/               # Windows pre-built binary (committed by CI after each release)
scripts/            # run.sh, serve-server.sh (user-facing entry points)
testing/            # fixtures/ (scan sample repo) + examples/ (CI configs, sloc.example.toml)
```

---

## AI Integration

The `sloc-mcp` binary implements the [Model Context Protocol](https://modelcontextprotocol.io), making oxide-sloc callable as a tool from Claude Desktop, Claude Code, and any MCP-compatible host.

```bash
cargo build -p sloc-mcp
```

**Claude Code** (project `.mcp.json`):
```json
{ "mcpServers": { "oxide-sloc": { "command": "sloc-mcp" } } }
```

Available tools: `analyze_path` · `get_metrics_latest` · `get_metrics_history` · `get_run_metrics` · `compare_runs` · `health_check` · `ingest_result`

Pre-built tool definitions for Claude API (`tool_use`) and OpenAI (`function_calling`): [`docs/mcp/`](./docs/mcp/). A running server also exposes `GET /llms.txt` and `GET /llms-full.txt` for agent self-discovery.

---

## License

**oxide-sloc** is licensed under [AGPL-3.0-or-later](./LICENSE).
Copyright (C) 2026 Nima Shafie.

---

**Nima Shafie** — [github.com/NimaShafie](https://github.com/NimaShafie)
