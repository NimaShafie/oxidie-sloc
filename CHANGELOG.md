# Changelog

All notable changes to oxide-sloc are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

---

## [1.5.4] — 2026-05-15

### Added

- **Tree-sitter symbol counting** (`sloc-languages`): Python AST walks now count functions,
  classes, test functions/classes, and assertion calls using tree-sitter. A new `SymbolKinds`
  struct drives per-language counting configuration; the C/C++ path returns `SymbolKinds::none()`
  (no behavioural change for C).
- **Auth integration tests** (`sloc-web`): 30+ new integration tests covering `auth/login` GET
  and POST, Bearer and `X-API-Key` header auth, export/import config (valid and malformed TOML),
  scan profile CRUD, schedule deletion, metrics and submodule endpoints, GitHub webhook smoke,
  metrics history, and error-module JSON shape (`not_found`, `bad_request`, `422`). New
  `make_test_router_with_key()` entry point supports auth-enabled test scenarios.
- **Jenkins graphical report enhancements** (`ci/jenkins/generate-dashboard.py`): Added a
  per-language metrics table (code / comment / blank / files columns) below the bar chart, a
  "Top Files by Code Lines" card (top 20 files from `per_file_records`), and a "Code Lines Δ"
  stat chip showing the SLOC delta between the two most recent builds when trend history has ≥ 2
  entries. Inline `<style>` extracted to a sidecar `dashboard_<slug>.css` file so the report
  renders under Jenkins' default artifact-viewer CSP without requiring a credential binding or
  `init.groovy.d`.

### Changed

- **Jenkins pipeline — SonarQube stage removed** (`Jenkinsfile`): `SKIP_SONAR`, `SONAR_URL`, and
  `GENERATE_COVERAGE` pipeline parameters and the entire SonarQube scan stage are removed.
  SonarQube analysis is now run externally via `ci/sonar/` scripts driven by the `SONAR_URL` and
  `SONAR_TOKEN` environment variables. See `docs/sonarqube-manual-setup.md` for setup
  instructions. The Graphical Report sidebar link is promoted above the SLOC Report link.
- **Jenkins CSP handling** (`ci/jenkins/`): The Content-Security-Policy override moved from an
  in-pipeline `System.setProperty` call (blocked by the Pipeline sandbox) to a startup Groovy
  script at `ci/jenkins/init.groovy.d/relax-csp.groovy`, which executes during Jenkins boot.
- **`sloc-config` serde defaults** (`crates/sloc-config/src/lib.rs`): All fields in
  `DiscoveryConfig`, `AnalysisConfig`, `ReportingConfig`, and `WebConfig` are annotated with
  `#[serde(default)]`; partial TOML files (e.g. CI presets that omit infrequently-set keys)
  now deserialize without errors.
- **CI preset TOMLs** (`ci/sloc-ci-*.toml`): All three presets (`default`, `full-scope`,
  `strict`) now explicitly declare `enabled_languages`, `extension_overrides`, and
  `shebang_detection` for self-documenting completeness.
- **Windows install path** (`scripts/`): `run.sh` on Windows now extracts the pre-built binary
  from `dist/oxide-sloc-windows-x64.zip` rather than bootstrapping the full Rust toolchain;
  air-gap Windows deployments require no compiler and no `toolchain/` archives.
- **`install.sh` relocated** (`scripts/internal/install.sh`): Moved from the repository root to
  `scripts/internal/`; `run.sh` updated to invoke the new path.
- **Jenkins trend sparkline** (`ci/jenkins/generate-dashboard.py`): Build-trend card moved before
  the Language Breakdown card for visual prominence; SLOC trend values persist across builds via
  the dashboard history store.

### Fixed

- **Jenkins HTML Publisher CSP** (`ci/jenkins/init.groovy.d/relax-csp.groovy`): The relaxed
  Content-Security-Policy is now applied at Jenkins startup rather than inside the pipeline,
  preventing sandbox rejections and ensuring the policy is in place before the first build runs.
- **Jenkins build description format** (`Jenkinsfile`): Build description now uses plain text;
  removes Jenkins HTML-injection warnings that appeared in the build log.
- **Web auth handler visibility** (`sloc-web`): Auth handlers reverted to `pub(crate)` to
  suppress the `redundant_pub_crate` Clippy warning introduced when the auth module was extracted.
- **RHEL unprivileged firewall check** (`scripts/`): Removed a `firewall-cmd --state` call that
  failed with a permission error when run as a non-root user on RHEL 8/9.

### Documentation

- **Jenkins manual setup** (`docs/jenkins-manual-setup.md`): Step 5b credential instructions
  replaced with a note explaining that `sonarqube-oxide-sloc-token` is no longer consumed by the
  current Jenkinsfile. Troubleshooting section rewritten to reflect the external-script SonarQube
  path; `SKIP_SONAR` references removed.
- **Jenkins README** (`ci/jenkins/README.md`): Job-name instructions clarified — `oxide-sloc` is
  the single canonical SCM-driven job; the `oxide-sloc-manual` name carries no special meaning.

---

## [1.5.1] — 2026-05-12

### Fixed

- **install.sh CA cert import** (`scripts/install.sh`): The self-signed Authenticode CA
  certificate is now imported silently without prompting the user; previous behaviour
  popped a native Windows security dialog mid-install.
- **CI cargo-cyclonedx flag** (`.github/workflows/release.yml`): Corrected an invalid
  flag passed to `cargo cyclonedx` that caused SBOM generation to fail; `build.rs` is
  now formatted to satisfy the `rustfmt` CI gate.

### Added

- **Windows CA cert trust — no Admin required** (`scripts/install.sh`): `install.sh`
  auto-detects the self-signed Authenticode CA certificate committed to `deploy/certs/` and
  offers to import it into the current user's certificate store using `certutil -addstore
  -user`, which requires no Administrator elevation.
- **Self-signed Authenticode cert + generator** (`deploy/certs/`, `scripts/internal/`): A
  self-signed code-signing certificate and companion generation script are committed to
  the repository so Windows builds can be Authenticode-signed immediately without waiting
  for a commercial CA.
- **Authenticode signing, SLSA provenance, and dist commit** (`release.yml`): The release
  workflow now signs `oxide-sloc.exe` with the committed certificate, attaches SLSA
  provenance, and commits the signed binary to `dist/` for air-gapped Windows deployments.
- **Windows test job** (`ci.yml`): A `windows-latest` test job is added to the CI matrix,
  covering `cargo test --workspace` on Windows and closing the gap where signing-related
  code was only tested on Linux runners.

---

## [1.5.0] — 2026-05-12

### Added

- **Multi-format coverage parsing** (`sloc-core/coverage.rs`): Added auto-detecting coverage parsers
  for Cobertura XML (`pytest-cov`, Maven Cobertura plugin), JaCoCo XML (Gradle, Maven JaCoCo plugin),
  and Istanbul/NYC JSON (`nyc --reporter=json-summary`, Jest) alongside existing LCOV. The new
  `parse_coverage_auto()` function dispatches to the correct parser by file extension and content
  sniff — `.xml` files are distinguished by `<coverage` vs `<report` header, `.json` goes to the
  Istanbul parser, and all other extensions fall back to LCOV.
- **`/api/suggest-coverage` endpoint** (`sloc-web`): Returns the inferred coverage file path(s)
  and the recommended generation command for a given project root. `detect_coverage_tool()` examines
  the directory tree for `Cargo.toml`, `pom.xml`, `build.gradle`, `package.json`, and other build
  files to select the correct tool and command hint. The web file picker now accepts all four
  coverage formats (LCOV `.info`, Cobertura `.xml`, JaCoCo `.xml`, Istanbul `.json`).
- **Test Metrics stat-chip summary strip** (`sloc-web`): Replaced the single test-density badge
  on the `/test-metrics` page with a four-chip summary strip: test-to-code density, most-tested
  language, number of languages with tests, and overall line coverage percentage.
- **`cov-gauge-card` coverage components** (`sloc-web`): Coverage display upgraded from a plain
  percentage text to animated `cov-gauge-card` components showing label, large percentage value,
  and an animated progress-bar track; cards lift on hover.
- **Trend report table enhancements** (`sloc-web`): The scan-history table in `/trend-reports`
  gains sortable columns (click header to sort ascending/descending with ↕/↑/↓ icons),
  column-resize handles, and a client-side filter row.
- **Trend report stat chips** (`sloc-web`): Summary chips above the trend chart now show Total
  Scans, Latest metric value, Net Change (with `+`/`−` colour coding), and Projects count.

### Changed

- **Artifact URL segment order** (`sloc-web`): Run artifact URLs swapped from
  `/runs/{run_id}/{artifact}` to `/runs/{artifact}/{run_id}` across all URL construction sites,
  route definitions, Confluence push, git_browser, and integrations handlers.
- **Run-ID chips** (`sloc-report`): Run-ID banners on the report page switch to `position:fixed`
  so they repeat on every printed/PDF page; chips lift on hover and show a click-to-copy tooltip.
  Print margins are widened when `report_header_footer` is set.
- **Support-opportunities table** (`sloc-report`): Description and Example columns now wrap with
  styled example-file badges instead of overflowing.
- **Per-file table scrollbar** (`sloc-report`): `overflow-y:scroll` is forced on per-file and
  skipped-file tables to keep the scrollbar gutter permanently allocated; a JS IIFE measures the
  actual scrollbar track width and compensates table padding.
- **Per-file table column widths** (`sloc-report`): All columns corrected to sum to ~98% so no
  column overflows under the scrollbar.
- **PDF print output** (`sloc-report`): Print zoom set to 0.82, chart spacing tightened, and
  the scatter chart rendered in a single-column centred layout.
- **Nav dropdown gap** (`sloc-web`, `sloc-report`): Added `::after` pseudo-element bridge on
  dropdown triggers so the hover state is not lost when moving the cursor from the trigger pill
  to the menu; nav pills and brand logo gain `white-space:nowrap` / `flex-shrink:0` to prevent
  wrapping on narrow viewports.
- **CLI headless-chrome noise** (`sloc-cli`): Suppressed `headless_chrome` crate transport log
  lines from the default tracing filter so PDF generation does not pollute terminal output.

---

## [1.4.3] — 2026-05-07

### Added

- **Browser-based login form** (`/auth/login`): New GET/POST route that lets browsers
  authenticate with the API key via a sign-in form. A successful sign-in sets an
  `HttpOnly; SameSite=Strict` session cookie (`sloc_session`) so subsequent page loads
  don't require header injection. Unauthenticated browser requests are now redirected to
  `/auth/login` instead of returning a bare `401`.
- **Configurable auth lockout** (`SLOC_AUTH_LOCKOUT_FAILS`, `SLOC_AUTH_LOCKOUT_SECS`):
  Auth-failure lockout threshold and window are now configurable via environment variables
  (defaults: 10 failures / 3600 s). The `Retry-After` response header on lockout replies
  now reflects the actual remaining seconds rather than a hardcoded value.
- **Firewall auto-open** (`--open-firewall`, `scripts/serve-server.sh`): New flag that
  automatically opens the server port via `firewall-cmd` or `ufw` (using `sudo`) when a
  blocking Linux firewall rule is detected.
- **Chart hover tooltips and entry animations** (`sloc-report/lib.rs`): Donut segments and
  bar chart rows animate on page load and display a floating, theme-aware tooltip (language
  name, code lines, percentage) on hover. SVG charts set `overflow:visible` so hover
  scaling remains fully visible.

### Fixed

- **PDF print layout** (`sloc-report/lib.rs`): Changed `@page` CSS to A4 landscape for
  better table rendering; released sticky column positioning in print media; set
  `min-width:0` on per-file and skipped-files tables so they scale to page width; set
  label `white-space:normal` to prevent line-content truncation in print.
- **Nav dropdown gap** (`sloc-report/lib.rs`): Added `padding-bottom:6px` to
  `.nav-dropdown-wrap` and changed menu `top` from `calc(100% + 6px)` to `100%`, removing
  the mouse-gap that caused the dropdown to close before the cursor reached it.
- **install.sh offline by default** (`scripts/install.sh`): Network access now requires
  the explicit `--online` flag; `--offline` is kept as a backward-compatible no-op. Fixed a
  `set -euo pipefail` × `grep` interaction that could silently abort the script when
  `SHA256SUMS.txt` contained no matching entry.
- **docker-compose.yml YAML** (`docker-compose.yml`): Switched `environment` block from
  list to map syntax to fix a parse error on Compose v2.

### Changed

- **`serve-server.sh` banner** (`scripts/serve-server.sh`): Banner now shows the browser
  URL, the login-form URL (when `SLOC_API_KEY` is set), lockout configuration hints, and
  the `curl` test command using the real LAN IP.
- **Super-repo compare scope** (`/compare-scans`): New `?scope=super` query parameter
  filters the diff to super-repo files only (excludes submodule files). The `/view-reports`
  page shows a scope pre-selection panel when two rows with submodule data are selected.
- **Submodule chips in history table** (`sloc-web/lib.rs`): Submodule names shown as chips
  in the history table; overflow truncated to 4 + "+N more".
- **LAN diagnostics** (`scripts/serve-server.sh`): `check_firewall()` probes `firewall-cmd`
  then `ufw` and prints the exact fix command when port `4317/tcp` is blocked;
  `get_primary_ip()` now uses `ip route get 1.1.1.1` to select the default-route interface
  IP, keeping Docker/Podman bridge addresses in a separate banner section.

---

## [1.4.2] — 2026-05-06

### Added

- **Async scan loading modal** (`sloc-web/lib.rs`): Redesigned loading overlay with elapsed
  timer, analysis phase indicator, error/retry UI, and dismiss button. The `analyze_handler`
  now returns an `X-Wait-Id` response header for client-side async tracking.
- **PDF status polling** (`/api/runs/{run_id}/pdf-status`): New endpoint for clients to poll
  PDF generation progress. The PDF button shows a spinner while generating and swaps to a
  live download link on completion.
- **Language icons** (`crates/sloc-web/assets/`): Added icons for Assembly, Go, R, XML,
  Groovy, Dockerfile, Makefile, and Perl. All icons and logos are now compiled into the
  binary via `include_bytes!()`, eliminating the runtime file-serving dependency.
- **Result page UX** (`sloc-report/lib.rs`): Dark/light theme toggle, floating code
  particles, background watermarks, and version footer added to the analysis result page.

### Fixed

- **PDF path on Windows** (`sloc-report/lib.rs`): PDF output now writes to a short temp
  path in `%TEMP%` then renames to the final destination, avoiding `MAX_PATH` failures on
  Windows.

### Changed

- **Dockerfile** updated from `rust:1.85` to `rust:1.95-slim-bookworm`.
- **Report UI polish** (`sloc-report/lib.rs`): Metric card and hero section redesigned with
  larger numbers and accent borders. Per-file table min-width increased to 1150 px with
  adjusted column widths.
- **Dependencies**: `tree-sitter` bumped to 0.26.8; `toml` bumped to 1.1.2 (TOML 1.1
  spec).

---

## [1.4.1] — 2026-05-04

### Added

- **LAN server launcher** (`scripts/serve-server.sh`): Dedicated script to start oxide-sloc in
  server mode (binds to `0.0.0.0:4317`). Auto-generates an API key, prints every LAN address the
  server is reachable on, and shows a ready-made `curl` test command. Also add `--host` flag and
  `SLOC_HOST=1` env var to `run.sh` as an alternative.
- **Auto-install Rust via rustup** (`scripts/install.sh`): When no pre-built binary is found and
  Rust is not installed, the installer now detects internet connectivity and offers to install Rust
  via `rustup`. New `--auto` flag installs without prompting (useful in CI).
- **VirusTotal scanning workflow** (`.github/workflows/vt-scan.yml`): Manual `workflow_dispatch`
  action that uploads compiled release binaries to VirusTotal and publishes a markdown scan report
  as a job summary. Supports both tag mode (scans an existing release) and HEAD mode (builds from
  current branch).
- **Integration test harness** (`crates/sloc-web/tests/integration.rs`): Initial integration test
  suite using the new `make_test_router()` entry point, covering core web routes without a live
  TCP binding.
- **`/locate-reports-dir` route**: New web endpoint to open a native directory-picker dialog
  specifically for selecting a reports output directory.

### Fixed

- **Webhook payload hardening** (`sloc-git/webhook.rs`): Replaced silent empty-string fallbacks
  with proper error propagation in all three webhook parsers (GitHub, GitLab, Bitbucket). Malformed
  or incomplete payloads now return descriptive errors instead of silently triggering scans with
  blank repository URLs or commit SHAs.
- **`ScanScheduleProvider` serialization** (`sloc-git/schedule.rs`): Changed from
  `rename_all = "snake_case"` to explicit per-variant `serde(rename = …)` attributes to ensure
  correct lowercase round-trip serialization (`github`, `gitlab`, `bitbucket`, `any`).
- **Git ref date format** (`sloc-git/ops.rs`): Changed `--format` date specifier from `iso8601`
  to `iso-strict` (RFC 3339) for branch and tag listing, fixing date parsing in environments
  where the `iso8601` alias is not available.
- **Git shallow clone depth** (`sloc-git/ops.rs`): Added `--depth=50` to `clone_or_fetch` so
  the git browser does not download the full history of large repositories.
- **PDF page layout** (`sloc-report/lib.rs`): Changed `@page` CSS from A4 landscape to A4
  portrait with tighter margins; fixes reports that were clipped or had excessive whitespace when
  exported to PDF.
- **Print page-break control** (`sloc-report/lib.rs`): `.hero` moved to `break-inside: auto`
  so large summary tables are not forced onto a single page, preventing blank-page artefacts.
- **CSP nonce plumbing** (`sloc-report/lib.rs`): Added `nonce` field to `ReportTemplate` and
  `nonce="{{ nonce }}"` attribute on the inline `<style>` tag so the web server can inject a
  per-request Content-Security-Policy nonce.

### Changed

- **Scripts reorganisation**: Internal maintenance scripts (`airgap-build.sh`,
  `clippy_to_sonar.py`, `install-hooks.sh`, `make-airgap-kit.sh`, `update-vendor.sh`,
  `vt-scan.py`) moved to `scripts/internal/`. All CI workflow references updated accordingly.
- **Router extraction** (`sloc-web/lib.rs`): `build_router()` extracted from `serve()` and made
  separately callable; `make_test_router()` added as a public entry point for test code.
- **README**: Added "Host on your LAN" section documenting `serve-server.sh`, firewall commands,
  and authentication usage for LAN deployments.

---

## [1.4.0] — 2026-05-03

### Added

- **Automated scanning via webhooks**: New `/webhook-setup` UI and `/webhooks/{github,gitlab,bitbucket}`
  receivers. Each schedule gets a unique HMAC-SHA256 secret; incoming push events are verified and
  trigger an automatic clone + scan without any manual action.
- **Polling-based scheduled scans**: Schedules can run on a configurable interval (seconds). The
  server compares the current HEAD SHA against the last-scanned SHA and only runs a scan when the
  branch has advanced. Poll tasks are restarted automatically on server boot from persisted state.
- **Git browser UI** (`/git-browser`): Browse branches, tags, and recent commits of any remote
  repository from the web UI. Each row has a **Scan** button; selecting two rows triggers a
  side-by-side SLOC comparison.
- **Point-in-time comparison across CLI, web, and Jenkins**:
  - CLI: `oxide-sloc git-scan <repo> <ref>` and `oxide-sloc git-compare <repo> <baseline> <current>`
  - CLI: `oxide-sloc watch <repo> <branch> --interval <secs>` for continuous local polling
  - Jenkins: `GIT_REF`, `COMPARE_TO_REF`, and `COMPARE_TO_PREV_TAG` parameters; new
    "Git-Ref Scan" and "Git-Ref Compare" stages produce `ref-scan.json`, `diff.json`, `diff.csv`
- **`sloc-git` crate** (new, first published to crates.io): git CLI wrappers
  (`clone_or_fetch`, `list_refs`, `create_worktree`, `destroy_worktree`, `get_sha`, `list_commits`),
  HMAC-SHA256 webhook verification via `ring`, and a JSON-persisted `ScheduleStore`.
- **SonarQube CI integration**: `clippy_to_sonar.py` converts Clippy JSON output to the
  SonarQube Generic Issue format; Jenkins pipeline now includes a SonarQube scan stage with
  coverage upload via `cargo-llvm-cov`.
- **`cargo-llvm-cov` vendored** for air-gapped coverage generation.

### Fixed

- **Docker hardening**: Multiple Dockerfile findings resolved — replaced `COPY . .` with explicit
  file copies, inlined `.cargo/config.toml` via `RUN`, split overlong `RUN` lines, and corrected
  Python security hotspot.
- **crates.io packaging**: Logo assets (`logo-text.png`, `small-logo.png`) moved into
  `sloc-report/assets/logo/` so the crate compiles correctly when installed via `cargo install`.
- **`sloc-git` metadata**: Added missing `description`, `homepage`, `documentation`, `keywords`,
  and `categories` fields required by crates.io.

---

## [1.3.7] — 2026-05-02

### Changed

- **CLI output helpers**: Extracted `log_written()` helper in `write_outputs()` to eliminate
  repeated quiet-flag checks across all five artifact types (JSON, HTML, PDF, CSV, XLSX).
- **Language analyzer refactoring**: Extracted `step_through_block_comment()`,
  `try_open_block_comment()`, `process_physical_line()`, `track_active_docstring()`,
  `try_record_docstring_if_context()`, `mark_unclosed_docstring_lines()`, and
  `classify_ts_line()` from the generic and Python docstring scanners; removes the
  remaining `#[allow(clippy::too_many_lines)]` attributes on those paths.
- **Web handler refactoring**: Extracted `validate_locate_request()`, `locate_path_hint()`,
  `apply_form_to_config()`, `spawn_pdf_background()`, `sum_added_code_lines()`,
  `sum_removed_code_lines()`, and `build_submodule_row()` from `analyze_handler` and
  `locate_report_handler`; removes the `#[allow(clippy::too_many_lines)]` attribute on
  `analyze_handler`.

---

## [1.3.6] — 2026-05-02

### Fixed

- **SMTP TLS**: Replaced implicit `starttls_relay` builder with an explicit `TlsParameters`
  builder + `Tls::Required`, ensuring certificate validation is enforced and the TLS
  handshake behaviour is unambiguous.
- **Webhook URL validation**: Extended IPv6 blocklist to cover ULA ranges (`fc00::/7`)
  and link-local addresses (`fe80::/10`), which were previously not blocked.
- **PDF temp-dir cleanup**: Replaced manual `create_dir_all` / `remove_dir_all` pair with
  `tempfile::Builder::tempdir()` so the browser profile directory is always cleaned up on
  drop, even when an error is returned mid-function.
- **Rate limiter memory growth**: The in-memory IP tracking map is now pruned when it
  exceeds 10,000 entries, preventing unbounded growth under sustained unique-IP traffic.
- **X-Forwarded-For IP spoofing**: Trusting the `X-Forwarded-For` header for rate limiting
  is now opt-in via `SLOC_TRUST_PROXY=1`; by default, only the socket peer address is used.
- **Auth brute-force**: IPs that exceed 10 failed authentication attempts within an hour are
  locked out for the remainder of that window and receive `429 Too Many Requests`.

### Changed

- **Multi-key authentication**: `SLOC_API_KEYS` (comma-separated list) is now the preferred
  env var; `SLOC_API_KEY` remains supported for backward compatibility. API key values are
  stored in `secrecy::Secret` to prevent accidental logging.
- **CORS policy**: In `--server` mode the CORS layer now defaults to deny-all; set
  `SLOC_ALLOWED_ORIGINS` (comma-separated) to allow specific origins. In local (non-server)
  mode, only `http://127.0.0.1:*` and `http://localhost:*` are permitted.
- **GitHub Actions permissions**: Moved `contents: write` from the workflow-level default to
  only the `publish` job; all other jobs receive `contents: read` (principle of least
  privilege).
- **Dockerfile**: Removed unused `wget` from the runtime image; replaced the `wget`-based
  `HEALTHCHECK` with `oxide-sloc healthz`.
- **docker-compose.yml**: Added container hardening — `cap_drop: ALL`,
  `no-new-privileges: true`, `read_only: true`, and a 64 MiB `/tmp` tmpfs mount.
- **Structured tracing**: Added `tracing::warn!` / `tracing::info!` events for auth
  failures, auth lockouts, rate-limit hits, path rejections, and completed scans.

---

## [1.3.5] — 2026-05-02

### Fixed

- **Jenkins build description**: Build description now correctly reads `params.SCAN_PATH`
  instead of `env.SCAN_PATH`, which was always null and produced blank descriptions.
- **Docker build**: Added `xz-utils` to the builder stage so `tar -xJf vendor.tar.xz`
  succeeds in environments where `xz` is not pre-installed.

---

## [1.3.0] — 2026-05-01

### Added

- **Air-gap build kit** (`scripts/make-airgap-kit.sh`): generates a fully self-contained
  offline build archive bundling the Rust host toolchain, musl Rust std, musl C toolchain
  (musl-gcc from musl.cc), all crate vendor sources, and a self-contained `install.sh`.
  The kit builds a fully static binary on air-gapped Linux systems with no pre-installed
  Rust, no C compiler, and no internet access required.

### Changed

- Repository layout migrated to standard skeleton: CI scripts moved to `ci/` (`lint.sh`,
  `build.sh`, `test.sh`, `release.sh`), launcher scripts moved to `scripts/`, sample
  fixtures moved to `tests/fixtures/basic/`, and image assets moved to `docs/assets/`.
- `vendor.tar.xz` is no longer committed to git; it is generated by the `vendor` job in
  the release workflow and attached as a GitHub release asset.
- `docs/airgap.md` restructured around four clearly labelled transfer paths, with the
  fully self-contained kit as the primary recommended option.
- Added `CODE_OF_CONDUCT.md`, `.github/dependabot.yml`, `clippy.toml`, `deny.toml`.

---

## [1.2.8] — 2026-05-01

### Changed

- Resolved 162 remaining SonarQube findings (16 HIGH, 146 MEDIUM) from the v1.2.7 rescan:
  - **Cognitive complexity (rust:S3776, 15 HIGH)**: Reduced cognitive complexity across 15 functions by extracting focused helper functions — `detect_by_shebang`, `detect_by_extension`, `scan_line`, `finalize_line_facts`, `process_string_char`, `process_block_comment_char`, `walk_root`, `process_submodules`, `assemble_run`, `check_metadata_policy`, `decode_file_contents`, `write_outputs`, `check_exit_conditions`, `build_browser_args`, `wait_for_pdf_stable`, `validate_server_scan_path`, `locate_report_error`, `build_run_registry_entry`, and others; `// NOSONAR` added to irreducibly complex state-machine functions
  - **`too_many_lines` (30)**: Added `#[allow(clippy::too_many_lines)]` to `print_summary`, `compute_delta`, `analyze_text`, `write_xlsx`, `compare_handler`, `build_preview_html`, and all functions also addressed by cognitive-complexity extraction
  - **`multiple_crate_versions` (68)**: Added `#![allow(clippy::multiple_crate_versions)]` at crate-root level in `sloc-cli`, `sloc-core`, `sloc-report`, and `sloc-web` — these are transitive dependency version conflicts outside project control
  - **`similar_names` (30)**: Added `#[allow(clippy::similar_names)]` to `analyze_handler` — abbreviated metric names (`prev_fa`, `prev_cl`, etc.) are idiomatic and intentional
  - **`struct_excessive_bools` (12)**: Added `#[allow(clippy::struct_excessive_bools)]` to `DiscoveryConfig`, `AnalysisConfig`, `ScanConfig` (both crates), `LineFacts`, and `AnalyzeArgs` — all booleans represent independent configuration flags
  - **`trivially_copy_pass_by_ref` (2)**: Changed `ieee: &IeeeFlags` → `ieee: IeeeFlags` in `analyze_generic` (3-byte `Copy` struct); updated all 38 call sites
  - **`zero_sized_map_values` (2)**: Replaced `HashMap<&str, ()>` with `HashSet<&str>` in `compute_delta`
  - **`missing_panics_doc` (2)**: Added `# Panics` section to `serve()`
  - **`python:S1186` (1)**: Added explanatory comment to the intentionally-empty `hello()` corpus test fixture

### Documentation

- **Jenkins bootstrap gaps closed**: Added `ci/jenkins/.env.example` for local credential storage and `ci/jenkins/preflight.sh` pre-flight check script.
- Added "Obtaining credentials" section to `ci/jenkins/README.md` and `docs/ci-integrations.md` covering initial admin password retrieval (native and Docker installs) and API token minting click-path.
- Added native/systemd plugin install path (Jenkins CLI jar) as Path 3 in `ci/jenkins/plugins.txt` and `ci/jenkins/README.md`.
- Rewrote the CLI bootstrap snippet in both docs to use `JENKINS_TOKEN` (sourced from `ci/jenkins/.env`) instead of the bare `JENKINS_PASS` placeholder; dropped the unnecessary cookie jar from token-based authentication.
- Added explicit seed-build curl (`POST /job/${JOB_NAME}/build`) with note that the first build seeds the parameters form.
- Added note that LAN/remote URLs (e.g., `http://10.0.0.8:8080`) are valid and that trailing slashes must be stripped.
- Added job-name decision rule: use `oxide-sloc` for the SCM-driven job; use `oxide-sloc-manual` only when maintaining a parallel hand-edited job in the same instance.
- Added `ci/jenkins/.env` to `.gitignore`.

---

## [1.2.7] — 2026-05-01

### Changed

- Resolved 485 SonarQube findings (16 HIGH, 469 MEDIUM) across all 6 crates with zero remaining actionable issues:
  - Replaced 139 unnecessary struct-name repetitions with `Self` in `impl` blocks
  - Converted 41 `push_str(&format!(...))` calls to `write!()` to avoid intermediate allocations
  - Fixed 22 case-sensitive file-extension comparisons to use `eq_ignore_ascii_case`
  - Added `# Errors` doc sections to all 15 public `Result`-returning functions missing them
  - Merged identical `match` arms, removed redundant closures, inlined format args, and applied `let…else` rewrites throughout
  - Tightened mutex-guard scopes in four `sloc-web` handlers (`significant_drop_tightening`)
  - Converted `resolve_output_root` from `Result<PathBuf>` to `PathBuf` (unnecessary wrap removed)
  - Added `#[allow]` with explanatory context for deliberate narrowing casts in ZIP generation, calendar math, and badge-pixel arithmetic
  - Added intent comment to Python test corpus fixture (`mixed.py`) for empty method

---

## [1.2.0] — 2026-04-29

### Added

**IEEE 1045-1992 physical SLOC compliance**
- The counting engine now implements all configurable parameters defined in IEEE Std 1045-1992 *Software Productivity Metrics*:
  - `continuation_line_policy` / `--continuation-line-policy` (`each-physical-line` | `collapse-to-logical`) — IEEE §3: optionally collapse backslash-continued C macro / shell / Makefile lines into a single logical line count instead of counting each physical line
  - `blank_in_block_comment_policy` / `--blank-in-block-comment-policy` (`count-as-comment` | `count-as-blank`) — IEEE §4: blank lines inside `/* ... */` blocks are classified as comment lines by default (IEEE aligned); `count-as-blank` restores legacy behaviour if needed
  - `count_compiler_directives` / `--no-count-compiler-directives` — IEEE §4.2: `#include`, `#define`, `#ifdef`, and other C/C++/Objective-C preprocessor directive lines are now tracked separately as `compiler_directive_lines` in the raw JSON output; passing `--no-count-compiler-directives` (or setting `count_compiler_directives = false`) excludes them from effective code SLOC while keeping the raw count intact
  - All three parameters are settable in `.oxide-sloc.toml` under `[analysis]` and via CLI flags on `analyze`

**Web server hardening**
- IP-based sliding-window rate limiter (60 requests / 60 seconds per client IP) across all routes — no external crate required; uses only `std` + `Instant`
- Bearer-token authentication via `SLOC_API_KEY` env var — when set, all requests must supply a matching `Authorization: Bearer <key>` or `X-API-Key: <key>` header; startup warning logged when running in server mode without a key
- Native TLS termination via `SLOC_TLS_CERT` / `SLOC_TLS_KEY` PEM env vars (powered by `tokio-rustls` + `rustls`); startup warning logged when `--server` is used without TLS configured
- CORS headers via `tower-http::CorsLayer`
- Response headers middleware (X-Content-Type-Options, X-Frame-Options, Referrer-Policy, etc.)
- Graceful shutdown on `Ctrl+C` (both local and server modes)

**New web routes**
- `GET /view-reports` — scan history browser
- `GET /compare-scans` — side-by-side scan comparison UI
- `GET /embed/summary` — embeddable summary widget (iframe-friendly)

**Webhook URL validation**
- `validate_webhook_url()` now enforces HTTPS and blocks loopback, RFC-1918 private ranges, link-local, and cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`, `*.local`)

**SMTP credential safety**
- `--smtp-pass` on the `send` command now emits a visible warning when used directly; use `SLOC_SMTP_PASS` env var instead to keep credentials out of process listings

**CI/CD build configuration**
- Docker builder and runtime images pinned to SHA-256 digests (`rust:slim@sha256:…`, `debian:bookworm-slim@sha256:…`) — prevents silent base-image substitution
- GitLab CI pipeline switched from curl-piped rustup to the official `rust:slim` pinned image
- `vendor.tar.xz` integrity verified via `sha256sum -c vendor.tar.xz.sha256` before extraction in Dockerfile, GitLab CI, and Jenkinsfile
- Docker image signed with `cosign` (keyless OIDC) and SBOM attached via `docker/build-push-action`; `id-token: write` permission added to `docker.yml`
- Jenkins parameters `SCAN_PATH`, `REPORT_TITLE`, `MIXED_LINE_POLICY` passed through `withEnv` (shell variables, not Groovy interpolation); allowlist validation added for choice and free-text parameters (`MIXED_LINE_POLICY`, `CI_PRESET`, `OUTPUT_SUBDIR`, glob patterns, language names)
- Jenkins CSP relaxation rationale documented inline; alternative of serving HTML from a separate origin noted for high-assurance environments

**Docker**
- `HEALTHCHECK` instruction added — polls `GET /healthz` every 30 s; 5 s timeout; 3 retries
- `SLOC_BROWSER_NOSANDBOX=1` env var added to Docker image — bypasses Chromium kernel-namespace sandbox (required in most container runtimes without `SYS_ADMIN`); documented with guidance on when to disable it
- `wget` added to runtime image (required by `HEALTHCHECK`)

---

## [1.0.0-rc.1] — 2026-04-25

> Release candidate for 1.0.0. Core feature set is complete. Please test and
> report issues — no breaking changes are expected between rc.1 and 1.0.0.

### Added

**Language support — 30 new languages (41 total)**
- Assembly (`.asm`, `.s`)
- Clojure (`.clj`, `.cljs`, `.cljc`, `.edn`)
- CSS (`.css`)
- Dart (`.dart`)
- Dockerfile (`Dockerfile`, `Dockerfile.*`)
- Elixir (`.ex`, `.exs`)
- Erlang (`.erl`, `.hrl`)
- F# (`.fs`, `.fsi`, `.fsx`)
- Groovy (`.groovy`, `.gradle`)
- Haskell (`.hs`, `.lhs`)
- HTML (`.html`, `.htm`, `.xhtml`)
- Julia (`.jl`)
- Kotlin (`.kt`, `.kts`)
- Lua (`.lua`)
- Makefile (`Makefile`, `GNUmakefile`, `.mk`)
- Nim (`.nim`, `.nims`)
- Objective-C (`.m`, `.mm`)
- OCaml (`.ml`, `.mli`)
- Perl (`.pl`, `.pm`, `.t`)
- PHP (`.php`)
- R (`.r`)
- Ruby (`.rb`, `.rake`, `Rakefile`, `Gemfile`)
- Scala (`.scala`, `.sc`)
- SCSS / Sass (`.scss`, `.sass`)
- SQL (`.sql`)
- Svelte (`.svelte`)
- Swift (`.swift`)
- Vue (`.vue`)
- XML / SVG (`.xml`, `.xsd`, `.xsl`, `.svg`)
- Zig (`.zig`)

**New output formats**
- `--csv-out <path>` on `analyze` and `report` — two-section CSV (summary + per-file)
- `--xlsx-out <path>` on `analyze` and `report` — multi-sheet Excel workbook (Summary, By Language, Per File, Skipped); self-contained ZIP+XML implementation, no external dependency
- `--csv-out` / `--xlsx-out` on `diff` — export delta as spreadsheet

**New CLI commands**
- `oxide-sloc diff <baseline.json> <current.json>` — compare two saved scans; prints colored delta summary; supports `--json-out`, `--csv-out`, `--xlsx-out`, `--plain`, `--quiet`
- `oxide-sloc init [PATH]` — generate a starter `.oxide-sloc.toml` with all options documented; `--force` to overwrite

**CLI improvements**
- Short flag aliases: `-j` (`--json-out`), `-H` (`--html-out`), `-c` (`--csv-out`), `-x` (`--xlsx-out`), `-q` (`--quiet`)
- `--open` on `analyze` and `report` — auto-opens the generated HTML in the system browser
- `--quiet` / `-q` — suppress all output except errors (useful in CI pipelines)
- `--fail-on-warnings` — exit with code 2 when warnings are present
- `--fail-below <N>` — exit with code 3 when code lines fall below threshold
- Colored terminal output when stdout is a TTY; suppressed by `NO_COLOR` env var or `--plain`
- Improved per-file and language-breakdown table formatting with aligned columns

**Release pipeline**
- `SHA256SUMS.txt` now included in every GitHub Release alongside the binaries

**Documentation**
- `CONTRIBUTING.md` — development workflow, vendor regeneration, PR checklist
- `SECURITY.md` — vulnerability disclosure policy and scope
- `CHANGELOG.md` (this file)

**Shebang detection extended** to Ruby, Perl, PHP, and Node.js scripts

---

## [0.2.0-beta.4] — 2026-04-24

### Changed
- Removed security commentary from source; pinned CI GitHub Actions to specific SHAs
- Applied `rustfmt` to `sloc-report` and `sloc-web` to pass CI format check
- Refreshed dist bundles (`[skip ci]`)

---

## [0.2.0-beta.3] — earlier

### Added
- `oxide-sloc serve --server` mode (binds `0.0.0.0`, suppresses browser auto-open)
- `oxide-sloc send` — SMTP and webhook delivery of saved JSON results
- Git metadata capture (`git_branch`, `git_commit_short/long`, `git_commit_author`, `git_tags`)
- Submodule breakdown (`--submodule-breakdown`)
- Delta computation in `sloc-core` (compare two `AnalysisRun` JSON files)
- Scan history/registry in `sloc-core` for the web UI
- PDF export via headless Chromium (`write_pdf_from_html`)
- Self-contained HTML report with light/dark theme toggle
- `run.sh` cross-platform launcher

### Fixed
- UTF-16 LE/BE and Windows-1252 encoding fallback during file discovery

---

## [0.1.0] — initial release

- CLI with `analyze`, `report`, `serve` subcommands
- JSON and HTML output formats
- 11 languages: C, C++, C#, Go, Java, JavaScript, Python, Rust, Shell, PowerShell, TypeScript
- Lexical state-machine analyzer with Python docstring classification
- Tree-sitter adapter scaffold (C and Python, behind `tree-sitter` feature flag)
- Axum web UI on `127.0.0.1:4317`
- GitHub Actions CI (fmt + clippy + build + test + smoke tests)
- Cross-platform release builds (Linux x86_64 musl, Windows x86_64 MSVC, macOS x86_64 + arm64)
