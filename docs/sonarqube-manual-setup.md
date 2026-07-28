# Running the SonarQube scan locally (no Jenkins)

This document shows how to run the oxide-sloc SonarQube analysis from a
developer workstation or any host that can reach the SonarQube server — no
Jenkins required.

## Supported SonarQube version

Tested against **SonarQube Server 26.4.0.121862** (Community Edition) with
the built-in Rust analyzer enabled.  The minimum supported version is
**SonarQube 10.x** (any edition that ships the Rust community sensor).

The Rust analyzer is bundled in SonarQube 10+ and does not require a
separate plugin download.

## Prerequisites on the host

| Requirement | Notes |
|---|---|
| Rust toolchain | Auto-bootstrapped by `bash scripts/run.sh`; see `docs/airgap.md` |
| `gcc` + system devel packages | Required by `--all-features` (activates the `rfd` crate via `native-dialog`) |
| Docker | Runs the `sonarsource/sonar-scanner-cli` image |
| SonarQube analysis token | See [Generating a token](#generating-a-token) |

### System devel packages for `--all-features`

The `--all-features` flag activates the optional `rfd` crate, which pulls in
`wayland-sys`, `gtk3`, and `libxdo` at compile time and requires their
development headers on the build host.

```bash
# RHEL / Rocky / Alma Linux
sudo dnf install gtk3-devel libxdo-devel wayland-devel

# Debian / Ubuntu
sudo apt install libgtk-3-dev libxdo-dev libwayland-dev
```

### Generating a token

1. Open **SonarQube → Project → Administration → Analysis Method → Locally**
2. Click **Generate token**, give it a name (e.g. `local-scan`), and copy
   the value — it is shown only once.

Export it as an environment variable before running any scan step:

```bash
export SONAR_TOKEN="sqa_xxxxxxxxxx..."
```

## Scan steps

Run each command from the repository root.

### Step 1 — Clippy (external-issues source)

> **Cold cache first — or the report silently under-reports.** `cargo clippy`
> reuses its warm cache and only re-lints crates that changed since the last build,
> so a warm run can emit findings for only *some* workspace members and a
> verification then passes vacuously. Force a cold lint of every crate first:
>
> ```bash
> cargo clean -p sloc-config -p sloc-languages -p sloc-core -p sloc-report \
>             -p sloc-git -p sloc-web -p sloc-mcp -p oxide-sloc
> ```
>
> There is **no `sloc-cli` package** — the binary crate in `crates/sloc-cli/` is
> named `oxide-sloc`, so `cargo clean -p sloc-cli` fails and cleans nothing. A plain
> `cargo clean` also works but rebuilds everything.

```bash
cargo clippy --workspace --all-targets --all-features \
    --message-format=json --offline \
    -- -W clippy::pedantic -W clippy::nursery \
       -A clippy::multiple_crate_versions \
    > clippy.json 2> clippy.stderr || true

python3 scripts/internal/clippy_to_sonar.py clippy.json clippy-sonar.json "$PWD"
```

`clippy_to_sonar.py` also drops findings that would be false positives against
production-code rules before they are imported: any finding under a `tests/`
directory, plus `clippy::multiple_crate_versions` (a workspace-level artifact). It
filters by **file path**, so clippy findings inside inline `#[cfg(test)]` modules in
`src/*.rs` are *not* dropped — harmless under the pedantic/nursery flags above (test
code is clean there), relevant only if the lint set is tightened. See the comment in
`scripts/internal/clippy_to_sonar.py`.

### Step 2 — Coverage (LCOV + Cobertura)

```bash
mkdir -p ci-out/coverage
bash ci/sonar/generate-coverage.sh ci-out/coverage
ln -sfn ci-out/coverage coverage
```

`cargo-llvm-cov` must be installed (vendored in `ci/tools/Cargo.toml` for
air-gapped agents):

```bash
# Online install
cargo install cargo-llvm-cov
rustup component add llvm-tools

# Offline install (air-gapped; requires vendor/ directory)
cargo install --offline cargo-llvm-cov
rustup component add llvm-tools
```

Coverage is optional — the scanner silently skips missing report files.

> **Regenerate coverage for the exact commit you are scanning.** Reusing an
> `lcov.info` from an earlier commit makes `new_coverage` unreliable: its line
> numbers no longer align with edited files, so the figure drifts (and near the 80%
> gate that can flip pass/fail on noise, not real coverage). If `cargo-llvm-cov`
> isn't available on the scan host, generate coverage in CI (the `coverage` job in
> `.github/workflows/ci.yml`) and pull the fresh `lcov.info` — do not treat a reused
> report as authoritative.

### Step 3 — Scanner container

```bash
SONAR_HOST=http://localhost:9000   # adjust to your server address

docker run --rm --network host \
    -e SONAR_TOKEN \
    -v "$PWD":/usr/src -w /usr/src \
    sonarsource/sonar-scanner-cli:latest \
    sonar-scanner \
        -Dsonar.host.url="$SONAR_HOST" \
        -Dproject.settings=ci/sonar/sonar-project.properties
```

`--network host` is required so the container can reach a SonarQube server
running on the host's LAN interface (e.g. `http://10.x.x.x:9000`).

### Step 4 — View results

Open `$SONAR_HOST/dashboard?id=oxide-sloc` in a browser.

### Step 5 — Verify test/main classification and clippy suppression

Confirm the `ci/sonar/sonar-project.properties` scoping is behaving. These queries
need an **admin** login — an analysis token gets `Insufficient privileges` on
`api/components/tree`.

```bash
ADMIN="admin:<password>"

# Test files should total 14 (UTS); main files 45 (FIL).
curl -s -u "$ADMIN" \
  "$SONAR_HOST/api/components/tree?component=oxide-sloc&qualifiers=UTS&ps=500" \
  | jq -r '.paging.total'   # expect 14
curl -s -u "$ADMIN" \
  "$SONAR_HOST/api/components/tree?component=oxide-sloc&qualifiers=FIL&ps=500" \
  | jq -r '.paging.total'   # expect 45
```

For clippy suppression, two API gotchas will otherwise produce a false result:

- **Pass `resolved=false`.** Without it the search also returns CLOSED/stale issues
  from earlier scans, so a test file can report hundreds of already-resolved
  `external_clippy` issues and look like a failure when the live count is 0.
- **Don't trust `.total` for a client-side filter, and don't let the default page
  size truncate.** Fetch with `ps=500` and count client-side.

```bash
# Live clippy issues on a test file — expect 0 (filtered in the converter).
curl -s -u "$ADMIN" \
  "$SONAR_HOST/api/issues/search?componentKeys=oxide-sloc:crates/sloc-web/tests/integration.rs&resolved=false&ps=500" \
  | jq '[.issues[]|select(.rule|startswith("external_clippy:"))]|length'   # expect 0

# Sanity that the import path still works — main code carries clippy issues.
# Count external_clippy unfiltered by rule id (a specific lint like doc_markdown may
# not fire on a given file under this lint set — e.g. it lands on sloc-cli/src/main.rs,
# not sloc-web/src/lib.rs).
curl -s -u "$ADMIN" \
  "$SONAR_HOST/api/issues/search?componentKeys=oxide-sloc:crates/sloc-web/src/lib.rs&resolved=false&ps=500" \
  | jq '[.issues[]|select(.rule|startswith("external_clippy:"))]|length'   # expect > 0
```

> **This suppression check is VACUOUS under the documented flags.** With
> `-W clippy::pedantic -W clippy::nursery` (Step 1), the test files emit **zero**
> clippy findings to begin with — so "0 live issues on a test file" proves nothing.
> To exercise the converter's `tests/` filter for real, re-run Step 1 with an
> aggressive set that makes test code noisy, e.g. add
> `-W clippy::unwrap_used -W clippy::expect_used -W clippy::panic -W clippy::indexing_slicing`,
> and confirm the raw `clippy.json` has hundreds of test-path findings while
> `clippy-sonar.json` has zero (jq on both). Do that as a **separate, non-scanning**
> run so it doesn't perturb the imported gate numbers.

## Scanning from a git worktree

Running the scan in a throwaway `git worktree` (to avoid disturbing an in-progress
checkout) has three traps — the last one is dangerous because it fails *green*:

- `.cargo/config.toml` and `vendor/` are **untracked**, so a fresh worktree can't
  build offline until you copy or symlink them in. Delete a `vendor/` symlink again
  **before** `git worktree remove`, or the remove refuses.
- Mount the worktree at its **real absolute path** in the scanner container, not a
  synthetic `/usr/src`. A worktree's `.git` is a file pointing back at the main
  repo's `.git/worktrees/<name>`; mounting elsewhere breaks that resolution, the
  scanner indexes **0 files**, and the quality gate **passes vacuously** — a green
  gate that analysed nothing. Verify the "N files indexed" line is non-zero every run.

## Discovering the correct Rust coverage key

`sonar.rust.lcov.reportPaths` is the key used in `ci/sonar/sonar-project.properties`.
If SonarQube shows no coverage data after a scan, verify the exact key
exposed by the installed Rust plugin:

```bash
curl -u "$SONAR_TOKEN:" \
  "$SONAR_HOST/api/settings/list_definitions" \
  | jq '.definitions[] | select((.subCategory//"")=="Rust" or (.category//"")=="Coverage")
                       | {key, name, description}'
```

Update `sonar.rust.lcov.reportPaths` in `ci/sonar/sonar-project.properties`
to whichever key the plugin actually exposes.

## Notes

- The `sonarsource/sonar-scanner-cli` image does **not** contain `cargo`.
  The bundled Rust sensor's clippy runner is intentionally disabled via
  `sonar.rust.clippy.disabled=true` in `ci/sonar/sonar-project.properties`.
  All Clippy findings reach SonarQube through the external-issues import
  produced by `scripts/internal/clippy_to_sonar.py`.
- `sonar.qualitygate.wait=true` is set in the properties file, so the
  scanner exits non-zero when the quality gate fails (exit 3).
- `sonar-coverage.xml` (Cobertura) is consumed by the Jenkins Coverage
  plugin (`recordCoverage(parser: 'COBERTURA')`).  It is **not** passed to
  SonarQube — the `sonar.coverageReportPaths` property (Generic Coverage
  format) is disabled because the Cobertura schema is incompatible.
