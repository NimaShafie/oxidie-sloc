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

```bash
cargo clippy --workspace --all-targets --all-features \
    --message-format=json --offline \
    -- -W clippy::pedantic -W clippy::nursery \
       -A clippy::multiple_crate_versions \
    > clippy.json 2> clippy.stderr || true

python3 scripts/internal/clippy_to_sonar.py clippy.json clippy-sonar.json "$PWD"
```

The converter strips the deprecated `type` / `engineId` fields from the
issue objects so SonarQube 26.x accepts the report without aborting.

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
