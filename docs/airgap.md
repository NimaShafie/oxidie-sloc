# Air-Gap / Offline Deployment

## TL;DR — what ships inside the repository

Every `git clone` includes everything needed to install and run oxide-sloc offline.

| What | File | Size | Status |
|---|---|---|---|
| **Windows pre-built binary** | `dist/oxide-sloc-windows-x64.zip` (+ `.tar.gz`) | ~9 MB | **Always committed** — updated by CI after every release |
| **Linux x86_64 pre-built binary** | `dist/oxide-sloc-linux-x86_64.tar.gz` | ~10 MB | **Always committed** — built in a UBI 8 container and updated by CI after every release |
| All Rust crate sources | `vendor.tar.gz.aa` / `.ab` / `.ac` | ~115 MB total (≤45 MB each) | **Always committed** |
| Vendor checksums | `vendor.checksums.sha256` | — | **Always committed** (per-part SHA-256) |
| Rust version pin | `rust-toolchain.toml` | — | **Always committed** |
| Cargo offline config | `.cargo/config.toml` | — | Written by install.sh / CI at build time |
| **Rust compiler + cargo (Linux)** | `toolchain/rust-toolchain-linux-*.tar.gz.aa` + `.ab` … | ≤45 MB per part | **Maintainer step** — only present after running `bundle-rust-toolchain.sh` and committing |

`bash scripts/run.sh` auto-invokes `install.sh` on first run and picks the right path
automatically. No network calls are made by default.

**Windows:** a plain `git clone` + `bash scripts/run.sh` extracts the pre-built binary from
`dist/` and launches the web UI. No Rust toolchain required, no compilation.

**Linux x86_64:** a plain `git clone` + `bash scripts/run.sh` extracts the committed
`dist/oxide-sloc-linux-x86_64.tar.gz` — no Rust required, no compilation.

**Linux arm64 (aarch64):** there is **no committed pre-built binary** for arm64, so
`bash scripts/run.sh` builds from source offline using the committed arm64 toolchain
(`toolchain/rust-toolchain-linux-arm64.tar.gz.*`) and the `vendor.tar.gz.*` parts. This works
fully offline; it just compiles once (a few minutes) instead of extracting an instant binary.
Pass `--build` to force compilation explicitly. (To ship an instant arm64 binary, build one on
an arm64 host and commit it as `dist/oxide-sloc-linux-arm64.tar.gz`.)

**Linux — Rust already installed:** a plain `git clone` + `bash scripts/run.sh` builds
offline from the `vendor.tar.gz.*` parts with no extra steps.

**Linux — Rust NOT installed:** a fully offline build additionally requires the maintainer to
have committed the `toolchain/` archives (see
[Populating the toolchain archive](#populating-the-toolchain-archive-maintainer-workflow)
below). Without them, use [`--online`](#option-d--auto-download-linux-no-rust-has-internet)
(Linux + curl) or [Option C](#option-c--airgap-kit-linux-no-rust).

---

## Installation paths

| Path | Platform | Prereqs on target machine | When to use |
|---|---|---|---|
| **[Option W — Pre-built Windows binary](#option-w--pre-built-windows-binary)** | Windows | Git Bash / `bash`, `unzip` | Default Windows path — no Rust required |
| **[Option A — Bundled toolchain build](#option-a--build-from-bundled-rust-toolchain-linux)** | Linux | `bash`, `tar` | No Rust, no internet — requires toolchain committed to git by maintainer |
| **[Option B — Vendor source build](#option-b--vendor-only-source-build)** | Linux / Windows | Rust ≥1.95 already installed | Rust is already on the machine |
| **[Option C — Airgap kit (Linux, no Rust)](#option-c--airgap-kit-linux-no-rust)** | Linux | `bash`, `tar` (xz), `sha256sum` | Linux, no Rust — full self-contained kit |
| **[Option D — Download from GitHub](#option-d--auto-download-linux-no-rust-has-internet)** | Linux | `bash`, `tar`, `curl` | Linux, no Rust, has internet |

In all cases, a single command does everything:

```bash
bash scripts/run.sh   # auto-installs on first run, then opens web UI at http://127.0.0.1:4317
```

`run.sh` calls `install.sh` automatically when the binary is absent and makes no network
calls by default. Pass `--online` to opt into GitHub downloads (Option D only).
Use `--rebuild` or `--force` to force a fresh install even if a binary already exists.

---

## Option W — Pre-built Windows binary

**Windows 10/11 only.** No Rust required. No compilation. No `.tools/` directory written.

`dist/oxide-sloc-windows-x64.zip` is committed directly to the repository and updated
automatically by the `update-dist.yml` CI workflow after every release. `install.sh` extracts
it on the first run — no network call, no build step.

```bash
# On the air-gapped Windows machine — after git clone:
bash scripts/run.sh   # extracts dist/oxide-sloc-windows-x64.zip → oxide-sloc.exe → launches
```

**System requirements:**

| | Windows 10/11 |
|---|---|
| Shell | Git Bash (ships with Git for Windows) |
| Extract tool | `unzip` (bundled with Git Bash) or PowerShell `Expand-Archive` |
| Root / sudo | Not required |
| Internet | Not required |
| Rust | Not required |

The `dist/` zip contains the release-mode binary built by `x86_64-pc-windows-msvc` in GitHub
Actions. When the `WINDOWS_CERTIFICATE` GitHub Actions secret is set, the binary inside is
Authenticode-signed.

> **Force re-extraction:** `bash scripts/run.sh --rebuild` re-extracts the zip even if the
> binary already exists — useful after a `git pull` that updates `dist/`.

---

## Option A — Build from bundled Rust toolchain (Linux)

**Linux only. No Rust installed. No internet required — provided the maintainer has committed the
toolchain archive** (see [Populating the toolchain archive](#populating-the-toolchain-archive-maintainer-workflow) below).

When `toolchain/` archives are present, `install.sh` detects them automatically,
installs Rust locally into `.tools/` (inside the repo, no system-wide changes, no root
required), and then compiles oxide-sloc from the vendored crate sources.

If `toolchain/` is absent on a fresh clone (`git ls-files toolchain/` returns nothing),
the maintainer must run `bundle-rust-toolchain.sh` and commit the result first (see [Populating the toolchain archive](#populating-the-toolchain-archive-maintainer-workflow)).

```bash
# On the air-gapped Linux machine — after git clone (toolchain/ must already be committed):
bash scripts/run.sh   # bootstraps Rust, builds from vendor.tar.gz.*, launches web UI
```

**What install.sh does under the hood:**
1. Detects no `cargo` on PATH.
2. Finds `toolchain/rust-toolchain-linux-{arch}.tar.gz`.
3. Verifies the SHA-256 checksum (from `toolchain/checksums.sha256`).
4. Extracts to `.tools/` and exports `RUSTUP_HOME`/`CARGO_HOME`/`PATH` for the session.
5. Verifies (`vendor.checksums.sha256`), reassembles, and decompresses `vendor.tar.gz.*` (one-time, ~115 MB → ~362 MB).
6. Runs `cargo build --release --offline -p oxide-sloc` with the animated progress display.
7. Copies the result to `oxide-sloc` in the repo root.

**System requirements:**

| | Linux x86_64 / arm64 |
|---|---|
| Shell | `bash` |
| Extract tools | `tar` (with xz flag) |
| C linker | `gcc` (system package) |
| Root / sudo | Not required |
| Internet | Not required |
| Rust | Not required — bootstrapped from `toolchain/` |

> **GUI system libraries:** The default build is headless and requires no GUI system
> libraries (`libwayland`, `libgtk`, `libxdo`). To enable native file-dialog support
> (Linux desktop only), build with:
> ```bash
> cargo build --release --offline --features native-dialog
> ```
> and install the required packages first:
> ```bash
> # Debian / Ubuntu
> apt install libwayland-dev libgtk-3-dev libxdo-dev
> # RHEL 8/9 equivalents
> dnf install wayland-devel gtk3-devel libxdo-devel
> ```

### Populating the toolchain archive (maintainer workflow)

Run `bundle-rust-toolchain.sh` to download and commit the Rust toolchain archive. (Windows users use `dist/oxide-sloc-windows-x64.zip` instead — no toolchain archive needed.)

```bash
# Requires internet access (run once, then commit the result):
bash scripts/internal/bundle-rust-toolchain.sh linux-x86_64  # Linux x64
bash scripts/internal/bundle-rust-toolchain.sh linux-arm64   # Linux arm64

# Commit the parts directly — each part is ≤45 MB:
git add toolchain/
git commit -m "chore: bundle Rust toolchain for offline builds"
git push
```

The script reads the Rust version from `rust-toolchain.toml`, downloads the matching
standalone installer from `https://static.rust-lang.org/dist/`, verifies the upstream
SHA-256, and regenerates `toolchain/checksums.sha256`.

---

## Option B — Vendor-only source build

Use this when the Rust toolchain (≥1.95) is already installed on the target machine.

The `vendor.tar.gz.*` parts and `vendor.checksums.sha256` are **committed to the repository** —
every `git clone` includes them. No separate download is needed. Gzip is used (not xz) so stock
Git Bash on Windows, which has no `xz`, can extract them; the archive is split into ≤45 MB parts
to stay under GitHub's 100 MB per-file limit.

```bash
bash scripts/run.sh   # detects cargo, reassembles + decompresses vendor.tar.gz.*, builds offline, launches
```

Or manually via the internal helper:

```bash
bash scripts/internal/airgap-build.sh
# Binary lands at: target/release/oxide-sloc
bash scripts/run.sh
```

`scripts/internal/airgap-build.sh` verifies the per-part checksums
(`vendor.checksums.sha256`), reassembles the `vendor.tar.gz.*` parts, extracts, writes
`.cargo/config.toml`, and runs `cargo build --release --offline`.

> **What the `vendor.tar.gz.*` parts cover:** all ~328 Rust crate sources needed for a fully offline
> `cargo build`. The Rust toolchain itself is not included — for that, use
> [Option A](#option-a--build-from-bundled-rust-toolchain) or
> [Option C](#option-c--airgap-kit-linux-no-rust).

---

## Option D — Download from GitHub (Linux, no Rust, has internet)

When `curl` is available and no Rust toolchain is detected, pass `--online` to have
`install.sh` fetch the matching release binary from GitHub Releases:

```bash
bash scripts/internal/install.sh --online   # downloads release binary, extracts
bash scripts/run.sh                         # launches web UI
```

The downloaded archive is verified against `SHA256SUMS.txt` from the same release when
`sha256sum` is available.

The default (without `--online`) makes no network calls.

**System requirements:** `bash`, `tar`, `curl`. `sha256sum` is used when present.

---

## Option C — Airgap kit (Linux, no Rust)

Use this when the target Linux machine has no internet access, no Rust installed, and
you need a fully self-contained statically-linked binary kit.

Run `scripts/internal/make-airgap-kit.sh` to produce a self-contained archive that bundles
the Rust toolchain, musl C toolchain, vendor sources, and the full source tree.

### What the kit bundles

| Component | Purpose |
|---|---|
| `rust-{ver}-{target}.tar.gz` | Rust host toolchain (rustc, cargo, std) |
| `rust-std-{ver}-{musl-target}.tar.gz` | Rust musl target standard library |
| `{arch}-linux-musl-native.tgz` | musl-gcc + headers + libc |
| `vendor.tar.gz.aa` / `.ab` / `.ac` + `vendor.checksums.sha256` | All ~328 Rust crate sources (split gzip parts) |
| `oxide-sloc-src.tar.gz` | Full source tree |
| `install.sh` | Wires everything together and builds |

Result: a **fully static binary** — copy it anywhere on Linux with no runtime deps.

### Generate the kit

```bash
bash scripts/internal/make-airgap-kit.sh              # auto-detect arch
bash scripts/internal/make-airgap-kit.sh linux-x86_64
bash scripts/internal/make-airgap-kit.sh linux-arm64
# Output: oxide-sloc-airgap-kit-{platform}-v{version}.tar.gz  (~700 MB)
```

### Build on the air-gapped machine

```bash
tar xzf oxide-sloc-airgap-kit-linux-x86_64-v*.tar.gz
cd oxide-sloc-airgap-kit-*/
bash install.sh
```

### System requirements on the air-gapped machine

| Requirement | Notes |
|---|---|
| OS | Linux x86_64 or arm64 |
| Tools | `bash`, `tar` (with xz/`-J` flag), `sha256sum` |
| Root / sudo | **Not required** |
| Internet | **Not required** |
| Rust | **Not required** — bundled by the kit |

---

## Script overview

Users interact with three scripts only. Internal scripts under `scripts/internal/` are
called automatically and should not be invoked directly.

| Script | Purpose | Notes |
|---|---|---|
| `bash scripts/run.sh` | **Primary entry point** — installs on first run, then launches web UI (localhost) | Accepts `--rebuild` / `--force` / `-f` to force a fresh install before launching |
| `bash scripts/serve-server.sh` | Launch web UI as LAN server (no auth by default; add `--with-auth` to require a key) | Does not auto-install — run `scripts/run.sh` at least once first |

| Internal script | Called by | Purpose |
|---|---|---|
| `scripts/internal/install.sh` | `run.sh` automatically | Install oxide-sloc (auto-detects best path); accepts `--rebuild`, `--online`, `--auto` |
| `scripts/internal/airgap-build.sh` | Manually (Option B manual path) | Plain offline build from vendor sources |
| `scripts/internal/bundle-rust-toolchain.sh` | Maintainer tooling | Downloads Rust toolchain, stages into `toolchain/` for commit |
| `scripts/internal/make-airgap-kit.sh` | Maintainer tooling | Builds Option C self-contained kit for Linux |
| `scripts/internal/update-vendor.sh` | Maintainer tooling | Regenerates the `vendor.tar.gz.*` parts + `vendor.checksums.sha256` after dependency changes |
| `scripts/internal/install-hooks.sh` | Developer setup | Installs git pre-commit hooks |

---

## CI/CD on air-gapped infrastructure

### Jenkins

The `vendor.tar.gz.*` parts are committed to the repo — Cargo crate sources are fully covered
after a `git clone`. The Rust toolchain is not in git; two options:

**Option 1 — Rebuild `ci/jenkins/Dockerfile.agent` (recommended)**

The Dockerfile bakes the pinned toolchain into the image at build time:

```bash
docker build -t jenkins-oxide-sloc:latest -f ci/jenkins/Dockerfile.agent .
docker compose down && docker compose up -d
```

**Option 2 — Commit a toolchain bundle directly**

```bash
bash scripts/internal/bundle-rust-toolchain.sh linux-x86_64
git add toolchain/
git commit -m "ci: add Rust toolchain bundle for offline builds"
```

The script compresses with gzip -9 and splits the output into ≤45 MB parts,
so every committed file is well within GitHub's per-file limit.

### GitHub Actions (self-hosted runner)

For internet-connected runners, cargo downloads crates normally via Swatinem/rust-cache.
For air-gapped runners, the `vendor.tar.gz.*` parts are already in the workspace after
`git clone` — add a verify + reassemble + extract step
(`sha256sum -c vendor.checksums.sha256 && cat vendor.tar.gz.* | tar -xzf -`) before `cargo build`.

---

## Runtime network requirements

| Feature | Network needed? |
|---|---|
| Web UI (`serve`) | No |
| `analyze` command | No |
| `report` command | No |
| PDF export | No — uses locally installed Chromium |
| `git-scan` / `git-compare` of a **remote** instance | Yes — a route to that git host |
| `git-scan` of an **offline bundle / `file://` / local path** | No — see below |
| Email delivery (`--smtp-to`) | Yes |
| Webhook delivery (`--webhook-url`) | Yes |

---

## Scanning air-gapped git instances (offline import)

The sections above cover installing oxide-sloc offline. To **scan** code from a git instance that
is unreachable from the machine running the tool, bring the repository in as an offline copy — a
git bundle is the simplest carrier:

```bash
# On a machine that can reach the instance:
git clone --mirror https://bitbucket.instance2.com/scm/proj/widget.git
git -C widget.git bundle create /media/transfer/widget.bundle --all

# On the air-gapped machine (copy the bundle in first):
export SLOC_GIT_ALLOW_LOCAL=1
export SLOC_GIT_LOCAL_ROOT=/srv/oxide-sloc/imports      # bundle must live under here
oxide-sloc git-scan /srv/oxide-sloc/imports/widget.bundle \
  --allow-local --local-root /srv/oxide-sloc/imports --html-out out/widget.html
```

Offline import is **off by default** and fail-closed: it requires both `SLOC_GIT_ALLOW_LOCAL` and
`SLOC_GIT_LOCAL_ROOT`, and rejects any source outside that root as well as UNC / `file://host` SMB
fetches. If the instance *is* reachable on the internal network, no offline step is needed — clone
it directly and supply a per-host credential. Full detail (per-host credentials, proxies, VLANs,
all three run modes) is in **[Scanning multiple git instances](multi-instance.md)**.
