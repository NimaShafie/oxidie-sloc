# Air-Gap / Offline Deployment

## TL;DR — what ships inside the repository

Every `git clone` of oxide-sloc includes everything needed to BUILD the project on a
fresh machine with **no internet connection**:

| What | File | Size | Notes |
|---|---|---|---|
| All Rust crate sources | `vendor.tar.xz` | 35 MB | Cargo's full dependency graph |
| Cargo offline config | `.cargo/config.toml` | — | Redirects crate lookups to `vendor/` |
| Rust version pin | `rust-toolchain.toml` | — | Channel 1.95 |
| **Rust compiler + cargo** | `toolchain/rust-toolchain-*.tar.gz` | ~70-90 MB | Committed directly to git (7-zip ultra, no LFS) |

`bash scripts/install.sh` detects which of these apply and picks the right build path
automatically. No flags, no extra downloads, no pre-installed tooling beyond Git Bash
(Windows) or `bash` + `tar` (Linux).

A plain `git clone` is sufficient — no `git lfs pull` or extra setup required.

---

## Installation paths

| Path | Prereqs on target machine | When to use |
|---|---|---|
| **[Option A — Bundled toolchain build](#option-a--build-from-bundled-rust-toolchain)** | Git Bash / `bash`, `tar` | No Rust, no internet — toolchain committed to git |
| **[Option B — Vendor source build](#option-b--vendor-only-source-build)** | Rust ≥1.95 already installed | Rust is already on the machine |
| **[Option C — Airgap kit (Linux, no Rust)](#option-c--airgap-kit-linux-no-rust)** | `bash`, `tar` (xz), `sha256sum` | Linux, no Rust — full self-contained kit |
| **[Option D — Download from GitHub](#option-d--auto-download-linux-no-rust-has-internet)** | `bash`, `tar`, `curl` | Linux, no Rust, has internet |

In all cases:

```bash
bash scripts/install.sh   # auto-detects the best available path
bash scripts/run.sh       # web UI at http://127.0.0.1:4317
```

`install.sh` makes no network calls by default. Pass `--online` to opt into GitHub
downloads (Option D only).

---

## Option A — Build from bundled Rust toolchain

**No Rust installed. No internet required after `git clone`.**

The repository includes a standalone Rust toolchain archive in `toolchain/` (committed
directly to git, 7-zip ultra compressed, no LFS). `install.sh` detects it automatically,
installs Rust locally into `.tools/` (inside the repo, no system-wide changes, no root
required), and then compiles oxide-sloc from the vendored crate sources.

```bash
# On the air-gapped machine — after git clone (no extra steps needed):
bash scripts/install.sh   # bootstraps Rust, builds from vendor.tar.xz
bash scripts/run.sh       # web UI at http://127.0.0.1:4317
```

**What install.sh does under the hood:**
1. Detects no `cargo` on PATH.
2. Finds `toolchain/rust-toolchain-{platform}.tar.gz`.
3. Verifies the SHA-256 checksum (from `toolchain/checksums.sha256`).
4. Extracts to `.tools/` and runs the bundled `install.sh` with `--prefix=.tools/rust`.
5. Exports `.tools/rust/bin` onto PATH for the rest of the session.
6. Decompresses `vendor.tar.xz` (one-time, ~35 MB → ~362 MB).
7. Runs `cargo build --release --offline -p oxide-sloc` with the animated progress display.
8. Copies the result to `oxide-sloc` (Linux) / `oxide-sloc.exe` (Windows) in the repo root.

**System requirements:**

| | Windows 10/11 | Linux x86_64 / arm64 |
|---|---|---|
| Shell | Git Bash (ships with Git for Windows) | `bash` |
| Extract tools | `tar` (bundled with Git Bash) | `tar` (with xz flag) |
| C linker | `gcc` (bundled with Git Bash's MinGW-w64) | `gcc` (system package) |
| Root / sudo | Not required | Not required |
| Internet | Not required | Not required |
| Rust | Not required — bootstrapped from `toolchain/` | Not required |

> **Windows linker note:** The Rust `x86_64-pc-windows-gnu` toolchain uses `gcc` as the
> linker. Git for Windows includes MinGW-w64 GCC at `/mingw64/bin/gcc.exe` — available
> automatically in every Git Bash session. No separate installation needed.

### Populating the toolchain archive (maintainer workflow)

The toolchain archive must be generated on a machine with internet access and committed
to the repository:

```bash
# On any machine with internet access:
bash scripts/internal/bundle-rust-toolchain.sh windows-x64   # Windows (~70-90 MB)
bash scripts/internal/bundle-rust-toolchain.sh linux-x86_64  # Linux x64 (~60-80 MB)
bash scripts/internal/bundle-rust-toolchain.sh linux-arm64   # Linux arm64 (~60-80 MB)

# Commit directly — no git LFS required (7-zip ultra keeps each archive under 100 MB):
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

`vendor.tar.xz` and `vendor.tar.xz.sha256` are **committed to the repository** — every
`git clone` includes them. No separate download is needed.

```bash
bash scripts/install.sh   # detects cargo, decompresses vendor.tar.xz, builds offline
bash scripts/run.sh
```

Or manually via the internal helper:

```bash
bash scripts/internal/airgap-build.sh vendor.tar.xz
# Binary lands at: target/release/oxide-sloc
bash scripts/run.sh
```

`scripts/internal/airgap-build.sh` verifies the vendor checksum, extracts, writes
`.cargo/config.toml`, and runs `cargo build --release --offline`.

> **What vendor.tar.xz covers:** all ~328 Rust crate sources needed for a fully offline
> `cargo build`. The Rust toolchain itself is not included — for that, use
> [Option A](#option-a--build-from-bundled-rust-toolchain) or
> [Option C](#option-c--airgap-kit-linux-no-rust).

---

## Option D — Download from GitHub (Linux, no Rust, has internet)

When `curl` is available and no Rust toolchain is detected, pass `--online` to have
`install.sh` fetch the matching release binary from GitHub Releases:

```bash
bash scripts/install.sh --online   # downloads release binary, extracts
bash scripts/run.sh
```

The downloaded archive is verified against `SHA256SUMS.txt` from the same release when
`sha256sum` is available.

The default (without `--online`) makes no network calls.

**System requirements:** `bash`, `tar`, `curl`. `sha256sum` is used when present.

---

## Option C — Airgap kit (Linux, no Rust)

Use this when the target Linux machine has no internet access, no Rust installed, no
`toolchain/` LFS archive available, and you need a statically-linked binary.

Run `scripts/internal/make-airgap-kit.sh` on any **networked** machine to produce a
self-contained archive that bundles the Rust toolchain, musl C toolchain, vendor
sources, and the full source tree.

### What the kit bundles

| Component | Purpose |
|---|---|
| `rust-{ver}-{target}.tar.gz` | Rust host toolchain (rustc, cargo, std) |
| `rust-std-{ver}-{musl-target}.tar.gz` | Rust musl target standard library |
| `{arch}-linux-musl-native.tgz` | musl-gcc + headers + libc |
| `vendor.tar.xz` | All ~328 Rust crate sources |
| `oxide-sloc-src.tar.gz` | Full source tree |
| `install.sh` | Wires everything together and builds |

Result: a **fully static binary** — copy it anywhere on Linux with no runtime deps.

### Generate the kit (networked machine)

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

## Setting up git LFS

The toolchain archives in `toolchain/` require git LFS. Set it up once per machine:

```bash
# Install git LFS (if not already installed):
# Windows: ships with Git for Windows — already available in Git Bash
# Linux:   sudo apt install git-lfs   OR   sudo dnf install git-lfs

git lfs install   # hook git LFS into your git config (once per machine)
git lfs pull      # download the toolchain archives for this clone
```

To verify LFS is working correctly:

```bash
ls -lh toolchain/rust-toolchain-*.tar.gz
# Should show ~170-200 MB files, not 200-byte pointer stubs
```

If the files are small (pointer stubs), LFS is not configured. Run `git lfs install`
then `git lfs pull`.

---

## Script overview

Users interact with three scripts only. Internal scripts under `scripts/internal/` are
called automatically and should not be invoked directly.

| Script | Purpose | Build progress display |
|---|---|---|
| `bash scripts/install.sh` | Install oxide-sloc (auto-detects best path) | Yes — Verify sources → Compile release build → Install binary |
| `bash scripts/run.sh` | Launch web UI (localhost) | Yes — Resolve dependencies → Compile workspace → Launch server |
| `bash scripts/serve-server.sh` | Launch web UI as LAN server | Yes — Resolve dependencies → Compile workspace → Launch server |

| Internal script | Called by | Purpose |
|---|---|---|
| `scripts/internal/airgap-build.sh` | Manually (Option B manual path) | Plain offline build from vendor sources |
| `scripts/internal/bundle-rust-toolchain.sh` | Maintainers — run on networked machine | Downloads Rust toolchain, stages into `toolchain/` for commit |
| `scripts/internal/make-airgap-kit.sh` | Maintainers — run on networked machine | Builds Option C self-contained kit for Linux |
| `scripts/internal/update-vendor.sh` | Maintainer tooling | Regenerates `vendor.tar.xz` after dependency changes |
| `scripts/internal/install-hooks.sh` | Developer setup | Installs git pre-commit hooks |

---

## CI/CD on air-gapped infrastructure

### Jenkins

`vendor.tar.xz` is committed to the repo — Cargo crate sources are fully covered after a
`git clone`. The Rust toolchain is not in git; two options:

**Option 1 — Rebuild `ci/jenkins/Dockerfile.agent` (recommended)**

The Dockerfile bakes the pinned toolchain into the image at build time:

```bash
docker build -t jenkins-oxide-sloc:latest -f ci/jenkins/Dockerfile.agent .
docker compose down && docker compose up -d
```

**Option 2 — Commit a toolchain bundle (git LFS)**

```bash
bash ci/jenkins/bundle-rust-toolchain.sh
git lfs install && git lfs track '*.tar.xz'
git add .gitattributes rust-toolchain-bundle.tar.xz rust-toolchain-bundle.tar.xz.sha256
git commit -m "ci: add Rust toolchain bundle for offline builds"
```

### GitHub Actions (self-hosted runner)

For internet-connected runners, cargo downloads crates normally via Swatinem/rust-cache.
For air-gapped runners, `vendor.tar.xz` is already in the workspace after `git clone` —
add a vendor extraction step before `cargo build`.

---

## Runtime network requirements

| Feature | Network needed? |
|---|---|
| Web UI (`serve`) | No |
| `analyze` command | No |
| `report` command | No |
| PDF export | No — uses locally installed Chromium |
| Email delivery (`--smtp-to`) | Yes |
| Webhook delivery (`--webhook-url`) | Yes |
