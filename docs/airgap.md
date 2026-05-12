# Air-Gap / Offline Deployment

## TL;DR — what ships inside the repository

Every `git clone` of oxide-sloc includes everything needed to run on a fresh machine
with **no internet connection and no pre-installed Rust**:

| What | File | Size |
|---|---|---|
| Windows pre-built binary | `dist/oxide-sloc-windows-x64.zip` | ~27 MB |
| Linux pre-built binary (x86_64) | `dist/oxide-sloc-linux-x86_64.tar.gz` | ~8 MB |
| Linux pre-built binary (arm64) | `dist/oxide-sloc-linux-arm64.tar.gz` | ~8 MB |
| Binary checksums | `dist/checksums.sha256` | — |
| All Rust crate sources | `vendor.tar.xz` | 35 MB |
| Cargo offline config | `.cargo/config.toml` | — |

`bash scripts/install.sh` detects which of these apply and picks the right path
automatically. No flags, no extra downloads, no pre-installed tooling beyond Git Bash
(Windows) or `bash` + `tar` (Linux).

---

## Installation paths

| Path | Prereqs on target machine | When to use |
|---|---|---|
| **[Option A — Windows pre-built](#option-a--windows-pre-built-binary)** | Git Bash | Windows 10/11 — no Rust, no internet |
| **[Option B — Linux pre-built](#option-b--linux-pre-built-binary)** | `bash`, `tar` | Linux — no Rust, no internet |
| **[Option C — Vendor source build](#option-c--vendor-only-source-build)** | Rust ≥1.95 | Rust is already installed |
| **[Option D — Airgap kit (Linux, no Rust)](#option-d--airgap-kit-linux-no-rust)** | `bash`, `tar` (xz), `sha256sum` | Linux, no Rust, no dist/ bundle |
| **[Option E — Download from GitHub](#option-e--auto-download-linux-no-rust-has-internet)** | `bash`, `tar`, `curl` | Linux, no Rust, has internet |

In all cases:

```bash
bash scripts/install.sh   # auto-detects the best available path
bash scripts/run.sh       # web UI at http://127.0.0.1:4317
```

`install.sh` makes no network calls by default. Pass `--online` to opt into GitHub
downloads (Option E only).

---

## Option A — Windows pre-built binary

**Prerequisites:** Git Bash (ships with Git for Windows). No Rust, no internet, no
additional downloads.

`dist/oxide-sloc-windows-x64.zip` is committed directly to the repository. Running
`bash scripts/install.sh` extracts it automatically:

```bash
# On a fresh Windows 10/11 machine — git clone, then:
bash scripts/install.sh   # finds dist/oxide-sloc-windows-x64.zip, extracts oxide-sloc.exe
bash scripts/run.sh       # web UI at http://127.0.0.1:4317
```

The installer verifies the SHA-256 checksum (from `dist/checksums.sha256`) before
extracting. It prints `[OK] Checksum verified.` on success; it exits with an error and
prints the expected vs actual hashes if the archive is corrupt.

**System requirements:** Git Bash, Windows 10/11 (x64).

To launch as a LAN server reachable from other devices on the network:

```bash
bash scripts/serve-server.sh
```

### Troubleshooting — "dist/oxide-sloc-windows-x64.zip not found"

This means the file is missing from the clone. Causes:

1. **Shallow or partial clone** — re-clone with `git clone https://github.com/oxide-sloc/oxide-sloc`
2. **Git LFS not configured** — if LFS is in use on your server, run `git lfs pull` after cloning
3. **Repository is not from the canonical source** — ensure you have a complete clone

If `dist/` is missing entirely and you have Rust installed, fall back to Option C:
`bash scripts/internal/airgap-build.sh vendor.tar.xz`

---

## Option B — Linux pre-built binary

`dist/oxide-sloc-linux-x86_64.tar.gz` (and `arm64` variant) are committed to the
repository alongside the Windows zip. No build step, no Rust required.

```bash
bash scripts/install.sh   # detects dist/ bundle and extracts
bash scripts/run.sh
```

The installer automatically picks the correct architecture (`x86_64` or `arm64`) and
verifies the SHA-256 checksum before extracting.

**Producing a fresh `dist/` bundle** (maintainer workflow — run on any machine with Rust):

```bash
bash scripts/internal/update-dist.sh
git add dist/
git commit -m "chore: update pre-built binaries vX.Y.Z"
```

`update-dist.sh` builds a release binary, packages it into the correct archive, and
regenerates `dist/checksums.sha256`.

---

## Option C — Vendor-only source build

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
`.cargo/config.toml`, and runs `cargo build --release --offline`. Output streams to the
terminal and is captured to a timestamped log under `logs/`.

> **What vendor.tar.xz covers:** all ~328 Rust crate sources needed for a fully offline
> `cargo build`. The Rust toolchain itself is not included — if you also need to transfer
> the toolchain, use [Option D](#option-d--airgap-kit-linux-no-rust) instead.

---

## Option E — Download from GitHub (Linux, no Rust, has internet)

When `curl` is available and no Rust toolchain is detected, pass `--online` to have
`install.sh` fetch the matching release binary from GitHub Releases:

```bash
bash scripts/install.sh --online   # downloads release binary, extracts
bash scripts/run.sh
```

The downloaded archive is verified against `SHA256SUMS.txt` from the same release when
`sha256sum` is available.

The default (without `--online`) makes no network calls. `--offline` and
`OXIDE_SLOC_NO_DOWNLOAD=1` are retained for backward compatibility.

**System requirements:** `bash`, `tar`, `curl`. `sha256sum` is used when present.

---

## Option D — Airgap kit (Linux, no Rust)

Use this when the target Linux machine has no internet access, no Rust installed, and no
pre-built binary available (e.g., `dist/` is missing or you need a statically-linked
build for an unusual distribution).

Run `scripts/internal/make-airgap-kit.sh` on any **networked** machine to produce a
self-contained archive that contains the Rust toolchain, musl C toolchain, vendor
sources, and the full source tree.

### What the kit bundles

| Component | Purpose |
|---|---|
| `rust-{ver}-{target}.tar.gz` | Rust host toolchain (rustc, cargo, std) |
| `rust-std-{ver}-{musl-target}.tar.gz` | Rust musl target standard library |
| `{arch}-linux-musl-native.tgz` | musl-gcc + headers + libc (no system compiler needed) |
| `vendor.tar.xz` | All ~328 Rust crate sources |
| `oxide-sloc-src.tar.gz` | Full source tree |
| `install.sh` | Wires everything together and builds |

Result: a **fully static binary** — copy it anywhere on Linux with no runtime deps.

### Generate the kit (networked machine)

```bash
# Auto-detect arch (Linux x86_64 or arm64):
bash scripts/internal/make-airgap-kit.sh

# Or specify explicitly:
bash scripts/internal/make-airgap-kit.sh linux-x86_64
bash scripts/internal/make-airgap-kit.sh linux-arm64

# Output: oxide-sloc-airgap-kit-{platform}-v{version}.tar.gz  (~700 MB)
```

Requirements: `bash`, `curl`, `tar`, `xz-utils`, `sha256sum`, `git`, `cargo`.

### Build on the air-gapped machine

```bash
tar xzf oxide-sloc-airgap-kit-linux-x86_64-v*.tar.gz
cd oxide-sloc-airgap-kit-*/
bash install.sh
```

The embedded `install.sh`:
1. Installs the Rust toolchain into `.tools/rust/` — no root, no system PATH changes.
2. Installs the musl C toolchain into `.tools/musl/` — no root.
3. Verifies and extracts the vendor crate sources.
4. Builds a fully static oxide-sloc binary with an animated three-phase progress display.

After a successful build:

```bash
./oxide-sloc serve              # web UI at http://127.0.0.1:4317
./oxide-sloc analyze /path/to/repo --plain
```

### Options

```bash
bash install.sh --gnu   # use system gcc instead of bundled musl-gcc
                        # produces a dynamically linked binary (requires glibc at runtime)
```

### System requirements on the air-gapped machine

| Requirement | Notes |
|---|---|
| OS | Linux x86_64 or arm64 |
| Tools | `bash`, `tar` (with xz/`-J` flag), `sha256sum` |
| Root / sudo | **Not required** — installs to `.tools/` inside the kit directory |
| Internet | **Not required** |
| Rust | **Not required** — bundled by the kit |
| C compiler | **Not required** — bundled musl-gcc is used |

---

## Keeping pre-built binaries up to date

Pre-built binaries in `dist/` must be rebuilt and committed after every release.
The `update-dist.sh` script handles this:

```bash
# Run on any machine with Rust and the target's cross-compilation toolchain installed:
bash scripts/internal/update-dist.sh

# Stage and commit atomically with the vendor archive if deps changed:
git add dist/ vendor.tar.xz vendor.tar.xz.sha256
git commit -m "chore: update pre-built binaries and vendor archive vX.Y.Z"
```

CI (GitHub Actions `release.yml`) runs `update-dist.sh` automatically on tagged releases
and commits the updated `dist/` back to the repository before creating the GitHub Release.

---

## Script overview

Users interact with three scripts only. Internal scripts under `scripts/internal/` are
called automatically and should not be invoked directly.

| Script | Purpose | Build progress display |
|---|---|---|
| `bash scripts/install.sh` | Install oxide-sloc (auto-detects best path) | Yes — Verify sources → Compile release build → Install binary |
| `bash scripts/run.sh` | Launch web UI (localhost) | Yes — Resolve dependencies → Compile workspace → Launch server |
| `bash scripts/serve-server.sh` | Launch web UI as LAN server | Yes — Resolve dependencies → Compile workspace → Launch server |

All three scripts show a live animated progress indicator when compiling from source.
Every run writes a timestamped log to `logs/`; on failure the log path and a clickable
terminal link are printed.

| Internal script | Called by | Build progress display |
|---|---|---|
| `scripts/internal/airgap-build.sh` | Manually (Option C manual path) | No — plain streaming output |
| `scripts/internal/update-dist.sh` | Maintainers; CI release workflow | No |
| `scripts/internal/make-airgap-kit.sh` | Run manually on networked machine (Option D) | No |
| `scripts/internal/update-vendor.sh` | Maintainer tooling — regenerates `vendor.tar.xz` | No |
| `scripts/internal/install-hooks.sh` | Developer setup — installs git hooks | No |

---

## CI/CD on air-gapped infrastructure

### Jenkins

`vendor.tar.xz` is committed to the repo — Cargo crate sources are fully covered after a
`git clone`. The Rust toolchain is not in git; two options:

**Option 1 — Rebuild `ci/jenkins/Dockerfile.agent` (recommended)**

The Dockerfile bakes the pinned toolchain into the image at build time. All pipeline runs
after the image rebuild are fully offline:

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

The Jenkinsfile Setup stage detects and extracts the bundle automatically.

### GitLab CI

Use a self-hosted GitLab runner with Rust pre-installed and `vendor.tar.xz` available in
the runner's workspace cache or via a custom pre-clone step.

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

PDF export requires a locally installed Chromium-based browser (Chrome, Edge, Brave,
Vivaldi, or Opera). Set `SLOC_BROWSER=/path/to/chromium` if auto-discovery fails.
In Docker, Chromium is bundled — no extra setup needed.
