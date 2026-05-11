# Air-Gap / Offline Deployment

## Installation paths

`bash scripts/install.sh` auto-detects the best available path for your environment. The table
below maps each scenario to the right option — pick the row that matches your machine.

| Path | Prereqs on target machine | When to use |
|---|---|---|
| **[Option A — Windows bundled binary](#option-a--windows-bundled-binary)** | Git Bash | Windows: `oxide-sloc.exe` is in the repo root |
| **[Option B — Linux pre-built binary](#option-b--linux-pre-built-binary-dist)** | `bash`, `tar` | Linux binary placed by CI into `dist/` |
| **[Option C — Vendor source build](#option-c--vendor-only-source-build)** | Rust toolchain already installed | Rust is already on the machine |
| **[Option E — Download from GitHub (Linux, no Rust, has internet)](#option-e--auto-download-linux-no-rust-has-internet)** | `bash`, `tar`, `curl` | Linux, no Rust, internet available — pass `--online` to fetch the release binary from GitHub |
| **[Option D — Airgap kit (Linux, no Rust)](#option-d--airgap-kit-linux-no-rust)** | `bash`, `tar` (xz), `sha256sum` | Linux, no Rust, no internet |

In all cases, start with:

```bash
bash scripts/install.sh   # auto-detects the best available path
bash scripts/run.sh       # web UI at http://127.0.0.1:4317
```

All options make no network calls by default — `install.sh` is offline-first. Option E
additionally downloads the release binary from GitHub when you explicitly pass `--online`.
`--offline` (and `OXIDE_SLOC_NO_DOWNLOAD=1`) are kept for backward compatibility; they are
now no-ops since offline is the default.

---

## Option A — Windows bundled binary

`oxide-sloc.exe` is committed to the repository root. No build step, no Rust installation,
no internet required.

```bash
# Clone or copy the repository to the target machine, then:
bash scripts/install.sh   # detects oxide-sloc.exe and exits immediately
bash scripts/run.sh       # web UI at http://127.0.0.1:4317
```

**System requirements:** Git Bash (bundled with Git for Windows), Windows 10/11.

To launch as a LAN server reachable from other devices on the network:

```bash
bash scripts/serve-server.sh
```

---

## Option B — Linux pre-built binary (`dist/`)

When CI has populated `dist/oxide-sloc-linux-x86_64.tar.gz`, the installer extracts and
installs it automatically — no Rust or build tools required.

```bash
bash scripts/install.sh   # detects dist/ bundle and extracts
bash scripts/run.sh
```

**Producing the `dist/` bundle on a networked build machine:**

```bash
cargo build --release
mkdir -p dist
tar czf dist/oxide-sloc-linux-x86_64.tar.gz -C target/release oxide-sloc
```

Transfer the full repository (or just `dist/` + `scripts/`) to the target machine via
USB, internal file server, or SCP to an intermediate host. Then run `bash scripts/install.sh`.

---

## Option C — Vendor-only source build

Use this when the Rust toolchain is already installed on the target machine.

`vendor.tar.xz` and `vendor.tar.xz.sha256` are **committed to the repository** — they are
present in every `git clone`. No separate download is needed.

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
`.cargo/config.toml`, and runs `cargo build --release --offline`. All output streams
to the terminal and is simultaneously captured to a timestamped log under `logs/`; on
failure, the log path and a clickable link are printed.

> **What vendor.tar.xz covers:** All Rust crate sources (~328 crates). The Rust toolchain
> itself is not included. If you also need to transfer the toolchain, use
> [Option D](#option-d--airgap-kit-linux-no-rust) instead.

---

## Option E — Download from GitHub (Linux, no Rust, has internet)

When `curl` is available and no Rust toolchain is detected, pass `--online` to have
`install.sh` fetch the matching release binary from GitHub Releases and drop it into `dist/`
before extracting.

```bash
bash scripts/install.sh --online   # downloads release binary, extracts
bash scripts/run.sh
```

The downloaded archive is verified against `SHA256SUMS.txt` from the same release when
`sha256sum` is available.

The default (without `--online`) makes no network calls. `--offline` and
`OXIDE_SLOC_NO_DOWNLOAD=1` are retained for backward compatibility and behave identically to
the default.

**System requirements:** `bash`, `tar`, `curl`. `sha256sum` is used for verification when present.

---

## Option D — Airgap kit (Linux, no Rust)

Run `scripts/internal/make-airgap-kit.sh` on any **networked** machine to produce a single
archive that contains everything needed to build oxide-sloc on a machine with no internet
access, no pre-installed Rust, and no system C compiler.

### What the kit bundles

| Component | Purpose |
|---|---|
| `rust-{ver}-{target}.tar.gz` | Rust host toolchain (rustc, cargo, std) |
| `rust-std-{ver}-{musl-target}.tar.gz` | Rust musl target standard library |
| `{arch}-linux-musl-native.tgz` | musl-gcc + headers + libc (no system compiler needed) |
| `vendor.tar.xz` | All ~328 Rust crate sources (no crates.io needed) |
| `oxide-sloc-src.tar.gz` | Full source tree |
| `install.sh` | Wires everything together and builds |

The result is a **fully static binary** — copy it anywhere on Linux and run it with no
runtime library dependencies.

### Generate the kit (networked machine)

```bash
# Auto-detect arch (Linux x86_64 or arm64):
bash scripts/internal/make-airgap-kit.sh

# Or specify explicitly:
bash scripts/internal/make-airgap-kit.sh linux-x86_64
bash scripts/internal/make-airgap-kit.sh linux-arm64

# Output: oxide-sloc-airgap-kit-{platform}-v{version}.tar.gz  (~700 MB)
```

Requirements for running the kit builder: `bash`, `curl`, `tar`, `xz-utils`, `sha256sum`,
`git`, `cargo` (for generating the vendor archive).

### Build on the air-gapped machine

```bash
# Transfer the kit archive via USB, SCP to an intermediate host, internal file server, etc.

tar xzf oxide-sloc-airgap-kit-linux-x86_64-v*.tar.gz
cd oxide-sloc-airgap-kit-*/
bash install.sh
```

The embedded `install.sh`:
1. Installs the Rust toolchain into `.tools/rust/` — no root, no system PATH changes.
2. Installs the musl C toolchain into `.tools/musl/` — no root.
3. Verifies and extracts the vendor crate sources.
4. Builds a fully static oxide-sloc binary with an animated three-phase progress display
   (Verify sources → Compile release build → Install binary) and a frozen completion summary.

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

## Script overview

Users interact with three scripts only. Internal scripts under `scripts/internal/` are
called automatically and should not be invoked directly.

| Script | Purpose | Build progress display |
|---|---|---|
| `bash scripts/install.sh` | Install oxide-sloc (auto-detects best path) | Yes — Verify sources → Compile release build → Install binary |
| `bash scripts/run.sh` | Launch web UI (localhost) | Yes — Resolve dependencies → Compile workspace → Launch server |
| `bash scripts/serve-server.sh` | Launch web UI as LAN server | Yes — Resolve dependencies → Compile workspace → Launch server |

All three scripts show a live animated progress indicator with spinner, progress bar, elapsed
timer, and cycling status messages when compiling from source. On completion the display
freezes with all milestones checked (✓) so the summary remains visible. Every run writes a
timestamped log to `logs/`; on failure the log path and a clickable terminal link are printed.

| Internal script | Called by | Build progress display |
|---|---|---|
| `scripts/internal/airgap-build.sh` | Manually (Option C manual path) | No — plain streaming output; logs to `logs/airgap-build-*.log` |
| `scripts/internal/make-airgap-kit.sh` | Run manually on networked machine to produce Option D kit | Kit's embedded `install.sh` logs to `logs/kit-install-*.log` on the air-gapped machine |
| `scripts/internal/update-vendor.sh` | Maintainer tooling — regenerates `vendor.tar.xz` | No |
| `scripts/internal/install-hooks.sh` | Developer setup — installs git hooks | No |

---

## CI/CD on air-gapped infrastructure

### Jenkins

`vendor.tar.xz` is committed to the repo — Cargo crate sources are fully covered after a
`git clone` with no extra download. The Rust toolchain (compiler, cargo, rustfmt, clippy)
is **not** in git; two air-gapped options are supported:

**Option 1 — Rebuild `ci/jenkins/Dockerfile.agent` (recommended)**

The Dockerfile bakes the pinned toolchain into `/opt/rust-toolchain` at image build time.
All pipeline runs after the image rebuild are fully offline:

```bash
docker build -t jenkins-oxide-sloc:latest -f ci/jenkins/Dockerfile.agent .
docker compose down && docker compose up -d
```

**Option 2 — Commit a toolchain bundle**

Run once on a networked Linux machine, then commit the output via git LFS:

```bash
bash ci/jenkins/bundle-rust-toolchain.sh
git lfs install && git lfs track '*.tar.xz'
git add .gitattributes rust-toolchain-bundle.tar.xz rust-toolchain-bundle.tar.xz.sha256
git commit -m "ci: add Rust toolchain bundle for offline builds"
```

The Jenkinsfile Setup stage detects and extracts the bundle automatically.

### GitLab CI

The included `.gitlab-ci.yml` works the same way. Use a self-hosted GitLab runner with
Rust pre-installed and `vendor.tar.xz` available in the runner's workspace cache or via
a custom pre-clone step.

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
