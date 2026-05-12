#!/usr/bin/env bash
# bundle-rust-toolchain.sh — create a minimal Rust toolchain archive using 7-zip
# ultra compression (level 9) so it can be committed directly to git (no LFS).
#
# Run ONCE on any machine that has internet access. The resulting archives in
# toolchain/ are committed to git and used by install.sh to bootstrap Rust on
# fully air-gapped machines with no pre-installed toolchain.
#
# Target archive sizes after 7-zip level-9 gzip:
#   toolchain/rust-toolchain-windows-x64.tar.gz  ~70-90 MB
#   toolchain/rust-toolchain-linux-x86_64.tar.gz ~60-80 MB
#   toolchain/rust-toolchain-linux-arm64.tar.gz  ~60-80 MB
#
# Usage:
#   bash scripts/internal/bundle-rust-toolchain.sh              # host platform
#   bash scripts/internal/bundle-rust-toolchain.sh windows-x64
#   bash scripts/internal/bundle-rust-toolchain.sh linux-x86_64
#   bash scripts/internal/bundle-rust-toolchain.sh linux-arm64
#   bash scripts/internal/bundle-rust-toolchain.sh all          # all three
#
# Requirements: bash, curl, 7-zip (auto-detected), sha256sum
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TOOLCHAIN_DIR="$REPO_ROOT/toolchain"

# ── Locate 7-zip ─────────────────────────────────────────────────────────────
find_7zip() {
    if command -v 7z &>/dev/null; then
        echo "7z"
        return
    fi
    # Windows common install paths (Git Bash / MSYS2)
    local candidates=(
        "/c/Program Files/7-Zip/7z.exe"
        "/c/Program Files (x86)/7-Zip/7z.exe"
        "/d/Program Files/7-Zip/7z.exe"
        "$HOME/AppData/Local/Programs/7-Zip/7z.exe"
    )
    for p in "${candidates[@]}"; do
        [[ -x "$p" ]] && { echo "$p"; return; }
    done
    # Last-resort: check Windows registry via PowerShell
    if command -v powershell &>/dev/null; then
        local reg_path
        reg_path="$(powershell -NoProfile -Command \
            "try { (Get-ItemProperty 'HKLM:\SOFTWARE\7-Zip').Path + '7z.exe' } catch { '' }" \
            2>/dev/null | tr -d '\r')"
        local git_path
        git_path="$(cygpath "$reg_path" 2>/dev/null)" || git_path="$reg_path"
        [[ -x "$git_path" ]] && { echo "$git_path"; return; }
    fi
    return 1
}

SEVENZIP=""
if SEVENZIP="$(find_7zip)"; then
    echo "[7-zip] $SEVENZIP"
else
    echo "[ERROR] 7-zip not found." >&2
    echo "  Windows: install from https://www.7-zip.org" >&2
    echo "  Linux:   sudo apt install p7zip-full  OR  sudo dnf install p7zip p7zip-plugins" >&2
    exit 1
fi

# ── Read Rust version from rust-toolchain.toml ───────────────────────────────
TOOLCHAIN_TOML="$REPO_ROOT/rust-toolchain.toml"
CHANNEL="$(grep 'channel' "$TOOLCHAIN_TOML" | sed 's/.*= *"\(.*\)"/\1/' | tr -d '[:space:]')"
case "$CHANNEL" in
    stable|nightly|beta) RUST_VER="$CHANNEL" ;;
    *.*.*)               RUST_VER="$CHANNEL" ;;
    *.*)                 RUST_VER="${CHANNEL}.0" ;;
    *)                   RUST_VER="$CHANNEL" ;;
esac
echo "Rust channel: $CHANNEL  (install as: $RUST_VER)"

# ── Platform argument ─────────────────────────────────────────────────────────
PLATFORM_ARG="${1:-}"
if [[ -z "$PLATFORM_ARG" ]]; then
    if [[ -n "${WINDIR+x}" ]] || [[ "${OSTYPE:-}" == msys* ]] || [[ "${OSTYPE:-}" == cygwin* ]]; then
        PLATFORM_ARG="windows-x64"
    else
        case "$(uname -m 2>/dev/null)" in
            aarch64|arm64) PLATFORM_ARG="linux-arm64"  ;;
            *)             PLATFORM_ARG="linux-x86_64" ;;
        esac
    fi
    echo "Auto-detected platform: $PLATFORM_ARG"
fi

build_one() {
    local plat="$1"
    local rust_target output_name

    case "$plat" in
        windows-x64)
            rust_target="x86_64-pc-windows-gnu"
            output_name="rust-toolchain-windows-x64.tar.gz"
            ;;
        linux-x86_64)
            rust_target="x86_64-unknown-linux-gnu"
            output_name="rust-toolchain-linux-x86_64.tar.gz"
            ;;
        linux-arm64)
            rust_target="aarch64-unknown-linux-gnu"
            output_name="rust-toolchain-linux-arm64.tar.gz"
            ;;
        *)
            echo "[ERROR] Unknown platform '$plat'. Supported: windows-x64 linux-x86_64 linux-arm64" >&2
            return 1
            ;;
    esac

    echo ""
    echo "━━━ Building toolchain archive for $plat ━━━"

    local work_dir
    work_dir="$(mktemp -d)"
    # shellcheck disable=SC2064
    trap "rm -rf '$work_dir'" EXIT

    local rustup_home="$work_dir/rustup"
    local cargo_home="$work_dir/cargo"
    mkdir -p "$rustup_home" "$cargo_home"

    # ── Install rustup + minimal toolchain ───────────────────────────────────
    echo "  Installing minimal Rust $RUST_VER toolchain via rustup..."
    local rustup_init
    if [[ -n "${WINDIR+x}" ]] || [[ "${OSTYPE:-}" == msys* ]]; then
        rustup_init="$work_dir/rustup-init.exe"
        curl -fsSL --connect-timeout 30 \
            "https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-gnu/rustup-init.exe" \
            -o "$rustup_init"
    else
        rustup_init="$work_dir/rustup-init"
        curl -fsSL --connect-timeout 30 \
            "https://sh.rustup.rs" | \
            RUSTUP_HOME="$rustup_home" CARGO_HOME="$cargo_home" \
            sh -s -- -y --default-toolchain "$RUST_VER" \
                --profile minimal \
                --no-modify-path \
                --target "$rust_target" \
                2>&1 | grep -v "^info:" | grep -v "^$" || true
        rustup_init=""
    fi

    if [[ -n "$rustup_init" ]]; then
        RUSTUP_HOME="$rustup_home" CARGO_HOME="$cargo_home" \
            "$rustup_init" -y \
                --default-toolchain "$RUST_VER" \
                --profile minimal \
                --no-modify-path \
                --target "$rust_target" \
                2>&1 | grep -v "^info:" | grep -v "^$" || true
    fi

    # ── Identify the installed toolchain directory ────────────────────────────
    local tc_dir
    tc_dir="$(find "$rustup_home/toolchains" -maxdepth 1 -type d | grep -v '^$' | grep "$rust_target" | head -1)"
    if [[ -z "$tc_dir" ]]; then
        # Try without host arch suffix
        tc_dir="$(find "$rustup_home/toolchains" -maxdepth 1 -mindepth 1 -type d | head -1)"
    fi
    if [[ -z "$tc_dir" ]]; then
        echo "[ERROR] Toolchain directory not found after rustup install." >&2
        return 1
    fi
    echo "  Toolchain installed: $tc_dir"

    local tc_size
    tc_size="$(du -sm "$tc_dir" | awk '{print $1}')"; echo "  Uncompressed size: ${tc_size} MB"

    # ── Package with 7-zip level 9 gzip ─────────────────────────────────────
    mkdir -p "$TOOLCHAIN_DIR"
    local output="$TOOLCHAIN_DIR/$output_name"
    local tmp_tar="$work_dir/toolchain.tar"

    echo "  Creating tar archive..."
    # Bundle: toolchain binaries + cargo home (registry cache stripped)
    rm -rf "$cargo_home/registry" "$cargo_home/git"
    tar -cf "$tmp_tar" \
        -C "$work_dir" \
        "rustup" \
        "cargo"

    echo "  Compressing with 7-zip level 9..."
    # 7-zip gzip: -tgzip creates .gz wrapper; -mx=9 = ultra compression
    "$SEVENZIP" a -tgzip -mx=9 -mpass=15 "$output" "$tmp_tar" > /dev/null

    local out_size
    out_size="$(du -sm "$output" | awk '{print $1}')"
    echo "  [OK] $output_name  (${out_size} MB compressed from ${tc_size} MB)"

    trap - EXIT
    rm -rf "$work_dir"
}

# ── Run ──────────────────────────────────────────────────────────────────────
mkdir -p "$TOOLCHAIN_DIR"

if [[ "$PLATFORM_ARG" == "all" ]]; then
    for plat in windows-x64 linux-x86_64 linux-arm64; do
        build_one "$plat"
    done
else
    build_one "$PLATFORM_ARG"
fi

# ── Regenerate checksums.sha256 ──────────────────────────────────────────────
echo ""
echo "Regenerating toolchain/checksums.sha256..."
CHECKSUMS="$TOOLCHAIN_DIR/checksums.sha256"
{
    printf '# oxide-sloc Rust toolchain checksums\n'
    printf '# Generated by scripts/internal/bundle-rust-toolchain.sh\n'
    printf '# Rust %s — minimal profile (rustc, cargo, rust-std)\n' "$RUST_VER"
    printf '# Compressed with 7-zip ultra (level 9) — committed directly to git, no LFS\n'
    printf '# Verify with: sha256sum -c toolchain/checksums.sha256\n\n'
    for f in "$TOOLCHAIN_DIR"/rust-toolchain-*.tar.gz; do
        [[ -f "$f" ]] && sha256sum "$f"
    done
} > "$CHECKSUMS"
cat "$CHECKSUMS"

echo ""
echo "Done. Commit the results (no git LFS required — archives are < 100 MB):"
echo ""
echo "  git add toolchain/"
echo "  git commit -m \"chore: update bundled Rust toolchain\""
echo "  git push"
echo ""
echo "Any 'git clone' of the repo will include the toolchain."
echo "Running 'bash scripts/install.sh' on a no-Rust machine will bootstrap"
echo "Rust from the bundle and build oxide-sloc from vendor sources offline."
