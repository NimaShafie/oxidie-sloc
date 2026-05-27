#!/usr/bin/env bash
# bundle-rust-toolchain.sh — create a minimal Rust toolchain archive using
# gzip -9, then split into ≤45 MB parts so every committed file stays well
# under GitHub's 100 MB per-file limit.
#
# Run ONCE on any machine that has internet access. The resulting parts in
# toolchain/ are committed to git and used by install.sh to bootstrap Rust on
# fully air-gapped machines with no pre-installed toolchain.
#
# Target part sizes after gzip -9 + split at 45 MB:
#   toolchain/rust-toolchain-windows-x64.tar.gz.aa  ≤45 MB (+ .ab if needed)
#   toolchain/rust-toolchain-linux-x86_64.tar.gz.aa ≤45 MB (+ .ab if needed)
#   toolchain/rust-toolchain-linux-arm64.tar.gz.aa  ≤45 MB (+ .ab if needed)
#
# Usage:
#   bash scripts/internal/bundle-rust-toolchain.sh              # host platform
#   bash scripts/internal/bundle-rust-toolchain.sh windows-x64
#   bash scripts/internal/bundle-rust-toolchain.sh linux-x86_64
#   bash scripts/internal/bundle-rust-toolchain.sh linux-arm64
#   bash scripts/internal/bundle-rust-toolchain.sh all          # all three
#
# Requirements: bash, curl, gzip, tar, sha256sum
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TOOLCHAIN_DIR="$REPO_ROOT/toolchain"

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
        # Download rustup-init to a file before executing — avoids the curl|sh
        # pattern flagged by OpenSSF Scorecard Pinned-Dependencies.
        rustup_init="$work_dir/rustup-init.sh"
        curl -fsSL --connect-timeout 30 \
            "https://sh.rustup.rs" -o "$rustup_init"
        RUSTUP_HOME="$rustup_home" CARGO_HOME="$cargo_home" \
            sh "$rustup_init" -y --default-toolchain "$RUST_VER" \
                --profile minimal \
                --no-modify-path \
                2>&1 | grep -v "^info:" | grep -v "^$" || true
        rm -f "$rustup_init"
        rustup_init=""
    fi

    if [[ -n "$rustup_init" ]]; then
        # rustup-init.exe is a native Windows EXE and cannot interpret MSYS2-style
        # paths like /c/Users/... — convert to Windows paths before passing as env vars.
        WIN_RUSTUP_HOME="$(cygpath -w "$rustup_home" 2>/dev/null || echo "$rustup_home")"
        WIN_CARGO_HOME="$(cygpath -w "$cargo_home" 2>/dev/null || echo "$cargo_home")"
        RUSTUP_HOME="$WIN_RUSTUP_HOME" CARGO_HOME="$WIN_CARGO_HOME" \
            "$rustup_init" -y \
                --default-toolchain "$RUST_VER" \
                --default-host "$rust_target" \
                --profile minimal \
                --no-modify-path \
                2>&1 | grep -v "^info:" | grep -v "^$" || true
    fi

    # ── Identify the installed toolchain directory ────────────────────────────
    local tc_dir
    # grep exits 1 when no match — || true prevents set -euo pipefail from killing the script
    tc_dir="$(find "$rustup_home/toolchains" -maxdepth 1 -type d | grep -v '^$' | grep "$rust_target" | head -1 || true)"
    if [[ -z "$tc_dir" ]]; then
        # Fallback: take whatever toolchain rustup installed
        tc_dir="$(find "$rustup_home/toolchains" -maxdepth 1 -mindepth 1 -type d | head -1 || true)"
    fi
    if [[ -z "$tc_dir" ]]; then
        echo "[ERROR] Toolchain directory not found after rustup install." >&2
        return 1
    fi
    echo "  Toolchain installed: $tc_dir"

    local tc_size
    tc_size="$(du -sm "$tc_dir" | awk '{print $1}')"; echo "  Uncompressed size: ${tc_size} MB"

    # ── Authenticode-sign Windows PE binaries (optional) ─────────────────────
    # When WINDOWS_CERT_PFX and WINDOWS_CERT_PASS are set (injected by
    # bundle-toolchain.yml), sign every .exe before packing.
    if [[ "$plat" == "windows-x64" ]] && [[ -n "${WINDOWS_CERT_PFX:-}" ]] && [[ -f "${WINDOWS_CERT_PFX}" ]]; then
        echo "  Authenticode-signing bundled Windows PE binaries..."
        _signtool=""
        if command -v signtool.exe &>/dev/null; then
            _signtool="signtool.exe"
        elif command -v signtool &>/dev/null; then
            _signtool="signtool"
        fi
        if [[ -n "$_signtool" ]]; then
            _pfx_win="$(cygpath -w "$WINDOWS_CERT_PFX" 2>/dev/null || echo "$WINDOWS_CERT_PFX")"
            _signed=0; _failed=0
            while IFS= read -r -d '' _bin; do
                _bin_win="$(cygpath -w "$_bin" 2>/dev/null || echo "$_bin")"
                if "$_signtool" sign \
                    /f "$_pfx_win" /p "${WINDOWS_CERT_PASS:-}" \
                    /tr http://timestamp.digicert.com /td sha256 /fd sha256 \
                    /d "Oxide SLOC Rust Toolchain" \
                    "$_bin_win" 2>/dev/null; then
                    (( _signed++ )) || true
                else
                    (( _failed++ )) || true
                fi
            done < <(find "$cargo_home/bin" "$rustup_home/toolchains" -name "*.exe" -print0 2>/dev/null)
            echo "  [OK] Signed ${_signed} toolchain binaries (${_failed} skipped/failed)."
        else
            echo "  [WARN] signtool not found — skipping PE signing."
        fi
    fi

    # ── Package with gzip -9 ────────────────────────────────────────────────
    mkdir -p "$TOOLCHAIN_DIR"
    local output="$TOOLCHAIN_DIR/$output_name"
    local tmp_tar="$work_dir/toolchain.tar"

    echo "  Creating tar archive..."
    # Bundle: toolchain binaries + cargo home (registry cache stripped)
    rm -rf "$cargo_home/registry" "$cargo_home/git"
    # --hard-dereference: store hardlinked files as independent regular files so
    # that extraction on Windows (Git Bash tar) never needs to create symlinks.
    # On Linux this also dereferences the rustup proxy symlinks in cargo/bin/.
    tar --hard-dereference -cf "$tmp_tar" \
        -C "$work_dir" \
        "rustup" \
        "cargo"

    echo "  Compressing with gzip -9..."
    gzip -9 -c "$tmp_tar" > "$output"

    local out_size_mb
    out_size_mb="$(du -sm "$output" | awk '{print $1}')"
    echo "  Compressed: ${out_size_mb} MB — splitting into ≤45 MB parts..."

    # Split into ≤45 MB parts so every committed file stays under GitHub's limit.
    # install.sh reassembles via: cat rust-toolchain-*.tar.gz.* | tar -xzf - -C .tools/
    split -b 45m "$output" "${output}."
    rm "$output"

    local part_count
    part_count="$(ls "${output}".* 2>/dev/null | wc -l | tr -d '[:space:]')"
    echo "  [OK] $output_name → ${part_count} part(s) of ≤45 MB each"

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
    printf '# Compressed with gzip -9, split into ≤45 MB parts\n'
    printf '# Verify with: sha256sum -c toolchain/checksums.sha256\n\n'
    for f in "$TOOLCHAIN_DIR"/rust-toolchain-*.tar.gz.*; do
        [[ -f "$f" ]] && sha256sum "$f"
    done
} > "$CHECKSUMS"
cat "$CHECKSUMS"

echo ""
echo "Done. Commit the results:"
echo ""
echo "  git add toolchain/"
echo "  git commit -m \"chore: update bundled Rust toolchain\""
echo "  git push"
echo ""
echo "Any 'git clone' of the repo will include the toolchain parts."
echo "Running 'bash scripts/run.sh' on a no-Rust machine will reassemble"
echo "the parts, bootstrap Rust, and build oxide-sloc from vendor sources offline."
