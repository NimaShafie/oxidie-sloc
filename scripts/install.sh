#!/usr/bin/env bash
# oxide-sloc installer
#
# Usage:
#   bash scripts/install.sh           # auto-detects best path
#   bash scripts/install.sh --rebuild # force a fresh build even if binary exists
#   bash scripts/install.sh --auto    # install rustup automatically if needed (no prompt)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

FORCE_REBUILD=false
AUTO_RUSTUP=false
for arg in "$@"; do
    case "$arg" in
        --rebuild|--force|-f) FORCE_REBUILD=true ;;
        --auto) AUTO_RUSTUP=true ;;
    esac
done

# Detect Windows (Git Bash / MSYS2 / Cygwin)
if [[ -n "${WINDIR+x}" ]] || [[ "${OSTYPE:-}" == msys* ]] || [[ "${OSTYPE:-}" == cygwin* ]]; then
    PLATFORM=windows
    EXE="$REPO_ROOT/oxide-sloc.exe"
    DIST_ARCHIVE="$REPO_ROOT/dist/oxide-sloc-windows-x64.zip"
    BUILD_OUTPUT="$REPO_ROOT/target/release/oxide-sloc.exe"
else
    PLATFORM=linux
    EXE="$REPO_ROOT/oxide-sloc"
    DIST_ARCHIVE="$REPO_ROOT/dist/oxide-sloc-linux-x86_64.tar.gz"
    BUILD_OUTPUT="$REPO_ROOT/target/release/oxide-sloc"
fi

VENDOR_ARCHIVE="$REPO_ROOT/vendor.tar.xz"
VENDOR_DIR="$REPO_ROOT/vendor"

echo ""
echo " oxide-sloc installer"
echo " ════════════════════"

# ── 1. Already installed ────────────────────────────────────────────────────
if [[ -f "$EXE" ]] && [[ "$FORCE_REBUILD" == false ]]; then
    echo " [OK] $(basename "$EXE") already present."
    echo " Run: bash scripts/run.sh"
    echo " To rebuild from source:  bash scripts/install.sh --rebuild"
    exit 0
fi

if [[ -f "$EXE" ]] && [[ "$FORCE_REBUILD" == true ]]; then
    echo " [--rebuild] Removing existing binary to force a fresh build..."
    rm -f "$EXE"
fi

# ── 2. Pre-built binary ─────────────────────────────────────────────────────
if [[ -f "$DIST_ARCHIVE" ]]; then
    echo " Extracting pre-built binary from dist/..."
    if [[ "$PLATFORM" == windows ]]; then
        WIN_ARCHIVE="$(cygpath -w "$DIST_ARCHIVE")"
        WIN_DEST="$(cygpath -w "$REPO_ROOT")"
        powershell -NoProfile -Command \
            "Expand-Archive -Path '$WIN_ARCHIVE' -DestinationPath '$WIN_DEST' -Force"
    else
        tar xzf "$DIST_ARCHIVE" -C "$REPO_ROOT"
    fi
    if [[ -f "$EXE" ]]; then
        [[ "$PLATFORM" == linux ]] && chmod +x "$EXE"
        echo " [OK] Extracted $(basename "$EXE")"
        echo ""
        echo " Start the web UI:  bash scripts/run.sh"
        exit 0
    fi
    echo " [WARN] Extraction completed but binary not found — archive may be corrupt."
fi

# ── 3. Build from vendored sources ──────────────────────────────────────────
if command -v cargo &>/dev/null; then
    if [[ ! -d "$VENDOR_DIR" ]]; then
        if [[ -f "$VENDOR_ARCHIVE" ]]; then
            echo " Decompressing vendor.tar.xz (22 MB → 362 MB, one-time)..."
            tar -xJf "$VENDOR_ARCHIVE" -C "$REPO_ROOT"
            echo " [OK] Vendor sources ready."
        else
            echo " [ERROR] Neither vendor/ nor vendor.tar.xz found." >&2
            echo "         Download vendor.tar.xz from the release page and place it" >&2
            echo "         alongside the repository, or clone the full repository." >&2
            exit 1
        fi
    fi

    echo " Rust found. Building from vendored sources (this may take a few minutes)..."
    # Create the cargo offline config that redirects to vendor/
    mkdir -p "$REPO_ROOT/.cargo"
    cat > "$REPO_ROOT/.cargo/config.toml" <<'EOF'
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
EOF

    cd "$REPO_ROOT"
    cargo build --release --offline -p oxide-sloc

    if [[ -f "$BUILD_OUTPUT" ]]; then
        cp "$BUILD_OUTPUT" "$EXE"
        [[ "$PLATFORM" == linux ]] && chmod +x "$EXE"
        echo " [OK] Built and installed $(basename "$EXE")"
        echo ""
        echo " Start the web UI:  bash scripts/run.sh"
        exit 0
    fi
    echo " [ERROR] Build failed. Check output above." >&2
    exit 1
fi

# ── 4. No Rust — offer to install it (networked) or give air-gap instructions ──

echo ""
echo " No pre-built binary and no Rust toolchain found."
echo ""

# Detect whether we can reach the internet (quick probe, ignore errors).
_has_internet=false
if command -v curl &>/dev/null && curl -sSf --max-time 4 https://sh.rustup.rs -o /dev/null 2>/dev/null; then
    _has_internet=true
elif command -v wget &>/dev/null && wget -q --timeout=4 --spider https://sh.rustup.rs 2>/dev/null; then
    _has_internet=true
fi

if [[ "$_has_internet" == true ]] && [[ "$PLATFORM" == linux ]]; then
    echo " Internet detected. Rust is required to build from source."
    echo ""
    if [[ "$AUTO_RUSTUP" == true ]]; then
        _install_rust=y
    else
        printf ' Install Rust toolchain now via rustup? [y/N] '
        read -r _install_rust </dev/tty || _install_rust=n
    fi

    if [[ "${_install_rust,,}" == y* ]]; then
        echo " Installing rustup (minimal profile, stable toolchain)..."
        curl -sSf https://sh.rustup.rs | sh -s -- --default-toolchain stable --profile minimal -y
        # Source the newly-installed cargo environment for this session
        # shellcheck source=/dev/null
        source "$HOME/.cargo/env" 2>/dev/null || export PATH="$HOME/.cargo/bin:$PATH"
        echo " [OK] Rust installed. Re-running installer..."
        exec bash "$SCRIPT_DIR/install.sh" "$@"
    fi
fi

echo " Option A — pre-built binary (easiest, no Rust required):"
echo "   Download from https://github.com/oxide-sloc/oxide-sloc/releases"
echo "   Place the binary next to scripts/, then run:  bash scripts/install.sh"
echo ""
echo " Option B — install Rust and build from source:"
if [[ "$PLATFORM" == linux ]]; then
    echo "   curl -sSf https://sh.rustup.rs | sh"
    echo "   source ~/.cargo/env"
    echo "   bash scripts/install.sh"
else
    echo "   Download rustup-init.exe from https://rustup.rs and run it."
    echo "   Open a new Git Bash terminal, then: bash scripts/install.sh"
fi
echo ""
echo " Option C — build from source on an air-gapped machine:"
echo "   On a NETWORKED machine, bundle the Rust toolchain:"
echo ""
if [[ "$PLATFORM" == linux ]]; then
    echo "   curl -sSf https://sh.rustup.rs | sh -s -- --default-toolchain stable --no-modify-path"
    echo "   tar -czf rust-toolchain-linux.tar.gz ~/.rustup ~/.cargo"
    echo "   Transfer to this machine, then:"
    echo "   tar xzf rust-toolchain-linux.tar.gz -C ~"
    echo "   echo 'export PATH=\"\$HOME/.cargo/bin:\$PATH\"' >> ~/.bashrc && source ~/.bashrc"
    echo "   bash scripts/install.sh"
else
    echo "   rustup-init.exe --default-toolchain stable --no-modify-path"
    echo "   Compress-Archive \"\$env:USERPROFILE\.rustup\",\"\$env:USERPROFILE\.cargo\" rust-toolchain-windows.zip"
    echo "   Transfer to this machine, then (PowerShell):"
    echo "   Expand-Archive rust-toolchain-windows.zip -DestinationPath \$env:USERPROFILE"
    echo "   [Environment]::SetEnvironmentVariable('PATH', \"\$env:USERPROFILE\.cargo\bin;\$env:PATH\", 'User')"
    echo "   Open a new terminal, then:  bash scripts/install.sh"
fi
echo ""
exit 1
