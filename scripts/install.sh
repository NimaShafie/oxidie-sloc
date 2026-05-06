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
            echo "         vendor.tar.xz is committed to the repository — ensure you have" >&2
            echo "         the complete repository, not just source files." >&2
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

# ── 4. No binary and no Rust toolchain ──────────────────────────────────────

echo ""
echo " No pre-built binary found and no Rust toolchain detected."
echo ""
echo " This repository is fully self-contained — no internet required."
echo " Refer to docs/airgap.md for the correct path for your environment:"
echo ""
if [[ "$PLATFORM" == windows ]]; then
    echo "  • oxide-sloc.exe should be present in the repository root."
    echo "    Ensure you have the complete repository package (not just source files)."
else
    echo "  • Linux pre-built binary:"
    echo "    Place dist/oxide-sloc-linux-x86_64.tar.gz alongside this repository"
    echo "    (produced by CI or a networked build machine), then re-run:"
    echo "    bash scripts/install.sh"
    echo ""
    echo "  • Linux source build (Rust not installed):"
    echo "    Use the self-contained airgap kit. On a networked machine run:"
    echo "    bash scripts/internal/make-airgap-kit.sh"
    echo "    Transfer the resulting archive via USB or internal file server, then:"
    echo "    tar xzf oxide-sloc-airgap-kit-*.tar.gz"
    echo "    cd oxide-sloc-airgap-kit-*/"
    echo "    bash install.sh"
fi
echo ""
echo " Full deployment guide: docs/airgap.md"
echo ""
exit 1
