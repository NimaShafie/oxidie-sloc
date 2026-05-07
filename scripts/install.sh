#!/usr/bin/env bash
# oxide-sloc installer
#
# Usage:
#   bash scripts/install.sh           # auto-detects best path (offline by default)
#   bash scripts/install.sh --rebuild # force a fresh build even if binary exists
#   bash scripts/install.sh --auto    # install rustup automatically if needed (no prompt)
#   bash scripts/install.sh --offline # explicit offline mode (now the default; kept for compatibility)
#   bash scripts/install.sh --online  # allow downloading release binary from GitHub if needed
#
# Environment:
#   OXIDE_SLOC_NO_DOWNLOAD=1  same as --offline
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

FORCE_REBUILD=false
AUTO_RUSTUP=false
OFFLINE=true   # default: no internet required; use --online to opt in
for arg in "$@"; do
    case "$arg" in
        --rebuild|--force|-f) FORCE_REBUILD=true ;;
        --auto) AUTO_RUSTUP=true ;;
        --offline) OFFLINE=true ;;
        --online) OFFLINE=false ;;
    esac
done
[[ "${OXIDE_SLOC_NO_DOWNLOAD:-}" == "1" ]] && OFFLINE=true

# Detect Windows (Git Bash / MSYS2 / Cygwin)
if [[ -n "${WINDIR+x}" ]] || [[ "${OSTYPE:-}" == msys* ]] || [[ "${OSTYPE:-}" == cygwin* ]]; then
    PLATFORM=windows
    EXE="$REPO_ROOT/oxide-sloc.exe"
    DIST_ARCHIVE="$REPO_ROOT/dist/oxide-sloc-windows-x64.zip"
    BUILD_OUTPUT="$REPO_ROOT/target/release/oxide-sloc.exe"
else
    PLATFORM=linux
    EXE="$REPO_ROOT/oxide-sloc"
    # Detect host architecture so we fetch the right release asset
    case "$(uname -m 2>/dev/null)" in
        aarch64|arm64) LINUX_ARCH=arm64 ;;
        *)             LINUX_ARCH=x86_64 ;;
    esac
    DIST_ARCHIVE="$REPO_ROOT/dist/oxide-sloc-linux-${LINUX_ARCH}.tar.gz"
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

# ── 2.5. Download release binary from GitHub (Linux, --online requested) ────
if [[ "$PLATFORM" == linux ]] && [[ "$OFFLINE" == false ]] && ! command -v cargo &>/dev/null; then
    if command -v curl &>/dev/null; then
        VER=$(grep -m1 '^version = ' "$REPO_ROOT/Cargo.toml" 2>/dev/null | sed 's/version = "\(.*\)"/\1/')
        if [[ -n "$VER" ]]; then
            RELEASE_URL="https://github.com/oxide-sloc/oxide-sloc/releases/download/v${VER}/oxide-sloc-linux-${LINUX_ARCH}.tar.gz"
            SUMS_URL="https://github.com/oxide-sloc/oxide-sloc/releases/download/v${VER}/SHA256SUMS.txt"
            echo " Downloading release binary v${VER} (${LINUX_ARCH}) from GitHub..."
            mkdir -p "$REPO_ROOT/dist"
            if curl -fsSL --connect-timeout 10 --max-time 120 -o "$DIST_ARCHIVE" "$RELEASE_URL"; then
                # Verify SHA256 when sha256sum is available
                SUMS_TMP=$(mktemp)
                ASSET="oxide-sloc-linux-${LINUX_ARCH}.tar.gz"
                if command -v sha256sum &>/dev/null && \
                   curl -fsSL --connect-timeout 10 --max-time 30 -o "$SUMS_TMP" "$SUMS_URL" 2>/dev/null; then
                    EXPECTED=$(grep "$ASSET" "$SUMS_TMP" 2>/dev/null | awk '{print $1}' || true)
                    ACTUAL=$(sha256sum "$DIST_ARCHIVE" | awk '{print $1}')
                    rm -f "$SUMS_TMP"
                    if [[ -n "$EXPECTED" ]] && [[ "$EXPECTED" != "$ACTUAL" ]]; then
                        echo " [ERROR] SHA256 mismatch — download may be corrupt or tampered." >&2
                        rm -f "$DIST_ARCHIVE"
                    elif [[ -z "$EXPECTED" ]]; then
                        echo " [OK] Downloaded (no entry for ${ASSET} in SHA256SUMS.txt — skipping verification)."
                    else
                        echo " [OK] Downloaded and verified."
                    fi
                else
                    rm -f "$SUMS_TMP"
                    echo " [OK] Downloaded (checksum file unavailable — skipping verification)."
                fi
            else
                echo " [WARN] Could not reach GitHub Releases — continuing without download."
                rm -f "$DIST_ARCHIVE"
            fi
        fi
    fi
fi

# Re-check dist/ archive after potential download
if [[ -f "$DIST_ARCHIVE" ]] && [[ ! -f "$EXE" ]]; then
    echo " Extracting pre-built binary from dist/..."
    tar xzf "$DIST_ARCHIVE" -C "$REPO_ROOT"
    if [[ -f "$EXE" ]]; then
        chmod +x "$EXE"
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
if [[ "$PLATFORM" == windows ]]; then
    echo " oxide-sloc.exe should be present in the repository root."
    echo " Ensure you have the complete repository package (not just source files)."
    echo " Full deployment guide: docs/airgap.md"
else
    echo " Options (see docs/airgap.md for details):"
    echo ""
    echo "  • Internet available (opt-in — re-run with --online):"
    echo "    install.sh fetches the release binary from GitHub automatically"
    echo "    when curl is present and no Rust toolchain is detected."
    echo "    curl is required. Run: bash scripts/install.sh --online"
    echo ""
    echo "  • Pre-staged dist/ bundle (Option B — no internet on target machine):"
    echo "    Place dist/oxide-sloc-linux-${LINUX_ARCH}.tar.gz here, then re-run:"
    echo "    bash scripts/install.sh"
    echo ""
    echo "  • Full air-gap kit (Option D — no internet, no Rust, no curl):"
    echo "    On a networked machine: bash scripts/internal/make-airgap-kit.sh"
    echo "    Transfer the kit archive, then:"
    echo "    tar xzf oxide-sloc-airgap-kit-*.tar.gz && cd oxide-sloc-airgap-kit-*/"
    echo "    bash install.sh"
fi
echo ""
echo " Full deployment guide: docs/airgap.md"
echo ""
exit 1
