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

LOG_DIR="$REPO_ROOT/logs"
mkdir -p "$LOG_DIR"

print_log_link() {
    local f="$1"
    local url
    if [[ "$PLATFORM" == windows ]]; then
        local wf
        wf="$(cygpath -w "$f" 2>/dev/null)" || wf="$f"
        wf="${wf//\\/\/}"
        url="file:///$wf"
    else
        url="file://$f"
    fi
    printf '  Log dir:  %s\n' "$LOG_DIR"
    printf '  Log file: %s\n' "$(basename "$f")"
    printf '  \033]8;;%s\033\\Click to open log\033]8;;\033\\\n' "$url"
}

# Runs `cargo build --release --offline -p oxide-sloc` with an animated progress display.
# Returns the cargo exit code.
build_with_progress() {
    local tmpout
    tmpout="$(mktemp)"
    local LOG_FILE="$LOG_DIR/install-$(date +%Y-%m-%d-%H-%M-%S).log"

    local total_pkgs=0
    if [[ -f "$REPO_ROOT/Cargo.lock" ]]; then
        total_pkgs="$(grep -c '^\[\[package\]\]' "$REPO_ROOT/Cargo.lock" 2>/dev/null)" || total_pkgs=0
    fi

    printf '\n'
    cargo build --release --offline -p oxide-sloc 2>"$tmpout" &
    local cargo_pid=$!

    trap 'kill "$cargo_pid" 2>/dev/null; rm -f "$tmpout"; printf "\033[?25h\n"; exit 130' INT TERM

    local spin=('|' '/' '-' '\')
    local si=0 compiled=0 last_crate="" bar_w=34
    local start_time="$SECONDS"
    local is_linking=0 first_draw=1
    local NLINES=9
    local resolution_msgs=(
        "Reading Cargo.lock..."
        "Verifying vendor archive..."
        "Checking source checksums..."
        "Scanning crate manifests..."
        "Validating offline sources..."
        "Preparing release build..."
    )
    local msg_idx=0 frame_count=0 msg_interval=17  # rotate every ~2 s (17 × 0.12 s)

    printf '\033[?25l'

    while kill -0 "$cargo_pid" 2>/dev/null; do
        compiled="$(grep -c "^   Compiling" "$tmpout" 2>/dev/null)" || compiled=0
        if [[ "$compiled" -gt 0 ]]; then
            last_crate="$(grep "^   Compiling" "$tmpout" 2>/dev/null | tail -1 | \
                sed 's/^   Compiling //' | cut -c1-46)" || last_crate=""
        fi
        grep -q "Linking " "$tmpout" 2>/dev/null && is_linking=1 || true

        local elapsed=$(( SECONDS - start_time ))
        local elapsed_str
        printf -v elapsed_str '%d:%02d' "$(( elapsed / 60 ))" "$(( elapsed % 60 ))"

        local frame="${spin[$si]}"
        si=$(( (si + 1) % 4 ))
        frame_count=$(( frame_count + 1 ))

        local phase step_n
        if   [[ "$is_linking" -eq 1 ]]; then phase="Linking & installing";      step_n=3
        elif [[ "$compiled"   -gt 0 ]]; then phase="Compiling release build";   step_n=2
        else                                 phase="Verifying sources";          step_n=1
        fi

        local bar="" fill=0 i
        if [[ "$total_pkgs" -gt 0 && "$compiled" -gt 0 ]]; then
            fill=$(( compiled * bar_w / total_pkgs ))
            [[ $fill -gt $bar_w ]] && fill=$bar_w
        fi
        for (( i = 0; i < bar_w; i++ )); do
            if   [[ $i -lt $fill ]]; then
                bar+='='
            elif [[ $i -eq $fill && $compiled -gt 0 && $fill -lt $bar_w ]]; then
                bar+='>'
            else
                bar+=' '
            fi
        done

        local count_str pct_str=""
        if [[ "$total_pkgs" -gt 0 ]]; then
            count_str="${compiled} / ~${total_pkgs}"
            [[ "$compiled" -gt 0 ]] && pct_str="($(( compiled * 100 / total_pkgs ))%)"
        else
            count_str="${compiled} crates"
        fi

        local ic_res='\xe2\x97\x8b' ic_cmp='\xe2\x97\x8b' ic_lnk='\xe2\x97\x8b'
        if   [[ "$is_linking" -eq 1 ]]; then
            ic_res='\xe2\x9c\x93'; ic_cmp='\xe2\x9c\x93'; ic_lnk="$frame"
        elif [[ "$compiled"   -gt 0 ]]; then
            ic_res='\xe2\x9c\x93'; ic_cmp="$frame"
        else
            ic_res="$frame"
        fi

        [[ "$first_draw" -eq 0 ]] && printf "\033[%dA" "$NLINES"
        first_draw=0

        printf "  %s  Step [%d/3]  %-46s\033[K\n"  "$frame"  "$step_n"  "$phase"
        printf "     [%s] %-16s%s\033[K\n"          "$bar"    "$count_str"  "$pct_str"
        local current_display
        if [[ "$compiled" -eq 0 ]]; then
            (( frame_count % msg_interval == 0 )) && msg_idx=$(( (msg_idx + 1) % ${#resolution_msgs[@]} ))
            current_display="${resolution_msgs[$msg_idx]}"
        else
            current_display="$last_crate"
        fi
        printf "     Current:  %-50s\033[K\n"       "$current_display"
        printf "     Elapsed:  %-50s\033[K\n"       "$elapsed_str"
        printf "     \033[K\n"
        printf "     Milestones:\033[K\n"
        printf "     %b  Verify sources\033[K\n"         "$ic_res"
        printf "     %b  Compile release build\033[K\n"  "$ic_cmp"
        printf "     %b  Install binary\033[K\n"         "$ic_lnk"

        sleep 0.12
    done

    wait "$cargo_pid"
    local exit_code=$?
    printf '\033[?25h'
    trap - INT TERM

    compiled="$(grep -c "^   Compiling" "$tmpout" 2>/dev/null)" || compiled=0

    {
        printf '# oxide-sloc install log\n# Date:     %s\n# Platform: %s\n# Exit:     %d\n#\n' \
            "$(date)" "$PLATFORM" "$exit_code"
        cat "$tmpout"
    } > "$LOG_FILE"

    [[ "$first_draw" -eq 0 ]] && printf "\033[%dA" "$NLINES"

    if [[ $exit_code -ne 0 ]]; then
        printf "  \xe2\x9c\x97  BUILD FAILED%-67s\n" ""
        for (( i = 1; i < NLINES; i++ )); do printf "\033[K\n"; done
        printf '\n'
        cat "$tmpout" >&2
        rm -f "$tmpout"
        printf '\n  Build failed. Full output saved:\n'
        print_log_link "$LOG_FILE"
        printf '\n'
        return 1
    fi

    rm -f "$tmpout"

    local final_elapsed=$(( SECONDS - start_time ))
    local final_elapsed_str
    printf -v final_elapsed_str '%d:%02d' "$(( final_elapsed / 60 ))" "$(( final_elapsed % 60 ))"

    local final_bar=""
    for (( i = 0; i < bar_w; i++ )); do final_bar+='='; done

    local final_count_str final_pct_str=""
    if [[ "$compiled" -gt 0 ]]; then
        final_count_str="${compiled} crates"
        final_pct_str="(100%)"
    fi

    if [[ "$compiled" -gt 0 ]]; then
        printf "  \xe2\x9c\x93  Step [3/3]  Build complete \xe2\x80\x94 %d crates compiled.%-13s\033[K\n" "$compiled" ""
        printf "     [%s] %-16s%s\033[K\n"    "$final_bar" "$final_count_str" "$final_pct_str"
        printf "     Current:  %-50s\033[K\n" "Done."
    else
        printf "  \xe2\x9c\x93  Step [3/3]  Already up to date.%-31s\033[K\n" ""
        printf "     [%s]\033[K\n"             "$final_bar"
        printf "     Current:  %-50s\033[K\n" "No changes detected."
    fi
    printf "     Elapsed:  %-50s\033[K\n" "$final_elapsed_str"
    printf "     \033[K\n"
    printf "     Milestones:\033[K\n"
    printf "     \xe2\x9c\x93  Verify sources\033[K\n"
    printf "     \xe2\x9c\x93  Compile release build\033[K\n"
    printf "     \xe2\x9c\x93  Install binary\033[K\n"
    printf '\n  Log \xe2\x86\x92 %s\n' "$LOG_FILE"
    return 0
}

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
        # Tolerate tarballs that use the platform-named binary instead of bare "oxide-sloc"
        if [[ "$PLATFORM" == linux ]] && [[ ! -f "$EXE" ]] && \
           [[ -f "$REPO_ROOT/oxide-sloc-linux-${LINUX_ARCH}" ]]; then
            mv "$REPO_ROOT/oxide-sloc-linux-${LINUX_ARCH}" "$EXE"
        fi
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
    # Tolerate tarballs that use the platform-named binary instead of bare "oxide-sloc"
    if [[ ! -f "$EXE" ]] && [[ -f "$REPO_ROOT/oxide-sloc-linux-${LINUX_ARCH}" ]]; then
        mv "$REPO_ROOT/oxide-sloc-linux-${LINUX_ARCH}" "$EXE"
    fi
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

    echo " Rust found. Building from vendored sources..."
    # Create the cargo offline config that redirects to vendor/
    mkdir -p "$REPO_ROOT/.cargo"
    cat > "$REPO_ROOT/.cargo/config.toml" <<'EOF'
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
EOF

    cd "$REPO_ROOT"
    build_with_progress || exit 1

    if [[ -f "$BUILD_OUTPUT" ]]; then
        cp "$BUILD_OUTPUT" "$EXE"
        [[ "$PLATFORM" == linux ]] && chmod +x "$EXE"
        echo " [OK] Built and installed $(basename "$EXE")"
        echo ""
        echo " Start the web UI:  bash scripts/run.sh"
        exit 0
    fi
    echo " [ERROR] Build failed — binary not found after build." >&2
    exit 1
fi

# ── 4. No binary and no Rust toolchain ──────────────────────────────────────

echo ""
echo " No pre-built binary found and no Rust toolchain detected."
echo ""
if [[ "$PLATFORM" == windows ]]; then
    echo " Expected: dist/oxide-sloc-windows-x64.zip  (committed pre-built binary)"
    echo " That file is missing from this clone — your repository may be incomplete."
    echo ""
    echo " If you cloned from GitHub, re-clone and ensure Git LFS / large files are"
    echo " fetched:  git clone https://github.com/oxide-sloc/oxide-sloc"
    echo ""
    echo " To build from source (requires Rust ≥1.95):"
    echo "   bash scripts/internal/airgap-build.sh vendor.tar.xz"
    echo ""
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
