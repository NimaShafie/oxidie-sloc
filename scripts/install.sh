#!/usr/bin/env bash
# oxide-sloc installer
#
# Usage:
#   bash scripts/install.sh           # build from source (offline, no Rust required)
#   bash scripts/install.sh --rebuild # force a fresh build even if a binary already exists
#   bash scripts/install.sh --auto    # auto-install rustup if cargo is absent (interactive prompt)
#
# Behavior:
#   No pre-built oxide-sloc binaries are shipped. Every install compiles from source.
#   If cargo (Rust) is on PATH  → extract vendor sources + run cargo build --release --offline.
#   If no cargo on PATH          → bootstrap Rust from toolchain/ archives, then build.
#   All dependency sources are in vendor.tar.xz (committed). No network access required.
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
    BUILD_OUTPUT="$REPO_ROOT/target/release/oxide-sloc.exe"
else
    PLATFORM=linux
    EXE="$REPO_ROOT/oxide-sloc"
    # Detect host architecture so we fetch the right release asset
    case "$(uname -m 2>/dev/null)" in
        aarch64|arm64) LINUX_ARCH=arm64 ;;
        *)             LINUX_ARCH=x86_64 ;;
    esac
    BUILD_OUTPUT="$REPO_ROOT/target/release/oxide-sloc"
fi

# Prefer vendor.tar.gz (gzip-compressed) if present; fall back to vendor.tar.xz
if [[ -f "$REPO_ROOT/vendor.tar.gz" ]]; then
    VENDOR_ARCHIVE="$REPO_ROOT/vendor.tar.gz"
    VENDOR_DECOMP="tar -xzf"
else
    VENDOR_ARCHIVE="$REPO_ROOT/vendor.tar.xz"
    VENDOR_DECOMP="tar -xJf"
fi
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

# After toolchain extraction: check whether the bundled cargo.exe is Authenticode-signed.
# Uses Get-AuthenticodeSignature (read-only, no admin needed). Prints a clear pass/fail
# so the user knows immediately if EDR on a corporate device will block the binary.
# When unsigned, explains the two non-admin paths (signing or IT-managed Rust install).
check_toolchain_signing() {
    [[ "$PLATFORM" != windows ]] && return 0
    local cargo_bin="$TOOLS_DIR/cargo/bin/cargo.exe"
    [[ -f "$cargo_bin" ]] || return 0
    local cargo_win
    cargo_win="$(cygpath -w "$cargo_bin" 2>/dev/null || echo "$cargo_bin")"
    local status
    status="$(powershell.exe -NoProfile -NonInteractive -Command \
        "(Get-AuthenticodeSignature '$cargo_win').Status" 2>/dev/null || echo "Unknown")"
    if [[ "$status" == "Valid" ]]; then
        echo " [OK] Toolchain binaries are Authenticode-signed — EDR will not flag them."
    else
        echo ""
        echo " WARNING: The extracted Rust toolchain binaries are unsigned."
        echo " On a corporate device managed by Carbon Black, CrowdStrike, or Defender"
        echo " with strict policy, cargo.exe / rustup.exe may be blocked — and without"
        echo " admin rights there is nothing a local user can do to un-block them."
        echo ""
        echo " Two solutions (neither requires admin rights on your machine):"
        echo ""
        echo "  1) Ask your project maintainer to activate Authenticode signing:"
        echo "     Set WINDOWS_CERTIFICATE in GitHub Actions secrets, then re-run"
        echo "     the 'Bundle Rust toolchain' workflow. The resulting toolchain"
        echo "     archives will contain signed PE files. No exclusions needed."
        echo ""
        echo "  2) Ask your IT team to install Rust (rustup) system-wide."
        echo "     When cargo is already on PATH, this installer skips .tools/"
        echo "     extraction entirely — no unsigned PE files are written at all."
        echo ""
        echo " See docs/av-whitelisting.md for details."
        echo ""
    fi
}

# Offer to import sloc-ca.crt into the current user's Windows trust store.
# Uses PowerShell X509Store API — no Administrator rights required, no GUI dialog.
trust_ca_cert() {
    [[ "$PLATFORM" != windows ]] && return 0
    local cert="$REPO_ROOT/certs/sloc-ca.crt"
    [[ -f "$cert" ]] || return 0
    local cert_win
    cert_win="$(cygpath -w "$cert" 2>/dev/null || echo "$cert")"
    # Skip silently if already trusted
    if certutil -user -verifystore Root "OxideSLOC Root CA" &>/dev/null 2>&1; then
        return 0
    fi
    echo " Trusting oxide-sloc signing certificate (current user, no Admin required)..."
    # X509Store.Add() via .NET imports into CurrentUser\Root without a confirmation dialog,
    # unlike certutil -addstore which always pops a Windows Security Warning for root certs.
    local ps_script="\$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2('${cert_win}'); \$store = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root','CurrentUser'); \$store.Open('ReadWrite'); \$store.Add(\$cert); \$store.Close()"
    if powershell.exe -NoProfile -NonInteractive -Command "$ps_script" &>/dev/null 2>&1; then
        echo " [OK] Certificate trusted. Signed binaries will verify without internet."
    else
        echo " [WARN] Certificate import failed. To trust manually (no Admin needed):"
        echo "        certutil -user -addstore Root certs/sloc-ca.crt"
    fi
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
    trust_ca_cert
    echo " Run: bash scripts/run.sh"
    echo " To rebuild from source:  bash scripts/install.sh --rebuild"
    exit 0
fi

if [[ -f "$EXE" ]] && [[ "$FORCE_REBUILD" == true ]]; then
    echo " [--rebuild] Removing existing binary to force a fresh build..."
    rm -f "$EXE"
fi

# ── 2. Bootstrap Rust from bundled toolchain (if cargo not on PATH) ──────────
# If cargo is not on PATH but a toolchain archive is committed to toolchain/,
# extract it locally into .tools/ and export the paths.
# Archives are gzip-9 .tar.gz files split into ≤45 MB parts by
# bundle-rust-toolchain.sh.  Parts:  rustup/  (toolchains)  and  cargo/  (bin/).
if ! command -v cargo &>/dev/null; then
    if [[ "$PLATFORM" == windows ]]; then
        TOOLCHAIN_ARCHIVE="$REPO_ROOT/toolchain/rust-toolchain-windows-x64.tar.gz"
    else
        TOOLCHAIN_ARCHIVE="$REPO_ROOT/toolchain/rust-toolchain-linux-${LINUX_ARCH}.tar.gz"
    fi

    # Collect split parts (*.tar.gz.aa, .ab, …); fall back to single archive
    TOOLCHAIN_PARTS=()
    for _tp in "${TOOLCHAIN_ARCHIVE}".*; do
        [[ -f "$_tp" ]] && TOOLCHAIN_PARTS+=("$_tp")
    done
    HAVE_TOOLCHAIN=false
    [[ "${#TOOLCHAIN_PARTS[@]}" -gt 0 ]] && HAVE_TOOLCHAIN=true
    [[ -f "$TOOLCHAIN_ARCHIVE" ]]         && HAVE_TOOLCHAIN=true

    if [[ "$HAVE_TOOLCHAIN" == true ]]; then
        echo " No Rust toolchain detected — bootstrapping from bundled archive..."
        echo " (one-time extract → ~300-500 MB on disk)"
        echo ""
        # Verify checksum of each part or the single archive
        TOOLCHAIN_CHECKSUMS="$REPO_ROOT/toolchain/checksums.sha256"
        if [[ -f "$TOOLCHAIN_CHECKSUMS" ]] && command -v sha256sum &>/dev/null; then
            _VERIFY_FILES=()
            if [[ "${#TOOLCHAIN_PARTS[@]}" -gt 0 ]]; then
                _VERIFY_FILES=("${TOOLCHAIN_PARTS[@]}")
            else
                _VERIFY_FILES=("$TOOLCHAIN_ARCHIVE")
            fi
            for _vf in "${_VERIFY_FILES[@]}"; do
                _VF_NAME="$(basename "$_vf")"
                _EXPECTED="$(grep "$_VF_NAME" "$TOOLCHAIN_CHECKSUMS" 2>/dev/null | awk '{print $1}')"
                if [[ -n "$_EXPECTED" ]]; then
                    _ACTUAL="$(sha256sum "$_vf" | awk '{print $1}')"
                    if [[ "$_EXPECTED" != "$_ACTUAL" ]]; then
                        echo " [ERROR] Toolchain checksum mismatch — ${_VF_NAME} may be corrupt." >&2
                        echo "         Expected: $_EXPECTED" >&2
                        echo "         Actual:   $_ACTUAL" >&2
                        exit 1
                    fi
                fi
            done
            echo " [OK] Toolchain checksum verified."
        fi

        TOOLS_DIR="$REPO_ROOT/.tools"
        mkdir -p "$TOOLS_DIR"

        echo " Extracting toolchain archive..."
        if [[ "$PLATFORM" == windows ]]; then
            # Windows: Git Bash tar records rustup's proxy hardlinks (cargo.exe,
            # rustc.exe, etc.) as POSIX symlinks pointing to rustup.exe.  Symlink
            # creation fails with ENOENT when the target hasn't been extracted yet
            # (alphabetical ordering puts cargo.exe before rustup.exe).  Extract
            # while tolerating those specific errors, then copy rustup.exe over
            # any proxy that tar couldn't create.
            _tar_stderr="$(mktemp)"
            if [[ "${#TOOLCHAIN_PARTS[@]}" -gt 0 ]]; then
                cat "${TOOLCHAIN_PARTS[@]}" | tar -xzf - -C "$TOOLS_DIR" \
                    2>"$_tar_stderr" || true
            else
                tar -xzf "$TOOLCHAIN_ARCHIVE" -C "$TOOLS_DIR" \
                    2>"$_tar_stderr" || true
            fi
            # Surface any real errors (non-symlink); silently discard symlink noise.
            grep -v "Cannot create symlink" "$_tar_stderr" >&2 || true
            rm -f "$_tar_stderr"
            # Patch missing proxy binaries: every file in cargo/bin/ that tar
            # couldn't create is a hardlink alias of rustup.exe — copy it there.
            _rustup_proxy="$TOOLS_DIR/cargo/bin/rustup.exe"
            if [[ -f "$_rustup_proxy" ]]; then
                for _proxy in cargo.exe rustc.exe rustdoc.exe; do
                    [[ -f "$TOOLS_DIR/cargo/bin/$_proxy" ]] || \
                        cp "$_rustup_proxy" "$TOOLS_DIR/cargo/bin/$_proxy"
                done
                echo " [OK] Windows toolchain proxy binaries verified."
            fi
        elif [[ "${#TOOLCHAIN_PARTS[@]}" -gt 0 ]]; then
            cat "${TOOLCHAIN_PARTS[@]}" | tar -xzf - -C "$TOOLS_DIR"
        else
            tar -xzf "$TOOLCHAIN_ARCHIVE" -C "$TOOLS_DIR"
        fi

        # Archive layout (from bundle-rust-toolchain.sh):
        #   .tools/rustup/toolchains/<ver>-<target>/bin/  ← rustc, etc.
        #   .tools/cargo/bin/                              ← cargo
        RUSTUP_HOME_LOCAL="$TOOLS_DIR/rustup"
        CARGO_HOME_LOCAL="$TOOLS_DIR/cargo"

        # Find the toolchain bin dir
        TC_BIN="$(find "$RUSTUP_HOME_LOCAL/toolchains" -maxdepth 2 -name bin -type d 2>/dev/null | head -1)"

        export RUSTUP_HOME="$RUSTUP_HOME_LOCAL"
        export CARGO_HOME="$CARGO_HOME_LOCAL"
        export PATH="$CARGO_HOME_LOCAL/bin:${TC_BIN:-$RUSTUP_HOME_LOCAL/bin}:$PATH"

        if ! command -v cargo &>/dev/null; then
            echo " [ERROR] cargo not found after toolchain extraction." >&2
            echo "         Verify the toolchain archive is complete and try:" >&2
            echo "           bash scripts/internal/bundle-rust-toolchain.sh" >&2
            exit 1
        fi
        echo " [OK] Rust toolchain bootstrapped at .tools/"
        check_toolchain_signing

        # RHEL/Linux: ensure a C linker is available (needed by Rust GNU target)
        if [[ "$PLATFORM" == linux ]] && ! command -v cc &>/dev/null && ! command -v gcc &>/dev/null; then
            echo ""
            echo " [WARN] No C linker (cc/gcc) found." >&2
            echo "        The Rust GNU target requires a C linker to link executables." >&2
            echo "        Install with:" >&2
            echo "          RHEL/CentOS:  sudo dnf install gcc" >&2
            echo "          Debian/Ubuntu: sudo apt install gcc" >&2
            echo "        Then re-run: bash scripts/install.sh" >&2
            exit 1
        fi
    fi
fi

# ── 3. Build from vendored sources ──────────────────────────────────────────
if command -v cargo &>/dev/null; then
    if [[ ! -d "$VENDOR_DIR" ]]; then
        if [[ -f "$VENDOR_ARCHIVE" ]]; then
            echo " Decompressing $(basename "$VENDOR_ARCHIVE") (one-time)..."
            $VENDOR_DECOMP "$VENDOR_ARCHIVE" -C "$REPO_ROOT"
            echo " [OK] Vendor sources ready."
        else
            echo " [ERROR] Neither vendor/ nor vendor.tar.xz / vendor.tar.gz found." >&2
            echo "         The vendor archive is committed to the repository — ensure you have" >&2
            echo "         the complete repository, not just source files." >&2
            exit 1
        fi
    fi

    echo " Rust toolchain found — building from vendored sources..."
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
        trust_ca_cert
        echo ""
        echo " Start the web UI:  bash scripts/run.sh"
        exit 0
    fi
    echo " [ERROR] Build failed — binary not found after build." >&2
    exit 1
fi

# ── 4. No Rust toolchain available ──────────────────────────────────────────

echo ""
echo " No Rust toolchain detected and no bundled toolchain archives found."
echo ""
echo " The toolchain/rust-toolchain-*.tar.gz.* archives must be present for"
echo " offline source builds. A maintainer generates them with:"
echo ""
if [[ "$PLATFORM" == windows ]]; then
    echo "   bash scripts/internal/bundle-rust-toolchain.sh windows-x64"
else
    echo "   bash scripts/internal/bundle-rust-toolchain.sh linux-x86_64   # or linux-arm64"
fi
echo "   git add toolchain/"
echo "   git commit -m \"chore: bundle Rust toolchain for offline builds\""
echo "   git push"
echo ""
echo " After the toolchain archives are committed, re-run this script on any fresh clone."
echo ""
echo " If Rust is already installed on this machine:"
echo "   bash scripts/install.sh"
echo ""
echo " Full deployment guide: docs/airgap.md"
echo ""
exit 1
