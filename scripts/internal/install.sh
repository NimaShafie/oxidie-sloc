#!/usr/bin/env bash
# oxide-sloc installer
#
# Usage:
#   bash scripts/internal/install.sh           # build from source (offline, no Rust required)
#   bash scripts/internal/install.sh --online  # download pre-built binary from GitHub Releases (Linux only)
#   bash scripts/internal/install.sh --rebuild # force a fresh build even if a binary already exists
#   bash scripts/internal/install.sh --auto    # auto-install rustup if cargo is absent (interactive prompt)
#
# Behavior:
#   --online: downloads the pre-built binary for the host arch, verifies its SHA-256 checksum,
#             and installs it.  Falls back to source build if the download or verification fails.
#   default:  compiles from source using vendor.tar.xz (committed). No network access required.
#   If cargo (Rust) is on PATH  → extract vendor sources + run cargo build --release --offline.
#   If no cargo on PATH          → bootstrap Rust from toolchain/ archives, then build.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

FORCE_REBUILD=false
AUTO_RUSTUP=false
ONLINE_MODE=false
for arg in "$@"; do
    case "$arg" in
        --rebuild|--force|-f) FORCE_REBUILD=true ;;
        --auto) AUTO_RUSTUP=true ;;
        --online) ONLINE_MODE=true ;;
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

# Import sloc-ca.crt into CurrentUser\Root via a direct registry write.
# The standard X509Store API always triggers a Windows Security Warning dialog for root
# certificates; writing the backing registry key directly bypasses it — no dialog, no Admin.
trust_ca_cert() {
    [[ "$PLATFORM" != windows ]] && return 0
    local cert="$REPO_ROOT/certs/sloc-ca.crt"
    [[ -f "$cert" ]] || return 0
    local cert_win
    cert_win="$(cygpath -w "$cert" 2>/dev/null || echo "$cert")"

    echo " Trusting oxide-sloc signing certificate (current user, no dialog)..."

    local ps_result
    ps_result="$(powershell.exe -NoProfile -NonInteractive -Command "
\$certPath = '${cert_win}'
\$cert    = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(\$certPath)
\$thumb   = \$cert.Thumbprint
\$regPath = \"HKCU:\SOFTWARE\Microsoft\SystemCertificates\Root\Certificates\\\$thumb\"

if (Test-Path \$regPath) { Write-Output 'ALREADY_TRUSTED'; exit 0 }

# Blob: propCount(4) + propId=20(4) + reserved(4) + derLen(4) + derBytes(N)
\$der  = \$cert.RawData
\$blob = [byte[]]::new(16 + \$der.Length)
\$pos  = 0
[System.BitConverter]::GetBytes([uint32]1 ).CopyTo(\$blob, \$pos); \$pos += 4
[System.BitConverter]::GetBytes([uint32]20).CopyTo(\$blob, \$pos); \$pos += 4
[System.BitConverter]::GetBytes([uint32]0 ).CopyTo(\$blob, \$pos); \$pos += 4
[System.BitConverter]::GetBytes([uint32]\$der.Length).CopyTo(\$blob, \$pos); \$pos += 4
\$der.CopyTo(\$blob, \$pos)

New-Item -Path \$regPath -Force | Out-Null
Set-ItemProperty -Path \$regPath -Name 'Blob' -Value \$blob -Type Binary
Write-Output 'IMPORTED'
" 2>/dev/null)" || true

    case "$ps_result" in
        ALREADY_TRUSTED)
            echo " [OK] Certificate already trusted — skipping."
            ;;
        IMPORTED)
            echo " [OK] Certificate trusted silently. Authenticode verification enabled."
            ;;
        *)
            echo " [WARN] Certificate import via registry failed. To trust manually (no Admin needed):"
            echo "        certutil -user -addstore Root certs/sloc-ca.crt"
            ;;
    esac
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
        "Scanning vendor crate manifests..."
        "Resolving dependency graph..."
        "Checking crate versions..."
        "Verifying source checksums..."
        "Building compile plan..."
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
        if [[ "$compiled" -eq 0 ]]; then
            # Phase 1: bouncing scanner — cargo is silent during resolution so we can't
            # track real progress; use an indeterminate animation to show activity.
            local scanner_w=5
            local bounce_range=$(( bar_w - scanner_w ))
            local bounce_pos=$(( frame_count % (bounce_range * 2) ))
            local scan_left
            if [[ $bounce_pos -le $bounce_range ]]; then
                scan_left=$bounce_pos
            else
                scan_left=$(( bounce_range * 2 - bounce_pos ))
            fi
            for (( i = 0; i < bar_w; i++ )); do
                if [[ $i -ge $scan_left && $i -lt $(( scan_left + scanner_w )) ]]; then
                    bar+='='
                else
                    bar+='.'
                fi
            done
        else
            if [[ "$total_pkgs" -gt 0 ]]; then
                fill=$(( compiled * bar_w / total_pkgs ))
                [[ $fill -gt $bar_w ]] && fill=$bar_w
            fi
            for (( i = 0; i < bar_w; i++ )); do
                if   [[ $i -lt $fill ]];                          then bar+='='
                elif [[ $i -eq $fill && $fill -lt $bar_w ]];     then bar+='>'
                else                                                   bar+=' '
                fi
            done
        fi

        local count_str pct_str=""
        if [[ "$compiled" -eq 0 ]]; then
            count_str="scanning..."
        elif [[ "$total_pkgs" -gt 0 ]]; then
            count_str="${compiled} / ~${total_pkgs}"
            pct_str="($(( compiled * 100 / total_pkgs ))%)"
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
        if [[ "$compiled" -eq 0 ]]; then
            # Phase 1: show verification sub-steps; step 2 advances at ~60s, step 3 at ~120s
            local ic_vs2 ic_vs3
            if   [[ $elapsed -lt 60  ]]; then ic_vs2="$frame"; ic_vs3='\xe2\x97\x8b'
            elif [[ $elapsed -lt 120 ]]; then ic_vs2="$frame"; ic_vs3="$frame"
            else                               ic_vs2="$frame"; ic_vs3="$frame"
            fi
            printf "     Scan steps:\033[K\n"
            printf "     \xe2\x9c\x93  Read Cargo.lock (%d packages)\033[K\n"  "$total_pkgs"
            printf "     %b  Validate vendor manifests\033[K\n"                 "$ic_vs2"
            printf "     %b  Build compile plan\033[K\n"                        "$ic_vs3"
        else
            printf "     Milestones:\033[K\n"
            printf "     %b  Verify sources\033[K\n"         "$ic_res"
            printf "     %b  Compile release build\033[K\n"  "$ic_cmp"
            printf "     %b  Install binary\033[K\n"         "$ic_lnk"
        fi

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
    echo " To rebuild from source:  bash scripts/internal/install.sh --rebuild"
    exit 0
fi

if [[ -f "$EXE" ]] && [[ "$FORCE_REBUILD" == true ]]; then
    echo " [--rebuild] Removing existing binary to force a fresh build..."
    rm -f "$EXE"
fi

# ── 2. Pre-built binary from dist/ (Windows) ────────────────────────────────
# oxide-sloc-windows-x64.zip is committed to dist/ by update-dist.yml after
# every release.  Extracting it here skips the toolchain bootstrap entirely —
# no unsigned PE files are written to disk, so EDR software won't block the install.
if [[ "$PLATFORM" == windows ]] && [[ "$FORCE_REBUILD" == false ]]; then
    DIST_WIN="$REPO_ROOT/dist/oxide-sloc-windows-x64.zip"
    if [[ -f "$DIST_WIN" ]]; then
        echo " Pre-built Windows binary found in dist/ — extracting..."
        _DIST_TMP="$(mktemp -d)"
        _DIST_OK=false
        if command -v unzip &>/dev/null; then
            unzip -q "$DIST_WIN" -d "$_DIST_TMP" && _DIST_OK=true
        else
            _DIST_WIN_W="$(cygpath -w "$DIST_WIN" 2>/dev/null || echo "$DIST_WIN")"
            _DIST_TMP_W="$(cygpath -w "$_DIST_TMP" 2>/dev/null || echo "$_DIST_TMP")"
            powershell.exe -NoProfile -NonInteractive -Command \
                "Expand-Archive -Path '$_DIST_WIN_W' -DestinationPath '$_DIST_TMP_W' -Force" \
                && _DIST_OK=true
        fi
        if [[ "$_DIST_OK" == true ]] && [[ -f "$_DIST_TMP/oxide-sloc.exe" ]]; then
            cp "$_DIST_TMP/oxide-sloc.exe" "$EXE"
            rm -rf "$_DIST_TMP"
            echo " [OK] oxide-sloc.exe installed from dist/"
            trust_ca_cert
            echo ""
            echo " Start the web UI:  bash scripts/run.sh"
            exit 0
        fi
        rm -rf "$_DIST_TMP"
        echo " [WARN] dist/ extraction failed — falling back to source build." >&2
    fi
fi

# ── 3. Online binary download (--online, Linux only) ────────────────────────
# Fetch the pre-built binary for this platform from GitHub Releases, verify its
# SHA-256 checksum, and install it.  Falls through to source build on any error.
if [[ "$ONLINE_MODE" == true ]] && [[ "$PLATFORM" == linux ]]; then
    _OV="$(grep '^version' "$REPO_ROOT/Cargo.toml" 2>/dev/null | head -1 | sed 's/.*"\(.*\)".*/\1/')"
    _ASSET="oxide-sloc-linux-${LINUX_ARCH}.tar.gz"
    _BASE="https://github.com/oxide-sloc/oxide-sloc/releases/download/v${_OV}"

    echo " Downloading oxide-sloc v${_OV} (linux-${LINUX_ARCH})..."

    _TMP="$(mktemp -d)"
    _OK=false

    if curl -fsSL -o "$_TMP/$_ASSET" "${_BASE}/${_ASSET}" 2>&1; then
        if curl -fsSL -o "$_TMP/SHA256SUMS.txt" "${_BASE}/SHA256SUMS.txt" 2>&1; then
            cd "$_TMP"
            if grep "$_ASSET" SHA256SUMS.txt | sha256sum --check --status 2>/dev/null; then
                tar -xzf "$_ASSET" -C "$_TMP"
                if [[ -f "$_TMP/oxide-sloc" ]]; then
                    cp "$_TMP/oxide-sloc" "$EXE"
                    chmod +x "$EXE"
                    _OK=true
                fi
            else
                echo " [WARN] Checksum mismatch — falling back to source build." >&2
            fi
            cd "$REPO_ROOT"
        else
            echo " [WARN] Could not fetch SHA256SUMS.txt — falling back to source build." >&2
        fi
    else
        echo " [WARN] Download failed — falling back to source build." >&2
    fi

    rm -rf "$_TMP"

    if [[ "$_OK" == true ]]; then
        echo " Downloaded and verified."
        echo " [OK] oxide-sloc v${_OV} installed → $(basename "$EXE")"
        echo ""
        echo " Start the web UI:  bash scripts/run.sh"
        exit 0
    fi
fi

# ── 4. Bootstrap Rust from bundled toolchain (if cargo not on PATH) ──────────
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

        # RHEL/Linux: ensure a C linker is available (needed by Rust GNU target)
        if [[ "$PLATFORM" == linux ]] && ! command -v cc &>/dev/null && ! command -v gcc &>/dev/null; then
            echo ""
            echo " [WARN] No C linker (cc/gcc) found." >&2
            echo "        The Rust GNU target requires a C linker to link executables." >&2
            echo "        Install with:" >&2
            echo "          RHEL/CentOS:  sudo dnf install gcc" >&2
            echo "          Debian/Ubuntu: sudo apt install gcc" >&2
            echo "        Then re-run: bash scripts/internal/install.sh" >&2
            exit 1
        fi
    fi
fi

# ── 5. Build from vendored sources ──────────────────────────────────────────
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

# ── 6. No Rust toolchain available ──────────────────────────────────────────

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
echo "   bash scripts/internal/install.sh"
echo ""
echo " Full deployment guide: docs/airgap.md"
echo ""
exit 1
