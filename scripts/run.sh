#!/usr/bin/env bash
# oxide-sloc launcher
#
# Usage:
#   bash scripts/run.sh              # localhost only  (http://127.0.0.1:4317)
#   bash scripts/run.sh --host       # LAN server mode (http://0.0.0.0:4317)
#   bash scripts/run.sh --lan        # alias for --host
#   SLOC_HOST=1 bash scripts/run.sh  # env-var form of --host
#
# For a dedicated LAN-server launcher with API-key setup and IP guidance see:
#   bash scripts/serve-server.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SLOC_PORT=4317

# Honour SLOC_HOST env var as well as --host / --lan CLI flag
HOST_MODE="${SLOC_HOST:-0}"

# Detect Windows (Git Bash / MSYS2 / Cygwin)
if [[ -n "${WINDIR+x}" ]] || [[ "${OSTYPE:-}" == msys* ]] || [[ "${OSTYPE:-}" == cygwin* ]]; then
    PLATFORM=windows
    EXE="$REPO_ROOT/oxide-sloc.exe"
    EXE_DIST="$REPO_ROOT/dist/oxide-sloc.exe"
    EXE_BUILD="$REPO_ROOT/target/release/oxide-sloc.exe"
    BUNDLE="$REPO_ROOT/dist/oxide-sloc-windows-x64.zip"
else
    PLATFORM=linux
    EXE="$REPO_ROOT/oxide-sloc"
    EXE_DIST="$REPO_ROOT/dist/oxide-sloc"
    EXE_BUILD="$REPO_ROOT/target/release/oxide-sloc"
    BUNDLE="$REPO_ROOT/dist/oxide-sloc-linux-x86_64.tar.gz"
fi

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

# Kill any process currently holding SLOC_PORT so re-launches never fail with
# "address already in use".  On Windows this covers both clean exits and
# hard-killed processes that leave a zombie socket.
free_port() {
    if [[ "$PLATFORM" == windows ]]; then
        powershell -NoProfile -Command "
            # Kill by process name first (fastest path)
            Get-Process -Name 'oxide-sloc' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
            # Also kill whatever process owns the TCP port
            \$conn = Get-NetTCPConnection -LocalPort $SLOC_PORT -ErrorAction SilentlyContinue
            if (\$conn) {
                \$conn | Select-Object -ExpandProperty OwningProcess | Sort-Object -Unique |
                    ForEach-Object { Stop-Process -Id \$_ -Force -ErrorAction SilentlyContinue }
            }
        " 2>/dev/null || true
        # Give Windows up to 2 s to release the socket
        local tries=0
        while netstat -ano 2>/dev/null | grep -qE ":${SLOC_PORT}[[:space:]].*LISTENING"; do
            (( tries++ )) && (( tries >= 8 )) && break
            sleep 0.25
        done
    else
        pkill -x oxide-sloc 2>/dev/null || true
        command -v fuser &>/dev/null && fuser -k "${SLOC_PORT}/tcp" 2>/dev/null || true
        # Brief wait for the kernel to release the socket
        sleep 0.3
    fi
}

# Print the local LAN IP if available (best-effort; no failure on error).
# On Linux, prefers the default-route interface over docker bridge addresses.
print_lan_ip() {
    local ip=""
    if [[ "$PLATFORM" == linux ]]; then
        # Try the address on the default route first (avoids picking a docker bridge)
        if command -v ip &>/dev/null; then
            ip="$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' | head -1)" || true
        fi
        if [[ -z "$ip" ]]; then
            ip="$(hostname -I 2>/dev/null | tr ' ' '\n' | \
                grep -vE '^(127\.|172\.(1[6-9]|2[0-9]|3[01])\.|10\.(88|244)\.|169\.254\.|$)' | \
                head -1)" || true
        fi
    else
        ip="$(powershell -NoProfile -Command \
            "(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { \$_.IPAddress -notmatch '^127\.' -and \$_.IPAddress -notmatch '^169\.254\.' } | Select-Object -First 1).IPAddress" \
            2>/dev/null)" || true
    fi
    [[ -n "$ip" ]] && printf '  LAN address \xe2\x86\x92 http://%s:%s\n' "$ip" "$SLOC_PORT"
}

# ── Firewall preflight (Linux only) ───────────────────────────────────────────
FIREWALL_STATUS="unknown"
FIREWALL_FIX=""

check_firewall() {
    [[ "$PLATFORM" != linux ]] && return
    if command -v firewall-cmd &>/dev/null && firewall-cmd --state &>/dev/null 2>&1; then
        if firewall-cmd --query-port="${SLOC_PORT}/tcp" &>/dev/null 2>&1; then
            FIREWALL_STATUS="open (firewalld)"
        else
            FIREWALL_STATUS="BLOCKED (firewalld active, port not permitted)"
            FIREWALL_FIX="sudo firewall-cmd --add-port=${SLOC_PORT}/tcp --permanent && sudo firewall-cmd --reload"
        fi
    elif command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        if ufw status | grep -qE "^${SLOC_PORT}(/tcp)?[[:space:]]+ALLOW"; then
            FIREWALL_STATUS="open (ufw)"
        else
            FIREWALL_STATUS="BLOCKED (ufw active, port not permitted)"
            FIREWALL_FIX="sudo ufw allow ${SLOC_PORT}/tcp"
        fi
    else
        FIREWALL_STATUS="no managed firewall detected"
    fi
}

# Abort if the port is still in use after free_port — e.g. owned by another user.
assert_port_free() {
    [[ "$PLATFORM" == windows ]] && return
    command -v ss &>/dev/null || return
    if ss -tln 2>/dev/null | grep -qE ":${SLOC_PORT}\b"; then
        printf '\nERROR: could not free port %s; another oxide-sloc may be running as a different user.\n' "$SLOC_PORT" >&2
        printf '  Check: ss -tlnp | grep %s\n\n' "$SLOC_PORT" >&2
        exit 1
    fi
}

launch() {
    free_port
    assert_port_free
    [[ "$PLATFORM" == linux ]] && chmod +x "$1"
    cd "$REPO_ROOT"
    export OXIDE_SLOC_ROOT="$REPO_ROOT"
    if [[ "$HOST_MODE" == "1" ]]; then
        check_firewall
        printf '\n  oxide-sloc starting in LAN server mode\n  Local   \xe2\x86\x92 http://127.0.0.1:%s\n' "$SLOC_PORT"
        print_lan_ip
        if [[ "$PLATFORM" == linux ]]; then
            printf '  Firewall: %s\n' "$FIREWALL_STATUS"
            if [[ -n "$FIREWALL_FIX" ]]; then
                printf '    Other LAN hosts cannot reach this server until you run:\n'
                printf '      %s\n' "$FIREWALL_FIX"
            fi
        fi
        printf '\n'
        [[ -z "${SLOC_API_KEY:-}" ]] && printf '  WARNING: SLOC_API_KEY is not set \xe2\x80\x94 all endpoints are unauthenticated.\n           Set it before exposing to untrusted networks.\n\n'
        printf '  Press Ctrl+C to stop.\n\n'
        "$1" serve --server
    else
        printf '\n  oxide-sloc starting \xe2\x86\x92 http://127.0.0.1:%s\n  Press Ctrl+C to stop.\n\n' "$SLOC_PORT"
        "$1"
    fi
}

launch_cargo() {
    free_port
    assert_port_free
    cd "$REPO_ROOT"
    export OXIDE_SLOC_ROOT="$REPO_ROOT"

    local bin_path="$REPO_ROOT/target/debug/oxide-sloc"
    [[ "$PLATFORM" == windows ]] && bin_path="${bin_path}.exe"

    local tmpout
    tmpout="$(mktemp)"
    local LOG_FILE="$LOG_DIR/run-$(date +%Y-%m-%d-%H-%M-%S).log"

    # Approximate total from lockfile for the progress bar denominator
    local total_pkgs=0
    if [[ -f "$REPO_ROOT/Cargo.lock" ]]; then
        total_pkgs="$(grep -c '^\[\[package\]\]' "$REPO_ROOT/Cargo.lock" 2>/dev/null)" || total_pkgs=0
    fi

    printf '\n  oxide-sloc \xe2\x80\x94 building from source\n\n'

    cargo build -p oxide-sloc 2>"$tmpout" &
    local cargo_pid=$!

    trap 'kill "$cargo_pid" 2>/dev/null; rm -f "$tmpout"; printf "\033[?25h\n"; exit 130' INT TERM

    local spin=('|' '/' '-' '\')
    local si=0 compiled=0 last_crate="" bar_w=34
    local start_time="$SECONDS"
    local is_linking=0 first_draw=1
    local NLINES=9  # height of the dynamic status block
    local resolution_msgs=(
        "Reading Cargo.lock..."
        "Verifying vendor sources..."
        "Resolving dependency graph..."
        "Checking workspace manifests..."
        "Scanning crate metadata..."
        "Validating source checksums..."
    )
    local msg_idx=0 frame_count=0 msg_interval=17  # rotate every ~2 s (17 × 0.12 s)

    printf '\033[?25l'  # hide cursor

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
        if   [[ "$is_linking" -eq 1 ]]; then phase="Linking & launching";    step_n=3
        elif [[ "$compiled"   -gt 0 ]]; then phase="Compiling workspace";    step_n=2
        else                                 phase="Resolving dependencies";  step_n=1
        fi

        # Progress bar
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

        # Milestone icons: ○ waiting  spinner in-progress  ✓ done
        local ic_res='\xe2\x97\x8b' ic_cmp='\xe2\x97\x8b' ic_lnk='\xe2\x97\x8b'
        if   [[ "$is_linking" -eq 1 ]]; then
            ic_res='\xe2\x9c\x93'; ic_cmp='\xe2\x9c\x93'; ic_lnk="$frame"
        elif [[ "$compiled"   -gt 0 ]]; then
            ic_res='\xe2\x9c\x93'; ic_cmp="$frame"
        else
            ic_res="$frame"
        fi

        # Move cursor back up to rewrite on every frame after the first
        [[ "$first_draw" -eq 0 ]] && printf "\033[%dA" "$NLINES"
        first_draw=0

        # 9-line status block — each line ends with \033[K to clear any trailing chars
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
        printf "     %b  Resolve dependencies\033[K\n"  "$ic_res"
        printf "     %b  Compile workspace\033[K\n"     "$ic_cmp"
        printf "     %b  Launch server\033[K\n"         "$ic_lnk"

        sleep 0.12
    done

    wait "$cargo_pid"
    local exit_code=$?
    printf '\033[?25h'  # restore cursor
    trap - INT TERM

    compiled="$(grep -c "^   Compiling" "$tmpout" 2>/dev/null)" || compiled=0

    {
        printf '# oxide-sloc run log\n# Date:     %s\n# Platform: %s\n# Exit:     %d\n#\n' \
            "$(date)" "$PLATFORM" "$exit_code"
        cat "$tmpout"
    } > "$LOG_FILE"

    # Overwrite the status block with the final result
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
        exit 1
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
    printf "     \xe2\x9c\x93  Resolve dependencies\033[K\n"
    printf "     \xe2\x9c\x93  Compile workspace\033[K\n"
    printf "     \xe2\x9c\x93  Launch server\033[K\n"
    printf '\n  Log \xe2\x86\x92 %s\n' "$LOG_FILE"

    if [[ "$HOST_MODE" == "1" ]]; then
        check_firewall
        printf '\n  oxide-sloc starting in LAN server mode\n  Local   \xe2\x86\x92 http://127.0.0.1:%s\n' "$SLOC_PORT"
        print_lan_ip
        if [[ "$PLATFORM" == linux ]]; then
            printf '  Firewall: %s\n' "$FIREWALL_STATUS"
            if [[ -n "$FIREWALL_FIX" ]]; then
                printf '    Other LAN hosts cannot reach this server until you run:\n'
                printf '      %s\n' "$FIREWALL_FIX"
            fi
        fi
        printf '\n'
        [[ -z "${SLOC_API_KEY:-}" ]] && \
            printf '  WARNING: SLOC_API_KEY is not set \xe2\x80\x94 all endpoints are unauthenticated.\n           Set it before exposing to untrusted networks.\n\n'
        printf '  Press Ctrl+C to stop.\n\n'
        "$bin_path" serve --server
    else
        printf '\n  oxide-sloc starting \xe2\x86\x92 http://127.0.0.1:%s\n  Press Ctrl+C to stop.\n\n' "$SLOC_PORT"
        "$bin_path"
    fi
}

extract_bundle() {
    echo "Extracting oxide-sloc..."
    if [[ "$PLATFORM" == windows ]]; then
        WIN_BUNDLE="$(cygpath -w "$BUNDLE")"
        WIN_DEST="$(cygpath -w "$REPO_ROOT")"
        powershell -NoProfile -Command "Expand-Archive -Path '$WIN_BUNDLE' -DestinationPath '$WIN_DEST' -Force"
    else
        tar xzf "$BUNDLE" -C "$REPO_ROOT"
    fi
}

# Parse flags — none are forwarded to the binary.
for arg in "$@"; do
    case "$arg" in
        --rebuild) ;;                   # no-op: cargo handles incremental builds
        --host|--lan) HOST_MODE=1 ;;   # enable LAN server mode
        *) ;;
    esac
done

# If cargo is available, always build and run from source so changes are picked up immediately.
if command -v cargo &>/dev/null && [[ -f "$REPO_ROOT/Cargo.toml" ]]; then
    launch_cargo
    exit 0
fi

if   [[ -f "$EXE" ]];       then launch "$EXE";       exit 0
elif [[ -f "$EXE_DIST" ]];  then launch "$EXE_DIST";  exit 0
elif [[ -f "$EXE_BUILD" ]]; then launch "$EXE_BUILD"; exit 0
elif [[ -f "$BUNDLE" ]]; then
    extract_bundle
    if [[ -f "$EXE" ]]; then
        launch "$EXE"
        exit 0
    fi
    echo "ERROR: extraction completed but binary not found — archive may be corrupt." >&2
    exit 1
fi

printf '\noxide-sloc: no binary found.\n\n' >&2
printf '  Run the installer first: bash scripts/install.sh\n' >&2
printf '  See docs/airgap.md for all deployment paths (no internet required).\n\n' >&2
exit 1
