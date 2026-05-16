#!/usr/bin/env bash
# oxide-sloc LAN server launcher
#
# Starts oxide-sloc in server mode: binds to 0.0.0.0:4317 so every device on
# your local network can reach it.  Separate from run.sh (which defaults to
# localhost-only).
#
# Usage:
#   bash scripts/serve-server.sh                 # no auth (default); all endpoints open
#   bash scripts/serve-server.sh --port 8080
#   bash scripts/serve-server.sh --open-firewall
#   bash scripts/serve-server.sh --with-auth     # generate an API key; all endpoints require it
#   bash scripts/serve-server.sh --no-auth       # explicit no-auth (same as default)
#   bash scripts/serve-server.sh --quiet         # suppress startup banner (scripted launches)
#   SLOC_API_KEY=mysecret bash scripts/serve-server.sh  # use a pre-set key
#
# What this does vs. run.sh --host:
#   - Dedicated entrypoint — purpose is obvious from the filename
#   - Defaults to no authentication for trusted-LAN use; use --with-auth or set
#     SLOC_API_KEY to require authentication
#   - Prints all LAN addresses and a ready-made curl example
#   - Detects firewall status and provides the exact fix command if blocked
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SLOC_PORT=4317

# Detect Windows (Git Bash / MSYS2 / Cygwin)
if [[ -n "${WINDIR+x}" ]] || [[ "${OSTYPE:-}" == msys* ]] || [[ "${OSTYPE:-}" == cygwin* ]]; then
    PLATFORM=windows
    EXE="$REPO_ROOT/oxide-sloc.exe"
else
    PLATFORM=linux
    EXE="$REPO_ROOT/oxide-sloc"
fi

# Parse flags
OPEN_FIREWALL=false
NO_AUTH=false
WITH_AUTH=false
QUIET=false
for arg in "$@"; do
    case "$arg" in
        --open-firewall) OPEN_FIREWALL=true ;;
        --no-auth) NO_AUTH=true ;;        # explicit; now also the default
        --with-auth) WITH_AUTH=true ;;
        --quiet) QUIET=true ;;
        --port) ;;            # next arg consumed below
        --port=*) SLOC_PORT="${arg#--port=}" ;;
        *) ;;
    esac
done
_prev=""
for arg in "$@"; do
    [[ "$_prev" == "--port" ]] && SLOC_PORT="$arg"
    _prev="$arg"
done

# ── API key setup ──────────────────────────────────────────────────────────────
_no_auth_mode=false
if [[ -n "${SLOC_API_KEY:-}" ]]; then
    # User explicitly set a key in the environment — honor it regardless of flags.
    export SLOC_API_KEY
    _key_generated=false
elif [[ "$WITH_AUTH" == true ]]; then
    # --with-auth: generate a fresh session key.
    if command -v openssl &>/dev/null; then
        SLOC_API_KEY="$(openssl rand -hex 32)"
    else
        # Fallback: timestamp-based pseudo-random (not cryptographic, but avoids no-key warning)
        SLOC_API_KEY="$(date +%s%N 2>/dev/null || date +%s)_$(od -A n -t x4 -N 8 /dev/urandom 2>/dev/null | tr -d ' \n' || echo "nokey")"
    fi
    export SLOC_API_KEY
    _key_generated=true
else
    # Default (and --no-auth): no authentication. All endpoints are open.
    unset SLOC_API_KEY
    _key_generated=false
    _no_auth_mode=true
fi

# ── Detect LAN IPs ─────────────────────────────────────────────────────────────
get_lan_ips() {
    if [[ "$PLATFORM" == linux ]]; then
        hostname -I 2>/dev/null | tr ' ' '\n' | grep -v '^$' | grep -v '^127\.' | grep -v '^::' || true
    else
        powershell -NoProfile -Command \
            "Get-NetIPAddress -AddressFamily IPv4 | Where-Object { \$_.IPAddress -notmatch '^127\.' -and \$_.IPAddress -notmatch '^169\.254\.' } | Select-Object -ExpandProperty IPAddress" \
            2>/dev/null || true
    fi
}

# IP on the default route — the address the kernel would use to reach the internet.
# Returns empty string if ip(8) is unavailable or the route cannot be determined.
get_primary_ip() {
    [[ "$PLATFORM" != linux ]] && return
    command -v ip &>/dev/null || return
    ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' | head -1 || true
}

# ── Firewall preflight (Linux only) ───────────────────────────────────────────
FIREWALL_STATUS="unknown"
FIREWALL_FIX=""

# If --open-firewall is set and a blocking rule was detected, run the fix via sudo.
maybe_open_firewall() {
    [[ "$PLATFORM" != linux ]] && return
    [[ "$OPEN_FIREWALL" != true ]] && return
    [[ -z "$FIREWALL_FIX" ]] && return
    printf '  Opening port %s/tcp via sudo...\n' "$SLOC_PORT"
    if sudo -n true 2>/dev/null; then
        eval "$FIREWALL_FIX"
    else
        sudo bash -c "$FIREWALL_FIX"
    fi
    # Re-evaluate after the fix so the banner shows the updated status.
    FIREWALL_FIX=""
    check_firewall
}

check_firewall() {
    [[ "$PLATFORM" != linux ]] && return
    # Detect firewalld via reliable signals; avoid firewall-cmd --state which
    # exits 253 ("Authorization failed") for unprivileged users on RHEL/polkit.
    if command -v firewall-cmd &>/dev/null \
       && { systemctl is-active --quiet firewalld 2>/dev/null \
            || [ -S /run/firewalld/private ] \
            || pgrep -x firewalld >/dev/null 2>&1; }; then
        if firewall-cmd --query-port="${SLOC_PORT}/tcp" &>/dev/null 2>&1; then
            FIREWALL_STATUS="open (firewalld)"
        elif sudo -n firewall-cmd --query-port="${SLOC_PORT}/tcp" &>/dev/null 2>&1; then
            FIREWALL_STATUS="open (firewalld)"
        else
            FIREWALL_STATUS="firewalld active — port status unknown (needs root to query)"
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

# ── Kill any process already holding the port ──────────────────────────────────
free_port() {
    if [[ "$PLATFORM" == windows ]]; then
        powershell -NoProfile -Command "
            Get-Process -Name 'oxide-sloc' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
            \$conn = Get-NetTCPConnection -LocalPort $SLOC_PORT -ErrorAction SilentlyContinue
            if (\$conn) {
                \$conn | Select-Object -ExpandProperty OwningProcess | Sort-Object -Unique |
                    ForEach-Object { Stop-Process -Id \$_ -Force -ErrorAction SilentlyContinue }
            }
        " 2>/dev/null || true
        local tries=0
        while netstat -ano 2>/dev/null | grep -qE ":${SLOC_PORT}[[:space:]].*LISTENING"; do
            (( tries++ )) && (( tries >= 8 )) && break
            sleep 0.25
        done
    else
        pkill -x oxide-sloc 2>/dev/null || true
        command -v fuser &>/dev/null && fuser -k "${SLOC_PORT}/tcp" 2>/dev/null || true
        sleep 0.3
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

# ── Print startup banner ───────────────────────────────────────────────────────
print_banner() {
    local all_ips primary_ip real_ips docker_ips first_ip
    all_ips="$(get_lan_ips)"
    primary_ip="$(get_primary_ip)"
    # Real LAN IPs: exclude docker/podman/flannel bridge ranges and link-local
    real_ips="$(echo "$all_ips" | grep -vE '^(172\.(1[6-9]|2[0-9]|3[01])\.|10\.(88|244)\.|169\.254\.)' || true)"
    # Docker / virtual bridge IPs — shown under a separate sub-heading
    docker_ips="$(echo "$all_ips" | grep -E '^(172\.(1[6-9]|2[0-9]|3[01])\.|10\.(88|244)\.|169\.254\.)' || true)"

    # Best single IP for the curl example: primary route > first real LAN > first of all
    if [[ -n "$primary_ip" ]]; then
        first_ip="$primary_ip"
    elif [[ -n "$real_ips" ]]; then
        first_ip="$(echo "$real_ips" | head -1)"
    elif [[ -n "$all_ips" ]]; then
        first_ip="$(echo "$all_ips" | head -1)"
    else
        first_ip=""
    fi

    printf '\n'
    printf '  ╔══════════════════════════════════════════════════╗\n'
    printf '  ║         OxideSLOC — LAN Server Mode              ║\n'
    printf '  ╚══════════════════════════════════════════════════╝\n'
    printf '\n'

    if [[ "$_no_auth_mode" == true ]]; then
        printf '  *** WARNING: running WITHOUT authentication — all endpoints are open ***\n'
        printf '  Anyone on this network can access and scan directories.\n'
        printf '  To require authentication, restart with --with-auth or set SLOC_API_KEY.\n'
    elif [[ "$_key_generated" == true ]]; then
        printf '  API key (generated for this session):\n'
        printf '    %s\n' "$SLOC_API_KEY"
        printf '\n'
        printf '  To set a persistent key:\n'
        printf '    export SLOC_API_KEY=%s\n' "$SLOC_API_KEY"
        printf '    bash scripts/serve-server.sh\n'
    else
        printf '  API key: set (from environment)\n'
    fi
    printf '\n'

    printf '  Local   → http://127.0.0.1:%s\n' "$SLOC_PORT"

    if [[ -n "$all_ips" ]]; then
        # Primary (default-route) IP listed first
        [[ -n "$primary_ip" ]] && printf '  Network → http://%s:%s\n' "$primary_ip" "$SLOC_PORT"
        # Other real LAN IPs (not the primary)
        while IFS= read -r ip; do
            [[ -z "$ip" || "$ip" == "$primary_ip" ]] && continue
            printf '  Network → http://%s:%s\n' "$ip" "$SLOC_PORT"
        done <<< "$real_ips"
        # Docker / virtual bridge IPs under a clearly labelled sub-heading
        if [[ -n "$docker_ips" ]]; then
            printf '  (docker / virtual interfaces):\n'
            while IFS= read -r ip; do
                [[ -z "$ip" || "$ip" == "$primary_ip" ]] && continue
                printf '    http://%s:%s\n' "$ip" "$SLOC_PORT"
            done <<< "$docker_ips"
        fi
    else
        printf '  Network → (could not detect LAN IP — run hostname -I or ipconfig)\n'
    fi
    printf '\n'

    if [[ -n "$first_ip" ]]; then
        printf '  Open in a browser (any device on this LAN):\n'
        printf '    http://%s:%s/\n' "$first_ip" "$SLOC_PORT"
        printf '\n'
        if [[ -n "${SLOC_API_KEY:-}" ]]; then
            printf '  API key is set — open the login page to sign in:\n'
            printf '    http://%s:%s/auth/login\n' "$first_ip" "$SLOC_PORT"
            printf '\n'
            printf '  Auth lockout: %d failed attempts from the same IP triggers a\n' "${SLOC_AUTH_LOCKOUT_FAILS:-10}"
            printf '  temporary lockout (SLOC_AUTH_LOCKOUT_SECS=%s). Restart the server\n' "${SLOC_AUTH_LOCKOUT_SECS:-3600}"
            printf '  to clear it immediately.\n'
            printf '\n'
        fi
        printf '  CLI test:\n'
        printf '    curl -H "Authorization: Bearer %s" http://%s:%s/healthz\n' \
               "${SLOC_API_KEY:-<no-key>}" "$first_ip" "$SLOC_PORT"
    fi
    printf '\n'

    if [[ "$PLATFORM" == linux ]]; then
        printf '  Firewall: %s\n' "$FIREWALL_STATUS"
        if [[ -n "$FIREWALL_FIX" ]]; then
            printf '    Other LAN hosts cannot reach this server until you run:\n'
            printf '      %s\n' "$FIREWALL_FIX"
        fi
        printf '\n'
    elif [[ "$PLATFORM" == windows ]]; then
        printf '  Firewall: Windows Defender may show a network access dialog.\n'
        printf '    Click "Allow access" to open port %s \xe2\x80\x94 no admin rights required.\n\n' "$SLOC_PORT"
    fi

    printf '  Press Ctrl+C to stop.\n\n'
}

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

# ── Launch ─────────────────────────────────────────────────────────────────────
do_launch_binary() {
    local bin="$1"
    free_port
    assert_port_free
    [[ "$PLATFORM" == linux ]] && chmod +x "$bin"
    check_firewall
    maybe_open_firewall
    [[ "$QUIET" != true ]] && print_banner
    cd "$REPO_ROOT"
    export OXIDE_SLOC_ROOT="$REPO_ROOT"
    "$bin" serve --server
}

do_launch_cargo() {
    free_port
    assert_port_free
    check_firewall
    maybe_open_firewall

    local bin="$REPO_ROOT/target/debug/oxide-sloc"
    [[ "$PLATFORM" == windows ]] && bin="${bin}.exe"

    local tmpout
    tmpout="$(mktemp)"
    local LOG_FILE="$LOG_DIR/serve-server-$(date +%Y-%m-%d-%H-%M-%S).log"

    local total_pkgs=0
    if [[ -f "$REPO_ROOT/Cargo.lock" ]]; then
        total_pkgs="$(grep -c '^\[\[package\]\]' "$REPO_ROOT/Cargo.lock" 2>/dev/null)" || total_pkgs=0
    fi

    printf '\n  oxide-sloc \xe2\x80\x94 building from source\n\n'
    cd "$REPO_ROOT"
    export OXIDE_SLOC_ROOT="$REPO_ROOT"

    cargo build -p oxide-sloc 2>"$tmpout" &
    local cargo_pid=$!

    trap 'kill "$cargo_pid" 2>/dev/null; rm -f "$tmpout"; [[ "$is_tty" -eq 1 ]] && printf "\033[?25h\n"; exit 130' INT TERM

    local spin=('|' '/' '-' '\')
    local si=0 compiled=0 last_crate="" bar_w=34
    local start_time="$SECONDS"
    local is_linking=0 first_draw=1
    local NLINES=9
    local resolution_msgs=(
        "Reading Cargo.lock..."
        "Verifying workspace sources..."
        "Resolving dependency graph..."
        "Checking workspace manifests..."
        "Scanning crate metadata..."
        "Preparing build graph..."
    )
    local msg_idx=0 frame_count=0 msg_interval=17

    # Suppress cursor-escape TUI when stdout is not a terminal (CI capture, tee, harness).
    local is_tty=0; [[ -t 1 ]] && is_tty=1
    local last_plain_ts="$SECONDS"

    [[ "$is_tty" -eq 1 ]] && printf '\033[?25l'

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

        if [[ "$is_tty" -eq 1 ]]; then
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
            printf "     %b  Resolve dependencies\033[K\n"  "$ic_res"
            printf "     %b  Compile workspace\033[K\n"     "$ic_cmp"
            printf "     %b  Launch server\033[K\n"         "$ic_lnk"

            sleep 0.12
        else
            # Non-TTY: print one plain progress line every ~10 s to keep the log alive.
            if (( SECONDS - last_plain_ts >= 10 )); then
                printf '  [build] Step [%d/3] %s — %s crates — %s\n' \
                    "$step_n" "$phase" "$compiled" "$elapsed_str"
                last_plain_ts="$SECONDS"
            fi
            sleep 1
        fi
    done

    wait "$cargo_pid"
    local exit_code=$?
    [[ "$is_tty" -eq 1 ]] && printf '\033[?25h'
    trap - INT TERM

    compiled="$(grep -c "^   Compiling" "$tmpout" 2>/dev/null)" || compiled=0

    {
        printf '# oxide-sloc serve-server log\n# Date:     %s\n# Platform: %s\n# Exit:     %d\n#\n' \
            "$(date)" "$PLATFORM" "$exit_code"
        cat "$tmpout"
    } > "$LOG_FILE"

    [[ "$is_tty" -eq 1 && "$first_draw" -eq 0 ]] && printf "\033[%dA" "$NLINES"

    if [[ $exit_code -ne 0 ]]; then
        if [[ "$is_tty" -eq 1 ]]; then
            printf "  \xe2\x9c\x97  BUILD FAILED%-67s\n" ""
            for (( i = 1; i < NLINES; i++ )); do printf "\033[K\n"; done
            printf '\n'
        fi
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

    if [[ "$is_tty" -eq 1 ]]; then
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
    else
        if [[ "$compiled" -gt 0 ]]; then
            printf '  [build] Done — %d crates compiled in %s\n' "$compiled" "$final_elapsed_str"
        else
            printf '  [build] Already up to date (%s)\n' "$final_elapsed_str"
        fi
    fi
    printf '\n  Log \xe2\x86\x92 %s\n' "$LOG_FILE"

    [[ "$QUIET" != true ]] && print_banner
    "$bin" serve --server
}

if [[ -f "$EXE" ]]; then
    do_launch_binary "$EXE"
    exit 0
fi

if command -v cargo &>/dev/null && [[ -f "$REPO_ROOT/Cargo.toml" ]]; then
    do_launch_cargo
    exit 0
fi

printf '\noxide-sloc: no binary found.\n\n' >&2
printf '  Run the installer first: bash scripts/run.sh\n' >&2
printf '  See docs/airgap.md for all deployment paths (no internet required).\n\n' >&2
exit 1
