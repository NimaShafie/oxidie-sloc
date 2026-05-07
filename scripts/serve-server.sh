#!/usr/bin/env bash
# oxide-sloc LAN server launcher
#
# Starts oxide-sloc in server mode: binds to 0.0.0.0:4317 so every device on
# your local network can reach it.  Separate from run.sh (which defaults to
# localhost-only).
#
# Usage:
#   bash scripts/serve-server.sh
#   bash scripts/serve-server.sh --port 8080
#   SLOC_API_KEY=mysecret bash scripts/serve-server.sh
#
# What this does vs. run.sh --host:
#   - Dedicated entrypoint — purpose is obvious from the filename
#   - Generates a random SLOC_API_KEY if one is not already set
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
    EXE_DIST="$REPO_ROOT/dist/oxide-sloc.exe"
    EXE_BUILD="$REPO_ROOT/target/release/oxide-sloc.exe"
else
    PLATFORM=linux
    EXE="$REPO_ROOT/oxide-sloc"
    EXE_DIST="$REPO_ROOT/dist/oxide-sloc"
    EXE_BUILD="$REPO_ROOT/target/release/oxide-sloc"
fi

# Parse flags
for arg in "$@"; do
    case "$arg" in
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
if [[ -z "${SLOC_API_KEY:-}" ]]; then
    if command -v openssl &>/dev/null; then
        SLOC_API_KEY="$(openssl rand -hex 32)"
    else
        # Fallback: timestamp-based pseudo-random (not cryptographic, but avoids no-key warning)
        SLOC_API_KEY="$(date +%s%N 2>/dev/null || date +%s)_$(od -A n -t x4 -N 8 /dev/urandom 2>/dev/null | tr -d ' \n' || echo "nokey")"
    fi
    export SLOC_API_KEY
    _key_generated=true
else
    _key_generated=false
fi
export SLOC_API_KEY

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

    if [[ "$_key_generated" == true ]]; then
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

    if [[ -n "$first_ip" ]]; then
        printf '  Test from another device:\n'
        printf '    curl -H "Authorization: Bearer %s" http://%s:%s/healthz\n' \
               "$SLOC_API_KEY" "$first_ip" "$SLOC_PORT"
    fi
    printf '\n'

    if [[ "$PLATFORM" == linux ]]; then
        printf '  Firewall: %s\n' "$FIREWALL_STATUS"
        if [[ -n "$FIREWALL_FIX" ]]; then
            printf '    Other LAN hosts cannot reach this server until you run:\n'
            printf '      %s\n' "$FIREWALL_FIX"
        fi
        printf '\n'
    fi

    printf '  Press Ctrl+C to stop.\n\n'
}

# ── Launch ─────────────────────────────────────────────────────────────────────
do_launch_binary() {
    local bin="$1"
    free_port
    assert_port_free
    [[ "$PLATFORM" == linux ]] && chmod +x "$bin"
    check_firewall
    print_banner
    cd "$REPO_ROOT"
    export OXIDE_SLOC_ROOT="$REPO_ROOT"
    "$bin" serve --server
}

do_launch_cargo() {
    free_port
    assert_port_free
    check_firewall
    print_banner
    cd "$REPO_ROOT"
    export OXIDE_SLOC_ROOT="$REPO_ROOT"
    export CARGO_INCREMENTAL=0
    cargo run -p oxide-sloc -- serve --server
}

if command -v cargo &>/dev/null && [[ -f "$REPO_ROOT/Cargo.toml" ]]; then
    do_launch_cargo
    exit 0
fi

if   [[ -f "$EXE" ]];       then do_launch_binary "$EXE";       exit 0
elif [[ -f "$EXE_DIST" ]];  then do_launch_binary "$EXE_DIST";  exit 0
elif [[ -f "$EXE_BUILD" ]]; then do_launch_binary "$EXE_BUILD"; exit 0
fi

printf '\noxide-sloc: no binary found.\n\n' >&2
printf '  Run the installer first: bash scripts/install.sh\n' >&2
printf '  See docs/airgap.md for all deployment paths (no internet required).\n\n' >&2
exit 1
