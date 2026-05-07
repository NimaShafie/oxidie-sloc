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
    export CARGO_INCREMENTAL=0
    if [[ "$HOST_MODE" == "1" ]]; then
        check_firewall
        printf '\n  oxide-sloc starting in LAN server mode\n  Local   \xe2\x86\x92 http://127.0.0.1:%s  (will auto-select next port if %s is blocked)\n' "$SLOC_PORT" "$SLOC_PORT"
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
        cargo run -p oxide-sloc -- serve --server
    else
        printf '\n  oxide-sloc starting \xe2\x86\x92 http://127.0.0.1:%s  (will auto-select next port if %s is blocked)\n  Press Ctrl+C to stop.\n\n' "$SLOC_PORT" "$SLOC_PORT"
        cargo run -p oxide-sloc
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
