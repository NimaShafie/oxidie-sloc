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
#   - Warns about firewall if needed
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

# ── Print startup banner ───────────────────────────────────────────────────────
print_banner() {
    local lan_ips
    lan_ips="$(get_lan_ips)"

    printf '\n'
    printf '  ╔══════════════════════════════════════════════════╗\n'
    printf '  ║         OxideSLOC — LAN Server Mode              ║\n'
    printf '  ╚══════════════════════════════════════════════════╝\n'
    printf '\n'
    printf '  Local   → http://127.0.0.1:%s\n' "$SLOC_PORT"
    if [[ -n "$lan_ips" ]]; then
        while IFS= read -r ip; do
            [[ -z "$ip" ]] && continue
            printf '  Network → http://%s:%s\n' "$ip" "$SLOC_PORT"
        done <<< "$lan_ips"
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

    if [[ -n "$lan_ips" ]]; then
        local first_ip
        first_ip="$(echo "$lan_ips" | head -1)"
        printf '  Test from another device:\n'
        printf '    curl -H "Authorization: Bearer %s" http://%s:%s/healthz\n' \
               "$SLOC_API_KEY" "$first_ip" "$SLOC_PORT"
    fi
    printf '\n'

    if [[ "$PLATFORM" == linux ]]; then
        printf '  Firewall: ensure port %s/tcp is open.\n' "$SLOC_PORT"
        printf '    sudo ufw allow %s/tcp    (UFW)\n' "$SLOC_PORT"
        printf '    sudo firewall-cmd --add-port=%s/tcp --permanent  (firewalld)\n' "$SLOC_PORT"
        printf '\n'
    fi

    printf '  Press Ctrl+C to stop.\n\n'
}

# ── Launch ─────────────────────────────────────────────────────────────────────
do_launch_binary() {
    local bin="$1"
    free_port
    [[ "$PLATFORM" == linux ]] && chmod +x "$bin"
    print_banner
    cd "$REPO_ROOT"
    export OXIDE_SLOC_ROOT="$REPO_ROOT"
    "$bin" serve --server
}

do_launch_cargo() {
    free_port
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
printf '  Install first: bash scripts/install.sh\n' >&2
printf '  Or build:      cargo build --release -p oxide-sloc\n' >&2
printf '  Or Docker:     docker compose up\n\n' >&2
exit 1
