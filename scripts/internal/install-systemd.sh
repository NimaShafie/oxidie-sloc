#!/usr/bin/env bash
# oxide-sloc systemd unit installer / uninstaller
#
# Installs oxide-sloc as a persistent systemd service on Linux, following the
# steps documented in docs/server-deployment.md § Option B.
#
# Usage:
#   sudo bash scripts/internal/install-systemd.sh              # install
#   sudo bash scripts/internal/install-systemd.sh --uninstall  # remove service and files
#
# What this script does (install):
#   1. Copy the oxide-sloc binary to /usr/local/bin/
#   2. Create the 'oxide-sloc' system user (no home dir, no login shell)
#   3. Create /opt/oxide-sloc/out and set ownership
#   4. Create /etc/oxide-sloc/oxide-sloc.env with a generated API key (0640) so the
#      fail-closed server starts authenticated; see deploy/corp.env.example for more
#   5. Copy deploy/oxide-sloc.service to /etc/systemd/system/
#   6. systemctl daemon-reload && systemctl enable --now oxide-sloc
#
# For persistent install (from serve-server.sh): bash scripts/internal/install-systemd.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

BINARY_NAME="oxide-sloc"
INSTALL_BIN="/usr/local/bin/$BINARY_NAME"
SERVICE_NAME="oxide-sloc"
SERVICE_FILE="$REPO_ROOT/deploy/oxide-sloc.service"
SYSTEMD_DIR="/etc/systemd/system"
WORK_DIR="/opt/oxide-sloc"
OUT_DIR="$WORK_DIR/out"
ENV_DIR="/etc/oxide-sloc"
ENV_FILE="$ENV_DIR/oxide-sloc.env"

# ── Privilege check ────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    exec sudo bash "$0" "$@"
fi

# ── Detect OS ────────────────────────────────────���────────────────────────────
if [[ "$(uname -s)" != Linux ]]; then
    printf 'Error: systemd service installation is only supported on Linux.\n' >&2
    exit 1
fi
if ! command -v systemctl &>/dev/null; then
    printf 'Error: systemctl not found — this system does not use systemd.\n' >&2
    exit 1
fi

# ── Flags ─────────────────────────────────────────────────────────────────────
UNINSTALL=false
for arg in "$@"; do
    case "$arg" in
        --uninstall) UNINSTALL=true ;;
        --help|-h)
            printf 'Usage: sudo bash scripts/internal/install-systemd.sh [--uninstall]\n'
            printf '\n'
            printf '  (no flags)   Install oxide-sloc as a systemd service.\n'
            printf '  --uninstall  Stop, disable, and remove the service and its files.\n'
            printf '\n'
            printf 'For persistent install (from serve-server.sh): bash scripts/internal/install-systemd.sh\n'
            exit 0
            ;;
    esac
done

# ── Uninstall ───���─────────────��───────────────────────────────────────────────
if [[ "$UNINSTALL" == true ]]; then
    printf 'Uninstalling oxide-sloc systemd service...\n'

    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        printf '  Stopping %s...\n' "$SERVICE_NAME"
        systemctl stop "$SERVICE_NAME"
    fi

    if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
        printf '  Disabling %s...\n' "$SERVICE_NAME"
        systemctl disable "$SERVICE_NAME"
    fi

    if [[ -f "$SYSTEMD_DIR/${SERVICE_NAME}.service" ]]; then
        printf '  Removing %s/%s.service...\n' "$SYSTEMD_DIR" "$SERVICE_NAME"
        rm -f "$SYSTEMD_DIR/${SERVICE_NAME}.service"
        systemctl daemon-reload
    fi

    if [[ -f "$INSTALL_BIN" ]]; then
        printf '  Removing %s...\n' "$INSTALL_BIN"
        rm -f "$INSTALL_BIN"
    fi

    if [[ -d "$WORK_DIR" ]]; then
        printf '  Removing %s...\n' "$WORK_DIR"
        rm -rf "$WORK_DIR"
    fi

    if [[ -d "$ENV_DIR" ]]; then
        printf '  Removing %s (contains the generated API key)...\n' "$ENV_DIR"
        rm -rf "$ENV_DIR"
    fi

    if id "$SERVICE_NAME" &>/dev/null; then
        printf '  Removing system user %s...\n' "$SERVICE_NAME"
        userdel "$SERVICE_NAME" 2>/dev/null || true
    fi

    printf '\noxide-sloc service uninstalled.\n'
    exit 0
fi

# ── Install ───────────────────────────────────────────────────────────────────
printf 'Installing oxide-sloc as a systemd service...\n'

# Locate the binary: prefer a pre-built one adjacent to this repo, then check PATH.
BINARY=""
for candidate in \
    "$REPO_ROOT/$BINARY_NAME" \
    "$REPO_ROOT/target/release/$BINARY_NAME" \
    "$(command -v $BINARY_NAME 2>/dev/null || true)"; do
    if [[ -n "$candidate" && -x "$candidate" ]]; then
        BINARY="$candidate"
        break
    fi
done

if [[ -z "$BINARY" ]]; then
    printf 'Error: oxide-sloc binary not found.\n' >&2
    printf '  Build it first: cargo build --release -p oxide-sloc\n' >&2
    printf '  Or run: bash scripts/install.sh\n' >&2
    exit 1
fi

if [[ ! -f "$SERVICE_FILE" ]]; then
    printf 'Error: service unit not found at %s\n' "$SERVICE_FILE" >&2
    exit 1
fi

# Step 1: install binary
printf '  [1/6] Installing binary %s → %s\n' "$BINARY" "$INSTALL_BIN"
install -m 755 "$BINARY" "$INSTALL_BIN"

# Step 2: create system user
if id "$SERVICE_NAME" &>/dev/null; then
    printf '  [2/6] System user %s already exists, skipping.\n' "$SERVICE_NAME"
else
    printf '  [2/6] Creating system user %s...\n' "$SERVICE_NAME"
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_NAME"
fi

# Step 3: create working directory
printf '  [3/6] Creating working directory %s...\n' "$OUT_DIR"
mkdir -p "$OUT_DIR"
chown -R "$SERVICE_NAME:$SERVICE_NAME" "$WORK_DIR"

# Step 4: create the EnvironmentFile with a generated API key (secure by default).
# `serve --server` is fail-closed, so without a key the unit would refuse to start.
# We only generate on first install — never clobber an operator's edited env/secret.
GENERATED_KEY=""
if [[ -f "$ENV_FILE" ]]; then
    printf '  [4/6] Env file %s already exists, leaving it untouched.\n' "$ENV_FILE"
else
    printf '  [4/6] Creating %s with a generated API key...\n' "$ENV_FILE"
    if command -v openssl &>/dev/null; then
        GENERATED_KEY="$(openssl rand -hex 32)"
    else
        GENERATED_KEY="$(head -c 32 /dev/urandom | od -A n -t x1 | tr -d ' \n')"
    fi
    mkdir -p "$ENV_DIR"
    umask 077
    cat > "$ENV_FILE" <<ENVEOF
# oxide-sloc systemd runtime config — generated by install-systemd.sh.
# This file holds a secret (SLOC_API_KEYS); keep it root:${SERVICE_NAME} 0640.
# For the full menu of secure knobs (TLS, mTLS, CORS, rate-limit, audit HMAC,
# frame-ancestors, allowed-roots), see deploy/corp.env.example and add them here.

# Authenticated by default. Rotate with: openssl rand -hex 32
SLOC_API_KEYS=${GENERATED_KEY}

# Listen address. Default binds all interfaces on 4317; pin a management IP here
# to expose only that interface, e.g. SLOC_BIND=10.0.0.8:4317
SLOC_BIND=0.0.0.0:4317

# Per-client rate limit (requests/min).
SLOC_RATE_LIMIT=120

# Directories the web UI may scan (colon-separated absolute paths).
# IMPORTANT: server mode is FAIL-CLOSED on this. While it is unset, every attempt
# to scan a server-side path is rejected with HTTP 403 — the UI loads and
# authenticates, but "Analyze <path>" will not run. Set it to the repos you want
# scannable, then restart the service. (The Browse / directory-upload flow works
# regardless — uploads are scanned from the server's temp area and bypass this.)
#SLOC_ALLOWED_ROOTS=/srv/repos:/opt/oxide-sloc/work

# Uncomment for HTTPS (provide the cert/key first):
#SLOC_TLS_CERT=/etc/oxide-sloc/tls/server.crt
#SLOC_TLS_KEY=/etc/oxide-sloc/tls/server.key
ENVEOF
    chown "root:$SERVICE_NAME" "$ENV_FILE"
    chmod 0640 "$ENV_FILE"
fi

# Step 5: install service unit
printf '  [5/6] Installing service unit → %s/%s.service\n' "$SYSTEMD_DIR" "$SERVICE_NAME"
cp "$SERVICE_FILE" "$SYSTEMD_DIR/${SERVICE_NAME}.service"
systemctl daemon-reload

# Step 6: enable and start
printf '  [6/6] Enabling and starting %s...\n' "$SERVICE_NAME"
systemctl enable --now "$SERVICE_NAME"
# `enable --now` is a no-op when the unit is ALREADY active — on an upgrade that
# would leave the OLD process running while the NEW binary sits on disk. Force a
# restart so the live process is the one we just installed. (try-restart only acts
# if the unit is active, so it's harmless on a first install.)
systemctl try-restart "$SERVICE_NAME"

LIVE_VERSION="$("$INSTALL_BIN" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"

printf '\nInstallation complete.\n\n'
if [[ -n "$LIVE_VERSION" ]]; then
    printf '  Now serving: oxide-sloc v%s (service restarted to pick up this binary).\n\n' "$LIVE_VERSION"
fi
if [[ -n "$GENERATED_KEY" ]]; then
    printf '  API key (generated, stored in %s):\n' "$ENV_FILE"
    printf '    %s\n' "$GENERATED_KEY"
    printf '  Send requests with:  Authorization: Bearer <key>\n\n'
else
    # Re-install (env file already existed): the key was printed only on the FIRST
    # install, so tell the operator where to read the existing one.
    printf '  API key: kept existing key in %s (only shown on first install).\n' "$ENV_FILE"
    printf '    View it:  sudo grep -E "^SLOC_API_KEYS?=" %s\n\n' "$ENV_FILE"
fi

# ── Recommended URL for clients ────────────────────────────────────────────────
# The startup banner logs the bind address (0.0.0.0:PORT), which is not an address
# a client can type. Resolve the primary LAN IP the same way serve-server.sh does
# (ask the OS which source IP it would use for an outbound route — no packet sent)
# and print a usable URL + the login page.
_bind="$(grep -E '^SLOC_BIND=' "$ENV_FILE" 2>/dev/null | tail -1 | cut -d= -f2-)"
_port="${_bind##*:}"; [[ -z "$_port" || "$_port" == "$_bind" ]] && _port=4317
_lan_ip="$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' | head -1)"
[[ -z "$_lan_ip" ]] && _lan_ip="$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -vE '^(127\.|$)' | head -1)"
if [[ -n "$_lan_ip" ]]; then
    printf '  Reach it from another machine on the LAN:\n'
    printf '    http://%s:%s/\n' "$_lan_ip" "$_port"
    printf '    http://%s:%s/auth/login    (sign in with the API key)\n\n' "$_lan_ip" "$_port"
else
    printf '  This host binds all interfaces on port %s; give clients its LAN IP\n' "$_port"
    printf '    (see: hostname -I) as http://<ip>:%s/auth/login\n\n' "$_port"
fi

printf '  Config:   sudo $EDITOR %s   (see deploy/corp.env.example for all knobs)\n' "$ENV_FILE"
printf '  Status:   sudo systemctl status %s\n' "$SERVICE_NAME"
printf '  Logs:     sudo journalctl -u %s -f\n' "$SERVICE_NAME"
printf '  Stop:     sudo systemctl stop %s\n' "$SERVICE_NAME"
printf '  Remove:   sudo bash scripts/internal/install-systemd.sh --uninstall\n\n'
# Firewall: open the port in the zone that owns the primary-route interface.
_pri_if="$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'dev \K\S+' | head -1)"
if command -v firewall-cmd &>/dev/null; then
    _zone="$(firewall-cmd --get-zone-of-interface="${_pri_if:-}" 2>/dev/null)"
    [[ -z "$_zone" || "$_zone" == "no zone" ]] && _zone="$(firewall-cmd --get-default-zone 2>/dev/null || echo public)"
    printf '  Firewall: sudo firewall-cmd --zone=%s --add-port=%s/tcp --permanent && sudo firewall-cmd --reload\n\n' "$_zone" "$_port"
fi
