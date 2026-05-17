#!/usr/bin/env bash
# oxide-sloc systemd unit installer / uninstaller
#
# Installs oxide-sloc as a persistent systemd service on Linux, following the
# steps documented in docs/server-deployment.md § Option B.
#
# Usage:
#   sudo bash scripts/install-systemd.sh              # install
#   sudo bash scripts/install-systemd.sh --uninstall  # remove service and files
#
# What this script does (install):
#   1. Copy the oxide-sloc binary to /usr/local/bin/
#   2. Create the 'oxide-sloc' system user (no home dir, no login shell)
#   3. Create /opt/oxide-sloc/out and set ownership
#   4. Copy deploy/oxide-sloc.service to /etc/systemd/system/
#   5. systemctl daemon-reload && systemctl enable --now oxide-sloc
#
# For persistent install (from serve-server.sh): bash scripts/install-systemd.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

BINARY_NAME="oxide-sloc"
INSTALL_BIN="/usr/local/bin/$BINARY_NAME"
SERVICE_NAME="oxide-sloc"
SERVICE_FILE="$REPO_ROOT/deploy/oxide-sloc.service"
SYSTEMD_DIR="/etc/systemd/system"
WORK_DIR="/opt/oxide-sloc"
OUT_DIR="$WORK_DIR/out"

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
            printf 'Usage: sudo bash scripts/install-systemd.sh [--uninstall]\n'
            printf '\n'
            printf '  (no flags)   Install oxide-sloc as a systemd service.\n'
            printf '  --uninstall  Stop, disable, and remove the service and its files.\n'
            printf '\n'
            printf 'For persistent install (from serve-server.sh): bash scripts/install-systemd.sh\n'
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
printf '  [1/5] Installing binary %s → %s\n' "$BINARY" "$INSTALL_BIN"
install -m 755 "$BINARY" "$INSTALL_BIN"

# Step 2: create system user
if id "$SERVICE_NAME" &>/dev/null; then
    printf '  [2/5] System user %s already exists, skipping.\n' "$SERVICE_NAME"
else
    printf '  [2/5] Creating system user %s...\n' "$SERVICE_NAME"
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_NAME"
fi

# Step 3: create working directory
printf '  [3/5] Creating working directory %s...\n' "$OUT_DIR"
mkdir -p "$OUT_DIR"
chown -R "$SERVICE_NAME:$SERVICE_NAME" "$WORK_DIR"

# Step 4: install service unit
printf '  [4/5] Installing service unit → %s/%s.service\n' "$SYSTEMD_DIR" "$SERVICE_NAME"
cp "$SERVICE_FILE" "$SYSTEMD_DIR/${SERVICE_NAME}.service"
systemctl daemon-reload

# Step 5: enable and start
printf '  [5/5] Enabling and starting %s...\n' "$SERVICE_NAME"
systemctl enable --now "$SERVICE_NAME"

printf '\nInstallation complete.\n\n'
printf '  Status:   sudo systemctl status %s\n' "$SERVICE_NAME"
printf '  Logs:     sudo journalctl -u %s -f\n' "$SERVICE_NAME"
printf '  Stop:     sudo systemctl stop %s\n' "$SERVICE_NAME"
printf '  Remove:   sudo bash scripts/install-systemd.sh --uninstall\n\n'
