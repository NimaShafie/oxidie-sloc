#!/usr/bin/env bash
# Offline source build for oxide-sloc.
#
# vendor.tar.xz is committed to the repository — no separate download needed.
# Transfer the full repository (or vendor.tar.xz + source tree) to the target
# machine, then run this script.
#
# Usage (on the target machine):
#   bash scripts/internal/airgap-build.sh [vendor.tar.xz]
#
# Requirements: Rust toolchain (see rust-toolchain.toml), tar, sha256sum.
set -euo pipefail

ARCHIVE="${1:-vendor.tar.xz}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ── Logging setup ─────────────────────────────────────────────────────────────
LOG_DIR="$REPO_ROOT/logs"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/airgap-build-$(date +%Y-%m-%d-%H-%M-%S).log"

# Tee all output (stdout + stderr) to the log file from this point forward.
exec > >(tee -a "$LOG_FILE") 2>&1

printf '# oxide-sloc airgap-build log — %s\n\n' "$(date)"

# Print a clickable terminal hyperlink to the log on failure (EXIT trap).
_on_exit() {
    local ec=$?
    [[ $ec -eq 0 ]] && return
    printf '\n[FAILED] Build exited with code %d.\n' "$ec"
    printf '  Log dir:  %s\n' "$LOG_DIR"
    printf '  Log file: %s\n' "$(basename "$LOG_FILE")"
    # OSC 8 terminal hyperlink — clickable in VS Code, Windows Terminal 1.9+, iTerm2
    local url="file://$LOG_FILE"
    printf '  \033]8;;%s\033\\Click to open log\033]8;;\033\\\n' "$url"
}
trap '_on_exit' EXIT

# ── Preflight ─────────────────────────────────────────────────────────────────

if [ ! -f "$ARCHIVE" ]; then
    echo "ERROR: vendor archive not found: $ARCHIVE"
    echo "vendor.tar.xz is committed to the repository — ensure you have the complete"
    echo "repository, not just source files."
    exit 1
fi

echo "==> Verifying vendor archive checksum..."
if [ -f "${ARCHIVE}.sha256" ]; then
    sha256sum -c "${ARCHIVE}.sha256"
else
    echo "WARNING: ${ARCHIVE}.sha256 not found — skipping checksum verification."
fi

echo "==> Extracting vendor archive..."
tar -xJf "$ARCHIVE"

echo "==> Configuring cargo to use vendor directory..."
mkdir -p .cargo
cat > .cargo/config.toml <<'EOF'
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
EOF

# ── Build ─────────────────────────────────────────────────────────────────────
echo "==> Building oxide-sloc (offline release build)..."
cargo build --release --offline -p oxide-sloc

echo ""
echo "  [OK] Binary: target/release/oxide-sloc"
echo "  Log:         $LOG_FILE"
