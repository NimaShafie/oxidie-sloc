#!/usr/bin/env bash
# Offline source build for oxide-sloc.
#
# The split vendor parts (vendor.tar.gz.aa/.ab/.ac) are committed to the
# repository — no separate download needed. Transfer the full repository (or the
# vendor.tar.gz.* parts + vendor.checksums.sha256 + source tree) to the target
# machine, then run this script.
#
# Usage (on the target machine):
#   bash scripts/internal/airgap-build.sh [dir-with-vendor-parts]
#
# The optional argument is the directory that holds the vendor.tar.gz.* parts;
# it defaults to the current directory.
#
# Requirements: Rust toolchain (see rust-toolchain.toml), tar, gzip, sha256sum.
set -euo pipefail

PARTS_DIR="${1:-.}"
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

if ! ls "${PARTS_DIR}"/vendor.tar.gz.* >/dev/null 2>&1; then
    echo "ERROR: vendor parts not found in: ${PARTS_DIR}"
    echo "The vendor.tar.gz.* split parts are committed to the repository — ensure you"
    echo "have the complete repository, not just source files."
    exit 1
fi

echo "==> Verifying vendor parts checksums..."
if [ -f "${PARTS_DIR}/vendor.checksums.sha256" ]; then
    ( cd "${PARTS_DIR}" && sha256sum -c vendor.checksums.sha256 )
else
    echo "WARNING: ${PARTS_DIR}/vendor.checksums.sha256 not found — skipping checksum verification."
fi

echo "==> Reassembling and extracting vendor parts..."
cat "${PARTS_DIR}"/vendor.tar.gz.* | tar -xzf -

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
