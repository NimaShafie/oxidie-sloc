#!/usr/bin/env bash
# Build an oxide-sloc RPM from a pre-built static Linux binary.
#
# Usage (run on any Linux machine with rpmbuild installed):
#   bash scripts/internal/make-rpm.sh [VERSION] [BINARY_PATH]
#
# Arguments:
#   VERSION      Semver string (default: read from Cargo.toml workspace version)
#   BINARY_PATH  Path to the pre-built oxide-sloc binary (default: dist/oxide-sloc)
#
# Prerequisites:
#   rpm-build package  →  sudo dnf install rpm-build   (RHEL/Fedora)
#                         sudo apt-get install rpm      (Ubuntu/Debian, for CI)
#
# Output:
#   oxide-sloc-{VERSION}-1.{dist}.x86_64.rpm  (current directory)
#
# The RPM installs just /usr/local/bin/oxide-sloc — no toolchain extraction,
# no compilation, safe for EDR-protected machines.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SPEC="$REPO_ROOT/installer/rhel/oxide-sloc.spec"

# ── Arguments ─────────────────────────────────────────────────────────────────
VERSION="${1:-}"
BINARY="${2:-}"

if [[ -z "$VERSION" ]]; then
    VERSION="$(grep '^version' "$REPO_ROOT/Cargo.toml" 2>/dev/null \
        | head -1 | sed 's/.*"\(.*\)".*/\1/')"
fi
if [[ -z "$VERSION" ]]; then
    echo "[make-rpm] ERROR: could not determine version from Cargo.toml" >&2
    exit 1
fi

if [[ -z "$BINARY" ]]; then
    # Prefer dist/ tarball extract; fall back to release build output
    _DIST="$REPO_ROOT/dist/oxide-sloc-linux-x86_64.tar.gz"
    _BUILD="$REPO_ROOT/target/release/oxide-sloc"
    if [[ -f "$_DIST" ]]; then
        _TMP="$(mktemp -d)"
        tar -xzf "$_DIST" -C "$_TMP"
        BINARY="$_TMP/oxide-sloc"
    elif [[ -f "$_BUILD" ]]; then
        BINARY="$_BUILD"
    else
        echo "[make-rpm] ERROR: no binary found. Provide a path or place" >&2
        echo "           dist/oxide-sloc-linux-x86_64.tar.gz in the repo root." >&2
        exit 1
    fi
fi

if [[ ! -f "$BINARY" ]]; then
    echo "[make-rpm] ERROR: binary not found: $BINARY" >&2
    exit 1
fi

if ! command -v rpmbuild &>/dev/null; then
    echo "[make-rpm] ERROR: rpmbuild not found." >&2
    echo "  Install with:  sudo dnf install rpm-build   (RHEL/Fedora)" >&2
    echo "                 sudo apt-get install rpm      (Ubuntu, for CI)" >&2
    exit 1
fi

echo "[make-rpm] Building oxide-sloc-${VERSION} RPM..."
echo "[make-rpm]   Spec:   $SPEC"
echo "[make-rpm]   Binary: $BINARY"

# ── Set up rpmbuild tree ───────────────────────────────────────────────────────
_RPMBUILD="$(mktemp -d)"
mkdir -p "$_RPMBUILD"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

cp "$BINARY" "$_RPMBUILD/SOURCES/oxide-sloc"
chmod 755 "$_RPMBUILD/SOURCES/oxide-sloc"
cp "$SPEC"  "$_RPMBUILD/SPECS/oxide-sloc.spec"

# ── Build ─────────────────────────────────────────────────────────────────────
rpmbuild -bb \
    --define "_topdir $_RPMBUILD" \
    --define "_version $VERSION" \
    --define "_build_id_links none" \
    "$_RPMBUILD/SPECS/oxide-sloc.spec"

# ── Collect output ────────────────────────────────────────────────────────────
_RPM="$(find "$_RPMBUILD/RPMS" -name "oxide-sloc-*.rpm" | head -1)"
if [[ -z "$_RPM" ]]; then
    echo "[make-rpm] ERROR: rpmbuild produced no .rpm file." >&2
    rm -rf "$_RPMBUILD"
    exit 1
fi

_OUT="$REPO_ROOT/$(basename "$_RPM")"
cp "$_RPM" "$_OUT"
rm -rf "$_RPMBUILD"

echo "[make-rpm] Done: $_OUT"
echo ""
echo "Install on RHEL 8/9:"
echo "  sudo rpm  -ivh $(basename "$_OUT")"
echo "  sudo dnf  install ./$(basename "$_OUT")"
echo ""
echo "Uninstall:"
echo "  sudo rpm  -e oxide-sloc"
