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

echo "==> Building oxide-sloc (offline)..."
cargo build --release -p oxide-sloc

echo ""
echo "Done. Binary: target/release/oxide-sloc"
