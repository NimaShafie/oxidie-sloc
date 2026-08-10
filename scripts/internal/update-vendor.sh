#!/usr/bin/env bash
# Regenerate the split vendor.tar.gz.* parts and vendor.checksums.sha256 from the
# current Cargo.lock.
#
# Run this any time you add, remove, or update a dependency in Cargo.toml/Cargo.lock,
# then stage and commit ALL generated files:
#
#   git add vendor.tar.gz.* vendor.checksums.sha256
#   git commit -m "chore: update vendor archive"
#
# All files are tracked by git so that a plain `git clone` is sufficient for a fully
# offline (air-gapped) build — no separate download step required. gzip (not xz) is
# used so extraction works everywhere (Git for Windows bundles no xz), and the
# archive is split into 45 MB parts so no single file exceeds GitHub's 100 MB limit.
#
# Usage: bash scripts/internal/update-vendor.sh
set -euo pipefail

CHECKSUMS_FILE=vendor.checksums.sha256

echo "Removing old vendor directory and archives..."
rm -rf vendor/
rm -f vendor.tar.gz vendor.tar.gz.* vendor.tar.xz vendor.tar.xz.sha256 "${CHECKSUMS_FILE}"

echo "Running cargo vendor..."
# --sync ci/tools/Cargo.toml pulls CI tooling (cargo-llvm-cov, etc.) into the
# vendor archive so they can be installed offline on air-gapped agents.
cargo vendor --sync ci/tools/Cargo.toml vendor/

echo "Packing vendor.tar.gz (gzip -9, deterministic sort)..."
# Use LC_ALL=C + sorted find output for a reproducible archive on any OS.
LC_ALL=C tar \
  --sort=name \
  --mtime="@0" \
  --owner=0 --group=0 --numeric-owner \
  -cf - vendor/ | gzip -9 > vendor.tar.gz

echo "Splitting into 45 MB parts (vendor.tar.gz.aa, .ab, ...)..."
split -b 45m vendor.tar.gz vendor.tar.gz.
rm -f vendor.tar.gz

echo "Writing ${CHECKSUMS_FILE}..."
sha256sum vendor.tar.gz.* > "${CHECKSUMS_FILE}"

echo "Done."
echo "  Parts   : $(ls vendor.tar.gz.* | tr '\n' ' ')"
echo "  Checksum: ${CHECKSUMS_FILE}"
echo ""
echo "Stage and commit all files:"
echo "  git add vendor.tar.gz.* vendor.checksums.sha256"
echo "  git rm --ignore-unmatch vendor.tar.xz vendor.tar.xz.sha256"
echo "  git commit -m \"chore: update vendor archive\""
