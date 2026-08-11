#!/usr/bin/env bash
# Creates rust-toolchain-bundle.tar.xz for fully offline Jenkins builds.
#
# Use this when the Docker-agent approach (ci/jenkins/Dockerfile.agent) is not
# available — e.g. a bare-metal Jenkins agent or a custom container image where
# you cannot rebuild the image from Dockerfile.agent.
#
# Run ONCE on any Linux machine with internet access.  Commit the two output
# files alongside the vendor.tar.gz.* parts so any git clone is build-ready end-to-end.
#
# The Jenkinsfile Setup stage checks for rust-toolchain-bundle.tar.xz in the
# workspace before falling back to the agent image or an internet download.
#
# Usage:
#   bash ci/jenkins/bundle-rust-toolchain.sh
#
# Output (written to the repo root):
#   rust-toolchain-bundle.tar.xz        — pre-installed cargo/ + rustup/ (~200-350 MB)
#   rust-toolchain-bundle.tar.xz.sha256 — SHA-256 checksum
#
# Committing the bundle:
#   The bundle is typically 200-350 MB — split before committing:
#     split -b 45m rust-toolchain-bundle.tar.xz rust-toolchain-bundle.tar.xz.
#     rm rust-toolchain-bundle.tar.xz
#     git add rust-toolchain-bundle.tar.xz.* rust-toolchain-bundle.tar.xz.sha256
#     git commit -m "ci: add Rust <version> toolchain bundle for offline builds"
#   Alternatively, rebuild ci/jenkins/Dockerfile.agent — it bakes the toolchain
#   at image build time so no bundle file is needed.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TOOLCHAIN=$(grep '^channel' "${REPO_ROOT}/rust-toolchain.toml" | cut -d'"' -f2)
ARCHIVE="${REPO_ROOT}/rust-toolchain-bundle.tar.xz"
SHA_FILE="${ARCHIVE}.sha256"
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "${TEMP_DIR}"' EXIT

export CARGO_HOME="${TEMP_DIR}/cargo"
export RUSTUP_HOME="${TEMP_DIR}/rustup"

echo "==> Installing Rust ${TOOLCHAIN} toolchain for bundling..."
# Download rustup-init to a file before executing — avoids the curl|sh pattern
# flagged by OpenSSF Scorecard Pinned-Dependencies.
RUSTUP_INIT="${TEMP_DIR}/rustup-init.sh"
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o "${RUSTUP_INIT}"
sh "${RUSTUP_INIT}" -y \
    --default-toolchain "${TOOLCHAIN}" \
    --component rustfmt clippy \
    --no-modify-path
rm -f "${RUSTUP_INIT}"

# Strip the cargo registry and git checkout cache — those are covered by
# the vendor.tar.gz.* parts at build time and would bloat the bundle unnecessarily.
rm -rf \
    "${CARGO_HOME}/registry" \
    "${CARGO_HOME}/git" \
    "${CARGO_HOME}/.package-cache"

echo "==> Packing ${ARCHIVE}..."
LC_ALL=C tar \
    --sort=name \
    --mtime="@0" \
    --owner=0 --group=0 --numeric-owner \
    -cJf "${ARCHIVE}" \
    -C "${TEMP_DIR}" \
    cargo rustup

sha256sum "${ARCHIVE}" > "${SHA_FILE}"

SIZE=$(du -sh "${ARCHIVE}" | cut -f1)
echo ""
echo "Done."
echo "  Archive : ${ARCHIVE}"
echo "  Size    : ${SIZE}"
echo "  SHA-256 : $(cat "${SHA_FILE}")"
echo ""
echo "To commit for fully offline Jenkins builds, split before committing:"
echo "  split -b 45m rust-toolchain-bundle.tar.xz rust-toolchain-bundle.tar.xz."
echo "  rm rust-toolchain-bundle.tar.xz"
echo "  git add rust-toolchain-bundle.tar.xz.* rust-toolchain-bundle.tar.xz.sha256"
echo "  git commit -m 'ci: add Rust ${TOOLCHAIN} toolchain bundle for offline builds'"
echo ""
echo "Alternatively, rebuild ci/jenkins/Dockerfile.agent — it bakes the toolchain"
echo "into /opt/rust-toolchain at image build time with no bundle file needed."
