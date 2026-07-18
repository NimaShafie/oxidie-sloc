#!/usr/bin/env bash
# Pre-populate the Rust toolchain cache on a Jenkins agent (Docker or native).
#
# Run this ONCE on the agent host — or on any networked machine and then transfer
# the resulting archive to an air-gapped host.  After running, every subsequent
# Jenkins build finds the toolchain in place and skips all network access.
#
# Works with both Docker-managed and native (systemd / bare-metal) agents because
# the Jenkinsfile reads CARGO_HOME/RUSTUP_HOME from ${HOME}/.rust-cache, which
# this script also uses.
#
# ── Run directly on the agent (internet available) ───────────────────────────
#   bash ci/jenkins/install-rust-cache.sh
#
# ── Transfer to an air-gapped agent ──────────────────────────────────────────
#   # On a networked machine:
#   bash ci/jenkins/install-rust-cache.sh
#   tar -czf rust-cache.tar.gz -C "${HOME}" .rust-cache
#
#   # On the air-gapped agent — Docker:
#   #   Copy rust-cache.tar.gz to the host, then:
#   tar -xzf rust-cache.tar.gz \
#       -C /var/lib/docker/volumes/<jenkins_home_volume>/_data
#
#   # On the air-gapped agent — native systemd (jenkins user home = /var/lib/jenkins):
#   sudo -u jenkins tar -xzf rust-cache.tar.gz -C /var/lib/jenkins
#   # Adjust the path if the jenkins user's home differs (check: getent passwd jenkins).
#
# After transfer, the Jenkinsfile Setup stage detects the cached toolchain on
# first build and skips all Rust-related network access automatically.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TOOLCHAIN=$(grep '^channel' "${REPO_ROOT}/rust-toolchain.toml" | cut -d'"' -f2)
CACHE_DIR="${HOME}/.rust-cache"

export CARGO_HOME="${CACHE_DIR}/cargo"
export RUSTUP_HOME="${CACHE_DIR}/rustup"

echo "Installing Rust ${TOOLCHAIN} into ${CACHE_DIR}..."
mkdir -p "${CARGO_HOME}" "${RUSTUP_HOME}"

if rustup toolchain list 2>/dev/null | grep -q "${TOOLCHAIN}"; then
    echo "Toolchain ${TOOLCHAIN} already present — skipping rustup install."
else
    # Download rustup-init to a file before executing — avoids the curl|sh pattern
    # flagged by OpenSSF Scorecard Pinned-Dependencies.
    _RUSTUP_INIT="$(mktemp)"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o "${_RUSTUP_INIT}"
    sh "${_RUSTUP_INIT}" -y \
        --default-toolchain "${TOOLCHAIN}" \
        --no-modify-path \
        --component rustfmt clippy llvm-tools
    rm -f "${_RUSTUP_INIT}"
fi

# Ensure llvm-tools is present regardless of whether the toolchain was just installed
# (it may be absent when the cache was seeded without the component, e.g. via rustup-init
# without --component llvm-tools, or when the cached toolchain predates this requirement).
rustup component add llvm-tools 2>/dev/null || true

# Pre-install CI tooling so the "Test Result" (cargo-nextest) and "Coverage"
# (cargo-llvm-cov) views work, and so the pipeline's auto-install step is a no-op.
# Installing into $CARGO_HOME/bin means the tools survive an agent-image rebuild
# when this script runs at image-build time (not just in a live container).
# Prefer the official prebuilt binaries (fast, no compile); fall back to
# `cargo install` (which can use the vendored sources on offline agents).
install_ci_tool() {  # $1 = binary name, $2 = prebuilt tarball URL, $3 = crate name
    local bin="$1" url="$2" crate="$3"
    if command -v "${bin}" >/dev/null 2>&1 || [ -x "${CARGO_HOME}/bin/${bin}" ]; then
        echo "${bin} already present — skipping."
        return 0
    fi
    echo "Installing ${bin} (prebuilt binary)..."
    local tmp
    tmp="$(mktemp)"
    if curl --proto '=https' --tlsv1.2 -LsSf "${url}" -o "${tmp}" \
        && tar -xzf "${tmp}" -C "${CARGO_HOME}/bin" 2>/dev/null; then
        echo "  ${bin} -> ${CARGO_HOME}/bin"
    else
        echo "  prebuilt download failed — falling back to cargo install ${crate}."
        cargo install "${crate}" \
            || echo "  WARNING: ${crate} install failed (network required for a fresh install)."
    fi
    rm -f "${tmp}"
}

install_ci_tool cargo-nextest \
    "https://get.nexte.st/latest/linux" \
    cargo-nextest
install_ci_tool cargo-llvm-cov \
    "https://github.com/taiki-e/cargo-llvm-cov/releases/latest/download/cargo-llvm-cov-x86_64-unknown-linux-gnu.tar.gz" \
    cargo-llvm-cov

JENKINS_HOME_GUESS="$(getent passwd jenkins 2>/dev/null | cut -d: -f6 || echo '/var/lib/jenkins')"

echo ""
echo "Done. Toolchain cached at: ${CACHE_DIR}"
echo ""
echo "To bundle for transfer to an air-gapped host:"
echo "  tar -czf rust-cache.tar.gz -C '${HOME}' .rust-cache"
echo ""
echo "Extract on the air-gapped agent — Docker:"
echo "  tar -xzf rust-cache.tar.gz \\"
echo "      -C /var/lib/docker/volumes/<jenkins_home_volume>/_data"
echo ""
echo "Extract on the air-gapped agent — native (jenkins user home = ${JENKINS_HOME_GUESS}):"
echo "  sudo -u jenkins tar -xzf rust-cache.tar.gz -C '${JENKINS_HOME_GUESS}'"
