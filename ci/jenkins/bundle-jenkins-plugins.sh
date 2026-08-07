#!/usr/bin/env bash
# Bundle all Jenkins plugins (direct + transitive) into jenkins-plugins.tar.xz.
#
# Run ONCE on any machine with Docker and internet access.
# Commit the two output files so any git clone is Jenkins-ready — no internet
# access is needed to install Jenkins plugins after that point.
#
# The same model as vendor.tar.xz (Rust crates) and rust-toolchain-bundle.tar.xz:
#   bundle (networked machine)  →  commit  →  install (air-gapped machine)
#
# Usage:
#   bash ci/jenkins/bundle-jenkins-plugins.sh [--jenkins-version <tag>]
#
#   --jenkins-version <tag>  Jenkins LTS tag to use for the plugin-cli container
#                            (default: lts-jdk21, same base as Dockerfile.agent)
#
# Output (written to the repo root):
#   jenkins-plugins.tar.xz        — all .hpi/.jpi files, direct + transitive deps
#   jenkins-plugins.tar.xz.sha256 — SHA-256 checksum
#
# Committing:
#   If the bundle exceeds 45 MB, split it before committing:
#     split -b 45m jenkins-plugins.tar.xz jenkins-plugins.tar.xz.
#     rm jenkins-plugins.tar.xz
#     git add jenkins-plugins.tar.xz.* jenkins-plugins.tar.xz.sha256
#     git commit -m "ci: bundle Jenkins plugins for air-gapped install"
#   Otherwise commit the single file directly:
#     git add jenkins-plugins.tar.xz jenkins-plugins.tar.xz.sha256
#     git commit -m "ci: bundle Jenkins plugins for air-gapped install"
#
# Regenerating:
#   Re-run whenever ci/jenkins/plugins.txt changes (added/removed plugins).
#   Keep jenkins-plugins.tar.xz and jenkins-plugins.tar.xz.sha256 in sync —
#   install-jenkins-plugins.sh and Dockerfile.controller both verify the checksum.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PLUGINS_FILE="${REPO_ROOT}/ci/jenkins/plugins.txt"
ARCHIVE="${REPO_ROOT}/jenkins-plugins.tar.xz"
SHA_FILE="${ARCHIVE}.sha256"
JENKINS_VERSION="lts-jdk21"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --jenkins-version) JENKINS_VERSION="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: Docker is required to run the plugin-cli container."
    echo "       Install Docker, then re-run this script."
    exit 1
fi

# ── Extract plugin IDs from plugins.txt ────────────────────────────────────
# Strip comment lines (# ...) and inline comments, blank lines, and lines
# whose only content is a comment continuation (long comment rows from plugins.txt).
PLUGIN_IDS=$(grep -Ev '^[[:space:]]*#|^[[:space:]]*$' "$PLUGINS_FILE" \
    | awk '{print $1}' \
    | grep -Ev '^$')

echo "==> Plugins to bundle (from ci/jenkins/plugins.txt):"
echo "${PLUGIN_IDS}" | sed 's/^/    /'
echo ""

# ── Prepare temp directories ────────────────────────────────────────────────
TEMP_DIR=$(mktemp -d)
PLUGIN_LIST_FILE="${TEMP_DIR}/plugin-list.txt"
DOWNLOAD_DIR="${TEMP_DIR}/plugins"
mkdir -p "${DOWNLOAD_DIR}"
trap 'rm -rf "${TEMP_DIR}"' EXIT

# Write one plugin ID per line for the plugin-cli --plugin-file flag.
echo "${PLUGIN_IDS}" > "${PLUGIN_LIST_FILE}"

PLUGIN_COUNT=$(echo "${PLUGIN_IDS}" | wc -l | tr -d ' ')
echo "==> Downloading ${PLUGIN_COUNT} plugins + all transitive dependencies..."
echo "    Using Jenkins ${JENKINS_VERSION} plugin-cli container."
echo "    This may take a few minutes on the first run."
echo ""

# Run the official jenkins-plugin-cli inside the same image we use for the
# controller.  Mounting the plugin-list and download dir avoids needing to
# build a custom image just for this step.
docker run --rm \
    --user root \
    -v "${PLUGIN_LIST_FILE}:/tmp/plugin-list.txt:ro" \
    -v "${DOWNLOAD_DIR}:/downloads" \
    "jenkins/jenkins:${JENKINS_VERSION}" \
    jenkins-plugin-cli \
        --plugin-file /tmp/plugin-list.txt \
        --plugin-download-directory /downloads \
        --verbose

# ── Normalize: flatten any subdirectories, collect *.hpi and *.jpi ─────────
# Older plugin-cli versions nest files as <id>/<id>.hpi; newer ones write them
# flat.  Normalize to a single flat directory of *.hpi files.
find "${DOWNLOAD_DIR}" \( -name '*.hpi' -o -name '*.jpi' \) \
    ! -path "${DOWNLOAD_DIR}/*" \
    -exec mv -n {} "${DOWNLOAD_DIR}/" \; 2>/dev/null || true
# Remove any now-empty subdirectories that may remain after the mv pass.
find "${DOWNLOAD_DIR}" -mindepth 1 -maxdepth 1 -type d -exec rm -rf {} + 2>/dev/null || true

TOTAL=$(find "${DOWNLOAD_DIR}" \( -name '*.hpi' -o -name '*.jpi' \) | wc -l | tr -d ' ')
echo ""
echo "==> Downloaded ${TOTAL} plugin files (direct + transitive dependencies):"
find "${DOWNLOAD_DIR}" \( -name '*.hpi' -o -name '*.jpi' \) \
    | xargs -n1 basename \
    | sort \
    | sed 's/^/    /'
echo ""

# ── Pack archive ───────────────────────────────────────────────────────────
echo "==> Packing ${ARCHIVE}..."
LC_ALL=C tar \
    --sort=name \
    --mtime="@0" \
    --owner=0 --group=0 --numeric-owner \
    -cJf "${ARCHIVE}" \
    -C "${DOWNLOAD_DIR}" \
    .

# Write the checksum with a BARE (basename) path, not the absolute build path, so
# `sha256sum -c` passes from any directory — Dockerfile.controller COPYs the archive
# to /tmp and verifies it there.
(cd "${REPO_ROOT}" && sha256sum "$(basename "${ARCHIVE}")" > "${SHA_FILE}")

SIZE=$(du -sh "${ARCHIVE}" | cut -f1)
echo ""
echo "Done."
echo "  Archive : ${ARCHIVE}"
echo "  Size    : ${SIZE}"
echo "  Plugins : ${TOTAL} .hpi/.jpi files (direct + transitive)"
echo "  SHA-256 : $(cat "${SHA_FILE}")"
echo ""

# Warn if the archive exceeds 45 MB — it must be split before committing.
SIZE_BYTES=$(stat -c%s "${ARCHIVE}" 2>/dev/null || stat -f%z "${ARCHIVE}" 2>/dev/null || echo 0)
if [ "${SIZE_BYTES}" -gt 47185920 ]; then
    echo "WARNING: Archive is larger than 45 MB — split before committing:"
    echo "  split -b 45m jenkins-plugins.tar.xz jenkins-plugins.tar.xz."
    echo "  rm jenkins-plugins.tar.xz"
    echo "  git add jenkins-plugins.tar.xz.* jenkins-plugins.tar.xz.sha256"
    echo ""
fi

echo "Commit for fully offline Jenkins setup:"
echo "  git add jenkins-plugins.tar.xz jenkins-plugins.tar.xz.sha256"
echo "  git commit -m 'ci: bundle Jenkins plugins for air-gapped install'"
echo ""
echo "To install into a running Jenkins instance:"
echo "  bash ci/jenkins/install-jenkins-plugins.sh --restart"
echo ""
echo "To build the Jenkins controller Docker image with plugins pre-installed:"
echo "  docker build -t jenkins-oxide-sloc-controller:latest \\"
echo "      -f ci/jenkins/Dockerfile.controller ."
