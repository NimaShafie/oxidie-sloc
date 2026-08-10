#!/usr/bin/env bash
# Pre-stage the split vendor.tar.gz.* parts on the Jenkins agent's persistent
# cache so that offline (air-gapped) builds never have to reach crates.io.
#
# The parts are committed to git AND attached to each GitHub release. Download
# them once on any machine that can reach GitHub, then call this script to place
# them at the path the Jenkinsfile's Setup stage checks first.
#
# Usage:
#   # Option A — download from GitHub releases (requires internet, run once):
#   bash ci/jenkins/install-vendor-cache.sh --download vX.Y.Z
#   #   Override the host for an internal mirror (no github.com):
#   VENDOR_RELEASE_BASE=https://artifacts.internal/oxide-sloc/releases \
#     bash ci/jenkins/install-vendor-cache.sh --download vX.Y.Z
#
#   # Option B — use a local copy you already have (point at the repo/dir that
#   #            holds the vendor.tar.gz.* parts + vendor.checksums.sha256):
#   bash ci/jenkins/install-vendor-cache.sh /path/to/dir-with-parts
#
#   # Option C — regenerate from the current workspace (requires Cargo online once):
#   bash scripts/internal/update-vendor.sh
#   bash ci/jenkins/install-vendor-cache.sh .
#
# After staging, transfer the persistent cache directory to the air-gapped host:
#   tar -czf rust-cache.tar.gz -C ~ .rust-cache
#   # Copy to agent host, then:
#   tar -xzf rust-cache.tar.gz -C /var/lib/docker/volumes/<jenkins_home_volume>/_data
#
# The Jenkinsfile expects the parts at:
#   /var/jenkins_home/.rust-cache/vendor.tar.gz.aa (.ab, .ac)
#   /var/jenkins_home/.rust-cache/vendor.checksums.sha256  (optional but recommended)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CACHE_DIR="${HOME}/.rust-cache"
DEST_CHECKSUMS="${CACHE_DIR}/vendor.checksums.sha256"

# Split part names — the committed layout (45 MB pieces from `split -b 45m`).
VENDOR_PARTS=( vendor.tar.gz.aa vendor.tar.gz.ab vendor.tar.gz.ac )

mkdir -p "${CACHE_DIR}"

# ── Argument handling ─────────────────────────────────────────────────────────
if [ "${1:-}" = "--download" ]; then
    TAG="${2:-}"
    if [ -z "${TAG}" ]; then
        echo "Usage: $0 --download vX.Y.Z" >&2
        exit 1
    fi
    # Release-asset host is overridable for mirrors / internal artifact stores, so a
    # semi-connected environment can pull the vendor parts from its own server
    # instead of github.com (fully air-gapped hosts use Option B/C — local files).
    #   VENDOR_RELEASE_BASE=https://artifacts.internal/oxide-sloc/releases \
    #     bash ci/jenkins/install-vendor-cache.sh --download vX.Y.Z
    RELEASE_BASE="${VENDOR_RELEASE_BASE:-https://github.com/oxide-sloc/oxide-sloc/releases/download}"
    BASE="${RELEASE_BASE%/}/${TAG}"
    for part in "${VENDOR_PARTS[@]}"; do
        echo "Downloading ${part} from ${BASE}..."
        curl -fL --retry 3 --retry-delay 2 -o "${CACHE_DIR}/${part}" "${BASE}/${part}"
    done
    echo "Downloading vendor.checksums.sha256..."
    curl -fL --retry 3 --retry-delay 2 -o "${DEST_CHECKSUMS}" "${BASE}/vendor.checksums.sha256"
else
    SRC_DIR="${1:-}"
    if [ -z "${SRC_DIR}" ]; then
        # Check if the parts already exist in the workspace root
        if [ -f "${REPO_ROOT}/vendor.tar.gz.aa" ]; then
            SRC_DIR="${REPO_ROOT}"
        else
            echo "Usage: $0 /path/to/dir-with-parts" >&2
            echo "       $0 --download vX.Y.Z" >&2
            echo "" >&2
            echo "Generate fresh parts first with:" >&2
            echo "  bash scripts/internal/update-vendor.sh" >&2
            exit 1
        fi
    fi

    SRC_DIR="$(realpath "${SRC_DIR}")"
    for part in "${VENDOR_PARTS[@]}"; do
        if [ ! -f "${SRC_DIR}/${part}" ]; then
            echo "Error: vendor part not found: ${SRC_DIR}/${part}" >&2
            exit 1
        fi
        echo "Copying ${SRC_DIR}/${part} → ${CACHE_DIR}/${part}..."
        cp "${SRC_DIR}/${part}" "${CACHE_DIR}/${part}"
    done

    # Copy the checksum file if it lives beside the source parts
    SRC_CHECKSUMS="${SRC_DIR}/vendor.checksums.sha256"
    if [ -f "${SRC_CHECKSUMS}" ]; then
        echo "Copying ${SRC_CHECKSUMS} → ${DEST_CHECKSUMS}..."
        cp "${SRC_CHECKSUMS}" "${DEST_CHECKSUMS}"
    else
        echo "No vendor.checksums.sha256 beside source — computing from copied parts..."
        ( cd "${CACHE_DIR}" && sha256sum "${VENDOR_PARTS[@]}" > "vendor.checksums.sha256" )
    fi
fi

# ── Verify the staged parts ────────────────────────────────────────────────────
echo "Verifying checksums..."
(cd "${CACHE_DIR}" && sha256sum -c "$(basename "${DEST_CHECKSUMS}")")

echo ""
echo "Vendor cache staged successfully:"
echo "  Parts    : ${VENDOR_PARTS[*]}"
echo "  Checksum : ${DEST_CHECKSUMS}"
echo "  Size     : $(cd "${CACHE_DIR}" && du -ch "${VENDOR_PARTS[@]}" | tail -1 | cut -f1)"
echo ""
echo "To bundle the full offline cache for transfer to an air-gapped host:"
echo "  tar -czf rust-cache.tar.gz -C '${HOME}' .rust-cache"
echo ""
echo "On the air-gapped Jenkins host:"
echo "  tar -xzf rust-cache.tar.gz -C /var/lib/docker/volumes/<jenkins_home>/_data"
