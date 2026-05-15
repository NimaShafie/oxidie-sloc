#!/usr/bin/env bash
# Install bundled Jenkins plugins from jenkins-plugins.tar.xz or a directory
# of .hpi files.
#
# This script works in two source modes and two destination modes:
#
# Source mode 1 — tar.xz bundle (default):
#   Extracts plugins from jenkins-plugins.tar.xz (includes full transitive deps).
#   Requires bundle-jenkins-plugins.sh to have been run first.
#
# Source mode 2 — directory of .hpi files (--from-dir):
#   Copies .hpi files from a local directory (e.g. ci/jenkins/plugins/).
#   Only direct plugins are copied; Jenkins resolves transitive deps from the
#   Update Center at startup.  If the host has no Update Center access, use the
#   tar.xz bundle (source mode 1) instead.
#
# Destination mode A — live Jenkins instance (Docker or native):
#   Installs .hpi files directly into $JENKINS_HOME/plugins/ and
#   optionally restarts Jenkins.  Run from the repo root on the Jenkins host.
#
# Destination mode B — target directory (Dockerfile use):
#   Copies .hpi files into a caller-specified directory.  Used by
#   Dockerfile.controller to populate /usr/share/jenkins/ref/plugins/.
#
# Usage:
#   bash ci/jenkins/install-jenkins-plugins.sh [OPTIONS]
#
#   --jenkins-home <path>   Override JENKINS_HOME auto-detection
#   --target-dir  <path>    Install to this directory instead of JENKINS_HOME/plugins
#   --from-dir    <path>    Copy .hpi files from this directory instead of tar.xz
#   --restart               Restart Jenkins after install (ignored with --target-dir)
#   --skip-checksum         Skip SHA-256 verification (not recommended, tar.xz only)
#
# Auto-detection of JENKINS_HOME (used only when --target-dir is not set):
#   1. /var/jenkins_home        (Docker container: jenkins/jenkins:lts)
#   2. Home of the "jenkins" system user (native / systemd install)
#   3. /var/lib/jenkins         (fallback for most distro packages)
#
# Air-gapped workflows:
#   Full bundle (includes transitive deps):
#     1. Run bundle-jenkins-plugins.sh on a networked machine
#     2. git add + commit jenkins-plugins.tar.xz jenkins-plugins.tar.xz.sha256
#     3. git clone (or pull) on the air-gapped machine
#     4. bash ci/jenkins/install-jenkins-plugins.sh --restart
#
#   Directory of .hpi files:
#     1. Run ci/jenkins/plugins/download.sh on a networked machine
#     2. Optionally commit the .hpi files: git add ci/jenkins/plugins/*.hpi
#     3. bash ci/jenkins/install-jenkins-plugins.sh \
#            --from-dir ci/jenkins/plugins --restart
#
# Plugin pinning:
#   A <name>.hpi.pinned marker file is written alongside each plugin to prevent
#   Jenkins's built-in update center from replacing the vendored versions.
#   In an air-gapped environment, update-center access will simply time out, but
#   pinning provides explicit protection and removes the "plugin update available"
#   banner in the Jenkins UI.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ARCHIVE="${REPO_ROOT}/jenkins-plugins.tar.xz"
SHA_FILE="${ARCHIVE}.sha256"

TARGET_DIR=""
JENKINS_HOME_OVERRIDE=""
FROM_DIR=""
DO_RESTART=0
SKIP_CHECKSUM=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --jenkins-home)   JENKINS_HOME_OVERRIDE="$2"; shift 2 ;;
        --target-dir)     TARGET_DIR="$2"; shift 2 ;;
        --from-dir)       FROM_DIR="$2"; shift 2 ;;
        --restart)        DO_RESTART=1; shift ;;
        --skip-checksum)  SKIP_CHECKSUM=1; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# ── Auto-detect --from-dir when neither source is explicitly given ──────────
# If --from-dir was not passed and jenkins-plugins.tar.xz does not exist, but
# ci/jenkins/plugins/ contains .hpi files, fall back to that directory automatically.
if [ -z "${FROM_DIR}" ] && [ ! -f "${ARCHIVE}" ]; then
    BUNDLED_PLUGINS_DIR="${REPO_ROOT}/ci/jenkins/plugins"
    if compgen -G "${BUNDLED_PLUGINS_DIR}/*.hpi" > /dev/null 2>&1; then
        echo "NOTE: jenkins-plugins.tar.xz not found, but .hpi files detected in"
        echo "      ci/jenkins/plugins/.  Using that directory as the plugin source."
        echo "      (Only direct plugins will be installed — transitive dependencies"
        echo "       must already be present or reachable from the Update Center.)"
        echo ""
        FROM_DIR="${BUNDLED_PLUGINS_DIR}"
    fi
fi

# ── Locate the plugin archive (tar.xz path, skipped when --from-dir is set) ──
if [ -z "${FROM_DIR}" ] && [ ! -f "${ARCHIVE}" ]; then
    echo "ERROR: jenkins-plugins.tar.xz not found at ${ARCHIVE}"
    echo ""
    echo "Available options:"
    echo ""
    echo "  Option 1 — Full bundle (includes transitive deps, requires Docker):"
    echo "    bash ci/jenkins/bundle-jenkins-plugins.sh"
    echo "    git add jenkins-plugins.tar.xz jenkins-plugins.tar.xz.sha256"
    echo "    git commit -m 'ci: bundle Jenkins plugins for air-gapped install'"
    echo ""
    echo "  Option 2 — Directory of direct plugins (no Docker required):"
    echo "    bash ci/jenkins/plugins/download.sh"
    echo "    bash ci/jenkins/install-jenkins-plugins.sh --from-dir ci/jenkins/plugins"
    exit 1
fi

# ── Verify checksum (tar.xz only — skipped when --from-dir is set) ──────────
if [ -z "${FROM_DIR}" ]; then
    if [ "${SKIP_CHECKSUM}" -eq 0 ]; then
        if [ -f "${SHA_FILE}" ]; then
            echo "==> Verifying jenkins-plugins.tar.xz integrity..."
            sha256sum -c "${SHA_FILE}"
            echo "    Checksum OK"
        else
            echo "ERROR: jenkins-plugins.tar.xz.sha256 not found."
            echo "       Re-run bundle-jenkins-plugins.sh or pass --skip-checksum."
            exit 1
        fi
    else
        echo "WARNING: Skipping checksum verification (--skip-checksum passed)."
    fi
fi

# ── Resolve install directory ───────────────────────────────────────────────
if [ -n "${TARGET_DIR}" ]; then
    INSTALL_DIR="${TARGET_DIR}"
    echo "==> Installing to target directory: ${INSTALL_DIR}"
else
    # Auto-detect Jenkins home
    if [ -n "${JENKINS_HOME_OVERRIDE}" ]; then
        JH="${JENKINS_HOME_OVERRIDE}"
    elif [ -d /var/jenkins_home ]; then
        JH=/var/jenkins_home
    else
        JH=$(getent passwd jenkins 2>/dev/null | cut -d: -f6 || true)
        if [ -z "${JH}" ] || [ ! -d "${JH}" ]; then
            JH=/var/lib/jenkins
        fi
    fi

    if [ ! -d "${JH}" ]; then
        echo "ERROR: Jenkins home '${JH}' does not exist."
        echo "       Pass --jenkins-home <path> to specify the correct location."
        exit 1
    fi

    INSTALL_DIR="${JH}/plugins"
    echo "==> Installing to Jenkins plugins directory: ${INSTALL_DIR}"
fi

mkdir -p "${INSTALL_DIR}"

# ── Install plugins ──────────────────────────────────────────────────────────
if [ -n "${FROM_DIR}" ]; then
    # Source mode 2: copy .hpi files from a local directory
    FROM_DIR="$(cd "${FROM_DIR}" && pwd)"
    if ! compgen -G "${FROM_DIR}/*.hpi" > /dev/null 2>&1; then
        echo "ERROR: No .hpi files found in ${FROM_DIR}"
        echo "       Run ci/jenkins/plugins/download.sh first to populate the directory."
        exit 1
    fi
    echo "==> Copying plugin files from ${FROM_DIR} ..."
    cp "${FROM_DIR}"/*.hpi "${INSTALL_DIR}/"
else
    # Source mode 1: extract from tar.xz bundle
    echo "==> Extracting plugins from jenkins-plugins.tar.xz..."
    tar -xJf "${ARCHIVE}" -C "${INSTALL_DIR}"
fi

PLUGIN_COUNT=$(find "${INSTALL_DIR}" \( -name '*.hpi' -o -name '*.jpi' \) | wc -l | tr -d ' ')
echo "==> Installed ${PLUGIN_COUNT} plugin files."

# ── Pin plugins to prevent update-center replacement ────────────────────────
# Creates <name>.hpi.pinned files.  Jenkins reads these at startup and skips
# the "update available" check for pinned plugins.
echo "==> Pinning plugins..."
PINNED=0
while IFS= read -r plugin_file; do
    base="${plugin_file%.hpi}"
    base="${base%.jpi}"
    pin_file="${base}.hpi.pinned"
    if [ ! -f "${pin_file}" ]; then
        touch "${pin_file}"
        PINNED=$((PINNED + 1))
    fi
done < <(find "${INSTALL_DIR}" \( -name '*.hpi' -o -name '*.jpi' \))
echo "==> Pinned ${PINNED} plugins."

# ── Restart Jenkins (Mode A only) ───────────────────────────────────────────
if [ "${DO_RESTART}" -eq 1 ] && [ -z "${TARGET_DIR}" ]; then
    echo "==> Restarting Jenkins to load the new plugins..."

    if systemctl is-active --quiet jenkins 2>/dev/null; then
        sudo systemctl restart jenkins
        echo "    systemd: jenkins restarted."

    elif CONTAINER=$(docker ps --format '{{.Names}}' 2>/dev/null \
            | grep -E '^jenkins(-controller|-oxide-sloc)?$' | head -1); \
         [ -n "${CONTAINER}" ]; then
        docker restart "${CONTAINER}"
        echo "    Docker container '${CONTAINER}' restarted."

    else
        echo "    Could not auto-detect Jenkins process."
        echo "    Restart Jenkins manually to activate the newly installed plugins."
    fi
else
    echo ""
    echo "Done.  Restart Jenkins to load the new plugins."
fi
