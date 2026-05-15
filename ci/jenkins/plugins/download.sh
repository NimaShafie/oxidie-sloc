#!/usr/bin/env bash
# Download Jenkins plugin .hpi files into this directory.
#
# Downloads the direct plugins listed in ci/jenkins/plugins.txt from the Jenkins
# Update Center (or a custom mirror).  Skips files that already exist unless
# --force is passed.
#
# Usage:
#   bash ci/jenkins/plugins/download.sh [OPTIONS]
#
#   --update-center <url>   Base URL of the Jenkins Update Center or a mirror.
#                           Default: https://updates.jenkins.io/latest
#   --force                 Re-download even when the .hpi file already exists.
#
# NOTE: This script downloads only the DIRECT plugins listed in plugins.txt.
# Jenkins resolves transitive dependencies from the Update Center at install time.
# If your Jenkins host has NO internet access and NO Update Center configured,
# use bundle-jenkins-plugins.sh (requires Docker) to produce a complete offline
# archive including all transitive dependencies.

set -uo pipefail
# Note: NOT using -e so that a single curl failure does not abort the whole loop.
# Failures are tracked manually and reported in the summary at the end.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGINS_TXT="${SCRIPT_DIR}/../plugins.txt"
UPDATE_CENTER="https://updates.jenkins.io/latest"
FORCE=0

# ── Parse arguments ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --update-center)
            UPDATE_CENTER="${2%/}"   # strip trailing slash
            shift 2
            ;;
        --force)
            FORCE=1
            shift
            ;;
        -h|--help)
            sed -n '2,/^set /p' "${BASH_SOURCE[0]}" | grep '^#' | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: bash ci/jenkins/plugins/download.sh [--update-center <url>] [--force]"
            exit 1
            ;;
    esac
done

# ── Sanity checks ────────────────────────────────────────────────────────────
if [ ! -f "${PLUGINS_TXT}" ]; then
    echo "ERROR: plugins.txt not found at ${PLUGINS_TXT}"
    exit 1
fi

if ! command -v curl &>/dev/null; then
    echo "ERROR: curl is required but not found in PATH."
    exit 1
fi

echo "==> Downloading Jenkins plugins"
echo "    Source : ${UPDATE_CENTER}/<id>.hpi"
echo "    Dest   : ${SCRIPT_DIR}/"
echo "    Force  : $([ "${FORCE}" -eq 1 ] && echo yes || echo no)"
echo ""

# ── Download loop ────────────────────────────────────────────────────────────
TOTAL=0
DOWNLOADED=0
SKIPPED=0
FAILED=0
FAILED_IDS=()

while IFS= read -r line; do
    # Skip blank lines and comment lines (lines starting with optional whitespace + #)
    [[ "${line}" =~ ^[[:space:]]*$ ]]  && continue
    [[ "${line}" =~ ^[[:space:]]*# ]]  && continue

    # Plugin ID is the first whitespace-separated token on the line
    plugin_id=$(echo "${line}" | awk '{print $1}')
    [ -z "${plugin_id}" ] && continue

    TOTAL=$((TOTAL + 1))
    dest="${SCRIPT_DIR}/${plugin_id}.hpi"
    url="${UPDATE_CENTER}/${plugin_id}.hpi"

    if [ -f "${dest}" ] && [ "${FORCE}" -eq 0 ]; then
        printf "  SKIP  %s\n" "${plugin_id}"
        SKIPPED=$((SKIPPED + 1))
        continue
    fi

    printf "  GET   %s ... " "${plugin_id}"
    if curl -fsSL -o "${dest}" "${url}" 2>/dev/null; then
        size=$(wc -c < "${dest}" 2>/dev/null || echo '?')
        printf "ok (%s bytes)\n" "${size}"
        DOWNLOADED=$((DOWNLOADED + 1))
    else
        # Remove partial file if curl failed
        rm -f "${dest}"
        printf "FAILED\n"
        FAILED=$((FAILED + 1))
        FAILED_IDS+=("${plugin_id}")
    fi

done < "${PLUGINS_TXT}"

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "==> Summary"
echo "    Total plugins in plugins.txt : ${TOTAL}"
echo "    Downloaded                   : ${DOWNLOADED}"
echo "    Skipped (already present)    : ${SKIPPED}"
echo "    Failed                       : ${FAILED}"

if [ "${FAILED}" -gt 0 ]; then
    echo ""
    echo "WARNING: The following plugins failed to download:"
    for id in "${FAILED_IDS[@]}"; do
        echo "    - ${id}  (${UPDATE_CENTER}/${id}.hpi)"
    done
    echo ""
    echo "    Possible causes:"
    echo "      - Plugin ID is misspelled or was renamed"
    echo "      - The Update Center URL is unreachable from this machine"
    echo "      - The plugin was removed from the Update Center"
    echo ""
    echo "    If you are behind a proxy, set HTTPS_PROXY before running:"
    echo "      HTTPS_PROXY=http://proxy.example.com:3128 bash ci/jenkins/plugins/download.sh"
fi

echo ""
echo "NOTE: Only DIRECT plugins were downloaded (those listed in plugins.txt)."
echo "      Transitive dependencies are resolved by Jenkins from the Update Center"
echo "      at install time.  For a fully offline install with no Update Center"
echo "      access, use bundle-jenkins-plugins.sh (requires Docker) instead."
echo ""
echo "==> Installation"
echo "    Option 1 — install-jenkins-plugins.sh:"
echo "      bash ci/jenkins/install-jenkins-plugins.sh --from-dir ci/jenkins/plugins --restart"
echo ""
echo "    Option 2 — copy manually:"
echo "      cp ci/jenkins/plugins/*.hpi \$JENKINS_HOME/plugins/"
echo "      # Then restart Jenkins."
echo ""
echo "    Option 3 — Jenkins UI (one at a time, no CLI required):"
echo "      Manage Jenkins → Plugins → Advanced → Deploy Plugin → Upload .hpi"

# Exit non-zero if any downloads failed so CI pipelines can detect the problem.
[ "${FAILED}" -eq 0 ]
