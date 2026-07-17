#!/usr/bin/env bash
# Runtime, permission-gated Jenkins plugin installer for the enrichment
# (visualization) plugins, gated by detected capabilities.
#
#   bash ci/jenkins/install-plugins.sh <output-dir>
#
# This is distinct from install-jenkins-plugins.sh (which populates a
# controller's JENKINS_HOME at host/Docker build time). This one runs INSIDE a
# pipeline on an agent and, only when the build is permitted, uploads the
# enrichment plugins to the live controller via the pluginManager REST API.
#
# It reads <output-dir>/capabilities.json (from detect-capabilities.py). If the
# build is NOT permitted to install plugins it prints a note and exits 0 — it
# never fails the build. When permitted, each requested enrichment plugin is
# installed from the committed offline bundle (jenkins-plugins.tar.xz or
# ci/jenkins/plugins/*.hpi) or, when the update centre is reachable, by name.
set -uo pipefail   # deliberately NOT -e: a failed install must not fail the build

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HERE}/../.." && pwd)"
OUT_DIR="${1:-.}"
CAPS="${OUT_DIR}/capabilities.json"
BUNDLE="${REPO_ROOT}/jenkins-plugins.tar.xz"
LOOSE_DIR="${SLOC_PLUGIN_DIR:-${REPO_ROOT}/ci/jenkins/plugins}"
BASE="${JENKINS_BASE_URL:-}"
[ -z "${BASE}" ] && BASE="$(printf '%s' "${BUILD_URL:-}" | sed 's#/job/.*##')"
BASE="${BASE%/}"
USER_ID="${JENKINS_USER:-}"
TOKEN="${JENKINS_AUTH_TOKEN:-}"

read_key() {  # read_key <json-key>  (scalar)
    python3 - "$CAPS" "$1" <<'PY' 2>/dev/null || echo ""
import json, sys
try:
    with open(sys.argv[1]) as f:
        print(json.load(f).get(sys.argv[2], ""))
except Exception:
    print("")
PY
}

read_list() {  # read_list <json-key>  (space-separated)
    python3 - "$CAPS" "$1" <<'PY' 2>/dev/null || true
import json, sys
try:
    with open(sys.argv[1]) as f:
        v = json.load(f).get(sys.argv[2], [])
    print(" ".join(str(x) for x in v))
except Exception:
    pass
PY
}

if [ ! -f "${CAPS}" ]; then
    echo "install-plugins: no capabilities.json — skipping plugin install."
    exit 0
fi

CAN_INSTALL="$(read_key can_install_plugins)"
SOURCE="$(read_key plugins_source)"
if [ "${CAN_INSTALL}" != "True" ] && [ "${CAN_INSTALL}" != "true" ]; then
    echo "install-plugins: build not permitted to install plugins (mode=$(read_key mode))."
    echo "                 Native dashboard will be used; no action taken."
    exit 0
fi

read -r -a PLUGINS <<< "$(read_list requested_plugins)"
if [ "${#PLUGINS[@]}" -eq 0 ]; then
    echo "install-plugins: no enrichment plugins requested; nothing to do."
    exit 0
fi

# Stage offline .hpi files (if any) into a flat directory for upload.
STAGE=""
if [ "${SOURCE}" = "offline-bundle" ]; then
    STAGE="$(mktemp -d)"
    trap 'rm -rf "${STAGE}"' EXIT
    if [ -f "${BUNDLE}" ]; then
        echo "==> Staging plugins from jenkins-plugins.tar.xz"
        tar -xJf "${BUNDLE}" -C "${STAGE}" 2>/dev/null || true
    fi
    if [ -d "${LOOSE_DIR}" ]; then
        find "${LOOSE_DIR}" -maxdepth 1 -name '*.hpi' -exec cp -f {} "${STAGE}/" \; 2>/dev/null || true
    fi
fi

crumb_header() {
    [ -z "${BASE}" ] && return 0
    curl -fsS ${USER_ID:+-u "${USER_ID}:${TOKEN}"} \
        "${BASE}/crumbIssuer/api/xml?xpath=concat(//crumbRequestField,%22:%22,//crumb)" \
        2>/dev/null || true
}
CRUMB="$(crumb_header)"
CRUMB_ARG=()
[ -n "${CRUMB}" ] && CRUMB_ARG=(-H "${CRUMB}")

installed=()
for name in "${PLUGINS[@]}"; do
    [ -z "${name}" ] && continue
    ok=1
    hpi="$(find "${STAGE:-/nonexistent}" -maxdepth 1 -name "${name}*.hpi" -o -name "${name}*.jpi" 2>/dev/null | head -1)"
    if [ -n "${hpi}" ] && [ -f "${hpi}" ]; then
        echo "==> Uploading ${name} (offline)"
        curl -fsS ${USER_ID:+-u "${USER_ID}:${TOKEN}"} "${CRUMB_ARG[@]}" \
            -F "file=@${hpi}" "${BASE}/pluginManager/uploadPlugin" >/dev/null 2>&1 || ok=0
    elif [ "${SOURCE}" = "update-center" ]; then
        echo "==> Installing ${name} from update centre"
        curl -fsS ${USER_ID:+-u "${USER_ID}:${TOKEN}"} "${CRUMB_ARG[@]}" \
            -d "<jenkins><install plugin=\"${name}@current\" /></jenkins>" \
            -H 'Content-Type: text/xml' \
            "${BASE}/pluginManager/installNecessaryPlugins" >/dev/null 2>&1 || ok=0
    else
        ok=0
    fi
    [ "${ok}" = "1" ] && installed+=("${name}") || echo "    (skipped ${name})"
done

# Record what we installed back into capabilities.json (best-effort).
python3 - "${CAPS}" "${installed[@]:-}" <<'PY' 2>/dev/null || true
import json, sys
path = sys.argv[1]
names = [n for n in sys.argv[2:] if n]
try:
    with open(path) as f:
        caps = json.load(f)
    caps["installed_plugins"] = names
    with open(path, "w") as f:
        json.dump(caps, f, indent=2)
except Exception:
    pass
PY

echo "install-plugins: installed ${#installed[@]} plugin(s): ${installed[*]:-none}"
echo "                 (a controller restart may be required to activate them)"
exit 0
