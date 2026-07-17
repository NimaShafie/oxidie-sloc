#!/usr/bin/env bash
# Post an oxide-sloc build status + report link to Bitbucket (Server/Data Center
# or Cloud). Fully opt-in: if the base URL or credentials are absent it prints a
# one-line note and exits 0 — it never fails the build.
#
#   bash ci/jenkins/notify-bitbucket.sh <state>
#     <state> = SUCCESSFUL | FAILED | INPROGRESS   (default: INPROGRESS)
#
# Environment
#   BITBUCKET_BASE_URL   e.g. https://bitbucket.example.com  (Server/DC)
#                        or   https://api.bitbucket.org      (Cloud)
#   BITBUCKET_TOKEN      HTTP access token / app password (bearer)
#   BITBUCKET_WORKSPACE  Cloud only: workspace id
#   BITBUCKET_REPO       Cloud only: repo slug
#   GIT_COMMIT           commit SHA the status attaches to
#   BUILD_KEY            unique key for this pipeline (default: JOB_NAME)
#   BUILD_NAME           human label (default: "oxide-sloc CI")
#   BUILD_URL            Jenkins build URL
#   REPORT_URL           link to the published SLOC report (falls back to BUILD_URL)
#   BUILD_DESCRIPTION    short summary line (optional)
set -uo pipefail

STATE="${1:-INPROGRESS}"
BASE="${BITBUCKET_BASE_URL:-}"
TOKEN="${BITBUCKET_TOKEN:-}"
SHA="${GIT_COMMIT:-}"
KEY="${BUILD_KEY:-${JOB_NAME:-oxide-sloc}}"
NAME="${BUILD_NAME:-oxide-sloc CI}"
URL="${REPORT_URL:-${BUILD_URL:-}}"
DESC="${BUILD_DESCRIPTION:-oxide-sloc code metrics report}"

if [ -z "${BASE}" ] || [ -z "${TOKEN}" ] || [ -z "${SHA}" ]; then
    echo "notify-bitbucket: not configured (need BITBUCKET_BASE_URL, BITBUCKET_TOKEN, GIT_COMMIT) — skipping."
    exit 0
fi

# Normalise Jenkins-ish states to the Bitbucket vocabulary.
case "${STATE}" in
    SUCCESS|SUCCESSFUL|PASSED) STATE="SUCCESSFUL" ;;
    FAIL|FAILED|FAILURE)       STATE="FAILED" ;;
    *)                         STATE="INPROGRESS" ;;
esac

BASE="${BASE%/}"
code=0
if printf '%s' "${BASE}" | grep -qi 'api.bitbucket.org'; then
    # Bitbucket Cloud
    WS="${BITBUCKET_WORKSPACE:-}"; RP="${BITBUCKET_REPO:-}"
    if [ -z "${WS}" ] || [ -z "${RP}" ]; then
        echo "notify-bitbucket: Cloud needs BITBUCKET_WORKSPACE + BITBUCKET_REPO — skipping."
        exit 0
    fi
    endpoint="${BASE}/2.0/repositories/${WS}/${RP}/commit/${SHA}/statuses/build"
else
    # Bitbucket Server / Data Center
    endpoint="${BASE}/rest/build-status/1.0/commits/${SHA}"
fi

payload=$(cat <<JSON
{"state":"${STATE}","key":"${KEY}","name":"${NAME}","url":"${URL}","description":"${DESC}"}
JSON
)

http=$(curl -sS -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer ${TOKEN}" \
    -H 'Content-Type: application/json' \
    -X POST --data "${payload}" "${endpoint}" 2>/dev/null) || code=$?

if [ "${code}" -ne 0 ]; then
    echo "notify-bitbucket: request failed (curl exit ${code}) — non-fatal, continuing."
elif [ "${http}" -ge 200 ] && [ "${http}" -lt 300 ]; then
    echo "notify-bitbucket: posted ${STATE} for ${SHA:0:8} → Bitbucket (${http})."
else
    echo "notify-bitbucket: Bitbucket returned HTTP ${http} — non-fatal, continuing."
fi
exit 0
