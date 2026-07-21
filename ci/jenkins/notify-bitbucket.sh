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
#   BITBUCKET_TOKEN      credential (see auth-scheme matrix below)
#   BITBUCKET_USER       Cloud username — when set, use Basic auth (user:token).
#                        Leave blank for Bearer auth (access token / Server PAT).
#   BITBUCKET_WORKSPACE  Cloud only: workspace id
#   BITBUCKET_REPO       Cloud only: repo slug
#   GIT_COMMIT           commit SHA the status attaches to
#   BUILD_KEY            unique key for this pipeline (default: JOB_NAME)
#   BUILD_NAME           human label (default: "oxide-sloc CI")
#   BUILD_URL            Jenkins build URL
#   REPORT_URL           link to the published SLOC report (falls back to BUILD_URL)
#   BUILD_DESCRIPTION    short summary line (optional)
#
# ── Auth-scheme matrix (which credential needs which scheme) ─────────────────
#   Target                         Credential                 Scheme   Set USER?
#   Bitbucket CLOUD                app password               Basic    YES  (email/username)
#   Bitbucket CLOUD                repo/workspace access tok  Bearer   no
#   Bitbucket SERVER / DC          HTTP access token / PAT    Bearer   no
#   -> Cloud APP PASSWORDS REQUIRE BASIC AUTH. Set BITBUCKET_USER to switch to
#      Basic; otherwise the default Bearer scheme is used (correct for tokens).
#
# ── SSRF note ────────────────────────────────────────────────────────────────
#   Unlike the web app (which enforces an SSRF allow/deny policy on user-supplied
#   Atlassian URLs), this CI script performs NO SSRF filtering. It runs in a
#   trusted CI context where BITBUCKET_BASE_URL is an operator-set job parameter,
#   not attacker-controlled input, so blocking loopback/link-local/metadata hosts
#   is neither needed nor desirable (self-hosted Server on a private LAN is valid).
set -uo pipefail

STATE="${1:-INPROGRESS}"
BASE="${BITBUCKET_BASE_URL:-}"
TOKEN="${BITBUCKET_TOKEN:-}"
BB_USER="${BITBUCKET_USER:-}"
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

# Build the JSON payload with a real serializer so a value containing a quote,
# backslash, or newline cannot produce invalid JSON. python3 is a documented CI
# prerequisite (it is already required by notify-confluence.py).
payload=$(
    SLOC_STATE="${STATE}" SLOC_KEY="${KEY}" SLOC_NAME="${NAME}" \
    SLOC_URL="${URL}" SLOC_DESC="${DESC}" \
    python3 -c 'import json, os; print(json.dumps({
        "state":       os.environ["SLOC_STATE"],
        "key":         os.environ["SLOC_KEY"],
        "name":        os.environ["SLOC_NAME"],
        "url":         os.environ["SLOC_URL"],
        "description": os.environ["SLOC_DESC"],
    }))'
) || {
    echo "notify-bitbucket: could not build JSON payload (python3 missing?) — skipping."
    exit 0
}

# Auth scheme: Basic when a username is supplied (Cloud app passwords), else
# Bearer (access tokens / Server PATs). Pass the secret via curl's config-file
# stdin (-K -) so it never appears in the process list or the shell history.
if [ -n "${BB_USER}" ]; then
    auth_conf="user = \"${BB_USER}:${TOKEN}\""
else
    auth_conf="header = \"Authorization: Bearer ${TOKEN}\""
fi

http=$(printf '%s\n' "${auth_conf}" | curl -sS -o /dev/null -w '%{http_code}' \
    -K - \
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
