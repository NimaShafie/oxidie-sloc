#!/usr/bin/env bash
# Renders job-config.xml.tmpl with REPO_URL / REPO_BRANCH substituted and writes to
# a temp file. Prints the temp file path on stdout so callers can capture it:
#   JOB_XML=$(bash ci/jenkins/render-job-config.sh)
set -euo pipefail

# Allow operators to keep credentials outside the working tree (e.g. ~/.config/oxide-sloc/jenkins.env).
# Set OXIDE_SLOC_ENV_FILE in your shell profile or invoke as:
#     OXIDE_SLOC_ENV_FILE=~/.config/oxide-sloc/jenkins.env bash ci/jenkins/render-job-config.sh
if [ -n "${OXIDE_SLOC_ENV_FILE:-}" ] && [ -f "${OXIDE_SLOC_ENV_FILE}" ]; then
    set -a; . "${OXIDE_SLOC_ENV_FILE}"; set +a
fi

# REPO_URL is REQUIRED — never silently default to an internet URL, so this is safe
# to run on an air-gapped host. Source ci/jenkins/.env (copied from .env.example) or
# export REPO_URL first.
if [ -z "${REPO_URL:-}" ]; then
    {
        echo "error: REPO_URL is not set."
        echo "  Set it to the oxide-sloc tooling repo (or your fork/mirror), e.g.:"
        echo "     export REPO_URL=https://git.internal.example/oxide-sloc/oxide-sloc.git"
        echo "     export REPO_URL=file:///srv/git/oxide-sloc.git   # air-gapped local mirror"
        echo "  Or: cp ci/jenkins/.env.example ci/jenkins/.env && \$EDITOR ci/jenkins/.env"
        echo "      set -a; . ci/jenkins/.env; set +a   (or set OXIDE_SLOC_ENV_FILE)"
    } >&2
    exit 1
fi

# Branch/ref spec for the pipeline SCM checkout. Defaults to */main; override for forks
# tracking a different branch or a pinned tag.
REPO_BRANCH="${REPO_BRANCH:-*/main}"

OUT="$(mktemp -t oxide-sloc-job.XXXXXX.xml)"
sed -e "s|__REPO_URL__|${REPO_URL}|g" \
    -e "s|__REPO_BRANCH__|${REPO_BRANCH}|g" \
    "$(dirname "$0")/job-config.xml.tmpl" > "$OUT"
echo "Written: $OUT (REPO_URL=${REPO_URL}, REPO_BRANCH=${REPO_BRANCH})" >&2
echo "$OUT"
