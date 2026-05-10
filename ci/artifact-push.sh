#!/usr/bin/env bash
# ci/artifact-push.sh — push oxide-sloc scan artifacts to an external artifact repository
#
# All configuration is passed via environment variables (set by the Jenkinsfile,
# a GitLab CI job, a GitHub Actions step, or by hand for local testing).
#
# ── Required ────────────────────────────────────────────────────────────────
#   ARTIFACT_REPO_TYPE   artifactory | nexus | nexus2 | s3 | minio | azure-blob | generic-http
#   ARTIFACT_REPO_URL    base URL of the repository service:
#                          Artifactory  https://repo.example.com/artifactory/sloc-reports
#                          Nexus 3      https://nexus.example.com
#                          Nexus 2      https://nexus.example.com/nexus
#                          S3           s3://my-bucket
#                          MinIO        s3://my-bucket  (set endpoint via ARTIFACT_REPO_EXTRA)
#                          Azure Blob   https://account.blob.core.windows.net
#                          Generic HTTP https://artifacts.example.com/sloc
#   ARTIFACT_REPO_PATH   path prefix / key prefix for uploaded artifacts
#                          e.g. oxide-sloc/my-job/42
#   ARTIFACT_DIR         local directory containing the files to push
#   ARTIFACT_FILES       space-separated filenames to push (e.g. "result.json report.html")
#
# ── Optional ────────────────────────────────────────────────────────────────
#   ARTIFACT_REPO_USER   username or access-key ID (omit for token-only auth)
#   ARTIFACT_REPO_PASS   password, API token, account key, or secret key
#   ARTIFACT_REPO_EXTRA  provider-specific extra setting:
#                          nexus / nexus2  Nexus repository name          (default: sloc-raw-hosted)
#                          azure-blob      storage container name         (default: sloc-reports)
#                          minio           MinIO endpoint URL             (e.g. https://minio.internal:9000)
#                          s3              extra flags for aws s3 cp      (e.g. --sse aws:kms)
#                          others          unused
#
# ── Exit codes ───────────────────────────────────────────────────────────────
#   0   all pushes succeeded
#   1   one or more file pushes failed
#   2   configuration error (bad type, missing required var, missing CLI tool)

set -euo pipefail

REPO_TYPE="${ARTIFACT_REPO_TYPE:-}"
REPO_URL="${ARTIFACT_REPO_URL:-}"
REPO_PATH="${ARTIFACT_REPO_PATH:-oxide-sloc}"
ARTIFACT_DIR="${ARTIFACT_DIR:-}"
ARTIFACT_FILES="${ARTIFACT_FILES:-result.json}"
REPO_USER="${ARTIFACT_REPO_USER:-}"
REPO_PASS="${ARTIFACT_REPO_PASS:-}"
REPO_EXTRA="${ARTIFACT_REPO_EXTRA:-}"

# ── Validation ───────────────────────────────────────────────────────────────

if [ -z "${REPO_TYPE}" ]; then
    echo "ERROR: ARTIFACT_REPO_TYPE is not set." >&2
    exit 2
fi

VALID_TYPES="artifactory nexus nexus2 s3 minio azure-blob generic-http"
valid=0
for t in ${VALID_TYPES}; do [ "${REPO_TYPE}" = "${t}" ] && valid=1 && break; done
if [ "${valid}" -eq 0 ]; then
    echo "ERROR: Unknown ARTIFACT_REPO_TYPE '${REPO_TYPE}'." >&2
    echo "       Supported: ${VALID_TYPES}" >&2
    exit 2
fi

if [ -z "${REPO_URL}" ]; then
    echo "ERROR: ARTIFACT_REPO_URL is not set." >&2
    exit 2
fi

if [ -z "${ARTIFACT_DIR}" ] || [ ! -d "${ARTIFACT_DIR}" ]; then
    echo "ERROR: ARTIFACT_DIR '${ARTIFACT_DIR}' is not set or does not exist." >&2
    exit 2
fi

# Normalise: strip trailing slash from URL, leading slash from path
REPO_URL="${REPO_URL%/}"
REPO_PATH="${REPO_PATH#/}"

PUSH_FAILURES=0

# ── Provider: JFrog Artifactory ──────────────────────────────────────────────
#
# Uses the Artifactory REST API: PUT /<repo-path>/<filename>
# Auth options (tested in order):
#   user + pass  → HTTP Basic
#   pass only    → X-JFrog-Art-Api header (API key)
#   neither      → anonymous (requires anonymous read/write enabled on the repo)
#
# Docs: https://jfrog.com/help/r/jfrog-rest-apis/deploy-artifact

push_artifactory() {
    echo "=== Artifactory → ${REPO_URL}/${REPO_PATH}/ ==="
    for f in ${ARTIFACT_FILES}; do
        local file="${ARTIFACT_DIR}/${f}"
        if [ ! -f "${file}" ]; then
            echo "  SKIP  ${f} (file not found)"
            continue
        fi
        local target="${REPO_URL}/${REPO_PATH}/${f}"
        echo "  PUT   ${f}  →  ${target}"

        local curl_auth=()
        if [ -n "${REPO_USER}" ] && [ -n "${REPO_PASS}" ]; then
            curl_auth=(-u "${REPO_USER}:${REPO_PASS}")
        elif [ -n "${REPO_PASS}" ]; then
            curl_auth=(-H "X-JFrog-Art-Api: ${REPO_PASS}")
        fi

        if curl -sf "${curl_auth[@]}" -X PUT "${target}" -T "${file}" \
                --retry 3 --retry-delay 2 --retry-max-time 60; then
            echo "  OK"
        else
            echo "  FAIL  ${f}" >&2
            PUSH_FAILURES=$((PUSH_FAILURES + 1))
        fi
    done
}

# ── Provider: Sonatype Nexus Repository Manager 3 ────────────────────────────
#
# Uses the Nexus 3 REST API for raw-format repositories:
#   POST /service/rest/v1/components?repository=<repo-name>
# One multipart request per file (avoids the 3-asset limit per request).
#
# ARTIFACT_REPO_URL  : base Nexus URL, e.g. https://nexus.example.com
# ARTIFACT_REPO_EXTRA: repository name, e.g. sloc-raw-hosted  (default: sloc-raw-hosted)
#
# Docs: https://help.sonatype.com/en/uploading-components.html

push_nexus() {
    local repo_name="${REPO_EXTRA:-sloc-raw-hosted}"
    local api_url="${REPO_URL}/service/rest/v1/components?repository=${repo_name}"
    echo "=== Nexus 3 (repo: ${repo_name}) → ${REPO_URL}/${REPO_PATH}/ ==="

    local curl_auth=()
    if [ -n "${REPO_USER}" ] && [ -n "${REPO_PASS}" ]; then
        curl_auth=(-u "${REPO_USER}:${REPO_PASS}")
    elif [ -n "${REPO_PASS}" ]; then
        curl_auth=(-H "Authorization: Bearer ${REPO_PASS}")
    fi

    for f in ${ARTIFACT_FILES}; do
        local file="${ARTIFACT_DIR}/${f}"
        if [ ! -f "${file}" ]; then
            echo "  SKIP  ${f} (file not found)"
            continue
        fi
        echo "  POST  ${f}  →  /${REPO_PATH}/${f}"

        if curl -sf "${curl_auth[@]}" -X POST "${api_url}" \
                -F "raw.directory=/${REPO_PATH}" \
                -F "raw.asset1=@${file};type=application/octet-stream" \
                -F "raw.asset1.filename=${f}" \
                --retry 3 --retry-delay 2 --retry-max-time 60; then
            echo "  OK"
        else
            echo "  FAIL  ${f}" >&2
            PUSH_FAILURES=$((PUSH_FAILURES + 1))
        fi
    done
}

# ── Provider: Sonatype Nexus Repository Manager 2 ────────────────────────────
#
# Uses the Nexus 2 content REST endpoint: PUT /content/repositories/<repo>/<path>/<file>
# The Nexus 2 context path (/nexus) must be included in ARTIFACT_REPO_URL if applicable.
#
# ARTIFACT_REPO_URL  : e.g. https://nexus.example.com/nexus
# ARTIFACT_REPO_EXTRA: repository ID (default: sloc-raw-hosted)
#
# Docs: https://support.sonatype.com/hc/en-us/articles/213465668

push_nexus2() {
    local repo_name="${REPO_EXTRA:-sloc-raw-hosted}"
    echo "=== Nexus 2 (repo: ${repo_name}) → ${REPO_URL}/${REPO_PATH}/ ==="

    local curl_auth=()
    if [ -n "${REPO_USER}" ] && [ -n "${REPO_PASS}" ]; then
        curl_auth=(-u "${REPO_USER}:${REPO_PASS}")
    fi

    for f in ${ARTIFACT_FILES}; do
        local file="${ARTIFACT_DIR}/${f}"
        if [ ! -f "${file}" ]; then
            echo "  SKIP  ${f} (file not found)"
            continue
        fi
        local target="${REPO_URL}/content/repositories/${repo_name}/${REPO_PATH}/${f}"
        echo "  PUT   ${f}  →  ${target}"

        if curl -sf "${curl_auth[@]}" -X PUT "${target}" -T "${file}" \
                --retry 3 --retry-delay 2 --retry-max-time 60; then
            echo "  OK"
        else
            echo "  FAIL  ${f}" >&2
            PUSH_FAILURES=$((PUSH_FAILURES + 1))
        fi
    done
}

# ── Provider: AWS S3 ──────────────────────────────────────────────────────────
#
# Uses the AWS CLI: aws s3 cp <file> <s3://bucket/path/file>
# Credentials are taken from ARTIFACT_REPO_USER (access key ID) and
# ARTIFACT_REPO_PASS (secret access key), falling back to the standard
# AWS credential chain (~/.aws, instance profile, env vars).
#
# ARTIFACT_REPO_URL  : s3://bucket-name
# ARTIFACT_REPO_EXTRA: extra flags for aws s3 cp (e.g. --sse aws:kms --storage-class STANDARD_IA)
#
# Requires: aws CLI  (https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html)

push_s3() {
    local extra_flags="${REPO_EXTRA:-}"
    echo "=== AWS S3 → ${REPO_URL}/${REPO_PATH}/ ==="

    if ! command -v aws >/dev/null 2>&1; then
        echo "ERROR: 'aws' CLI not found on PATH. Install the AWS CLI on this agent." >&2
        PUSH_FAILURES=$((PUSH_FAILURES + 1))
        return
    fi

    if [ -n "${REPO_USER}" ] && [ -n "${REPO_PASS}" ]; then
        export AWS_ACCESS_KEY_ID="${REPO_USER}"
        export AWS_SECRET_ACCESS_KEY="${REPO_PASS}"
    fi

    for f in ${ARTIFACT_FILES}; do
        local file="${ARTIFACT_DIR}/${f}"
        if [ ! -f "${file}" ]; then
            echo "  SKIP  ${f} (file not found)"
            continue
        fi
        local target="${REPO_URL}/${REPO_PATH}/${f}"
        echo "  cp    ${f}  →  ${target}"

        # shellcheck disable=SC2086
        if aws s3 cp "${file}" "${target}" ${extra_flags}; then
            echo "  OK"
        else
            echo "  FAIL  ${f}" >&2
            PUSH_FAILURES=$((PUSH_FAILURES + 1))
        fi
    done
}

# ── Provider: MinIO (S3-compatible) ──────────────────────────────────────────
#
# Uses the AWS CLI with a custom --endpoint-url for MinIO.
#
# ARTIFACT_REPO_URL  : s3://bucket-name  (the bucket, not the server URL)
# ARTIFACT_REPO_USER : MinIO access key
# ARTIFACT_REPO_PASS : MinIO secret key
# ARTIFACT_REPO_EXTRA: MinIO server endpoint URL (e.g. https://minio.internal:9000)
#
# Requires: aws CLI  (https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html)

push_minio() {
    local endpoint="${REPO_EXTRA:-}"
    echo "=== MinIO → ${REPO_URL}/${REPO_PATH}/ (endpoint: ${endpoint:-<from REPO_URL>}) ==="

    if ! command -v aws >/dev/null 2>&1; then
        echo "ERROR: 'aws' CLI not found on PATH. MinIO uses the aws CLI with --endpoint-url." >&2
        PUSH_FAILURES=$((PUSH_FAILURES + 1))
        return
    fi

    if [ -z "${endpoint}" ]; then
        echo "WARNING: ARTIFACT_REPO_EXTRA not set — cannot construct MinIO endpoint URL." >&2
        echo "         Set ARTIFACT_REPO_EXTRA to your MinIO server URL (e.g. https://minio.internal:9000)." >&2
        PUSH_FAILURES=$((PUSH_FAILURES + 1))
        return
    fi

    if [ -n "${REPO_USER}" ] && [ -n "${REPO_PASS}" ]; then
        export AWS_ACCESS_KEY_ID="${REPO_USER}"
        export AWS_SECRET_ACCESS_KEY="${REPO_PASS}"
    fi

    for f in ${ARTIFACT_FILES}; do
        local file="${ARTIFACT_DIR}/${f}"
        if [ ! -f "${file}" ]; then
            echo "  SKIP  ${f} (file not found)"
            continue
        fi
        local target="${REPO_URL}/${REPO_PATH}/${f}"
        echo "  cp    ${f}  →  ${target}"

        if aws s3 cp "${file}" "${target}" --endpoint-url "${endpoint}"; then
            echo "  OK"
        else
            echo "  FAIL  ${f}" >&2
            PUSH_FAILURES=$((PUSH_FAILURES + 1))
        fi
    done
}

# ── Provider: Azure Blob Storage ─────────────────────────────────────────────
#
# Uses the Azure CLI: az storage blob upload
# Auth: account key (ARTIFACT_REPO_PASS as raw key) or SAS token (ARTIFACT_REPO_PASS
# starting with "?sv=" or "sv="). Omitting ARTIFACT_REPO_PASS falls back to the
# Azure CLI's ambient credential chain (Managed Identity, az login, etc.).
#
# ARTIFACT_REPO_URL  : https://<account>.blob.core.windows.net
# ARTIFACT_REPO_EXTRA: container name (default: sloc-reports)
#
# Requires: az CLI  (https://learn.microsoft.com/cli/azure/install-azure-cli)

push_azure_blob() {
    local container="${REPO_EXTRA:-sloc-reports}"
    echo "=== Azure Blob Storage → ${REPO_URL}/${container}/${REPO_PATH}/ ==="

    if ! command -v az >/dev/null 2>&1; then
        echo "ERROR: 'az' CLI not found on PATH. Install the Azure CLI on this agent." >&2
        PUSH_FAILURES=$((PUSH_FAILURES + 1))
        return
    fi

    # Derive storage account name from URL: https://<account>.blob.core.windows.net
    local account
    account=$(echo "${REPO_URL}" | sed -E 's|https?://([^.]+)\..*|\1|')

    local auth_flags=()
    if [ -n "${REPO_PASS}" ]; then
        if [[ "${REPO_PASS}" == "?sv="* ]] || [[ "${REPO_PASS}" == "sv="* ]]; then
            auth_flags=(--sas-token "${REPO_PASS}")
        else
            auth_flags=(--account-key "${REPO_PASS}")
        fi
    fi

    for f in ${ARTIFACT_FILES}; do
        local file="${ARTIFACT_DIR}/${f}"
        if [ ! -f "${file}" ]; then
            echo "  SKIP  ${f} (file not found)"
            continue
        fi
        local blob_name="${REPO_PATH}/${f}"
        echo "  upload ${f}  →  ${container}/${blob_name}"

        if az storage blob upload \
                --account-name "${account}" \
                --container-name "${container}" \
                --name "${blob_name}" \
                --file "${file}" \
                --overwrite \
                "${auth_flags[@]}" \
                --output none; then
            echo "  OK"
        else
            echo "  FAIL  ${f}" >&2
            PUSH_FAILURES=$((PUSH_FAILURES + 1))
        fi
    done
}

# ── Provider: Generic HTTP PUT ───────────────────────────────────────────────
#
# Sends each artifact via HTTP PUT to <ARTIFACT_REPO_URL>/<ARTIFACT_REPO_PATH>/<filename>.
# Works with any HTTP server that accepts PUT requests (Sonatype Nexus raw,
# Artifactory legacy endpoints, Gitea packages, custom artifact stores, etc.).
# Auth: user+pass → Basic; pass only → Bearer token.

push_generic_http() {
    echo "=== Generic HTTP PUT → ${REPO_URL}/${REPO_PATH}/ ==="

    local curl_auth=()
    if [ -n "${REPO_USER}" ] && [ -n "${REPO_PASS}" ]; then
        curl_auth=(-u "${REPO_USER}:${REPO_PASS}")
    elif [ -n "${REPO_PASS}" ]; then
        curl_auth=(-H "Authorization: Bearer ${REPO_PASS}")
    fi

    for f in ${ARTIFACT_FILES}; do
        local file="${ARTIFACT_DIR}/${f}"
        if [ ! -f "${file}" ]; then
            echo "  SKIP  ${f} (file not found)"
            continue
        fi
        local target="${REPO_URL}/${REPO_PATH}/${f}"
        echo "  PUT   ${f}  →  ${target}"

        if curl -sf "${curl_auth[@]}" -X PUT "${target}" -T "${file}" \
                --retry 3 --retry-delay 2 --retry-max-time 60; then
            echo "  OK"
        else
            echo "  FAIL  ${f}" >&2
            PUSH_FAILURES=$((PUSH_FAILURES + 1))
        fi
    done
}

# ── Dispatch ─────────────────────────────────────────────────────────────────

echo ""
echo "oxide-sloc artifact push"
echo "  type  : ${REPO_TYPE}"
echo "  url   : ${REPO_URL}"
echo "  path  : ${REPO_PATH}"
echo "  files : ${ARTIFACT_FILES}"
echo "  dir   : ${ARTIFACT_DIR}"
echo ""

case "${REPO_TYPE}" in
    artifactory)  push_artifactory ;;
    nexus)        push_nexus ;;
    nexus2)       push_nexus2 ;;
    s3)           push_s3 ;;
    minio)        push_minio ;;
    azure-blob)   push_azure_blob ;;
    generic-http) push_generic_http ;;
esac

echo ""
if [ "${PUSH_FAILURES}" -gt 0 ]; then
    echo "RESULT: ${PUSH_FAILURES} artifact(s) failed to push — see output above." >&2
    exit 1
fi

echo "RESULT: all artifacts pushed successfully."
