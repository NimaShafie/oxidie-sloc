#!/usr/bin/env bash
# Scan the repository at a specific git ref using a temporary worktree.
# Environment variables required (set by the Jenkinsfile withEnv block):
#   GIT_REF        — the ref to scan (branch, tag, or commit SHA)
#   OUTPUT_SUBDIR  — artifact output directory (relative to WORKSPACE)
#   BINARY         — path to compiled oxide-sloc binary (set in Jenkinsfile environment{})
#   WORKSPACE      — Jenkins workspace root (set by Jenkins)
set -euo pipefail

REF="${GIT_REF:-}"
OUT="${WORKSPACE}/${OUTPUT_SUBDIR}"
WT="${WORKSPACE}/.wt-ref-scan"

echo "=== Git-Ref Scan: ${REF} ==="
git worktree add --detach "${WT}" "${REF}"

"${BINARY}" analyze "${WT}" \
    --json-out  "${OUT}/ref-scan.json" \
    --html-out  "${OUT}/ref-scan.html" \
    --csv-out   "${OUT}/ref-scan-summary.csv" \
    --report-title "Ref scan: ${REF}" \
    --plain

git worktree remove --force "${WT}" || true
