#!/usr/bin/env bash
# Guard against status-masking shell pipes in Jenkins Groovy and ci/ shell
# scripts. Thin wrapper around lint-pipeline-shell.py so it is callable as a
# shell step from the Jenkinsfile Lint stage, the .gitlab-ci.yml lint job, and
# ci/lint.sh. Fast (<2s), no Jenkins/cargo/network.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"

# Resolve a Python interpreter. Linux agents ship `python3`; Git Bash on Windows
# usually ships `python` (and the launcher `py`) but NOT `python3`. Honour an
# explicit SLOC_PY override first, then fall back python3 -> python -> py.
if [ -n "${SLOC_PY:-}" ]; then
    PY="${SLOC_PY}"
elif command -v python3 >/dev/null 2>&1; then
    PY=python3
elif command -v python >/dev/null 2>&1; then
    PY=python
elif command -v py >/dev/null 2>&1; then
    PY=py
else
    echo "lint-pipeline-shell: no Python interpreter found (tried python3, python, py)." >&2
    echo "  Install Python 3, or set SLOC_PY to its path." >&2
    exit 1
fi

# Re-verify the guard itself against its regression fixtures before scanning, so a
# silent guard regression fails CI instead of passing green.
"${PY}" "${here}/lint-pipeline-shell-test.py"
exec "${PY}" "${here}/lint-pipeline-shell.py" "$@"
