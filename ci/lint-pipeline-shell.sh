#!/usr/bin/env bash
# Guard against status-masking shell pipes in Jenkins Groovy and ci/ shell
# scripts. Thin wrapper around lint-pipeline-shell.py so it is callable as a
# shell step from the Jenkinsfile Lint stage, the .gitlab-ci.yml lint job, and
# ci/lint.sh. Fast (<2s), no Jenkins/cargo/network.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
# Re-verify the guard itself against its regression fixtures before scanning, so a
# silent guard regression fails CI instead of passing green.
python3 "${here}/lint-pipeline-shell-test.py"
exec python3 "${here}/lint-pipeline-shell.py" "$@"
