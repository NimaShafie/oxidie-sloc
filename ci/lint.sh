#!/usr/bin/env bash
set -euo pipefail

echo "==> Pipeline shell-pipe guard"
bash "$(dirname "$0")/lint-pipeline-shell.sh"

echo "==> Format check"
cargo fmt --all -- --check

echo "==> Clippy"
cargo clippy --workspace --all-targets -- -D warnings
