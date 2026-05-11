#!/usr/bin/env bash
# Build the demo project.  Pass "coverage" as $2 to instrument with gcov.
set -euo pipefail

BUILD_DIR="${1:-build}"
COVERAGE="${2:-OFF}"

CPU_COUNT=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

echo "==> Configuring (BUILD_DIR=$BUILD_DIR  COVERAGE=$COVERAGE)"
cmake -S . -B "$BUILD_DIR" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DENABLE_COVERAGE="$COVERAGE"

echo "==> Building with $CPU_COUNT parallel jobs"
cmake --build "$BUILD_DIR" --parallel "$CPU_COUNT"

echo "==> Done — artifacts in $BUILD_DIR/"
