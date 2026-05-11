#!/usr/bin/env bash
# Build with coverage instrumentation, run tests, and emit an lcov report.
set -euo pipefail

BUILD_DIR="${1:-build}"
REPORT_DIR="${2:-coverage}"

# Build with gcov instrumentation
bash "$(dirname "$0")/build.sh" "$BUILD_DIR" ON

echo "==> Running test suite"
cd "$BUILD_DIR"
ctest --output-on-failure --parallel "$(nproc 2>/dev/null || echo 4)"
cd ..

mkdir -p "$REPORT_DIR"

echo "==> Capturing lcov data"
lcov --capture \
     --directory "$BUILD_DIR" \
     --output-file "$REPORT_DIR/lcov.info" \
     --exclude '*/third_party/*' \
     --exclude '/usr/*' \
     --exclude '*/gtest/*'

echo "==> Generating HTML report"
genhtml "$REPORT_DIR/lcov.info" \
        --output-directory "$REPORT_DIR/html" \
        --title "Demo Project Coverage" \
        --legend

echo ""
echo "Coverage report: $REPORT_DIR/html/index.html"
lcov --summary "$REPORT_DIR/lcov.info"
