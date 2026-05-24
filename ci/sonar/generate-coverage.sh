#!/usr/bin/env bash
# Generate LCOV and Cobertura coverage reports for Jenkins and SonarQube import.
#
# Usage: bash ci/sonar/generate-coverage.sh [output-dir]
# Default output directory: coverage/
#
# Tool priority:
#   1. cargo-llvm-cov  — preferred; produces LCOV with line + branch coverage
#        (BRH/BRF LCOV records) and Cobertura XML with function-level data.
#        Vendored in ci/tools/Cargo.toml for offline install on air-gapped agents.
#        Install (online):  cargo install cargo-llvm-cov
#        Install (offline): cargo install --offline cargo-llvm-cov
#        Also requires:     rustup component add llvm-tools
#   2. cargo-tarpaulin — cross-platform fallback; produces LCOV (line coverage
#        only — no branch data) and Cobertura XML.
#        Install: cargo install cargo-tarpaulin
#
# Output files written to OUTPUT_DIR:
#   lcov.info            — LCOV format; consumed by:
#                            • recordCoverage(parser: 'LCOV') in Jenkinsfile
#                            • sonar.rust.lcov.reportPaths in sonar-project.properties
#                            • genhtml for HTML fallback report
#   sonar-coverage.xml   — Cobertura XML; consumed by:
#                            • recordCoverage(parser: 'COBERTURA') in Jenkinsfile
#                            (sonar.coverageReportPaths is intentionally disabled —
#                            it expects Generic Coverage format, not Cobertura)
#   coverage-summary.txt — human-readable line/branch coverage summary

set -euo pipefail

OUTPUT_DIR="${1:-coverage}"
mkdir -p "$OUTPUT_DIR"

has_cargo_subcommand() {
    cargo "$1" --version &>/dev/null 2>&1
}

# Print a coverage summary from an lcov.info file.
print_lcov_summary() {
    local lcov_file="$1"
    [ -f "$lcov_file" ] || return
    local lf lh bf bh line_pct branch_pct
    lf=$(grep -E '^LF:' "$lcov_file" | awk -F: '{s+=$2} END{print s+0}')
    lh=$(grep -E '^LH:' "$lcov_file" | awk -F: '{s+=$2} END{print s+0}')
    bf=$(grep -E '^BRF:' "$lcov_file" | awk -F: '{s+=$2} END{print s+0}')
    bh=$(grep -E '^BRH:' "$lcov_file" | awk -F: '{s+=$2} END{print s+0}')
    line_pct=$([ "$lf" -gt 0 ] && awk "BEGIN { printf \"%.1f\", ($lh/$lf)*100 }" || echo "N/A")
    if [ "${bf:-0}" -gt 0 ]; then
        branch_pct=$(awk "BEGIN { printf \"%.1f\", ($bh/$bf)*100 }")
    else
        branch_pct="N/A (no branch data)"
    fi
    {
        echo "=== Coverage Summary ==="
        echo "  Line coverage  : ${line_pct}% (${lh}/${lf} lines hit)"
        echo "  Branch coverage: ${branch_pct}${bf:+ (${bh}/${bf} branches hit)}"
    } | tee "$OUTPUT_DIR/coverage-summary.txt"
}

# ── System library check (Linux only) ────────────────────────────────────────
# --all-features activates the optional rfd crate (via native-dialog), which
# requires libwayland, libgtk-3, and libxdo devel headers at compile time.
# Detect missing packages early so the error is actionable rather than a
# multi-screen Rust build failure deep inside cargo.
if [[ "$(uname -s)" == "Linux" ]] && ! pkg-config --exists wayland-client gtk+-3.0 2>/dev/null; then
    echo "ERROR: missing system devel packages required for --all-features:" >&2
    echo "  RHEL/Rocky/Alma: sudo dnf install gtk3-devel libxdo-devel wayland-devel" >&2
    echo "  Debian/Ubuntu:   sudo apt install libgtk-3-dev libxdo-dev libwayland-dev" >&2
    exit 1
fi

# ── cargo-llvm-cov ────────────────────────────────────────────────────────────
if has_cargo_subcommand llvm-cov; then
    echo "==> Generating coverage with cargo-llvm-cov"

    # llvm-tools component is declared in rust-toolchain.toml; add it explicitly
    # as a no-op safeguard for environments that didn't install from the toolchain file.
    rustup component add llvm-tools 2>/dev/null || true

    # LCOV output — includes both line coverage (LH/LF) and branch coverage
    # (BRH/BRF) from LLVM source-based instrumentation.  Branch data is used by
    # the Jenkins Coverage plugin's branch % metric and genhtml's branch report.
    cargo llvm-cov \
        --workspace \
        --all-features \
        --lcov \
        --output-path "${OUTPUT_DIR}/lcov.info"

    # Rewrite absolute build paths to workspace-relative so SF: records resolve
    # under any mount point (host path or /usr/src inside sonar-scanner-cli).
    sed -i "s|^SF:$(pwd)/|SF:|" "${OUTPUT_DIR}/lcov.info"

    # Cobertura XML — provides function-level hit counts in addition to line
    # coverage; consumed by recordCoverage(parser: 'COBERTURA') and SonarQube.
    cargo llvm-cov \
        --workspace \
        --all-features \
        --cobertura \
        --output-path "${OUTPUT_DIR}/sonar-coverage.xml"

    print_lcov_summary "${OUTPUT_DIR}/lcov.info"
    echo "Coverage reports written to ${OUTPUT_DIR}/"
    exit 0
fi

# ── cargo-tarpaulin ───────────────────────────────────────────────────────────
if has_cargo_subcommand tarpaulin; then
    echo "==> Generating coverage with cargo-tarpaulin"
    echo "    NOTE: tarpaulin produces line coverage only — no branch data (BRH/BRF)."
    echo "    Install cargo-llvm-cov for full line + branch coverage."

    cargo tarpaulin \
        --workspace \
        --all-features \
        --out Lcov Xml \
        --output-dir "${OUTPUT_DIR}" \
        --exclude-files "tests/*" \
        --timeout 120

    # tarpaulin names the XML file "cobertura.xml"; rename to the expected name.
    if [ -f "${OUTPUT_DIR}/cobertura.xml" ]; then
        mv -f "${OUTPUT_DIR}/cobertura.xml" "${OUTPUT_DIR}/sonar-coverage.xml"
    fi

    print_lcov_summary "${OUTPUT_DIR}/lcov.info"
    echo "Coverage reports written to ${OUTPUT_DIR}/"
    exit 0
fi

# ── Neither tool found ────────────────────────────────────────────────────────
cat >&2 <<'EOF'
WARNING: Neither cargo-llvm-cov nor cargo-tarpaulin is installed.
  Coverage data will NOT be generated for Jenkins or SonarQube.

  Recommended — cargo-llvm-cov (produces LCOV with line + branch coverage):
    cargo install cargo-llvm-cov     # vendored in ci/tools/Cargo.toml for air-gapped agents
    rustup component add llvm-tools  # declared in rust-toolchain.toml

  Alternative — cargo-tarpaulin (line coverage only, no branch data):
    cargo install cargo-tarpaulin
EOF
exit 0
