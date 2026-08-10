#!/usr/bin/env bash
# Reassemble the split vendor.tar.gz parts and write .cargo/config.toml for offline builds.
# CARGO_HOME is set by the Jenkinsfile environment{} block.
set -euo pipefail

AGENT_CHECKSUMS="${CARGO_HOME}/../vendor.checksums.sha256"

# Stale vendor/ from a recycled workspace — re-extract to guarantee Cargo.lock-aligned versions.
if [ -d vendor ] && ls vendor.tar.gz.* >/dev/null 2>&1; then
    echo "vendor/ exists alongside split parts — wiping and re-extracting for freshness."
    rm -rf vendor
fi

if [ -d vendor ]; then
    echo "vendor/ already present — skipping extraction."
elif ls vendor.tar.gz.* >/dev/null 2>&1; then
    echo "Verifying vendor.tar.gz.* integrity..."
    sha256sum -c vendor.checksums.sha256
    echo "Reassembling and decompressing vendor.tar.gz.*..."
    cat vendor.tar.gz.* | tar -xzf -
elif ls "${CARGO_HOME}/.."/vendor.tar.gz.* >/dev/null 2>&1; then
    echo "vendor.tar.gz.* not in workspace — falling back to agent cache..."
    cp "${CARGO_HOME}/.."/vendor.tar.gz.* .
    if [ -f "${AGENT_CHECKSUMS}" ]; then
        cp "${AGENT_CHECKSUMS}" vendor.checksums.sha256
        echo "Verifying vendor.tar.gz.* integrity..."
        sha256sum -c vendor.checksums.sha256
    else
        echo "WARNING: No vendor.checksums.sha256 in agent cache — skipping checksum verification."
    fi
    echo "Reassembling and decompressing vendor.tar.gz.*..."
    cat vendor.tar.gz.* | tar -xzf -
else
    echo "ERROR: vendor.tar.gz.* parts not found in workspace or agent cache." >&2
    echo "       Ensure the repository was cloned from the correct branch/tag." >&2
    exit 1
fi

echo "Writing .cargo/config.toml for fully offline builds..."
mkdir -p .cargo
cat > .cargo/config.toml << 'CARGOEOF'
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
CARGOEOF
