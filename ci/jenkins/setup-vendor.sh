#!/usr/bin/env bash
# Decompress vendor.tar.xz and write .cargo/config.toml for offline builds.
# CARGO_HOME is set by the Jenkinsfile environment{} block.
set -euo pipefail

AGENT_ARCHIVE="${CARGO_HOME}/../vendor.tar.xz"
AGENT_SHA="${CARGO_HOME}/../vendor.tar.xz.sha256"

# Stale vendor/ from a recycled workspace — re-extract to guarantee Cargo.lock-aligned versions.
if [ -d vendor ] && [ -f vendor.tar.xz ]; then
    echo "vendor/ exists alongside a tarball — wiping and re-extracting for freshness."
    rm -rf vendor
fi

if [ -d vendor ]; then
    echo "vendor/ already present — skipping extraction."
elif [ -f vendor.tar.xz ]; then
    echo "Verifying vendor.tar.xz integrity..."
    sha256sum -c vendor.tar.xz.sha256
    echo "Decompressing vendor.tar.xz..."
    tar -xJf vendor.tar.xz
elif [ -f "${AGENT_ARCHIVE}" ]; then
    echo "vendor.tar.xz not in workspace — falling back to agent cache..."
    cp "${AGENT_ARCHIVE}" vendor.tar.xz
    if [ -f "${AGENT_SHA}" ]; then
        cp "${AGENT_SHA}" vendor.tar.xz.sha256
        echo "Verifying vendor.tar.xz integrity..."
        sha256sum -c vendor.tar.xz.sha256
    else
        echo "WARNING: No .sha256 in agent cache — skipping checksum verification."
    fi
    echo "Decompressing vendor.tar.xz..."
    tar -xJf vendor.tar.xz
else
    echo "ERROR: vendor.tar.xz not found in workspace or agent cache." >&2
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
