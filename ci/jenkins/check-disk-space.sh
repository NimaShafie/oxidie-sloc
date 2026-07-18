#!/usr/bin/env bash
# oxide-sloc CI disk-space preflight + cache maintenance.
#
# Run at the very start of a build (from runSetup). It:
#   1. Reports free space + the big consumers (workspace, persistent Rust cache).
#   2. FAILS FAST if free space is below the hard minimum — a clear error up front
#      is far better than an ENOSPC crash halfway through a 5-minute Rust build.
#   3. Optionally prunes the persistent Rust cache's regeneratable download caches
#      when it grows past a cap, so the cache that survives cleanWs() across builds
#      cannot balloon unbounded. Installed tools and vendored sources are NOT
#      touched — only cargo's re-downloadable registry caches.
#
# Tunables (env):
#   SLOC_DISK_MIN_GB    hard floor; build fails below this   (default 3)
#   SLOC_DISK_WARN_GB   warn below this                      (default 8)
#   SLOC_CACHE_CAP_GB   prune Rust cache download caches above this (default 20; 0 disables)
set -uo pipefail

MIN_GB="${SLOC_DISK_MIN_GB:-3}"
WARN_GB="${SLOC_DISK_WARN_GB:-8}"
CAP_GB="${SLOC_CACHE_CAP_GB:-20}"
WS="${WORKSPACE:-$PWD}"
CARGO_HOME="${CARGO_HOME:-$HOME/.rust-cache/cargo}"

# Free space (GiB) on the workspace filesystem.
free_gb="$(df -PBG "${WS}" 2>/dev/null | awk 'NR==2 {gsub(/G/,"",$4); print $4+0}')"
[ -z "${free_gb}" ] && free_gb=999   # df unavailable → don't block

# Size a directory in GiB, capped at 25s so a huge tree can never stall the
# preflight (prints "?" if it times out / du is unavailable).
du_gb() {
    local out
    if command -v timeout >/dev/null 2>&1; then
        out="$(timeout 25 du -sBG "$1" 2>/dev/null | awk '{gsub(/G/,"",$1); print $1+0}')"
    else
        out="$(du -sBG "$1" 2>/dev/null | awk '{gsub(/G/,"",$1); print $1+0}')"
    fi
    printf '%s' "${out:-?}"
}

echo "==> Disk preflight"
echo "    Free on $(df -PBG "${WS}" 2>/dev/null | awk 'NR==2{print $6}'): ${free_gb} GiB"
[ -d "${WS}/target" ]     && echo "    Workspace target/ : $(du_gb "${WS}/target") GiB"
[ -d "${CARGO_HOME}" ]    && echo "    Rust cache        : $(du_gb "${CARGO_HOME}") GiB (${CARGO_HOME})"

# ── Cache cap prune (safe: only cargo's re-downloadable caches) ───────────────
if [ "${CAP_GB}" -gt 0 ] && [ -d "${CARGO_HOME}" ]; then
    cache_gb="$(du_gb "${CARGO_HOME}")"
    if [[ "${cache_gb}" =~ ^[0-9]+$ ]] && [ "${cache_gb}" -gt "${CAP_GB}" ]; then
        echo "==> Rust cache ${cache_gb} GiB exceeds cap ${CAP_GB} GiB — pruning download caches"
        rm -rf "${CARGO_HOME}/registry/cache" 2>/dev/null || true
        find "${CARGO_HOME}/registry/index" -type d -name '.cache' -exec rm -rf {} + 2>/dev/null || true
        rm -rf "${CARGO_HOME}/git/checkouts" 2>/dev/null || true
        echo "    Rust cache now    : $(du_gb "${CARGO_HOME}") GiB (installed tools + vendored src kept)"
    fi
fi

# ── Fail-fast / warn on low free space ────────────────────────────────────────
if [ "${free_gb}" -lt "${MIN_GB}" ]; then
    echo "ERROR: only ${free_gb} GiB free on the build volume (hard minimum ${MIN_GB} GiB)." >&2
    echo "       Aborting before the build to avoid a mid-run out-of-disk failure." >&2
    echo "       Free space by: cleaning old builds, lowering buildDiscarder retention," >&2
    echo "       or pruning the Rust cache at ${CARGO_HOME}." >&2
    exit 1
fi
if [ "${free_gb}" -lt "${WARN_GB}" ]; then
    echo "WARNING: only ${free_gb} GiB free (below the ${WARN_GB} GiB comfort threshold)." >&2
    echo "         The build will proceed, but consider freeing space soon." >&2
fi
echo "==> Disk preflight OK"
exit 0
