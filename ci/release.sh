#!/usr/bin/env bash
# Usage: bash ci/release.sh [TARGET]
# Omit TARGET to build for the host. Provide a Rust target triple for cross-compilation.
set -euo pipefail

TARGET="${1:-}"

# native-dialog (rfd) requires wayland-client/GTK on Linux, which are not
# available in the musl static build environment or cross-compile sysroots.
# macOS and Windows have native API backends that need no extra system libs.
case "$TARGET" in
    *-linux-*)
        FEATURES_FLAG="--no-default-features"
        ;;
    *)
        FEATURES_FLAG=""
        ;;
esac

if [ -n "$TARGET" ]; then
    echo "==> Release build (target: $TARGET${FEATURES_FLAG:+, $FEATURES_FLAG})"
    # shellcheck disable=SC2086
    cargo build --release --target "$TARGET" -p oxide-sloc $FEATURES_FLAG
else
    echo "==> Release build (host target)"
    cargo build --release -p oxide-sloc
fi
