# Stage 1: build the release binary
# Pin builder to rust:1.95-slim-bookworm so the toolchain and runtime both use
# Debian bookworm (glibc 2.36). rust:slim can resolve to a trixie-based digest
# (glibc 2.39) while the runtime stage below is still bookworm-slim, causing
# "GLIBC_2.39 not found" at container startup.
# Digest pinned to prevent silent base-image substitution.
# To update: docker pull rust:1.95-slim-bookworm && docker inspect --format '{{index .RepoDigests 0}}' rust:1.95-slim-bookworm
FROM rust:1.95-slim-bookworm@sha256:d7482085ff5b415f84dba5647ae71606650bdef00db7aeb69f4b3d170c3e4082 AS builder

# Upgrade base packages first to pull in any OS-level security fixes
# that have landed since the image was published.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends \
    pkg-config \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
RUN mkdir -p .cargo
COPY ci/docker-cargo-config.toml .cargo/config.toml
COPY crates/ crates/
COPY docs/ docs/
COPY vendor.tar.xz vendor.tar.xz.sha256 ./

# Verify the vendor archive integrity and extract it.
# This must happen before `cargo build` because .cargo/config.toml points cargo
# at the vendor/ directory as the sole crate source (no network access).
RUN sha256sum -c vendor.tar.xz.sha256 \
    && tar -xJf vendor.tar.xz \
    && rm vendor.tar.xz

# Pre-flight: confirm the workspace source tree is actually present in the build
# context. If crates/ is accidentally re-added to .dockerignore this produces a
# clear, actionable error instead of a cryptic Cargo manifest failure.
RUN test -d crates/sloc-config \
    || { \
         echo "ERROR: crates/sloc-config is missing from the Docker build context." >&2; \
         echo "Check .dockerignore — crates/ must not be excluded." >&2; \
         exit 1; \
       }

RUN cargo build --release -p oxide-sloc --no-default-features

# Stage 2: minimal runtime image
# Pin to a specific digest to prevent silent base-image substitution.
# To update: docker pull debian:bookworm-slim && docker inspect --format '{{index .RepoDigests 0}}' debian:bookworm-slim
FROM debian:bookworm-slim@sha256:0104b334637a5f19aa9c983a91b54c89887c0984081f2068983107a6f6c21eeb

# Install Chromium for PDF export (headless).
# For a fully air-gapped Docker host, build this layer from a pre-populated
# apt mirror or use a pre-built image that already contains chromium.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends \
    chromium \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/oxide-sloc /usr/local/bin/oxide-sloc

# Create a non-root service account and ensure the output directory is writable by it.
RUN groupadd -r sloc && useradd -r -g sloc -u 1001 sloc \
    && mkdir -p /app/out \
    && chown -R sloc:sloc /app/out

ENV OXIDE_SLOC_ROOT=/app

# Point oxide-sloc at the system Chromium
ENV SLOC_BROWSER=/usr/bin/chromium
# SLOC_BROWSER_NOSANDBOX is intentionally NOT set here.
# Pass -e SLOC_BROWSER_NOSANDBOX=1 at runtime when running in a container
# runtime that does not grant SYS_ADMIN (most runtimes, and required when
# cap_drop: ALL is set). With SYS_ADMIN and a permissive seccomp profile the
# sandbox can be enabled by leaving this unset.

EXPOSE 4317

USER 1001

# HEALTHCHECK verifies the /healthz endpoint is responsive.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD oxide-sloc healthz 2>/dev/null || exit 1

ENTRYPOINT ["oxide-sloc"]
# --server: binds to 0.0.0.0, suppresses browser auto-open, disables desktop-only routes.
CMD ["serve", "--server"]
