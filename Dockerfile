# syntax=docker/dockerfile:1.6
#
# ARGUS multi-stage Dockerfile.
#
# Goal: a small, reproducible container image users can pull and run
# anywhere (Windows Docker Desktop, macOS, Linux, CI runners, K8s)
# without touching their local endpoint security posture. No exe on
# the host, no SmartScreen / Defender / EDR interaction, no PATH
# updates. Just:
#
#   docker pull ghcr.io/vatsayanvivek/argus:v1.9.0
#   docker run --rm -v ~/.azure:/home/argus/.azure:ro \
#              ghcr.io/vatsayanvivek/argus:v1.9.0 \
#              scan --tenant <id> --subscription <id>
#
# Two-stage build:
#   1. Builder — full Go toolchain; compiles a fully-static binary
#      with CGO_ENABLED=0 so the runtime image doesn't need a libc.
#   2. Runtime — Google's distroless `static-debian12` image. ~2 MB
#      base, no shell, no package manager, no user-installable
#      tools. Purely the argus binary + its CA certs. Smallest
#      viable attack surface for a security tool.
#
# Build locally:
#   docker build -t argus:local .
#   docker run --rm argus:local --version

# --- Stage 1: build ---------------------------------------------------
FROM golang:1.25-alpine AS builder

# Install git (go mod needs it to resolve some modules) and ca-certs
# (copied to the runtime image so argus can verify Azure endpoint
# certs at runtime).
RUN apk add --no-cache git ca-certificates

WORKDIR /src

# Pre-fetch modules before copying source so Docker can cache the
# go.mod/go.sum layer separately from every source change.
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest and run the embed-prep step (which mirrors
# policies/, data/, templates/ into the package dirs Go's
# //go:embed directive can see).
COPY . .
RUN mkdir -p internal/engine internal/benchmark internal/reporter && \
    cp -R policies internal/engine/policies && \
    cp -R data internal/benchmark/data && \
    mkdir -p internal/reporter/templates && \
    cp templates/report.html internal/reporter/templates/report.html && \
    cp data/azure_builtin_roles.json internal/drift/builtin_roles.json

# Static build. The -s -w strip reduces binary size by ~30 %. The
# VERSION build arg lets CI stamp the release tag in; defaults to
# "dev" for local builds.
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.Version=${VERSION}" \
    -o /out/argus ./main.go

# --- Stage 2: runtime -------------------------------------------------
#
# Base image: Chainguard's `static` — a hardened, minimal base image
# purpose-built for Go static binaries.
#
# Why Chainguard static over alternatives:
#   - Rebuilt within hours of every upstream CVE disclosure, so we
#     ship a container with effectively zero known vulnerabilities.
#   - Contains only ca-certificates, tzdata, and /etc/passwd — no
#     shell, no package manager, no coreutils. Attack surface is
#     approximately zero.
#   - Signed by Sigstore (cosign verifiable).
#   - Runs as nonroot user by default (uid 65532).
#   - Free and publicly distributed with no subscription required.
#   - Equivalent to Google's distroless/static-debian12 or Docker
#     Hardened Images' static tier in security posture; chosen here
#     because Chainguard publishes SBOMs and attestations for every
#     image without a paid subscription.
#
# The CI runs Trivy against the final image on every release to
# verify the zero-CVE claim — see .github/workflows/release.yml.
FROM cgr.dev/chainguard/static:latest AS runtime

# OCI labels surface provenance in registry UIs and in
# `docker inspect` output. Registry reputation systems consume these.
LABEL org.opencontainers.image.title="ARGUS" \
      org.opencontainers.image.description="Attack chain analysis for Microsoft Azure" \
      org.opencontainers.image.source="https://github.com/vatsayanvivek/argus" \
      org.opencontainers.image.url="https://github.com/vatsayanvivek/argus" \
      org.opencontainers.image.documentation="https://github.com/vatsayanvivek/argus#readme" \
      org.opencontainers.image.vendor="vatsayanvivek" \
      org.opencontainers.image.licenses="PolyForm-Strict-1.0.0" \
      org.opencontainers.image.base.name="cgr.dev/chainguard/static:latest"

# Chainguard static already ships /etc/ssl/certs/ca-certificates.crt,
# so we don't need to copy it from the builder stage — one fewer
# layer, one fewer chance of certificate skew between build + runtime.
COPY --from=builder /out/argus /usr/local/bin/argus

# Home directory for the nonroot user. Mount ~/.azure from the host
# with -v ~/.azure:/home/nonroot/.azure:ro to pass Azure CLI creds
# into the container.
WORKDIR /home/nonroot
VOLUME ["/home/nonroot/.azure"]

ENTRYPOINT ["/usr/local/bin/argus"]
CMD ["--help"]
