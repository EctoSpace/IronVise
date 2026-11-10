#!/bin/sh
# Build the local image without BuildKit provenance or SBOM attestations.
# Those attestations record the source repository URL, and on a native
# buildx --load they are also counted in the image size. The Dockerfile's
# last stage is a single runtime rootfs, so do not pass --target builder.
# Extra buildx arguments are passed through, for example:
#   scripts/docker-build.sh --platform linux/amd64 --load -t ironvise:local
set -eu
cd "$(dirname "$0")/.."
exec docker buildx build \
    --file Dockerfile \
    --provenance=false \
    --sbom=false \
    "$@" \
    .
