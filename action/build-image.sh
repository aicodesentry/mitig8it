#!/bin/sh
# Build the action's image. Used by the composite action and by CI, so the two cannot drift.
#
#   build-image.sh <tag> [cache-dir]
#
# The context is always the repository root, which is this script's parent directory, because
# the image bundles the analysis, remediation and github services that live beside the action.
#
# Caching needs a word of explanation. buildx's default "docker" driver cannot export a build
# cache at all: asking it to fails the build outright with "Cache export is not supported for
# the docker driver". A cache therefore requires a builder on the docker-container driver, which
# this script creates on demand and reuses. `--load` still puts the finished image in the local
# daemon, which is what `docker run` needs, so nothing is pushed anywhere.
#
# Every capability is optional and degrades to a plain build rather than a failure: no buildx, a
# builder that cannot be created, or no cache directory given all fall back to `docker build`.
set -eu

TAG="${1:?usage: build-image.sh <tag> [cache-dir]}"
CACHE_DIR="${2:-}"

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
ROOT="$(CDPATH='' cd -- "${SCRIPT_DIR}/.." && pwd)"
DOCKERFILE="${SCRIPT_DIR}/Dockerfile"
BUILDER=mitig8it-action-builder

start="$(date +%s)"

use_cache=0
if [ -n "${CACHE_DIR}" ] && docker buildx version >/dev/null 2>&1; then
  if docker buildx inspect "${BUILDER}" >/dev/null 2>&1 \
    || docker buildx create --name "${BUILDER}" --driver docker-container >/dev/null 2>&1; then
    use_cache=1
  else
    echo "Could not create a docker-container builder; building without a layer cache."
  fi
fi

if [ "${use_cache}" -eq 1 ]; then
  docker buildx build \
    --builder "${BUILDER}" \
    --file "${DOCKERFILE}" \
    --tag "${TAG}" \
    --load \
    --cache-from "type=local,src=${CACHE_DIR}" \
    --cache-to "type=local,dest=${CACHE_DIR}.new,mode=max" \
    "${ROOT}"
  # buildx appends to an existing cache rather than replacing it, so without this rotation the
  # directory grows on every run until the cache is bigger than the image it is meant to speed
  # up. The guard matters: the image is already built by this point, and an export that wrote
  # nothing must not fail a build that succeeded.
  if [ -d "${CACHE_DIR}.new" ]; then
    rm -rf "${CACHE_DIR}"
    mv "${CACHE_DIR}.new" "${CACHE_DIR}"
  else
    echo "The build exported no cache; keeping the previous one."
  fi
else
  [ -n "${CACHE_DIR}" ] || echo "No cache directory given; building without a layer cache."
  docker build --file "${DOCKERFILE}" --tag "${TAG}" "${ROOT}"
fi

echo "Image built in $(( $(date +%s) - start ))s."
docker image inspect "${TAG}" --format '{{ .Size }}' \
  | awk '{ printf "Image size: %.0f MB\n", $1 / 1048576 }'
