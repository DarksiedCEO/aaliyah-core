#!/usr/bin/env bash
# Build the production image (from the PARENT dir so the file: contracts dep
# resolves) and push it to Artifact Registry, tagged with the git SHA.
#
#   deploy/build-and-push.sh          # build + push
#   deploy/build-and-push.sh --build  # build only (no push, no GCP needed)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE_DIR="$(cd "$HERE/.." && pwd)"
PARENT_DIR="$(cd "$CORE_DIR/.." && pwd)"
CONFIG="${AALIYAH_DEPLOY_CONFIG:-$HERE/config.env}"
MODE="${1:-push}"

SHA="$(git -C "$CORE_DIR" rev-parse --short HEAD)"

if [ "$MODE" = "--build" ]; then
  echo "Building aaliyah-core:$SHA (local, no push) ..."
  docker build -f "$CORE_DIR/Dockerfile" -t "aaliyah-core:$SHA" "$PARENT_DIR"
  echo "Built aaliyah-core:$SHA"
  exit 0
fi

[ -f "$CONFIG" ] || { echo "ERROR: $CONFIG not found (copy config.example.env)" >&2; exit 1; }
# shellcheck disable=SC1090
set -a; . "$CONFIG"; set +a
: "${ARTIFACT_REGISTRY_HOST:?}"; : "${GCP_PROJECT_ID:?}"; : "${ARTIFACT_REPO:?}"

IMAGE_REF="$ARTIFACT_REGISTRY_HOST/$GCP_PROJECT_ID/$ARTIFACT_REPO/aaliyah-core:$SHA"
command -v gcloud >/dev/null || { echo "ERROR: gcloud not installed" >&2; exit 1; }
gcloud auth configure-docker "$ARTIFACT_REGISTRY_HOST" --quiet

echo "Building + pushing $IMAGE_REF ..."
docker build -f "$CORE_DIR/Dockerfile" -t "$IMAGE_REF" "$PARENT_DIR"
docker push "$IMAGE_REF"
echo "Pushed. Set IMAGE=$IMAGE_REF in your deploy config."
