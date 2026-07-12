#!/usr/bin/env bash
# Render the Cloud Run manifest from deploy config and apply it — or, with
# --validate, only render + check without touching any live project.
#
#   deploy/deploy.sh --validate            # render + config check, no GCP calls
#   deploy/deploy.sh                        # render + gcloud run services replace
#
# Fails closed: every required variable must be set, or it stops before acting.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="${AALIYAH_DEPLOY_CONFIG:-$HERE/config.env}"
MODE="${1:-deploy}"

REQUIRED_VARS=(
  GCP_PROJECT_ID REGION SERVICE_NAME IMAGE RUNTIME_SERVICE_ACCOUNT
  CLOUDSQL_INSTANCE_CONNECTION_NAME KMS_LOCATION KMS_KEY_RING KMS_CRYPTO_KEY
  GOOGLE_OAUTH_REDIRECT_URI SECRET_DATABASE_URL SECRET_GOOGLE_CLIENT_ID
  SECRET_GOOGLE_CLIENT_SECRET CONCURRENCY REQUEST_TIMEOUT_SECONDS CPU MEMORY
  MIN_INSTANCES MAX_INSTANCES
)

if [ ! -f "$CONFIG" ]; then
  echo "ERROR: deploy config not found at $CONFIG (copy deploy/config.example.env)" >&2
  exit 1
fi
# shellcheck disable=SC1090
set -a; . "$CONFIG"; set +a

missing=()
for v in "${REQUIRED_VARS[@]}"; do
  [ -z "${!v:-}" ] && missing+=("$v")
done
if [ "${#missing[@]}" -gt 0 ]; then
  echo "ERROR: missing required deploy vars: ${missing[*]}" >&2
  exit 1
fi
# Guard against shipping example placeholders.
case "$IMAGE" in
  *REPLACED_WITH_GIT_SHA*|*your-gcp-project-id*)
    echo "ERROR: IMAGE still contains a placeholder — set a real pushed image ref" >&2
    exit 1;;
esac

RENDERED="$(mktemp)"
trap 'rm -f "$RENDERED"' EXIT
# Substitute ONLY our known vars (envsubst without a var list would eat $PORT etc.
# that must stay literal in the manifest).
# shellcheck disable=SC2016
envsubst "$(printf '${%s} ' "${REQUIRED_VARS[@]}")" < "$HERE/cloud-run-service.yaml" > "$RENDERED"

if grep -q '\${' "$RENDERED"; then
  echo "ERROR: unresolved \${...} placeholders remain after render:" >&2
  grep -n '\${' "$RENDERED" >&2
  exit 1
fi

echo "Rendered manifest for service '$SERVICE_NAME' in $REGION (image: $IMAGE)"

if [ "$MODE" = "--validate" ]; then
  echo "VALIDATE mode: manifest rendered and fully resolved. No GCP calls made."
  cat "$RENDERED"
  exit 0
fi

command -v gcloud >/dev/null || { echo "ERROR: gcloud not installed" >&2; exit 1; }
echo "Applying to project $GCP_PROJECT_ID ..."
gcloud run services replace "$RENDERED" --project "$GCP_PROJECT_ID" --region "$REGION"

echo "Deployed. Verifying readiness ..."
URL="$(gcloud run services describe "$SERVICE_NAME" --project "$GCP_PROJECT_ID" --region "$REGION" --format='value(status.url)')"
"$HERE/verify-deployment.sh" "$URL"
