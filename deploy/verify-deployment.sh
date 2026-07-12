#!/usr/bin/env bash
# Post-deploy verification: the service must answer liveness AND readiness.
# Readiness proves the deployed instance actually reached Postgres.
#
#   deploy/verify-deployment.sh https://aaliyah-core-xxxx.run.app
set -euo pipefail

BASE="${1:?usage: verify-deployment.sh <service-url>}"
fail=0

check() {
  local path="$1" expect="$2"
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' --retry 10 --retry-delay 2 --retry-connrefused "$BASE$path" || echo 000)"
  if [ "$code" = "$expect" ]; then
    echo "OK   $path -> $code"
  else
    echo "FAIL $path -> $code (expected $expect)"; fail=1
  fi
}

echo "Verifying $BASE"
check /health 200
check /ready 200

if [ "$fail" -ne 0 ]; then
  echo "DEPLOYMENT VERIFICATION FAILED" >&2
  echo "Rollback: gcloud run services update-traffic \$SERVICE_NAME --to-revisions=PRIOR_REVISION=100 --region \$REGION" >&2
  exit 1
fi
echo "DEPLOYMENT VERIFIED (liveness + readiness green)"
