#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

expected_sha="91a6c34b7e02cf9ffc9c17cc14db5f1a9a82d81d"
expected_contract="aaliyah.postcondition-verification/v1"
contracts_repo="../aaliyah-contracts"

[ -d "$contracts_repo/.git" ] || {
  printf 'FAIL  Contracts repository unavailable at %s\n' "$contracts_repo" >&2
  exit 1
}

actual_sha="$(git -C "$contracts_repo" rev-parse HEAD)"
[ "$actual_sha" = "$expected_sha" ] || {
  printf 'FAIL  Contracts SHA mismatch: expected %s, got %s\n' \
    "$expected_sha" "$actual_sha" >&2
  exit 1
}

[ -z "$(git -C "$contracts_repo" status --short)" ] || {
  printf 'FAIL  Contracts worktree is dirty; provenance is not immutable\n' >&2
  exit 1
}

actual_contract="$(node -e '
  const contracts = require("@aaliyah/contracts/v1");
  process.stdout.write(contracts.POSTCONDITION_VERIFICATION_CONTRACT_VERSION ?? "");
')"
[ "$actual_contract" = "$expected_contract" ] || {
  printf 'FAIL  installed Contracts version mismatch: expected %s, got %s\n' \
    "$expected_contract" "${actual_contract:-missing}" >&2
  exit 1
}

for artifact in \
  verification-receipt.js \
  postcondition-verification.js \
  execution.js \
  index.js
do
  source_artifact="$contracts_repo/dist/src/v1/$artifact"
  installed_artifact="node_modules/@aaliyah/contracts/dist/src/v1/$artifact"
  [ -f "$source_artifact" ] || {
    printf 'FAIL  missing built Contracts artifact: %s\n' "$source_artifact" >&2
    exit 1
  }
  [ -f "$installed_artifact" ] || {
    printf 'FAIL  missing installed Contracts artifact: %s\n' "$installed_artifact" >&2
    exit 1
  }
  cmp -s "$source_artifact" "$installed_artifact" || {
    printf 'FAIL  installed Contracts artifact is stale: %s\n' "$artifact" >&2
    exit 1
  }
done

printf 'PASS  Contracts provenance %s (%s)\n' "$expected_sha" "$expected_contract"
