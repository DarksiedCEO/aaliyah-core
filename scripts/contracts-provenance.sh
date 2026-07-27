#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

expected_sha="31801a029c79f8286a63300058e82b3c2687fb60"
expected_tree="84c440d8211a91bb2ec551cc1d3a3603bb7b32f0"
expected_contract="aaliyah.postcondition-verification/v1"
expected_executive_contract="aaliyah.executive-messaging/v1"
expected_wave1_contract="aaliyah.executive-communications/wave1"
contracts_repo="../aaliyah-wave1-contracts"

git -C "$contracts_repo" rev-parse --git-dir >/dev/null 2>&1 || {
  printf 'FAIL  Contracts repository unavailable at %s\n' "$contracts_repo" >&2
  exit 1
}

actual_sha="$(git -C "$contracts_repo" rev-parse HEAD)"
[ "$actual_sha" = "$expected_sha" ] || {
  printf 'FAIL  Contracts SHA mismatch: expected %s, got %s\n' \
    "$expected_sha" "$actual_sha" >&2
  exit 1
}

actual_tree="$(git -C "$contracts_repo" rev-parse HEAD^{tree})"
[ "$actual_tree" = "$expected_tree" ] || {
  printf 'FAIL  Contracts tree mismatch: expected %s, got %s\n' \
    "$expected_tree" "$actual_tree" >&2
  exit 1
}

[ -z "$(git -C "$contracts_repo" status --short)" ] || {
  printf 'FAIL  Contracts worktree is dirty; provenance is not immutable\n' >&2
  exit 1
}

build_root="$(mktemp -d "${TMPDIR:-/tmp}/aaliyah-contracts-build.XXXXXX")"
trap 'rm -rf "$build_root"' EXIT
git -C "$contracts_repo" archive "$expected_sha" | tar -x -C "$build_root"
[ -d "$contracts_repo/node_modules" ] || {
  printf 'FAIL  Contracts build dependencies are unavailable\n' >&2
  exit 1
}
mkdir "$build_root/node_modules"
cp -R "$contracts_repo/node_modules/." "$build_root/node_modules"
if ! pnpm -C "$build_root" build >"$build_root/build.log" 2>&1; then
  cat "$build_root/build.log" >&2
  printf 'FAIL  isolated Contracts build failed\n' >&2
  exit 1
fi

installed_manifest="node_modules/@aaliyah/contracts/package.json"
[ -f "$installed_manifest" ] || {
  printf 'FAIL  installed Contracts package manifest is unavailable\n' >&2
  exit 1
}
cmp -s "$build_root/package.json" "$installed_manifest" || {
  printf 'FAIL  installed Contracts package manifest does not match exact SHA\n' >&2
  exit 1
}

actual_contracts="$(node -e '
  const contracts = require("@aaliyah/contracts/v1");
  process.stdout.write([
    contracts.POSTCONDITION_VERIFICATION_CONTRACT_VERSION ?? "",
    contracts.EXECUTIVE_MESSAGING_CONTRACT_VERSION ?? "",
    contracts.AALIYAH_EXECUTIVE_COMMUNICATIONS_CONTRACT_VERSION ?? "",
  ].join("|"));
')"
[ "$actual_contracts" = "$expected_contract|$expected_executive_contract|$expected_wave1_contract" ] || {
  printf 'FAIL  installed Contracts version mismatch: expected %s|%s|%s, got %s\n' \
    "$expected_contract" "$expected_executive_contract" "$expected_wave1_contract" \
    "${actual_contracts:-missing}" >&2
  exit 1
}

fresh_dist="$build_root/dist"
installed_dist="node_modules/@aaliyah/contracts/dist"
[ -d "$fresh_dist" ] || {
  printf 'FAIL  isolated Contracts build produced no dist tree\n' >&2
  exit 1
}
[ -d "$installed_dist" ] || {
  printf 'FAIL  installed Contracts package has no dist tree\n' >&2
  exit 1
}
diff -qr "$fresh_dist" "$installed_dist" >/dev/null || {
  printf 'FAIL  installed Contracts artifacts do not match isolated exact-SHA build\n' >&2
  exit 1
}

printf 'PASS  Contracts provenance %s tree %s (%s, %s, %s)\n' \
  "$expected_sha" "$expected_tree" "$expected_contract" \
  "$expected_executive_contract" "$expected_wave1_contract"
