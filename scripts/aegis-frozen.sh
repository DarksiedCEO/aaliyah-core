#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

manifest=".aegis-frozen.sha256"
usage() {
  cat <<'EOF'
Usage:
  scripts/aegis-frozen.sh verify
  scripts/aegis-frozen.sh regenerate --allow PATH [--allow PATH ...]

The regenerate command updates the manifest atomically and only when the
allow-list exactly matches the frozen paths whose content hashes changed.
EOF
}

die() {
  printf 'FAIL  %s\n' "$*" >&2
  exit 1
}

[ -f "$manifest" ] || die "missing $manifest"
[ -s "$manifest" ] || die "empty $manifest"

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/aegis-frozen.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT

paths="$tmp_dir/paths"
sorted_paths="$tmp_dir/paths.sorted"
changed_paths="$tmp_dir/changed.sorted"
allowed_paths="$tmp_dir/allowed.sorted"
generated="$tmp_dir/generated"

awk '
  length($1) != 64 ||
  $1 !~ /^[0-9a-f]+$/ ||
  NF != 2 ||
  $2 !~ /^src\// ||
  $2 ~ /(^|\/)\.\.(\/|$)/ { exit 1 }
  { print $2 }
' "$manifest" > "$paths" || die "malformed or unsafe manifest entry"

[ -s "$paths" ] || die "manifest contains no paths"
LC_ALL=C sort "$paths" > "$sorted_paths"
[ -z "$(uniq -d "$sorted_paths")" ] || die "duplicate manifest path"

while IFS= read -r path; do
  [ -f "$path" ] || die "missing or non-regular frozen path: $path"
  [ ! -L "$path" ] || die "symlink frozen path is prohibited: $path"
  git ls-files --error-unmatch -- "$path" >/dev/null 2>&1 ||
    die "untracked frozen path: $path"
done < "$sorted_paths"

: > "$changed_paths"
while read -r expected path; do
  actual="$(shasum -a 256 "$path" | awk '{ print $1 }')"
  if [ "$actual" != "$expected" ]; then
    printf '%s\n' "$path" >> "$changed_paths"
  fi
done < "$manifest"
LC_ALL=C sort -o "$changed_paths" "$changed_paths"

: > "$generated"
while IFS= read -r path; do
  shasum -a 256 "$path" >> "$generated"
done < "$sorted_paths"

case "${1:-}" in
  verify)
    [ "$#" -eq 1 ] || die "verify accepts no additional arguments"
    if ! cmp -s "$manifest" "$generated"; then
      printf 'FAIL  frozen manifest is stale or non-canonical\n' >&2
      diff -u "$manifest" "$generated" >&2 || true
      exit 1
    fi
    printf 'PASS  frozen manifest verified (%s pinned)\n' "$(wc -l < "$manifest" | tr -d ' ')"
    ;;

  regenerate)
    shift
    [ "$#" -gt 0 ] || die "regenerate requires at least one --allow PATH"
    : > "$allowed_paths"
    while [ "$#" -gt 0 ]; do
      [ "$1" = "--allow" ] || die "expected --allow, got: $1"
      [ "$#" -ge 2 ] || die "--allow requires a path"
      printf '%s\n' "$2" >> "$allowed_paths"
      shift 2
    done

    LC_ALL=C sort -o "$allowed_paths" "$allowed_paths"
    [ -z "$(uniq -d "$allowed_paths")" ] || die "duplicate allowed path"
    while IFS= read -r path; do
      grep -Fqx "$path" "$sorted_paths" || die "allowed path is not frozen: $path"
    done < "$allowed_paths"

    if ! cmp -s "$allowed_paths" "$changed_paths"; then
      printf 'FAIL  allow-list does not exactly match changed frozen paths\n' >&2
      diff -u "$allowed_paths" "$changed_paths" >&2 || true
      exit 1
    fi

    replacement="$(mktemp "./.aegis-frozen.sha256.tmp.XXXXXX")"
    cp "$generated" "$replacement"
    chmod --reference="$manifest" "$replacement" 2>/dev/null || chmod 644 "$replacement"
    mv "$replacement" "$manifest"
    printf 'PASS  regenerated %s atomically (%s pinned)\n' "$manifest" "$(wc -l < "$manifest" | tr -d ' ')"
    ;;

  *)
    usage >&2
    exit 2
    ;;
esac
