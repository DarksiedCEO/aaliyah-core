#!/usr/bin/env bash
# run-suite.sh <label> <pristine|used> [--root DIR] [-- test files...]
#
# The R1 measurement driver. One suite run, serial, against the builder's own
# PostgreSQL 16 container (aaliyah-w13-r1, 127.0.0.1:54610). Written for R1 so
# every run in the R1 record was produced the same way and says so.
#
#   pristine  every non-template database except `postgres` is DROPPED WITH
#             (FORCE), then `aaliyah_test` is CREATED, before the run.
#   used      the cluster is left exactly as the previous run left it.
#
# Before and after each run it records a cluster fingerprint: databases, live
# backends, load average, git HEAD, `git status --porcelain`, the count of
# `git ls-files -v` entries with an assume-unchanged/skip-worktree bit, and the
# worktree list. It refuses to start if another watchdog is already running on
# this host (quiet host is load-bearing: see the R1 work order).
#
# Output lands OUTSIDE the repository, in $OUT (default ~/aaliyah-w13-r1-runs),
# so a run's own artifacts can never make the next run's tree dirty. They are
# copied into aaliyah-w13-evidence/r1/runs/ at commit checkpoints.
set -uo pipefail
LABEL=$1; MODE=$2; shift 2
ROOT=/Users/andrelove/aaliyah-w13/aaliyah-wave1-core
if [ "${1:-}" = "--root" ]; then ROOT=$2; shift 2; fi
if [ "${1:-}" = "--" ]; then shift; fi
OUT=${OUT:-/Users/andrelove/aaliyah-w13-r1-runs}
CONTAINER=aaliyah-w13-r1
ADMIN=postgres://postgres:test@127.0.0.1:54610/postgres
export AALIYAH_TEST_DATABASE_URL=postgres://postgres:test@127.0.0.1:54610/aaliyah_test
mkdir -p "$OUT"
test ! -e "$OUT/$LABEL.json" || { echo "refusing: $OUT/$LABEL.json exists" >&2; exit 2; }
case "$MODE" in pristine|used) ;; *) echo "mode must be pristine|used" >&2; exit 2;; esac

if pgrep -f 'scripts/test-watchdog.mjs' >/dev/null; then
  echo "refusing: another test-watchdog is running on this host:" >&2
  pgrep -fl 'scripts/test-watchdog.mjs' >&2
  exit 2
fi

fingerprint() {
  echo "time        $(date -u +%FT%TZ)"
  echo "load        $(sysctl -n vm.loadavg)"
  echo "head        $(git -C "$ROOT" rev-parse HEAD)"
  echo "porcelain   $(git -C "$ROOT" status --porcelain | wc -l | tr -d ' ') lines"
  echo "lsfiles-v   $(git -C "$ROOT" ls-files -v | grep -cE '^[a-z]') flagged"
  echo "databases   $(psql "$ADMIN" -Atc "select string_agg(datname, ',' order by datname) from pg_database")"
  echo "backends    $(psql "$ADMIN" -Atc "select count(*) from pg_stat_activity where backend_type='client backend' and pid <> pg_backend_pid()")"
  echo "watchdogs   $(pgrep -f 'scripts/test-watchdog.mjs' | wc -l | tr -d ' ')"
  echo "worktrees:"
  git -C "$ROOT" worktree list | sed 's/^/  /'
}

{
  echo "label       $LABEL"
  echo "mode        $MODE"
  echo "root        $ROOT"
  echo "files       ${*:-FULL_SUITE}"
  echo "--- before (pre-reset)"
  fingerprint
} >"$OUT/$LABEL.fingerprint.txt"

if [ "$MODE" = pristine ]; then
  for db in $(psql "$ADMIN" -Atc "select datname from pg_database where not datistemplate and datname <> 'postgres'"); do
    psql "$ADMIN" -qAtc "DROP DATABASE \"$db\" WITH (FORCE)" || { echo "drop $db failed" >&2; exit 2; }
  done
  psql "$ADMIN" -qAtc "CREATE DATABASE aaliyah_test" || { echo "create failed" >&2; exit 2; }
  { echo "--- after pristine reset"; fingerprint; } >>"$OUT/$LABEL.fingerprint.txt"
fi

PGSTART=$(date -u +%FT%TZ)
( cd "$ROOT" && node scripts/test-watchdog.mjs --evidence "$OUT/$LABEL.json" "$@" ) >"$OUT/$LABEL.out.txt" 2>&1
CODE=$?
docker logs --since "$PGSTART" "$CONTAINER" >"$OUT/$LABEL.pglog.txt" 2>&1
{ echo "--- after run (exit $CODE)"; fingerprint; } >>"$OUT/$LABEL.fingerprint.txt"

VERDICT=$(grep -E '^WATCHDOG VERDICT:' "$OUT/$LABEL.out.txt" | tail -1)
printf '%s\t%s\t%s\t%s\t%s\n' "$LABEL" "$MODE" "$(git -C "$ROOT" rev-parse --short HEAD)" "$CODE" "${VERDICT:-NO VERDICT LINE}" >>"$OUT/INDEX.tsv"
echo "$LABEL [$MODE] exit=$CODE :: ${VERDICT:-NO VERDICT LINE}"
grep -E '^  reason:' "$OUT/$LABEL.out.txt" | cut -c1-400
exit $CODE
