#!/usr/bin/env bash
# kill-mid-run.sh <label> <seconds> [--root DIR]
#
# I-9 under gate 5's actual condition: a database left by a KILLED run.
# Recreates the database (pristine), starts a FULL_SUITE watchdog, SIGTERMs it
# after <seconds>, waits for it to exit, and records what it left behind: the
# cluster's databases, live backends, any surviving test processes, and the
# row counts of the target database's memory_% tables and migration ledger.
# The NEXT run-suite.sh invocation in `used` mode is then the measurement.
set -uo pipefail
LABEL=$1; SECS=$2; shift 2
ROOT=/Users/andrelove/aaliyah-w13/aaliyah-wave1-core
if [ "${1:-}" = "--root" ]; then ROOT=$2; shift 2; fi
OUT=${OUT:-/Users/andrelove/aaliyah-w13-r1-runs}
ADMIN=postgres://postgres:test@127.0.0.1:54610/postgres
DB=postgres://postgres:test@127.0.0.1:54610/aaliyah_test
export AALIYAH_TEST_DATABASE_URL=$DB
if pgrep -f 'scripts/test-watchdog.mjs' >/dev/null; then echo "refusing: a watchdog is running" >&2; exit 2; fi
for db in $(psql "$ADMIN" -Atc "select datname from pg_database where not datistemplate and datname <> 'postgres'"); do
  psql "$ADMIN" -qAtc "DROP DATABASE \"$db\" WITH (FORCE)"
done
psql "$ADMIN" -qAtc "CREATE DATABASE aaliyah_test"
( cd "$ROOT" && exec node scripts/test-watchdog.mjs --evidence "$OUT/$LABEL.json" ) >"$OUT/$LABEL.out.txt" 2>&1 &
PID=$!
sleep "$SECS"
kill -TERM "$PID"
wait "$PID"; CODE=$?
sleep 2
{
  echo "label       $LABEL"
  echo "killed at   ${SECS}s with SIGTERM; watchdog exit $CODE"
  echo "verdict     $(grep -E '^WATCHDOG VERDICT:' "$OUT/$LABEL.out.txt" | tail -1)"
  echo "survivors   $(pgrep -f "$ROOT/tests/|ts-node/register" | wc -l | tr -d ' ') test processes"
  echo "databases   $(psql "$ADMIN" -Atc "select string_agg(datname, ',' order by datname) from pg_database")"
  echo "backends    $(psql "$ADMIN" -Atc "select count(*) from pg_stat_activity where backend_type='client backend' and pid <> pg_backend_pid()")"
  echo "ledger      $(psql "$DB" -Atc "select count(*) from aaliyah_mail_migrations" 2>&1 | head -1)"
  echo "memory rows:"
  psql "$DB" -Atc "select string_agg(format('%s=%s', relname, n_live_tup), ' ' order by relname) from pg_stat_user_tables where relname like 'memory\_%'" 2>&1 | fold -w 160 | sed 's/^/  /'
} >"$OUT/$LABEL.left-behind.txt"
printf '%s\tkilled@%ss\t%s\t%s\t%s\n' "$LABEL" "$SECS" "$(git -C "$ROOT" rev-parse --short HEAD)" "$CODE" "$(grep -E '^WATCHDOG VERDICT:' "$OUT/$LABEL.out.txt" | tail -1)" >>"$OUT/INDEX.tsv"
cat "$OUT/$LABEL.left-behind.txt"
