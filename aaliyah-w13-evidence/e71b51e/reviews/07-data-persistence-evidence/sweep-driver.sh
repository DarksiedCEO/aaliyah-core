#!/bin/bash
# usage: sweep.sh <objects-json> <out-tsv> <bundle-name>
set -u
ROOT=/Users/andrelove/aaliyah-w13-rv5-data/aaliyah-wave1-core
export AALIYAH_TEST_DATABASE_URL='postgres://postgres:test@127.0.0.1:54606/aaliyah_test'
PGURL="$AALIYAH_TEST_DATABASE_URL"
OBJ="$1"; OUT="$2"; BUNDLE="$3"
case "$BUNDLE" in
  fast) FILES="tests/wave1MemoryConstraintDestroyersPostgres.integration.test.ts tests/wave1MemoryDigestOraclePostgres.integration.test.ts";;
  mid)  FILES="tests/wave1MemoryConstraintDestroyersPostgres.integration.test.ts tests/wave1TrustedMemoryPostgres.integration.test.ts tests/wave1MemoryIdentityPostgres.integration.test.ts tests/wave1MemoryReconciliationPostgres.integration.test.ts tests/wave1MemoryDigestOraclePostgres.integration.test.ts tests/wave1MemoryReachabilityPostgres.integration.test.ts tests/wave1AliasRegistryPostgres.integration.test.ts";;
  full) FILES="tests/wave1MemoryConstraintDestroyersPostgres.integration.test.ts tests/wave1TrustedMemoryPostgres.integration.test.ts tests/wave1MemoryHoldErasurePostgres.integration.test.ts tests/wave1MemoryIdentityPostgres.integration.test.ts tests/wave1MemoryReconciliationPostgres.integration.test.ts tests/wave1MemoryUpgradePostgres.integration.test.ts tests/wave1MemoryDigestOraclePostgres.integration.test.ts tests/wave1MemoryReachabilityPostgres.integration.test.ts tests/wave1AliasRegistryPostgres.integration.test.ts";;
esac
cd "$ROOT" || exit 1
N=$(node -e "console.log(require('$OBJ').length)")
for ((i=0;i<N;i++)); do
  read -r KIND TBL NAME <<< "$(node -e "const o=require('$OBJ')[$i];console.log(o.kind,o.tbl,o.name)")"
  if [ "$KIND" = "check" ]; then
    DROP="ALTER TABLE $TBL DROP CONSTRAINT $NAME;"
  else
    DROP="DROP TRIGGER $NAME ON $TBL;"
  fi
  psql "$PGURL" -q -v ON_ERROR_STOP=1 -c "$DROP" >/dev/null 2>&1 || { echo -e "$KIND\t$TBL\t$NAME\tDROP_FAILED" >> "$OUT"; continue; }
  V=$(node scripts/test-watchdog.mjs --deadline-ms 90000 --test-timeout-ms 25000 --exit-grace-ms 5000 $FILES 2>&1 | grep 'WATCHDOG VERDICT' | head -1)
  # restore
  if [ "$KIND" = "check" ]; then
    DEF=$(node -e "const o=require('$OBJ')[$i];process.stdout.write(o.def)")
    psql "$PGURL" -q -v ON_ERROR_STOP=1 -c "ALTER TABLE $TBL ADD CONSTRAINT $NAME $DEF;" >/dev/null 2>&1 && R=RESTORED || R=RESTORE_FAILED
  else
    DEF=$(node -e "const o=require('$OBJ')[$i];process.stdout.write(o.def)")
    psql "$PGURL" -q -v ON_ERROR_STOP=1 -c "$DEF;" >/dev/null 2>&1 && R=RESTORED || R=RESTORE_FAILED
  fi
  case "$V" in *PASS*) K=SURVIVED;; *) K=KILLED;; esac
  echo -e "$KIND\t$TBL\t$NAME\t$K\t$R\t$V" >> "$OUT"
  echo "[$((i+1))/$N] $NAME -> $K / $R"
done
