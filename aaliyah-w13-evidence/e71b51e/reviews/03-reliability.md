# GATE 3 — RELIABILITY — W1.3 candidate-4
subject: e71b51e9ed333d1feab1cd6819496269d201a6e2 · contracts 7d576681 · blocking: TRUE
verdict: BLOCK  (full detail at the end of this file)

reviewer environment: /Users/andrelove/aaliyah-w13-rv5-rel/aaliyah-wave1-core
database: postgres://postgres:test@127.0.0.1:54603/aaliyah_test
started: 2026-09-20

## Subject verified (not trusted)

| claim | verified | how |
|---|---|---|
| HEAD == e71b51e9ed333d1feab1cd6819496269d201a6e2 | YES | `git -C $ROOT/aaliyah-wave1-core rev-parse HEAD` -> `e71b51e9ed333d1feab1cd6819496269d201a6e2` |
| contracts == 7d576681d1001eb4c4a7f044f7793cdb3f80af76 | YES | `git -C $ROOT/aaliyah-wave1-contracts rev-parse HEAD` -> `7d576681d1001eb4c4a7f044f7793cdb3f80af76` |
| worktree clean BEFORE | YES | `git status --porcelain` -> empty |
| worktree clean AFTER | YES | `git status --porcelain` empty; `migrations.ts` and `pool.ts` sha256 byte-identical to pre-mutation — see "Subject re-verified AFTER all work" |
| database identity | PostgreSQL 16.14, db `aaliyah_test`, user `postgres`, port 54603, 0 tables in `public` at start (clean) | `select version()`, `select count(*) from pg_tables where schemaname='public'` -> 0 |
| claimed suite 1088/1088 fail 0 | **NOT REPRODUCIBLE HERE — 1 PASS in 5 runs** | see R-13; runs 2 PASS 1088/1088, runs 3/4/5 FAIL, run 1 FAIL (environment) |
| guards 8/8 | VERIFIED 8/8 | `bash scripts/ci-guards.sh` -> `RELEASE GUARDS: PASS`, full output near the end of this file |

## Work log / findings

---

## R-01 · Info (CONFIRMS the fix) — the migrator race reproduces on demand, and the restored advisory lock stops it dead

**What I executed.** The defect of the round could not be staged by the builder
("six concurrent migrators over eight fresh databases: 0 crashes in 48"). I reproduced
it, at will, by racing the EXACT ledger statement the migrator issues
(`src/persistence/postgres/migrations.ts:6172-6177`) from 16 sessions over a fresh
database, repeating the round after a `DROP TABLE`, with a small RANDOM START JITTER.
Jitter is what the builder was missing: with every session firing in the same tick,
every loser blocks on the winner's uncommitted speculative insertion and gets `23505`
and only `23505`. `42710` needs a loser whose `pg_class` check lands BEFORE the winner's
commit and whose `pg_type` check lands AFTER — a window a few milliseconds of stagger
opens reliably.

Harness (reviewer scratch, deleted at end): `.rel-ledger-race2.ts`, argv
`url n rounds jitterMs useLock`.

    $ node --require ts-node/register/transpile-only .rel-ledger-race2.ts \
        "postgres://postgres:test@127.0.0.1:54603/relledger" 16 150 0 0
    {"n":16,"rounds":150,"jitterMs":0,"useLock":false,"creates":2400,"losers":2250,
     "hist":{"23505|pg_type_typname_nsp_index":2250}}
    ... jitterMs 1 -> {"creates":2400,"losers":2250,"hist":{"23505|pg_type_typname_nsp_index":2250}}
    ... jitterMs 2 -> {"creates":2400,"losers":2250,
         "hist":{"23505|pg_type_typname_nsp_index":2244,
                 "42710|type \"aaliyah_mail_migrations\" already exists":6}}
    ... jitterMs 5 -> {"creates":2400,"losers":1900,
         "hist":{"23505|pg_type_typname_nsp_index":1870,
                 "42710|type \"aaliyah_mail_migrations\" already exists":30}}
    ... jitterMs 10 -> {"creates":3200,"losers":971,
         "hist":{"23505|pg_type_typname_nsp_index":928,
                 "42710|type \"aaliyah_mail_migrations\" already exists":40,
                 "42P07|relation \"aaliyah_mail_migrations\" already exists":3}}
    ... jitterMs 20 -> {"creates":3200,"losers":2722,
         "hist":{"23505|...":2700,"42710|type ... already exists":22}}
    ... jitterMs 50 -> {"creates":3200,"losers":1422,
         "hist":{"23505|...":1394,"42710|...":27,"42P07|relation ... already exists":1}}

**The 42710 of candidate-3 is REAL and I hold it in my hand**: `type
"aaliyah_mail_migrations" already exists`, 125 occurrences.

**The advisory lock's positive control**, same harness, `useLock=1`, i.e. each session
takes `pg_advisory_lock(hashtextextended('aaliyah_mail_migrations',0))` exactly as
`migrations.ts:6278` does:

    ... 16 x 200, jitter 0  -> {"creates":3200,"losers":0,"hist":{}}
    ... 16 x 200, jitter 5  -> {"creates":3200,"losers":0,"hist":{}}
    ... 16 x 200, jitter 20 -> {"creates":3200,"losers":0,"hist":{}}

**Denominator.** Unlocked: 21,600 raced `CREATE TABLE IF NOT EXISTS` statements over 9
configurations, 15,965 losers. Locked: 9,600 raced statements, 0 losers.
The lock is not decorative: it is the difference between 15,965 lost races and none.

**The tolerated enumeration is empirically complete over this denominator.** Every one
of the 15,965 losers carried one of exactly three SQLSTATEs —
23505 (15,836, always `pg_type_typname_nsp_index`), 42710 (125), 42P07 (4) — which is
exactly `LEDGER_RACE_LOST` at `migrations.ts:6128`. No fourth code appeared.
This is evidence over 15,965 samples on PostgreSQL 16.14, NOT a proof of completeness;
a different server version or a concurrent DDL of a different shape could still produce
a fourth.

---

## R-02 · Info (CONFIRMS the fix, and is the proof K-06b cannot give) — the 42710 tolerance is load-bearing against REAL server errors

K-06b (`tests/wave1MigrationReplayPostgres.integration.test.ts:195`) exercises
`createLedgerToleratingARace` with a HAND-WRITTEN `bounded` that throws a JS object
carrying `code`. That proves the `Set` membership check, not that PostgreSQL 16 ever
raises those codes here. I re-ran the destroyer against the REAL function with REAL
raced errors on a real database: 16 live sessions each calling the exported
`createLedgerToleratingARace(boundedQuery(client, 30_000))` with random start jitter,
200 rounds per configuration, table dropped between rounds, and an assertion after each
round that the ledger really is present.

Harness: `.rel-tolerance-live.ts` (argv `url n rounds jitterMs cand|old`).
`cand` imports the candidate; `old` imports a copy whose only difference is
`LEDGER_RACE_LOST = new Set(["42P07","23505"])` — i.e. the `97bb476` set, verified against
`git show 97bb476:src/persistence/postgres/migrations.ts:5903`.

    CANDIDATE (42710 tolerated)
    {"which":"cand","n":16,"rounds":200,"jitterMs":2, "calls":3200,"rejected":0,"hist":{}}
    {"which":"cand","n":16,"rounds":200,"jitterMs":5, "calls":3200,"rejected":0,"hist":{}}
    {"which":"cand","n":16,"rounds":200,"jitterMs":10,"calls":3200,"rejected":0,"hist":{}}
    {"which":"cand","n":16,"rounds":200,"jitterMs":10,"calls":3200,"rejected":0,"hist":{}}
    {"which":"cand","n":16,"rounds":200,"jitterMs":10,"calls":3200,"rejected":0,"hist":{}}
    {"which":"cand","n":16,"rounds":200,"jitterMs":20,"calls":3200,"rejected":0,"hist":{}}
    {"which":"cand","n":16,"rounds":200,"jitterMs":20,"calls":3200,"rejected":0,"hist":{}}

    DESTROYER — 42710 removed from the tolerated set (the 97bb476 build)
    {"which":"old","n":16,"rounds":200,"jitterMs":2, "calls":3200,"rejected":0,"hist":{}}
    {"which":"old","n":16,"rounds":200,"jitterMs":5, "calls":3200,"rejected":0,"hist":{}}
    {"which":"old","n":16,"rounds":200,"jitterMs":10,"calls":3200,"rejected":26,
      "hist":{"42710|type \"aaliyah_mail_migrations\" already exists":26}}
    {"which":"old","n":16,"rounds":200,"jitterMs":10,"calls":3200,"rejected":57,
      "hist":{"42710|type \"aaliyah_mail_migrations\" already exists":57}}
    {"which":"old","n":16,"rounds":200,"jitterMs":20,"calls":3200,"rejected":41,
      "hist":{"42710|type \"aaliyah_mail_migrations\" already exists":41}}

**Denominator:** candidate 22,400 live raced calls, 0 rejections, `LEDGER_MISSING_AFTER_
ROUND` never fired. 97bb476-equivalent: 16,000 calls, 124 rejections, every one the exact
candidate-3 crash string. The register's account of the defect is TRUE, and the fix is
load-bearing under real load, not only under a mock.

---

## R-03 · Low — the tolerance's "confirm the ledger is really there" re-check is weaker than its comment claims, but the runner still fails CLOSED

`migrations.ts:6189-6194` says the presence re-check exists so that "a duplicate-object
error from something that is NOT this table would otherwise be swallowed here". The check
is `SELECT to_regclass('public.aaliyah_mail_migrations') IS NOT NULL`. `to_regclass`
answers for ANY relation of that name — including a composite TYPE's `pg_class` row
(`relkind 'c'`) and a table of an entirely different shape. It does not confirm the object
is a TABLE, nor that it has `id`/`applied_at`.

I attacked both squats directly:

    $ psql -d reltype -c "CREATE TYPE aaliyah_mail_migrations AS (bogus int);"
    $ psql -d reltype -c "SELECT to_regclass('public.aaliyah_mail_migrations') IS NOT NULL;"
     t                                        <-- the guard would say "present"
    $ psql -d reltype -c "CREATE TABLE IF NOT EXISTS aaliyah_mail_migrations (...)"
    NOTICE:  relation "aaliyah_mail_migrations" already exists, skipping
    CREATE TABLE                              <-- no error at all; nothing created

    $ node --require ts-node/register/transpile-only .rel-one.ts ".../reltype"
    {"result":"THREW","code":"42809","message":"cannot lock relation \"aaliyah_mail_migrations\""}

    # wrong-shape squatter
    $ psql -d relshape -c "CREATE TABLE aaliyah_mail_migrations (id int PRIMARY KEY, note text)"
    $ node --require ts-node/register/transpile-only .rel-one.ts ".../relshape"
    {"result":"THREW","code":"22P02",
     "message":"invalid input syntax for type integer: \"001_mail_oauth_states\""}
    $ psql -d relshape -c "select count(*) from aaliyah_mail_migrations"   ->  0
    $ psql -d relshape -c "select count(*) from pg_tables where schemaname='public'" -> 1

**Verdict on the dispatch's four questions.**
- *partially created ledger*: not reachable — `CREATE TABLE` is transactional in
  PostgreSQL, so `to_regclass` non-NULL implies a fully committed relation.
- *a different table with the same name*: the guard DOES pass, but the run then aborts at
  the first real use, the transaction rolls back (0 ledger rows, no migration objects
  created). FAIL-CLOSED, with a poor message.
- *a concurrent DROP between the error and the re-check*: the re-check returns false and
  the original error is rethrown — K-06b's `absent` case, and the code at
  `migrations.ts:6193` is the path.
- *is the tolerance too broad*: the `try` contains exactly one statement (the ledger
  `CREATE`), so the blast radius of swallowing is one statement, and a non-race SQLSTATE
  (42501) still propagates — I re-ran K-06b's negative control and it holds.

**Severity Low, NOT blocking.** No silent success was produced in any attack. The finding
is that the comment overstates the guard: it claims to discriminate "not this table", and
it only discriminates "no relation of this name". A `to_regclass(...)::regclass` +
`relkind = 'r'` check, or a column check, would make the comment true.
**Falsifier:** show a `to_regclass`-passing squat that makes `runMailMigrations` return
successfully. I could not construct one.

---

## R-04 · Medium — the migrator's PATIENCE (120s) is shorter than the work it waits for (300s per statement, unbounded in aggregate): a rolling deploy over a slow migration CRASHES every second instance at boot

**The claim under test.** `migrations.ts:6203-6208`: "A second instance booting during a
rolling deploy legitimately waits here for the first one's migrations; DDL over populated
tables legitimately takes longer than an ordinary statement. Neither is allowed to wait
forever."

**What I executed.** `lock_timeout` DOES bound `pg_advisory_lock` — I verified the
primitive first, because the code's ordering depends on it:

    $ psql -d rellt -c "SET lock_timeout='2000ms'; SELECT pg_advisory_lock(hashtextextended('aaliyah_mail_migrations',0));"
    SET
    ERROR:  canceling statement due to lock timeout

`runMailMigrations` issues `SET lock_timeout = '120000ms'` (`migrations.ts:6213`) BEFORE
`SELECT pg_advisory_lock(...)` (`migrations.ts:6278`). So the advisory wait is capped at
`MIGRATION_BOUNDS.lockTimeoutMs`. Measured in-process against a real holder:

    # holder: SELECT pg_advisory_lock(hashtextextended('aaliyah_mail_migrations',0)); SELECT pg_sleep(400);
    $ node --require ts-node/register/transpile-only .rel-timed.ts ".../rellt3"
    {"result":"THREW","code":"55P03","message":"canceling statement due to lock timeout",
     "elapsedMs":120020}

120,020 ms — exactly `MIGRATION_BOUNDS.lockTimeoutMs` (`pool.ts:67-72`).

**Why that is a defect and not just a bound.** The same constants block permits the
migration being waited on to run far longer: `statementTimeoutMs: 300_000` per statement,
`queryTimeoutMs: 330_000` client ceiling, and SIXTY statements with no aggregate bound.
The waiter's patience (120s) is 2.5x SHORTER than one permitted statement. And
`src/server.ts:78` calls `await runMailMigrations(pool)` OUTSIDE any try — a rejection
propagates to `main().catch` at `src/server.ts:240-244` and `process.exit(1)`.

So on the exact scenario the comment names — a rolling deploy where instance A is applying
DDL over populated tables — instance B crash-loops at boot after two minutes with
`canceling statement due to lock timeout`, for as long as A's migration runs. That is
fail-CLOSED (no corruption) but it is an availability defect, and the code's own comment
claims the case is handled.

**What assertion should have caught it and did not.** Nothing in the suite compares
`MIGRATION_BOUNDS.lockTimeoutMs` with `MIGRATION_BOUNDS.statementTimeoutMs`. The only
`MIGRATION_BOUNDS` references in tests are
`tests/wave1MigrationReplayPostgres.integration.test.ts:149` and `:396`, both
GUC-hygiene assertions that the raised `lock_timeout` is RESET, not that its value is
coherent. Contrast `tests/wave1PoolResiliencePostgres.integration.test.ts:431-435`, which
DOES assert `queryTimeoutMs > statementTimeoutMs` for the pool bounds — the analogous
invariant for the migration bounds (`lockTimeoutMs >= statementTimeoutMs`, or an
aggregate run bound) is simply absent.

**Falsifier.** Show that a migration run cannot exceed 120s, or show a test that fails
when `MIGRATION_BOUNDS.lockTimeoutMs` is set below `statementTimeoutMs`.
**Blocking: NO** (Medium; fail-closed, availability only, and pre-existing — before
`c2e5747` the same 120s bound applied to the `LOCK TABLE` wait instead).

---

## R-05 · Info (CONFIRMS) — crash mid-migration: no torn state, no leaked lock, clean recovery

Backends terminated mid-DDL with `pg_terminate_backend`, migrator built exactly as
`server.ts` builds it (`createMailDbPool`, so `guardPoolErrors` is attached). Harness
`.rel-kill.ts`. `ledgerRowsBeforeRerun` is read before any recovery attempt:

    kill@ALTER TABLE  -> {"result":"THREW","code":"57P01","killedQuery":"ALTER TABLE service_identities ADD COLUMN IF NOT EXISTS workspace_ids ...",
                          "poolIdleAfter":0,"poolTotalAfter":0,"advisoryLocksLeft":0,
                          "ledgerRowsBeforeRerun":0,"rerun":"OK","ledgerRows":60}
    kill@CREATE INDEX -> {"result":"THREW","code":"57P01","killedQuery":"CREATE INDEX IF NOT EXISTS idx_mail_connections_scope ...",
                          "poolIdleAfter":0,"poolTotalAfter":0,"advisoryLocksLeft":0,
                          "ledgerRowsBeforeRerun":0,"rerun":"OK","ledgerRows":60}
    kill@CREATE TABLE -> {"result":"THREW","code":"57P01","killedQuery":"CREATE TABLE IF NOT EXISTS aaliyah_mail_migrations ...",
                          "poolIdleAfter":0,"poolTotalAfter":0,"advisoryLocksLeft":0,
                          "ledgerRowsBeforeRerun":"ERR 42P01","rerun":"OK","ledgerRows":60}
    kill@GRANT/DO$do$ -> THREW 57P01, advisoryLocksLeft 0, rerun OK

Every surface: the transaction rolled back whole (0 ledger rows — never a ledger row for
a migration whose DDL was undone), the ambiguous client was DESTROYED not pooled
(`poolIdleAfter 0`, `poolTotalAfter 0`, which is `releaseClient`/`isConnectionAmbiguous`
at `pool.ts:201-228` doing its job on a real 57P01), no advisory lock left behind, and a
re-run completed all 60.

SIGKILL of the whole migrator PROCESS at 50/100/150/200/250ms into the run, 5 trials:
ledger absent or partial-free, and `rerun` returned `{"result":"OK"}` in all 5. A poll
taken IMMEDIATELY after `kill -9` still showed `advisory locks = 1` in that database —
the backend had not yet noticed the closed socket — but it always cleared before the
next migrator needed it. **Named as a window, not a defect:** a migrator process killed
on a host whose socket close is delayed (a network partition rather than a local kill)
would leave the ledger advisory lock held until the server reaps the backend, and the
next instance then burns its whole 120s patience (see R-04) before crashing. No
`tcp_keepalives_*` / `idle_session_timeout` is set on the migration connection.

---

## R-06 · Info — the POSITIVE CONTROL for `guardPoolErrors` fires, unprompted

My first kill harness used a bare `new Pool()` with only a POOL-level `'error'` listener
(no per-client listener). Killing the backend during `ALTER TABLE` killed the whole Node
process:

    Error: Connection terminated unexpectedly
        at Connection.<anonymous> (.../pg/lib/client.js:199:73)

Re-running the identical scenario through `createMailDbPool` (which attaches
`pool.on("connect", client => client.on("error", record))`, `pool.ts:296-299`) produced
the clean `{"result":"THREW","code":"57P01",...}` rows in R-05. That is exactly the
failure `pool.ts:276-291` documents, reproduced accidentally and then closed by the
control. The control is real.

---

## R-07 · Important (ENVIRONMENT-ATTRIBUTED, but it is a real fail-mode of the SUITE) — under co-tenant load the shared memory-table lock times out and FOUR files die in `before`, producing 315 failures and a THIRD suite denominator

**Baseline attempt 1**, watchdog defaults (trap 4 respected: no mutant-judging bound),
`AALIYAH_TEST_DATABASE_URL` the only exported variable (trap 1):

    $ AALIYAH_TEST_DATABASE_URL="postgres://postgres:test@127.0.0.1:54603/aaliyah_test" npm test
    WATCHDOG VERDICT: FAIL scope=FULL_SUITE tests=1091 pass=776 fail=315 cancelled=0 skipped=0 todo=0
      reason: NONZERO_EXIT: code=1 signal=null
      reason: FAILED_TESTS: 315
      reason: PASSED_NOT_EQUAL_TESTS: 776 of 1091
      reason: RUNNER_REPORTED_UNSUCCESSFUL
      reason: FILES_WITHOUT_TESTS: tests/wave1ExecutiveHttpReachabilityPostgres.integration.test.ts,
        tests/wave1MemoryDigestOraclePostgres.integration.test.ts,
        tests/wave1MemoryReconciliationPostgres.integration.test.ts,
        tests/wave1TrustedMemoryPostgres.integration.test.ts

Root cause, from the log, NOT guessed:

    Error: shared memory-table lock not acquired within 200000ms: canceling statement due to statement timeout
    Error: shared memory-table lock not acquired within 200000ms: Query read timeout
    ✔ the privilege map of every memory role equals the declared map, section by section (223829.427708ms)
    ✖ a blocked advisory lock is refused by lock_timeout and is FAIL (184314.037584ms)

The machine is shared with five other reviewer environments
(`docker ps` shows `aaliyah-w13-rv5-{test,sec,rel,red,int,data}` on ports 54601-54606) and
`uptime` reported **load averages: 25.30 19.75 17.60** with another root running a
full-suite watchdog. Files that normally take ~45s took 180-224s. Once one file exceeds
`SHARED_TABLE_LOCK_WAIT_MS = 200_000` (`tests/support/sharedMemoryTables.ts:39`), the next
file's `before` hook is refused, its `after` hook then throws
`TypeError: Cannot read properties of undefined (reading 'end')`, and the whole file's
tests are counted failed.

**I am attributing this to the environment, not to the candidate** — the failure is a
timeout on a fixture-serialisation lock, the named refusal message is emitted correctly,
and the privileges file (the G-05 subject) PASSED every test. But three things are worth
recording for AEGIS:

1. The DENOMINATOR moved again: **tests=1091** here, against `1086`, `1087` and the
   claimed `1088` recorded elsewhere. The count is inflated by `hookSentinel.cjs` wrapper
   tests on failing files, which is a benign explanation — but it means the suite's test
   COUNT is not a stable identity of the executed set when files fail, which is exactly
   the property review-subject #2 of the dispatch protocol depends on.
2. `SHARED_TABLE_LOCK_WAIT_MS` (200s) sits below the watchdog's per-file
   `testTimeoutMs` (240s) on purpose, but ABOVE nothing: there is no bound relating it to
   how long a file may legitimately hold it. One slow file therefore cascades into the
   failure of every file behind it. Under load that is a suite-wide single point of
   failure.
3. One refusal arrived as `Query read timeout` — the CLIENT ceiling
   (`SHARED_TABLE_LOCK_WAIT_MS + 20_000`, `sharedMemoryTables.ts:57`), not the server's
   200s `lock_timeout`. A backend starved enough not to fire its own timer within 20s of
   slack is the K-05 shape, and `lockSharedMemoryTables` handles it correctly
   (`client.release(true)`), so this is an observation, not a defect.

**Blocking: NO by itself** — but it means I could not obtain a clean green baseline on
this box, and that is recorded honestly rather than rounded up. Attempts 2+ below.

---

## R-08 · Info (CLOSES the mutation gate's named gap) — pool.ts's K-05 ambiguous-connection guard IS covered; I mutated it and it dies

`06-mutation-fuzz.md` records, under "What I did NOT cover": *"Did not mutate `pool.ts`'s
K-05 ambiguous-connection-destruction guard itself (only observed it pass in the baseline
full-suite run)."* I mutated it. Each mutant was applied to the tracked file, judged by
the watchdog VERDICT (not by `failures[]` — trap 3), restored from a byte-copy, and
`shasum -a 256` + `git status --porcelain <file>` verified clean after every one.
Target file run with the watchdog's own DEFAULT bounds (trap 4 — this file legitimately
takes 70s and 35s in single tests).

| mutant | change | verdict | killed by |
|---|---|---|---|
| MUT-3 | `isConnectionAmbiguous` replaced by `return false` (the whole guard deleted) | **KILLED** FAIL 14/17 | `K-05: an AMBIGUOUS connection is DESTROYED...` (0.8ms), `a STORE that connects and releases by hand...` (70.0s), `a WEDGED transport is abandoned by the client...` (35.0s) |
| MUT-3a | only `/Query read timeout/i` removed from the classifier (the K-05 client-ceiling shape) | **KILLED** FAIL 14/17 | same three |
| MUT-4 | `releaseClient` never destroys — `client.release(undefined)` always (this is register mutant M-29) | **KILLED** FAIL 15/17 | `K-05: an AMBIGUOUS connection is DESTROYED...`, `a STORE that connects and releases by hand...` |

Restoration evidence, printed by the runner for every mutant:
`restored_ok=YES git=0`.

**So M-29's closure is REAL and independently executed**, and the standing rule
("a surviving mutant is closed by adding a detector... EXECUTED rather than argued") is
honoured for this one. This is the opposite of the `97bb476` migrator case.

---

## R-09 · Info (METHOD) — migrator control-deletion sweep: both restored controls have real detectors

| mutant | change | verdict | killed by |
|---|---|---|---|
| MUT-1 | delete `await bounded("SELECT pg_advisory_lock(...)")` at `migrations.ts:6278` — i.e. recreate `97bb476` | **KILLED** FAIL 17/18 in 6.1s | `K-06c: migrators SERIALIZE on the advisory lock before the ledger exists` with the NAMED message `AssertionError: no migrator ever waited on the ledger advisory lock — the runner is not taking it` (`tests/wave1MigrationReplayPostgres.integration.test.ts:324`) |
| MUT-2 | delete the `pg_advisory_unlock` from the `finally` at `migrations.ts:6447-6449` | **KILLED** FAIL 13/18 | `the migrator leaves NO session state on the connection it returns — success AND refusal`, `K-06 REOPENED: the real migrator survives a concurrent OLDER build on a FRESH database`, and the 2-/3-/5-way concurrent-migrator tests |

Both die with a NAMED assertion, in seconds, not as a HUNG_WORKER — which is the specific
failure the builder records having had to fix twice. Independently confirmed.

---

## R-10 · IMPORTANT · BLOCKING — three of the mail pool's reliability bounds can be weakened 10x-60x and the ENTIRE 1088-test suite still reports PASS: the only assertions that mention them compare each constant to ITSELF

**The defect in one sentence.** `connectionTimeoutMillis`, `idleInTransactionSessionTimeoutMs`
and `keepAliveInitialDelayMillis` in `src/persistence/postgres/pool.ts:16-60` are asserted
only against their own values, so the suite cannot tell a correct bound from a broken one.

**The self-referential assertions** (`tests/wave1PoolResiliencePostgres.integration.test.ts`):

    :155  assert.equal(await show("statement_timeout"), `${MAIL_DB_POOL_BOUNDS.statementTimeoutMs / 1000}s`);
    :156  assert.equal(await show("lock_timeout"),      `${MAIL_DB_POOL_BOUNDS.lockTimeoutMs / 1000}s`);
    :158  assert.equal(await show("idle_in_transaction_session_timeout"),
    :159                                                `${MAIL_DB_POOL_BOUNDS.idleInTransactionSessionTimeoutMs / 60_000}min`);
    :164  assert.equal(pool.options.connectionTimeoutMillis, MAIL_DB_POOL_BOUNDS.connectionTimeoutMillis);
    :165  assert.ok(MAIL_DB_POOL_BOUNDS.connectionTimeoutMillis > 0);
    :426  assert.equal(options.keepAliveInitialDelayMillis, MAIL_DB_POOL_BOUNDS.keepAliveInitialDelayMillis);

Both sides of every one of those come from the same constant. The comment above them —
"Read back from the SERVER, not from the config object: a bound that never reached the
session bounds nothing" — is true and is NOT the property that matters: it proves the
value ARRIVED, never that the value is RIGHT.

**Denominator, collected by grep over the whole `tests/` + `scripts/` tree:**
`idleInTransactionSessionTimeoutMs` appears in exactly ONE test line (`:159`);
`keepAliveInitialDelayMillis` in exactly ONE (`:426-427`);
`connectionTimeoutMillis` in exactly TWO (`:164`, `:165`), the second being `> 0`.
No other file in the repository asserts any of them.

**EXECUTED.** Individually against the pool-resilience file (watchdog DEFAULT bounds —
trap 4), then all three together against the FULL suite:

| mutant | change | file verdict | full-suite verdict |
|---|---|---|---|
| MUT-5 | `idleInTransactionSessionTimeoutMs: 60_000 -> 600_000` (1 min -> 10 min) | PASS 17/17 (see note) | — |
| MUT-6 | `keepAliveInitialDelayMillis: 10_000 -> 600_000` (10 s -> 10 min) | **PASS 17/17 — SURVIVED** | — |
| MUT-7 | `connectionTimeoutMillis: 10_000 -> 600_000` (10 s -> 10 min) | **PASS 17/17 — SURVIVED** | — |
| MUT-5+6+7 | all three at once | — | **`WATCHDOG VERDICT: PASS scope=FULL_SUITE tests=1088 pass=1088 fail=0 cancelled=0 skipped=0 todo=0`** |

Runner output for the decisive run:

    === MUT567FULL rc=0 restored_ok=YES git=0
    WATCHDOG VERDICT: PASS scope=FULL_SUITE tests=1088 pass=1088 fail=0 cancelled=0 skipped=0 todo=0
      evidence: .test-evidence/last-run.json

Note on MUT-5: its FIRST file-level run reported FAIL via `HUNG_WORKER` — `K-05: an
AMBIGUOUS connection is DESTROYED...` sat at exactly 240,001 ms. The re-run (`MUT5b`)
reported `PASS 17/17`, and the combined full-suite run passed with the same change, so I
record MUT-5 as **SURVIVED with one non-reproducing hang**, not as detected. A detector
that fires once in two runs and only as "something hung" names no property — the
builder's own standard, from `c2e5747`'s message.

**Why each is a real control, not a cosmetic number** — from `pool.ts`'s own comments:
- `connectionTimeoutMillis` exists because the b3efc82 reliability review found
  `store.create()` "pending past 8s with no error and no fallback, occupying a pool slot
  the whole time — and nothing bounded it" (`pool.ts:7-13`). At 10 minutes every caller
  queues for a pool slot for ten minutes under exhaustion: the finding, restored.
- `idleInTransactionSessionTimeoutMs` is what terminates "a session left idle inside an
  open transaction" (`pool.ts:24`) — at 10 minutes it holds its locks ten times longer.
- `keepAliveInitialDelayMillis` exists because "a dead peer that never sends a FIN is
  indistinguishable from a silent one" (`pool.ts:55-58`) — at 10 minutes the kernel asks
  after ten minutes.

**What assertion should have caught it and did not.** Any assertion with an INDEPENDENT
right-hand side: a literal, a ceiling relation (the file already does this correctly ONCE,
at `:431-435`, `queryTimeoutMs > statementTimeoutMs`), or a behavioural bound like the one
at `:184-185` — which is itself self-referential and so only proves the bound is whatever
the constant says.

**Falsifier.** Name a test in this repository that fails when
`MAIL_DB_POOL_BOUNDS.connectionTimeoutMillis` becomes 600_000. I executed the whole suite
with it at 600_000 and 1088 of 1088 passed.

**Blocking: YES.** Not because any value is wrong today — all three are correct at this
SHA — but because this is precisely the failure mode that produced the defect of the
round: `97bb476` deleted the migrator's advisory lock on the evidence that "deleting the
lock broke no test", and the register's own conclusion was *"'No test fails when I delete
this' is evidence about the tests before it is evidence about the code."* Three more
controls are in exactly that state, and the standing rule the protocol asks me to enforce
is that a control whose removal nothing detects is a finding regardless of current
correctness.

**Mutants that DID die**, so this is a specific gap and not a claim that the file is weak:
MUT-3, MUT-3a, MUT-4 (K-05 guard) and MUT-8 (the per-client `'error'` listener — killed by
`the mail pool SURVIVES a backend terminated while its client is CHECKED OUT in a
transaction` and `the idempotency store's pool SURVIVES...`). Every mutant restored:
`restored_ok=YES git=0`.

---

## R-11 · IMPORTANT · BLOCKING — the suite carries a LATENT FLAKE in the very file written to close the flake: a positive control asserts one SQLSTATE for a race this candidate's own register says has three

`tests/wave1MigrationReplayPostgres.integration.test.ts:765-790`,
"POSITIVE CONTROL: bare concurrent CREATE TABLE IF NOT EXISTS really does crash N-1 with
23505", ends:

    assert.ok(
      codes.every((code) => code === "23505"),
      `expected 23505 unique-violation losses; got ${JSON.stringify(codes)}`,
    );

But `LEDGER_RACE_LOST` at `src/persistence/postgres/migrations.ts:6128` is
`new Set(["42P07", "23505", "42710"])`, and the whole point of `c2e5747` is that a loser
of THIS EXACT RACE can carry `42710` or `42P07`. The control demands one of the three.

**EXECUTED.** I replicated the test body faithfully — three COLD pools (`new Pool`, then
one query each, so the connect handshake supplies the few milliseconds of natural stagger
the 42710 window needs), same tick, fresh database per trial — and ran it 360 times:

    $ node --require ts-node/register/transpile-only .rel-poscontrol.ts \
        "postgres://postgres:test@127.0.0.1:54603/aaliyah_test" 120
    {"trials":120,"hist":{"23505":239,"42710":1},"wouldFailNoLoser":0,"wouldFailNot23505":1}
    $ ... 240
    {"trials":240,"hist":{"23505":480},"wouldFailNoLoser":0,"wouldFailNot23505":0}

**1 trial in 360 produced `42710`** — `wouldFailNot23505: 1` is the harness computing the
test's own assertion over the codes it observed. On that run the suite would have gone red
on a CORRECT build, with the message `expected 23505 unique-violation losses; got
["42710"]`. The one hit came in the batch run while the box was busiest, which matches the
register's own "the window only opens under load".

Cross-reference to R-01: over 21,600 raced `CREATE TABLE IF NOT EXISTS` statements I
observed 15,836 x 23505, 125 x 42710 and 4 x 42P07. `42710` and `42P07` are not exotic;
they are 0.8% of losses at this server's timings and rise with stagger.

**What assertion should have caught it.** The test's own falsifier should have been
"at least one creator lost, and every loss is a code the runner TOLERATES" —
`codes.every((code) => LEDGER_RACE_LOST.has(code))` — which is the property the control
exists to demonstrate. Pinning `23505` pins an accident of scheduling.

**Falsifier for this finding.** Show that three same-tick cold-pool `CREATE TABLE IF NOT
EXISTS` statements on PostgreSQL 16.14 can only ever lose with 23505. I have a counter-example.

**Blocking: YES.** A false-failure source in the suite is exactly the class of defect this
round exists to remove: the migrator race was found BY a flake, and a suite that
manufactures its own flakes destroys the signal that found it. It is also, by the dispatch's
standing test, an assertion that is wrong about the code it guards.

---

## R-12 · Info (G-05 AUDIT — the mandate's item 4a) — every acquire/release of the shared advisory lock, audited; no comparison remains outside it

G-05's window was "the privileges suite released the shared advisory lock BEFORE its final
restoration comparison". I audited the whole population rather than the two sites the
register names.

**Population and inclusion rule.** Every reference to `lockSharedMemoryTables` /
`SharedTableLock` / the key `728_133_001` anywhere under `tests/`, collected with
`grep -rn "lockSharedMemoryTables\|SharedTableLock\|728_133_001\|728133001" tests/`.
**Result: 12 files, 16 acquisition sites.**

- **10 files acquire ONCE in `before` and release in `after`** (alias registry, constraint
  destroyers, digest oracle, executive HTTP reachability, memory identity, memory
  reachability, memory reconciliation, trusted memory, hold erasure). File-scoped: there
  is no "after the release" for a comparison to fall into.
- **`tests/wave1MemoryPrivilegesPostgres.integration.test.ts` — 5 per-test acquisitions**
  (`:55`, `:232`, `:265`, `:323`, `:377`). I read all five. Every one has the shape
  `const lock = await lockSharedMemoryTables(pool); try { ...all comparisons... } finally
  { await lock.release(); }`. The two trailing comparisons G-05 named are at `:250-254`
  (`const restored = await memoryPrivilegeMap(pool); for (...) assert.deepEqual(...)`) and
  `:356` (`await compareDeclaredMap()`), both INSIDE the try. `:379` and `:395` likewise.
  **No comparison, assertion or map read occurs after any `release()`.**
- **`tests/wave1PoolResiliencePostgres.integration.test.ts` — 2 per-test acquisitions**
  (`:244` boot-composition, `:309` K-10). K-10 is the other half of G-05: it REVOKEs two
  grants and restores them at `:404-405`, inside the `finally` that precedes
  `await sharedTableLock.release()` at `:406`. The restore therefore completes before the
  lock is dropped. Correct.
- **Two files touch privileges/DDL WITHOUT the lock**
  (`wave1MemoryUpgradePostgres`, `wave1MigrationReplayPostgres`) — both run on their OWN
  databases (`aaliyah_upgrade_test` at `:73-74`, `aaliyah_replay_test` and
  `withFreshDatabase` at `:32-34`/`:579-590`), so they cannot collide with the shared
  tables. Correctly excluded.

**One ordering nit, non-blocking:** at
`tests/wave1MemoryPrivilegesPostgres.integration.test.ts:377-380` the `GRANT` is issued
AFTER `lockSharedMemoryTables` but BEFORE the `try` whose `finally` releases it. If that
`GRANT` threw, the lock would be held until the file's `pool.end()` in `after`. The
consequence is a slower suite, not a wrong result, and the pool teardown does release it.

**Empirical side:** across the full-suite runs below, the privileges file passed every
test every time, including the run where it waited 223.8s for the lock. I saw no
recurrence of the G-05 signature (a diff naming exactly the two K-10 privileges); I
grepped every run's log for `widened`/`narrowed` diffs and found none.

---

## R-13 · IMPORTANT · BLOCKING — the claimed `1088/1088` is NOT reproducible here: 1 clean PASS in 5 full-suite runs, and `K-05` HANGS for its full 240s timeout roughly one run in four

**Every full-suite run I made, in order, on the unmutated tree at
`e71b51e9ed333d1feab1cd6819496269d201a6e2`, watchdog DEFAULT bounds, only
`AALIYAH_TEST_DATABASE_URL` exported:**

| # | verdict | counts | cause |
|---|---|---|---|
| 1 | **FAIL** | tests=1091 pass=776 fail=315 | shared memory-table lock timed out under co-tenant load (R-07) — environment |
| 2 | **PASS** | tests=1088 pass=1088 fail=0 | — |
| M | PASS | tests=1088 pass=1088 fail=0 | with MUT-5+6+7 applied to `pool.ts` (R-10) |
| 3 | **FAIL** | no summary | `HUNG_WORKER` / `TIMED_OUT: tests/wave1PoolResiliencePostgres.integration.test.ts :: K-05: an AMBIGUOUS connection is DESTROYED, and an ordinary error's connection is not` |
| 4 | **FAIL** | tests=1088 pass=1087 fail=1 | `POSITIVE CONTROL: bare concurrent CREATE TABLE IF NOT EXISTS really does crash N-1 with 23505` — `error: terminating connection due to administrator command` (R-14) |
| 5 | **FAIL** | tests=1088 pass=1087 fail=1 | identical to run 4 |

Load average was **25.30** during run 1 and **2.81-6.76** during runs 3-5, so runs 3-5
are NOT explainable as load. The count is stable at 1088 whenever a summary is produced.

### The K-05 hang, reproduced three times independently

| context | outcome |
|---|---|
| `MUT-5` first file-only run (mutated `pool.ts`) | `K-05 ... (240001.892542ms)` HUNG_WORKER |
| full-suite run 3 (CLEAN tree) | `TIMED_OUT ... K-05: an AMBIGUOUS connection is DESTROYED ...` |
| 2-file run `replay + poolResilience`, attempt 3 of 3 (CLEAN tree) | `✖ K-05 ... (240004.01075ms)` |

Isolation runs, all with the watchdog's own defaults:

    replay alone            x3 -> PASS 18/18, PASS 18/18, PASS 18/18
    replay + poolResilience x3 -> PASS 35/35, PASS 35/35, FAIL (K-05 hung 240004ms)

So it needs `wave1PoolResiliencePostgres` and it does not need the full suite. In both
logs the hang follows immediately after `K-10: a FAILING reconciliation pass...`, which
spawns a real `src/server.ts` and ends it with `boot.kill("SIGKILL")`.
Observed rate across every execution of that file in this review: **3 hangs in 13 runs**.

### Why it can hang at all — cited, and it is the builder's OWN named anti-pattern

`tests/wave1PoolResiliencePostgres.integration.test.ts:503-524`:

    503  try {
    504    const client = await pool.connect();
    505    let failure: unknown;
    506    try {
    507      await client.query("BEGIN");
    508      const pid = (await client.query("SELECT pg_backend_pid() AS pid")).rows[0].pid as number;
    509      await adminPool.query("SELECT pg_terminate_backend($1)", [pid]);
    510      await client.query("SELECT 1");
    511      assert.fail("the terminated backend must reject the next query");
    512    } catch (error) {
    513      failure = error;
    514    }
    515    assert.equal(isConnectionAmbiguous(failure), true, String(failure));
    516    releaseClient(client, failure);
    ...
    522  } finally {
    523    await pool.end().catch(() => undefined);
    524  }

1. **The assertion at `:515` runs BEFORE the release at `:516`.** `assert.fail` at `:511`
   is caught by `:512`, so if the terminate does not land in time, `failure` is an
   `AssertionError`, `isConnectionAmbiguous(AssertionError)` is `false`, `:515` throws,
   `:516` never runs, and `pool.end()` at `:523` waits FOREVER on a client that was never
   handed back. That is verbatim the failure `scripts/test-watchdog.mjs:16-19` was built
   for: *"a test held the only client of a one-connection pool, an assertion threw before
   the release, and `finally { await pool.end() }` waited forever."*
2. **`adminPool` at `:39` is `new Pool({ connectionString: DB_URL, max: 2 })`** — no
   `query_timeout`, no `connectionTimeoutMillis`. `adminPool.query(...)` at `:509` must
   first obtain one of two clients and has NO client-side ceiling. That is exactly the
   K-05 defect this very test exists to prove was fixed, present in the test's own
   fixture.

**What assertion should have caught it and did not.** None can: a hang produces FAIL with
no named failure, which is why `c2e5747`'s own message records having to rewrite K-06c
twice — *"A control that can only say 'something hung' names no property."* The same rule
has not been applied to K-05.

**Falsifier.** Run `node scripts/test-watchdog.mjs tests/wave1MigrationReplayPostgres.integration.test.ts
tests/wave1PoolResiliencePostgres.integration.test.ts` enough times without seeing
`K-05 ... (240...ms)`. I saw it in 1 of 3, and in 3 of 13 executions overall.

**Blocking: YES.** The candidate's headline claim is `1088/1088 — fail 0`. On an
independent environment at the same SHA that reproduces once in five.

---

## R-14 · IMPORTANT · BLOCKING — `POSITIVE CONTROL: bare concurrent CREATE TABLE IF NOT EXISTS ...` is killed by an administrator termination it cannot come from, in 2 of 5 full-suite runs, and NOTHING in the repository explains it

Runs 4 and 5, identical:

    test at tests/wave1MigrationReplayPostgres.integration.test.ts:640:25
    ✖ POSITIVE CONTROL: bare concurrent CREATE TABLE IF NOT EXISTS really does crash N-1 with 23505 (36.3ms / 36.2ms)
      error: terminating connection due to administrator command
          at parseErrorMessage (.../pg-protocol/src/parser.ts:394:9)

SQLSTATE 57P01. The error did NOT arrive through the test's own
`Promise.allSettled` — had it, the failure message would have been the test's
`expected 23505 unique-violation losses; got [...]`. It escaped the `try`, so it struck
either a pool teardown or `withFreshDatabase`'s own `adminPool` statements
(`tests/wave1MigrationReplayPostgres.integration.test.ts:579-590`).

**Denominator on the possible sources.** `grep -rn "pg_terminate_backend" tests/ src/`
returns exactly TWO call sites, both in `tests/wave1PoolResiliencePostgres.integration.test.ts`
(`:85`, `:509`), both targeting a single pid read moments earlier. The only other
administrator termination available is `DROP DATABASE ... WITH (FORCE)`, and every such
statement in the suite names a database no other file uses.

**Ruled out:** PID recycling (backend pids on this container were ~5900 after five hours;
`pid_max` is far larger), leftover reviewer databases or connections (`select datname from
pg_database` -> `aaliyah_test, postgres, template0, template1`; `pg_stat_activity` showed
one admin backend and no strays at the time of the check), and machine load (load average
2.81-6.76 for runs 4 and 5).

**Not reproduced in isolation:** `replay + poolResilience` x3 did not produce it. It needs
the full parallel file set.

**I did not root-cause this.** I am reporting it as an OPEN, reproduced (2/5) suite
failure on a clean tree with an unexplained source of backend termination. Combined with
R-11 — the same test also fails legitimately on `42710` about 1 run in 360 — this single
positive control is the least trustworthy assertion I touched.

**Blocking: YES**, on the same ground as R-13: the suite does not pass reproducibly, and a
57P01 arriving from an unidentified source in a database-backed test suite is a
reliability question by definition.

---

## R-15 · Medium — the PRODUCTION provider deadline (`PROVIDER_DEADLINE_MS = 5_000`) has no assertion at all: I raised it to 83 minutes and the only file that exercises it passed 132/132

`src/persistence/postgres/wave1TrustedMemoryStore.ts:413`:

    export const PROVIDER_DEADLINE_MS = 5_000;

`:548`: `const providerDeadlineMs = options.providerDeadlineMs ?? PROVIDER_DEADLINE_MS;`
`src/server.ts:100` builds the memory service with no `providerDeadlineMs`, so 5,000 ms is
the value that bounds every PII-key-provider call the process awaits **before
`app.listen()`** — the exact path K-04/probe4 is about.

**Denominator.** `grep -rn "PROVIDER_DEADLINE_MS" tests/ src/` -> ONE hit outside the
declaration, and it is `:548` itself. `grep -rn "providerDeadlineMs" tests/` -> ONE hit,
`tests/wave1MemoryHoldErasurePostgres.integration.test.ts:6070`, where the test supplies
its OWN 400 ms. The one other test that uses a slow provider on the DEFAULT deadline
(`:5937`) hangs for `HANG_MS = 3_000` (`:5907`) — BELOW 5,000 — so the default never
fires there either.

**EXECUTED.**

    MUT-9: PROVIDER_DEADLINE_MS 5_000 -> 5_000_000  (5s -> 83 minutes)
    === MUT9 rc=0 restored_ok=YES git=0
    WATCHDOG VERDICT: PASS scope=FOCUSED tests=132 pass=132 fail=0 cancelled=0 skipped=0 todo=0

**What this does and does not mean.** The deadline MECHANISM is properly covered — the
R-4/K-04 test at `:6037-6091` uses a provider that never settles and asserts
`notProvenReasons = { PROVIDER_TIMEOUT: 1 }`, and I confirm the fail-closed semantics are
right by reading `wave1TrustedMemoryStore.ts:2623-2631` and `:3241-3249`: a timeout yields
`NOT_PROVEN / PROVIDER_TIMEOUT` and NEVER `PROVEN_DESTROYED`, and destruction is confirmed
by re-asking rather than by trusting the call's return. What is uncovered is the VALUE
that production actually uses.

**Severity Medium, not Important**, because a wrong value here degrades boot latency and
does not falsify a destruction claim. It is the same class as R-10 and is listed
separately so the fix is scoped correctly: assert the default, not only the injected one.

---

## R-16 · Low — `googleOAuthHttp` retries with no backoff and no jitter

`src/mail/google/googleOAuthHttp.ts:88-120`: `attempts = maxRetries + 1` (default 3) with
a 10 s per-attempt `AbortController` and `continue` on 5xx — immediately, with no delay.
Correctly scoped (`{ retry: false }` for the single-use code exchange at `:137`), and
correctly bounded per attempt. But three back-to-back requests against a provider that is
already returning 5xx is textbook retry amplification. Out of the W1.3 trusted-memory
scope and not exercised against any live provider (the protocol forbids it), so recorded
as an observation only. **Blocking: NO.**

---

## Fail-closed audit of the paths the mandate names (item 3)

| seam | behaviour observed | fail-closed? |
|---|---|---|
| migration, backend killed mid-DDL | `57P01`, transaction rolled back whole (0 ledger rows), client DESTROYED, no lock left, rerun recovers (R-05) | YES |
| migration, whole process SIGKILLed | ledger absent/partial-free, rerun recovers 5/5 (R-05) | YES |
| migration, advisory lock held by another | `55P03` at exactly 120,020 ms -> `server.ts` `process.exit(1)` (R-04) | YES (but see R-04) |
| migration over a squatted ledger name | `42809` / `22P02`, transaction rolled back, nothing applied (R-03) | YES |
| migration, an applied migration's SQL edited | refused before anything is applied, ledger untouched (`INT-DIGEST`, re-observed passing in every run) | YES |
| replaying an older migration (W1BR-014) | refused with the ordinal message; connection returned healthy with no session state and no advisory lock (verified by MUT-2 killing it) | YES |
| PII key provider hangs forever | `NOT_PROVEN` / `PROVIDER_TIMEOUT`, never `PROVEN_DESTROYED`; key still `active` afterwards (`wave1TrustedMemoryStore.ts:2623-2631`, `:3241-3249`, R-4/K-04) | YES |
| PII key provider unavailable / answers `unknown` | `NOT_PROVEN` with a NAMED reason, counted, never a destruction | YES |
| destroyDataKey returns success | NOT trusted — the state is re-read and only `destroyed` is recorded (`:3216-3236`) | YES |
| idle client error / backend killed under a checked-out client | logged, not fatal; POSITIVE CONTROL proves the unguarded shape dies (R-06, MUT-8) | YES |
| boot recovery pass fails | each pass reports its own failure and the process still boots — deliberate, documented fail-OPEN, scoped to historical unknowns only (`src/server.ts:88-99`, K-10) | deliberate |

I found **no fail-OPEN** on any path I exercised.

## Guards

    $ bash scripts/ci-guards.sh
    PASS  frozen manifest verified (17 pinned)
    PASS  no file-backed persistence in src/
    PASS  no role/service grants mail.send.execute
    PASS  no new unfinished-work markers (disclosed frozen sims excluded)
    PASS  no committed .env / key / service-account files
    PASS  no core->aaliyah-workflows code dependency
    PASS  Contracts provenance 7d576681d1001eb4c4a7f044f7793cdb3f80af76 tree a34af636b5ce62dbb2830a8a7b716816f42ea041
    PASS  the full suite's executed set is bound to the commit
    RELEASE GUARDS: PASS

8/8 as claimed. VERIFIED.

---

## Subject re-verified AFTER all work

    $ git -C /Users/andrelove/aaliyah-w13-rv5-rel/aaliyah-wave1-core rev-parse HEAD
    e71b51e9ed333d1feab1cd6819496269d201a6e2                       <- unchanged
    $ git -C /Users/andrelove/aaliyah-w13-rv5-rel/aaliyah-wave1-core status --porcelain
    (empty)                                                        <- clean
    $ git -C /Users/andrelove/aaliyah-w13-rv5-rel/aaliyah-wave1-contracts rev-parse HEAD
    7d576681d1001eb4c4a7f044f7793cdb3f80af76                       <- unchanged, clean
    $ shasum -a 256 src/persistence/postgres/migrations.ts src/persistence/postgres/pool.ts
    f40cda6a27b67ddb48da0fe874cfb006d31cec692b7a1522c3cda255b744c416  migrations.ts
    043ddceb8aa5fd834608660db1a897f7488238c5050c0a8c6ede35fd27d0878d  pool.ts

Both hashes are byte-identical to the values I recorded BEFORE any mutation.
Nine mutants were applied (MUT-1, MUT-2 to `migrations.ts`; MUT-3, MUT-3a, MUT-4, MUT-5,
MUT-5b, MUT-6, MUT-7, MUT-8, MUT-5+6+7 to `pool.ts`; MUT-9 to `wave1TrustedMemoryStore.ts`)
and every one restored from a pre-mutation byte copy with `restored_ok=YES git=0` printed
by the runner. Two untracked mutant COPIES were created under
`src/persistence/postgres/.relMutant*.ts` for the mixed-build harnesses and deleted before
any suite run; ten untracked scratch harnesses at the repo root, all deleted.

## Database left behind (stated, as required)

`postgres://postgres:test@127.0.0.1:54603/aaliyah_test`

    databases: aaliyah_test, postgres, template0, template1   (no scratch databases left)
    aaliyah_test: 38 tables in public, 60 rows in aaliyah_mail_migrations
    schemas: public ONLY (no w23_probe, no opsched, no attacker schema)
    roles: aaliyah_memory_{hold_officer,issuer,mutator,reader,reconciler,revoker,settler}
           (no attacker_app)

This is the state the last full-suite run left: fully migrated, clean. I created and
dropped ~700 scratch databases during the race work (`relrace_*`, `relledger`, `reltol`,
`reltype`, `relshape`, `rellt*`, `relkill`, `relsigkill`, `relmix_*`,
`aaliyah_concurrent_control_rv*`); none survive. I did NOT run the search_path exploit, so
this database is NOT contaminated by it.

## What I did NOT cover (named gaps, so nobody inherits a false all-clear)

1. **K-21 memory exhaustion** — not attempted, per the protocol's "do not spend budget".
   I did not encounter it in normal operation. fd exhaustion: not re-executed either; I
   inherit the register's claim without independent confirmation.
2. **The 1086/1087 discrepancy (review subject #2)** — I observed a THIRD number, 1091,
   and explained it as `hookSentinel` wrapper tests on failing files (R-07). I did NOT
   reconcile 1086 vs 1087 vs 1088; every run of mine that produced a summary said 1088.
3. **R-14 is unattributed.** I reproduced a 57P01 killing a test in 2 of 5 full-suite runs
   and could not identify what terminated the backend. That is an OPEN reliability question
   I am handing on, not an explained one.
4. **Single-flight / duplicate-execution on the memory stores** — the
   `pg_advisory_xact_lock` single-flight in `wave1TrustedMemoryStore.ts:1103`,
   `wave1AliasRegistryStore.ts:978/:1475`, `wave1LifecycleStore.ts:80` and
   `wave1MemoryReconciler.ts:254` was READ, not raced. I spent my concurrency budget on the
   migrator, which the mandate ranked first. `DUPLICATE_EXECUTION` and
   `SINGLE_FLIGHT_BROKEN` are therefore NOT_VERIFIED by me at this SHA.
5. **Settlement and erasure seams were not severed mid-flight.** I killed backends during
   MIGRATION only. Erasure/settlement fail-closed behaviour was established by reading the
   cited code and by the existing K-04 tests, not by my own fault injection.
6. **Disk exhaustion** and **pool exhaustion under sustained concurrent load** were not
   executed.
7. **MUT-6, MUT-7 and MUT-9 survivors were judged against their own files plus a
   repo-wide grep denominator**; only the combined MUT-5+6+7 was judged against the FULL
   suite. MUT-9 was not run against the full suite.
8. **Rolling-deploy / production behaviour is NOT certified**, and I make no claim about
   remote CI, cloud KMS, migration 047 or anything outside the local boundary.

---

## Findings index

| ID | severity | one line | blocking |
|---|---|---|---|
| R-01 | Info | the migrator race reproduces on demand with start jitter (15,965 lost races over 21,600 raced CREATEs); the restored advisory lock gives 0 losses in 9,600 | no |
| R-02 | Info | the 42710 tolerance is load-bearing against REAL errors: candidate 0/22,400 rejections, the 97bb476 set 124/16,000, all 42710 | no |
| R-03 | Low | the tolerance's presence re-check only proves "a relation of this name exists", not "this table"; still fails closed | no |
| R-04 | Medium | the migrator waits 120 s for a lock protecting work permitted 300 s per statement; second instance crash-loops at boot, and no test relates the two bounds | no |
| R-05 | Info | crash mid-migration: no torn state, no leaked lock, clean recovery on every surface tested | no |
| R-06 | Info | `guardPoolErrors`' positive control fired unprompted against my own unguarded harness | no |
| R-07 | Important | under co-tenant load the shared memory-table lock cascades into 315 failures and a 1091 denominator — environment-attributed | no |
| **R-10** | **Important** | **three pool bounds weakened 10-60x; FULL suite still 1088/1088 PASS. The only assertions that mention them compare each constant to itself** | **YES** |
| **R-11** | **Important** | **the migration positive control pins `23505` for a race with three SQLSTATEs; 1 in 360 replicas produced `42710` and would have gone red on a correct build** | **YES** |
| R-08/R-09 | Info | K-05's guard and both restored migrator controls DO have real detectors — MUT-1, MUT-2, MUT-3, MUT-3a, MUT-4, MUT-8 all killed with named assertions | no |
| R-12 | Info | G-05 audited over all 16 acquisition sites: no comparison remains outside the shared lock | no |
| **R-13** | **Important** | **1 clean PASS in 5 full-suite runs at this SHA; `K-05` hangs its full 240 s timeout in 3 of 13 executions, by the builder's own named anti-pattern (assert before release, `pool.end()` in `finally`)** | **YES** |
| **R-14** | **Important** | **the migration positive control is killed by an unexplained `57P01` in 2 of 5 full-suite runs on a clean tree; no source in the repository accounts for it** | **YES** |
| R-15 | Medium | the PRODUCTION `PROVIDER_DEADLINE_MS = 5_000` has no assertion; raised to 83 minutes, its only file passed 132/132 | no |
| R-16 | Low | OAuth retries have no backoff or jitter | no |

## Where the gates themselves failed (the protocol's review subject #4)

- `97bb476` deleted the advisory lock as mutation-closure M-30 and gates 1-3 passed on
  three consecutive candidates. **Confirmed independently**: with the lock deleted, the
  full migrator race is invisible unless the ledger CREATE is raced with millisecond-scale
  stagger, which no gate did. My `.rel-race-nolock.ts` reproduction of the BUILDER's method
  (6 concurrent migrators x 64 fresh databases = 384 unlocked migrators) also found
  **0 crashes** — the same null result the builder got. The method, not the diligence, was
  the failure. Adding jitter turned a 0-in-384 null into a 125-occurrence positive.
- The closure rule ("never by deleting the mechanism") is honoured for M-29 (R-08) and for
  the two restored migrator controls (R-09). It is NOT honoured for the bounds in R-10 and
  R-15, which have no falsifier at all — the state `97bb476` was in when it deleted the lock.

## VERDICT

**BLOCK · blocking: true**

Four Important findings, each executed and each with a falsifier:
**R-10** (three reliability bounds a full 1088-test suite cannot distinguish from broken),
**R-11** (a positive control that goes red on correct behaviour, proven by counter-example),
**R-13** (the headline `1088/1088 — fail 0` reproduces once in five here, and `K-05` hangs
240 s in 3 of 13 executions with no named assertion), and
**R-14** (an unexplained `57P01` failing the same test in 2 of 5 clean runs).

The migrator work itself — the defect of the round — I find **SOUND and independently
verified**: the race is real and I reproduced it at will (R-01), the restored advisory lock
eliminates it (0 losses in 9,600 raced statements), the 42710 tolerance is load-bearing
against real server errors and not only against a mock (R-02), both controls have named
detectors that fire in seconds rather than hanging (R-09), and crash/kill recovery is clean
on every surface I injected into (R-05). R-03 and R-04 are qualifications on it, neither
blocking.

What blocks is the surrounding test estate: a suite that does not pass reproducibly, and
controls whose removal nothing would notice. I do not certify. AEGIS Omega adjudicates.
