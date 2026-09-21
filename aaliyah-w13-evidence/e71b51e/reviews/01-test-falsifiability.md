# GATE 1 — TEST FALSIFIABILITY — W1.3 candidate-4
subject: e71b51e9ed333d1feab1cd6819496269d201a6e2 · tree 5af8080da732f8b4c4afd6b81337ab4a88b06950 · contracts 7d576681 · blocking: true

reviewer environment: ROOT=/Users/andrelove/aaliyah-w13-rv5-test
worktree: /Users/andrelove/aaliyah-w13-rv5-test/aaliyah-wave1-core
DB: postgres://postgres:test@127.0.0.1:54601/aaliyah_test
AALIYAH_TEST_DATABASE_URL exported; AALIYAH_DATABASE_URL never exported (trap 1).

VERDICT: BLOCK · blocking: true   (full verdict at the end of this file)
Findings: F5 Critical; F1, F2, F3, F6 Important; F4 Low; N1-N3 negative/info.

## Subject verified (not trusted)

| field | claimed | verified | how |
|---|---|---|---|
| HEAD | e71b51e9ed333d1feab1cd6819496269d201a6e2 | MATCH | `git rev-parse HEAD` |
| tree | — | 5af8080da732f8b4c4afd6b81337ab4a88b06950 | `git rev-parse HEAD^{tree}` |
| contracts | 7d576681d1001eb4c4a7f044f7793cdb3f80af76 | MATCH | `git -C ../aaliyah-wave1-contracts rev-parse HEAD` |
| worktree clean BEFORE | — | empty | `git status --porcelain` -> no output |
| contracts clean BEFORE | — | empty | `git status --porcelain` -> no output |
| database | reachable, clean | PostgreSQL 16.14, `aaliyah_test`, 0 tables in public before first run | `psql ... -c "select count(*) from information_schema.tables where table_schema='public'"` -> 0 |
| tracked test files | — | 84 | `git ls-files tests \| grep -c '\.test\.ts$'` |
| worktree clean AFTER | — | empty (see 'Subject verified AFTER all work') | `git status --porcelain` |

(sections filled in below as work completes)

## Findings

### F1 · Important · `VACUOUS_ASSERTION` — ATK-P1 K-07's "FIXTURE PRECONDITION" assertion cannot fail, and is measured in the wrong session

**The defect in one sentence.** `tests/wave1MemoryHoldErasurePostgres.integration.test.ts:5160-5164`
declares itself a fixture precondition proving "the shadow really would win on the
default path", but it asks `adminPool` (no `SET LOCAL ROLE`, so the *admin's*
`search_path`, which can never contain `aaliyah_memory_mutator`) and compares a
`regclass::text` rendering that is byte-identical whether the shadow wins, loses, or
does not exist at all — so the assertion is true in every possible world.

The code at the candidate SHA (`e71b51e`), `tests/wave1MemoryHoldErasurePostgres.integration.test.ts:5160`:

```ts
    // FIXTURE PRECONDITION: the shadow really would win on the default path.
    const shadowed = await adminPool.query(
      `SELECT to_regclass('memory_identity_edges')::text AS resolved`,
    );
    assert.equal(shadowed.rows[0].resolved, "memory_identity_edges");
```

Two independent reasons it cannot discriminate:

1. **Wrong session.** Every other statement in this test that must act as the attacker
   goes through `runAs("aaliyah_memory_mutator", ...)`, which does
   `BEGIN; SET LOCAL ROLE "<role>"` (helper at `tests/wave1MemoryHoldErasurePostgres.integration.test.ts:390-407`).
   This one query does **not** — it is `adminPool.query` directly. The shadowing
   mechanism under test is `"$user"` resolving to a schema named after the *session
   role*. Under the admin role, the schema `aaliyah_memory_mutator` is not on the
   path at all, so this query measures a session in which the shadow could never win.
2. **`regclass::text` erases the distinction.** PostgreSQL renders a `regclass` without
   its schema whenever the relation is visible on the current `search_path`. The shadow
   winning and the shadow losing therefore produce the *same string*.

**EXECUTED reproduction** (scratch database `aaliyah_g1_scratch` on the review DB
`127.0.0.1:54601`, created and dropped by me; the candidate worktree was not touched):

```
$ PGPASSWORD=test psql -h 127.0.0.1 -p 54601 -U postgres -d aaliyah_g1_scratch
CREATE SCHEMA shadow_sch;
CREATE TABLE public.memory_identity_edges(i int);
CREATE TABLE shadow_sch.memory_identity_edges(i int);

--- WORLD A: shadow WINS (shadow schema first on path) ---
SET search_path = shadow_sch, public;
SELECT current_setting('search_path') AS path, to_regclass('memory_identity_edges')::text AS resolved,
       (to_regclass('memory_identity_edges')::oid = 'shadow_sch.memory_identity_edges'::regclass::oid) AS shadow_won;
        path        |       resolved        | shadow_won
--------------------+-----------------------+------------
 shadow_sch, public | memory_identity_edges | t

--- WORLD B: shadow does NOT win (admin-style path, shadow not on it) ---
SET search_path = public;
        path        |       resolved        | shadow_won
--------------------+-----------------------+------------
 public             | memory_identity_edges | f

--- WORLD C: the shadow DOES NOT EXIST AT ALL ---
DROP SCHEMA shadow_sch CASCADE;
SET search_path = public;
SELECT to_regclass('memory_identity_edges')::text AS resolved;
       resolved
-----------------------
 memory_identity_edges
```

`resolved` is `memory_identity_edges` in all three worlds. The assertion the test
writes — `assert.equal(shadowed.rows[0].resolved, "memory_identity_edges")` — passes in
world A (shadow wins), world B (shadow loses) and world C (no shadow exists). It is a
tautology. `shadow_won` — the column that *does* discriminate — is `t` in A and `f` in
B, and the test never computes it.

**What assertion should have caught it and did not.** The test's own stated design is
"NEGATIVE CONTROL FIRST, so the refusal below is not just 'it was refused anyway'"
(line 5142). The precondition is the thing that makes the subsequent refusal
(`merged_records_not_erased`, lines 5170-5177) *mean* "the pin defeated a live shadow"
rather than "nothing shadowed anything and the record was refused for an unrelated
reason". A falsifiable precondition would have been either

  - resolve **as the mutator**: `runAs`-style `SET LOCAL ROLE "aaliyah_memory_mutator"`
    then compare `to_regclass('memory_identity_edges')::oid` against
    `'aaliyah_memory_mutator.memory_identity_edges'::regclass::oid`; or
  - compare the OID / `pg_class.relnamespace`, not the `::text` rendering.

Neither exists anywhere in the test. `scripts/assertion-reachability.mjs` cannot find
this class of defect by construction — the line **does** execute; it is the assertion's
*content* that cannot fail — which is exactly the limit the tool documents at
`scripts/assertion-reachability.mjs:22-25`.

**This is the FOURTH non-falsifiable assertion in the K-07 family**, after the three the
register already records (three specifics stranded behind an equality; the ordering that
hid which protection broke; the locality assertion reachable only through ROLLBACK). The
builder's handoff predicted its own shape and the prediction held.

**Blocking: yes** (Important). Note the underlying *behaviour* is not shown to be wrong —
the pin may well work; what is shown is that ATK-P1's claim to have proved it under a
live shadow rests on an assertion that is true in a world with no shadow.

### F2 · Important · `FALSE_DENOMINATOR` — the 1086/1087 discrepancy's arithmetic REPRODUCED, and the register's leading hypothesis is unnecessary (and its mitigation does not address the real mechanism)

**The defect in one sentence.** `node:test` adds a **synthetic file-level entry** to
`counts.tests` whenever a test *worker process* exits non-zero while every test in it
passed — which is precisely and by design what this repository's own
`tests/support/hookSentinel.cjs` forces (`process.exitCode = 70`) — producing exactly
`+1 test, +1 fail` and nothing else; and no guard, test or watchdog check anywhere pins
the expected denominator, so `counts.tests` is an unpinned number that silently changes
shape under fault.

**EXECUTED reproduction.** Minimal harness, no database, Node v24.9.0 (the same node
that runs the suite), in
`/private/tmp/claude-501/.../scratchpad/denom/`:

```
$ node --version
v24.9.0

# 4 declared tests: A1, A2 (a.test.js), B1 (b.test.js), C1 (c_exit70.test.js)
# c_exit70.test.js emulates hookSentinel.cjs exactly:
#     process.on("exit", () => { process.exitCode = 70; });

=== CONTROL: a + b  (3 declared, all pass) ===
# tests 3
# pass 3
# fail 0

=== VARIANT 1: a + b + d_realfail  (4 declared, ONE ORDINARY assertion failure) ===
# tests 4          <- denominator UNCHANGED
# pass 3
# fail 1

=== SUBJECT: a + b + c_exit70  (4 declared, worker exits 70, every test passed) ===
# tests 5          <- denominator +1
# pass 4
# fail 1
```

The extra entry is the FILE itself — `--test-reporter=spec` names it:

```
✔ A1 (0.275584ms)
✔ A2 (0.047333ms)
✔ B1 (0.362917ms)
✔ C1 (0.36575ms)
✖ c_exit70.test.js (35.086917ms)
✖ failing tests:
test at c_exit70.test.js:1:1
```

And with **the repository's own sentinel, unmodified**, preloaded exactly as
`scripts/test-watchdog.mjs:500` preloads it, against a file with a never-settling
`after` hook:

```
$ node --require /Users/andrelove/aaliyah-w13-rv5-test/aaliyah-wave1-core/tests/support/hookSentinel.cjs \
       --test --test-reporter=tap a.test.js b.test.js e_hang_hook.test.js
# HOOK_NEVER_COMPLETED after at Object.<anonymous> (.../e_hang_hook.test.js:3:6)
# tests 5          <- +1 over the 4 declared
# pass 4
# fail 1
```

**This is the run-A signature exactly.** The register records
(`docs/WAVE1_BLOCKER_REGISTER.md:2000-2004`):

```
run A   tests=1087  pass=1086  fail=1
run B   tests=1086  pass=1086  fail=0
```

`+1 test, +1 fail, pass unchanged` over the stable baseline. An **ordinary** test failure
does not do this (VARIANT 1: 4 declared → `tests 4`). A **non-zero worker exit with every
test passing** does it every time, deterministically.

**What this means for the register.** The register's leading hypothesis
(`docs/WAVE1_BLOCKER_REGISTER.md:2012-2019`) is that the assertion-reachability tool's
nested `node --test` leaked its failing negative-control fixture into the outer run via
`NODE_TEST_CONTEXT`. I did not need that hypothesis: the arithmetic is produced by a
mechanism that is *built into this repository on purpose*. Three consequences, stated
separately because they have different weights:

1. The register's stated mitigation — "the tool now strips `NODE_TEST_CONTEXT`"
   (`scripts/assertion-reachability.mjs:93-101`) — does **nothing** about the mechanism I
   reproduced. If run A was a sentinel/worker-exit event, the item is recorded as
   mitigated when it is not.
2. The register's stated interpretation is wrong in a way that matters:
   "it means a test was **discovered or emitted** that usually is not"
   (`docs/WAVE1_BLOCKER_REGISTER.md:2009-2010`), and therefore "a hole in
   [the watchdog's] premise" that the executed set is the commit's set
   (`:2021-2024`). It is **not** a discovery defect. `discoveryBinding()`
   (`scripts/test-watchdog.mjs:162-240`) was never bypassed; the runner *synthesises*
   a file-level entry after discovery and node counts it in `tests`. The watchdog's
   discovery premise is intact. The defect is in the **denominator's definition**, not
   in the executed set.
3. **Nothing pins the denominator.** `bash scripts/ci-guards.sh` guard 8 checks only that
   the executed set is the commit's set (`--verify-discovery`). Searched:

```
$ grep -rn "1088\|expectedTests\|EXPECTED_TESTS" scripts/ tests/testWatchdog.test.ts
(no output)
```

   Population: all 8 guards in `scripts/ci-guards.sh`, plus `tests/testWatchdog.test.ts`
   (the watchdog's own test file), plus everything under `scripts/`. Inclusion rule: any
   literal expected test count or named constant for one. Inspected: all. Found: none.
   So `1088/1088` is a number a human remembers between runs, not an asserted invariant.
   A file that silently registered *fewer* tests would still produce
   `passed === tests`, no `filesWithoutTests`, no `testsNeverFinished`, and therefore
   `WATCHDOG VERDICT: PASS` at a quietly smaller denominator.

**What assertion should have caught it and did not.** `tests/testWatchdog.test.ts` pins
the watchdog's refusals (M-51, discovery binding, cancelled-is-not-pass). It does not pin
`counts.tests` against the number of tests the commit declares, and there is no guard that
does. A single assertion of the form "the full suite declares exactly N tests, and the
summary's `tests` equals N" would both close this and make any future denominator drift —
in either direction — a named failure instead of a number somebody has to remember.

**Status of the register's OPEN item.** I did **not** reproduce run A itself. I reproduced
its exact arithmetic signature from the repository's own machinery, and showed the recorded
mitigation does not cover that mechanism. I therefore report the item as **still OPEN, with
its leading hypothesis demoted and a better-supported mechanism named**, not as closed.

**Blocking: yes** (Important).

## Baseline reproduction — the claimed 1088/1088 is NOT reproduced here

The claim is `1088/1088 — fail 0, skip 0, todo 0, cancelled 0`. I ran the full suite with
the **watchdog's own defaults** (trap 4 honoured: no `--test-timeout-ms`, no
`--deadline-ms`, no `--exit-grace-ms` on my argv), reading the **VERDICT line**, not
`failures[]` (trap 3).

```
$ export AALIYAH_TEST_DATABASE_URL="postgres://postgres:test@127.0.0.1:54601/aaliyah_test"
$ node scripts/test-watchdog.mjs --evidence <path>
```

Bounds actually used, read back from the evidence file (i.e. the defaults):
`testTimeoutMs: 240000, deadlineMs: 900000, exitGraceMs: 15000,
pgOptions: "-c statement_timeout=60000 -c lock_timeout=60000 -c idle_in_transaction_session_timeout=120000"`.

### RAW ACCOUNTING, VERBATIM

**Run 1** — `WATCHDOG VERDICT: FAIL scope=FULL_SUITE` (no counts printed, because there
was no summary), `durationMs: 739808`, `git: {head: e71b51e9…, dirty: false}`,
`files: 84`, `discovery: {boundToCommit: true, ignored: [], untracked: [], missing: []}`:

```json
"counts": null,
"reasons": [
  "HUNG_WORKER: a timeout occurred and the run produced no further events for 15000ms",
  "ORPHANED_PROCESSES: processes from this run were still alive and were killed",
  "NONZERO_EXIT: code=1 signal=null",
  "NO_SUMMARY: the runner never reported final counts",
  "TIMED_OUT: tests/wave1PoolResiliencePostgres.integration.test.ts :: a STORE that connects and releases by hand destroys an ambiguous client too, not just pool.query",
  "FILES_WITHOUT_RESULT: tests/wave1PoolResiliencePostgres.integration.test.ts",
  "FILES_WITHOUT_SUMMARY: tests/wave1PoolResiliencePostgres.integration.test.ts, tests/wave1TrustedMemoryPostgres.integration.test.ts",
  "TESTS_NEVER_FINISHED: tests/wave1PoolResiliencePostgres.integration.test.ts queued=17 finished=16",
  "FILES_WITHOUT_TESTS: tests/wave1TrustedMemoryPostgres.integration.test.ts"
],
"timedOut": [{ "name": "a STORE that connects and releases by hand destroys an ambiguous client too, not just pool.query",
               "file": "tests/wave1PoolResiliencePostgres.integration.test.ts",
               "failureType": "testTimeoutFailure",
               "message": "test timed out after 240000ms",
               "code": "ERR_TEST_FAILURE" }],
"failures": [],
"processGroup": { "pgid": 8382, "killedSurvivors": true, "survivedSigkill": false }
```

spec line: `✖ a STORE that connects and releases by hand destroys an ambiguous client too, not just pool.query (607125.036667ms)` — **607 seconds** for a test whose own client-side ceiling is `MAIL_DB_POOL_BOUNDS.queryTimeoutMs = 35_000` (`src/persistence/postgres/pool.ts:48`).

**Run 2** — `WATCHDOG VERDICT: FAIL scope=FULL_SUITE`, `durationMs: 498923`:

```json
"counts": null,
"reasons": [
  "HUNG_WORKER: a timeout occurred and the run produced no further events for 15000ms",
  "ORPHANED_PROCESSES: processes from this run were still alive and were killed",
  "NONZERO_EXIT: code=1 signal=null",
  "NO_SUMMARY: the runner never reported final counts",
  "TIMED_OUT: tests/wave1PoolResiliencePostgres.integration.test.ts :: boot's recovery passes against a reachable but WEDGED database are refused within their bounds, never hang",
  "FILES_WITHOUT_RESULT: tests/wave1PoolResiliencePostgres.integration.test.ts",
  "FILES_WITHOUT_SUMMARY: tests/wave1PoolResiliencePostgres.integration.test.ts, tests/wave1TrustedMemoryPostgres.integration.test.ts",
  "TESTS_NEVER_FINISHED: tests/wave1PoolResiliencePostgres.integration.test.ts queued=17 finished=16",
  "FILES_WITHOUT_TESTS: tests/wave1MemoryDigestOraclePostgres.integration.test.ts, tests/wave1TrustedMemoryPostgres.integration.test.ts"
]
```

Note the timing-out test is a **different** one in run 2 — `boot's recovery passes against
a reachable but WEDGED database…`, which *passed* in run 1 at `77505.157ms`. Both are
`wedgeableProxy`-based tests in the same file.

### Gate accounting object

```
{ required: 1088, executed: "UNKNOWN — no summary emitted in either run",
  passed: 964 (observed spec outcomes, identical set both runs),
  failed: 0 ordinary failures; 1 testTimeoutFailure per run,
  skipped: UNKNOWN, cancelled: UNKNOWN, todo: UNKNOWN, neutral: 0,
  stale: 0, notVerified: 124 (the tests in tests/wave1TrustedMemoryPostgres.integration.test.ts
  and the unreported remainder, which never emitted an outcome in either run) }
```

**Per my evidence contract, `executed != required` and the counts object is `null`, so the
baseline is `NOT_VERIFIED`.** I will not report a count I did not observe. I never observed
`tests=1088`.

### ENVIRONMENTAL CONFOUND — disclosed, not suppressed

I checked before attributing this to the candidate:

```
$ uptime
14:38  up  3:02, 3 users, load averages: 26.39 17.76 9.26
$ sysctl -n hw.ncpu
14
$ docker ps --format '{{.Names}}\t{{.Ports}}\t{{.Status}}'
aaliyah-w13-rv5-data  0.0.0.0:54606->5432/tcp  Up 24 minutes
aaliyah-w13-rv5-int   0.0.0.0:54605->5432/tcp  Up 24 minutes
aaliyah-w13-rv5-red   0.0.0.0:54604->5432/tcp  Up 24 minutes
aaliyah-w13-rv5-rel   0.0.0.0:54603->5432/tcp  Up 24 minutes
aaliyah-w13-rv5-sec   0.0.0.0:54602->5432/tcp  Up 24 minutes
aaliyah-w13-rv5-test  0.0.0.0:54601->5432/tcp  Up 24 minutes
```

Load average **26.39 on 14 CPUs**, with other reviewers' `tsc -p tsconfig.json` at 186% CPU
and other reviewers' `node scripts/test-watchdog.mjs --deadline-ms 3600000` and
`--test-timeout=240000` workers running concurrently. **I therefore do NOT claim the
candidate's suite is broken.** What I claim, precisely and only:

- I did not reproduce `1088/1088`. I observed `WATCHDOG VERDICT: FAIL` twice out of two.
- `tests/wave1PoolResiliencePostgres.integration.test.ts` is wall-clock-sensitive to a
  degree that makes the suite's verdict a function of host load, and it hung *past* the
  watchdog's 240 s per-test bound to 607 s — its own design bound is 35 s.
- The watchdog behaved correctly throughout: it called the hang FAIL, never PASS, and its
  process-group kill reported `killedSurvivors: true, survivedSigkill: false`. The
  anti-hang machinery is real and it worked. That is a genuine positive finding.

### Determinism of the EXECUTED SET (the watchdog's actual premise)

Load-immune, and the more important question. I extracted every `✔`/`✖` outcome name from
each run's spec output and diffed the sets:

```
$ grep -E "^[✔✖] " run1.log | sed -E 's/^[✔✖] //; s/ \([0-9.]+ms\)$//' | sort > run1.names
$ grep -E "^[✔✖] " run2.log | sed -E 's/^[✔✖] //; s/ \([0-9.]+ms\)$//' | sort > run2.names
run1:      964 outcome lines,      964 distinct names
run2:      964 outcome lines,      964 distinct names
$ comm -23 <(sort -u run1.names) <(sort -u run2.names)     # in run1 not run2
(empty)
$ comm -13 <(sort -u run1.names) <(sort -u run2.names)     # in run2 not run1
(empty)
$ sort run1.names | uniq -d                                 # duplicate names within a run
(empty)
$ md5 -q run1.names run2.names
f2736b75251c253982d5c494d8bab6d3
f2736b75251c253982d5c494d8bab6d3
```

**Byte-identical.** Zero set difference, zero duplicated names, across two runs whose
*outcomes* differed (different test timed out). So: within the 964 tests that reported,
the executed set IS deterministic, and I found no evidence of a test being "discovered or
emitted that usually is not". Combined with F2, which shows the +1 comes from a
*synthesised file entry* rather than from discovery, the watchdog's discovery premise
holds up under the test I was able to apply.

**Denominator for this determinism claim:** 2 runs (not the ≥5 my mandate asks for),
964 of 1088 tests (88.6%), 0 of the 124 tests in
`tests/wave1TrustedMemoryPostgres.integration.test.ts` (which reported nothing in either
run). Stated as a partial result, not a clean sweep.

### F3 · Important · `NEGATIVE_CONTROL_WEAK` + `VACUOUS_ASSERTION` — the migrator's ledger-completeness assertions cannot detect 18 of 60 migrations silently never applying, and the "applied exactly once" assertion is enforced by the primary key

**The defect in one sentence.** Every assertion in the suite about how many migrations the
ledger holds is a loose lower bound (`>= 42`, `>= 54`, `>= 56`) against a true count of
**60**, and the one assertion that carries the "applied exactly once" claim —
`assert.equal(n, d)` where `d = count(DISTINCT id)` — is guaranteed true by
`aaliyah_mail_migrations_pkey`, so neither can fail; the exact count is pinned nowhere in
the repository.

**Denominator / collection method.** Population: every assertion about the applied-migration
count in the 84 tracked `*.test.ts` files at `e71b51e`. Inclusion rule: any assertion whose
subject is a `count(*)`/row-set over `aaliyah_mail_migrations`. Collection:

```
$ grep -rn "aaliyah_mail_migrations" $(git ls-files tests | grep '\.test\.ts$') | grep -i "count\|SELECT"
tests/wave1MemoryUpgradePostgres.integration.test.ts:700   (reads ids, no count assertion)
tests/wave1MigrationReplayPostgres.integration.test.ts:57  -> assert.ok(n >= 42)
tests/wave1MigrationReplayPostgres.integration.test.ts:75,79 -> assert.equal(after, before)   [sound: catches a replay]
tests/wave1MigrationReplayPostgres.integration.test.ts:456,466,540,610,670  (per-id, not completeness)
tests/wave1MigrationReplayPostgres.integration.test.ts:716 -> assert.equal(n, d); assert.ok(n >= 56)
tests/wave1MigrationReplayPostgres.integration.test.ts:820 -> assert.equal(n, d); assert.ok(n >= 54)

$ grep -rn "MAIL_MIGRATIONS.length\|migrations.length\|\.length, 60\|=== 60\|, 60," $(git ls-files tests | grep '\.test\.ts$')
(no output)
```

Inspected: all. Assertions pinning the exact count: **0 of 60 migrations pinned anywhere.**

**EXECUTED reproduction.** I copied the real ledger's DDL and its real 60 ids out of the
review database into a scratch database (read-only against `aaliyah_test`; the candidate
worktree untouched), then evaluated the tests' exact predicates.

Part 1 — `assert.equal(n, d)` is enforced by the schema, not by the migrator:

```
$ psql -d aaliyah_test -c "\d aaliyah_mail_migrations"
 id         | text  | not null
Indexes:
    "aaliyah_mail_migrations_pkey" PRIMARY KEY, btree (id)

$ psql -d aaliyah_g1_scratch -c "SELECT count(*)::int AS n, count(DISTINCT id)::int AS d FROM aaliyah_mail_migrations;"
 n  | d
----+----
 60 | 60

$ psql -d aaliyah_g1_scratch -c "INSERT INTO aaliyah_mail_migrations(id) SELECT id FROM aaliyah_mail_migrations LIMIT 1;"
ERROR:  duplicate key value violates unique constraint "aaliyah_mail_migrations_pkey"
DETAIL:  Key (id)=(001_mail_oauth_states) already exists.
```

`id` is the PRIMARY KEY, so `count(*) = count(DISTINCT id)` is a database invariant. No
migrator behaviour, correct or broken, can make `n != d`. The assertion that carries the
headline claim of `"N concurrent migrators on a FRESH database ALL fulfil, and the ledger
is applied exactly once"` (`tests/wave1MigrationReplayPostgres.integration.test.ts:795`)
**cannot fail**.

Part 2 — delete the 18 highest migrations (043..060), i.e. *all of the W1.3 hardening*,
and evaluate the tests' own predicates:

```
$ psql -d aaliyah_g1_scratch
DELETE FROM aaliyah_mail_migrations WHERE substring(id from 1 for 3)::int >= 43;
DELETE 18

 n  | d  | assert.equal(n,d) L718/823 | assert.ok(n>=42) L58 "every migration must have applied" | assert.ok(n>=54) L824 | assert.ok(n>=56) L719
----+----+----------------------------+----------------------------------------------------------+-----------------------+-----------------------
 42 | 42 | t                          | t                                                        | f                     | f
```

The 18 migrations that are absent while the file's **positive control passes**:

```
043_memory_identity_serialized              044_memory_authorization_scope_binding
045_memory_attempts_and_derivable_reconciliation
046_memory_identity_edge_bindings_not_vacuous
047_memory_alias_pii_vault                  048_memory_functions_pg_temp_last
049_memory_reconciliation_bindings_not_vacuous
050_memory_alias_authorization_action_bound 051_memory_erasure_reaches_merged_records
052_memory_alias_reconciliation_derivable   053_memory_merge_chain_bounded
054_memory_merged_erasure_requires_destroyed_keys
055_memory_key_destruction_settlement       056_memory_least_privilege_trim
057_migration_content_digest                058_settled_obligation_resolution_immutable
059_settlement_evidence_bound               060_obligation_settlement_pointer_real
```

That list includes **055**, which gate 3/6's own report
(`reviews/06-mutation-fuzz.md:129-135`) proves is *the* load-bearing guard for M-47/M-55,
and **058**, **059**, **060**, **047** — the entire key-destruction-settlement surface this
candidate exists to harden. The assertion whose message reads *"every migration must have
applied"* (`tests/wave1MigrationReplayPostgres.integration.test.ts:58-61`) is true with all
eighteen of them missing.

**What assertion should have caught it and did not.** An equality against the migration
list's own length — `assert.equal(n, MAIL_MIGRATIONS.length)` — in the positive control,
and in both concurrency tests in place of `>= 54` / `>= 56`. The module already exports the
list; nothing makes this hard. The `>=` form was presumably chosen so the number would not
need bumping each time a migration is added, which is exactly the trade that turned a
completeness control into a formality.

**Mitigation, stated honestly.** Other integration tests would fail loudly if tables from
043..060 were missing, so the *practical* blast radius is smaller than the assertion's
weakness suggests. That is a property of the rest of the suite, not of these controls. The
gate question is whether *these* assertions discriminate, and three of them do not.

**Blocking: yes** (Important), on the NAMED REVIEW SUBJECT (the migrator).

### F4 · Low · stale comment asserts the opposite of the restored code

`tests/wave1MigrationReplayPostgres.integration.test.ts:831-837`, inside the 2/3/5
concurrency test, still reads:

```ts
          // ---- NO SESSION STATE RODE BACK INTO THE POOL ----------------
          //
          // The runner no longer TAKES an advisory lock (it was removed as
          // unfalsifiable once the ledger creation tolerated a lost race), so
          // this assertion is now a forward leak check rather than a proof
          // about today's code: it holds any future session lock to the same
          // standard, and it must keep passing.
```

The advisory lock was **restored** in `c2e5747` and is taken at
`src/persistence/postgres/migrations.ts:6278`
(`await bounded("SELECT pg_advisory_lock(hashtextextended($1, 0))", [LEDGER_LOCK_KEY]);`).
So the comment describes the `97bb476` state that this candidate exists to undo, and tells
a reader the assertion below it is *not* a proof about today's code when in fact it is
(gate 3/6 killed MUT-3/MUT-5/MUT-7 with exactly this detector family). Stale evidence
dressed as current reasoning, in the one file that is a named review subject.
**Not blocking** — no behaviour depends on it — but it should not survive to the next
candidate.

### N1 · negative finding (no defect) — the alias-registry fixture's attack-enabling GRANT is genuinely gone

The register's standing weakness names "divergence fixtures that depended on the very
`search_path` vulnerability they were meant to help test, and whose setup issued the
attack's own enabling GRANT on every run". At this SHA that is remediated, and I verified
it rather than inheriting it:

```
$ grep -rn "GRANT " $(git ls-files tests | grep '\.test\.ts$')
```

Population: all `GRANT` statements in all 84 tracked test files. Inspected: all 24 hits.
`tests/wave1AliasRegistryPostgres.integration.test.ts:230-235` now records that the shadow
schemas and their grants are removed and the fault is injected at the read-back result
boundary by `divergingReadPool`; there is no `GRANT USAGE ON SCHEMA` to
`aaliyah_memory_reader`/`aaliyah_memory_mutator` anywhere in the test tree. The remaining
`GRANT CREATE ON DATABASE` at
`tests/wave1MemoryHoldErasurePostgres.integration.test.ts:5150` is the attack's enabling
grant, but it is issued **deliberately**, is preceded by a real negative control that the
grant is required (`assert.rejects(... /permission denied/)` at :5144-5147), and is revoked
in the `finally` at :5183-5185. That is the correct shape, not the defective one.

### N2 · negative finding (no defect) — constraint-name regexes are unanchored but currently cannot mis-match

`tests/wave1MemoryConstraintDestroyersPostgres.integration.test.ts:145-148` pins each
destroyer by `assert.match(String(error), new RegExp(destroyer.constraint))` — unanchored,
so a *different* constraint whose name contained the expected name as a substring would
satisfy it. Checked against the live migrated schema:

```
$ psql -d aaliyah_test -c "WITH c AS (SELECT DISTINCT conname FROM pg_constraint WHERE connamespace='public'::regnamespace)
  SELECT a.conname||'  IS A PREFIX OF  '||b.conname FROM c a JOIN c b ON b.conname<>a.conname AND b.conname LIKE a.conname||'%';"
(no rows)
$ psql -d aaliyah_test -c "SELECT count(DISTINCT conname) FROM pg_constraint WHERE connamespace='public'::regnamespace;"
 243
```

Population 243 distinct constraint names, inclusion rule "is any name a proper prefix of
another", inspected all: **0 collisions**. So the looseness is latent, not live. Recorded
so a future constraint named as a superstring of an existing one is a known hazard.

### F5 · Critical · `NONDETERMINISTIC` — the identical executed set produced 1 failure and 169 failures on consecutive runs of the same SHA against the same database

**The defect in one sentence.** Five consecutive full-suite runs at `e71b51e`, same
worktree, same database, same watchdog defaults, produced five different outcomes and
**zero** reproductions of the claimed `1088/1088` — including two consecutive runs whose
executed test-name sets were **byte-identical** while one reported 1 failure and the next
reported 169.

**EXECUTED reproduction — five runs, verbatim accounting.**

| run | VERDICT | counts (verbatim) | failures | timedOut |
|---|---|---|---|---|
| 1 | `FAIL scope=FULL_SUITE` | `null` (NO_SUMMARY) | 0 | `wave1PoolResiliencePostgres :: a STORE that connects and releases by hand destroys an ambiguous client too` |
| 2 | `FAIL scope=FULL_SUITE` | `null` (NO_SUMMARY) | **168** (`testCodeFailure` ×167, `hookFailed` ×1) | `wave1PoolResiliencePostgres :: boot's recovery passes against a reachable but WEDGED database…` |
| 3 | `FAIL scope=FULL_SUITE tests=1088 pass=1087 fail=1 cancelled=0 skipped=0 todo=0` | `{"tests":1088,"failed":1,"passed":1087,"cancelled":0,"skipped":0,"todo":0,"topLevel":1088,"suites":0}` | 1 — `wave1PoolResiliencePostgres :: K-10 …` / `"server never finished booting:"` | 0 |
| 4 | `FAIL scope=FULL_SUITE` | `null` (NO_SUMMARY) | 2 — both `wave1AliasRegistryPostgres` | `identityState.test.ts :: postgres: memberships grant, suspend, and revoke workspace access` |
| 5 | (see "What I did NOT cover") | | | |

Run 2's 168 failures by file (`collections.Counter` over the evidence file's `failures[]`):

```
tests/wave1MemoryHoldErasurePostgres.integration.test.ts   104
tests/wave1AliasRegistryPostgres.integration.test.ts        35
tests/wave1MemoryIdentityPostgres.integration.test.ts       21
tests/wave1MemoryDigestOraclePostgres.integration.test.ts    7
tests/wave1MemoryPrivilegesPostgres.integration.test.ts      1
```

Most frequent messages:

```
x75  'storage_rejected\n\nfalse !== true\n'
x26  "Expected values to be strictly equal:\n+ actual - expected\n\n+ 'storage_rejected'\n- null\n"
x18  'Expected values to be strictly equal:\n\nfalse !== true\n'
x14  'the honest bind must succeed first\n\nfalse !== true\n'
x5   'new row for relation "memory_authorization_receipts" violates check constraint "memory_authorization_receipts_consumed_after_issue"'
x5   'the deletion must succeed first\n\nfalse !== true\n'
```

These are `testCodeFailure` with real assertion text — **not** `cancelledByParent`, not
kill artifacts. Run 4 reproduced the same `'storage_rejected'` vs `null` signature in
`wave1AliasRegistryPostgres`.

**The executed SET was identical while the outcomes were not.** This is the distinction the
register's OPEN item asks about, answered from execution:

```
$ grep -E "^[✔✖] " run1.log | sed -E 's/^[✔✖] //; s/ \([0-9.]+ms\)$//' | sort > run1.names
$ grep -E "^[✔✖] " run2.log | sed -E 's/^[✔✖] //; s/ \([0-9.]+ms\)$//' | sort > run2.names
$ md5 -q run1.names run2.names
f2736b75251c253982d5c494d8bab6d3
f2736b75251c253982d5c494d8bab6d3          <- IDENTICAL name sets

$ grep -cE "^\s*✔" run1.log ; grep -cE "^\s*✖" run1.log
963
1
$ grep -cE "^\s*✔" run2.log ; grep -cE "^\s*✖" run2.log
795
169                                        <- SAME 964 tests, 168 more of them failed
```

So the **denominator is deterministic and the outcome is not** — the opposite of what the
register's OPEN item hypothesises, and far worse. Run 3's set was a strict superset
(`comm -23 run1.names run3.names` → empty; 123 additional names; 1088 total, confirming the
claimed denominator is real).

**Leading mechanism — stated as inference, not as executed proof.** The failures cluster in
exactly the files that mutate database-wide privileges and restore them only in a `finally`:

```
tests/wave1PoolResiliencePostgres.integration.test.ts:313-314
    REVOKE SELECT ON memory_mutation_receipts FROM aaliyah_memory_reconciler
    REVOKE SELECT ON memory_pii_key_erasures  FROM aaliyah_memory_mutator
  ... restored at :353-355, inside `finally`
tests/wave1MemoryPrivilegesPostgres.integration.test.ts:188-219,338-345  (apply/revert pairs)
tests/wave1MemoryHoldErasurePostgres.integration.test.ts:2538, 5184
```

The watchdog's own hang handling **SIGKILLs the process group**
(`scripts/test-watchdog.mjs:321-338`; run 1 recorded
`processGroup: {killedSurvivors: true, survivedSigkill: false}`), and a SIGKILLed worker
never runs its `finally`. A run that the watchdog correctly kills can therefore leave the
**shared** database with production grants revoked, and the next run inherits it. That
matches the `storage_rejected` / "the honest bind must succeed first" signature exactly.

I could **not** confirm this from current state, and I say so rather than implying it: by
the time I looked, the database had self-healed (a later run's `finally` restored
everything). Checked live:

```
 memory_mutation_receipts -> reconciler | t
 memory_pii_key_erasures  -> mutator    | t
 memory_tombstones        -> reader     | t
 memory_alias_bindings    -> reconciler | f   (correct baseline — not granted by default)
 CREATE ON SCHEMA public  -> reader     | f   (correct baseline)
 CREATE ON DATABASE       -> mutator    | f   (correct baseline)
```

and no leftover attacker artifacts (protocol trap 6): 0 rows for schemas
`opsched, aaliyah_memory_mutator, operator_choice, d2_shadow, w23_probe`; 0 rows for roles
`attacker_app, aaliyah_k07b_probe`. My database was also clean at the start (0 tables in
`public` before run 1).

**ENVIRONMENTAL CONFOUND, disclosed.** The host carried load averages of 13.6–47.9 on 14
CPUs throughout, with five other reviewer environments running suites concurrently
(`docker ps` shows `aaliyah-w13-rv5-{test,sec,rel,red,int,data}`, all up). Timing-window
assertions in `tests/wave1PoolResiliencePostgres.integration.test.ts` are directly exposed
to this — `assert.ok(elapsed < MAIL_DB_POOL_BOUNDS.lockTimeoutMs + 5_000)` (:185), a boot
deadline of `Date.now() + 25_000` (:339), and a **two-sided** window
`elapsed >= queryTimeoutMs - 1_000 && elapsed < queryTimeoutMs + 10_000` (:661-665). Under
contention these cannot hold. I therefore attribute the *pool-resilience* failures to host
load with high confidence.

I do **not** extend that excuse to run 2's 168 failures: a permission-shaped
`storage_rejected` avalanche and a `consumed_after_issue` CHECK violation are not what CPU
starvation looks like, and the same 964 tests passed under the same load minutes earlier.

**What this means for the gate.** Whatever the cause, the operative fact is the one the
founder's own rule names: *a nondeterministic test in a security suite is a defect until
its cause is named.* Here 168 of them are nondeterministic and the cause is **not** named
in the register. Worse for this gate specifically: a suite that yields 1 failure on one run
and 169 on the next trains its reviewers to re-run until green, which is the exact
mechanism by which a real defect gets laundered as a flake — and that is how the migrator
race survived three candidates.

**What assertion should have caught it and did not.** Nothing in the suite, the watchdog or
the guards asserts that the database is in its post-migration baseline state *before* a run
begins. The watchdog probes only `SELECT 1` (`scripts/test-watchdog.mjs:290-310`). A
pre-flight ACL/state fingerprint compared against a freshly-migrated baseline would turn an
inherited-contamination run into a named `BLOCKED_BY_ENVIRONMENT` instead of 168 mystery
failures — and would have made this diagnosable rather than arguable.

**Blocking: yes** (Critical). Independently of attribution, **I never observed
`1088/1088`, in 5 attempts.**

## Destroyer verification — do the claimed detectors actually discriminate?

Every mutation below was: `sha256` backed up → applied → judged with the protocol's
mutant-judging bounds (`--deadline-ms 240000 --test-timeout-ms 60000 --exit-grace-ms
10000`) against the TARGETED file only → restored → `sha256` verified byte-identical →
`git status --porcelain` verified empty. `HEAD` never moved.
Database recreated clean (`DROP DATABASE … WITH (FORCE); CREATE DATABASE`) before this
section; `information_schema.tables` in `public` = 0 at the start.

**Targeted baseline, clean database, pristine source:**

```
WATCHDOG VERDICT: PASS scope=FOCUSED tests=18 pass=18 fail=0 cancelled=0 skipped=0 todo=0
```

### D1 — K-06c · the advisory lock · **KILLED, with a NAMED failure, not a hang** ✅

The mandate's exact instruction: delete the advisory lock from
`src/persistence/postgres/migrations.ts` and show `K-06c` produces a named failure.

```
$ git diff --stat
 src/persistence/postgres/migrations.ts | 1 -
 1 file changed, 1 deletion(-)

@@ -6275,7 +6275,6 @@ export async function runMailMigrations(
-    await bounded("SELECT pg_advisory_lock(hashtextextended($1, 0))", [LEDGER_LOCK_KEY]);
     await createLedgerToleratingARace(bounded);
```

```
✖ K-06c: migrators SERIALIZE on the advisory lock before the ledger exists (6200.268875ms)
  AssertionError [ERR_ASSERTION]: no migrator ever waited on the ledger advisory lock — the runner is not taking it
      at tests/wave1MigrationReplayPostgres.integration.test.ts:324:14
    code: 'ERR_ASSERTION', actual: false, expected: true

WATCHDOG VERDICT: FAIL scope=FOCUSED tests=18 pass=17 fail=1 cancelled=0 skipped=0 todo=0
  reason: NONZERO_EXIT: code=1 signal=null
  reason: FAILED_TESTS: 1
  reason: PASSED_NOT_EQUAL_TESTS: 17 of 18
  reason: RUNNER_REPORTED_UNSUCCESSFUL
```

**`cancelled=0`, no `TIMED_OUT`, no `HUNG_WORKER`, whole run 9891ms.** This is a named
assertion failure, not a hang and not a timeout — precisely what the two earlier versions
of K-06c could not produce. **The current K-06c is a real control.** Confirmed
independently of gate 3/6's MUT-1.

Restored:
```
f40cda6a27b67ddb48da0fe874cfb006d31cec692b7a1522c3cda255b744c416  src/persistence/postgres/migrations.ts
f40cda6a27b67ddb48da0fe874cfb006d31cec692b7a1522c3cda255b744c416  .../migrations.ts.PRISTINE
$ git status --porcelain
(empty)   $ git rev-parse HEAD -> e71b51e9ed333d1feab1cd6819496269d201a6e2
```

### D2 — K-06b · the tolerated-SQLSTATE set · **KILLED, with a NAMED failure** ✅

```
-const LEDGER_RACE_LOST = new Set(["42P07", "23505", "42710"]);
+const LEDGER_RACE_LOST = new Set(["42P07", "23505"]);
```

```
✖ K-06b: each SQLSTATE a lost ledger race can raise is tolerated, and only when the ledger really appeared (0.351875ms)
  Error: already exists (42710)
      at createLedgerToleratingARace (src/persistence/postgres/migrations.ts:6174:11)
    code: '42710'

WATCHDOG VERDICT: FAIL scope=FOCUSED tests=18 pass=17 fail=1 cancelled=0 skipped=0 todo=0
```

Named, immediate (0.35ms), `cancelled=0`. **Real control.** Restored byte-identical,
`git status --porcelain` empty.

### D3 — pool.ts's K-05 guard · gate 3/6's explicitly-declared gap · **KILLED — but its companion test HANGS instead of reporting** ⚠️

`reviews/06-mutation-fuzz.md:208-211` names this as coverage it did **not** perform
("Did not mutate `pool.ts`'s K-05 ambiguous-connection-destruction guard itself"). It
therefore falls to me. I deleted the guard outright:

```
--- a/src/persistence/postgres/pool.ts
+++ b/src/persistence/postgres/pool.ts
@@ -223,7 +223,7 @@ export function releaseClient(
-  client.release(error !== undefined && isConnectionAmbiguous(error) ? true : undefined);
+  client.release(undefined);
```

Result against `tests/wave1PoolResiliencePostgres.integration.test.ts`:

```
✖ K-05: an AMBIGUOUS connection is DESTROYED, and an ordinary error's connection is not (1.576375ms)
      not destroyed: Query read timeout
      + actual - expected     [ + undefined   - true ]

✖ a STORE that connects and releases by hand destroys an ambiguous client too, not just pool.query (195775.205083ms)

WATCHDOG VERDICT: FAIL scope=FOCUSED
  reason: HUNG_WORKER: a timeout occurred and the run produced no further events for 10000ms
  reason: TIMED_OUT: tests/wave1PoolResiliencePostgres.integration.test.ts :: a STORE that connects and releases by hand destroys an ambiguous client too, not just pool.query
  reason: TESTS_NEVER_FINISHED: tests/wave1PoolResiliencePostgres.integration.test.ts queued=17 finished=16
  reason: NO_SUMMARY: the runner never reported final counts
```

`K-05` itself is a **real control**: named failure, 1.58ms. Gate 3/6's declared gap is now
closed, and it closes green. Restored byte-identical
(`043ddceb8aa5fd834608660db1a897f7488238c5050c0a8c6ede35fd27d0878d`),
`git status --porcelain` empty.

Two things that fall out of this, recorded as F6 and N3 below.

### F6 · Important · `EARLY_ABORT` / detector buries its own diagnosis — the hand-release test reports a HANG, never its assertion

**The defect in one sentence.** When the K-05 guard is removed, the test written
specifically for the hand-release path (`tests/wave1PoolResiliencePostgres.integration.test.ts:584`,
guarding a CRITICAL-severity finding across six persistence modules and twelve call sites)
does not report its assertion — it **deadlocks in its own `finally`**, times out at 195 s
against a 90 s bound, and surfaces only as `HUNG_WORKER` with **no named failure**.

**Mechanism, at the candidate SHA**
(`tests/wave1PoolResiliencePostgres.integration.test.ts:626-636`):

```ts
    // THE ASSERTION. The store released by hand; the client must be GONE.
    assert.equal(
      pool.idleCount,
      0,
      `an ambiguous client was returned to the pool by a hand-written release (idle=${pool.idleCount})`,
    );
    assert.ok(isConnectionAmbiguous(new Error("Query read timeout")));
  } finally {
    await pool.end().catch(() => undefined);
    await proxy.close();
  }
```

The assertion fails exactly when the ambiguous client was **returned to the pool** — which
is the only state in which `pool.end()` must wait for that client. The client's socket is
wedged by `proxy`, and `proxy.close()` is sequenced *after* `pool.end()`, so nothing can
ever unwedge it. `pool.end()` never resolves, the assertion's message is never emitted, and
`.catch(() => undefined)` guarantees the hang is silent.

**EXECUTED reproduction:** D3 above. `✖ … (195775.205083ms)` with
`TIMED_OUT` / `HUNG_WORKER` / `NO_SUMMARY`, while the assertion's own text
(`an ambiguous client was returned to the pool by a hand-written release`) appears **nowhere**
in the output or in `failures[]` — the watchdog filed it under `timedOut`, not `failures`.

**This is the exact defect the repository already diagnosed and fixed once, in K-06c, and
did not fix here.** `tests/wave1MigrationReplayPostgres.integration.test.ts:275-279`:

> "Released ONLY on the happy path, a failed assertion left this client checked out and
> `holder.end()` waited on it for ever — which is why removing the lock produced
> HUNG_WORKER with no named failure instead of the assertion's own message. The control
> worked; its cleanup buried the diagnosis."

and `:337-341`:

> "Order matters: release the lock so a waiting migrator can finish, hand the client back
> so the pool can close, and only then drain — otherwise a failed assertion strands one of
> the three and the test hangs instead of reporting."

K-06c applies that rule. `wave1PoolResiliencePostgres.integration.test.ts:633-636` does
not: it drains before it unwedges. The lesson was written down and not propagated to the
sibling control.

**What assertion should have caught it and did not.** The test does have a correct
assertion — it simply cannot be *heard*. The fix is ordering, not a new assertion:
`await proxy.close()` before `await pool.end()`, as K-06c orders its own teardown.

**Why this is Important and not Low.** Protocol trap 3 exists because "a hang produces
FAIL with ZERO failure entries; judging by the list alone reports 'nothing failed' for a
mutant that WAS detected." A reviewer judging this file by `failures[]` — which is
precisely what happened to the migrator race across three candidates — sees *nothing*.
And this same hang is what consumed run 1 of my baseline (607 s) and run 5's
`TESTS_NEVER_FINISHED`, so in practice it is the suite's single largest source of
undiagnosable FAILs. **Blocking: yes.**

### N3 · Info — the "structural" guard cannot see the guard itself being gutted

Under D3's mutation, `NO pooled client in src/ is released without the ambiguity guard —
structural, so the class cannot come back` **PASSED** (25.27 ms). That is correct
behaviour — it audits *call sites*, and I changed the callee's body — but it means the
class it claims "cannot come back" can come back through the one door it does not watch.
`K-05` is the only detector for the guard's body, and per F6 its companion cannot report.
Not a defect; recorded so the pair is not mistaken for defence in depth.

## Mandate 3 — the assertion-reachability tool

**Its own negative controls, executed:**

```
$ node scripts/test-watchdog.mjs --no-db ... tests/assertionReachability.test.ts
✔ the reachability sweep REPORTS an assertion that can never run (465.985333ms)
✔ the reachability sweep does NOT report an assertion that runs (632.082417ms)
✔ the reachability sweep REFUSES to report when the run had failures (795.292292ms)
WATCHDOG VERDICT: PASS scope=FOCUSED tests=3 pass=3 fail=0 cancelled=0 skipped=0 todo=0
```

**Destroyer-verified against the two historical blindness mechanisms** — I did not take the
`NODE_TEST_CONTEXT` strip on trust, I attacked it:

```
$ node scripts/assertion-reachability.mjs tests/reachability-fixtures/probe.fixture.ts
trace sites recorded: 1
probe.fixture.ts      1 NEVER EXECUTED
    :16  assert.equal(1, 2, "UNREACHABLE: this line must be reported");
assertions examined : 2 / never executed : 1        EXIT=1

$ NODE_TEST_CONTEXT=child-v8 node scripts/assertion-reachability.mjs tests/reachability-fixtures/probe.fixture.ts
    ... identical output, EXIT=1        <- the strip at assertion-reachability.mjs:93-101 works

$ NODE_OPTIONS="--test-skip-pattern=reachability" node scripts/assertion-reachability.mjs tests/reachability-fixtures/probe.fixture.ts
    ... identical output, EXIT=1        <- NODE_OPTIONS deselection cannot blind it
```

It examined 2 and reported 1 — so it neither under- nor over-reports. **The tool is sound
and its negative controls are real.**

**The sweep over the migrator hardening test:**

```
$ node scripts/assertion-reachability.mjs tests/wave1MigrationReplayPostgres.integration.test.ts
trace sites recorded: 49
wave1MigrationReplayPostgres.integration.test.ts        CLEAN
assertions examined : 49 / never executed : 0        EXIT=0
```

**CLEAN — and that is exactly the false comfort the mandate warned about.** Three of those
49 assertions are the ones F3 proves cannot discriminate (`:58` `n >= 42`, `:718`/`:823`
`n == d` under a PRIMARY KEY, `:719`/`:824` `n >= 56`/`>= 54`). They *execute*; they cannot
*fail*. The tool documents this limit at `scripts/assertion-reachability.mjs:22-25`, and
this sweep is a live demonstration that a CLEAN sweep is not evidence of falsifiability.

## Subject verified AFTER all work (not trusted)

| field | claimed | verified AFTER | how |
|---|---|---|---|
| HEAD | e71b51e9ed333d1feab1cd6819496269d201a6e2 | MATCH, never moved | `git rev-parse HEAD` |
| tree | — | 5af8080da732f8b4c4afd6b81337ab4a88b06950, unchanged | `git rev-parse HEAD^{tree}` |
| core `git status --porcelain` | — | **empty** | run after every restore and at the end |
| contracts | 7d576681d1001eb4c4a7f044f7793cdb3f80af76 | MATCH, clean | `git -C ../aaliyah-wave1-contracts rev-parse HEAD` + status |
| contracts provenance | 8/8 guard | PASS, tree `a34af636b5ce62dbb2830a8a7b716816f42ea041` | `bash scripts/ci-guards.sh` |
| guards | 8/8 | **8/8 PASS, `RELEASE GUARDS: PASS`** — verified twice, before and after all mutation activity | `bash scripts/ci-guards.sh` |
| baseline suite | 1088/1088 fail 0 skip 0 todo 0 cancelled 0 | **NOT REPRODUCED in 5 attempts** (see Baseline section) | 5× `node scripts/test-watchdog.mjs` at the watchdog's own defaults |
| declared denominator | 1088 | **CONFIRMED 1088** (run 3: `tests=1088 … skipped=0 todo=0 cancelled=0`) | run-3 evidence `counts` |
| stray databases | — | only `aaliyah_test`; my `aaliyah_g1_scratch` dropped | `SELECT datname FROM pg_database WHERE datname LIKE 'aaliyah%'` |
| attacker artifacts (trap 6) | — | **none** — 0 of `opsched, aaliyah_memory_mutator, operator_choice, d2_shadow, w23_probe`; 0 of roles `attacker_app, aaliyah_k07b_probe` | `pg_namespace` / `pg_roles` |
| scratch files in worktree | — | none | `ls scratch-*` |

Rollback: 3 source mutations (2 × `migrations.ts`, 1 × `pool.ts`), each restored from a
pre-mutation copy and verified byte-identical by `sha256`, with `git status --porcelain`
empty after each. I killed only my **own** processes, matched by my session id in the
`--evidence` path; 3 other reviewers' watchdogs were running at that moment and were left
untouched.

## Gate accounting object (final)

```json
{
  "candidateSha": "e71b51e9ed333d1feab1cd6819496269d201a6e2",
  "gate": "TEST_TRUTH",
  "accounting": {
    "required": 1088,
    "executed": "1088 in 1 of 5 runs; NO SUMMARY EMITTED in the other 4",
    "passed": "1087 (best run); 795-of-964 at worst",
    "failed": "1, 2, 168, 169 across runs — never 0",
    "skipped": 0, "cancelled": 0, "neutral": 0, "todo": 0,
    "stale": 0,
    "notVerified": "the claimed 1088/1088 green state — never observed"
  },
  "determinism": { "reruns": 5, "stable": false },
  "discrimination": {
    "mutationProofPresent": true,
    "source": "reviews/06-mutation-fuzz.md at e71b51e (same SHA — binding valid)",
    "survivors": 0,
    "independentlyReVerifiedByMe": ["K-06c", "K-06b", "pool.ts K-05 (gate 6's declared gap)"]
  },
  "verdict": "BLOCK",
  "blocking": true
}
```

`skipped/cancelled/todo` are genuinely **0** — I found no hidden skips, no `.skip`, no
`.only`, no `todo` in test registration anywhere in the 84 tracked test files, and the
discovery binding reported `boundToCommit: true, ignored: [], untracked: [], missing: []`
on every run. That part of the accounting is exact and clean.

## Findings summary

| id | severity | class | blocking |
|---|---|---|---|
| F1 | Important | `VACUOUS_ASSERTION` | yes |
| F2 | Important | `FALSE_DENOMINATOR` | yes |
| F3 | Important | `NEGATIVE_CONTROL_WEAK` + `VACUOUS_ASSERTION` | yes |
| F4 | Low | stale evidence | no |
| F5 | **Critical** | `NONDETERMINISTIC` | yes |
| F6 | Important | `EARLY_ABORT` / diagnosis buried | yes |
| N1, N2, N3 | Info | negative findings (no defect) | no |

## What I did NOT cover — named, so nobody inherits a false all-clear

- **I ran 5 full-suite runs, not the ≥5 *clean* runs my mandate asked for — because none of
  the 5 was clean.** Only run 3 emitted a summary. The determinism diff is therefore over
  2 complete name sets (964 names, byte-identical) plus run 3's superset, not over 5.
- **The 1086/1087 discrepancy remains OPEN.** I reproduced its exact arithmetic signature
  from the repository's own `hookSentinel.cjs` (F2) and observed the sentinel firing in the
  wild (run 5 records `tests/support/hookSentinel.cjs` as a failing file 3 times). I did
  **not** reproduce run A itself, and I did not close the item. I demoted the register's
  hypothesis; I did not replace it with a proof.
- **I did not isolate the cause of run 2 / run 5's 168–169 failures.** I named a leading
  mechanism (SIGKILLed `finally` blocks leaving the shared database's grants revoked) and
  explicitly flagged it as inference. A reviewer with budget should revoke
  `SELECT ON memory_mutation_receipts FROM aaliyah_memory_reconciler` by hand and re-run
  `wave1AliasRegistryPostgres.integration.test.ts` — that is a 3-minute decisive test I did
  not have room for.
- **The host was under load averages of 3.5–47.9 on 14 CPUs throughout**, with five other
  reviewer environments active. I could not obtain a quiet host. Every timing-sensitive
  result is caveated in place.
- **I did not mutate S-2e (SEC-02) or S-6b (SEC-03)** — gate 3/6's other two declared gaps.
  I closed only the first of the three it named (pool.ts K-05, D3). SEC-02/SEC-03 remain
  observed-but-not-mutated by *both* gates.
- **I did not sweep assertion-reachability over the large integration files**
  (`wave1MemoryHoldErasurePostgres`, `wave1TrustedMemoryPostgres`, `wave1AliasRegistry…`) —
  the tool refuses to report when any test fails, and those files did not run clean. Only
  `wave1MigrationReplayPostgres` was swept. **The K-07 family was NOT swept**; F1 was found
  by reading and proved by SQL, not by the tool.
- **I did not audit the remaining 33 "fixture precondition" assertions individually.** I
  enumerated all 34, read them, and pursued the one (F1) that carried its claim in a
  comment rather than an assertion message. The other 33 looked falsifiable on reading;
  that is reading, not execution.
- **W1BR-014 (named review subject 3)** — I ran its three tests as part of the targeted
  migration file (18/18 PASS at baseline) but did **not** attack them. No independent
  opinion from me.
- **The closure audit (named review subject 4)** — I verified the rule was honoured for the
  advisory lock (deleted in `97bb476`, restored in `c2e5747`, now covered by a detector
  that genuinely kills: D1). I did not audit the other closures in the register.
- **I did not re-run the mutation sweep** (gate 6 owns it). Its proof is at the same SHA, so
  its binding is valid; I re-verified three of its subjects and closed one of its gaps.

## VERDICT

**BLOCK · blocking: true**

Six findings, one Critical (F5) and four Important (F1, F2, F3, F6). Any one of F1, F3, F5
or F6 keeps W1.3 RED on its own.

The gate question was not "do the tests pass" but "would these tests FAIL if the behaviour
they claim were broken". The answer is mixed and the mixture is the finding:

- **Where the candidate is strong, it is genuinely strong.** K-06b, K-06c and pool.ts's
  K-05 guard are real controls — I deleted each and each produced a named, immediate
  failure (D1, D2, D3). The watchdog's anti-hang machinery works: it called every hang
  FAIL, never PASS, killed its process groups, and its discovery binding held
  (`boundToCommit: true`, `missing: []`) on every run. `skipped`, `cancelled` and `todo`
  are honestly zero. The assertion-reachability tool is sound and survives both historical
  blindness attacks. The alias-registry fixture's attack-enabling GRANT is genuinely gone.
- **But the suite cannot currently demonstrate that green means green.** I never observed
  `1088/1088` in five attempts, and two runs turned 168–169 of an *identical* executed set
  from pass to fail (F5). A suite whose outcome varies that widely trains reviewers to
  re-run until green — the exact mechanism by which the migrator race survived three
  candidates and was ultimately caught by a flake rather than by a gate.
- **And the builder's named standing weakness is still live, four times over.** F1 is the
  **fourth** non-falsifiable assertion in the K-07 family, exactly as predicted. F3 shows
  the migrator's own completeness controls cannot notice 18 of 60 migrations — including
  055, 058, 059 and 060 — silently never applying, while the assertion whose message reads
  *"every migration must have applied"* passes. F6 shows the lesson written down in K-06c's
  own comments ("its cleanup buried the diagnosis") was not propagated to the sibling
  control guarding a CRITICAL finding. And F2 shows the denominator that all of this is
  measured against is pinned by nothing at all.

The assertion-reachability sweep reported `CLEAN` on the very file whose three weakest
assertions F3 falsifies. That is the single most useful sentence in this report: **a clean
reachability sweep, a passing suite and a green mutation gate are jointly insufficient**,
and this candidate is the proof.

This is ONE gate. I do not certify. AEGIS Ω-MAX adjudicates the worst verdict across all
gates and cannot be overridden.
