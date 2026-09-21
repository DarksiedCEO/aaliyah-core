# W1.3 R1 — OVERNIGHT BUILDER REPORT

    session     builder, sole writer on wave1/w13-trusted-memory
    started     2026-09-20 21:31 PDT     stopped  2026-09-20 ~22:20 PDT
    base        f6bb3ab (work order blob 0904da9e… verified)
    database    builder's own PostgreSQL 16.14 container aaliyah-w13-r1, 127.0.0.1:54610
    evidence    aaliyah-w13-evidence/r1/   (runs/INDEX.tsv lists every run)
    register    docs/WAVE1_BLOCKER_REGISTER.md, section "R1 — OVERNIGHT BUILDER RUN"

## WHY I STOPPED

**The R1.2 premise did not reproduce, and the work order says to stop in that case**
(R1.2 step 1: *"If it does not, stop and report — the root cause is elsewhere and R1.5
becomes primary."*). I stopped under the rule after about 50 minutes, not because the
five-hour budget ran out.

## STEP 0 — INTEGRITY: PASSED

    git rev-parse HEAD:docs/W13_R1_WORK_ORDER.md = 0904da9ee3782807fa6189cd8d818da750023c2e
    HEAD = f6bb3ab (branch wave1/w13-trusted-memory)
    git ls-files -v lines with a lowercase tag: 0
    git status --porcelain: empty

## R1 ITEMS

| item | status | commits |
|---|---|---|
| R1.1 release before assert / bounded end | **DONE, proven by forced failure** | `fe78fd0` fix, `7cbc691` proof |
| R1.2 harness refuses a used database | **STOPPED: premise did not reproduce** | evidence only |
| R1.3 pinned manifest | drafted, **never executed**, not in the tree | `wip/…UNEXECUTED.patch` |
| R1.4 full LEDGER_RACE_LOST set | drafted, **never executed**, not in the tree | same patch |
| R1.5 57P01 root cause | **issuer named and reproduced in isolation**; not fixed | evidence only |
| R1.6 vacuous discovery / fixed /tmp path | drafted, **never executed**, not in the tree | same patch |
| Driver | `98321de` | measurement driver used for every run |

### R1.1 — executed proof

    BEFORE 98321de, K-05 inverted       WATCHDOG VERDICT: FAIL scope=FOCUSED
        HUNG_WORKER · NO_SUMMARY · K-05 timed out at 240002ms · failures[] EMPTY
    AFTER fe78fd0, K-05 assert.fail     WATCHDOG VERDICT: FAIL scope=FOCUSED tests=17 pass=16 fail=1 cancelled=0 skipped=0 todo=0
        reported in 8.68ms, message in failures[]
    AFTER fe78fd0, gate 1 D3 mutant     WATCHDOG VERDICT: FAIL scope=FOCUSED tests=17 pass=15 fail=2 cancelled=0 skipped=0 todo=0
        F6's own message at 70s; gate 1 saw a 195s hang with no message

## THE 2×2 — ONLY THE SERIAL COLUMN WAS MEASURED, AS A PREMISE CHECK

These are **premise runs at `7cbc691`, not R1 acceptance runs.** Acceptance was
**not reached.** The concurrent column was **not run**, because the run rules forbid
a suite running alongside another suite.

| | pristine | used |
|---|---|---|
| **serial** | P1 `WATCHDOG VERDICT: FAIL scope=FULL_SUITE tests=1088 pass=1087 fail=1 cancelled=0 skipped=0 todo=0` | U1 `WATCHDOG VERDICT: FAIL scope=FULL_SUITE tests=1088 pass=1087 fail=1 cancelled=0 skipped=0 todo=0`<br>U2 `WATCHDOG VERDICT: PASS scope=FULL_SUITE tests=1088 pass=1088 fail=0 cancelled=0 skipped=0 todo=0` |
| **concurrent** | not run (rule) | not run (rule) |

**R1 acceptance cells:** pristine ×5: **not reached**. Used ×5: **not reached**.

Diagnostic runs, **not premise or acceptance data**. They ran on a used database with
an instrumented test file in a disposable worktree, so `git.dirty` is true:

    D1 WATCHDOG VERDICT: PASS scope=FULL_SUITE tests=1088 pass=1088 fail=0 cancelled=0 skipped=0 todo=0
    D2 WATCHDOG VERDICT: PASS scope=FULL_SUITE tests=1088 pass=1088 fail=0 cancelled=0 skipped=0 todo=0
    D3 WATCHDOG VERDICT: FAIL scope=FULL_SUITE tests=1088 pass=1087 fail=1 cancelled=0 skipped=0 todo=0

The denominator was 1088 in every run.

## PREMISES

| premise | tier | result |
|---|---|---|
| I-9: a used database changes the verdict | EXECUTED-BY-GATE | **DID NOT REPRODUCE.** The only failure (K-02 probe1) hit pristine and used alike, and a used run passed. Tested only under "used = left by the previous run"; gate 5's database had been left by a killed run, which I did not test. |
| R-14: an unexplained 57P01 | EXECUTED-BY-GATE | **Mechanism reproduced and attributed.** The positive control's own `DROP DATABASE … WITH (FORCE)` kills its pools' still-open sockets after `end()` resolves. It has no `error` listener, so the error goes uncaught: 2 in 200 isolated iterations, matched 1:1 in the server log. Not seen failing a full suite tonight. |
| R-13/F6: K-05 hangs | EXECUTED-BY-GATE | **Reproduced** as a 240s hang before the fix. The cause of the underlying failure is new (see below). |
| Gate 3's reading: "the terminate does not land in time" | EXECUTED-BY-GATE | **Did not reproduce**: 0 of 800 terminated backends answered. The real cause is an unclassified pg error shape. |
| F2: synthetic +1 from a non-zero worker exit | EXECUTED-BY-GATE | **Reproduced** in a minimal harness (5+1+1 = 7). Never observed in a full run tonight. |
| R1.6: an empty set yields a vacuous PASS | VERIFIED-HERE | The code branch exists, but **the entrypoint cannot reach it**: `usage()` exits 2 first. |

## NEW FINDINGS

1. **K-05 depends on timing, through a production classifier gap.** After a backend is
   terminated, pg rejects the next query either with `57P01` or with the un-coded
   "Client has encountered a connection error and is not queryable". The second shape
   came up 13 times in 800. `isConnectionAmbiguous` in `pool.ts` does not classify it. pg-pool evicts that
   client anyway, so production is safe, but K-05 can fail. R1.1 turned that failure into a report
   instead of a hang. The fix needs a change to `pool.ts`, which R1 does not name.
2. **K-02 probe1 fails on another file's transaction.** It measures the oldest idle
   transaction in the whole database. The session caught when it failed was
   `UPDATE watchdog_fixture_78003 …`, from `tests/testWatchdog.test.ts`'s DB-blocking fixtures
   running in parallel on the same `aaliyah_test`. It failed 3 times in 6 full runs here, and is
   the only failure seen in any full run tonight.

## PUSHES

Every commit pushed; **no push was denied.**

## CLUSTER STATE LEFT BEHIND

- Container `aaliyah-w13-r1` is up on :54610, with `log_statement=ddl` set by ALTER SYSTEM.
  Databases: `aaliyah_test, postgres, template0, template1`.
- My worktrees: `~/aaliyah-w13-r1run/aaliyah-wave1-core` (clean at 7cbc691) and
  `~/aaliyah-w13-r1mut/aaliyah-wave1-core` (7cbc691 with the diagnostic patch applied,
  disposable).
- Docker Desktop was started (it was down). No other worktree or container was touched.
  The reviewer containers stay stopped.

## EXACT NEXT TASK

Andre's answer to Q1 decides it. If the answer is "treat K-02 probe1 and K-05 as R1-instrument items":
1. Apply `aaliyah-w13-evidence/r1/wip/R1.3-R1.4-R1.6-UNEXECUTED.patch` and run the
   watchdog's own tests. Generate the manifest with `--write-manifest` from a clean
   full run, then commit.
2. Scope K-02 probe1's two `pg_stat_activity` measurements to its own sessions (for example by
   `application_name`), or give the watchdog DB-fixture tests their own database.
3. Give the replay POSITIVE CONTROL's pools an `error` listener (R1.5), then rerun the
   isolated teardown probe to show the uncaught count is 0.
4. Decide `pool.ts` (Q2), then run R1 acceptance: 5 pristine plus 5 used.

## QUESTIONS ONLY ANDRE CAN ANSWER

1. **The I-9 premise did not reproduce, and the work order says stop.** Should R1 continue with
   R1.5 as primary, and should K-02 probe1's cross-file contamination (a test file R1 doesn't
   name) join R1's scope? Without that fix, five consecutive passes are unlikely: probe1 failed 3 times in 6.
2. **`pool.ts` `isConnectionAmbiguous`:** may it classify pg's "not queryable" error as
   ambiguous? It's a production change outside R1's named files. Without it, K-05 fails
   intermittently.
3. Should I-9 also be tested under gate 5's definition of "used", meaning a database left by a
   killed run?

W1.3 status: RED
