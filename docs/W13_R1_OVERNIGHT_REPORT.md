# W1.3 R1 — OVERNIGHT BUILDER REPORT

> **UPDATE 2026-09-21 ~05:10 — R1 ACCEPTANCE MET at `fa14db0`.** After the founder's
> answers (03:00) the run resumed. The section "CONTINUATION" at the end supersedes the
> status, 2×2 and next-task sections below it. Those sections are kept unedited as the
> record of the first stop.

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

(first stop, 2026-09-20 22:20: W1.3 status: RED)

---

## CONTINUATION — 2026-09-21 03:15 to ~05:10

Resumed on the founder's answers: (1) R1.5 is the main thread, and the K-02 probe1 fix is in
scope; (2) `pool.ts` may classify pg's exact "not queryable" error; (3) test I-9
after a killed run. Plus a new rule: a premise that fails to reproduce stops its own item only.

**A correction to the founder's note, applied.** The note described the 57P01 as K-02
probe1's. They're two separate defects: the 57P01 is the replay POSITIVE CONTROL's own
FORCE-drop (R1.5), and K-02 probe1 is cross-file contamination. Both fixed, both test-only.

### R1 ITEMS — FINAL

| item | status | commits |
|---|---|---|
| R1.1 | DONE, forced-failure proof | `fe78fd0`, `7cbc691` |
| R1.2 | **I-9 CLOSED, NOT REPRODUCED** (clean-used and killed-used); refusal not built | `fd71d4d`, `fa14db0` |
| R1.3 | DONE: manifest of 1098, refusals; 9 of 9 mutants killed (M7 needed a new detector) | `f54adc1`, `27b545e`, `d0b4c14`, `565d6d3` |
| R1.4 | DONE: asserted against the exported production set; 23505-drop mutant killed | `f54adc1`, `d0b4c14` |
| R1.5 | DONE: listeners where missing; 0 uncaught with 4 terminations absorbed (was 2 of 2 uncaught) | `d65cb05` |
| R1.6 | DONE: DISCOVERY_VACUOUS; private temp file; guard 8 PASS | `f54adc1` |
| K-02 probe1 | DONE: scoped by application_name; old fails on contamination, new catches its own held transaction | `7eadfa1`, `3859022` |
| **pool.ts (production)** | DONE: exact shape only; K-05b kills both the "unrecognised" and the "widened" mutant | `fd7432a`, `e045070` |

### BOTH ACCEPTANCE CELLS — at `fa14db0`, verbatim

Serial, quiet host (load 1.8–3.0), clean tree, executed set equal to the committed manifest
in every run (1098 executed, 1098 pinned, 0 added, 0 lost, 0 synthetic entries):

| # | pristine | used |
|---|---|---|
| 1 | `WATCHDOG VERDICT: PASS scope=FULL_SUITE tests=1098 pass=1098 fail=0 cancelled=0 skipped=0 todo=0` | `WATCHDOG VERDICT: PASS scope=FULL_SUITE tests=1098 pass=1098 fail=0 cancelled=0 skipped=0 todo=0` |
| 2 | `WATCHDOG VERDICT: PASS scope=FULL_SUITE tests=1098 pass=1098 fail=0 cancelled=0 skipped=0 todo=0` | `WATCHDOG VERDICT: PASS scope=FULL_SUITE tests=1098 pass=1098 fail=0 cancelled=0 skipped=0 todo=0` |
| 3 | `WATCHDOG VERDICT: PASS scope=FULL_SUITE tests=1098 pass=1098 fail=0 cancelled=0 skipped=0 todo=0` | `WATCHDOG VERDICT: PASS scope=FULL_SUITE tests=1098 pass=1098 fail=0 cancelled=0 skipped=0 todo=0` |
| 4 | `WATCHDOG VERDICT: PASS scope=FULL_SUITE tests=1098 pass=1098 fail=0 cancelled=0 skipped=0 todo=0` | `WATCHDOG VERDICT: PASS scope=FULL_SUITE tests=1098 pass=1098 fail=0 cancelled=0 skipped=0 todo=0` |
| 5 | `WATCHDOG VERDICT: PASS scope=FULL_SUITE tests=1098 pass=1098 fail=0 cancelled=0 skipped=0 todo=0` | `WATCHDOG VERDICT: PASS scope=FULL_SUITE tests=1098 pass=1098 fail=0 cancelled=0 skipped=0 todo=0` |

The used cell passed. The I-9 hypothesis is falsified, and the harness does not enforce pristine.
The server log shows 80 terminations across the ten runs, 8 per run, every one deliberate.

### I-9 AFTER A KILLED RUN (gate 5's condition)

    kill@45s  -> WATCHDOG VERDICT: PASS scope=FULL_SUITE tests=1098 pass=1098 fail=0 cancelled=0 skipped=0 todo=0
    kill@90s  -> WATCHDOG VERDICT: PASS scope=FULL_SUITE tests=1098 pass=1098 fail=0 cancelled=0 skipped=0 todo=0
    kill@150s -> WATCHDOG VERDICT: PASS scope=FULL_SUITE tests=1098 pass=1098 fail=0 cancelled=0 skipped=0 todo=0

The residue was real: 60 ledger rows and 99 record versions after the 45s kill.

### THE DENOMINATOR

1098 = 1088 (candidate-4) + 9 new watchdog tests + K-05b. It's now pinned, and a
delta is a named refusal.

### PUSHES

Every commit pushed. None denied.

### NOT COVERED BY R1 (also in the register)

- The concurrent column of the 2×2, never run by rule.
- `boundToCommit` still ignores `untracked` (R4).
- `/tmp/frozen.out` and `/tmp/contracts-provenance.out` (R4.3).
- pool-resilience `adminPool` has no client-side bound.
- Gates 1–3 at the new SHA (R4.2).

### STATE LEFT FOR THE REVIEW SIDE

Container `aaliyah-w13-r1` (:54610) and worktrees `~/aaliyah-w13-r1run` (clean at `fa14db0`)
and `~/aaliyah-w13-r1mut` (disposable) are kept as evidence, per the founder. Tear down after
review.

### NEXT

Candidate-5 is declared by the review side, not here. It's a **production-code descendant**
(`pool.ts`), so full gates 1–3 run on the review side under R4.2, then the seven gates, then
adjudication. R2–R4 remain.

R1 acceptance: MET at fa14db0; W1.3 status: RED pending R2–R4
