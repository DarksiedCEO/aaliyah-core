# COORDINATOR NOTE — W1.3 candidate-4 review round

Written by the dispatching session, NOT by any gate. It records how the round was run,
what the coordinator measured itself, and where the gates disagree. It is not a verdict
and it is not evidence about the candidate except where it says "measured".

    subject      e71b51e9ed333d1feab1cd6819496269d201a6e2  (tag w13-candidate-4)
    contracts    7d576681d1001eb4c4a7f044f7793cdb3f80af76
    dispatched   2026-09-20, seven gates, six newly run

## Method

Six gates were dispatched CONCURRENTLY, each into its own detached worktree at the
candidate SHA plus its own PostgreSQL 16 container, built by
`aaliyah-w13-evidence/tools/mkenv.sh`:

    gate 1  test falsifiability   /Users/andrelove/aaliyah-w13-rv5-test   port 54601
    gate 2  security              /Users/andrelove/aaliyah-w13-rv5-sec    port 54602
    gate 3  reliability           /Users/andrelove/aaliyah-w13-rv5-rel    port 54603
    gate 4  red team              /Users/andrelove/aaliyah-w13-rv5-red    port 54604
    gate 5  integration           /Users/andrelove/aaliyah-w13-rv5-int    port 54605
    gate 7  data & persistence    /Users/andrelove/aaliyah-w13-rv5-data   port 54606

Gate 6 (mutation/fuzz, `06-mutation-fuzz.md`) was NOT re-run — it already existed at this
SHA from an earlier dispatch. It was handed to the others as an input.

**Gate 7 is a coordinator inference, not a founder designation.** The handoff says "seven
reviewers" but only six gate files (01-06) have ever existed on this branch. The
coordinator assigned the seventh to data & persistence integrity, and gave it the
CHECK-constraint drop-test audit the handoff flags as a pending founder deliverable. If
the intended seventh was something else, that gate has not been run.

## What the CONCURRENCY cost, stated plainly

Six gates at once drove host load to **76 on 14 CPUs**. This is the coordinator's doing,
not the candidate's. Consequences the gates recorded:

- Gate 1's F5 (Critical, nondeterminism) ran at load 3.5-47.9 and disclosed it in place.
- Gate 4's first baseline hit `DEADLINE_EXCEEDED` at the watchdog's own 900 s default
  (1,103,864 ms) against 270,492 ms unloaded. Environment-attributed by that gate.
- Gate 5's I-4 records that `ci-guards.sh` uses FIXED `/tmp` filenames, so concurrent
  guard runs can collide. Every "guards 8/8" observed during the concurrent window is
  therefore weaker evidence than it looks.

Two measurements were re-run by the coordinator afterwards, alone, on a quiet box.

## Coordinator measurement 1 — release guards, run alone

    cd /Users/andrelove/aaliyah-w13/aaliyah-wave1-core && bash scripts/ci-guards.sh
    -> 8 PASS lines, RELEASE GUARDS: PASS, exit 0        (load 3.09, nothing else running)

I-4 did not produce a false green here. Note what this does and does not mean: guard 8 is
"the full suite's executed set is bound to the commit", and gate 4's RT4-5 demonstrated
that `--verify-discovery` — which IS guard 8 — prints `WATCHDOG VERDICT: PASS` and writes
`verdict: "PASS", counts: null` while running ZERO tests. Guard 8 passing is not evidence
that a suite ran.

## Coordinator measurement 2 — serial determinism probe

Three full-suite runs, one at a time, watchdog's OWN defaults (trap 4), **database
DROPped and re-CREATEd before each run**, load 3.8-5.4 throughout:

    RUN 1  WATCHDOG VERDICT: PASS scope=FULL_SUITE tests=1088 pass=1088 fail=0 cancelled=0 skipped=0 todo=0
    RUN 2  WATCHDOG VERDICT: PASS scope=FULL_SUITE tests=1088 pass=1088 fail=0 cancelled=0 skipped=0 todo=0
    RUN 3  WATCHDOG VERDICT: PASS scope=FULL_SUITE tests=1088 pass=1088 fail=0 cancelled=0 skipped=0 todo=0

    HEAD e71b51e before and after; `git status --porcelain` empty before and after.
    Script: scratchpad/serial-probe.sh; logs: scratchpad/serial-run-{1,2,3}.log

**What this does NOT establish.** The probe changed TWO variables against gates 1 and 3 —
it ran serially AND it recreated the database each run. Three runs cannot separate them.
It therefore does not falsify F5 or R-13, and must not be read as clearing them:

- Gate 3 observed 4 FAIL in 5 runs with three of those failures at load **2.8-6.8** — a
  quiet box, the same condition as this probe. Load alone does not explain gate 3.
- Gate 3 named a STRUCTURAL mechanism that a passing run does not repair:
  `wave1PoolResiliencePostgres.integration.test.ts:515` asserts BEFORE `:516` releases the
  client, so `pool.end()` at `:523` can wait forever. Gate 1's F6 reached the same file and
  line pair independently. A test that hangs 3 times in 13 executions is not made sound by
  3 clean runs.
- Gate 1's failing runs included `counts: null` — a watchdog-level outcome, not a test
  failure, and a different shape from anything this probe produced.

**What it does suggest, as a hypothesis for the next reviewer, not a finding:** the suite
may be reproducible on a PRISTINE database and not on a USED one. Gate 5's I-9 measured
exactly that shape — same command, same SHA, `git.dirty:false`, watchdog probe
`reachable:true` both times: FAIL 118/472, then PASS 471/471 after recreating the
database. Gate 3 created and dropped ~700 scratch databases during its work; gate 1 did
not recreate between runs. If that hypothesis holds, the defect is not "the suite is
flaky" but "the suite's verdict depends on database state that nothing measures", which
is worse and is I-9's point. **Untested. Someone should run the 2x2.**

## Cross-gate disagreements, left UNRECONCILED for AEGIS

1. **RT-M4 / the three-column unnest JOIN.** Gate 2 (SEC-D) rates it **Low** — executed,
   confirmed removable with 132/132 passing, but judged NOT exploitable because the
   scoped map key is the load-bearing control. Gate 4 (RT4-4) rates it **Important** —
   removable with the FULL suite at 1088/1088 byte-identical to the certified baseline,
   unclosed across two rounds, against the branch's own standing closure rule. Same
   mutant, same result, different severity axis: exploitability vs detectability.

2. **The migrator.** Gate 3 calls it SOUND and proved it (21,600 raced statements without
   the lock -> 15,965 losers incl. 125x42710; with the lock -> 9,600 raced, 0 losers).
   Gate 4's RT4-3 defeats the same lock by SWAPPING TWO ADJACENT LINES with the owning
   test file 18/18 green and the race measurably back (xact_rollback delta 7,7,7 vs
   0,0,0). These are compatible and both should stand: the shipped code is correct AND
   its control cannot detect reordering. Every destroyer in the published set deletes or
   inverts; none reorders.

3. **The 1086/1087 denominator.** FOUR gates touched it and NONE closed it.
   Gate 1 reproduced a +1 mechanism from the repo's own `hookSentinel.cjs` and demoted
   the register's `NODE_TEST_CONTEXT` hypothesis as unnecessary, noting its mitigation
   does not address the mechanism found. Gate 5 saw 472 vs 471 but refused to close it
   because its +1 was a FAILURE entry and cannot explain a 1087 that PASSED. Gate 4
   recorded a run at **1093** with `files: 84, boundToCommit: true, untracked: []` and no
   file-level explanation, not root-caused. Gate 3 saw a third number, 1091. Gate 7 saw
   1088 four times and could not reproduce it at all. The coordinator saw 1088 three
   times. **Nothing anywhere pins the expected denominator** (gate 1). Item stays OPEN.

4. **Gate 4 asserted a gap that does not exist.** It wrote that `pool.ts`'s K-05 bounds
   went unmutated "now two gates deep, gate 3 skipped it too". Gate 3 DID mutate them —
   that is R-10. Gate 4 could not see gate 3's report. The real remaining hole is
   narrower: `isConnectionAmbiguous` and `releaseClient` specifically.

## A false premise the coordinator propagated

The dispatch protocol repeated the handoff's claim that the contracts pin is "verifiable
WITHOUT access to the contracts repo". Gate 5 (I-1) proved it false by execution:
`scripts/contracts-provenance.sh` emits `FAIL Contracts repository unavailable`. No gate's
work was invalidated (every environment had the contracts worktree), but six reviewers
were handed a false statement about the subject.

## Hygiene verified by the coordinator, not taken on trust

- Gate 3's exit state checked independently: zero stray processes under its worktree, and
  its cluster back to 4 databases after ~700 scratch databases. Matches its claim.
- All six reviewer databases confirmed migrated to 060 against a real 38-table schema
  mid-round, so no gate was silently measuring an empty database. (Gate 2's arrived empty
  and it migrated its own before attacking — `mkenv.sh` creates the cluster but does not
  migrate. Worth fixing in `mkenv.sh`.)
- Gate 7 reported the sandbox denied it a second published port; it used a second database
  inside its own container instead. Recorded because it is a constraint on that gate's
  method, not a defect.

## The six environments are still up

Not destroyed, so findings can be re-examined. Destroy with
`bash aaliyah-w13-evidence/tools/rmenv.sh rv5-{test,sec,rel,red,int,data}`.
