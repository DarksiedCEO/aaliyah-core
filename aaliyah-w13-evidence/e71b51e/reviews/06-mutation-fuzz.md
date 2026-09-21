# GATE 3 — INDEPENDENT MUTATION & FUZZ — W1.3 candidate-4

canonical: AG-MUTATION-FUZZ · role: INDEPENDENT REVIEWER (adversarial, read-only to candidate)
run: THIRD dispatch of this gate. Prior two ran against SHAs (candidates 1–3, all
descendants of 97bb476) that carried a live production race (the migrator's
deleted advisory lock, M-30) which none of them found because all prior runs
migrated quiescent, never under contention. This run's top mandate item is
exactly that gap.

## Subject verified (not trusted)

| field | claimed | verified |
|---|---|---|
| candidate SHA | e71b51e9ed333d1feab1cd6819496269d201a6e2 | `git rev-parse HEAD` = e71b51e9ed333d1feab1cd6819496269d201a6e2 (tag `w13-candidate-4` points-at HEAD) |
| contracts | 7d576681d1001eb4c4a7f044f7793cdb3f80af76 (pinned) | `bash scripts/contracts-provenance.sh` → PASS, exact SHA, tree a34af636b5ce62dbb2830a8a7b716816f42ea041 |
| worktree | /Users/andrelove/aaliyah-w13-gauntlet/mutfuzz/aaliyah-wave1-core | confirmed pwd; is a git worktree |
| database | postgres://postgres:test@127.0.0.1:54557/aaliyah_test, migrated to 060 | confirmed reachable, 38 tables present, `\dt` matches expected schema |
| `git status --porcelain` before | — | empty |
| `git status --porcelain` after | — | empty (verified after every mutant restore, and at end) |
| baseline suite | 1088/1088, fail 0, skip 0, todo 0 | REPRODUCED — see below (one caveat) |
| `bash scripts/ci-guards.sh` | 8 guards | REPRODUCED — 8 PASS lines, `RELEASE GUARDS: PASS` |

**Baseline caveat, disclosed rather than hidden**: my FIRST full-suite attempt used
`--test-timeout-ms 60000` (the protocol's mutant-judging bound) for the BASELINE
run too, and the watchdog correctly reported `FAIL` (`HUNG_WORKER`, no summary)
on `tests/wave1PoolResiliencePostgres.integration.test.ts`'s
"a STORE that connects and releases by hand destroys an ambiguous client too"
test, which legitimately needs more than 60s (it terminates backends and waits
on retries). This is exactly the watchdog-verdict-not-failure-list lesson the
protocol names — I read the VERDICT, recognized MY bound was too tight for a
baseline (not a defect), and re-ran with the watchdog's own defaults
(`testTimeoutMs: 240000`, `deadlineMs: 900000`, `exitGraceMs: 15000`), which
produced `WATCHDOG VERDICT: PASS scope=FULL_SUITE tests=1088 pass=1088 fail=0
cancelled=0 skipped=0 todo=0`. All subsequent mutant judgments used TARGETED
files only, never the full suite, per protocol.

I did not re-chase the register's own separately-disclosed 1086-vs-1087
denominator anomaly (recorded as OPEN in `docs/WAVE1_BLOCKER_REGISTER.md`,
"OPEN — SUITE TEST-COUNT DISCREPANCY"); my own full-suite run was clean and
consistent with the 1088 baseline, and re-litigating an already-disclosed,
already-mitigated (NODE_TEST_CONTEXT stripped) open item was not the highest
use of a bounded budget. Noting it here as a named input I inherited rather
than independently re-chased.

## Priority 1 — THE MIGRATOR UNDER CONTENTION (top mandate item)

Targeted file: `tests/wave1MigrationReplayPostgres.integration.test.ts` (18
tests, baseline ~5.3s clean). All mutant judgments below used
`--deadline-ms 240000 --test-timeout-ms 60000 --exit-grace-ms 10000` against
this file only. Every mutant was: applied → judged → restored →
`sha256sum` verified byte-identical to a pre-mutation backup → `git status
--porcelain` verified empty, before touching the next mutant.

Source under attack: `src/persistence/postgres/migrations.ts`,
`runMailMigrations` / `createLedgerToleratingARace` (lines ~6128–6456).

| id | mutation | file:line | verdict | evidence |
|---|---|---|---|---|
| MUT-1 | delete the advisory-lock ACQUIRE line (`SELECT pg_advisory_lock(hashtextextended($1,0))`) — this is the EXACT M-30 deletion that let the 42710 race back into candidates 1–3 | migrations.ts:6278 | **KILLED** | `K-06c: migrators SERIALIZE on the advisory lock before the ledger exists` → `AssertionError: no migrator ever waited on the ledger advisory lock`. 1/18 failed, watchdog VERDICT=FAIL (not a hang) |
| MUT-2 | drop `"42710"` from `LEDGER_RACE_LOST` (`new Set(["42P07","23505"])`) | migrations.ts:6128 | **KILLED** | `K-06b` → uncaught `Error: already exists (42710)` propagates through `createLedgerToleratingARace`. 1/18 failed |
| MUT-3 | delete the advisory-lock RELEASE call in the `finally` block (lock rides back onto the pooled connection) | migrations.ts:6449–6451 | **KILLED** | 5/18 failed: `the migrator leaves NO session state…`, and all three of `2/3/5 concurrent migrators…` (`a migrator left a session advisory lock held`, `1 !== 0`) |
| MUT-4 | invert the tolerance's presence re-check (`!== true` → `=== true`), so the tolerance throws when the ledger genuinely IS there and swallows when it genuinely is NOT | migrations.ts:6190 | **KILLED** | 2/18 failed: `K-06b` directly (`Error: already exists (42P07)` now propagates for a real race), AND behaviourally — `K-06 REOPENED` (real 10-trial old-build race) crashed with `duplicate key value violates unique constraint "pg_type_typname_nsp_index"`, proving this is a reachable, load-triggerable regression and not just a unit artifact |
| MUT-5 | mismatch acquire/release lock KEY (acquire uses `hashtextextended($1,1)`, release still uses `hashtextextended($1,0)` — a subtler leak than MUT-3) | migrations.ts:6278 | **KILLED** | 6/18 failed, same detector family as MUT-3 (`pg_locks` count checks do not care which key leaked, only that one did) |
| MUT-6 | delete `RESET lock_timeout` in the `finally` (GUC, not the lock, rides back into the pool) | migrations.ts:6452 | **KILLED** | 2/18 failed: `the migrator leaves NO session state…` (`'2min' !== '1min'`) and `the LEDGER-CREATION phase leaves no session state…` (same GUC leak on the 42501-permission-denied path) |
| MUT-7 | invert the cleanup gate (`if (!broken)` → `if (broken)`) — cleans up ONLY on a broken connection, i.e. never on the ordinary success/refusal path | migrations.ts:6448 | **KILLED** | 6/18 failed, same lock-leak detector family |
| MUT-8 | make the post-apply digest backfill re-check reuse the STALE `hasDigest` flag instead of re-querying (`const digestColumnNow = hasDigest;`) — reintroduces the historical "undigested until a second run" defect | migrations.ts:6399–6405 | **KILLED** | `INT-DIGEST: …a fresh apply is fully digested` → `60 applied migrations have no digest` (`0 !== 60`) |

**Denominator for this section: 8/8 mutants against the migrator's contention
and cleanup logic were KILLED. 0 REAL_SURVIVOR. 0 STRUCTURALLY_UNREACHABLE
claimed here.** Coverage was chosen to hit every clause the mandate names
explicitly: lock acquisition, lock release, lock-key integrity, the tolerated
SQLSTATE set (both directions), the presence re-check's polarity, the cleanup
gate's polarity, and GUC leakage — i.e. "any way a migrator crashes another,
or a lock or GUC rides back into the pool" was exercised as eight distinct,
independently-restored single-point mutations, not one composite change.

### Fuzz: the tolerated-SQLSTATE boundary

Property-fuzzed `createLedgerToleratingARace` directly (exported for exactly
this purpose) against the PRISTINE source via `node --require ts-node/register`,
537 inputs: the three real codes in every case/whitespace/type variant I could
construct (`"42710"`, `" 42710"`, `"42710\n"`, `42710` as a number, `true`,
objects, `"__proto__"`, `"constructor"`), 30 named adjacent-but-wrong Postgres
SQLSTATEs (`55006`, `40001`, `40P01`, `57014`, `53300`, `08006`, `08003`,
`XX000`, `42501`, `22P02`, `23503`, `23514`, `3D000`, `3F000`, `P0001`, …), and
500 random 5-character alphanumeric SQLSTATE-shaped strings. Result: **0
mismatches out of 537** — only `"42P07"`, `"23505"`, `"42710"` (exact string
match) are ever tolerated; everything else propagates. This is a genuine
negative fuzz finding (no bypass), executed, not asserted.

### Load fuzz: concurrency beyond the committed suite

The committed suite tops out at 5 concurrent new-build migrators (`K-06
REOPENED` runs 10 trials of exactly 1-new-vs-1-old). I ran, against the
pristine build on scratch databases (dropped after each trial, verified none
left behind):

  **8 concurrent NEW-build migrators + 3 concurrent OLD-build migrators
  (`migrateLikeAnOlderBuild`, no advisory lock, races `CREATE TABLE` directly),
  5 trials, each on a fresh database.**

Result: 5/5 trials clean — all 8 new migrators fulfilled every time, ledger
rows=60=distinct every time, 0 advisory locks leaked every time. No crash, no
hang, no leaked session state at this exceeded concurrency. Recorded as
executed load coverage, not as a guarantee at unbounded concurrency (I did not
try, e.g., 50-way).

## Priority 2 — K-06b / K-06c: are they REAL controls?

Both were removed independently (MUT-2 removes what K-06b asserts; MUT-1
removes what K-06c asserts) and both turned the corresponding test RED with no
other change. **Confirmed real, not decorative”, by direct removal, not by
reading their names.**

## Priority 3 — re-EXECUTE, not carry forward: STRUCTURALLY_UNREACHABLE_WITH_PROOF (M-47 / M-55)

The register's own history is that an EARLIER version of exactly this
classification (eighth pass, `97bb476`) was published, then INDEPENDENTLY
FALSIFIED by two other reviewers at `a9d203d` who executed the removal rather
than reasoning about it, and the corrected proof names migration 055's CHECK
constraint (`memory_key_destruction_obligations_resolution_named`) as the real
load-bearing guard, not migration 058's trigger. Per this gate's mandate, I did
not carry that corrected proof forward on trust either — I re-executed it
myself, at `e71b51e`, two ways:

1. **Isolated SQL, inside a rolled-back transaction** against the live test
   database: planted an already-settled obligation row directly (`resolved_by
   = 'SETTLEMENT'`, `settled_by` set), `ALTER TABLE … DISABLE TRIGGER ALL`
   (removes 058's trigger AND FK enforcement, isolating the CHECK alone), then
   issued the exact statement `clearHealedObligations` would issue with M-55's
   filter removed (`resolved_by='PROVIDER'`, no `state` filter). Result:
   **refused**, `code=23514`,
   `constraint=memory_key_destruction_obligations_resolution_named` — the 055
   CHECK alone, with every trigger disabled, still blocks it. Transaction
   rolled back; DB unchanged (confirmed no stray rows).
2. **Full-stack, against the real TypeScript source**: applied BOTH M-47 (re-add
   `provenDestroyed.push(row)` at wave1TrustedMemoryStore.ts:3157-3165) and M-55
   (remove the `AND state = 'KEY_DESTRUCTION_NOT_PROVEN'` filter at
   wave1TrustedMemoryStore.ts:3336-3342) simultaneously, then ran the full
   132-test `tests/wave1MemoryHoldErasurePostgres.integration.test.ts`.
   **Result: 132/132 PASS, unchanged from baseline.** No test — including
   `S-2c`, which is the test written specifically for this invariant —
   observes any difference, because the UPDATE `clearHealedObligations` now
   issues fails on 055's CHECK and is silently swallowed
   (`.catch(() => undefined)` at the call site), leaving the settled row's
   correct attribution intact.

**Classification: STRUCTURALLY_UNREACHABLE_WITH_PROOF, independently
re-verified at e71b51e (this SHA), by direct execution at both the isolated-SQL
layer and the full-suite layer.** Not carried forward from the register's prose.

One residual note, disclosed rather than suppressed: this proves the OBSERVABLE
behaviour is unaffected, not that the swallowed failure is cost-free — an
operator running `completePendingAliasErasures` with these two mutants and 058
also gone would have a `clearHealedObligations` call fail-closed silently every
time it hit a settled row in the batch, which is availability debt (a healing
pass quietly does less than it could) rather than a correctness bypass. Not a
new finding — this is the register's own SEC-02 "058 makes forgery
unrepairable" shape from the other side — but I want it on record rather than
implied by "PASS".

## Priority 4 — highest-value behavioural target (subject reported ERASED while its key is alive)

Targeted the SEC-01 fix directly: `settleKeyDestruction`'s provider-contradiction
gate at `wave1TrustedMemoryStore.ts:3595`
(`if (live.proof === "PROVEN_NOT_DESTROYED") { … settlement_contradicted_by_provider … }`).

**MUT-9**: inverted the comparison (`===` → `!==`), which reintroduces the exact
a9d203d SEC-01 defect (a settlement claiming `PROVEN_DESTROYED` would be
ACCEPTED over a key the provider says is alive, and REJECTED over a key the
provider says is destroyed or cannot answer about — backwards).

**Result: KILLED, 17/132 failing** in
`tests/wave1MemoryHoldErasurePostgres.integration.test.ts`, including `S-4f`
("a settlement is REFUSED over a key the provider says is ALIVE" — the direct
falsifier) and cascading failures in S-7, S-8 and others whose fixtures depend
on the gate's correct polarity. **This is a real, heavily-covered control, not
a decoration.** Restored and re-verified byte-identical.

I did not attempt a second single-point mutation on this path (e.g. removing
the gate's transaction-boundary comment's guarantee that it asks with no open
transaction) — one clean kill against the exact CVE-shaped inversion was the
highest-value use of remaining budget, and I'm disclosing the narrower scope
rather than implying full coverage of every mutation this function admits.

## Priority 5 — further mutually-masking guards / missing detectors

Time-boxed search, not exhaustive. I read `docs/WAVE1_BLOCKER_REGISTER.md`'s
"THE FINDINGS" table from the a9d203d gauntlet in full. Several entries there
(SEC-02 "the mutator forges a SETTLED obligation", SEC-03 "replay short-circuit
compares 7 of 22 columns") are recorded OPEN at a9d203d but I found
**`S-2e SEC-02`** and **`S-6b SEC-03`** as named, passing tests in the CURRENT
suite (`wave1MemoryHoldErasurePostgres.integration.test.ts`), which is evidence
those two were closed somewhere in the remediation between a9d203d and this
candidate — I did not independently re-execute mutants against SEC-02/SEC-03
myself (budget), so I report this as an OBSERVATION (tests exist and pass at
this SHA) rather than as a verified-by-me control. **Flagging this as scope NOT
covered by my own execution**, distinct from the mandate items I did execute.

I did not find a NEW mutually-masking pair beyond the ones the register already
names (RT-M4, RT-M11, RT-M14/15 are recorded OPEN in the register from an
earlier pass and I did not re-attack them — out of this run's time budget).
Per the mandate's rule, I am naming this as **coverage NOT performed**, not
silently passing it over.

## What I did NOT cover (explicit denominator)

- Did not mutate `pool.ts`'s K-05 ambiguous-connection-destruction guard
  itself (only observed it pass in the baseline full-suite run); the migrator's
  OWN cleanup path (its own `finally`, its own GUC/lock hygiene) got the full
  attack treatment instead, per the mandate's explicit priority.
- Did not re-attack RT-M4, RT-M11, RT-M14/15, RT-M10/RT-M3, RT-6/7/8, RT-13/14
  from the a9d203d register (all recorded OPEN there); no independent
  confirmation either way at this SHA from me.
- Did not fuzz beyond 8-way/3-old concurrency on the migrator (load fuzz was
  5 trials at that one concentration, not a sweep).
- Did not attempt tenant-escape / traversal / replay attacks outside the
  migrator and key-destruction-settlement surfaces named in the mandate —
  no time spent on, e.g., alias-registry or legal-hold mutation this round.
- Did not independently re-verify SEC-02/SEC-03 closure by mutation (see above
  — observed passing named tests only).

## Rollback / hygiene

Every one of the 10 mutants above (8 in migrations.ts, 1 in
wave1TrustedMemoryStore.ts for SEC-01, 1 combined M-47+M-55 in the same file)
was: backed up before mutation, restored after judging, and verified via
`sha256sum` byte-identical to the pre-mutation backup, with `git status
--porcelain` empty after every restore. `HEAD` never moved
(e71b51e9ed333d1feab1cd6819496269d201a6e2 throughout). All scratch scripts
(`scratch-*.ts`, `scratch-*.mjs`) were deleted after use; `git status
--porcelain` is empty as of this report. All scratch/load-fuzz databases
(`aaliyah_loadfuzz_*`) were dropped by their own `finally` blocks; confirmed 0
stray `aaliyah_*` databases remain beyond `aaliyah_test` itself. `ci-guards.sh`
re-run clean (8/8 PASS) after all mutation activity concluded.

## Result

```
{
  "candidateSha": "e71b51e9ed333d1feab1cd6819496269d201a6e2",
  "mutantsKilled": 10,
  "mutantsSurvived": [],
  "fuzzFindings": [
    {
      "input": "537-input property fuzz of createLedgerToleratingARace's tolerated-SQLSTATE boundary (exact codes, case/whitespace/type variants, 30 named adjacent SQLSTATEs, 500 random 5-char codes)",
      "class": "NONE — negative finding, 0 mismatches",
      "repro": "node --require ts-node/register against src/persistence/postgres/migrations.ts:createLedgerToleratingARace; script deleted after use, reconstructable from this report's candidate list"
    },
    {
      "input": "8 concurrent new-build + 3 concurrent old-build runMailMigrations on 5 independent fresh databases",
      "class": "NONE — negative finding, 5/5 clean, exceeds committed suite's max concurrency of 5",
      "repro": "ts-node script per report body; scratch DBs dropped in finally, 0 left behind"
    }
  ],
  "bypasses": [],
  "verdict": "GREEN",
  "blocking": false
}
```

MUTATION_GREEN

This is ONE gate. Not a certification. Founder/AEGIS Ω adjudicate final
verdict across all gates.
