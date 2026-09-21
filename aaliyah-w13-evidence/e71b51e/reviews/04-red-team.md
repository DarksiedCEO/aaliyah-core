# GATE 4 — RED TEAM — W1.3 candidate-4
subject: e71b51e9ed333d1feab1cd6819496269d201a6e2 · contracts 7d576681 · blocking: true

STATUS: COMPLETE.


## Subject verified (not trusted)

| claim | claimed | verified by me | result |
|---|---|---|---|
| HEAD | e71b51e9ed333d1feab1cd6819496269d201a6e2 | `git -C $ROOT/aaliyah-wave1-core rev-parse HEAD` | e71b51e9ed333d1feab1cd6819496269d201a6e2 — MATCH |
| tree | — | `git rev-parse HEAD^{tree}` | 5af8080da732f8b4c4afd6b81337ab4a88b06950 |
| contracts | 7d576681d1001eb4c4a7f044f7793cdb3f80af76 | `git -C $ROOT/aaliyah-wave1-contracts rev-parse HEAD` | MATCH |
| worktree clean BEFORE | clean | `git status --porcelain` | empty — MATCH |
| database | postgres://…:54604/aaliyah_test | `psql -c "select current_database(), version()"` | aaliyah_test, PostgreSQL 16.14 — reachable |
| baseline suite | 1088/1088 fail 0 skip 0 todo 0 cancelled 0 | `npm test` (watchdog defaults), 3 independent runs | `PASS tests=1088 pass=1088 fail=0 cancelled=0 skipped=0 todo=0` — MATCH. **One caveat:** my FIRST run FAILED `DEADLINE_EXCEEDED` at the watchdog's own 900s default (durationMs 1103864) on a machine at load 13+; the same suite unloaded is 270492 ms. Environment-attributed, see RT4-7. |
| guards | 8/8 | `bash scripts/ci-guards.sh` | `RELEASE GUARDS: PASS`, 8/8 — MATCH. But see RT4-1: guard 1 pins 17 `src/` paths, none of them in the W1.3 surface, and all 8 pass with the migrator's advisory lock deleted on disk. |
| worktree clean AFTER | — | `git status --porcelain` + `git ls-files -v \| grep -v '^H '` | both empty — CLEAN, see "Subject verified AFTER the work" |

Environment: ROOT=/Users/andrelove/aaliyah-w13-rv5-red. Only
`AALIYAH_TEST_DATABASE_URL` was ever exported (harness trap 1).

## Findings

(appended as they are executed)

---------------------------------------------------------------------------
### RT4-1 · IMPORTANT · class EVIDENCE_FORGEABLE
### Every hygiene claim the register publishes for gates 1–3 (`worktree clean at the SHA`, `guards 8/8`, `boundToCommit: true`, `git.dirty: false`) stays green while the production source on disk is a DIFFERENT file from the commit — and the reintroduction used is the exact M-30 defect that got through three candidates

The register publishes gates 1–3 as ALL PASS, **run in the builder's own
session**, and the only integrity evidence offered for "the thing measured was
the commit" is `git status --porcelain` plus the watchdog's own `git.dirty` /
`boundToCommit` fields. All four are forgeable by a single git command that
**never touches the harness**: `git update-index --assume-unchanged`. It is a
local index bit. It does not appear in `git status`, in `git diff`, in the
watchdog's evidence, or in any of the 8 release guards.

**EXECUTED** in `/Users/andrelove/aaliyah-w13-rv5-red/aaliyah-wave1-core` at
`e71b51e`:

    $ shasum -a 256 src/persistence/postgres/migrations.ts
    f40cda6a27b67ddb48da0fe874cfb006d31cec692b7a1522c3cda255b744c416
    $ git status --porcelain            # before
    [empty]

    $ git update-index --assume-unchanged src/persistence/postgres/migrations.ts
    $ perl -0pi -e 's/^\s*await bounded\("SELECT pg_advisory_lock\(hashtextextended\(\$1, 0\)\)", \[LEDGER_LOCK_KEY\]\);\n//m' \
        src/persistence/postgres/migrations.ts
    $ grep -c "pg_advisory_lock(hashtextextended" src/persistence/postgres/migrations.ts
    0                                   # the M-30 deletion, reintroduced on disk

    $ git status --porcelain            # after the mutation
    [empty]                             # <-- the worktree reports CLEAN

    $ bash scripts/ci-guards.sh | tail -3
    PASS  the full suite's executed set is bound to the commit
    RELEASE GUARDS: PASS                # <-- 8/8, with the lock deleted

    $ node scripts/test-watchdog.mjs --verify-discovery --evidence .test-evidence/forge.json
    WATCHDOG VERDICT: PASS scope=FULL_SUITE
    exit=0
    git        {'head': 'e71b51e9ed...', 'dirty': False}      # <-- FALSE
    discovery  {'boundToCommit': True, 'ignored': [], 'untracked': [], 'missing': []}

Restored and proven: `shasum` back to `f40cda6a…`, `git ls-files -v` back to
`H`, `git status --porcelain` empty.

**Why this is not merely "you own the checkout".** The prior red team classified
its PASS forgeries as TCB-boundary because they required editing the harness
(`NODE_OPTIONS`, `TS_NODE_PROJECT`, `scripts/`). This one does not. Every
harness-editing forgery shows up in `git status`; `assume-unchanged` is the one
that does not, and `git status` is precisely the control the protocol,
the handoff and the register all name as the proof of subject integrity
("Verify HEAD, tree and a clean `git status --porcelain` before and after your
work"). The detection cost is one command nobody in this round has run:
`git ls-files -v | grep -v '^H'`.

**Compounding: the frozen-file guard covers none of the reviewed surface.**
Guard 1 (`scripts/aegis-frozen.sh verify`, "frozen manifest verified (17
pinned)") pins 17 paths, and the awk filter refuses any path not matching
`^src/`. The pinned set is entirely `src/application/planner/plannerClient.ts`,
`src/mail/sendGuard.ts`, `src/services/…` follow-up scorers. It contains
**zero** of the W1.3 subject: not `src/persistence/postgres/migrations.ts`,
not `wave1TrustedMemoryStore.ts`, not `pool.ts`, and by construction no test
file at all. So the one content-integrity guard in the suite cannot see any
file this candidate is about.

**What assertion should have caught it and did not.** `tests/testWatchdog.test.ts`
asserts the discovery binding over *ignored* and *missing* files (K-19, B5).
Nothing asserts that a tracked, discovered file's CONTENT is the commit's
content, and nothing anywhere reads `git ls-files -v`. `evidence.git.dirty` is
computed from `git status --porcelain` — the same forged oracle — so the
evidence file cannot independently contradict it.

**Falsifier / fix shape (not my job to apply):** have the watchdog compute the
binding from `git diff --quiet HEAD` *and* refuse any run where
`git ls-files -v -- tests src | grep -qv '^H'`, and record the tree OID it
actually measured. A verdict that names a SHA must hash what it ran.

**Blocking:** yes — it invalidates the *provenance* of the gate 1–3 results the
register publishes at this SHA, which were self-run by the party under review.
It does not by itself show those results were wrong.

---------------------------------------------------------------------------
### RT4-2 · MEDIUM · class UNKNOWN_UNKNOWN / MUTANT_SURVIVED-shape
### `enterMemoryRole` — the one function whose stated purpose is that the pin and the least-privilege role "cannot be forgotten" — silently does NOTHING when called outside a transaction, leaving the caller as the POOL OWNER on the default `"$user", public` path, and no test, guard or type can see it

`src/persistence/postgres/pool.ts:179-186`:

    export async function enterMemoryRole(
      client: { query: (sql: string) => Promise<unknown> },
      role: string | null,
    ): Promise<void> {
      await client.query(PINNED_SEARCH_PATH_SQL);   // set_config(..., true) = LOCAL
      if (role === null) return;
      await client.query(`SET LOCAL ROLE "${role}"`);
    }

whose docstring (`pool.ts:101-105`) claims:

> ONE function, used by every store, because the property it carries is one a
> caller **must not be able to forget**.

Both statements are transaction-LOCAL. Outside a transaction PostgreSQL makes
both no-ops and raises a **WARNING, not an error** — and node-postgres delivers
warnings on the `notice` event, which no store in `src/` subscribes to
(`grep -rn "'notice'" src/` → no matches). So the promise fails open, silently.

**EXECUTED** against the real function, `AALIYAH_TEST_DATABASE_URL` only:

    $ node --require ts-node/register ./rt-probe.ts
    NO-BEGIN   -> { role: 'postgres', path: '"$user", public' }
                  notices: [ 'SET LOCAL can only be used in transaction blocks' ]
    WITH BEGIN -> { role: 'aaliyah_memory_mutator', path: 'pg_catalog, public, pg_temp' }
                  notices: []

Corroborated directly in psql (same result, WARNING then `postgres` /
`"$user", public`).

`"$user", public` is *exactly* the configuration the K-07 / ATK-P1 search_path
attack needs — `pool.ts:108-116` describes the mutator creating a schema named
after itself that `"$user"` resolves to FIRST — and `postgres` is the pool
owner, i.e. the privilege escalation is total, not partial.

**Denominator, so this is not an insinuation.** I inspected every call site of
`enterRole` / `enterMemoryRole` in `src/` — 30 sites across 6 stores
(`wave1TrustedMemoryStore.ts` ×16, `wave1AliasRegistryStore.ts` ×5,
`wave1LegalHoldStore.ts` ×3, `wave1MemoryReconciler.ts` ×3,
`memoryMutationAttempts.ts` ×1, `wave1IdentityGraphStore.ts` ×1). Inclusion
rule: every line matching `enterRole(`/`enterMemoryRole(<client>` in
`src/persistence/postgres/`. **All 30 are preceded by
`await <client>.query("BEGIN")`.** So there is no live defect at this SHA.

**Why it is a finding anyway, by this register's own stated standard** ("for any
control this candidate claims, ask what happens if you DELETE it, and find the
assertion that would notice"): delete the `BEGIN` at any one of those 30 sites
and the store runs that statement as the pool owner on an attacker-influenceable
path, and *nothing* reports it — not the type system (the parameter type is
`{ query }`, it cannot express "in a transaction"), not a guard, not a test.
This is the seventh instance of the named standing weakness, and it sits on the
mechanism that closes the round's own search_path HIGH.

**What assertion should have caught it and did not.** `K-07` / `K-07b`
(`tests/wave1MemoryHoldErasurePostgres.integration.test.ts:5213-5345`) both open
`BEGIN` themselves before calling `enterMemoryRole`, so they only ever exercise
the path where it works. There is no negative case asserting that a
non-transactional call is REFUSED.

**Falsifier**: make `enterMemoryRole` fail closed — `SELECT
txid_current_if_assigned()`/`pg_current_xact_id_if_assigned()` is not enough
(read-only transactions have none); assert
`current_setting('transaction_isolation')` is unavailable outside a block, or
simply issue the pin non-locally and read `current_user` back, throwing when it
is not the requested role. Then add a test that calls it with no `BEGIN` and
asserts the throw.

**Blocking:** no — behaviour at this SHA is correct at all 30 call sites. It is
recorded as MEDIUM because the failure mode is total privilege escalation and
the detector count is zero.

---------------------------------------------------------------------------
### RT4-3 · IMPORTANT · class MUTANT_SURVIVED
### The migrator's advisory lock — the control restored in `c2e5747` because its deletion caused a live production race through three candidates — can be made completely ineffective by MOVING ONE LINE, and `K-06c`, the detector written specifically for it, stays GREEN. Measured: the race comes back at N-1 of N.

This is the named review subject #1, and it is the one the register says is now
closed ("Destroyer-verified: removing the lock now yields 'no migrator ever
waited on the ledger advisory lock'"; gate 2's D6 and D8; gate 3's MUT-1
"KILLED by K-06c"). Every one of those attacks **deletes** the lock. None
**reorders** it.

`src/persistence/postgres/migrations.ts:6278-6279` at `e71b51e`:

    await bounded("SELECT pg_advisory_lock(hashtextextended($1, 0))", [LEDGER_LOCK_KEY]);
    await createLedgerToleratingARace(bounded);

**MUT-B** = swap those two lines. The lock is still taken, still on the right
key, still session-scoped, still unlocked in the same place. It is simply taken
**after** the ledger is created instead of before — which destroys the whole
property, because `pool.ts`/`migrations.ts:6248-6250` states it exactly:

> A session advisory lock needs no table, so it is taken FIRST and covers the
> creation against every migrator that TAKES IT.

**1. The detector file is GREEN.** Executed (`AALIYAH_TEST_DATABASE_URL` only):

    # clean source, focused baseline
    $ npm test -- --evidence .test-evidence/focbase-mig.json \
        tests/wave1MigrationReplayPostgres.integration.test.ts
    WATCHDOG VERDICT: PASS scope=FOCUSED tests=18 pass=18 fail=0 cancelled=0 skipped=0 todo=0

    # MUT-B applied (the two lines swapped), same file
    $ npm test -- --evidence .test-evidence/mutB-foc.json \
        --test-timeout-ms 120000 --deadline-ms 600000 --exit-grace-ms 10000 \
        tests/wave1MigrationReplayPostgres.integration.test.ts
    WATCHDOG VERDICT: PASS scope=FOCUSED tests=18 pass=18 fail=0 cancelled=0 skipped=0 todo=0

18/18, zero failures. That file owns `K-06b`, **`K-06c`**, `K-06 REOPENED`, the
`POSITIVE CONTROL: bare concurrent CREATE TABLE IF NOT EXISTS really does crash
N-1 with 23505` and the 2/3/5-concurrent-migrator cases. VERDICT read, not
`failures[]` (trap 3): the verdict is PASS, not a silent hang.

**2. And the race really is back.** Not argued — measured, on fresh databases,
with the migrator's own `runMailMigrations`. A ledger-creation race that
`createLedgerToleratingARace` swallows still aborts the losing backend's
implicit transaction, so `pg_stat_database.xact_rollback` counts it:

    N = 8 concurrent migrators on a FRESH database, 3 trials each

    MUT-B (lock AFTER creation)      trial 0: aborted = 7
                                     trial 1: aborted = 7
                                     trial 2: aborted = 7      TOTAL 21
    e71b51e as committed             trial 0: aborted = 0
                                     trial 1: aborted = 0
                                     trial 2: aborted = 0      TOTAL 0

Exactly **N-1 of N** migrators lose the `CREATE TABLE IF NOT EXISTS` race under
MUT-B and **zero** do on the committed source. That is the identical signature
the suite's own `POSITIVE CONTROL: bare concurrent CREATE TABLE IF NOT EXISTS
really does crash N-1 with 23505` exists to characterise, and it is the exact
state the register root-causes as the cause of the production crash
(`type "aaliyah_mail_migrations" already exists`, 42710) that got through
candidates 1, 2 and 3. Under MUT-B the *only* thing left between the system and
that crash is the tolerance list — i.e. precisely the post-M-30 posture the
register calls a DEFECT.

**What assertion should have caught it and did not.** `K-06c`
(`tests/wave1MigrationReplayPostgres.integration.test.ts:256-352`) is named
*"migrators SERIALIZE on the advisory lock **before the ledger exists**"*. Its
mechanism is: hold the lock, start a migrator, and poll `pg_locks` for
`locktype='advisory' AND NOT granted`. **An ungranted advisory request appears
whether the migrator asks for the lock before or after creating the ledger**, so
the test's two assertions —

    assert.ok(waiting > 0, "no migrator ever waited on the ledger advisory lock …")
    assert.equal(finished, false, "the migrator finished while the lock was held")

— are both satisfied by MUT-B. K-06c holds "the lock is requested at some point
and blocks" and does **not** hold the word in its own title: *before*. The
ordering is the entire property, and nothing reads it.

`K-06b` holds the tolerance, not the lock. The 2/3/5-concurrent-migrator cases
assert only that all migrators *fulfil* — which they do under MUT-B, because the
tolerance forgives the race. The POSITIVE CONTROL uses bare SQL, not the
migrator.

**Falsifier (what would close it, per the standing rule — a detector, not a
deletion).** Assert the ORDER, not the block: from the holder's session, after
the migrator is confirmed waiting, assert
`to_regclass('public.aaliyah_mail_migrations') IS NULL` — the ledger must NOT
exist while a migrator is blocked on the lock. That single line is red under
MUT-B and green on the committed source. Alternatively assert the measurement
above directly: N concurrent migrators on a fresh database must produce **zero**
`xact_rollback` deltas.

**Restoration proven.** `shasum -a 256 src/persistence/postgres/migrations.ts`
→ `f40cda6a27b67ddb48da0fe874cfb006d31cec692b7a1522c3cda255b744c416` (identical
to pre-mutation), `git status --porcelain` empty.

**Blocking:** yes. It is a surviving single-point mutant on the fix for the
round's own root-cause defect, and the register's STANDING RULE requires a
surviving mutant to be closed by a detector.

---------------------------------------------------------------------------
### RT4-4 · IMPORTANT · class MUTANT_SURVIVED
### RT-M4 CARRIED FORWARD AND RE-EXECUTED AT THIS SHA: the three-column `unnest` JOIN the register names as the G-02 tenant-crossover fix (the previous round's HIGH) can still be removed with the FULL SUITE at 1088/1088. It was NOT closed by a detector, and the closure rule says it must be.

RT-M4 is recorded **OPEN** in the register
(`REGISTER-AT-HEAD-f0eaadf.md:1812`). It is re-executed here, not inherited.

**The mutation**, `src/persistence/postgres/wave1TrustedMemoryStore.ts:2699-2701`:

    -             ON want.tenant_id = s.tenant_id
    -            AND want.workspace_id = s.workspace_id
    -            AND want.key_ref = s.key_ref
    +             ON want.key_ref = s.key_ref

i.e. `settlementProven` matches settlements on the key reference ALONE — the
exact shape of G-02, the HIGH the security review of `86d33c9` found, in which
one tenant's sound `PROVEN_DESTROYED` settlement satisfied a DIFFERENT tenant's
identical key reference.

**EXECUTED at `e71b51e`, `AALIYAH_TEST_DATABASE_URL` only, database DROPped and
re-CREATEd before every run so no run inherits another's state:**

    run                                              verdict  counts
    ------------------------------------------------ -------- -------------------------------
    clean, FULL_SUITE (baseline3)                     PASS     tests=1088 pass=1088 fail=0
    clean, FOCUSED hold-erasure (owns S-13)           PASS     tests=132  pass=132  fail=0
    RT-M4, FOCUSED hold-erasure (owns S-13)           PASS     tests=132  pass=132  fail=0   <- SURVIVOR
    RT-M4, FULL_SUITE (rtm4-full3)                    PASS     tests=1088 pass=1088 fail=0   <- SURVIVOR

The full-suite run with the mutant applied is **PASS, 1088 of 1088, fail 0,
cancelled 0, skipped 0, todo 0** — byte-identical in counts to the baseline the
candidate is certified on. VERDICT read, not `failures[]` (trap 3).

**S-13 is green with the mutant applied**, which is the point: S-13
(`tests/wave1MemoryHoldErasurePostgres.integration.test.ts:6894-7080`) asserts
the OUTCOME — `pass.notProven >= 1` and an obligation row for the second
tenant. That outcome is reached through `scopedKey(row.tenant_id,
row.workspace_id, row.key_ref)` at `wave1TrustedMemoryStore.ts:2661/2721`: with
the JOIN narrowed, the cross-tenant match is still FILED under the other
tenant's scoped map key and never read back. So the isolation survives on the
map key alone, and the JOIN — the half the register credits — has no falsifier.
This is unchanged from the finding at `a9d203d`: an **asymmetrically masked
pair** on the fix for a HIGH.

**Disclosure, because it cut the other way once and I will not hide it.** An
earlier FULL_SUITE run with RT-M4 applied, taken while the shared machine was at
load average 23, reported `tests=1093 pass=804 fail=289`. That run is NOT
evidence of detection: it reports a **denominator of 1093 where the commit's
suite is 1088**, its failures are 0.02 ms cascades across 9 files, and the same
mutant on the same source on a quiet machine is 1088/1088 twice over. I record
it because it is an independent reproduction of named review subject #2 — see
RT4-7.

**What assertion should have caught it and did not.** None exists. The register's
own falsifier for RT-M4 was stated a round ago ("assert that `settlementProven`
returns NO row for a cross-scope collision — count the rows the query returns,
or assert the map has exactly one entry") and has not been written.

**Against the STANDING RULE.** The register's rule (`:2090`) is that a surviving
mutant is closed by a detector, or by a redundancy proof reviewed as a
production change and EXECUTED. RT-M4 has been closed by **neither**. It is
carried as OPEN prose. Stated plainly, as instructed: **it was not closed by a
detector.**

**Restoration proven.** `shasum -a 256 …/wave1TrustedMemoryStore.ts` →
`f3e28a07a5129eeae4b0ae99f8ec6e7ba4b9757a47d16ae6f4963525da6472b0` (identical to
pre-mutation), `git status --porcelain` empty.

**Blocking:** yes — a surviving single-point mutant on the remediation of a HIGH,
unclosed across two review rounds.

---------------------------------------------------------------------------
### RT4-5 · MEDIUM · class VACUOUS_SUCCESS_CONDITION / EVIDENCE_FORGEABLE
### The watchdog records `boundToCommit: true` on a run whose executed set is NOT the commit's set — 85 files and 1090 tests where the commit has 84 and 1088 — and `scripts/ci-guards.sh` reports 8/8 on it. This is the denominator hole named as review subject #2, weaponised.

Named review subject #2 says the 1086/1087 discrepancy matters "because the
watchdog's entire premise is that the executed set IS the commit's set". That
premise has a hole that needs no flake at all.

`scripts/test-watchdog.mjs:162-240` refuses an IGNORED discovered file and a
MISSING tracked file, but **allows an untracked-but-not-ignored one**
(`:201`, and the comment at `:150-152`). `boundToCommit` (`:428-433`) is then
computed as `verified && ignored.length === 0 && missing.length === 0` — the
`untracked` array is **excluded from the calculation**, so the field asserts
"bound to the commit" while the very same JSON object lists a file that is not
in the commit.

**EXECUTED** (file created, run, deleted, `git status --porcelain` empty before
and after):

    $ cat > tests/zzRedTeamExtra.test.ts    # two trivial passing tests
    $ git check-ignore -v tests/zzRedTeamExtra.test.ts   ; echo $?
    1                                        # not ignored -> allowed

    $ bash scripts/ci-guards.sh | tail -3
    PASS  the full suite's executed set is bound to the commit
    RELEASE GUARDS: PASS                     # <-- guard 8 green

    $ npm test
    WATCHDOG VERDICT: PASS scope=FULL_SUITE tests=1090 pass=1090 fail=0 cancelled=0 skipped=0 todo=0

    evidence: verdict PASS, files 85,
              git        {'head': 'e71b51e9ed…', 'dirty': True}
              discovery  {'boundToCommit': True,            # <-- FALSE
                          'untracked': ['tests/zzRedTeamExtra.test.ts'],
                          'ignored': [], 'missing': []}

A **PASS at a denominator of 1090** against a commit whose suite is 1088, with
the watchdog asserting the executed set is the commit's set and the release
guards 8/8.

**How far it goes, honestly.** `git.dirty` correctly reads `True` here, and
`untracked` names the file, so a reviewer who reads the whole evidence object
can catch it. I tried to suppress `dirty` as well — `git add` + `git
update-index --assume-unchanged` does NOT work, because `assume-unchanged`
suppresses worktree-vs-index comparison only and a file absent from HEAD still
reports `A `. So for ADDED tests the dirty bit is an honest signal. What is
*not* honest is the field named `boundToCommit`, and it is the field a gate
report quotes.

**Two further vacuous conditions in the same file, found and recorded:**

1. `--verify-discovery` (`:480-483`) prints `WATCHDOG VERDICT: PASS
   scope=FULL_SUITE`, exits 0, and writes an evidence file with
   `verdict: "PASS", counts: null` while **running zero tests**. It is guard 8.
   Any consumer that matches on `WATCHDOG VERDICT: PASS` or on
   `evidence.verdict === "PASS"` cannot distinguish a full green suite from a
   sub-second run that executed nothing. (I confirmed by `grep -rn
   "test-evidence" scripts src docs tests` that nothing in the repository reads
   `last-run.json` today, so this is latent, not live.)
2. `pgOptions()` (`:242-261`) strips exactly three inherited keys and passes
   **every other** `PGOPTIONS` setting through to every test backend, while the
   evidence records `bounds.pgOptions` as if the watchdog owned them. Not
   executed as an exploit — recorded as an unattacked surface in
   "What I did NOT cover".

**Falsifier**: include `untracked` in `boundToCommit`, and refuse a FULL_SUITE
verdict when it is non-empty (or record `boundToCommit: false` plus a reason);
give `--verify-discovery` its own verdict token that is not the string `PASS`.

**Blocking:** no — disclosed by `git.dirty` and `untracked` in the same record.
Recorded because the field's name is a claim the field does not support, and
because this is the mechanism class of the OPEN denominator finding.

---------------------------------------------------------------------------
### RT4-6 · IMPORTANT · class CLAIM_FALSIFIED
### The closure audit is incomplete AND one of the closures it omits is a `STRUCTURALLY_UNREACHABLE_WITH_PROOF` classification whose proof is FALSE — the third of that exact shape, falsified here by execution against the harness's own database

The register's audit (`REGISTER-AT-HEAD-f0eaadf.md:2104-2113`) states its
denominator: "`8a0bf05..e71b51e` searched for retirements, deletions and
redundancy claims", and lists **three**: M-30, TST-1, M-47/M-55.

I re-ran that search (`git log 8a0bf05..e71b51e --format='%h %s%n%b'`, then
`grep -inE "retire|redundan|remov|delet|unreachable|no longer|superfluous"`, 25
commits, every body read). It finds a **fourth**, in `cb392e8` — inside the
stated range — that the table does not list:

> **G-07**, `docs/WAVE1_BLOCKER_REGISTER.md:1378`, classified
> `STRUCTURALLY_UNREACHABLE_WITH_PROOF`:
> "A mutant removing the `COALESCE(d.datacl, acldefault(...))` NULL fallback in
> the privilege map SURVIVED: `datacl` is NULL only for the bootstrap
> `postgres` database, and every database created with `CREATE DATABASE`
> inherits a non-null ACL from `template1`, so the NULL branch is unreachable
> under this harness."

and which `K-08` (`:1123`) then cites to withdraw a coverage claim: "that NULL
branch is structurally unreachable under this harness and is not claimed as
tested".

**The proof is false. EXECUTED against the harness's own PostgreSQL 16.14:**

    $ psql -c "SELECT datname, datacl IS NULL AS datacl_is_null, datacl FROM pg_database ORDER BY 1"
       datname    | datacl_is_null |               datacl
    --------------+----------------+-------------------------------------
     aaliyah_test | t              |
     postgres     | t              |
     template0    | f              | {=c/postgres,postgres=CTc/postgres}
     template1    | f              | {=c/postgres,postgres=CTc/postgres}

    $ psql -c "CREATE DATABASE rt_datacl_probe;" \
           -c "SELECT datname, datacl IS NULL FROM pg_database WHERE datname='rt_datacl_probe';"
     rt_datacl_probe | t

`aaliyah_test` — the harness's own database, created with `CREATE DATABASE` —
has `datacl IS NULL`. A freshly created database has `datacl IS NULL`.
`template1`'s non-null ACL is **not** inherited. So the NULL branch is not
unreachable: it is the **only** branch the harness ever takes, on every run
including the one that produced the 1088/1088 certification.

**And the mutant is not a survivor. EXECUTED:**

    -- the databases section as committed
    $ … aclexplode(COALESCE(d.datacl, acldefault('d', d.datdba))) …
    PUBLIC <current> CONNECT,TEMPORARY
    -- the G-07 mutant: COALESCE removed
    $ … aclexplode(d.datacl) …
    (no rows)                                   # the whole section vanishes

    $ # mutant applied to tests/support/memoryPrivileges.ts, clean database
    $ npm test -- tests/wave1MemoryPrivilegesPostgres.integration.test.ts
    WATCHDOG VERDICT: FAIL scope=FOCUSED tests=6 pass=5 fail=1 cancelled=0 skipped=0 todo=0
      * the privilege map of every memory role equals the declared map, section by section
        || + narrowed: [ 'PUBLIC <current> CONNECT,TEMPORARY' ]  - narrowed: []
             section: 'databases'

**KILLED, by name, with `timedOut: 0`.** The declared map's entire `databases`
section — `["PUBLIC <current> CONNECT,TEMPORARY"]` in
`tests/support/memoryPrivileges.expected.json` — exists *because of* that
`COALESCE`.

**The code already knew.** `tests/support/memoryPrivileges.ts:63-68` says the
correct thing in plain words:

> "`datacl` is NULL on a freshly created database and that does NOT mean 'no
> privileges' — it means the built-in default, which grants CONNECT and
> TEMPORARY to PUBLIC."

The register published the opposite of its own source file, and used it to
withdraw a true coverage claim (K-08).

**This is the third `STRUCTURALLY_UNREACHABLE_WITH_PROOF` of this shape and the
third to be falsified by executing what it reasoned about** — M-47 and M-55
were the first two (falsified by RT-3 and SEC-08). The register itself names
the rule that was broken: "The proof must be EXECUTED, not argued: this
register has already published one unreachability proof that two reviewers
falsified by running the combination it merely reasoned about."

**What assertion should have caught it and did not.** The privileges test DOES
catch the mutant — the defect is entirely in the register: a false proof, a
withdrawn true claim, and an audit whose stated denominator missed the entry.
Nothing in the repository checks a register classification against execution.

**Falsifier**: re-classify G-07 as COVERED (the `COALESCE` is load-bearing and
the `databases` section is its detector), restore K-08's wording, and add G-07
to the closure-audit table with its corrected status.

**Blocking:** yes — a published FALSE proof in the document that adjudicates
what is closed, of the identical class the round has already been burned by
twice, plus an audit whose declared denominator is wrong.

**And the part of the audit that HELD — TST-1, re-executed, not inherited.**
The register says TST-1 "Meets the rule … Re-verify under the new rule". I did,
on a database dropped and recreated for each run:

    layer mutated                                          verdict  failing assertion
    ------------------------------------------------------ -------- ----------------------------------
    A. translation: `constraint.endsWith("independent_      FAIL     S-4 — deepEqual, actual
       verifier")` -> a name that never matches             131/132  rejection 'settlement_malformed'
    B. enforcement: the DB CHECK …_independent_verifier     FAIL     S-4 — deepEqual, actual
       DROPped live                                         131/132  { recorded: true, replay: false }
    C. enforcement DROPped AND the deleted pre-check        FAIL     S-4 — "Missing expected rejection"
       re-added (the masked state TST-1 removed)            131/132  (the RAW INSERT assertion)

**TST-1's closure holds.** Both surviving layers are falsifiable, and case C
proves the raw-insert half is a real control and not decoration. **One
correction to the register's wording**, from execution: it says "S-4's raw
insert holds the DB CHECK, S-4's store call holds the translation". In fact the
**store call** is what reports BOTH mutants at this SHA (cases A and B), because
it is asserted first and the raw insert is unreachable once it throws. The raw
insert only becomes the reporter in case C. Attribution imprecise; redundancy
proof sound. Recorded as Info, not as a finding.

---------------------------------------------------------------------------
### RT4-7 · LOW (Info-with-evidence) · class INSUFFICIENT_EVIDENCE
### The 1086/1087 denominator defect reproduces at this SHA, larger: I observed `tests=1093` against a commit whose suite is 1088. I did not root-cause it. I also observed the certified baseline FAIL at the watchdog's own default deadline.

Named review subject #2 is OPEN and unattributed; gate 1 owns reproducing it.
Two observations from my runs, recorded so the count of independent sightings is
not lost:

1. **A 1093 denominator.** A FULL_SUITE run at this SHA, taken while the shared
   machine was at load average ~23, reported
   `tests=1093 pass=804 fail=289` (`.test-evidence/rtm4.json`). The commit's
   suite is 1088 and `files: 84` was correct, `boundToCommit: true`,
   `untracked: []`, `ignored: []`, `missing: []` — so **no file-level
   explanation**. The failures were 0.02 ms cascades across 9 files. Two
   subsequent runs of the identical source on a quiet machine were 1088/1088.
   This is the same *shape* as run A of the register's table (denominator +N,
   failures +N) at five times the magnitude, and it is the second independent
   sighting of a non-commit denominator on this branch.
   **Not root-caused by me.** The register's leading hypothesis (nested
   `node --test` leakage from `scripts/assertion-reachability.mjs`) is
   consistent with it — that file was among the failures — but I did not
   capture the event stream, so I cannot attribute it. `INSUFFICIENT_EVIDENCE`,
   not `CLAIM_FALSIFIED`.
2. **The certified baseline FAILs at the watchdog's own default bound under
   load.** My first baseline, at default `deadlineMs` 900_000:
   `WATCHDOG VERDICT: FAIL … DEADLINE_EXCEEDED … durationMs 1103864`. The same
   suite on a quiet machine: `PASS tests=1088 … durationMs 270492`. A 4×
   margin that a contended machine erases entirely. Environment-attributed (5
   other reviewer environments were running), **not** a defect in the
   candidate — recorded because the published 1088/1088 is a load-sensitive
   result and CI is not proven.

**Blocking:** no.

---------------------------------------------------------------------------
## What SURVIVED my best attempt — reported as the limit of the attempt, never as proof

### Gate 2's "8 destroyers, 8 DETECTED, each by its own named assertion" — CONFIRMED for the 7 I could reconstruct

The register's D-list was re-executed independently, each on a database DROPped
and re-CREATEd first, each judged on the watchdog VERDICT and on `timedOut` /
`cancelled` (trap 3 — a hang yields FAIL with ZERO failure entries, and I
checked for exactly that).

    destroyer  mutation I applied                                 verdict  cancelled/timedOut  the assertion that FIRED, by name
    ---------- -------------------------------------------------- -------- ------------------- -----------------------------------------------------
    D1  pin removed        delete `client.query(PINNED_SEARCH_     FAIL      0 / 0              K-07  "the pin never ran: the path is still whatever
                           PATH_SQL)` from enterMemoryRole         130/132                       the session supplied"
                                                                                                K-07b "the pin never ran on a role-poisoned session"
    D2  pg_temp not last   pin -> 'pg_catalog, pg_temp, public'    FAIL      0 / 0              K-07  "pg_temp is not last" (and K-07b, same)
                                                                   130/132
    D3  $user restored     pin -> 'pg_catalog, "$user", public,    FAIL      0 / 0              K-07  "$user survived in some casing"
                           pg_temp'                                130/132                      K-07b "a role-level path reached the store: …"
    D4  inheriting pin     pin -> 'pg_catalog, operator_choice,    FAIL      0 / 0              K-07  "a session-chosen schema survived"
                           public, pg_temp'                        130/132                      K-07b "the role's own schema reached the store"
    D5  not xact-local     set_config(…, true) -> (…, false)       FAIL      0 / 0              K-07  "the pin is not transaction-local: it survived
                                                                   131/132                       COMMIT onto the pooled connection as …"
    D6  lock removed       delete the pg_advisory_lock call        FAIL      0 / 0              K-06c "no migrator ever waited on the ledger advisory
                                                                   17/18                         lock — the runner is not taking it"
    D7  42710 dropped      LEDGER_RACE_LOST -> {42P07, 23505}      FAIL      0 / 0              K-06b "already exists (42710)"
                                                                   17/18

Every one produced a NAMED assertion failure, not a hang and not a timeout.
`cancelled: 0` and `timedOut: 0` in all seven evidence files. **Gate 2's claim
is independently confirmed as far as it goes.** D8 is D6 under contention; I
covered that property differently, by measuring the race directly (RT4-3).

**The limit of this attempt**: confirming that each destroyer's *named*
assertion fires says nothing about the destroyer SET being complete, and RT4-3
is a counterexample inside the very same mechanism — every destroyer in the set
DELETES or INVERTS, and a REORDER of the same two statements is invisible to
all of them.

### Gate 1's "exploit replay: DEAD" — CONFIRMED, against the REAL `enterMemoryRole`, on a fully poisoned database

I replayed `/Users/andrelove/aaliyah-w13-evidence/search-path-attack/run.sh
54604` against migrations 001..060 on my own disposable database (60 applied),
which leaves `opsched`, the `attacker_app` login and the fabricated row in
place, then drove the store's real `enterMemoryRole` as `attacker_app` — whose
ROLE-LEVEL `search_path` is `opsched, public`, i.e. the attack's own first link,
requiring no privilege:

    1 INHERITED (no pin)        {"p":"opsched, public","tblschema":"opsched","fnschema":"opsched","rowsVisible":1}
    2 AFTER real enterMemoryRole {"p":"pg_catalog, public, pg_temp","tblschema":"public","fnschema":"public","rowsVisible":0}
    3 AFTER COMMIT (leak check)  {"p":"opsched, public","tblschema":"opsched","fnschema":"opsched","rowsVisible":1}

The shadowed `memory_pii_key_erasures`, the shadowed
`aaliyah_memory_unerased_merged_records` (the helper the DATABASE's erasure
guard calls) and the fabricated row are all present and all unreachable through
the pin; and the pin is transaction-local, so it does not leak onto the pooled
connection (line 3 is the same as line 1). **DEAD, confirmed independently.**

**The limit of this attempt**: one exploit, one replay, one database. I did not
attack `AUTHORITATIVE_SCHEMA` being something other than `public`, nor the
non-memory stores, nor any path that reaches SQL without going through
`enterMemoryRole`.

### TST-1's redundancy proof — RE-EXECUTED and it HOLDS (see RT4-6, cases A/B/C)

### Attacks I ran that found nothing

- **30/30 `enterRole` call sites are inside a transaction** — I checked every
  one (RT4-2 denominator). No live privilege defect at this SHA.
- **`assume-unchanged` on an ADDED test file** does not suppress `git.dirty`
  (the index-vs-HEAD diff still reports `A `), so the untracked-file path in
  RT4-5 cannot be made fully silent that way.
- **A tracked test file deeper than two directories** would be caught:
  `discoveryBinding`'s `missing` check is real, and `git ls-files -- tests |
  awk -F/ 'NF>3'` returns nothing at this SHA (84 tracked `.test.ts`, 84
  discovered).
- **`boundedQuery`'s per-query `query_timeout`** is honoured by node-postgres
  (`node_modules/pg/lib/client.js:660`: `config.query_timeout ||
  this.connectionParameters.query_timeout`), so the K-05 client-side ceiling is
  a real bound and not a no-op. I did not mutate it.

## Denominator / scope

    population                    material claims made ABOUT w13-candidate-4 at e71b51e:
                                  HANDOFF.md, REGISTER-AT-HEAD-f0eaadf.md (gates 1-3 self-run,
                                  the closure audit, the standing rule, the OPEN denominator),
                                  docs/WAVE1_BLOCKER_REGISTER.md as of the SHA,
                                  scripts/ci-guards.sh's 8 guards, the watchdog's own
                                  verdict/binding claims.
    inclusion rule                every claim whose falsification could be ATTEMPTED with
                                  localhost-only execution inside my own ROOT and DB.
    claims identified             14
    claims attacked (executed)    11
    claims falsified              5   (RT4-1, RT4-3, RT4-4, RT4-5, RT4-6)
    claims that survived          4   (gate 1 DEAD; gate 2 D1-D7 named; TST-1 redundancy;
                                       the 1088/1088 baseline itself, reproduced 3x)
    claims NOT attacked           3   -> INSUFFICIENT_EVIDENCE, named below
    collection method             git log 8a0bf05..e71b51e (25 commits, every body read),
                                  full read of the two claim documents, grep of src/ tests/
                                  scripts/ for each named mechanism.

    suite runs executed           7 FULL_SUITE + 12 FOCUSED, database DROPped and re-CREATEd
                                  before every judged run.

## What I did NOT cover

Named so the next reviewer does not inherit a false all-clear.

1. **I did not root-cause the 1093 denominator** I observed (RT4-7). I did not
   capture the raw `node:test` event stream, so the nested-runner hypothesis is
   neither confirmed nor refuted by me. Gate 1 owns reproduction.
2. **`PGOPTIONS` pass-through** (`test-watchdog.mjs:242-261` strips exactly
   three keys and forwards everything else to every test backend, including
   `-c search_path=…`, `-c session_replication_role=replica`, `-c row_security=off`).
   I read it and recorded it in RT4-5; **I did not execute an exploit through it.**
   It is the most promising unattacked surface I am leaving behind.
3. **The `node_modules` / `pnpm-lock.yaml` supply chain.** `--require
   ts-node/register` resolves out of an untracked tree. Genuinely TCB, unlike
   RT4-1 — not attacked.
4. **I did not mutate `pool.ts`'s K-05 bounds, `isConnectionAmbiguous`, or
   `releaseClient`** (gate 3 explicitly left the K-05 guard unmutated too, so
   this gap is now TWO gates deep).
5. **No HTTP-surface, traversal, authn/authz, replay or PII attacks** outside
   the migrator, the pin and the settlement surfaces.
6. **Concurrency**: I measured the ledger race at one concentration (N=8, 3
   trials, 2 source variants). No sweep, no fuzz of migration ordering, no
   attack on the identity-merge locking (`S-7`).
7. **Migration 047, cloud KMS/HSM, K-21 memory exhaustion, remote CI,
   production** — out of the claimed scope per the protocol; not attacked.
8. **`AUTHORITATIVE_SCHEMA` set to anything but `public`**, and every store
   other than the six I enumerated for RT4-2.

## Subject verified AFTER the work

    $ git rev-parse HEAD              e71b51e9ed333d1feab1cd6819496269d201a6e2   MATCH
    $ git rev-parse HEAD^{tree}       5af8080da732f8b4c4afd6b81337ab4a88b06950   MATCH
    $ git status --porcelain          [empty]                                    CLEAN
    $ git ls-files -v | grep -v '^H ' [empty]   no assume-unchanged/skip-worktree left behind
    $ bash scripts/ci-guards.sh       RELEASE GUARDS: PASS  (8/8)
    $ npm test                        WATCHDOG VERDICT: PASS scope=FULL_SUITE
                                      tests=1088 pass=1088 fail=0 cancelled=0 skipped=0 todo=0

Byte-for-byte restoration of every file I mutated, each verified by sha256
against the copy taken before the mutation:

    src/persistence/postgres/migrations.ts            f40cda6a27b67ddb48da0fe874cfb006d31cec692b7a1522c3cda255b744c416
    src/persistence/postgres/wave1TrustedMemoryStore.ts f3e28a07a5129eeae4b0ae99f8ec6e7ba4b9757a47d16ae6f4963525da6472b0
    src/persistence/postgres/pool.ts                  043ddceb8aa5fd834608660db1a897f7488238c5050c0a8c6ede35fd27d0878d
    tests/support/memoryPrivileges.ts                 7fb0a4db046c1340cc271d998d77e5902f1f15525bb33be1f57943a45028196d

**Database hygiene, disclosed.** I ran the search_path exploit replay against my
own database, which leaves `opsched` and the `attacker_app` login behind. Both
are gone: `DROP DATABASE aaliyah_test WITH (FORCE)`, `DROP ROLE attacker_app`,
`CREATE DATABASE aaliyah_test`. Verified afterwards — 4 databases
(`aaliyah_test`, `postgres`, `template0`, `template1`), 8 roles (the 7
`aaliyah_memory_*` plus `postgres`), no `opsched`. The final 1088/1088 above was
run on that clean database. No environment other than
`/Users/andrelove/aaliyah-w13-rv5-red` and port 54604 was written to;
`AALIYAH_TEST_DATABASE_URL` was the only variable exported (trap 1).

## Summary of findings

    id      severity    class                    blocking
    ------  ----------  -----------------------  --------
    RT4-1   Important   EVIDENCE_FORGEABLE       yes
    RT4-2   Medium      UNKNOWN_UNKNOWN          no
    RT4-3   Important   MUTANT_SURVIVED          yes
    RT4-4   Important   MUTANT_SURVIVED          yes
    RT4-5   Medium      VACUOUS_SUCCESS_CONDITION no
    RT4-6   Important   CLAIM_FALSIFIED          yes
    RT4-7   Low         INSUFFICIENT_EVIDENCE    no

## VERDICT

**BLOCK · blocking: true**

Four substantiated Important findings. Two are surviving single-point mutants on
the remediations of this round's own HIGHs — the migrator advisory lock (RT4-3,
a REORDER that no destroyer in the set can see, with the race measured back at
N-1 of N while the detector file is 18/18 green) and the G-02 tenant-crossover
JOIN (RT4-4, the full suite 1088/1088 with the fix removed, unclosed across two
rounds). One is a published FALSE unreachability proof of the exact class this
register has already been burned by twice, inside a closure audit whose stated
denominator missed it (RT4-6). One makes the provenance of the builder-self-run
gate 1-3 results forgeable by a command that never touches the harness (RT4-1).

Gate 1's exploit replay and gate 2's named destroyers D1-D7 survived my best
attempt and are reported as such. That is the limit of my attempt, not proof of
correctness.

I do not certify. AEGIS Ω-MAX adjudicates.
