# GATE 5 — INTEGRATION & REGRESSION — W1.3 candidate-4
subject: e71b51e9ed333d1feab1cd6819496269d201a6e2 · contracts 7d576681 · blocking: true

Reviewer: independent gate 5. Read-only audit. No edits to the candidate or its history.
Environment: ROOT=/Users/andrelove/aaliyah-w13-rv5-int · DB=postgres://postgres:test@127.0.0.1:54605/aaliyah_test

## Subject verified (not trusted)

| item | claimed | verified | how |
|---|---|---|---|
| core HEAD | e71b51e9ed333d1feab1cd6819496269d201a6e2 | MATCH | `git -C $ROOT/aaliyah-wave1-core rev-parse HEAD` |
| core tree OID | (not claimed) | 5af8080da732f8b4c4afd6b81337ab4a88b06950 | `git rev-parse HEAD^{tree}` |
| core status --porcelain (before) | clean | EMPTY | executed |
| contracts HEAD | 7d576681d1001eb4c4a7f044f7793cdb3f80af76 | MATCH | `git -C $ROOT/aaliyah-wave1-contracts rev-parse HEAD` |
| contracts tree OID | a34af636b5ce62dbb2830a8a7b716816f42ea041 | MATCH | `git rev-parse HEAD^{tree}` |
| core status --porcelain (after) | — | EMPTY | re-verified at the end |
| contracts status --porcelain (after) | — | EMPTY | re-verified at the end |

**VERDICT: BLOCK · blocking: true** (full reasoning at the end of this file)

---

## 1. THE CONTRACTS PIN — falsified four ways, guard holds

Baseline (executed, `$ROOT/aaliyah-wave1-core`):

    $ bash scripts/contracts-provenance.sh
    PASS  Contracts provenance 7d576681d1001eb4c4a7f044f7793cdb3f80af76 tree a34af636b5ce62dbb2830a8a7b716816f42ea041 (aaliyah.postcondition-verification/v1, aaliyah.executive-messaging/v1, aaliyah.executive-communications/wave1)
    exit 0

    $ bash scripts/ci-guards.sh
    PASS x8 ... RELEASE GUARDS: PASS   (exit 0)   <- the claimed 8/8, VERIFIED

Contracts worktree tree OID **a34af636b5ce62dbb2830a8a7b716816f42ea041 — MATCHES** the
register/guard claim (`git -C $ROOT/aaliyah-wave1-contracts rev-parse HEAD^{tree}`).

### FALSIFICATION A — pin drift (contracts HEAD moved to the pin's parent)

    $ git -C $ROOT/aaliyah-wave1-contracts checkout --detach aa1190c
    $ bash scripts/contracts-provenance.sh
    FAIL  Contracts SHA mismatch: expected 7d576681d1001eb4c4a7f044f7793cdb3f80af76, got aa1190c72819cb0271ef4c02b0533c1f9ce97081
    provenance EXIT=1
    (restored to 7d57668; tree a34af636... re-verified, status --porcelain empty)

### FALSIFICATION B — the thing core actually IMPORTS is tampered

This is the load-bearing one: `node_modules/@aaliyah/contracts` is a real copy under
`.pnpm/`, NOT a symlink into the worktree, so the worktree's SHA proves nothing about
what core runs. Appended one comment line to the installed
`node_modules/@aaliyah/contracts/dist/src/index.js`:

    BEFORE:    4919c29d4db11dcf2ba0179978cea80f34ac6ed7372a70b725138e5366a1d9d3
    TAMPERED:  677facab223660cedda968905a7e3faa275eef7ec6b6259fe345b5d5d1d12c8c
    $ bash scripts/contracts-provenance.sh
    FAIL  installed Contracts artifacts do not match isolated exact-SHA build
    provenance EXIT=1
    RESTORED:  4919c29d4db11dcf2ba0179978cea80f34ac6ed7372a70b725138e5366a1d9d3  (byte-identical)
    $ bash scripts/contracts-provenance.sh  -> PASS, exit 0

### FALSIFICATION C — dirty contracts worktree, AND guard-7 propagation through ci-guards

    $ printf '\n// gate5 drift\n' >> $ROOT/aaliyah-wave1-contracts/src/agents/followup.ts
    $ bash scripts/ci-guards.sh
    ...
    FAIL  Contracts provenance mismatch:
        FAIL  Contracts worktree is dirty; provenance is not immutable
    PASS  the full suite's executed set is bound to the commit

    RELEASE GUARDS: FAIL
    (restored with `git checkout --`; status --porcelain empty, tree a34af636... re-verified)

**Verdict on the pin mechanism: the guard is real. It fails when it should fail, on three
independent axes, and the failure propagates to `RELEASE GUARDS: FAIL`.** This is the one
control this round that survived deletion-style falsification cleanly.

### FINDING I-1 · Low · the handoff's "verifiable WITHOUT access to the contracts repo" is false

`scripts/contracts-provenance.sh:13-16` is fail-CLOSED on the repo being absent, so with
no contracts repo the pin is not verified — the script refuses. Executed with a
byte-identical copy of the script placed where `../aaliyah-wave1-contracts` does not exist:

    $ cmp -s scripts/contracts-provenance.sh $SCRATCH/fake2/aaliyah-wave1-core/scripts/contracts-provenance.sh && echo identical
    identical
    $ bash $SCRATCH/fake2/aaliyah-wave1-core/scripts/contracts-provenance.sh
    FAIL  Contracts repository unavailable at ../aaliyah-wave1-contracts
    EXIT=1

What is true is the weaker and still useful claim: **core carries the expectation**
(`expected_sha` + `expected_tree` hardcoded at `scripts/contracts-provenance.sh:6-7`), so
a reader need not TRUST the contracts repo — but they must HAVE it. Fail-closed is the
right behaviour; the HANDOFF sentence (`HANDOFF.md:26-28`) overstates it.
What assertion should have caught it: none exists — no test asserts the repo-absent path.
Blocking: NO.

### FINDING I-2 · Info · the isolated build trusts the contracts repo's own node_modules

`scripts/contracts-provenance.sh:44-45` copies `$contracts_repo/node_modules/.` into the
isolated build root and compiles with it. The compiler used to produce the "independent"
reference build is therefore the unverified one sitting next to the subject. A tampered
`typescript` there would produce a tampered reference that matches a tampered install, and
the `diff -qr` at line 87 would pass. Local-only scope; recorded, not blocking.

### FINDING I-3 · Low · the frozen manifest covers 17 `src/` files and NONE of this round's subjects

`scripts/aegis-frozen.sh:37-44` rejects any manifest path not beginning with `src/`, and
`.aegis-frozen.sha256` pins 17 files. `src/persistence/postgres/migrations.ts`,
`src/persistence/applicationState.ts`, `src/server.ts` and the privilege map are NOT among
them, and neither `scripts/ci-guards.sh` nor `scripts/contracts-provenance.sh` CAN be
(the awk filter forbids non-`src/` paths). Guard 1's "frozen manifest verified (17 pinned)"
therefore says nothing about any file this candidate changed. Not a defect in itself —
recorded so guard 1 is not read as coverage it does not provide. Blocking: NO.

### FINDING I-4 · Low · `ci-guards.sh` writes fixed-name files into `/tmp`

`scripts/ci-guards.sh:15,73,87` use `/tmp/frozen.out`, `/tmp/contracts-provenance.out`,
`/tmp/discovery.out`. Six reviewer environments were dispatched concurrently against this
same host; concurrent runs clobber each other's output files. The pass/fail decision comes
from the exit status, so the VERDICT is not corruptible this way, but the printed evidence
is — a `PASS  <other process's text>` line is possible. Blocking: NO.

---

## 2. MIGRATIONS 001..060 AS AN INTEGRATION SURFACE

Method: the REAL COMPILED runner, `dist/src/persistence/postgres/migrations.js`, built at
this SHA with `npx tsc -p tsconfig.json` (exit 0). Probes are ES modules in the session
scratchpad; each creates its own database on `postgres://postgres:test@127.0.0.1:54605`
and none touches the suite's database. `dist/` is `.gitignore`d; where a probe needed a
mutated build, the file was saved, mutated, and restored, with SHA-256 printed each time
(original `984643ebf2dbd8c577d21442ffd225dd4c10c1debdbfd95a08c0264c265dd423` — restored
and re-verified after every mutation).

### INT-DIGEST re-executed independently — the three claimed properties HOLD

    $ node probes/p1-digest.mjs                       (database g5_int_digest, fresh)
    P1 fresh apply ONE run: {"rows":60,"digested":60}
    P2 re-run no-op: LEDGER IDENTICAL {"h":"81b8e609850f0ecf2dc59a1b345ce0ad","n":60}
    P3 refusal: migration 055_memory_key_destruction_settlement was applied with different content (sha256:bbbb...)
    P3 ledger untouched: YES

60/60 digested in ONE run (the first-version defect the register names does NOT recur),
re-running leaves the ledger byte-identical, and a changed digest is refused with the
ledger hash unchanged. The claimed INT-DIGEST properties are VERIFIED by execution.

Boundary probes against a DIGESTED ledger, with the real runner carrying a mutated build:

| probe | edit to migration 055's SQL | result |
|---|---|---|
| comment-only | inserted `-- G5 EDIT: ...` as a leading line | **REFUSED** |
| whitespace-only | one extra space in `CREATE TABLE IF NOT EXISTS  memory_...` | **REFUSED** |

The digest is SHA-256 over the exact SQL text (`migrations.ts:19-21`), with no
normalisation, so there is no comment/whitespace/semantic-rewrite bypass: every byte
change moves the hash. Executed, not argued.

### FINDING I-5 · **Important** · G-08's fix LAUNDERS an edited migration on the pre-057 upgrade path, and the register does not disclose it

**The defect in one sentence.** On the upgrade path every already-deployed database must
take — a ledger written before migration 057 existed, so every row has no digest — an
edited already-applied migration is not merely undetected: the first post-057 run WRITES A
DIGEST asserting the edited content was applied, permanently certifying the database as
holding SQL it does not hold.

**EXECUTED reproduction.** Two databases, both created with the UNMODIFIED compiled build:

    $ node probes/p4-setup.mjs
    A pre-057 deployment: rows= 56  sql_digest column present= 0      (runMailMigrations(pool,{through:"056_memory_least_privilege_trim"}))
    B post-057 deployment: {"rows":60,"digested":60}
    B recorded digest for 055: sha256:5f39d2affcb1cb02cb42f9ac9c7633b4a506717e274c3da5b8b793b25556766c

Then migration 055's SQL was edited in the compiled build (one added comment line;
dist sha 984643eb… -> 57eacbe5…) and the SAME runner was pointed at both databases:

    $ node probes/p4-run.mjs
    A pre-057 upgrade path: ACCEPTED SILENTLY
    A pre-057 upgrade path: ledger {"rows":60,"digested":60}  055 digest now sha256:85f47cd79237a7e9b65f11e17a446a80b7aa4c198011740fd523aae514f5a86b
    B post-057 positive control: REFUSED -> migration 055_memory_key_destruction_settlement was applied with different content (sha256:5f39d2af...)
    B post-057 positive control: ledger {"rows":60,"digested":60}  055 digest now sha256:5f39d2af...

`85f47cd7…` is the digest of the EDITED text. The database ran the UNEDITED 055 and is now
recorded as having run the edited one. B is the positive control that proves the probe
would have caught it had a digest existed.

**Second-order consequence — the laundering is not recoverable.** Restoring the correct
source does not repair the database; it makes the correct source the thing that is refused:

    $ node probes/p6-poison.mjs        (unmodified build, sha 984643eb…, against database A)
    g5_pre057 recorded 055 digest: sha256:85f47cd79237a7e9b65f11e17a446a80b7aa4c198011740fd523aae514f5a86b
    UNMODIFIED build against the laundered ledger: REFUSED -> migration 055_memory_key_destruction_settlement
      was applied with different content (sha256:85f47cd7...) than this build carries (sha256:5f39d2af...)

**The same laundering is reachable WITHOUT a pre-057 database.** Any ledger row whose
`sql_digest` is NULL is blessed by `migrations.ts:6406-6414` — including a row an OLDER
build inserts during a mixed-build rolling deploy, since the pre-057 insert is
`INSERT INTO aaliyah_mail_migrations (id) VALUES ($1)` and succeeds with the column
present and NULL. Executed directly:

    P3b digest NULLed for 055; re-running the runner...
    P3b result: ACCEPTED, digest re-blessed to sha256:5f39d2affcb1cb02cb42f9ac9c7633b4a506717e274c3da5b8b793b25556766c

**What assertion should have caught it and did not.** `INT-DIGEST`
(`tests/wave1MigrationReplayPostgres.integration.test.ts:621-677`) exercises ONLY the
fresh-apply population: `runMailMigrations(pool)` on an empty database, then a digest
rewrite. There is no test in the repository that migrates `through` a pre-057 point,
changes content, and re-runs — the one population where G-08's original defect actually
lives. `grep -rn "through:" tests/` confirms the upgrade-path helper exists and is used
elsewhere, so the mechanism to write this test was already in hand.

**And the source cites a disclosure that does not exist.** `migrations.ts:6387-6391`:

        // Rows written before 057 have no digest. They are filled in from the
        // current source, which means a content edit made BEFORE 057 existed is
        // blessed here — there is nothing to compare it against. Only edits after
        // this point are detectable, and the register says so.

    $ grep -n -i "backfill\|blessed\|pre-057\|before 057\|undigested" docs/WAVE1_BLOCKER_REGISTER.md
    (one hit: line 1379, the G-08 row itself — which says none of this)

The register's G-08 disposition reads **"CLOSED** by migration 057: the ledger records a
digest of the SQL applied, and the runner refuses before applying anything when an applied
migration's content no longer matches", with no population limit. It is CLOSED for
databases that were already digested. It is not closed — and is actively made worse — for
the population the G-08 incident was actually about.

**Blocking: YES.** Not because a fresh apply is wrong (it is right, and I proved it), but
because a HIGH finding is published CLOSED against a population where the remediation
manufactures a false attestation, and the source's claim that the register discloses this
is false. A non-laundering backfill (leave NULL, or record `unverified:` so later runs
cannot mistake it for proof) plus a corrected register row would close it.

### W1BR-014 — verified by execution, and the boundary mapped

Eight boundary probes, each against its OWN freshly-created, fully-migrated database
(the first attempt let probes contaminate each other; that run was discarded and redone).
`node probes/p7b.mjs`, real compiled runner, verbatim output:

    B1 delete 027 — the canonical W1BR-014 case
       ledger before n=59 -> after n=59  UNCHANGED
       REFUSED -> migration 027_memory_exact_numeric_domain is older than migration ordinal 60, which is already applied...
    B2 delete the HIGHEST row 060 ONLY — the top edge of 'older'
       ledger before n=59 -> after n=60  CHANGED
       ACCEPTED (no refusal)
    B3 delete the tail 059+060
       ledger before n=58 -> after n=60  CHANGED
       ACCEPTED (no refusal)
    B4 keep ONLY 060 — a wiped ledger with one late row
       ledger before n=1 -> after n=1  UNCHANGED
       REFUSED -> migration 001_mail_oauth_states is older than migration ordinal 60...
    B5 EMPTY the ledger entirely — highestApplied = -1
       ledger before n=0 -> after n=0  UNCHANGED
       REFUSED -> constraint "wave1_lifecycle_tenant_binding" for relation "wave1_lifecycle_events" already exists
    B6 malformed ledger id — does migrationOrdinal fail CLOSED?
       ledger before n=61 -> after n=61  UNCHANGED
       REFUSED -> migration id not-a-migration does not begin with a three-digit ordinal
    B7 a FUTURE id 061 from a newer build, everything else applied (DOWNGRADE)
       ledger before n=61 -> after n=61  UNCHANGED
       ACCEPTED (no refusal)
    B8 delete 057 (the digest migration itself) — column stays, row gone
       ledger before n=59 -> after n=59  UNCHANGED
       REFUSED -> migration 057_migration_content_digest is older than migration ordinal 60...

**W1BR-014 itself is REAL and fail-closed where it claims to be.** B1, B4, B6 and B8 are
all refused with the ledger byte-unchanged, and B8 in particular shows you cannot escape
the digest check by deleting 057's own ledger row. The refusal is also genuinely
pre-emptive: `MIGRATIONS` is strictly ascending by ordinal (verified — 60 ids, 001..060,
no duplicate ordinals, no inversion), so the FIRST unapplied entry carries the lowest
unapplied ordinal, and if it is refused nothing has been applied yet. And B5 shows the
apply phase is atomic: the run died mid-way and the ledger came back at n=0.

### FINDING I-6 · Medium · "older" exempts the top of the ledger, and the source claims a partial-restore protection it does not have

The predicate is `ordinal < highestApplied` (`migrations.ts:6371`), strictly less than the
highest OTHER applied ordinal. Consequences, executed:

- **B2/B3: deleting the newest row, or a tail of rows, is a SILENT REPLAY.** Not refused,
  not warned, ledger CHANGED. The operator action W1BR-014 exists to refuse — "delete a
  row and re-run, believing it is a repair" — is refused for every migration except the
  most recent ones, which are precisely the ones an operator is most likely to be poking
  at after a bad deploy. The deleted row takes its digest with it, so I-5's content check
  does not cover this path either.
- **B5: an emptied ledger gets NO W1BR-014 refusal at all.** `migrations.ts:6357-6359`
  states the protection covers "when a row is deleted and the runner is re-run, when
  tooling replays by id, or **after a partial restore**". After a restore that loses the
  ledger, `highestApplied` is `-1` and every migration is `>= -1`, so the runner replays
  001 forward over a populated schema and dies on the first non-idempotent DDL
  (`constraint "wave1_lifecycle_tenant_binding" ... already exists`). The outcome is
  SAFE — the transaction rolls back, ledger unchanged — but it is safe by accident of DDL
  idempotence, not by the stated guard, and the operator gets a constraint error instead
  of the designed refusal. The written claim is falsified by execution.
- **B7: a DOWNGRADE is accepted in silence.** A ledger row from a newer build
  (`061_from_a_newer_build`) is ignored: nothing in the runner notices that the database
  is ahead of the build, so an older binary boots and serves against a schema it does not
  know. Nothing refuses, nothing logs.

What assertion should have caught it: `tests/wave1MigrationReplayPostgres.integration.test.ts`
tests exactly one case — delete 027, expect refusal (lines 83-117), plus the same case
again inside the session-state test (lines 167-173) and a `through`-variant at line 441.
There is no assertion at the top edge, none for an emptied ledger, and none for an unknown
future id. Blocking: NO — the behaviour is not unsafe in the cases I executed; the
register's and the source's DESCRIPTION of the protection is wider than the protection.

### FINDING I-7 · Low · a stale comment in the migration test says the advisory lock is gone

`tests/wave1MigrationReplayPostgres.integration.test.ts:121-123`: "The lock is gone
(removed as unfalsifiable once the ledger creation tolerated a lost race)". It is not
gone — it was restored in `c2e5747` and is taken at `src/persistence/postgres/migrations.ts:6278`.
The test's own final assertion (`pg_locks` advisory count = 0 after the run) is still
correct, because the runner releases it. A reviewer reading this file for the migrator's
lock story is told the opposite of the code. Blocking: NO.

### Migration 047 — nothing silently depends on it being safe

Not re-proving it unsafe (out of scope per the protocol). Checked only that nothing else
asserts or assumes rolling-update/rollback safety for it. `grep -rn "047" src/ tests/ docs/`
results are recorded in "What I did NOT cover" below.

---

## 3. THE MIGRATOR UNDER REAL INTEGRATION — the boot path DOES reach the tested code

`src/server.ts:79` calls the same exported `runMailMigrations(pool)` the tests import
(`tests/wave1MigrationReplayPostgres.integration.test.ts:6-9`). That is confirmed by
reading AND by execution: the refusal message the real boot emits is byte-identical to the
one the test asserts.

Four boots of the REAL compiled `dist/src/server.js`, each against its own database, with
`AALIYAH_DATABASE_URL` set on THAT PROCESS ONLY (never exported to my shell — trap 1):

| boot | database state | result |
|---|---|---|
| (a) | fresh, empty | boots; `mail state: postgres (migrations applied)`; `/ready` -> `{"status":"ready","checks":{"database":"ok","readDatabase":"ok"}}` |
| (b) | partially migrated (`through: 049_...`, 49 rows) | boots; completes to 60 rows, 60 digested |
| (c) | migrated by a simulated OLDER build (`through: 056_...`, **no `sql_digest` column at all**) | boots; completes to 60 rows, 60 digested |
| (d) | fully migrated, 055's recorded digest poisoned | **REFUSES TO BOOT**, exit 1, no socket opened |

(d) verbatim:

    startup failed: migration 055_memory_key_destruction_settlement was applied with different
    content (sha256:eeee...) than this build carries (sha256:5f39d2af...). The database does
    not hold what this source says it holds. Refusing.
    EXIT=1
    /ready: (no answer)

**This is a genuine positive result and I want it recorded as such:** the digest control is
not a test-only artefact. It is on the real boot path, it fails closed, and it refuses
before the HTTP socket exists. That is the right shape.

It is also where FINDING I-5 bites in production terms: boot (c) is a real deployment
upgrading from a pre-057 build, and the real server silently stamped 60/60 digests over a
ledger it could not verify — the laundering happens on the boot path, unattended, with the
only output being `mail state: postgres (migrations applied)`.

---

## 4. OPERATOR SURFACES (G-09) AND STALE PROOF

### G-09 is STILL TRUE at this SHA — confirmed by route enumeration, not by grep alone

The compiled app's express router, walked in-process
(`createCoreApp` from `dist/src/http/createCoreApp.js`, the same constructor `server.js`
calls), exposes exactly ten routes:

    DELETE       /api/mail/connections/:connectionId
    GET          /api/mail/connections/:connectionId
    GET          /api/mail/connections/google/callback
    GET          /health
    GET          /ready
    POST         /api/auth/google/login
    POST         /api/auth/logout
    POST         /api/mail/connections/:connectionId/test
    POST         /api/mail/connections/google/start
    POST         /internal/evals/run-task
    TOTAL ROUTES: 10

None reaches the obligation ledger. The CLI (`local-runner/aaliyah.ts`) has four commands
— `connect`, `draft-inbox`, `status`, `init-profile` — and none reaches it either.
Denominator for the absence claim: 10 HTTP routes (all of them, enumerated from the live
router object, not from source) + 4 CLI commands (all of them, from the command switch).
Inclusion rule: every route/command the compiled app registers.
`grep -rn "listKeyDestructionObligations\|settleKeyDestruction" src/ local-runner/ tests/`
returns callers only in `src/application/memory/*` (the service plumbing),
`src/persistence/postgres/wave1TrustedMemoryStore.ts` (the implementation) and
`tests/wave1MemoryHoldErasurePostgres.integration.test.ts`. **G-09 verified.**

### FINDING I-8 · Low · K-01's row STILL claims "listable", twice, un-annotated

G-09's disposition says "the K-01 wording is corrected below". The correction is a separate
paragraph at `docs/WAVE1_BLOCKER_REGISTER.md:1411-1420`. **K-01's own row was not
touched**: line 1116 still reads "a durable, **listable** obligation naming WHY", and its
"Proven by" column still ends "**obligation ledger listable**". A reader who looks up K-01
— which is a CRITICAL entry, and the one an operator hitting `ERASURE_PENDING_SETTLEMENT`
would look up — is told twice that the ledger is listable, with no marker pointing 295
lines forward to the correction. The correction exists; it is not where the claim is.
Blocking: NO.

---

## CORRECTION TO FINDING I-6 — I OVERCLAIMED, AND THE SUITE FALSIFIED ME

I wrote I-6 from probe output before running the suite. Running it corrects me, and the
correction is recorded here rather than quietly edited out.

`node scripts/test-watchdog.mjs -- tests/wave1MigrationReplayPostgres.integration.test.ts
tests/wave1MemoryPrivilegesPostgres.integration.test.ts
tests/wave1MemoryUpgradePostgres.integration.test.ts`
-> `WATCHDOG VERDICT: PASS scope=FOCUSED tests=30 pass=30 fail=0 cancelled=0 skipped=0 todo=0`

Two of the boundaries I reported as uncovered are covered, deliberately and by name:

- **B2 is not a gap.** `tests/wave1MigrationReplayPostgres.integration.test.ts:448-469`,
  "W1BR-014: deleting the HIGHEST applied migration is allowed to re-apply" — with the
  reason stated: "Re-applying the newest migration reverts nothing, because nothing later
  exists to revert — so the guard must NOT refuse it, or an ordinary re-run after an
  interrupted deploy would be impossible." That is correct and it is asserted. **B3 falls
  to the same argument** (a contiguous tail replays in order, reverting nothing), and I
  confirmed the non-contiguous case is caught by the general rule.
- **B6 is not a gap.** Same file, line 471: "a migration id without a three-digit ordinal
  fails loudly rather than sorting arbitrarily".
- The general rule is also held beyond migration 027 — line 431, "W1BR-014: the refusal is
  about ORDER, not about that one migration", using 038.

**I-6 is hereby reduced to Low, and its content to exactly two items:**

1. **B5 — the source's "after a partial restore" claim is false.** `migrations.ts:6357-6359`
   says the protection covers "when a row is deleted and the runner is re-run, when tooling
   replays by id, or **after a partial restore**". With the ledger emptied, `highestApplied`
   is `-1` and no refusal is possible; the run replays 001 forward over a live schema and
   dies on `constraint "wave1_lifecycle_tenant_binding" ... already exists`. Ledger came
   back n=0 — the apply phase IS atomic, which is the mitigating fact — but the guard named
   in the comment does not exist for that case and no test asserts one.
2. **B7 — a ledger row from a NEWER build is ignored in silence.** Inserting
   `061_from_a_newer_build` and running the 001..060 build: ACCEPTED, no refusal, no log.
   An older binary will serve against a schema it does not know. No test covers it.

Blocking: NO.

### What the same focused run also PROVES (regression, section 5 evidence)

Previously-green properties most at risk from this candidate's diff, re-executed at
e71b51e rather than inherited:

| property | test | result at e71b51e |
|---|---|---|
| privilege map = declared map, section by section, live DB vs `memoryPrivileges.expected.json` | `the privilege map of every memory role equals the declared map` | PASS |
| every SECURITY DEFINER guard still pins `search_path=pg_catalog, public, pg_temp` | same file, line 171-174 | PASS |
| the four positive controls that prove the map CAN see a widening | 4 POSITIVE CONTROL tests | PASS |
| migrator race, older build, fresh DB, 10 trials | `K-06 REOPENED` | PASS (2006ms) |
| migrator race, steady state | `K-06: a STEADY-STATE database is raced cleanly` | PASS |
| 2/3/5 concurrent migrators on a fresh DB all fulfil, ledger applied exactly once | 3 tests | PASS |
| the bare-`CREATE TABLE IF NOT EXISTS` crash really does happen (negative control) | `POSITIVE CONTROL: bare concurrent CREATE TABLE IF NOT EXISTS really does crash N-1 with 23505` | PASS |
| advisory-lock serialisation before the ledger exists | `K-06c` | PASS |
| 42710/42P07/23505 tolerance, and only when the ledger really appeared | `K-06b` | PASS |
| 050–060 apply over a database populated at 049 | `U-1` | PASS |
| 047 refuses over a plaintext binding, plaintext survives the refusal | dedicated test | PASS |
| INT-DIGEST | dedicated test | PASS |

The privilege-map test is NOT self-referential: `compareDeclaredMap()`
(`tests/wave1MemoryPrivilegesPostgres.integration.test.ts:63-73`) reads the LIVE map via
`memoryPrivilegeMap(pool)` and diffs it against the declared JSON section by section,
reporting `widened`/`narrowed` by name, and a SECOND test asserts the declared JSON's own
boundaries so a regenerated map that absorbed a widening still fails. I checked this
specifically because "assertions that cannot fail" is this round's standing weakness; this
pair can fail, and the four positive controls demonstrate that it does.

---

## 5. REGRESSION — diff against predecessors, and the properties re-executed

All five named predecessors are ancestors of the candidate (`git merge-base --is-ancestor`
-> YES for `8a0bf05`, `b3efc82`, `3ba769f`, `03581a3`, `86d33c9`), so this is a linear
history: no merge, no rebase artefact, no lost hunk to look for. `86d33c9..e71b51e` over
`src/` + `scripts/` is 17 files, +1533/-236, dominated by
`src/persistence/postgres/migrations.ts` (+684) and
`src/persistence/postgres/wave1TrustedMemoryStore.ts` (+546).

Migration count 56 -> 60. The four new migrations are 057 (digest), 058 (settled-obligation
immutability), 059 (settlement evidence binding), 060 (obligation settlement pointer FK +
a narrowed INSERT column grant).

Properties I judged most at risk and RE-EXECUTED at this SHA (table in the correction
section above, plus):

**Clean-database full memory/migration/alias/pool integration batch — 471/471 PASS:**

    $ node scripts/test-watchdog.mjs -- \
        tests/wave1MemoryHoldErasurePostgres.integration.test.ts \
        tests/wave1MemoryIdentityPostgres.integration.test.ts \
        tests/wave1MemoryPrivilegesPostgres.integration.test.ts \
        tests/wave1MemoryReachabilityPostgres.integration.test.ts \
        tests/wave1MemoryReconciliationPostgres.integration.test.ts \
        tests/wave1MemoryUpgradePostgres.integration.test.ts \
        tests/wave1MigrationReplayPostgres.integration.test.ts \
        tests/wave1PoolResiliencePostgres.integration.test.ts \
        tests/wave1TrustedMemoryPostgres.integration.test.ts \
        tests/wave1AliasRegistryPostgres.integration.test.ts
    WATCHDOG VERDICT: PASS scope=FOCUSED tests=471 pass=471 fail=0 cancelled=0 skipped=0 todo=0
    duration_ms 365570.960792

No regression found in the migrator, the privilege map, settlement, or the `search_path`
pin. The privilege map's own diff (live vs declared) reported zero `widened` and zero
`narrowed` in every section.

### Rolling-deploy coupling introduced by the NEW migrations — checked, and bounded

The register's disclosed rule (line 912) is "a release containing 047 must be a full-stop
deploy, and so must any later **column-dropping** migration". I checked whether 057–060
introduce the same hazard by another route. They drop no column
(`grep -n "DROP COLUMN" src/persistence/postgres/migrations.ts` -> only lines 4227-4229,
which are 047 itself). They DO narrow privileges — `060` at `migrations.ts:6058-6064`
revokes `INSERT` on `memory_key_destruction_obligations` from `aaliyah_memory_mutator` and
re-grants a narrower column list. I checked whether the predecessor build writes a column
outside that list: no code in `86d33c9` or at HEAD issues `INSERT INTO
memory_key_destruction_obligations` directly, so there is no old-build statement the new
grant breaks. **Not a finding — checked and clear.** `056`'s revokes predate this
candidate (86d33c9 already carried 56 migrations) and are not new coupling here.

### FINDING I-13 · Low · G-04's "all 35 SECURITY DEFINER functions pinned" is stale by two — but the property is RE-BOUND and strengthened

`docs/WAVE1_BLOCKER_REGISTER.md:1375`, G-04's evidence column: "The reviewer's own
execution: ATK-P1 closed, `ALTER ROLE … SET search_path` inert under `SET LOCAL ROLE`,
**all 35 SECURITY DEFINER functions pinned**". That execution happened against `86d33c9`.
At `e71b51e` there are **37**:

    $ node -e 'const m=require("./tests/support/memoryPrivileges.expected.json"); ...'
    securityDefiner entries: 37
    functionConfig entries: 46
    functionConfig entries WITHOUT the pinned path: 0 []
    SECURITY DEFINER functions with NO pinned-path entry: 0 []

    $ diff 86d33c9's map against this one
    86d33c9 securityDefiner: 35   e71b51e: 37
    ADDED:
      + public.aaliyah_memory_record_settled_destruction(text) OWNER postgres
      + public.aaliyah_memory_settled_obligation_frozen() OWNER postgres
    REMOVED: (none)

Both additions are on the settlement path this candidate built for B2/G-03. The stale
NUMBER is in the register; the PROPERTY is re-bound, because this candidate ADDED a
`functionConfig` section to the declared map (it does not exist in `86d33c9`'s map at all)
and the live-vs-declared diff plus
`tests/wave1MemoryPrivilegesPostgres.integration.test.ts:171-174` now assert the pinned
path for all 46 entries. **This is a case where the builder strengthened a control instead
of inheriting a reviewer's one-off — it should be credited.** Only the register's "35"
needs correcting. Blocking: NO.

### Stale proofs, named

Per the fail-closed rule, every prior proof not re-executed at this exact tuple is STALE by
default. These are the ones that matter and their status after my run:

| claim | bound to | re-executed at e71b51e? | status |
|---|---|---|---|
| G-01 migrator vs older build, 10 fresh + 5 steady | 86d33c9 probe, landed as tests | YES, by me (`K-06 REOPENED`, `K-06 STEADY-STATE`) | RE-BOUND |
| G-01's discrimination half ("FAILS against 86d33c9") | 86d33c9, disposable worktree | NO — cannot be, without reverting | STALE by construction; gate 6 owns discrimination |
| G-02 tenant crossover / S-13 | 86d33c9 | YES (in the 471) | RE-BOUND |
| G-03 privilege map lost `settled_by` | declared map | YES (live-vs-declared diff) | RE-BOUND |
| G-04 "all 35 SECURITY DEFINER pinned" | 86d33c9 manual execution | property YES, COUNT NO (37 now) | see I-13 |
| G-05 privileges/K-10 lock window | 86d33c9 | YES (privileges file passed in a 10-file batch) | RE-BOUND |
| G-07 surviving COALESCE mutant | mutation sweep | NO | STALE; gate 6 owns it |
| G-08 INT-DIGEST | this SHA | YES, by me — and see I-5 for the population it does not cover | RE-BOUND, SCOPE WRONG |
| G-09 no operator surface | 86d33c9 boot | YES, by me (10 routes, 4 CLI commands) | RE-BOUND |
| G-10 stray freeze file | evidence dir SHA256SUMS | NOT MY SCOPE — see gaps | — |
| G-11 ambient env coupling | 86d33c9 | YES, by me (reproduced) | RE-BOUND |
| K-12 "no RLS exists anywhere in src/ or tests/" | 86d33c9 grep | YES, by me | RE-BOUND — `grep -rniE "ROW LEVEL SECURITY\|CREATE POLICY\|ALTER POLICY\|FORCE ROW LEVEL"` over `src/ tests/ scripts/` returns zero policy definitions; the only `BYPASSRLS` strings are the privilege map's own detector (`tests/support/memoryPrivileges.ts:269`) and its positive control (`tests/wave1MemoryPrivilegesPostgres.integration.test.ts:199`) |
| K-13 migration 047 full-stop procedure | never executed | NO, and not claimed | honestly declared |
| K-21 memory exhaustion | never executed | NO, and declared NOT_VERIFIED | honestly declared |
| "67 untested CHECK constraints" | nothing | NO, declared UNVERIFIED | honestly declared |
| suite 1088/1088 | builder's run | **NO — I did not complete a full-suite run** | STALE for me; see gaps |
| guards 8/8 | builder's run | YES, by me | RE-BOUND |

---

## 6. ENVIRONMENT COUPLING (G-11) — reproduced, and judged

### Reproduction (executed, ambient variable scoped to ONE process, never to my shell)

    $ node scripts/test-watchdog.mjs -- tests/relationship.test.ts tests/trust.test.ts \
        tests/onboarding.test.ts tests/applicationStore.test.ts tests/tenantIsolation.test.ts \
        tests/style.test.ts tests/revenue.test.ts
    WATCHDOG VERDICT: PASS scope=FOCUSED tests=38 pass=38 fail=0 ...   duration_ms 4339

    $ env AALIYAH_DATABASE_URL=<same DB> node scripts/test-watchdog.mjs -- <same files>
    ✖ approval reviews never leak across tenants (the live JSONL gap) (39.873375ms)
    WATCHDOG VERDICT: FAIL scope=FOCUSED tests=38 pass=37 fail=1 ...   duration_ms 14670
    (my shell: AALIYAH_DATABASE_URL=<unset>  — trap 1 respected throughout)

One of the register's four, in this subset; the 4.3s -> 14.7s jump confirms the tests
really were rerouted to Postgres. The coupling is real and deterministic.

### My judgement on the disposition

**The production code path is not a defect, and I will not call it one.**
`src/persistence/applicationState.ts:100-115` implements a documented resolution rule —
Postgres when `AALIYAH_DATABASE_URL` is set, in-memory twin for dev, throw in production
with neither — mirroring the mail and identity backends. A store that changes backend
because its backend variable is set is doing exactly what it says. Memoising it is
ordinary. `resetApplicationStoreForTests()` exists at line 118.

**But the disclosure IS papering over one thing, and it is cheap to fix.** The suite has an
undeclared, unasserted precondition: "`AALIYAH_DATABASE_URL` must not be set". Nothing
enforces it. The consequence is not a slow test or a confusing message — it is a
**FAIL verdict with named failing tests**, which reads as a code defect. The watchdog is
the right place to fail closed and already does so for harness-integrity questions of
exactly this shape (`FILES_WITHOUT_TESTS`, `NO_SUMMARY`, `--verify-discovery`), and it
already inspects the environment (`environment.nodeOptionsIgnored`,
`environment.tsNodeIgnored` are in its evidence). It does not ask this one.

### FINDING I-11 · Low · the G-11 precondition is disclosed in prose and asserted nowhere

Two reviewers have paid for this (the register says so), I paid part of a run for it, and
the remedy is one check in `scripts/test-watchdog.mjs` that REFUSES with a named reason
instead of letting four tests fail as if the code were wrong — or, better, four tests that
pass an explicit env to `applicationStoreFromEnv({...})` instead of reading `process.env`.
Disposition "not a candidate defect" is correct about `src/`; it is not correct that
nothing is owed. Blocking: NO.

---

## 7. TWO INTEGRATION DEFECTS IN THE HARNESS ITSELF, FOUND BY EXECUTION

### FINDING I-9 · Medium · a run's result depends on residual database state from a previous run, and nothing detects it

**The defect in one sentence.** At the same SHA, with `git.dirty: false` and the
watchdog's database probe reporting `reachable: true, reason: null`, the identical
ten-file command produced **FAIL 118/472** and then **PASS 471/471** — the only difference
being that I recreated `aaliyah_test` in between.

**EXECUTED reproduction.** My own full-suite attempt was killed by my background harness
(`reason: watchdog received SIGTERM`, `ORPHANED_PROCESSES: processes from this run were
still alive and were killed`), leaving `aaliyah_test` mid-flight. The next run:

    WATCHDOG VERDICT: FAIL scope=FOCUSED tests=472 pass=354 fail=118 cancelled=0 skipped=0 todo=0
      reason: FAILED_TESTS: 118
      reason: PASSED_NOT_EQUAL_TESTS: 354 of 472
    evidence database: {"required":true,"before":{"reachable":true,"reason":null},"after":{"reachable":true,"reason":null}}
    evidence git:      {"head":"e71b51e...","dirty":false}

Then, with nothing else changed:

    $ psql .../postgres -c "DROP DATABASE aaliyah_test WITH (FORCE)" -c "CREATE DATABASE aaliyah_test"
    $ <the identical command>
    WATCHDOG VERDICT: PASS scope=FOCUSED tests=471 pass=471 fail=0 cancelled=0 skipped=0 todo=0

**What assertion should have caught it and did not.** The watchdog's database probe
(`database.before`) tests REACHABILITY only. It does not ask whether the schema is the
one this commit's migrations produce, whether constraints/triggers a `ConstraintDestroyers`
file dropped were restored, or whether a previous run died mid-transaction. Its own
evidence file is therefore unable to distinguish a genuine 118-failure regression from a
dirty database — which is precisely the "commit message is not transferable evidence"
failure mode one layer down. It would be cheap to record, at minimum, a digest of
`aaliyah_mail_migrations` plus a count of enabled triggers before and after, and refuse
when `before` differs from a fresh migrate.

This matters beyond my own mishap: the register already records "AN OBSERVED INCOMPLETE
RUN" that "did not reproduce" and was attributed to host contention. A run killed or
crashed mid-flight leaves state that the NEXT run silently inherits, and the next run's
evidence file records `dirty: false` and `reachable: true`. **Blocking: NO** (it is a
harness-integrity defect, not a product defect), but it is the reason no verdict in this
round should be read without knowing whether the database was fresh.

### FINDING I-10 · Medium · the DENOMINATOR moves at a fixed SHA — a mechanism for the OPEN 1086/1087 finding

**Executed.** The two runs above executed the same ten files at the same SHA and reported
**472** and **471** tests. Diffing the two reporter outputs (cutting at the `✖ failing
tests:` block so the failure list is not double-counted) gives exactly one difference:

    contaminated: 472   clean: 471
    === ONLY IN CONTAMINATED ===
    tests/wave1MemoryUpgradePostgres.integration.test.ts
    === ONLY IN CLEAN ===
    (nothing)

The extra "test" is a **synthetic FILE-LEVEL entry**, emitted because that file's `before`
hook produced async activity after the test ended:

    ℹ Error: Test hook "before" at tests/support/hookSentinel.cjs:50:21 generated asynchronous
      activity after the test ended. This activity created the error "error: terminating
      connection due to administrator command" and would have caused the test to fail, but
      instead triggered an uncaughtException event.
    ✖ tests/wave1MemoryUpgradePostgres.integration.test.ts (11080.572875ms)

All 471 real tests ran in BOTH runs; the file-level entry is ADDITIONAL. So the watchdog's
denominator is `real tests + file-level failure entries`, and it moves by one for each file
that dies at file level. **That is a concrete, reproduced mechanism for a denominator that
differs at a fixed SHA**, and the watchdog's discovery guard cannot see it: that guard
binds the FILE SET to the commit (I verified it: `files: 84`, `boundToCommit: true`,
`ignored/untracked/missing: []`), not the TEST COUNT.

**The caveat, stated so nobody over-reads this.** In my reproduction the +1 entry is a
FAILURE entry, so it can only appear in a run that also FAILS. If the historical 1087 run
was reported as a PASS, this mechanism does not explain it and something else does. **I did
not reproduce a PASSING run with an inflated denominator**, and I am not claiming the
1086/1087 finding is closed. What I am claiming, with evidence, is that the denominator is
not a stable function of the commit, and that the watchdog asserts nothing about it.
Blocking: NO.

### FINDING I-12 · Info · one test consumes 29% of the full suite's deadline

    ✔ Contracts provenance rejects stale artifacts and redirected package exports (260575.120167ms)

260.6 seconds against a `deadlineMs` default of 900 000. That test shells out to repeated
isolated `pnpm build`s of the contracts repo (the mechanism I verified in section 1 and
which I am glad exists). With six reviewer environments dispatched against one host, a
single test holding 29% of the budget is a plausible contributor to the incomplete runs
this round keeps recording. Recorded as a measurement, not a defect.

---

## Subject re-verified AFTER the work

| item | value | status |
|---|---|---|
| core HEAD | `e71b51e9ed333d1feab1cd6819496269d201a6e2` | unchanged |
| core tree OID | `5af8080da732f8b4c4afd6b81337ab4a88b06950` | unchanged |
| core `git status --porcelain` | (empty) | CLEAN |
| contracts HEAD | `7d576681d1001eb4c4a7f044f7793cdb3f80af76` | unchanged |
| contracts tree OID | `a34af636b5ce62dbb2830a8a7b716816f42ea041` | unchanged, and MATCHES the register's claim |
| contracts `git status --porcelain` | (empty) | CLEAN |
| `dist/src/persistence/postgres/migrations.js` | `984643ebf2dbd8c577d21442ffd225dd4c10c1debdbfd95a08c0264c265dd423` | restored byte-for-byte after 3 mutations |
| `node_modules/@aaliyah/contracts/dist/src/index.js` | `4919c29d4db11dcf2ba0179978cea80f34ac6ed7372a70b725138e5366a1d9d3` | restored byte-for-byte after 1 mutation |
| `bash scripts/ci-guards.sh` (final) | 8 PASS, `RELEASE GUARDS: PASS`, exit 0 | re-verified |
| cluster databases (final) | `aaliyah_test, postgres, template0, template1` | all 11 probe databases dropped |
| server processes | 0 | all 4 boots terminated |

**Database disclosure, per the protocol.** I dropped and recreated `aaliyah_test` once,
mid-review, after my own backgrounded full-suite attempt was SIGTERMed and left it dirty.
Everything after that point ran against a database rebuilt from this commit's migrations.
Everything before it is section 1–4 work, which used its own per-probe databases and never
wrote to `aaliyah_test`. I am saying so rather than hiding it, and I turned it into
FINDINGS I-9 and I-10.

---

## Findings summary

| ID | Severity | Finding | Blocking |
|---|---|---|---|
| **I-5** | **Important** | G-08's digest fix LAUNDERS an edited migration on the pre-057 upgrade path: the run writes a digest attesting content that was never applied, the register's G-08 says "CLOSED" without the population limit, and `migrations.ts:6390` claims a register disclosure that does not exist | **YES** |
| I-9 | Medium | a run's verdict depends on residual database state from a previous run; the watchdog probes reachability, not cleanliness; 118 false failures vs 0 at the same SHA with `dirty:false` | no |
| I-10 | Medium | the test DENOMINATOR moves at a fixed SHA (472 vs 471) via synthetic file-level failure entries; discovery binds the FILE SET, not the test count | no |
| I-1 | Low | HANDOFF's "the contracts pin is verifiable WITHOUT access to the contracts repo" is false — the script fails closed when the repo is absent | no |
| I-3 | Low | the frozen manifest pins 17 `src/` files and structurally CANNOT cover `scripts/`; none of this round's subjects are in it | no |
| I-4 | Low | `ci-guards.sh` writes fixed-name files into `/tmp` while six environments run concurrently | no |
| I-6 | Low | `migrations.ts:6357-6359` claims W1BR-014 covers "after a partial restore"; with an emptied ledger it provides no refusal at all. A newer build's ledger row is ignored in silence | no |
| I-7 | Low | `wave1MigrationReplayPostgres...:121-123` says the advisory lock "is gone"; it was restored in `c2e5747` and is taken at `migrations.ts:6278` | no |
| I-8 | Low | K-01's row still says the obligation ledger is "listable" twice, un-annotated, 295 lines from its correction | no |
| I-11 | Low | the G-11 suite precondition is disclosed in prose and asserted nowhere, though the watchdog already fails closed on harness-integrity questions of the same shape | no |
| I-13 | Low | G-04's "all 35 SECURITY DEFINER functions pinned" is stale (37 now); the property is re-bound and, to the builder's credit, strengthened | no |
| I-2 | Info | the "isolated" contracts build compiles with the contracts repo's own unverified `node_modules` | no |
| I-12 | Info | one test consumes 260.6s of the 900s suite deadline | no |

### What I could NOT break, and will say so plainly

- The contracts pin guard. Three independent falsifications (SHA drift, dirty worktree,
  tampered installed artefact) all produced FAIL, and the failure propagated to
  `RELEASE GUARDS: FAIL`. This is the one control this round that survived
  deletion-style attack cleanly.
- INT-DIGEST's three claimed properties, on the fresh-apply population: 60/60 digested in
  ONE run, re-run byte-identical, changed digest refused with the ledger untouched.
  No whitespace, comment or normalisation bypass exists.
- W1BR-014 on every case it claims: refused with the ledger unchanged, pre-emptively
  (the array is strictly ascending, so the first unapplied entry is the lowest), and
  fail-closed on a malformed id. The top-edge exemption is deliberate, tested and
  correctly reasoned.
- The digest control on the REAL boot path: `dist/src/server.js` refuses to boot, exits 1,
  and opens no socket when a recorded digest disagrees.
- The privilege map. It is a genuine live-vs-declared diff with four positive controls,
  not a file asserting things about itself.
- 471/471 across ten memory/migration/alias/pool integration files on a clean database.

---

## What I did NOT cover

Named, so the next reviewer does not inherit a false all-clear.

1. **I did not complete a full-suite run.** My one attempt was killed by my own background
   harness. The claimed 1088/1088 is therefore UNVERIFIED BY ME. I verified 471 + 38 + 30
   in focused runs, and the discovery guard's file denominator (84, bound to commit).
   Gates 1–3 own the suite count; do not read my verdict as confirming it.
2. **The 1086/1087 discrepancy is NOT closed.** I produced a reproduced mechanism for a
   moving denominator (I-10) but explicitly could not produce a PASSING run with an
   inflated count, which is what the original observation may have been.
3. **G-10** — the evidence directory's `SHA256SUMS` and whether any stray freeze file sits
   in this candidate's evidence folder. I did not audit `/Users/andrelove/aaliyah-w13-evidence/e71b51e/`
   for strays; that is a provenance-examiner job and I left it there deliberately.
4. **Migration 047's unsafety** — not re-proven (out of scope per the protocol). I checked
   only that nothing depends on it being safe, and that 057–060 introduce no new
   column-dropping or old-build-breaking privilege hazard. I did NOT execute the nine-step
   full-stop procedure.
5. **Mutation/discrimination.** I re-executed tests and confirmed they pass; I did not
   confirm they would FAIL against a mutated build, except where my own dist mutations
   did so incidentally (055 edits, digest poisoning). Gate 6 owns discrimination.
6. **The contracts repo's own test suite** — I verified the pin and the artefacts, not the
   contracts' behaviour.
7. **Concurrency at scale.** I ran the committed 2/3/5-way concurrent migrator tests; I did
   not stage my own high-load race, and the 42710 window is by the builder's own account
   too narrow to stage deliberately.
8. **Rolling-deploy execution.** I reasoned about, and grep-checked, the 057–060 privilege
   narrowing against the predecessor's code. I did NOT actually run an `86d33c9` build
   against a `e71b51e` schema. That experiment is worth someone's budget.
9. **The executive route** was unmounted in every boot (no `AALIYAH_CEO_PROFILE`), so its
   routes are absent from my 10-route denominator. I confirmed no executive route calls
   the obligation methods by grep, not by mounting it.

---

## VERDICT

**BLOCK · blocking: true**

One substantiated **Important** finding: **I-5**. G-08 is published `CLOSED` in the
register, and on the fresh-apply population it genuinely is — I proved that by execution
and I want that credited. But on the pre-057 upgrade path, which is the path every
already-deployed database takes and the exact population the G-08 incident was about, the
remediation does not merely fail to detect an edited migration: **it writes a digest
attesting to content that was never applied**, and the attestation is not recoverable —
restoring the correct source afterwards makes the correct source the thing that is refused.
The source comment at `migrations.ts:6390` closes with "and the register says so." The
register does not say so; I grepped for it.

That is this round's standing shape exactly: a control whose gap is asserted to be
disclosed, where the disclosure does not exist, and where no assertion would notice.
The remedy is small — a non-laundering backfill (leave NULL, or record `unverified:`) and
a corrected G-08 row naming the population — and it is a remedy, not a rewrite.

Everything else I found is Medium or below and does not block. I am not certifying
anything: AEGIS Ω-MAX adjudicates.

    subject:  e71b51e9ed333d1feab1cd6819496269d201a6e2
    tree:     5af8080da732f8b4c4afd6b81337ab4a88b06950
    contracts 7d576681d1001eb4c4a7f044f7793cdb3f80af76 / tree a34af636b5ce62dbb2830a8a7b716816f42ea041
    scope:    cross-package integration, regression, hidden coupling, stale proof
    verdict:  BLOCK
    blocking: true
