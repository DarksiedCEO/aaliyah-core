# GATE 7 — DATA & PERSISTENCE INTEGRITY — W1.3 candidate-4
subject: e71b51e9ed333d1feab1cd6819496269d201a6e2 · contracts 7d576681 · blocking: true

## Subject verified (not trusted)

| item | claimed | verified | how |
|---|---|---|---|
| worktree HEAD | e71b51e | e71b51e9ed333d1feab1cd6819496269d201a6e2 | `git -C /Users/andrelove/aaliyah-w13-rv5-data/aaliyah-wave1-core rev-parse HEAD` |
| worktree clean BEFORE | clean | clean (empty porcelain) | `git status --porcelain` -> `` |
| contracts | 7d576681 | 7d576681d1001eb4c4a7f044f7793cdb3f80af76 | `git -C .../aaliyah-wave1-contracts rev-parse HEAD` |
| database identity | mine alone | `aaliyah_test` @ 127.0.0.1:54606, container `aaliyah-w13-rv5-data` | `docker ps`: 54606 maps to `aaliyah-w13-rv5-data` only; peers on 54601-54605 untouched |
| migrations apply on empty DB | 001..060 | MIGRATIONS OK, 60 entries in ledger | `runMailMigrations` on fresh DB |
| baseline focused subset | n/a | 542 tests, pass 542, fail 0, 129s, WATCHDOG VERDICT: PASS | 9 memory/alias postgres integration files |

## Census — the real numbers, from the live schema (not the register)

Freshly migrated database, no test had run against it at census time.

| population | register says | LIVE schema |
|---|---|---|
| CHECK constraints, `public` schema, all tables | — | **169** |
| CHECK constraints on `memory_%` tables | 131 | **162** |
| non-internal triggers on `memory_%` tables | (cites 1 by name) | **56** |
| total drop-testable objects on `memory_%` | — | **218** |

Collection method:
```sql
SELECT count(*) FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid
  JOIN pg_namespace n ON n.oid=t.relnamespace
 WHERE n.nspname='public' AND t.relname LIKE 'memory_%' AND c.contype='c';
```

Baseline schema fingerprint (checks + triggers, whole `public` schema):
`3a2a09b93e9d69833733bb9429afea59`

(in progress — findings appended as executed)

---

## D-01 · Important · A test FILE that fails when run alone and passes when run with any other file

`tests/wave1MemoryIdentityPostgres.integration.test.ts` cannot be run on its own.
36 of its 37 tests fail. Add ANY second file to the same `node --test` invocation
and all 37 pass. Reproduced on a **freshly created, freshly migrated** database
(so this is not fixture contamination from an earlier run).

EXECUTED:

```
$ psql .../postgres -c "DROP DATABASE aaliyah_test WITH (FORCE)" -c "CREATE DATABASE aaliyah_test"
$ node -r ts-node/register <runMailMigrations>   ->  MIGRATIONS OK
$ export AALIYAH_TEST_DATABASE_URL=postgres://postgres:test@127.0.0.1:54606/aaliyah_test

$ node scripts/test-watchdog.mjs ... tests/wave1MemoryIdentityPostgres.integration.test.ts
WATCHDOG VERDICT: FAIL scope=FOCUSED tests=37 pass=1 fail=36 cancelled=0 skipped=0 todo=0
   AssertionError at createRecord (tests/wave1MemoryIdentityPostgres.integration.test.ts:246:10)
   + actual: 'storage_rejected'   - expected: null

  (repeated 3x, identical: FAIL / FAIL 36 / FAIL 36)

$ node scripts/test-watchdog.mjs ... wave1MemoryIdentityPostgres + wave1MemoryDigestOraclePostgres
WATCHDOG VERDICT: PASS scope=FOCUSED tests=44 pass=44 fail=0

$ node scripts/test-watchdog.mjs ... wave1MemoryIdentityPostgres + wave1TrustedMemoryPostgres
WATCHDOG VERDICT: PASS scope=FOCUSED tests=160 pass=160 fail=0
```

The discriminator is the FILE COUNT, not which other file: `node --test` runs a
single file in-process and >=1 files in isolated child processes. The file only
passes in the child-process mode.

**Why this is a gate finding, not a curiosity.** Any per-file mutation or
drop-test sweep that judges a mutant by running ONE file reports a **false KILL**
for all 36 of these tests against an UNMUTATED tree — the baseline is already red.
This is the register's own standing weakness in its other direction: an oracle
that reports a kill it did not earn. It also means these 36 tests have never been
shown to hold anything on their own.

What should have caught it and did not: nothing asserts that each test file is
independently runnable. `scripts/assertion-reachability.mjs` answers a different
question (does the line execute), and the full-suite run always supplies >1 file
so the mode is never exercised.

Blocking: NO on its own (the committed suite runs multi-file), but it
INVALIDATES any single-file mutant oracle, and I report it so the next reviewer
does not build one.

---

## D-02 · Info · My own database was contaminated mid-review, and I rebuilt it

`tests/wave1MemoryPrivilegesPostgres.integration.test.ts` positive control
"W2/W3 — an object HIDDEN IN ANOTHER SCHEMA is reported, then removed" TIMED OUT
(262s, watchdog `TIMED_OUT` + `ORPHANED_PROCESSES`) and left the schema
`memory_tombstone_shadow` behind in my database:

```
$ psql -At -c "select nspname from pg_namespace where nspname not like 'pg_%' and nspname<>'information_schema'"
public
memory_tombstone_shadow
```

That is the test's own "then removed" step never running. I DROPped and
re-CREATEd the database and re-ran the migrations before any measurement below;
the constraint/trigger fingerprint was identical before and after
(`3a2a09b93e9d69833733bb9429afea59`), so no constraint was affected. Recorded
because a reviewer who runs that file and then sweeps is sweeping a contaminated
subject (protocol trap 6), and because a positive control that does not clean up
after a timeout is a control that poisons the next run.

---

## D-03 · Important · The migration ledger can be made to certify a schema that was never applied — and the migrator reports success

Attacked the ledger AS DATA, against the real `runMailMigrations`, each case on a
freshly created database in my own container (`aaliyah_ledger`).

### Results table — what fails CLOSED and what fails OPEN

| # | ledger state | migrator | direction |
|---|---|---|---|
| L2 | MID-ordinal row deleted (`030_memory_alias_tenant_policy`) | **REFUSED** | fail CLOSED (correct, W1BR-014) |
| L2b | junk id `not-a-migration` inserted | **REFUSED** | fail CLOSED (correct) |
| L2c | invented future id `099_invented` inserted | accepted | fail closed *later* (poisons the ordinal floor; see D-06) |
| L3 | HIGHEST-ordinal row (`060`) deleted | accepted, silently **REPLAYED** 060 | see D-06 |
| L5-control | an applied row's `sql_digest` set to a WRONG value | **REFUSED** | fail CLOSED (correct) |
| **L4** | **rows inserted for 057..060, never applied (no digest)** | **`{"ok":true}`** | **fail OPEN** |
| **L4b** | **rows inserted for 058..060 with their TRUE digests, never applied** | **`{"ok":true}`** | **fail OPEN** |
| **L5** | **an applied row's `sql_digest` set to NULL** | **`{"ok":true}`, then re-blessed** | **fail OPEN** |

### L4 — EXECUTED

```
through 056: {"ok":true}
ledger rows after 056: 56
sql_digest column present: false
phantom rows inserted for 057..060
migrator re-run: {"ok":true}
sql_digest column present AFTER: false
060's constraint memory_key_destruction_obligations_settled_by_real present: false
058's trigger memory_key_destruction_obligations_settled_frozen present: false
final ledger rows: 60
```

### L4b — EXECUTED (the mandate's exact phrasing: a digest present for SQL never applied)

True digests were read out of a separately-migrated reference database, so these
are the digests this build itself computes — not forgeries.

```
migrate through 057: {"ok":true}
  inserted TRUE digests for 058,059,060 without applying them
  re-run -> {"ok":true}
  058's trigger present: false
  060's constraint present: false
  ledger says applied: 60
```

The ledger reports 60/60 applied with correct digests. The schema is at 057. The
digest check passes *because the digests are right* — it compares the ledger
against the SOURCE, never against the SCHEMA.

### L5 — EXECUTED (tamper detection defeated by a single NULL)

```
  CONTROL wrong digest  -> {"ok":false,"msg":"migration 055_memory_key_destruction_settlement was applied
        with different content (sha256:000...000) than this build carries
        (sha256:5f39d2affcb1cb02cb42f9ac9c7633b4a506717e274c3da5b8b793b25556766c).
        The database does not hold what this source says it holds. Refusing."}
  ATTACK digest NULLed  -> {"ok":true}
  digest AFTER the run: sha256:5f39d2affcb1cb02cb42f9ac9c7633b4a506717e274c3da5b8b793b25556766c
  nulls remaining: 0
```

`UPDATE aaliyah_mail_migrations SET sql_digest = NULL` turns the content check
off. `migrations.ts` skips NULL (`if (recorded === undefined || recorded === null)
continue;`) and the backfill at the end of the same run then **writes the current
source digest into that row**. One run later the ledger is fully digested,
internally consistent, and attests to content it never verified. The mechanism
cannot distinguish "pre-057 row, legitimately undigested" from "digest removed".

### Root cause, one sentence

The ledger is a record of INTENT, and every check the migrator performs compares
the ledger to the SOURCE. Nothing anywhere compares the ledger to the SCHEMA.
I grepped the whole of `src/` for any schema-existence verification outside
`migrations.ts` — `to_regclass`, `information_schema`, `pg_constraint`,
`pg_trigger` — and there is none, so there is no second line of defence at boot.

### Why this is reachable without an attacker

`src/persistence/postgres/migrations.ts:6350` (the W1BR-014 comment) already names
the population: *"It happens when a row is deleted and the runner is re-run, when
tooling replays by id, or after a partial restore — and in every one of those cases
the operator believes they are repairing something."* The code implements the
**deleted-row** half of that sentence and not the **inserted-row** half. A ledger
restored from a newer backup than its schema, a `pg_dump --data-only` of the ledger
alone, or the standard operational move of marking a failed migration as applied to
get past it, all produce L4 exactly. The table is owner-only
(`table_privileges` for `aaliyah_mail_migrations`: `postgres` only), so this is an
operator/restore integrity defect, not an unprivileged attack.

### What assertion should have caught it and did not

`tests/wave1MigrationReplayPostgres.integration.test.ts` covers the REFUSAL cases
(L2). There is no test that inserts a ledger row for an unapplied migration and
asserts the migrator refuses, and no test that NULLs a digest and asserts the
run is refused. The builder's standing weakness, exactly: the control (the 057
digest chain) has a removal — `SET sql_digest = NULL` — that nothing detects.

Reproducer: `/private/tmp/.../scratchpad/L4.cjs`, `L5.cjs`, `L2.cjs` (transcripts above).
Falsifier: show a `runMailMigrations` run that REFUSES a ledger containing an id
whose objects are absent from the schema, or that refuses a NULL `sql_digest` on a
database where the `sql_digest` column already exists.

Blocking: YES.

---

## D-04 · Medium (disclosed, and the disclosure is ACCURATE) · Erasure leaves the plaintext readable in the heap until VACUUM, and nothing ever vacuums

The mandate asks whether an erased record is gone at the STORAGE layer or only
unreachable through the application. Measured, not argued.

Method: inserted one `memory_record_versions` row carrying the distinctive string
`CANARY-PLAINTEXT-ZZTOPSECRET-9271` inside `payload->'content'`, then performed the
erasure exactly as the `memory_record_versions_append_only` guard permits
(`jsonb_set(payload,'{content}','null')` + `content_erased_at` + `erasure_tombstone_id`),
then examined the raw heap with `pageinspect`.

### (a) The logical erasure is COMPLETE — no surviving copy in ANY table

Every column of every table in `public` scanned:

```
NOTICE:  LIVE ROWS CONTAINING CANARY: (none)
```

So: no prior row version, no audit table, no `memory_mutation_attempts`, no
tombstone, and nothing the obligations ledger retains holds the plaintext. The
digest is retained by design and is disclosed as an offline oracle (W1BR-008).
No index covers `payload` — all four indexes on `memory_record_versions` are
btrees over scalar scope/id columns — so there is no index leak.

### (b) The heap pre-image IS recoverable, and reads out as plaintext

```
$ SELECT lp, t_xmin, t_xmax,
         position('CANARY-PLAINTEXT-ZZTOPSECRET-9271' in encode(t_data,'escape')) AS canary_at
    FROM heap_page_items(get_raw_page('memory_record_versions',0)) WHERE t_data IS NOT NULL;

 lp | t_xmin | t_xmax | canary_at
----+--------+--------+-----------
  1 |  54385 |  54392 |       862     <-- the DEAD pre-image tuple
  2 |  54392 |  54392 |         0     <-- the live, erased tuple

$ SELECT substr(encode(t_data,'escape'), 840, 90) FROM heap_page_items(...) WHERE ... LIKE '%CANARY%';
0\200!\000\000\000noteCANARY-PLAINTEXT-ZZTOPSECRET-9271\000\000\000 \000\000\000\000\200\
```

### (c) VACUUM removes it — and nothing in the product ever runs one

```
$ VACUUM memory_record_versions;
$ SELECT lp, t_xmin, t_xmax, position('CANARY...' in encode(t_data,'escape')) FROM heap_page_items(...);
  2 |  54392 |  54392 |  0        <-- lp 1 is gone
```

```
$ grep -rn "VACUUM\|vacuum" src/ scripts/ --include='*.ts' --include='*.mjs'
src/persistence/postgres/migrations.ts:2123:  // tuple; the old one survives until VACUUM, and the pre-image is in the
src/persistence/postgres/wave1TrustedMemoryStore.ts:161: * new heap tuple; the pre-image survives in the old tuple until VACUUM, in the
```

Two hits, both COMMENTS. There is no `VACUUM`, no scheduled cleanup, and no
post-erasure storage step anywhere in the product.

### Why this is Medium and NOT the Critical the mandate defines

The mandate's Critical is "leaves recoverable bytes while reporting
`PROVEN_DESTROYED`". It does not report that:

* `PROVEN_DESTROYED` in this schema is a state of
  `memory_key_destruction_obligations` and concerns an EXTERNAL provider's KEY,
  not heap bytes;
* the tombstone carries `cache_index_propagation` whose domain explicitly admits
  `unknown` (`memory_tombstones_propagation_domain` CHECK over
  `{not_started,in_progress,complete,failed,unknown}`), which is the schema
  refusing to overclaim about downstream copies;
* `migrations.ts:2119-2128` states the limitation in the source, verbatim, before
  I found it.

So this is an accurately disclosed residual, and I verified the disclosure is TRUE
rather than inheriting it. It is reported at Medium because the gap between
"erasure returned success" and "the bytes are gone" is unbounded in time and has
no operational close-out step in the product — not because the claim is dishonest.

Blocking: NO.

---

## D-05 · Important · Tenant isolation is a QUERY CONTRACT, not a database boundary, and the key-destruction schema actively permits the G-02 crossover

### (a) There is no row-level security anywhere

```
$ select count(*) from pg_class c join pg_namespace n on n.oid=c.relnamespace
   where n.nspname='public' and c.relkind='r' and c.relrowsecurity;   ->  0
$ select count(*) from pg_policies where schemaname='public';          ->  0
```

Denominator/population: all 21 `memory_%` tables plus every other table in
`public`; 0 have RLS enabled and 0 policies exist.

What IS enforced by the database: every `memory_%` table carries `tenant_id`
(0 exceptions), and the `..._zz_authorization_scope` triggers bind a written
row's four scope columns to the scope of the authorization that witnesses it —
a genuine schema-level control on the WRITE path. What is NOT enforced: nothing
on the READ path. There are only **4 foreign keys** across all 21 `memory_%`
tables, and while all 4 are correctly tenant-prefixed, they leave every other
relationship unconstrained.

This matches the source's own header (`migrations.ts:25-27`): *"every read is
expected to filter on them — scoping is a query contract, not an option."* It is
accurate. It also means a single forgotten `WHERE tenant_id = $1` is a
cross-tenant read with no database backstop.

**Isolation mode used, and what it does NOT prove:** I verified column presence,
FK scoping, RLS absence and write-path scope triggers by direct catalogue query
on a freshly migrated database. This is *schema-level* evidence only. It does NOT
prove application-layer authorization (AEGIS-SECURITY / gate 2 owns that), and it
does NOT prove any live cross-tenant read is or is not reachable.

### (b) The schema permits one key reference to exist in two tenants — EXECUTED

```
$ INSERT INTO memory_key_destruction_obligations (...) VALUES
    ('tenant-A','ws-A',...,'SHARED-KEY-REF-0001',...),
    ('tenant-B','ws-B',...,'SHARED-KEY-REF-0001',...);
INSERT 0 2
  tenant-A|SHARED-KEY-REF-0001
  tenant-B|SHARED-KEY-REF-0001

$ INSERT INTO memory_pii_key_erasures (...) VALUES
    ('tenant-A',...,'SHARED-KEY-REF-0001','provider-local','key_destroyed'),
    ('tenant-B',...,'SHARED-KEY-REF-0001','provider-local','key_destroyed');
INSERT 0 2
  tenant-A|SHARED-KEY-REF-0001|key_destroyed
  tenant-B|SHARED-KEY-REF-0001|key_destroyed
```

Every uniqueness object on the three key-destruction tables is scope-prefixed and
none is global:

```
memory_pii_key_erasures_once                        UNIQUE (tenant_id, workspace_id, key_ref, event)
memory_key_destruction_obligations_key_unique       UNIQUE (tenant_id, workspace_id, key_ref)
memory_key_destruction_settlements_scope_unique     UNIQUE (tenant_id, workspace_id, key_ref, erasure_authorization_id)
```

So **nothing in the database prevents two tenants naming the same key**, and
nothing in the database prevents a lookup that matches on fewer than three
columns from crossing between them. The G-02 HIGH crossover is held off entirely
by application code.

### (c) The application code IS currently correct — which is the finding

I read every live consumer. All of them match three columns wide:

* `wave1TrustedMemoryStore.ts:2660` — `scopedKey(tenantId, workspaceId, keyRef)`
  as the map key, with a comment stating precisely why `key_ref` alone is a
  cross-tenant lookup;
* `settlementProven` joins `unnest($1,$2,$3) AS want(tenant_id, workspace_id, key_ref)`
  on all three;
* the `key_destroyed` EXISTS/NOT EXISTS subqueries at lines ~2558, ~3023 and ~3066
  all carry `d.tenant_id = c.tenant_id AND d.workspace_id = c.workspace_id`.

**A schema that permits the defect and an application that avoids it is a
finding.** The invariant "a key reference is meaningful only within a scope" is
stated in prose in three comments and enforced in the database nowhere. The
control is three SQL predicates; deleting any one of them re-creates G-02.

### What holds it instead, and the limit of my evidence

`tests/wave1MemoryHoldErasurePostgres.integration.test.ts` DOES build a
two-tenant, same-`key_ref` fixture (`OTHER_TENANT`, lines ~6907-7075) and asserts
on it, so there is test coverage of the application control — this is not an
uncovered control. I did **NOT** execute a mutant that removes one of the three
scope predicates to confirm those tests actually kill it, because that requires
editing the candidate and my gate is read-only. That specific claim is
**NOT_VERIFIED**, and I state it rather than implying it passed. The mutation
gate (06) is the right owner of that experiment.

Blocking: YES, on (b) — the schema-level gap, which is mine to own and which no
gate has reported at any SHA on this branch.

---

## D-06 · VERIFIED (no defect) · Double-spend of an authorization is refused by the DATABASE, not by the application

This system has no money ledger; its double-spend surface is the authorization
nonce ("one authorization, one mutation", migration 038). My contract defaults
money paths to BLOCK until double-spend is MEASURED, so I measured it — as a raw
writer with no application in front of me.

```
$ INSERT INTO memory_authorization_nonces (tenant_id, workspace_id, binding_digest,
    authorization_id, action, target_record_id, issued_at, expires_at)
  VALUES ('t-ds','w-ds','sha256:ccc...','ds-auth-000000000001','correct','rec-ds', now()-'1 min', now()+'1 hour');
INSERT 0 1

-- SPEND #1
$ UPDATE ... SET consumed_at=now(), consumed_by_mutation_receipt_id='mut-ds-1'
   WHERE authorization_id='ds-auth-000000000001' AND consumed_at IS NULL;
UPDATE 1

-- SPEND #2, a second receipt against the same authorization
$ UPDATE ... SET consumed_at=now(), consumed_by_mutation_receipt_id='mut-ds-2' WHERE ...;
ERROR:  aaliyah memory: consumption is irreversible on memory_authorization_nonces

-- SPEND #2b, re-point the witness only
$ UPDATE ... SET consumed_by_mutation_receipt_id='mut-ds-2' WHERE ...;
ERROR:  aaliyah memory: a consumption witness is irreversible on memory_authorization_nonces

-- SPEND #2c, un-consume then re-spend
$ UPDATE ... SET consumed_at=NULL, consumed_by_mutation_receipt_id=NULL WHERE ...;
ERROR:  aaliyah memory: consumption is irreversible on memory_authorization_nonces

-- final
ds-auth-000000000001|t|mut-ds-1
```

3 replays, 0 duplicate effects. Backed by real schema objects, not by a query
convention:

```
memory_authorization_nonces_unique                UNIQUE (tenant_id, binding_digest)
memory_authorization_nonces_authorization_unique  UNIQUE (authorization_id)      <-- GLOBAL
memory_record_versions_receipt_unique             UNIQUE (tenant_id, workspace_id, mutation_receipt_id)
```

Note the contrast with D-05(b): `authorization_id` IS globally unique here, while
`key_ref` is unique only per scope. The design knows how to make an identifier
globally unique when it matters; the key-destruction tables simply do not.

Caveat stated: `aaliyah_memory_consumption_monotonic` is a TRIGGER, so a superuser
with `session_replication_role = replica` bypasses it. That is inherent and the
source says so. Whether the trigger's REMOVAL is detected by any test is answered
by the sweep in D-07.

Blocking: NO — this is a pass.

---

## D-07 · VERIFIED (no defect) · Greenfield and brownfield converge exactly

My contract requires both hashes and the comparison output, so here they are.
Three independent paths to migration 060 on three freshly created databases:

* **greenfield** — empty -> `runMailMigrations()` once;
* **brownfield** — empty -> `through:023` -> `through:040` -> `through:056` -> full, four runs;
* **stepwise** — empty -> 60 separate runs, `through:` each migration id in turn.

Fingerprint covers, for schema `public`: every column of every table (name, type,
NOT NULL, default), every constraint definition, every index definition, every
non-internal trigger definition, every function body (md5), and every table ACL.

```
greenfieldHash  : ca535c58fbc0e4a2832962f68eb7e48adf03d7c4d26817082a6d2bfb95a30571
brownfieldHash  : ca535c58fbc0e4a2832962f68eb7e48adf03d7c4d26817082a6d2bfb95a30571
stepwiseHash    : ca535c58fbc0e4a2832962f68eb7e48adf03d7c4d26817082a6d2bfb95a30571
identical(green,brown): true
identical(green,step) : true

cv_green ledger rows 60 digested 60 ledgerHash d440e90c00eb6f4a04cc43c482ccf2f9
cv_brown ledger rows 60 digested 60 ledgerHash d440e90c00eb6f4a04cc43c482ccf2f9
cv_step  ledger rows 60 digested 60 ledgerHash d440e90c00eb6f4a04cc43c482ccf2f9
```

`convergence: { greenfieldHash: ca535c58…, brownfieldHash: ca535c58…, identical: true }`.

This also independently confirms the digest BACKFILL works on all three paths:
60/60 rows digested with an identical ledger hash, including the stepwise path
where 001..056 are each applied in their own transaction before 057 creates the
`sql_digest` column.

Blocking: NO — this is a pass.

---

## D-08 · Low · There is no rollback path for ANY migration, and the append-only chain is not append-only against TRUNCATE

Two smaller storage-layer facts, both measured.

**(a) No down-migrations exist at all.** `migrations.ts:29` —
`const MIGRATIONS: ReadonlyArray<{ id: string; sql: string }>`. There is no
`down`, no `revert`, no `rollbackSql` field, for any of the 60. The register
discloses "Migration 047: NOT rollback safe"; the accurate general statement is
that **none of the 60 has a rollback path**, and the only recovery from a bad
migration is a restore from backup, for which the repo ships no tooling. Failure
class `NO_RESTORE_PATH`, at Low because nothing claims otherwise and no
deployment is authorised.

Interruption safety, on the other hand, is sound and I checked it:
`grep -c CONCURRENTLY src/persistence/postgres/migrations.ts` -> **0**, and every
migration is applied inside the single `BEGIN`/`COMMIT` the runner opens, so an
interrupted run rolls back whole. There is no partial-application window.

**(b) TRUNCATE defeats the append-only triggers — for the owner only.**

```
$ select count(*) from memory_record_versions;      -> 1
$ TRUNCATE memory_record_versions;                  -> TRUNCATE TABLE
$ select count(*) from memory_record_versions;      -> 0
```

The `..._append_only` triggers are `BEFORE UPDATE OR DELETE` and TRUNCATE fires
neither. `migrations.ts:738-739` says this is deliberate. The mitigation is real
and I verified it: **no `aaliyah%` role holds TRUNCATE, DELETE or UPDATE on any
`memory_%` table** (`information_schema.table_privileges` filtered to
`grantee LIKE 'aaliyah%'` returned zero rows), and

```
$ SET ROLE aaliyah_memory_mutator; TRUNCATE memory_record_versions;
ERROR:  permission denied for table memory_record_versions
$ SET ROLE aaliyah_memory_mutator; DELETE FROM memory_record_versions;
ERROR:  permission denied for table memory_record_versions
```

So the append-only property holds against every application role and is owner-only
bypassable. Recorded so nobody reads "append-only trigger" as "append-only table".

**(c) Wrong-target destructive operations: no surface.** `grep -rn` for
`DROP DATABASE|DROP SCHEMA|DROP TABLE|TRUNCATE` across `src/` and `scripts/`
returns only comments — the product never issues a destructive whole-database
operation, so the `WRONG_TARGET_DESTRUCTIVE` failure class has nothing to target
here. (The test FIXTURES truncate, as owner; that is in the test tree, not the
product.)

Blocking: NO.

---

## D-09 · THE CHECK-CONSTRAINT AND TRIGGER DROP-TEST AUDIT (the headline)

The register carries this as a **PENDING FOUNDER DELIVERABLE** and says plainly
that the **"67 untested"** figure is an UNVERIFIED claim an independent reader
could not reproduce. I am that reader. This section reports EXECUTED results and
publishes no number I did not measure.

### Population, and how it was collected

Freshly created database, freshly migrated 001..060, **no test had ever run
against it** at census time (the register requires this, because fixtures disable
and re-enable triggers and a used database is not a clean subject).

| population | register | LIVE |
|---|---|---|
| CHECK constraints, `contype='c'`, schema `public`, ALL tables | — | **169** |
| CHECK constraints on `memory_%` tables | **131** | **162** |
| non-internal triggers on `memory_%` tables | — | **56** |
| **total drop-testable objects in scope** | — | **218** |

The register's 131 is **wrong by 31**. Its older "86 CHECK constraints on the five
memory tables" is a narrower population that no longer matches anything in the
live schema. Collection:

```sql
SELECT count(*) FROM pg_constraint c
  JOIN pg_class t ON t.oid=c.conrelid JOIN pg_namespace n ON n.oid=t.relnamespace
 WHERE n.nspname='public' AND t.relname LIKE 'memory_%' AND c.contype='c';   -- 162
SELECT count(*) FROM pg_trigger tg
  JOIN pg_class t ON t.oid=tg.tgrelid JOIN pg_namespace n ON n.oid=t.relnamespace
 WHERE n.nspname='public' AND t.relname LIKE 'memory_%' AND NOT tg.tgisinternal; -- 56
```

Triggers are IN scope deliberately: the mandate names
`memory_record_versions_deletion_erases`, and a trigger is exactly the kind of
control whose deletion the builder's standing weakness says nothing may notice.

### Method — EXECUTION, not sampling, and its exact cost

Every one of the 218 objects is individually **DROPPED**, the tests are **RUN**,
the object is **RESTORED** from `pg_get_constraintdef` / `pg_get_triggerdef`
captured before the sweep, and the restore is verified. This is **not a sample**:
the drop-test denominator is 218 of 218.

Because the whole suite per object is hours, the sweep is tiered, and each tier is
individually sound:

* **Tier 1** — drop, run `wave1MemoryConstraintDestroyersPostgres` +
  `wave1MemoryDigestOraclePostgres` (112 tests, 4s baseline), restore.
  A FAIL here is a definitive KILL.
* **Tier 2** — every tier-1 survivor is re-dropped and run against the full 9-file
  memory/alias integration bundle (542 tests, 50s baseline, a strict superset of
  tier 1), then restored.
* **Tier 3** — every tier-2 survivor is dropped **simultaneously** and the ENTIRE
  committed suite is run once. Group-dropping is sound in this direction: if the
  full suite PASSES with all of them absent, then **not one of them** is detected
  by any test in the commit. A single run establishes the whole untested set
  against the full-suite denominator.

Watchdog bounds: tier 1 `--deadline-ms 90000 --test-timeout-ms 25000
--exit-grace-ms 5000`; tier 2 `--deadline-ms 240000 --test-timeout-ms 60000
--exit-grace-ms 10000`. A HANG yields FAIL, which this sweep counts as KILLED —
correct, because a mutant that hangs the suite is a mutant the suite detected
(protocol: a timeout is never a PASS). Verdicts are read from
`WATCHDOG VERDICT`, never from the failure list.

**Baselines were taken with the watchdog's own defaults, not the mutant bound**
(protocol trap 4), and every run in the sweep names >=2 files, because a
single-file run is not a valid oracle on this tree (finding D-01).

### Tier 1 result — 218/218 executed

```
$ wc -l t1.tsv        -> 218
$ awk -F'\t' '{print $4}' t1.tsv | sort | uniq -c
  103 KILLED
  115 SURVIVED
$ awk -F'\t' '$5!="RESTORED"' t1.tsv | wc -l   -> 0     (zero restore failures)
```

Schema fingerprint immediately after tier 1, compared to the pre-sweep baseline:

```
before: 3a2a09b93e9d69833733bb9429afea59
after : 3a2a09b93e9d69833733bb9429afea59      IDENTICAL
```

Tier-2 population: **115** objects (66 CHECK constraints, 49 triggers).

*(tiers 2 and 3 appended below as they complete)*

### Tier 2 result — 115/115 executed

```
$ wc -l t2.tsv -> 115
  98 KILLED
  17 SURVIVED
$ awk -F'\t' '$5!="RESTORED"' t2.tsv | wc -l  -> 0
$ fingerprint after tier 2: 3a2a09b93e9d69833733bb9429afea59   (== baseline)
```

### Combined tiers 1+2 — all 218 objects individually drop-tested

```
TOTAL objects: 218
KILLED:   201   (checks 145 / triggers 56)
SURVIVED:  17   (checks  17 / triggers  0)
```

**Every one of the 56 triggers is drop-tested.** Including
`memory_record_versions_deletion_erases`, which the mandate singles out: dropping
it turns the suite red. Every survivor is a CHECK constraint.

### Tier 3 — the survivors against the ENTIRE committed suite

Full-suite BASELINE, watchdog defaults, everything restored:

```
$ node scripts/test-watchdog.mjs
WATCHDOG VERDICT: PASS scope=FULL_SUITE tests=1088 pass=1088 fail=0 cancelled=0 skipped=0 todo=0
  duration_ms 214878   (215s)
```

All 17 dropped simultaneously (`17` constraints missing, confirmed
`162 - count(*) = 17`), then the entire suite:

```
$ psql -f t3_drop.sql       (17 x ALTER TABLE ... DROP CONSTRAINT)
$ node scripts/test-watchdog.mjs
WATCHDOG VERDICT: PASS scope=FULL_SUITE tests=1088 pass=1088 fail=0 cancelled=0 skipped=0 todo=0
  duration_ms 213898
```

**1088 of 1088 still pass with all 17 constraints absent. Not one test in the
commit detects their removal.**

### POSITIVE CONTROL — the tier-3 oracle is live, not dead

This is the step whose absence would make the result above worthless.
One constraint the sweep KILLED was dropped alone and the full suite re-run:

```
$ ALTER TABLE memory_record_versions DROP CONSTRAINT memory_record_versions_content_digest_form;
$ node scripts/test-watchdog.mjs
WATCHDOG VERDICT: FAIL scope=FULL_SUITE tests=1088 pass=1087 fail=1
```

The oracle discriminates. So "1088/1088 with the 17 gone" is a real absence of
detection, not a suite that cannot fail.

### RESTORATION — verified, object by object

```
$ psql -f t3_add.sql   (17 x ALTER TABLE ... ADD CONSTRAINT)
CHECK constraints on memory_%  : 162     (== census)
triggers on memory_%           :  56     (== census)
full fingerprint               : 3a2a09b93e9d69833733bb9429afea59   (== baseline)
$ diff <pre-sweep census of all 218 names> <post-sweep census>
NO DIFFERENCE — all 218 objects present and identical
$ select nspname from pg_namespace ...  ->  public        (no leftover schema)
```

Restoration was verified three independent ways: the count per object class, the
md5 over every constraint AND trigger DEFINITION (not just names), and a
name-by-name diff against the census taken before the first drop. Per-object
restore was also verified inside each sweep iteration: **0 restore failures in
333 drop/restore cycles** (218 + 115).

### THE ANSWER TO THE FOUNDER'S QUESTION

> The handoff asserts **67 untested**.

**REFUTED, in both directions, by execution.**

| | register | measured |
|---|---|---|
| population (CHECK on `memory_%`) | 131 | **162** |
| untested CHECK constraints | **67** | **17** |
| untested triggers | not counted | **0 of 56** |
| method | not run | 218 individual drop/restore cycles + 1 group run vs the full suite |

The register **understated the population by 31** and **overstated the untested
count by 50**. The true figure is **17 of 162** CHECK constraints — 10.5% — with
every trigger covered.

### The 17, and why two families are not the same finding

**Family A — 9 type guards, MASKED (Low).**
`memory_{alias_bindings, authorization_receipts, identity_edges, legal_holds,
mutation_attempts, mutation_receipts, record_versions, tombstones}_payload_object`
and `memory_reconciliations_evidence_object`, each
`CHECK (jsonb_typeof(payload) = 'object')`.

Masked, and I have the execution to show it rather than the argument. The
destroyers suite feeds `["not","an","object"]` as a payload; the PostgreSQL log
from that run shows what actually refuses it:

```
ERROR:  new row for relation "memory_identity_edges" violates check constraint
        "memory_identity_edges_authorization_binding"
DETAIL:  Failing row contains (10, ..., ["not", "an", "object"], ...)
```

A non-object payload fails a payload-BINDING CHECK (`payload->>'x' = x` yields
NULL) before the type guard is reached. So the type guard cannot be the *first*
refusal for any row a test can write, and has no reachable killing input.

**Family B — 8 domain and shape constraints on the KEY-DESTRUCTION ledger,
NOT masked (Important).**

```
memory_key_destruction_obligations_state_domain      state IN (KEY_DESTRUCTION_NOT_PROVEN, PROVEN_DESTROYED, PROVEN_NOT_DESTROYED)
memory_key_destruction_obligations_reason_domain     not_proven_reason IN (7 values)
memory_key_destruction_obligations_resolution_named  resolved without naming HOW is unrepresentable
memory_key_destruction_settlements_decision_domain   decision IN (7 values)
memory_key_destruction_settlements_states_known      predecessor/successor_state IN (4 values)
memory_key_destruction_settlements_policy_known      policy_version = 'aaliyah.key-destruction-settlement/v1'
memory_key_destruction_settlements_digest_shape      evidence_digest ~ '^sha256:[0-9a-f]{64}$'
memory_pii_key_audits_state_domain                   last_state IN (active, destroyed, unknown, unreachable)
```

These are the SOLE enforcement of their invariants — there is no binding CHECK
behind them to mask them. With `..._state_domain` gone, an obligation row can
carry any string as its state, including one no reader has a branch for. With
`..._digest_shape` gone, a settlement's evidence digest need not be a digest.

And the sharpest one: **`memory_key_destruction_obligations_resolution_named`**.
This register credits the sibling `..._resolution_named` CHECK from migration 055
with **falsifying its own published proof about M-47/M-55**
(`WAVE1_BLOCKER_REGISTER.md:1872-1873`). A constraint the register names as the
thing that caught its own false proof has **no drop-test**: all 1088 tests pass
without it. That is the builder's standing weakness in its purest form and it sits
on the key-destruction settlement path — the one this system calls "proof of
destruction".

### Bonus: naming is NOT coverage, in both directions (measured)

I also partitioned the 218 objects by whether their name appears anywhere in
`tests/`, then compared that prediction to the executed result:

* `memory_alias_bindings_payload_object` IS named in
  `tests/wave1AliasRegistryPostgres.integration.test.ts:2893` — and **survives**
  the full suite. Named, discussed in a comment, not drop-tested.
* `memory_key_destruction_settlements_decided_not_future` is named **nowhere** in
  `tests/` — and is **killed**. Unnamed, but genuinely covered.

So a grep-based coverage claim is wrong in both directions, which is exactly why
this section reports execution and not static analysis. (This is also why the
"67" could not be reproduced from source by a reader: it is not reproducible from
source at all.)

### What assertion should have caught this and did not

Nothing in the tree asserts that each database constraint is load-bearing. The
constraint-destroyer suite
(`tests/wave1MemoryConstraintDestroyersPostgres.integration.test.ts`, 105 tests)
was built for exactly this and covers the five original memory tables well — it
was simply never extended to `memory_key_destruction_obligations`,
`memory_key_destruction_settlements` or `memory_pii_key_audits`, the tables added
by migrations 055-060, which are the newest and least-exercised money-adjacent
surface in the system.

Reproducer: `t3_drop.sql` (the 17 ALTER statements above) then
`node scripts/test-watchdog.mjs` -> PASS 1088/1088.
Falsifier: add one test that writes a
`memory_key_destruction_obligations` row with `state='NOPE'` (or a
`memory_key_destruction_settlements` row with `evidence_digest='x'`) as the table
owner and asserts the named CHECK refuses it; that test fails when the constraint
is dropped, and Family B stops being a finding.

Severity: **Important** for Family B (8 constraints), **Low** for Family A (9).
Blocking: YES.

---

## Subject re-verified AFTER the review

| item | before | after |
|---|---|---|
| worktree HEAD | e71b51e9ed333d1feab1cd6819496269d201a6e2 | **e71b51e9ed333d1feab1cd6819496269d201a6e2** |
| `git status --porcelain` | empty | **empty** |
| contracts HEAD | 7d576681d1001eb4c4a7f044f7793cdb3f80af76 | **7d576681d1001eb4c4a7f044f7793cdb3f80af76** |
| CHECK constraints on `memory_%` | 162 | **162** |
| triggers on `memory_%` | 56 | **56** |
| schema fingerprint | 3a2a09b93e9d69833733bb9429afea59 | **3a2a09b93e9d69833733bb9429afea59** |
| full suite | PASS 1088/1088 | **PASS 1088/1088** |
| release guards | 8/8 claimed | **RELEASE GUARDS: PASS** (verified, incl. contracts provenance 7d576681 / tree a34af636) |

Nothing in the candidate was edited, at any point. My review made zero writes to
the worktree.

### Database hygiene — stated explicitly

My database is **NOT contaminated**. Final state of
`postgres://…@127.0.0.1:54606/aaliyah_test`: 162 checks, 56 triggers, fingerprint
identical to the pre-sweep baseline, `public` the only non-system schema, and the
full suite green on it after every drop was restored.

Full disclosure of what happened in between:
* it WAS contaminated once, mid-review, by the candidate's own privileges test
  (see D-02); I dropped and recreated the database before any measurement;
* 333 drop/restore cycles were executed against it, with **0 restore failures**;
* I created and have since **dropped** six disposable scratch databases in my own
  container (`aaliyah_ledger`, `aaliyah_ledger_ref`, `cv_green`, `cv_brown`,
  `cv_step`, and one accidentally named `undefined`). `aaliyah_test` is the only
  database remaining.

I touched no other environment. Containers `aaliyah-w13-rv5-{test,sec,rel,red,int}`
on ports 54601-54605 and the implementation worktree were never connected to. I
attempted to start a SECOND disposable container for the schema probes and the
sandbox denied the port publish; I used a second database inside my own container
instead, after verifying that migrations create roles under
`IF NOT EXISTS (SELECT 1 FROM pg_roles ...)` and so could not disturb the
concurrent sweep.

---

## Summary of findings

| id | severity | one line | blocking |
|---|---|---|---|
| D-09 (B) | **Important** | 17 of 162 CHECK constraints have NO drop-test; 8 of them are the sole enforcement on the key-destruction ledger, including the `resolution_named` family the register credits with falsifying its own proof | **YES** |
| D-03 | **Important** | the migration ledger fails OPEN on phantom rows and on a NULLed digest: the migrator reports success against a schema that was never applied | **YES** |
| D-05 | **Important** | no RLS anywhere; key references are unique only per scope, so the G-02 crossover is prevented by application code alone | **YES** |
| D-01 | Important | `wave1MemoryIdentityPostgres` fails 36/37 when run as a single file; any single-file mutant oracle reports false kills | no |
| D-04 | Medium | erasure leaves the plaintext readable in the heap pre-image until VACUUM, and nothing ever vacuums (accurately disclosed) | no |
| D-09 (A) | Low | 9 `jsonb_typeof(payload)='object'` guards are masked by the payload-binding CHECKs and have no reachable killing input | no |
| D-08 | Low | no rollback path exists for ANY of the 60 migrations; TRUNCATE defeats the append-only triggers (owner-only) | no |
| D-02 | Info | the candidate's privileges test left schema `memory_tombstone_shadow` behind after a timeout | no |
| D-06 | pass | double-spend of an authorization nonce refused by the DATABASE, 3 replays / 0 duplicate effects | no |
| D-07 | pass | greenfield == brownfield == stepwise, identical schema and ledger hashes | no |

Corrections to the record, both measured:
* the register's **131** CHECK constraints on `memory_%` is really **162**;
* the handoff's **67 untested** is really **17** — and **0 of 56 triggers**.

---

## What I did NOT cover

Named, so the next reviewer inherits no false all-clear.

1. **I did not run a source mutant against the three-column scope predicates in
   `wave1TrustedMemoryStore.ts`.** D-05(c) is therefore `NOT_VERIFIED` on the
   question "do the existing two-tenant tests actually kill the removal of
   `d.tenant_id = c.tenant_id`?" That needs a source edit; my gate is read-only.
   Route to gate 06.
2. **Production cloud KMS/HSM: not touched**, per the dispatch. All key results
   are against the LOCAL test provider.
3. **Concurrent-migrator racing (K-06b/K-06c) was not re-run.** I audited the
   ledger as DATA, not the advisory-lock race. That is gate 3's (reliability).
   I confirmed only that the lock is present in the source at this SHA and that
   `LEDGER_RACE_LOST` now enumerates `42P07, 23505, 42710`.
4. **WAL, replicas and physical backups were not examined** for the erasure
   pre-image. I proved the local heap case (D-04b); the source claims the WAL and
   any replica also retain it and I did not verify that half.
5. **TOAST was not separately examined.** The canary payload was small enough to
   live inline, so D-04 proves the main-heap case only. A payload large enough to
   TOAST may behave differently and I did not test it.
6. **`memory_alias_blind_indexes` blinding strength** was not cryptanalysed; I
   only confirmed its constraints are drop-tested.
7. **The 1086/1087 suite-count discrepancy is not explained.** I observed **1088**
   on three independent full-suite runs in my environment (baseline, group-drop,
   final) plus 1088 on the positive control, all `scope=FULL_SUITE` with the
   commit-binding guard passing. I never saw 1086 or 1087, so I can neither
   reproduce nor close it.
8. **Tier-1 and tier-2 used bounded watchdog runs**; a constraint whose drop
   causes a >60s slowdown but no failure would be recorded KILLED by timeout
   rather than by assertion. This direction is conservative (it can only
   over-count kills), and tier 3 — which decided the 17 — ran with watchdog
   DEFAULTS, so the published untested set is not affected.
9. **Application-layer authorization** belongs to gate 2 and **concurrency
   mechanics** to gate 3; I did not duplicate either.

---

## VERDICT

**BLOCK · blocking: true**

Three Important findings, each EXECUTED, each independently sufficient:

* **D-09(B)** — 17 of 162 CHECK constraints are not drop-tested, proven by
  dropping all 17 and watching the full 1088-test suite pass unchanged, with a
  positive control proving the oracle was live. 8 of them are the only
  enforcement of their invariant and sit on the key-destruction settlement path.
  This substantiates the *class* the founder asked about while REFUTING the
  specific "67" figure and correcting the population from 131 to 162.
* **D-03** — the migration ledger can be made to certify a schema that was never
  applied, and the 057 digest chain is switched off by a single
  `SET sql_digest = NULL`, which the next run then re-blesses.
* **D-05** — tenant isolation has no database backstop (0 RLS policies, 0 of 21
  memory tables), and the key-destruction schema permits the exact G-02
  crossover that application code alone currently prevents.

Not a certification. Reported for AEGIS Omega to adjudicate.
