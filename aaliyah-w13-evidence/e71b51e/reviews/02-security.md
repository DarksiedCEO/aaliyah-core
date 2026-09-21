# GATE 2 — SECURITY — W1.3 candidate-4
subject: e71b51e9ed333d1feab1cd6819496269d201a6e2 · contracts 7d576681 · blocking: false

Independent offensive review. Read-only to candidate; PoC in disposable sandbox/DB only.
This file is written INCREMENTALLY as attacks are executed.

## Subject verified (not trusted)

| field | claimed | verified |
|---|---|---|
| candidate SHA | e71b51e9ed333d1feab1cd6819496269d201a6e2 | `git rev-parse HEAD` = e71b51e9ed333d1feab1cd6819496269d201a6e2 ✓ |
| contracts | 7d576681d1001eb4c4a7f044f7793cdb3f80af76 | worktree HEAD = 7d576681... ✓ |
| worktree clean (before) | — | `git status --porcelain` empty ✓ |
| worktree clean (after) | — | TBD at end |
| database | postgres://postgres:test@127.0.0.1:54602/aaliyah_test | reachable, PostgreSQL 16.14, db=aaliyah_test user=postgres ✓ |
| DB env | AALIYAH_TEST_DATABASE_URL only (trap 1) | enforced |

Prerequisite read: reviews/06-mutation-fuzz.md (SEC-01 provider-contradiction gate,
M-47/M-55 re-executed there = STRUCTURALLY_UNREACHABLE_WITH_PROOF). I extend, not duplicate.

## Findings
(appended as executed)

---
## Note on DB state
My `aaliyah_test` on port 54602 arrived EMPTY (0 tables, no migration ledger). I migrated
it to 060 via a scratch `runMailMigrations` script (built a `pg.Pool` directly on the
connection string to avoid the AALIYAH_DATABASE_URL singleton trap-1), then deleted the
script; `git status --porcelain` empty afterward. Post-migration: 60 rows in
`aaliyah_mail_migrations`, top=`060_obligation_settlement_pointer_real`, 37 SECURITY
DEFINER `aaliyah_*` functions present.

---
## MANDATE 1 — SEARCH_PATH / SCHEMA SHADOWING

### SEC-A (Info / negative): the constant pin defeats attacker-reachable shadowing — EXECUTED
`pool.ts:177` `PINNED_SEARCH_PATH_SQL = SELECT set_config('search_path','pg_catalog, public, pg_temp', true)`
is a CONSTANT; `enterMemoryRole` (pool.ts:179-186) runs it then `SET LOCAL ROLE`.
NOTE: the register's G-04 prose (docs/WAVE1_BLOCKER_REGISTER.md:1375, 1384-1409) still
DESCRIBES `enterMemoryRole` as "KEEPS every other schema the session was configured with"
— that describes the SUPERSEDED pin. The code at this SHA does NOT keep session schemas;
it is a constant. The register text is stale relative to the code (documentation drift,
not a vulnerability). The mandate's premise ("deliberately KEEPS operator-configured
session schemas") is FALSE at e71b51e.

I built my own attacker fixture (schema `sec_atk`, non-superuser login `sec_atk_login`
granted the memory roles, `GRANT USAGE ON SCHEMA sec_atk TO aaliyah_memory_mutator`, and
`ALTER ROLE sec_atk_login SET search_path = sec_atk, public` — a USERSET poison needing NO
privilege), planted a shadow `sec_atk.memory_pii_key_erasures` with a fabricated
`key_destroyed` row and a shadow `sec_atk.aaliyah_memory_unerased_merged_records(text,text,text)`
(PUBLIC gets EXECUTE by default). Connected AS the poisoned login and ran the EXACT store
sequence (`BEGIN; set_config(..pinned..,true); SET LOCAL ROLE aaliyah_memory_mutator`):

    login session default path  = sec_atk, public
    STORE-PIN effective path     = pg_catalog, public, pg_temp
    STORE-PIN table resolves to  = public       (NOT sec_atk)
    STORE-PIN helper resolves to = public       (NOT sec_atk)
    STORE-PIN rows store would see = 0           (NOT the fabricated row)

pg_temp shadow (attacker HAS TEMP on database = true): planted a session temp
`memory_pii_key_erasures` with a row; under the pin `to_regclass('memory_pii_key_erasures')`
still resolved to `public`, store saw 0 rows. pg_temp being LAST defeats it.

SECURITY DEFINER audit (live DB, read-only): all 37 `aaliyah_*` SECURITY DEFINER functions
carry a pinned `search_path` in `proconfig`; the query for any secdef function LACKING a
pinned path returned 0 rows. So there is no "unpinned SECURITY DEFINER path" to reach.

Transaction-boundary check (the `SET LOCAL`/`set_config(...,true)` no-op-outside-a-txn
risk): grepped every `enterRole`/`enterMemoryRole` call site across all five stores — each
is immediately preceded by `client.query("BEGIN")`. The pin therefore never runs in
autocommit, so it cannot silently no-op and let the session path govern the next query.
"Survive past COMMIT": is_local reverts at COMMIT, and each store method re-opens BEGIN and
re-pins; no store path issues a role-scoped query outside its pinning transaction.

VERDICT mandate-1 (beyond-replay): the attacker-reachable shadowing vector is CLOSED at
this SHA, confirmed by execution, not by reading the mitigation. Fixture fully removed
(sec_atk schema + sec_atk_login role: 0 remaining). Register G-04 prose is stale — a
documentation finding, non-blocking.

---
## MANDATE 2 — TENANT CROSSOVER (G-02) and RT-M4

Code: `settlementProven` (wave1TrustedMemoryStore.ts:2663-2739) now (a) matches THREE
columns via `JOIN unnest($1,$2,$3) ON want.tenant_id=s.tenant_id AND want.workspace_id=
s.workspace_id AND want.key_ref=s.key_ref` (lines 2697-2701) and (b) keys the result map by
`scopedKey(tenant,workspace,keyRef)` (line 2660-2661, NUL-separated). Both callers look up
by their own row's full scope (2809 for `proveInScopeKeys`, 3155 for the boot pass). The
boot pass (`completePendingAliasErasures`, called unfiltered by src/server.ts:131) is the
cross-tenant one.

Baseline (mutation of the candidate is disposable, restored + sha256-verified byte-identical
after each experiment; `git status` clean throughout; store sha f3e28a07...):
- Whole erasure file PRISTINE: **132/132 PASS**, S-13 green (105s). => crossover is NOT
  reachable today. This is the executed answer to "is cross-tenant satisfaction reachable":
  NO.

### SEC-B (half 1: reachability) — CROSSOVER NOT REACHABLE at e71b51e — EXECUTED
S-13 (`tests/wave1MemoryHoldErasurePostgres.integration.test.ts:6894`) builds the exact
G-02 collision: two tenants sharing `pii_key_ref`, only the first with a sound
PROVEN_DESTROYED settlement, second tenant's key kept ALIVE with a mutator-forged
`key_destroyed` row, and it FORCES the batch ordering the defect needs (settled tenant
first, via the audits `NULLS FIRST` order — asserted at 7034). It then runs the real
unfiltered boot pass and asserts the second tenant is unproven WITH an obligation
(NO_PROVIDER_CONFIGURED) and the first tenant's own settlement still answers for its own
key. This PASSES on pristine code. Crossover is closed.

### SEC-C (half 2a: the LOAD-BEARING control IS falsifiable) — EXECUTED
Mutation A: collapse `scopedKey` to `keyRef` alone (line 2661 `keyRef;`), i.e. re-key the
map by key_ref only (the exact shape of the original G-02 defect). Whole file:
**WATCHDOG VERDICT: FAIL, 30/132 failing**, S-13 among them
(`✖ S-13 ... (82ms)`). So the scoped map key is a REAL, well-covered control; S-13 is a
genuine falsifier for it, not decorative. Restored, sha verified byte-identical.

### SEC-D (half 2b: RT-M4 CONFIRMED — the 3-column JOIN is a redundant, UN-proven control) — EXECUTED · Low · NON-BLOCKING
Mutation B: collapse the JOIN's `ON` to `want.key_ref = s.key_ref` alone (RT-M4's exact
claim). Whole file: **WATCHDOG VERDICT: PASS, 132/132**, S-13 green. So the three-column
`unnest` JOIN can be removed and NOTHING in the erasure suite notices — RT-M4 reproduced by
execution at this SHA.

CRUCIAL security determination the register's OPEN RT-M4 does not state: removing the JOIN
does NOT create a reachable crossover. The map is keyed by the SETTLEMENT ROW's own
(tenant,workspace,key_ref) and every caller looks up by the WANTED row's own scope; a
settlement fetched from tenant A therefore lands in the map under A's scope and tenant B
never looks A up. With key_ref-only matching the query merely fetches more rows (all
tenants sharing a key_ref) — a scaling cost — but the scoped map key still prevents
satisfaction across scopes, which is why S-13 stays green. So:
  - single-point removal of the JOIN: UNDETECTED but NOT exploitable (defense-in-depth).
  - single-point removal of the map-key scoping: DETECTED (S-13 fails).
No single-point mutation produces an UNDETECTED crossover.

FINDING SEC-D: this is the builder's standing-weakness pattern (a control whose removal
nothing detects) confirmed on the fix for the previous round's HIGH — a genuine
test-completeness gap. Severity Low, NON-BLOCKING, because the JOIN is redundant with the
map-key control that IS proven, so no cross-tenant satisfaction is reachable today. The
correct closure per the standing rule is a falsifier for the JOIN half (e.g. an assertion
that `settlementProven` fetches ONLY the wanted scopes), NOT deletion. Recorded as
CONFIRMED-and-scoped, extending the register's OPEN RT-M4.

---
## MANDATE 3 — SIXTH PRIVILEGE-MAP-INVISIBLE WIDENING

### SEC-E · Medium · the declared privilege map does NOT capture function BODIES (prosrc) — a SECURITY DEFINER guard can be silently reimplemented — EXECUTED
The map (`tests/support/memoryPrivileges.ts`, `memoryPrivilegeMap`) captures, per section:
databases, tables, columns, sequences, schemas, defaultAcl (pg_default_acl), functions
(proacl), catalogFunctions, secdef-owners, function-owners, triggers (tgenabled), rules
(pg_rewrite), functionConfig (proconfig), membershipOptions, parameterPrivileges,
typePrivileges, roleAttributes (rolsuper/createrole/createdb/login/replication/bypassrls/
inherit), memberships. It does NOT capture `prosrc` (the function body). `grep -niE
'prosrc|functiondef|md5|body'` over memoryPrivileges.ts returns only comments — the file at
line 146 even reasons about "what a function can do without changing one byte of its body."

This is the SIXTH widening, distinct from K-08's five (CREATE ON DATABASE / cross-schema
view / cross-schema secdef fn / granted pg_catalog fn / function-owner change). Same trust
tier as those five (an actor able to run DDL as the function owner — a compromised owner
role, a malicious migration, or the DBA the G-04 residual explicitly scopes to).

EXECUTED PoC (against `aaliyah_memory_unerased_merged_records(text,text,text)`, the
STABLE SECURITY DEFINER erasure-guard helper whose returning-empty IS the ATK-C1 bypass —
"a subject reported ERASED while its key is alive"):

1. Baseline map snapshot (`memoryPrivilegeMap`) sha256 = 72f84050...200ec8b6...26139b36
   (424 lines). Original body md5(prosrc)=0f949f1b7440633d09f9eaed5112501a.
2. Widening applied:
     CREATE OR REPLACE FUNCTION public.aaliyah_memory_unerased_merged_records(...)
       RETURNS SETOF text LANGUAGE sql STABLE SECURITY DEFINER
       SET search_path TO 'pg_catalog','public','pg_temp'
       AS $function$ SELECT 'WIDENING-PROOF-'||p_record $function$;
   md5(prosrc) -> c6330601a29587ae41c4f0f9e86af388 (CHANGED); secdef=true, owner=postgres,
   cfg=search_path=pg_catalog, public, pg_temp (ALL UNCHANGED).
3. IT WORKS: `SELECT * FROM public.aaliyah_memory_unerased_merged_records('any-tenant',
   'any-ws','rec-XYZ')` returned `WIDENING-PROOF-rec-XYZ` — the new body executes; the
   original body could never emit that. (The security-relevant variant is `... WHERE false`
   / `RETURN` empty: the guard would then report every unerased subject as erased, exactly
   ATK-C1, over live keys.)
4. MAP UNCHANGED: post-widening snapshot sha256 = 72f84050...26139b36 — IDENTICAL,
   `diff` empty. The declared map cannot see the guard was reimplemented.
5. THE TEST DOES NOT CATCH IT: `node scripts/test-watchdog.mjs
   tests/wave1MemoryPrivilegesPostgres.integration.test.ts` -> WATCHDOG VERDICT: PASS 6/6
   with the swapped body in place.
6. REVERTED to the exact migration definition (migrations.ts:5237-5285); md5(prosrc) back
   to 0f949f1b7440633d09f9eaed5112501a; map snapshot diff vs pre-widening = empty;
   `git status --porcelain` clean.

WHAT ASSERTION SHOULD HAVE CAUGHT IT AND DID NOT: no map section records `md5(prosrc)` /
`pg_get_functiondef` for the `aaliyah_*` functions. Adding a `functionBodies` section
(prosrc digest per aaliyah_* function, especially the 37 SECURITY DEFINER ones) is the
falsifier. This is the builder's standing-weakness shape on the CONTROL that the map itself
is: the map's own declared surface has a hole its authors reasoned around rather than
closed. Severity Medium (not blocking on its own: exploitation needs owner-level DDL, the
disclosed G-04/DBA trust tier, not the mutator/reader attacker), but it is a genuine SIXTH
map-blind widening as the mandate asked for, on the most safety-critical function class in
the schema.

---
## MANDATE 4 — KEY DESTRUCTION / ERASURE: forgery, replay, privilege abuse

Role privileges (live DB, information_schema.role_column_grants):
- G-03 CONFIRMED: `aaliyah_memory_mutator` has SELECT-only on
  `memory_key_destruction_obligations.settled_by` (no INSERT/UPDATE); `settler` has UPDATE.
- Settlement WRITE: only `aaliyah_memory_settler` has INSERT on
  `memory_key_destruction_settlements`; only the settler may EXECUTE the secdef writer
  `aaliyah_memory_record_settled_destruction`. Self-verified settlements refused by CHECK
  `..._independent_verifier` (verified below). SETTLED-path obligation forgery is closed by
  S-2e (grant + FK `settled_by_real`), which I confirmed still present. I did NOT re-run the
  full B1/B8 settlement-forgery battery (register CLOSED, mutfuzz observed S-2e/S-6b pass) —
  scope note, not a clearance.

### SEC-F · Low · NON-BLOCKING (disclosed privileged-writer boundary) — the mutator can forge a live key's obligation to PROVEN_DESTROYED via the PROVIDER path — EXECUTED
The 055 CHECK `..._resolution_named` permits `state='PROVEN_DESTROYED'` when
`resolved_by='PROVIDER'` AND `settled_by IS NULL`. The 058 trigger
`aaliyah_memory_settled_obligation_frozen` only freezes rows where `OLD.settled_by IS NOT
NULL` (`IF OLD.settled_by IS NULL THEN RETURN NEW`). The mutator holds INSERT on all
NOT-NULL obligation columns and UPDATE on `state`+`resolved_by`. So, entirely as
`aaliyah_memory_mutator` (SET ROLE, rolled back — DB left with 0 such rows):

    INSERT ... state='KEY_DESTRUCTION_NOT_PROVEN', not_proven_reason='NO_PROVIDER_CONFIGURED'   -- key-LIVE
       -> after insert: KEY_DESTRUCTION_NOT_PROVEN / resolved_by=NULL / settled_by=NULL
    UPDATE ... SET state='PROVEN_DESTROYED', resolved_by='PROVIDER', not_proven_reason='PROVIDER_DOES_NOT_OWN_KEY'
       -> AFTER FORGE: PROVEN_DESTROYED / PROVIDER / settled_by=NULL   (UPDATE 1, accepted)

A provider was never asked; no settlement exists. The obligation ledger — which operators
read to see erasure state (register G-09) — now falsely reports a live key as provider-proven
destroyed.

Scope/impact, stated honestly:
- This is the EXACT raw UPDATE the healing path itself issues (wave1TrustedMemoryStore.ts:3338
  `SET state='PROVEN_DESTROYED', ... resolved_by='PROVIDER'`), so the capability is BY DESIGN;
  there is no DB binding of a PROVIDER resolution to a real provider answer, and one is not
  possible without a provider-signed attestation (production cloud KMS/HSM — explicitly NOT
  CLAIMED, protocol line 51; register row A "authenticity against a privileged writer is NOT
  PROVEN").
- It corrupts the ledger/audit record only; it does NOT complete an erasure over a live key —
  the erasure guard `aaliyah_memory_unerased_merged_records` reads real `key_destroyed`
  evidence, not the obligation ledger, and forged `key_destroyed` evidence is separately
  defended (test "K-9 SECURITY F2", the provider-contradiction gate SEC-01, settlement
  soundness).
- STANDING-WEAKNESS observation (mandate 5 shape): the SETTLEMENT attribution path is
  defended in depth (grant separation, FK to a real settlement, S-2e, the append-only +
  binds-real-key triggers, self-verification CHECK) while the PROVIDER attribution path has
  NO equivalent binding and NO test asserting the mutator cannot forge it (grep for such an
  assertion returned none). An attacker forging "this live key is destroyed" simply writes
  `resolved_by='PROVIDER'` and sidesteps every settlement defense. Closing it needs a
  provider-attestation record with an FK (analogous to `settled_by_real`), which is
  meaningful only with KMS-class signing — out of the W1.3 local boundary.
Classified Low / NON-BLOCKING: within the disclosed KMS-not-provisioned trust boundary and
does not breach the erasure guard. Recorded because the mandate explicitly asked "can a role
make a live key report resolved?" — the answer is YES for the ledger via the PROVIDER path,
NO for an actual erasure.

---
## MANDATE 5 — STANDING WEAKNESS / TST-1: verify the deleted self-verification pre-check IS redundant — EXECUTED

TST-1 deleted the store's self-verification pre-check in `settleKeyDestruction` on a
redundancy proof (S-4's comment, test file:7108). Verified BY EXECUTION at e71b51e, not
inherited: the DB control is a plain validated table CHECK
`memory_key_destruction_settlements_independent_verifier :: CHECK (settlement_authority_id
<> verifier_principal_id)` (convalidated=t). Isolated it exactly as mutfuzz did for M-55
(`ALTER TABLE ... DISABLE TRIGGER ALL` — removes FK + the two settlement triggers, leaves
CHECK + NOT NULL) inside a rolled-back transaction:

    (A) authority = verifier = 'SAME-PRINCIPAL', valid digest/evidence ->
        ERROR: violates check constraint "memory_key_destruction_settlements_independent_verifier"

So with the store gone, every trigger disabled, and every FK disabled, the DATABASE alone
still refuses a self-verified settlement. Baseline S-4 also passes (store translates it to
`settlement_self_verified`). The redundancy proof holds at this SHA: deleting the store-side
pre-check does not remove the property, because the CHECK is its independent falsifier. NOT
a finding.

(Note the digest_shape CHECK fired first on my initial malformed attempt — recorded so the
next reviewer sees the differential was genuine, not a lucky single-constraint hit.)

Other standing-weakness results are folded into SEC-D (JOIN removable undetected),
SEC-E (function-body swap invisible to the map), and SEC-F (PROVIDER-path forge untested).

---
## MANDATE 1 (replay half) — canned search-path replay against port 54602 — EXECUTED
`/Users/andrelove/aaliyah-w13-evidence/search-path-attack/run.sh 54602` output:

    VULNERABLE PIN PATH: pg_catalog, opsched, public, pg_temp
    VULNERABLE TABLE RESOLVES TO: opsched
    VULNERABLE ERASURE-GUARD HELPER RESOLVES TO: opsched
    VULNERABLE ROWS THE STORE WOULD SEE: 1
    FIXED PIN PATH: pg_catalog, public, pg_temp
    FIXED TABLE RESOLVES TO: public          <-- as mandated
    FIXED ERASURE-GUARD HELPER RESOLVES TO: public
    FIXED ROWS THE STORE WOULD SEE: 0

Under the new (constant) pin the store's names resolve to `public`, seeing 0 fabricated
rows; under the old pin they resolved to `opsched`, seeing the attacker's forged row. Matches
my independent fixture PoC (SEC-A). The fix is confirmed two independent ways by execution.

TRAP 6 handling: I ran this replay LAST, then CLEANED UP the `opsched` schema and
`attacker_app` role it leaves behind. Post-cleanup verification: opsched=0, attacker_app=0,
migrations=60, settlements=0, `aaliyah_memory_unerased_merged_records` md5 back to
0f949f1b7440633d09f9eaed5112501a. The database is left CLEAN and reusable (NOT contaminated).

---
## Subject verified (after)

| field | value |
|---|---|
| HEAD (after) | e71b51e9ed333d1feab1cd6819496269d201a6e2 (unchanged) |
| worktree (after) | `git status --porcelain` empty — CLEAN |
| contracts (after) | 7d576681d1001eb4c4a7f044f7793cdb3f80af76 (unchanged) |
| store file sha (after) | f3e28a07a5129eeae4b0ae99f8ec6e7ba4b9757a47d16ae6f4963525da6472b0 (== pre-mutation) |
| DB (after) | migrations=60, all my fixtures/mutations reverted, function bodies restored |

All source mutations (map-key collapse, JOIN collapse) and DB experiments (schema shadow
fixture, function-body swap, obligation forge, self-verified settlement) were transient PoC,
each restored and verified (sha256 for files, md5(prosrc) for functions, ROLLBACK for DML).

## What I did NOT cover (explicit denominator)
- Did NOT re-run the full B1/B3/B4/B6/B8 settlement-forgery battery (register CLOSED; mutfuzz
  observed S-2e/S-6b/S-9 passing). I re-executed only the self-verification CHECK (TST-1) and
  the SETTLED-path grant/FK (S-2e present) directly.
- Did NOT independently re-verify SEC-01 provider-contradiction gate or M-47/M-55 — mutfuzz
  gate 3 re-executed those at this SHA; I extended into the PROVIDER-path forge instead.
- Did NOT test session/token replay, webhook signature forgery, or HTTP-layer authz — there
  is no HTTP route to the memory/erasure surface (register G-09); the attack surface is SQL
  role privileges, which I exercised.
- Did NOT exhaustively enumerate EVERY map-blind widening class (default privileges, event
  triggers, large-object/FDW/language ACLs) — I confirmed the map DOES capture pg_default_acl,
  rules, proconfig, role attributes, and memberships, and delivered ONE new class
  (function bodies / prosrc, SEC-E) as the mandate required.
- Did NOT attack tenant crossover beyond the settlement/obligation surface (e.g. alias
  registry, identity graph, legal hold cross-tenant reads) — bounded by budget; the mandate
  named the settlement path.
- Production cloud KMS/HSM: explicitly NOT CLAIMED, not attacked (per protocol line 51).

## Boundaries tested (denominator)
| boundary | tested | method |
|---|---|---|
| search_path / schema shadowing (attacker-reachable) | yes | own fixture + poisoned session path + pg_temp + canned replay; all resolve to public |
| SECURITY DEFINER unpinned path | yes | live pg_proc audit: 37/37 secdef aaliyah_* pinned, 0 unpinned |
| tenant crossover (settlement) | yes | S-13 baseline PASS + map-key collapse FAIL + JOIN collapse PASS (executed mutations) |
| privilege-map completeness | yes | 6th widening (function-body swap) executed, map byte-identical, test PASS, reverted |
| settlement forgery (SETTLED path) | yes | grant enumeration + S-2e present; settler-only INSERT confirmed |
| obligation forge (PROVIDER path) | yes | mutator SET ROLE UPDATE executed (accepted), rolled back |
| self-verification redundancy (TST-1) | yes | independent_verifier CHECK isolated via DISABLE TRIGGER ALL, refused |
| replay of settlement receipt | partial | S-6/S-6b observed passing at baseline; not independently re-mutated |

## VERDICT
Findings: SEC-D (Low, non-blocking) · SEC-E (Medium, non-blocking) · SEC-F (Low, non-blocking).
No CRITICAL or HIGH substantiated. All named boundaries were EXERCISED (none NOT_VERIFIED).
The strongest finding, SEC-E (the privilege map — a claimed control — cannot see a SECURITY
DEFINER guard's body being reimplemented), requires owner-level DDL to exploit (the disclosed
G-04/DBA trust tier, same tier as K-08's five catalogued widenings) and is handed up for
founder/AEGIS-Omega adjudication.

SECURITY_GREEN · blocking: false

This is ONE gate. Not a certification. AEGIS Omega-MAX adjudicates the worst verdict across
all gates.
