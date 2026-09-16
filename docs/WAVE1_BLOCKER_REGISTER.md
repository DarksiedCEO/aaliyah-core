# Wave 1 Blocker Register

Findings that block a Wave 1 gate but are **out of scope for the gate that found
them**. Entries are opened by an independent review gate, never by the
implementer, and are closed only by an independent gate against an exact SHA.

A finding in this register is **not** a backlog item. A Wave 1 gate may not be
declared GREEN while an entry bound to it remains open.

| Field | Meaning |
| --- | --- |
| Gate | The Wave 1 gate the finding blocks |
| Source | The independent review gate that opened it |
| Subject SHA | The exact immutable candidate the finding was proven against |
| Disposition | `OPEN` · `CLOSED_BY_SHARED_PRIMITIVE` · `CLOSED_INDEPENDENTLY_VERIFIED` |

---

## Provenance

All entries below were proven by executed proof-of-concept against
`aaliyah-contracts` at candidate SHA
`e9d57cf13ad8134f66fed4242598efe62f5c33be`, tree
`7ced5044de732fe2c1d6c43e8d957a27fae079c3`, during the W1.3 stop-loss review.
They were found while reviewing W1.3 and are recorded here because they live in
the **authority path that W1.6 depends on**, not in the memory path W1.3 owns.

Per founder authorization (Part H): these must not be silently fixed as
unrelated W1.6 behaviour. Where a *shared trust primitive* built for W1.3 can
safely close the defect without expanding W1.3 scope, it may be closed — with
explicit tests and independent review. Otherwise it stays open as a W1.6
blocker.

---

## W1BR-001 — Revocation-vs-consumption race

- **Gate:** W1.6 · **Source:** Reliability · **Severity:** HIGH
- **Location:** `src/v1/wave1-authority.ts:398-416` (`verifyExecutiveQualityDraft`)

The stored approval is read and checked for `revokedAt` / `consumedAt` at
`:399-402`, then the nonce is claimed at `:413`. The claim primitive's signature
is `(nonce: string) => boolean` (`:225`) — it **structurally cannot express**
"claim only if still unrevoked". An approval revoked inside that window is
consumed anyway and the draft still verifies.

- **Disposition:** `OPEN`
- **Shared-primitive candidate:** YES. W1.3 Part E requires atomic consumption
  that verifies, *in the same transaction*, that the authorization is real,
  unexpired, unrevoked, unconsumed, action-matching, target-matching, and
  current-head-matching. That primitive is the fix. W1.6 must then **adopt** it;
  building it for the memory path does not by itself close this entry.

## W1BR-002 — `assertHumanApprovalUsable` authenticates caller-supplied claims

- **Gate:** W1.6 · **Source:** Security (CRITICAL) · **Severity:** CRITICAL
- **Location:** `src/v1/wave1-authority.ts:178-199`; exported via `src/v1/index.ts:51`

The function takes `raw: unknown` plus one nonce callback. It has **no**
`resolveApprovalRecord` and **no** `resolveApproverAuthority`. Every field it
checks — `decision`, `revokedAt`, `consumedAt`, `decidedAt`, `expiresAt` — is
supplied by the caller being authorized.

Proven: an approval with `approvalId: "approval-NEVER-ISSUED"`,
`approverActorId: "mallory-who-never-approved-anything"`, `tenantId:
"tenant-VICTIM"` and a fresh nonce returned **VERIFIED**. It is the exported
weak sibling of `verifyExecutiveQualityDraft`, which *does* resolve both.

Human-in-the-loop is decorative on this path.

- **Disposition:** `OPEN`
- **Shared-primitive candidate:** PARTIAL. Part E establishes "authorization is
  real stored state, not caller-supplied truth" as the governing rule. Applying
  that rule here is a W1.6 change; the rule itself comes from W1.3.
- **Note:** also carries no tenant/workspace scope, so it is a confused-deputy
  path across tenants (Security H10).

## W1BR-003 — Approval replay by nonce rotation

- **Gate:** W1.6 · **Source:** Security (CRITICAL) · **Severity:** CRITICAL
- **Location:** `src/v1/wave1-authority.ts:194`; nonce field at `:118`

`approvalNonce` is an attacker-supplied `z.string().min(16)` that is **not
bound** to `approvalId`, `immutableEventDigest`, or `candidateDigest`. Replay
protection keys on the nonce, so an attacker rotates the nonce rather than the
approval. The same `approvalId` submitted three times under
`nonce-…0001/0002/0003` verified all three times. `consumedAt` is never written
back.

The identical-nonce replay **is** correctly rejected — the control catches the
one case an attacker never needs.

- **Disposition:** `OPEN`
- **Shared-primitive candidate:** YES. Part E requires the nonce to be bound to
  `authorizationId`, `action`, `target`, and expected head. A nonce bound that
  way cannot be rotated independently of the authorization it authorizes.

## W1BR-004 — Nonce burn has no compensation

- **Gate:** W1.6 · **Source:** Reliability · **Severity:** MEDIUM
- **Location:** `src/v1/wave1-authority.ts:194`, `:413`

The nonce is consumed, then the function returns. A crash between consumption
and the caller's use of the result leaves the nonce burned with no release path
and no operation key making the retry idempotent. `idempotencyKey` exists on the
binding (`src/v1/wave1-common.ts:27`) but is not passed to the claim.

Fail-closed in direction, but a real recovery gap: a legitimate retry is
permanently rejected.

- **Disposition:** `OPEN`
- **Shared-primitive candidate:** YES. Part B requires an
  `UNKNOWN_PENDING_RECONCILIATION` (or equivalent) fail-closed state for unknown
  transaction outcomes, plus an immutable mutation receipt. That is the
  compensation mechanism.

## W1BR-005 — Synchronous resolver architecture cannot express timeouts

- **Gate:** W1.6 · **Source:** Reliability · **Severity:** MEDIUM
- **Location:** `src/v1/wave1-memory.ts:565-580`, `src/v1/wave1-authority.ts:211-255`

Every resolver is declared `(x) => T | null`. No timeout, deadline, or abort is
expressible. Measured: a resolver taking 1.2 s blocked the caller for 1199.8 ms
with no way to bound it. A real store is network-bound, so plugging one in
either blocks the event loop or forces a cache — and a cache is precisely what
makes a current-head check stale.

- **Disposition:** `OPEN`
- **Shared-primitive candidate:** NO for W1.6's existing contracts-level
  resolvers. W1.3 sidesteps it structurally: Part B moves authoritative
  resolution into an async Core service against PostgreSQL, so the memory path
  will not carry this defect. The W1.6 draft path retains it until migrated.

---

## W1BR-006 — Canonical digest: fractional numeric residual

- **Gate:** W1.3 · **Source:** Mutation + Security, confirmed by orchestrator against live PostgreSQL 16
- **Location:** `aaliyah-contracts` `src/v1/canonical-digest.ts` @ `8f24129`

PostgreSQL `jsonb` stores numbers as arbitrary-precision `numeric`; Node's
`JSON.parse` collapses them to IEEE-754 doubles. Two distinct persisted values
can therefore digest identically.

Commit `8f24129` adopted the enforced-precondition option: accepted numbers must
satisfy `Number.isSafeInteger(v) || !Number.isInteger(v)`. Executed against the
shipped module:

| input | result |
| --- | --- |
| `9007199254740993` | REJECTED — integer magnitude exceeds exact range |
| `12345678901234567890` | REJECTED |
| `0.1` vs `0.1000000000000000000001` | **same digest** |
| `3` vs `3.0000000000000000001` | **same digest** |
| `1.5` vs `1.5000000000000000001` | **same digest** |

PostgreSQL returns `0.1000000000000000000001` and `3.0000000000000000001`
verbatim, so the collapse is on the JS side, before the digest.

**Integer collision class: CLOSED. Fractional collision class: OPEN.**

- **Disposition:** `OPEN` (residual, documented and tested — not a silent gap)
- **Exploit precondition:** a writer that is not this JS layer — SQL-side
  arithmetic, a `numeric`→`jsonb` cast, or a non-JS service — must place a
  high-precision decimal on the receipt path. A JS writer cannot produce one:
  the value collapses before it is ever written.
- **Closure path:** digest the database's exact decimal *text* rather than a
  parsed JS number (the "strict" option). Not adoptable inside
  `canonical-digest.ts` alone — `MemoryProvenanceReceiptSchema` and
  `MemoryPromotionReceiptSchema` declare `recordVersion: z.number()`
  (`wave1-memory.ts:149,188`) and those receipts are exactly what is digested,
  so strict rejection would fail honest stores closed. Closing this requires a
  coordinated call-site migration carrying numerics as canonical decimal
  strings.
- **Interim control required in Part B:** Core must be the only writer on the
  receipt path, and that exclusivity must be enforced, not assumed.

---

## W1BR-007 — The mutation role can burn a pending approval

- **Gate:** W1.3 · **Source:** Security, executed against `34ac77f` on a live
  PostgreSQL 16 · **Severity:** MEDIUM
- **Location:** `src/persistence/postgres/migrations.ts` migration 029
  (`GRANT UPDATE (consumed_at, consumed_by_mutation_receipt_id) ON
  memory_authorization_nonces TO aaliyah_memory_mutator`)

Consumption has to be available to the mutation role — spending the nonce is
the whole point of the role. That same grant lets it spend an approval it was
never asked to spend:

```sql
SET LOCAL ROLE aaliyah_memory_mutator;
UPDATE memory_authorization_nonces
   SET consumed_at = now(), consumed_by_mutation_receipt_id = 'attacker'
 WHERE binding_digest = $1;   -- ACCEPTED, 1 row
```

The legitimate holder of that approval then gets `authorization_already_consumed`
and has to have a new one issued. This is a **denial of service against an
approval**, not a forgery: migration 034 means a burned nonce cannot be turned
into a record version or a committed outcome, and migration 035 means the burn
cannot afterwards be undone or attributed to somebody else.

- **Disposition:** `OPEN` (residual, disclosed and tested — the burn is
  permanent and attributable, not silent)
- **Closure path:** a consumption that names the mutation receipt id BEFORE the
  mutation transaction begins (a reservation), or an issuer-side second factor
  on consumption. Either changes the store's transaction shape and is out of
  scope for Part B2.

---

## W1BR-008 — The unkeyed content digest is an offline oracle

- **Gate:** W1.3 · **Source:** Security, executed against `34ac77f` on a live
  PostgreSQL 16 · **Severity:** MEDIUM
- **Location:** `src/application/memory/wave1TrustedMemory.ts:171`
  (`memoryContentDigest`), `aaliyah-contracts` `canonicalDigest`

`canonicalDigest` is an **unkeyed, deterministic** SHA-256 over canonical JSON.
Anyone who holds a record's `contentDigest` — from a head read, from a mutation
receipt, from a backup, from a log — can confirm guessed content offline by
digesting the guess and comparing. For the low-entropy content this path
actually carries (a participant identity, a status, a short note, a
last-four) the guess space is small enough to enumerate.

Executed: `memoryContentDigest({ ssn: "123-45-6789" })` equals the stored head
digest of a record holding exactly that value, computed with no access to the
database at all.

The read-side half is narrowed by Part B2: `readHead` now filters on all four
scope dimensions, so an actor from another principal in the same workspace can
no longer obtain the digest through the store. The oracle itself is untouched —
it lives in the digest construction, not in the query.

- **Disposition:** `OPEN` (residual, disclosed; the read path is narrowed, the
  construction is not changed)
- **Closure path:** a KEYED construction — HMAC or a signature whose key lives
  in a KMS/HSM, outside the database — so that possessing a digest without the
  key confirms nothing. That primitive is not in this repository, and closing it
  changes a shared contracts-level digest that other Wave 1 paths depend on, so
  it is a coordinated migration and not a Part B2 change.

---

## Cross-cutting note carried forward from the W1.3 review

The W1.3 candidate's suite was green while 25 of 31 applied mutations survived,
including a mutant that deleted 71 of 73 lines of runtime verification. Any
entry above that is later claimed CLOSED must be closed with tests that
**fail when the control is deleted** — not merely tests that pass while it is
present. See founder authorization Part G, mandatory mutation targets.

---

## W1BR-009 — A genesis could be planted under another principal, user, or workspace

- **Gate:** W1.3 · **Source:** Security, executed against `d6d77ad` on a live
  PostgreSQL 16 under `aaliyah_memory_mutator` · **Severity:** CRITICAL
- **Location:** `src/persistence/postgres/migrations.ts` migrations 034/038
  (`aaliyah_memory_record_version_guard`, `aaliyah_memory_spent_nonce`)

Migration 034 pins ownership **continuity**: version N+1 may not change
principal or user from version N. That check sits on the branch taken when a
prior version is found, so **version 1 never reached it**. The witness
resolves on tenant, authorization and receipt, plus the record id the guard
adds — nothing about workspace, principal or user.

Executed: a holder of the mutation role and **one legitimately issued `create`
authorization for its own scope** spent that authorization and wrote version 1
under another principal and user, in another workspace.

```sql
SET LOCAL ROLE "aaliyah_memory_mutator";
UPDATE memory_authorization_nonces SET consumed_at=now(),
       consumed_by_mutation_receipt_id='m.poc' WHERE binding_digest=$own;
INSERT INTO memory_record_versions (..., principal_id, user_id, ...)
VALUES (..., 'principal-victim', 'user-victim', ...);   -- ACCEPTED
```

The victim's own `retrieve` returned attacker-chosen content as the victim's
record, and an ordinary protocol `correct()` over it succeeded — so the forged
root became an indistinguishable, digest-linked, receipted chain. The identical
forgery at version 2 was refused by 034.

**Provenance:** inherited. `migrations.ts` is byte-identical at `8de7da9` and
`d6d77ad`. The `create` operation did not introduce the gap; it converted
genesis from "something privileged inserted" into a protocol operation whose
safety argument was stated inline and **was not enforceable**.

- **Disposition:** `CLOSED` by migration
  `039_memory_genesis_owner_binding`, which binds a genesis row's
  `(tenant, workspace, principal, user)` to the `memory_authorization_receipts`
  row its `authorization_id` resolves to. No new column; the receipt already
  carries all four NOT NULL.
- **Falsification performed:** with 039 reverted in the database, the three
  new attack tests fail and the positive control still passes; with 039
  applied, all four pass. The pin is therefore not a blanket refusal.

---

## W1BR-010 — `create` is a cross-principal record-id existence oracle

- **Gate:** W1.3 · **Source:** Security, executed against `d6d77ad` ·
  **Severity:** LOW
- **Location:** `src/persistence/postgres/wave1TrustedMemoryStore.ts`, the
  CAS-on-absence head lookup

The genesis CAS reads the head filtered by `(tenant, workspace, record_id)`
only, so any head — owned by any principal in the workspace — refuses the
genesis. `head_mismatch` versus success therefore discriminates whether a
record id is taken by somebody else. The probe is free: consumption happens
after the CAS, so an aborted attempt does not burn the nonce.

Bounded: no content, digest or owner leaks (`retrieve` and `readHead` both
answer null for the prober), nothing of the victim's is mutated, and the
**equivalent oracle already exists on the unchanged `correct()` path**
(`record_owner_mismatch` versus `head_mismatch`). `create` adds a cleaner
signal, not a new capability.

- **Disposition:** `OPEN` (residual, disclosed and bounded — not introduced by
  W1.3, present on an existing action)
- **Closure path:** return an indistinguishable rejection for "exists but not
  yours" and "does not exist", or scope the CAS-on-absence lookup to all four
  actor dimensions. **In tension** with the deliberate choice at the ownership
  comparison not to filter the head lookup, which exists so a takeover is
  distinguishable from a `head_mismatch` and the control stays killable. The
  tradeoff should be decided explicitly, not drifted into.

---

## W1BR-011 — Unresolved `create` attempts are an unbounded durable-write primitive

- **Gate:** W1.3 · **Source:** Security, executed against `d6d77ad` ·
  **Severity:** LOW
- **Location:** `src/persistence/postgres/wave1TrustedMemoryStore.ts`,
  `auditUnresolvedAttempt`

**Introduced by W1.3.** For non-create actions the function returns early when
no head is observable, so a sweep against unreachable ids writes zero rows. For
`create`, `fromHead` is the constant `no_prior_version`, so a row is always
written. Executed: 100 `create()` calls with valid-shaped but nonexistent
authorization ids, by a caller holding no authorizations, produced 100 durable
rows in 160ms; the same 100 `correct()` calls produced 0.

The audit widening itself is intended and disclosed — probing ids that do not
exist is exactly what a genesis sweep looks like, and it was previously
unaudited. The **denial-of-service side was not disclosed**, and is here.
`UNIQUE (tenant, workspace, mutation_receipt_id, phase)` does not bound it:
`mutationReceiptId` is caller-supplied.

Attribution holds — rows are filed under the authenticated actor's scope and
could not be forged onto another party.

- **Disposition:** `OPEN` (residual, disclosed, bounded and attributable)
- **Closure path:** a per-actor rate limit upstream of the store, or a
  retention policy on the audit partition of `memory_mutation_receipts`, with
  the ceiling stated. Not a store-layer change.

---

## W1BR-012 — Retention obligations do not gate `create` (informational)

- **Gate:** W1.3 · **Source:** Security, executed against `d6d77ad` ·
  **Severity:** INFORMATIONAL

The retention check sits inside the `delete` branch, so a `create` on a record
id carrying an unexpired obligation succeeds. This is **not** a bypass: an
obligation constrains destruction, a genesis over a non-existent id destroys
nothing, and a genesis over an existing id is refused by the CAS.

- **Disposition:** `BOUNDED_AND_PROVEN_NONBLOCKING` — recorded so the absence
  is not later read as an oversight.

---

## W1BR-013 — 34 of 103 mutants survived at `002aec2`

- **Gate:** W1.3 · **Source:** Mutation-discrimination sweep, isolated worktree
  and database, executed against `002aec2` · **Severity:** HIGH (test evidence)

A comprehensive sweep applied 103 mutants and 34 survived — the failure mode
this register already warns about. The headline: **all nine conjuncts of
`postStateAgrees` survived independently.** That expression is the last gate
before a `COMMITTED_AND_READ_BACK` receipt is minted, and no test had ever
built a read-back agreeing on eight fields and disagreeing on the ninth.

- **Disposition:** `PARTIALLY CLOSED`.

**Closed and re-falsified** (each mutant re-applied after the test existed, and
each now turns the suite red):

| Control | Why it had no test |
| --- | --- |
| `postStateAgrees.contentDigest` | stored column can differ from the recomputed payload digest |
| `postStateAgrees.predecessorDigest` | no test observed a head linking elsewhere |
| `postStateAgrees.state` | no test observed a head in the wrong state |
| `postStateAgrees.scope.principalId` | the ownership half of the takeover |
| `postStateAgrees.scope.userId` | the ownership half of the takeover |
| CAS head lookup `workspace_id` | no test placed one record id under two workspaces |
| migration 039 `a.tenant_id` | the fix shipped with principal/user/workspace tests and no tenant test |
| migration 039 `a.authorization_id` | a guard checking only scope would accept another party's approval |
| consumption `revoked_at IS NULL` | a real TOCTOU window, now driven by row locks |
| consumption `expires_at > now()` | only non-redundant when the ROW changes |
| consumption `tenant_id = $1` | `UNIQUE (tenant_id, binding_digest)` permits a shared digest |
| `memory_authorization_receipts_exact_numbers` | only the `record_versions` sibling was tested |
| `memory_tombstones_exact_numbers` | only the `record_versions` sibling was tested |

**Reported as surviving, NOT claimed covered.** Four `postStateAgrees`
conjuncts — `recordId`, `version`, `scope.tenantId`, `scope.workspaceId` — are
UNREACHABLE: `headFromRow` refuses a payload disagreeing with its columns on
all four, the read-back query filters on three of them, and the version is
rejected earlier. Plus the two backstops the code already discloses
(`expectedHeadKindFor`, the erasure `rowCount` equality).

**STILL OPEN:** 15 of 19 sampled CHECK constraints survived a direct
`DROP CONSTRAINT`, and **67 of 86 CHECK constraints on the five memory tables
were never drop-tested at all** — `NOT_VERIFIED`, not passing. Two mutants were
inconclusive (the run hung rather than completing); neither is reachable
through the application surface.

---

## W1BR-014 — Migrations are not independently replayable

- **Gate:** W1.3 · **Source:** Encountered directly while restoring a mutant ·
  **Severity:** MEDIUM (operational)

Migration 027 creates `aaliyah_memory_jsonb_numbers` and
`aaliyah_memory_reject_inexact_numbers` unqualified and without a pinned
`search_path`. Migration **033** redefines both as `public.`-qualified with
`SET search_path = pg_catalog, public`, which is what defeats a caller that
shadows the helper in its own `search_path`.

Both use `CREATE OR REPLACE`. So deleting 027's row from
`aaliyah_mail_migrations` and re-running **silently reverts 033's hardening**,
and the only visible symptom is that the search-path shadowing test starts
failing. Observed exactly that way.

Not reachable through `runMailMigrations`, which skips applied ids. It is
reachable by an operator re-applying a migration by hand, by tooling that
replays by id, and by a partial restore.

- **Disposition:** `OPEN` (residual, disclosed, operational)
- **Closure path:** make later hardening idempotent under replay — either fold
  033's definitions back into 027 so there is one definition, or add a
  migration-order assertion that refuses to apply an id lower than the highest
  already applied. Both are schema-tooling changes, not store changes.

---

## W1.3 IDENTITY SEMANTICS — FOUNDER DECISION, LOCKED

Recorded here because it is a product decision, not an implementation one, and
the code now depends on it.

**MERGE.** `merge_identity` targets the ABSORBED identity. The absorbed
record's history remains immutable and retained; it becomes frozen against
future ordinary mutation; the merge does NOT imply deletion. Canonical
read-time resolution may redirect an absorbed identity to its surviving
identity without rewriting historical evidence.

**SPLIT.** `split_identity` does not implicitly create another identity. The
split-off identity must already exist through its own independently authorized
`create`. The split then records the relationship change.

**CORE LAW.** ONE AUTHORIZATION → ONE MUTATION. The nonce, receipt, CAS,
version and witness invariants are not to be weakened to make merge or split
more convenient.

Read-time canonical resolution is implemented in
`src/application/memory/wave1MemoryService.ts` and is strictly read-only: it
resolves, and it never mutates or hides the absorbed record.

---

## W1BR-015 — A merge could name a record that was itself merged away

- **Gate:** W1.3 · **Source:** Found while building the read-time canonical
  resolver — not by a test · **Severity:** MEDIUM
- **Location:** `src/persistence/postgres/migrations.ts` migration 041

Migration 041 refuses a SECOND outgoing merge from one record and freezes a
record once absorbed. Neither stopped an edge pointing INTO an absorbed record.

Two consequences. A merge into a ghost: the named survivor no longer accepts
mutations, so the identity resolves to something already superseded. And a
CYCLE — A merged into B, then B merged into A. B is not frozen by its own
outgoing edge, and A's head state is still `active` (a merge freezes, it does
not delete), so every check in 041 passes and the graph closes a loop. A
resolver walking that graph never terminates.

- **Disposition:** `CLOSED` by migration
  `042_memory_identity_no_merge_into_absorbed`, plus the matching
  application-side refusal `identity_counterparty_merged_away`.
- **Defence in depth:** the resolver carries an independent depth bound and
  refuses rather than truncating, because a replica or a restored backup
  carries no trigger guarantee — and a truncated walk returns a NON-canonical
  identity indistinguishable from a canonical one.

---

## W1BR-016 — The executive pipeline is not reachable over HTTP

- **Gate:** W1.3 · **Source:** Reachability wiring · **Severity:** MEDIUM
  (completeness, disclosed)

W1.3 item 4 asked for proof that trusted memory is reached by a real Core
consumer rather than being dead library code. That is now true of the STORE:
`src/server.ts` composes the memory service at boot, runs a reconciliation
pass before opening a socket, and `runEaPipeline` reads authoritative memory
for an email's sender through the alias registry and the identity graph.

**The honest remaining gap: `runEaPipeline` itself has no HTTP route.** Its
only callers are tests. So the chain
`email -> alias -> identity -> canonical identity -> trusted memory -> consumer`
is proven end to end against a live PostgreSQL, and the ENTRY to that chain
from an actual request is not yet wired.

- **Disposition:** `OPEN` (residual, disclosed). Reported rather than described
  as "wired", because a chain that no request can enter is reachable only from
  a test.
- **Closure path:** an inbound route that constructs the EA deps — including
  the memory service `src/server.ts` already builds — and calls the pipeline.
  That is W1.4 surface, not W1.3.

---

## W1BR-013 UPDATE — the CHECK-constraint destroyers

The residual left open under W1BR-013 was: 67 of the CHECK constraints on the
five memory tables had never been drop-tested, and 15 of 19 sampled survived.

`tests/wave1MemoryConstraintDestroyersPostgres.integration.test.ts` now writes
a row DIRECTLY, as the table owner, that is valid in every respect except the
one constraint it names, and pins that constraint **by name** — a generic "it
was refused" passes when a different constraint fires, which is exactly how a
constraint appears covered while never having been exercised.

**Verified by dropping all 81 CHECK constraints, one at a time**, restoring
each afterwards, and running the suite against every drop:

| Result | Count |
| --- | --- |
| Killed — the drop turns the suite red | **77** |
| Survived | 4 |

**The four survivors are one structural fact, not four gaps.**
`<table>_payload_object` on `memory_record_versions`,
`memory_authorization_receipts`, `memory_tombstones` and
`memory_alias_bindings` cannot be violated in isolation: every payload binding
reads `payload ->> 'x'`, which is NULL for an array or a scalar, so the
bindings refuse a non-object payload before the object check is reached.
Dropping any of the four changes nothing observable. They are reported as
SURVIVING, not claimed as covered; a consolidated test proves the property
that actually matters — a non-object payload lands on none of the four.

Two preconditions the positive controls caught, which would otherwise have made
every case in their table pass for the wrong reason:

- `memory_tombstones_structural` is a BEFORE trigger requiring the target to
  already be a deleted record, so **no** tombstone row reached the CHECK layer
  at all. The cases run with it stood down and always restored; its own
  behaviour is proven in the hold/erasure suite.
- `memory_alias_bindings` carries a FOREIGN KEY onto the tenant's alias policy,
  so without that row the base binding was refused by the FK and never reached
  a CHECK.

- **Disposition:** `CLOSED` for 77 of 81; the remaining 4 are
  `BOUNDED_AND_PROVEN_NONBLOCKING` — structurally unreachable, disclosed, with
  the property they exist to protect proven by other means.

---

## W1BR-008 UPDATE — the oracle, measured, and a sharper edge than first stated

`tests/wave1MemoryDigestOraclePostgres.integration.test.ts` executes the
residual rather than describing it.

**THE EDGE THE ORIGINAL ENTRY DID NOT NAME: erasure does not destroy the
digest.** `delete` nulls `payload.content` on every prior version, and leaves
`content_digest` standing — on the erased row, and again on the tombstone
version's `predecessor_digest`, where it is the chain link. Executed: after a
`subject_erasure_request`, the plaintext is gone from every version, and
`memoryContentDigest({ nationalId: "123-45-6789", status: "verified" })` still
equals the stored digest. **The content is destroyed; the ability to confirm
what it was is not.**

That second copy is why this cannot be closed by nulling a column. The
predecessor digest is what makes the chain verifiable, so removing it breaks
the property the chain exists for. Closing it requires a KEYED construction,
which is what `src/crypto/memoryIntegrity.ts` provides.

**THE BOUND, PROVEN:**

- The store does NOT hand the digest to another principal: `readHead` and
  `retrieve` filter on all four scope dimensions, and an intruding principal
  gets null from both.
- The exposure is to a party with STORED-STATE access — a backup, a replica, a
  log that captured a receipt — not to an ordinary API caller.
- A wrong guess is rejected precisely, which is what makes a low-entropy guess
  space searchable.

**THE CLOSURE PATH, DEMONSTRATED:** the same correct guess against the keyed
primitive confirms nothing, an attacker-chosen key does not reproduce the tag,
and the holder of the real key still verifies it — so the tag stays an
integrity control rather than becoming an opaque value.

**STATUS.** A test asserts no keyed-tag column exists on
`memory_record_versions`, so this residual cannot quietly come to be believed
closed because a keyed primitive was merged.

- **Disposition:** `BOUNDED_AND_PROVEN_NONBLOCKING` for W1.3 as gated —
  production key infrastructure remains honestly NOT PROVEN, which the gate
  admits. Closing requires the contracts-level digest to become keyed across
  both repositories.
- **FOUNDER DECISION NEEDED, and it is not mine:** whether a subject-erasure
  guarantee is acceptable while a party with stored-state access can still
  confirm erased low-entropy content. That is a compliance question about what
  Aaliyah promises a data subject, not an engineering trade-off. Raising it
  before real personal data is handled, not after.

---

## W1BR-014 — CLOSED

`runMailMigrations` now refuses to apply a migration whose ordinal is lower
than the highest already applied, because applying an older definition over a
newer one is not a repair. Migration ids are parsed for a three-digit ordinal
and a malformed id fails loudly rather than sorting arbitrarily.

Proven on a database of its own: migrations apply from empty (the positive
control), re-running is a no-op, deleting an old row and re-running is refused
with 033's hardened definition still live, the refusal is general rather than
specific to one migration, and **re-applying the HIGHEST migration is still
allowed** — otherwise an ordinary re-run after an interrupted deploy would be
impossible.

- **Disposition:** `CLOSED`. Falsified: disabling the ordering check turns the
  suite red.

---

## W1BR-016 — CLOSED

`POST /executive/inbound/draft` is the inbound route that enters the chain:

```
request -> authenticated principal -> authorized workspace -> memory actor
        -> alias registry -> canonical identity -> authoritative record
        -> EA pipeline -> draft for review
```

Proven against a LISTENING SERVER over real HTTP, with the memory service
composed by the same function `src/server.ts` calls at boot. Not a direct call
to `runEaPipeline` — that was the previous state and it is what "reachable only
from a test" meant.

Refusals, each proven: no credentials → 401; a bad token → 401; **a workspace
the principal does not belong to → 403**, because the store scopes on workspace
and a route that accepted the caller's claim would read another workspace's
memory with a perfectly valid session; a malformed body → 400 before anything
is read.

The route SENDS NOTHING. It returns a draft as a proposal; there is no send
path and no approval on it. Turning a draft into an outbound message is W1.6
authority work behind its own gate, and a test asserts the response carries no
send, approval or delivery field.

`src/server.ts` mounts it only when a CEO profile and at least one model
provider credential are already present in the environment — **no credentials
are created** — and prints why it is not mounted otherwise. A route mounted
without a provider would answer every message `degraded`, and one mounted
without a profile would draft in nobody's voice; both look like a working
endpoint, which is worse than a 404.

- **Disposition:** `CLOSED`.

---

## W1BR-017 — The trusted-memory principal is mapped to the user

- **Gate:** W1.3 · **Source:** HTTP reachability wiring · **Severity:** LOW
  (modelling, disclosed)

Trusted memory scopes on four dimensions: tenant, workspace, principal, user.
An authenticated `Principal` carries three — there is no `principalId` anywhere
in Core outside the memory layer.

`memoryActorFor` maps `principalId` to the authenticated user's own id: in
Wave 1 the human acts as their own memory principal. This is a DEPLOYMENT FACT,
not a weakening — the store still compares all four dimensions independently
and every control over them is unchanged; both simply carry the same value.

Raised rather than decided quietly: a distinct assistant principal acting on a
user's behalf is not modelled anywhere, and inventing a namespace for one
inside an HTTP handler is the kind of identity decision that should not be made
in an HTTP handler.

- **Disposition:** `OPEN` (residual, disclosed, no control weakened)
- **Closure path:** model the assistant principal explicitly when an agent
  acts on a user's behalf rather than as them — W1.6 authority surface.

---

## ENGINEERING DOCTRINE — WORKTREE SEPARATION

Adopted after two incidents in one session, both self-inflicted, both
recovered: `git checkout -- <file>` during mutation testing reverted a file to
HEAD and destroyed uncommitted implementation — once for `merge_identity` /
`split_identity`, once for the W1BR-014 migration-order guard. Writing the
lesson into a commit message did not prevent the repeat, because the failure is
one of ORDERING, not of intent.

An earlier incident is the same class: two reviewers were dispatched into the
worktree and database the builder was actively committing to, and both flagged
that the candidate moved under them mid-review.

```text
BUILDER WORKTREE
  Never used for destructive mutation experiments.
  Implement -> verify green -> COMMIT -> only then mutate.

MUTATION WORKTREE
  Disposable. Detached at the exact candidate SHA. Own database.
  May be destroyed freely; nothing of value lives here.

REVIEW WORKTREE
  Immutable for the duration of the review. One reviewer.
  Own database. No concurrent writer, including the builder.
```

A reviewer's guarantee is "the candidate was immovable while I judged it", not
"the evidence happened to survive". A mutation sweep's guarantee is "the only
thing I destroyed was disposable".

Applies to Aaliyah beyond W1.3.

---

## W1.3 CANDIDATE FREEZE

The candidate below is frozen for adjudication. No feature work, no polish, no
W1.4 surface is added to it. Remediation of any reviewer finding produces a
DESCENDANT SHA, and every applicable reviewer re-inspects that new subject —
a candidate does not become GREEN because six reviewers passed while one found
a real Critical or Important defect.
