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

---

## W1.3 REMEDIATION OF b3efc82 — SESSION 3

`b3efc82` was independently BLOCKED (Security, Reliability, Red Team BLOCK;
Test Falsifiability and Mutation NOT_VERIFIED; Integration GREEN with three
non-blocking findings). It is preserved unmodified, tagged
`w13-candidate-b3efc82-BLOCKED`. The six reviewer reports are preserved
verbatim, with SHA-256 sums, outside the repository at
`aaliyah-w13-evidence/b3efc82/reviews/`.

Every entry below was produced by the implementer. Per this register's rule,
none is CLOSED here: each is **REMEDIATED — PENDING INDEPENDENT VERIFICATION**
against the next frozen candidate, and each names the control, the regression
tests, and the mutation evidence gathered in a disposable worktree against a
fresh database.

| Entry | Finding (reviewer, severity) | Remediation | Proven by |
| --- | --- | --- | --- |
| W1BR-018 | Suite hangs rather than fails; 20 mutants with no verdict (Mutation, gate-blocking) | `b094151` — `npm test` is `scripts/test-watchdog.mjs`: per-test/per-file timeout, whole-run deadline, process-group kill, suite-wide `statement_timeout`/`lock_timeout`/`idle_in_transaction_session_timeout`, hook sentinel, strict accounting; root cause (`pool.end()` awaiting an unreleased client in M-3) fixed | 19 watchdog attack tests; P1 sweep 17/21 killed, 4 disclosed (2 redundant accounting checks, 1 masked lock bound, 1 unreachable grace path); A09 — the original hang — KILLED in 35s, and in 74s with the M-3 fix reverted |
| W1BR-019 | No pool `'error'` listener: an idle-connection blip kills the process (Reliability, CRITICAL) | `2285e8b` — `guardPoolErrors` on the mail and idempotency pools | child-process probe: bare pool dies (positive control), guarded pools survive 57P01 and serve; C2 mutants killed |
| W1BR-020 | No statement/lock/connection bound anywhere (Reliability, HIGH) | `2285e8b` — pool startup bounds; transaction-local `lock_timeout` in both stores and the reconciler (`record_busy`); explicit migration bounds; `/ready` probes the read pool | R-1, R-2, pool bound read back from the server, readiness; C2 mutants killed, alias-store bound killed after `aa5f424` |
| W1BR-015 (REOPENED) | Recorded CLOSED; a merge cycle was reachable on the primary (Red Team BREAK 2, HIGH) | `eb123f3` — store locks both endpoints in sorted order; migration 043 locks both endpoints in the edge guard and the record in the freeze trigger | S-1, S-3, S-7 (driven interleavings, not sampled); C3 mutants killed |
| W1BR-021 | Merge racing delete merged into a destroyed record; resolution answered "no memory" (Red Team BREAK 3, HIGH) | `eb123f3` — same serialization; counterparty head must be ACTIVE (043); a redirect to an unretrievable survivor throws instead of returning null | S-2, S-4, S-5, S-6; C3 mutants killed |
| W1BR-022 | Identity edge scope never bound to its authorization (Security, HIGH, introduced) | `08228c3` — migration 044: every mutated table's row must carry its authorization's (tenant, workspace, principal, user); an edge may only leave a record its owner holds. Also closed the wider gap: versions after genesis were bound by continuity only | C4-1 (PoC B), C4-2 (PoC A + mirror), C4-3, C4-5/6 one dimension at a time, C4-A alias binding and retirement; C4 mutants killed per table and per dimension |
| W1BR-011 (WIDENED, REMEDIATED) | The `create` audit path was also a receipt-id squatting primitive (Red Team BREAK 1, HIGH) | `b5892b8` — see W1BR-023 | N-2 |
| W1BR-023 | A committed, read-back-verified mutation filed as ABORTED/UNKNOWN; reconciler barred forever (Red Team BREAK 1, HIGH) | `b5892b8` — migration 045: attempts in their own append-only table; ABORTED refused in receipts; a receipt id on record is spent; terminal must match pending; receipts bound to authorization scope | N-1 (the ordinary retry now verifies), N-2..N-6; C5 mutants killed; alias store routing and reuse killed after `aa5f424`. `findUnresolved`'s predicate is structurally masked by the ABORTED refusal — disclosed |
| W1BR-024 | Reconciler role could file COMMITTED with no record version (Security, MEDIUM) and verdicts derived from a caller-supplied authorization (Red Team M2) | `b5892b8` — migration 045 derives every verdict in the database; `reconcile()` reads the stored unknown receipt | V-1..V-4; C5 mutants killed |
| W1BR-025 | 14 unique constraints droppable with the suite green, including the CAS index (Mutation, CRITICAL) | `a9b6ec7` — uniqueness destroyers from real rows, one index at a time, with positive controls | U-1..U-5; every targeted index killed by drop. Two indexes structurally redundant (a superset of another unique key), premise pinned |
| W1BR-026 | Four identity-edge payload bindings vacuous against NULL (Red Team M4) | `a9b6ec7` — migration 046 | absent and null member refused per binding |
| W1BR-027 | Subject erasure left the email address in cleartext, indestructible (Red Team BREAK 4, HIGH) | `6188c7e` — the alias PII vault (migration 047, `src/crypto/memoryPiiKeys.ts`), under the founder's locked erasure decision | P-1..P-19 against real flows; provider unit attacks; see W1BR-008 below |
| W1BR-029 | CHECKs outside the original 81 were never reachable by any test (Red Team M3; measured by the P6 sweep) | `7825b89` — `assertCheckConstraintsKill` from real rows for identity edges, legal holds and children, retention, mutation receipts, reconciliations, alias policy and protected domains; migration 049 re-creates the vacuous reconciliation evidence bindings | C8; P6 |
| W1BR-030 | P6 survivors: loose privilege matchers, owner-only privilege tests, untested legal-hold FKs, unconfirmed key destruction, index/binding mismatch, 047 over plaintext, index-less binding commit, two exact-number triggers | `dcc4a5d` — C9 | re-run at `dcc4a5d`: 18/18 KILLED |
| W1BR-028 | `pg_temp` searched first by every guard's search_path (found by the implementer while building the Priority 6 matrix; not exploitable at `6188c7e` because every relation reference was qualified) | `1cff471` — migration 048 | T-1 pins every function; T-2 attacks with a forged temp receipt |

Mediums also remediated: `/ready` ignored the read pool (Integration); the
`postStateAgrees` unreachable conjuncts are disclosed beside the code; the
nonce/receipt target conjunct (A14) has a killing test; loose error regexes are
pinned to exact messages.

---

## W1BR-008 — RE-EVALUATED, DIMENSION BY DIMENSION

The previous founder question was aimed at the wrong residual (red team): the
larger one was that the address itself could not be erased. With the alias
vault built, the seven things W1BR-008 had been conflating are dispositioned
separately. No single primitive is claimed to settle more than one of them.

| | Dimension | Disposition | Basis |
| --- | --- | --- | --- |
| A | Content integrity | **BOUNDED_AND_PROVEN_NONBLOCKING** | The chain is an unkeyed canonical digest. Against every non-superuser writer it is enforced by the database — witnesses, continuity, genesis and scope binding (039, 044), uniqueness (W1BR-025). Against a superuser, AUTHENTICITY is NOT PROVEN: that needs a keyed signature under production key management, which is not provisioned. |
| B | Content confidentiality | **BOUNDED_AND_PROVEN_NONBLOCKING** | Record content is not application-encrypted. Reads are scoped on four dimensions and proven; erasure nulls content (037) and the database refuses a half-erased chain. Encryption at rest is an infrastructure property and is NOT PROVEN here. |
| C | Offline confirmation / oracle resistance | **ALIASES: PROPOSED CLOSED (local). RECORD CONTENT: BOUNDED_AND_PROVEN_NONBLOCKING.** | Aliases: the authorization digest covers a KEYED commitment (P-16), lookup is keyed (P-3), and no unkeyed hash of an alias is stored anywhere. Record content: the unkeyed `content_digest` remains, in several copies (versions, receipts, predecessor links — red team M1), so a party with STORED-STATE access and a guess can still confirm erased low-entropy CONTENT. Not reachable through the store (four-dimension scoping). Closing it is the coordinated keyed-digest migration across both repositories. Recorded as the one remaining erasure-adjacent residual, not hidden inside the alias closure. |
| D | Alias confidentiality | **PROPOSED CLOSED for the local architecture** | No plaintext alias column exists (047); the payload may not carry the alias; AES-256-GCM envelope under a per-binding key with scope-binding associated data; the address appears in no text or jsonb column of any table, before or after erasure (P-1). |
| E | Alias lookup | **PROPOSED CLOSED for the local architecture** | HMAC-SHA256 blind index, per tenant/scope/purpose/version, domain-separated; not a raw hash (unit); rotation keeps old and new versions findable and colliding (P-17); a match that does not decrypt to the requested address is refused. |
| F | Alias erasure | **PROPOSED CLOSED for the local architecture; production key management NOT PROVEN** | Deletion erases every binding naming the participant in the same transaction; the database refuses a tombstone that leaves one (P-8) and an erasure without a tombstone (P-9); keys are destroyed and confirmed; a ciphertext copy dies (P-2); holds and retention refuse and nothing is reported erased (P-4, P-5); crash and outage are recoverable and never reported complete (P-6, P-7); restore, replay and races do not resurrect (P-11, P-12, P-18). |
| G | Audit evidence | **PROPOSED CLOSED, with one bounded residual** | Non-PII evidence survives: tombstone, `memory_pii_key_erasures` (committed and destroyed, append-only), attempts, receipts, reconciliations — none holds the address (P-1). Residual, BOUNDED: the tombstone's `destroyedFieldNames` retains the erased content's FIELD NAMES (red team M1) — names, never values. |

Production KMS/HSM: **NOT PROVEN.** No production PII key provider is
provisioned; `src/server.ts` states the vault as not configured, and the alias
registry neither stores nor resolves an alias there. Nothing here is a claim of
GDPR, CCPA or other legal compliance: these are engineering controls, and
whether they satisfy a regulation is not decided by this code.

## W1BR-014 AND W1BR-016 — REVERIFIED, NOT REBUILT

Both CLOSED entries were re-tested after remediation: their suites run in every
full-suite pass, and the Priority 6 sweep mutates each control (the migration
ordinal guard; the route's memory dependency) against a fresh database.

## THE W1.3 RESIDUALS STILL MARKED OPEN — EXPLICIT GATE DISPOSITION

This register says a gate may not be GREEN while an entry bound to it is OPEN.
Five W1.3 entries were recorded "OPEN (residual, disclosed)", which is
ambiguous against that rule. Each is dispositioned explicitly here, for the
independent gate to confirm or reject. None is claimed CLOSED.

| Entry | Proposed disposition | Why it does not block W1.3 as scoped |
| --- | --- | --- |
| W1BR-006 fractional numeric digest collision | BOUNDED_AND_PROVEN_NONBLOCKING | The collision needs a stored decimal JavaScript cannot represent exactly. Every memory table with a digested jsonb payload carries the exact-numeric trigger — record versions, authorization receipts, mutation receipts, tombstones, alias bindings, identity edges and attempts — so no writer can place one (tests per table, incl. U-1 for mutation receipts). |
| W1BR-007 the mutation role can burn a pending approval | BOUNDED_AND_PROVEN_NONBLOCKING | Denial of service against one approval, not forgery: a burned nonce cannot become a version, a committed outcome or an edge (034, 038, 044, 045), and the burn is permanent and attributable. Closure (a reservation or second factor) changes the transaction shape and is recorded, not attempted. |
| W1BR-010 `create` as a record-id existence oracle | BOUNDED_AND_PROVEN_NONBLOCKING | No content, digest or owner leaks; nothing is mutated; the equivalent oracle already exists on `correct`. |
| W1BR-011 unresolved attempts as an unbounded durable write | BOUNDED_AND_PROVEN_NONBLOCKING (DoS side); squatting side REMEDIATED (W1BR-023) | Attempts are filed under the authenticated actor and cannot be forged onto another party; they can no longer collide with a real mutation. The ceiling belongs to an upstream per-actor rate limit. |
| W1BR-017 memory principal mapped to the user | BOUNDED_AND_PROVEN_NONBLOCKING | A modelling fact of Wave 1, not a weakened control: all four dimensions are still compared independently in the store and bound in the database (034, 039, 044). |

W1BR-001..005 are W1.6 gate entries and are unchanged.

## PRIORITY 6 — THE HOSTILE DATABASE MATRIX

Generated from the LIVE catalog, not from a list of what the implementer
remembered: every CHECK (151), trigger (50), unique index (28) and foreign key
(4) on the memory tables; `RESET search_path` on every aaliyah_* function (37);
fifteen grant widenings across the mutator, reader and reconciler roles
(including role membership); and source mutants for the alias vault, the
W1BR-014 ordinal guard, the W1BR-016 route's memory dependency and migration
048. Each mutant ran against a freshly migrated database in a disposable
worktree, through the watchdog.

At `7825b89`: 301 mutants, 273 KILLED, 28 SURVIVED, 0 invalid, 0 without a
verdict. Survivors were classified and the 18 reachable ones closed by C9
(`dcc4a5d`); re-run at `dcc4a5d`: those 18 KILLED, 10 survive, all disclosed:

| Survivor | Disposition | Proof |
| --- | --- | --- |
| `_payload_object` on record versions, authorization receipts, tombstones, alias bindings, identity edges, legal holds, mutation receipts, attempts; `_evidence_object` on reconciliations (9) | MASKED BACKSTOP | Every binding CHECK on the table sorts earlier by name and also fails on a non-object value (`->>` is NULL), so the backstop cannot be the reported violation. The property is proven per table: a non-object value is refused by a CHECK of that table. |
| `memory_authorization_receipts_tenant_id_workspace_id_author_key` (1) | STRUCTURALLY REDUNDANT | A duplicate on (tenant, workspace, authorization) is a duplicate on authorization, refused first by the unique global id; premise pinned in U-1. |

The sweep also surfaced two defects of the M4 class, both closed: vacuous
reconciliation evidence bindings (migration 049, C8) and the implementer-found
`pg_temp` search order (migration 048, W1BR-028).

Critical surviving behavioural mutants: **0.**

---

## W1.3 REMEDIATION OF 2b2e554 — SESSION 3, SECOND HOSTILE CHAIN

`2b2e554` was independently BLOCKED. Integration and Security were GREEN.
Test Falsifiability, Reliability and Red Team returned BLOCK. It is preserved
unmodified. The five reports and the red team's reproducers are kept verbatim
outside the repository, at `aaliyah-w13-evidence/2b2e554/reviews/` and
`redteam-repro/`.

Two dispositions recorded above were falsified by that chain, and are
corrected here rather than left to read as they did:

- **W1BR-019 was HALF-fixed.** It covered idle clients only. A backend lost
  while a client was checked out still killed the process.
- **W1BR-008 F ("alias erasure, proposed closed")** did not hold across a
  merge.

As before, every entry is **REMEDIATED — PENDING INDEPENDENT VERIFICATION**.

| Entry | Finding (reviewer, severity) | Remediation | Proven by |
| --- | --- | --- | --- |
| W1BR-031 | A backend terminated while a client is CHECKED OUT crashes the process through the store's own `ROLLBACK ... .catch()`; pg-pool detaches its listener at checkout (Reliability, CRITICAL) | `356eb2b` — every guarded pool attaches a permanent client listener on `'connect'` | Probe: an unguarded pool dies (positive control); guarded mail and idempotency pools survive 57P01 mid-transaction, clean up and serve. RED before the fix. |
| W1BR-032 | After P merged into S, erasing S reported verified with nothing erased, and P (frozen) could never be erased (Red Team BREAK A, HIGH) | `df046c3` — migration 051: the freeze admits exactly one further version on an absorbed record, a `subject_erasure_request` deletion; a subject-erasure tombstone is refused while any record merged into its target, transitively, is unerased; the store refuses first as `merged_records_not_erased`. No cascade: ONE AUTHORIZATION → ONE MUTATION holds. | X-1..X-5 (X-5 blinds the store's check with a shadow schema) |
| W1BR-033 | The binding guard never checked what the witnessing authorization was for: a spent `correct` authorization witnessed a binding for an erased participant (Red Team BREAK C, HIGH) | `df046c3` — migration 050: a binding needs a spent `assign_alias` for its own participant plus that mutation's participant version; a retirement needs the same of `remove_alias` | K-1..K-5 (K-5 is RT2-H1 in shape) |
| W1BR-034 | A correct alias mutation whose read-back failed could only be reconciled `COMMITTED_DIVERGED`, permanently (Red Team BREAK B, HIGH) | `83f7d2b` — migration 052: for alias actions the verdict is derived from the authorized head being extended by the authorization's own version and the alias effect being on record; the reconciler mirrors it through a SECURITY DEFINER function and is not granted the binding table | Q-1 (RT2-R1), Q-2, Q-3, Q-4. **Disclosed limit:** the keyed assignment digest cannot be recomputed inside PostgreSQL (keys live outside it). That the content matched it was verified inside the committing transaction. |
| W1BR-035 | `reconcile()`'s principal/user comparison had no discriminating test (Test Falsifiability, MEDIUM) | `83f7d2b` — V-5 | one dimension at a time, with a positive control |
| W1BR-036 | The mutation role can record `key_destroyed` for a live key, and completion never re-examined it (Red Team M2) | `68328f9` — the completion pass asks the provider about evidenced keys too, and destroys contradicted ones | K-6 (RT2-K1), and the tombstone match of the evidence guard (BM4). **Residual, bounded:** the forged evidence row itself remains representable; the database cannot see a key outside it. |
| W1BR-037 | 17 legitimate merges make every identity on the chain unresolvable; the resolver also refused exactly 16 (Red Team M3) | `68328f9` — migration 053 bounds a chain at 16 hops (serialized by the absorbed record's own lock, 043: a chain grows only at its canonical end); store refuses first as `identity_chain_too_deep`; the resolver walks MAX + 1 | D-1, D-2 |
| W1BR-038 | `NODE_OPTIONS` could deselect tests while the watchdog still said PASS (Red Team M1) | `68328f9` — dropped for the child, recorded in the evidence | watchdog self-test on a two-test fixture with one failing |
| W1BR-039 | Branch-level mutants of the receipt-id discipline survived (Red Team L2: BM1 action, BM8 target) | `68328f9` — N-5b | one dimension at a time |

### Dispositioned, not remediated

These are stated as dispositions, not as fixes.

- **Red Team BM2 (user comparison in the receipt-id discipline) and BM3 (key-erasure guard): MASKED.**
  - BM2: a terminal receipt that differs only in user is refused by the later `zz_` scope binding.
  - BM3: the `pii_present_or_erased` CHECK refuses the row first.
- **Red Team L1: BOUNDED_AND_PROVEN_NONBLOCKING.**
  - What happens: `carriesPlaintext` matches substrings, so an address split across two content strings is stored in the record's clear content.
  - Why it is bounded: record content is operator-authorized, and deletion erases it. Since W1BR-032, that includes an absorbed record.
  - Remaining risk: record content is not application-encrypted (W1BR-008 B).
- **Red Team L3: BOUNDED_AND_PROVEN_NONBLOCKING.**
  - What happens: the mutation role can write an attempt row under any tenant.
  - Why it is bounded: attempts are rejections and carry no authority. No verdict, reconciliation or mutation reads them as proof.
- **Integration MEDIUM, migration 047 across a rolling deploy or rollback: DISCLOSED.**
  - What happens: `b3efc82`-era code reads columns that 047 drops, so the two cannot share a database.
  - Rule: a release containing 047 must be a full-stop deploy, and so must any later column-dropping migration.
  - This candidate's first deploy starts from an empty database under one code version.
- **Reliability LOW:**
  - Six test-only read-back pools replaced the watchdog's PostgreSQL bounds. They now keep them.
  - The boot-time reconcile pass handles up to 100 mutations sequentially, each individually bounded. This is bounded but slow, and NOT tested at that scale.
- **Reliability NOT_VERIFIED:**
  - fd/memory exhaustion;
  - restart recovery against an out-of-process KMS. None is provisioned.
- **Test Falsifiability / Security, flakiness under load:**
  - One full-suite run failed in `wave1MigrationReplayPostgres` and passed 4/4 in isolation.
  - The watchdog's positive control misjudged a pass under load. It now runs with relaxed bounds.
  - Both errors run toward FAIL, never toward PASS.
- **Red Team, watchdog limit: DISCLOSED.**
  - What happens: a test file that registers tests after a promise that never settles, with no live handle, reports only the tests it registered.
  - Why this is a limit, not a fix: the watchdog cannot know tests it was never told about. A hostile test author has simpler ways to write a vacuous test.

### The confirming sweep at `f59a6f7`, and its survivors

This sweep ran before any review of `f59a6f7`, on 350 mutants:
- the live catalog: 279 controls;
- 19 grant mutants;
- 28 source mutants that revert each remediation above;
- the earlier vault, route and migration mutants;
- the red team's branch mutants;
- the test reviewer's CAS mutant.

It ran on eight disposable workers, each with its own database, with every mutant reached from both ends of the list. That makes most verdicts independent duplicates.

Real survivors, each closed with a falsifier that carries both a negative and a positive control:

| Entry | Survivor | Closed by |
| --- | --- | --- |
| W1BR-040 | `FX-04`: migration 051's live-head check was masked by its binding check. X-1 always bound an alias. | `14df48d` — X-1b: a merged record with content and no alias |
| W1BR-041 | `FX-16` / `FX-17` / `FX-20`: the alias head comparison. Q-4 moved version and digest together, so each check masked the other. | `ca28da8` — Q-5: content goes back to its authorized value (ABA), so only the version differs. Q-6: the right version with the wrong digest. |
| W1BR-042 | `G-19`: the alias-effect oracle granted to PUBLIC went unobserved. | `952e04e` — Q-7: each of the three new helpers runs only for its own role, and every other memory role is refused by privilege. |

Disclosed survivors, unchanged from earlier sweeps, each with proof:
- the nine `_payload_object` / `_evidence_object` masked backstops;
- the structurally redundant unique index on authorization receipts `(tenant, workspace, authorization)`.

**Load-induced verdicts.** With eight workers sharing one machine, a kill is not trusted from its verdict alone. One disclosed backstop was "killed" on one worker by unrelated HTTP-reachability failures from CPU starvation, and survived on another. Every kill backed only by a timeout, cancellation, deadline, hook-sentinel failure or mass failure is re-run on a quiet machine against the frozen descendant before it counts. The re-run evidence sits beside the sweep at `aaliyah-w13-evidence/`.

---

## W1.3 THIRD HOSTILE CHAIN — `3ba769f`

Five reviewers ran on the same SHA, each with its own worktree and database. Their reports are at `aaliyah-w13-evidence/3ba769f/reviews/`.

| Reviewer | Verdict | Blocking findings |
| --- | --- | --- |
| Test Falsifiability | TEST_TRUTH_GREEN | none |
| Security | SECURITY_GREEN | none |
| Red Team | GREEN | none |
| Reliability | NOT_VERIFIED | none |
| Integration | NOT_VERIFIED | none |

- **Test Falsifiability:** three clean full runs of 1001/1001. 12 database and 8 source mutants of its own, all killed. 5 hostile watchdog fixture classes, none PASS.
- **Security:** 050–053, the vault, `pg_temp`, and HTTP were re-attacked under least-privilege roles, including RT2-H1 and RT2-K1.
- **Red Team:**
  - Breaks A/B/C and M1–M3 could not be reopened.
  - F1 (MEDIUM): `TS_NODE_*` bypass.
  - F2 (LOW): completion-pass starvation.
- **Reliability:**
  - W1BR-031 held through a real store `delete()` terminated while blocked on a lock.
  - A 16-hop race held.
  - MEDIUM: audit starvation by a pending backlog.
  - Gaps: boot end-to-end, and resource exhaustion.
- **Integration:**
  - No regression. `piiKeys: null` wiring was proven over live HTTP.
  - Gap: 050–053 over a database populated at 049.
  - MEDIUM, reasoned: DDL state left behind by a SIGKILLed test.

The confirming sweep's duplicate verdicts also surfaced two real survivors, G-13 and G-16. `3ba769f` is therefore superseded, and none of its GREENs carries forward.

| Entry | Finding | Remediation | Proven by |
| --- | --- | --- | --- |
| W1BR-043 | G-13, G-16: privilege widenings unobserved (sweep, duplicate verdicts) | `aca256d`: an exact, declared privilege map of every memory role — tables, columns, sequences, functions, memberships — with the boundaries the register relies on asserted by name | `wave1MemoryPrivilegesPostgres`, including a positive control that a widened grant is reported |
| W1BR-044 | Red Team F1: inherited `TS_NODE_PROJECT` preloads code into every worker; a failing fixture was PASS | `aca256d`: the watchdog drops and records every `TS_NODE_*` | the red team's preload as a fixture, with a positive control that it is hostile |
| W1BR-045 | Red Team F2 and Reliability MEDIUM: the evidenced-key audit shared the batch limit, so it could be starved from either side | `aca256d`: evidenced keys are audited on every pass, outside the limit | K-7 (settled rows ahead), K-8 (pending backlog ahead), at limit 1. Cost: one provider state call per evidenced key per pass; disclosed. |
| W1BR-046 | Reliability gap: boot recovery against a wedged database was verified only through primitives | `aca256d`: the real service, built as `server.ts` builds it | refused with 55P03 within the bound; completes once the wedge is lifted |

**Still open — these block GREEN, not dispositioned:**
- **INTEGRATION: migrations 050–053 over a database populated at 049.** No test builds rows at 049 and then performs honest operations after the upgrade: retiring a pre-050 binding, reconciling a pre-052 UNKNOWN alias mutation, subject-erasing a pre-051 merged participant, merging on a chain that predates 053. All four new guards are forward-only `AFTER` triggers, so no break is *expected*, but expectation is not proof. This needs `runMailMigrations` to stop at a named migration, plus store fixtures on a separate database.
- **INTEGRATION MEDIUM (reasoned): DDL state left behind by a SIGKILLed test.** A test killed while it has a trigger disabled or a shadow schema created leaves that state for the next run against the same database. Mitigation today: CI and every reviewer run against a fresh database. There is no structural defense.
- **RELIABILITY NOT_VERIFIED:** fd and memory exhaustion.
- **SECURITY, theoretical (not executed):** a survivor's subject erasure checks the absorbed record's bindings for `pii_erased_at`. After a provider outage during the absorbed record's erasure, that binding is erased while its key is pending, so the survivor may report verified before the absorbed key is destroyed. The absorbed record's own erasure reported `erasure_incomplete`, and completion converges.
- **Process:** the implementer ran `git checkout -- src/persistence/postgres/migrations.ts` in the implementation worktree to revert its own uncommitted, never-committed `through` option. No other change was in that file, and no work was lost. This still violates the worktree doctrine, and it is recorded here.

**Freeze of `3569122`: FAIL, 1007/1008.** The new privilege test's positive control changed a GRANT on a shared table without the suite's shared memory-table lock, and collided with another file's catalog change ("tuple concurrently updated"). This was a defect in the test, not load. The descendant takes the lock for that control. At `3569122` all 22 targeted mutants were KILLED: G-01..G-19 by the privilege map alone, plus H-01 (audit under the batch limit), H-02 (audit removed) and H-03 (TS_NODE_* inherited).

**Freeze of `94daf48`: FAIL, 1007/1008.**
- **Failure:** `decision-engine.test.ts` "execution remains unsuccessful until independent read-back verifies it", with `postcondition_verification_receipt_from_future`. The same test failed in the first `3ba769f` attempt.
- **Why:** the test read `nowMs` and then had the verifier stamp `verifiedAt` with a fresh clock reading. Whenever the millisecond ticked between the two, the receipt was correctly refused as 1 ms in the future.
- **Nature:** a pre-existing time race in a W1.1 test, not W1.3 code and not clock skew. Skew during that run was 10–19 ms.
- **Fix:** the descendant derives both timestamps from one reading, with the receipt one second old. The contract check is unchanged.
- **Other gates:** release guards PASS; 22/22 targeted mutants KILLED at `94daf48`.

| Entry | Finding | Remediation | Proven by |
| --- | --- | --- | --- |
| W1BR-047 | Integration (3ba769f): migrations 050–053 were never applied over a database populated at 049 | `runMailMigrations(pool, { through })` stops after a named migration; an unknown name is refused before anything is applied. `wave1MemoryUpgradePostgres` runs on its own database and uses the current stores throughout. | U-0: writes rows at 049 and asserts no 050–053 object exists. U-1: upgrades, asserts the three triggers and three helpers exist, and nothing already there is refused. U-2: retires a binding made before 050. U-3: reconciles an alias mutation left UNKNOWN before 052 to COMMITTED_CONFIRMED. U-4: subject-erases a participant bound before the upgrade (envelope, key and index gone). U-5: an unknown target is refused. |

**Remaining limit of W1BR-047: DISCLOSED.** A merge chain that predates 053 is not built.
- The current store's merge path calls the 053 helper, so this code cannot merge at 049.
- A chain created by *older* code before 053 is therefore not exercised.
- 053's guard measures chains only when a new merge edge is inserted, so a pre-existing chain longer than 16 hops is not rewritten. Every further merge onto it is refused, and its identities stay unresolvable by the resolver. This can only arise if older code ran merges past 16 hops.
- This candidate's first deploy starts from an empty database, so no such chain exists.

---

## W1.3 FOURTH HOSTILE CHAIN — `03581a3`

Reports are at `aaliyah-w13-evidence/03581a3/reviews/`.

| Reviewer | Verdict |
| --- | --- |
| Security | **BLOCK**: F1 HIGH, executed |
| Red Team | **BLOCK**: same break, rated MEDIUM, executed |
| Integration | GREEN, bounded |
| Test Falsifiability | recorded when it completes |
| Reliability | recorded when it completes |

**Security F1 / Red Team C5.** The pending-key window across a merge, listed above as theoretical and still open, is REAL.
- **What happened:** after a provider outage during the absorbed record's erasure, the survivor's subject erasure reported verified. The absorbed subject's data key was still live, so a ciphertext copy taken before erasure decrypted to the full address.
- **Transitive case:** the same held through an intermediate record (ATK-C2).
- **Recovery:** the window lasted until a completion pass ran, which happens at boot.

| Entry | Finding | Remediation | Proven by |
| --- | --- | --- | --- |
| W1BR-048 | Security F1 (HIGH) / Red Team C5: a survivor's erasure verified over a merged-in live key | Migration 054: `aaliyah_memory_unerased_merged_records` counts a merged-in binding with `erasure_committed` and no `key_destroyed` as unerased, so the store's pre-check and the tombstone trigger both refuse. The store also asks the provider about every merged-in data key, since the evidence row is writable by the mutation role. | X-6 (ATK-C1: refused, nonce unconsumed, key live; completion then lets the survivor erase and the copy is dead). X-7 (forged `key_destroyed` still refused, because the provider is asked). X-8 (store pre-check blinded and provider lying: the database refuses). All three RED before the fix. |
| W1BR-049 | Security F2 (MEDIUM): the evidenced audit filtered on this provider's id, so another provider's forged evidence vanished from the pending count | Every provider's evidence is selected; a key this store cannot ask about stays pending | K-9 (pending stays 1 after forgery; the owning provider destroys it) |

**Dispositioned, not remediated, at this descendant:**
- **Security F3 (MEDIUM): the privilege map does not close the whole class.** Grants to PUBLIC, grant options, schema CREATE, role attributes, and SECURITY DEFINER functions not named `aaliyah_*` are outside the map. None exists at this SHA (reviewer's live catalog survey). **OPEN**: extend the map.
- **Security F4 (LOW):**
  - PUBLIC can execute the SECURITY DEFINER `aaliyah_memory_restricting_hold`, which answers whether a named participant is held, and the hold id.
  - `aaliyah_memory_spent_nonce` is also PUBLIC.
  - **OPEN**: revoke PUBLIC, and confirm trigger-internal calls still resolve.
- **Security F5 (LOW):** the reconciler has SELECT on blind indexes and key-erasure rows it does not read, and the issuer and revoker read bindings. **OPEN**: least-privilege trim.
- **Security F6 (LOW): audit cost grows with erasure history.** DISCLOSED.
- **Red Team C1: TCB boundary.** An attacker who owns the watchdog process can forge PASS, via its own NODE_OPTIONS preload, GIT_DIR, or a gitignored node_modules shim. That is outside what an in-process verdict can defend. DISCLOSED; not a claim this repository makes.
- **Integration LOW:** both `ABORT_REASON` maps are typed `Record<string, …>`, so exhaustiveness is not compile-checked. **OPEN.**

**Test Falsifiability of `03581a3`: BLOCK.**
- **Five surviving mutants.** The privilege map missed a table grant to PUBLIC, `INSERT` on tombstones to PUBLIC, a column grant to PUBLIC, schema `CREATE`, and a default privilege. This is Security F3, now shown by survivors.
- **One surviving source mutant: the evidenced-audit provider filter.** It is removed at `7f10e19`, so the finding is moot there.
- **Discrimination proof:** no independent mutation-fuzz proof exists at that SHA.

| Entry | Finding | Remediation | Proven by |
| --- | --- | --- | --- |
| W1BR-050 | Test Falsifiability BLOCK and Security F3: the privilege map was blind to PUBLIC, grant options, schemas, default privileges, role attributes, and SECURITY DEFINER functions of other names | The map is read from the ACLs themselves (`aclexplode` over `pg_class`, `pg_attribute`, `pg_namespace`, `pg_proc`, `pg_default_acl`). PUBLIC is an entry, and grant options are marked. New sections: `schemas`, `defaultPrivileges`, `securityDefiner`, `roleAttributes`. Named assertions: no PUBLIC table/column/sequence privilege, no grant option anywhere, schema `public` is PUBLIC USAGE only, no default privileges, no dangerous role attribute, every SECURITY DEFINER function is `aaliyah_*`. | A positive control for each of the seven widenings the reviews used: applied, reported by name, reverted, map restored |

**Freeze of `7f10e19`: superseded before review.**
- Suite passed twice, 1018/1018. Release guards PASS. 26/27 targeted mutants KILLED.
- The one survivor, M54-03, was MIS-SPECIFIED: it filtered on the literal `local-test/v1`, which K-9's rows carry anyway. The regression it meant to model is a filter on the store's OWN provider id, and that corrected mutant is run at the next freeze.

---

## W1.3 FIFTH HOSTILE CHAIN — `8a0bf05`, AND THE REMEDIATION AFTER IT

Reports are at `aaliyah-w13-evidence/8a0bf05/reviews/`. Findings that landed
after the candidate was frozen were held outside the repository so the SHA
under review was not changed while reviewers judged it
(`aaliyah-w13-evidence/8a0bf05/OPEN-FINDINGS-INHERITED.md`); they are all here
now.

| Reviewer | Verdict at `8a0bf05` |
| --- | --- |
| Test Falsifiability | TEST_TRUTH_GREEN (and: no independent mutation-fuzz proof at that SHA) |
| Security | SECURITY_GREEN, scoped — one MEDIUM, three LOW |
| Reliability | **RELIABILITY_RED** — one CRITICAL, one HIGH |
| Red Team | **BLOCK** — one HIGH, one MEDIUM, plus register hygiene |
| Integration Marshal | **BLOCK** — one CRITICAL |
| Release Guardian / AEGIS Ω | not run |

### THE STALE "STILL OPEN" LIST IS SUPERSEDED

Red team B3 was right: the "Still open" list around line 993 was not updated
when W1BR-047 and W1BR-048 closed two of its items, the 03581a3 reliability
result was never recorded at all, and the red team's own B1 appeared nowhere.
**That list is superseded by the register below.** Every finding recovered from
evidence against `8a0bf05` — including the four items the 03581a3 reliability
review left open, whose code was unchanged at that SHA — carries an explicit
disposition here. Nothing is a backlog item.

### FOUNDER DECISION — SURVIVOR ERASURE, OPTION B, LOCKED

When a merged-in key cannot be AUTHORITATIVELY confirmed destroyed, Aaliyah
must not represent the subject as erased. The state is
`ERASURE_PENDING_SETTLEMENT` / `KEY_DESTRUCTION_NOT_PROVEN` and it stays
unresolved until an evidence-bound settlement resolves it. UNKNOWN never
becomes ERASED because a row says destroyed, a retry budget expired, the
provider is unavailable, the key cannot be found, an operator says "probably
gone", or time elapsed. Database evidence alone does not substitute for
authoritative key-provider destruction proof.

Implemented by migration 055 and `src/application/memory/wave1KeyDestruction.ts`.
Settlement is bounded and is **not** an administrative bypass; each required
property is enforced where a caller cannot reach it, and each is listed against
K-01/K-09 below.

### REGISTER

| ID | Sev | Reviewer | Finding | Disposition | Proven by |
| --- | --- | --- | --- | --- | --- |
| K-01 | CRITICAL | Integration | With `piiKeys: null` — the actual production wiring, no production KMS provisioned — `state` is forced to null, null is never `"destroyed"`, and every survivor of a merge whose absorbed record ever carried a PII binding is refused subject erasure PERMANENTLY, including its own content, even where the merged-in key was genuinely destroyed with evidence. Undisclosed. | **CLOSED.** OPTION B: the question is three-valued, an unprovable key yields `key_destruction_not_proven` with a durable, listable obligation naming WHY, and a bounded settlement resolves it. Both reachable states are covered: evidence-says-destroyed-but-unaskable, and evidence-pending-with-no-provider (RV5-U-7). | S-1, S-2, S-2b, S-3, S-3b, S-4..S-10; obligation ledger listable |
| K-02 | CRITICAL | Reliability | Survivor-erasure provider calls ran INSIDE the open `mutate()` transaction holding the record's advisory lock and a pool slot, with no application timeout; `pool.max` concurrent ordinary erasures during provider latency exhaust the write pool for every tenant. | **CLOSED.** The proof phase runs before `BEGIN`, holding nothing — sound because destruction latches — and the transaction re-reads the in-scope key set under the record's lock, refusing any key the proof phase did not answer for. Every provider call has an explicit deadline. | R-1 (probe1: no transaction and no record lock held ACROSS the call, measured as durations), R-2 (probe2: an unrelated mutation completes WHILE the provider is hung) |
| K-03 | HIGH | Red Team B1 | A subject erasure reported `verified:true` while the subject's OWN key was live and a pre-erasure ciphertext copy still decrypted. Needed only a provider outage plus one `restore`: the second erasure wrote no new `erasure_committed` rows and the tombstone-scoped denominator was empty. | **CLOSED.** The completeness denominator is the SUBJECT's canonical merge set, whatever tombstone recorded a key and whatever state its owning record is now in. | RT5-R1 and RT5-R1b (both deletion reasons), RT5-R2 |
| K-04 | HIGH | Reliability | The evidenced-key audit had no batch bound and re-confirmed every historically destroyed key on every pass forever; no per-call provider timeout; `server.ts` awaits that pass before `app.listen()`. | **CLOSED.** Its own limit plus round-robin ordering by least-recently-audited: constant cost per pass, total coverage, and volume moves a forged row towards the front of the queue rather than away from it. Per-call deadlines throughout. | R-3 (probe3: bounded AND every key still reached), R-4 (probe4: a never-answering provider is abandoned and named PROVIDER_TIMEOUT), K-7, K-8 |
| K-05 | HIGH | Reliability (03581a3, unchanged at 8a0bf05) | Every bound was the SERVER's. A SIGSTOPped backend held boot 30s past its 10s bound; no `query_timeout`, no TCP keepalive. | **CLOSED.** Pools carry `query_timeout` (35s, above the 30s statement bound so a live server's own `57014` still wins) and keepalives; migrations get a wider ceiling with their wider server bounds. A query that trips the ceiling leaves the connection AMBIGUOUS, so it is destroyed rather than reused. | A pass-through TCP proxy that completes the real handshake then stops relaying — harsher than SIGSTOP, since the server's own timeout fires and cannot arrive — abandoned at 35.03s, with a transparency control |
| K-06 | HIGH | Reliability (03581a3, unchanged) | `CREATE TABLE IF NOT EXISTS aaliyah_mail_migrations` ran outside any lock; 2-way and 3-way concurrent migrators crashed N-1 with `23505` on `pg_type_typname_nsp_index`, and `server.ts` turns that into `process.exit(1)`. | **CLOSED — at the second attempt.** A session advisory lock covers the creation against every migrator that TAKES it, and the ledger creation now also TOLERATES losing the race (`42P07`/`23505`, then confirm the ledger is really there), outside any transaction. **The first attempt's rationale was wrong and is retracted below.** | A positive control proving bare concurrent `IF NOT EXISTS` really crashes N-1 with 23505 on this server; 2, 3 and 5 concurrent migrators all fulfilling with the ledger applied exactly once and no session lock left held; and the reliability reviewer's own probe — the real migrator racing a simulated OLDER build, 10 trials on a fresh database plus 5 on a steady-state one — which FAILS against the pre-fix code and passes after it |
| K-07 | MEDIUM | Security NEW-1 / Red Team B2 | The stores named tables UNQUALIFIED under `SET LOCAL ROLE` on the default `"$user", public` path; granted CREATE on the database, the mutator shadowed `memory_identity_edges` and a survivor's erasure verified over a LIVE key with forged evidence (ATK-P1). | **CLOSED.** `enterMemoryRole` strips `"$user"` and re-appends `pg_temp` LAST, in one statement, for every store. Schemas the OPERATOR configured are kept — that is a deployment decision, and it is what lets a read-back pool be pointed at a divergent schema, which a dozen tests rely on. | ATK-P1 reproduced with the grant in place and refused, with a negative control proving the schema is otherwise uncreatable; plus a direct test of the three path properties and of `SET LOCAL` not leaking |
| K-08 | MEDIUM | Red Team B2 | Five more widenings produced NO map diff and all WORKED: CREATE ON DATABASE, a view in another schema, a SECURITY DEFINER function in another schema, a granted `pg_catalog` function (`pg_read_file` read 29,950 bytes of `postgresql.conf`), and a function owner change. TEMP/CONNECT through PUBLIC undeclared. | **CLOSED.** The map has a `databases` section (with `acldefault`, so the implicit PUBLIC CONNECT/TEMPORARY is stated — though see G-07: that NULL branch is structurally unreachable under this harness and is not claimed as tested), scans every non-system schema and names it in each entry, has a `catalogFunctions` section for explicit `pg_catalog` grants, and records owners. | A positive control per widening: ten in one test plus W2/W3 in another, each applied, reported by name, reverted, map restored |
| K-09 | MEDIUM | Security NEW-2 | A merged-in key the store's provider cannot confirm (lost key, provider migration) blocked the survivor's erasure permanently. Fails closed, undisclosed, no operator path. | **CLOSED** with K-01. Named `PROVIDER_DOES_NOT_OWN_KEY` / `PROVIDER_ANSWERED_UNKNOWN` rather than skipped, and settleable. An obligation that heals because the owning provider finally answers is closed as resolved BY PROVIDER, not by settlement, so the ledger does not accumulate rows that healed on their own. | S-10, K-9 |
| K-10 | MEDIUM | Reliability (03581a3) | `server.ts` awaited both recovery passes in ONE try/catch, so a `reconcilePending` rejection skipped erasure completion entirely — and silently, since the catch spoke only of reconciliation. | **CLOSED.** Two independent passes, each reporting its own result or its own failure; `notProven` is surfaced separately from `pending`, so a permanent state no longer looks like a counter that has not moved yet. | A REAL spawned `server.ts` with both passes made to fail by privilege: both failures appear, and the process still boots |
| K-11 | MEDIUM | Reliability (03581a3) | `destroyed` was incremented unconditionally after `ON CONFLICT DO NOTHING`, so two racing passes over ten keys reported 15 and 16. | **CLOSED.** Counted from rows that actually landed. A new `repaired` count carries the case the rowCount check would otherwise silence: a forged `key_destroyed` row already holds the evidence slot, so a real destruction of a live key would have reported zero. | R-5 (two racing passes sum to the ledger), K-6, K-7, K-8, K-9 |
| K-12 | MEDIUM | Integration | `tests/support/sharedMemoryTables.ts`'s advisory lock is per-database and structurally cannot protect cluster-wide DDL (`ALTER ROLE`, proven empirically) from a concurrent file on another database in the same cluster. | **BOUNDED_AND_PROVEN_NONBLOCKING.** See "Cluster-scoped DDL" below: the boundary is now written down, no RLS exists anywhere in `src/` or `tests/`, and BYPASSRLS has no effect without policies. Not exploited. | The reviewer's own empirical proof (`pg_try_advisory_lock` from another database succeeded while the first was held); grep for RLS across the repository |
| K-13 | MEDIUM | Integration / founder | Migration 047 is NOT rolling-update safe and NOT rollback safe, and no full-stop procedure was written down. | **DISCLOSED, documented, NOT DEPLOYED.** See "Migration 047 deployment" below. Production: **NOT PROVEN**. | The register section below; migration replay and upgrade suites |
| K-14 | MEDIUM | Founder SIXTH priority | An address in ordinary record content may remain in the clear until that record is deleted. | **DETERMINATION (B): outside the W1.3 erasure contract, and BLOCKING later production privacy claims.** Measured, not described — see "The clear-content residual" below. Surfaced to AEGIS as a residual, not as a closed finding. | X-10, which pins both what the contract destroys and the exact two locations (one physical row, surfaced through a view) where the residual survives |
| K-15 | LOW | Red Team B3 | Register hygiene: the "Still open" list was stale, the 03581a3 reliability result was never recorded, B1 appeared nowhere. | **CLOSED.** This section. The stale list is explicitly superseded and every recovered finding has a disposition. | — |
| K-16 | LOW | Security F4 | PUBLIC EXECUTE on two SECURITY DEFINER helpers handed a login role with NO GRANTS a hold id and a full nonce row while direct SELECT was denied. | **CLOSED** by migration 056. `aaliyah_memory_restricting_hold` is granted to the three roles that call it; `aaliyah_memory_spent_nonce` to none, because it is called only from inside other SECURITY DEFINER guards, which run as owner. | The declared privilege map, which now shows exactly three grantees for the first and none for the second |
| K-17 | LOW | Security F5 | Grants wider than the code needs; no runtime code in `src/` uses the issuer or revoker roles at all. | **CLOSED** by migration 056: the reconciler's blind-index SELECT and the issuer's/revoker's SELECT on bindings, blind indexes and key erasures are revoked. New grants in 055 were written against call sites rather than tables. | Full suite green after the trim; the declared map |
| K-18 | LOW | Red Team | Producer-chosen alias ids can carry the address and survive a verified erasure; `carriesPlaintext` checks only record content. | **BOUNDED_AND_PROVEN_NONBLOCKING, DISCLOSED.** See "The alias-id residual" below. | RT5-O1 as the reviewer executed it; the semantics are stated below rather than claimed closed |
| K-19 | LOW | Red Team | Full-suite discovery picked up git-ignored test directories while `git.dirty=false`, so the executed set was not bound to the SHA. | **CLOSED.** An ignored discovered file is refused before anything is spawned; an untracked-but-not-ignored file is allowed because `git status` reports it; an unverifiable binding refuses a FULL_SUITE verdict. | A negative control planting a git-ignored probe (FAIL, counts null, under 10s) and a positive control on a clean tree |
| K-20 | LOW | Integration | Both `ABORT_REASON` maps were `Record<string, …>`, so a new rejection compiled and silently reported `policy_rejected`. | **CLOSED.** Both are exhaustive over their rejection enums, with no `??` fallback at the call site. | A negative control: adding an unmapped rejection fails `tsc` in both stores |
| K-21 | NOT_VERIFIED | Reliability (03 and 03581a3) | fd and memory exhaustion never executed, twice disclosed. Reconciliation-versus-pool-exhaustion not separately probed. | **STILL NOT_VERIFIED, and named as such.** Not rounded up, not closed, and not claimed. It is the one item in this round that no evidence here covers. | — |
| K-22 | LOW | Reliability (03581a3) | Evidenced-key audit cost O(all evidenced rows, all time). | **CLOSED** by K-04's bound and ordering. | R-3 |
| K-23 | MEDIUM | Founder FOURTH priority | The merge-chain cap must remain exactly 16 valid / 17 rejected, and the erasure contract must hold across the WHOLE chain, not the nearest hop. | **CLOSED.** The cap is unchanged and re-proven; the erasure scope is the transitive closure. | D-1 (16 valid, 17 refused, nonce unspent, plus a branch control), D-2 (the database refuses the 17th even past the store), X-9 (a three-hop chain where a key three hops away is asked about and refuses the survivor, with a positive control) |

### RETRACTED: what K-06's first fix claimed, and why it was false

The register said, of the first K-06 fix: *"`LOCK TABLE` is kept to bind a
migrator running an OLDER build of this function, which knows nothing about
this key."*

**That was false, and the reliability review of 86d33c9 falsified it 10 trials
out of 10 on a fresh database.** A `pg_advisory_lock` serializes only the
participants that take it. An older build issues a bare
`CREATE TABLE IF NOT EXISTS` with no advisory lock, races this build's creation
directly, and `LOCK TABLE` cannot protect a table that does not exist yet. The
instance that died was THIS one, with the original defect's exact error. On a
steady-state database, where the ledger already exists and there is something
to lock, the same pair raced cleanly 5/5 — so the gap was precisely the
first-rollout case K-06 was opened for.

It is worth recording WHY the wrong claim was written: it asserted enforcement
for a mechanism that cannot enforce it, and no test drove it, because the
tests all raced the NEW build against ITSELF. An older build cannot be bound at
all — so the fix is not to win that race but to make losing it harmless, which
is what the second attempt does.

### Cluster-scoped DDL — the boundary, written down (K-12)

`lockSharedMemoryTables` takes a PostgreSQL **advisory lock**, and advisory
locks are **per-database**. It therefore excludes concurrent files on the SAME
database, which covers the class it was built for: `TRUNCATE`, table `GRANT`s
and `LOCK TABLE` on shared tables.

It does **not** and cannot cover **cluster-scoped** DDL: `ALTER ROLE`,
`CREATE`/`DROP ROLE`, `ALTER DATABASE`. Role attributes are cluster-wide, and
the integration review proved the gap empirically — a second
`pg_try_advisory_lock` on the same key from another database on the same
cluster succeeded immediately while the first was held.

Why it is non-blocking today, stated as facts rather than as comfort:
`ENABLE ROW LEVEL SECURITY` and `CREATE POLICY` appear nowhere in `src/` or
`tests/`, so `BYPASSRLS` has no functional effect; and no test file on any
other database reads a memory role's attributes. A future test that asserts a
role attribute from a suite on a different database would be unprotected, which
is what this entry exists to tell its author.

### Migration 047 deployment — full stop, and NOT AUTHORIZED (K-13)

Migration 047 is **NOT rolling-update safe and NOT rollback safe**, and that
disclosure is preserved rather than rewritten away. It refuses to run over an
existing plaintext alias binding, and the code that writes bindings before and
after it disagrees about where the identifier lives. **No deployment is
authorized now. Production: NOT PROVEN. This is documentation and test
evidence only.**

If a full-stop deployment is ever authorized, these are its preconditions and
steps, in order:

1. **Preconditions.** A verified backup that restores to a running database;
   the exact candidate SHA and its migration set recorded; `pnpm test` green
   against a copy of production data at the current schema; every writer
   identified, including workers and cron, not only HTTP instances.
2. **Maintenance mode.** Refuse writes at the edge first, so nothing is
   half-written while the writers are still being stopped.
3. **Writer shutdown.** Every writer stopped and CONFIRMED stopped by
   `pg_stat_activity`, not by a deploy tool's opinion. `runMailMigrations`
   serializes concurrent migrators (K-06), which bounds an accident; it is not
   a substitute for stopping writers.
4. **Backup.** Taken AFTER the writers are confirmed stopped, so the restore
   point is a quiet database.
5. **Migration.** `runMailMigrations` once, from one instance.
6. **Verification.** The ledger's last id is the expected one; every expected
   trigger, helper and privilege is present — the declared privilege map is the
   check, section by section, including trigger enablement; a read-only smoke
   of the erasure path.
7. **Failure behavior.** Each migration is one all-or-nothing transaction, so a
   crash mid-migration leaves the ledger and the schema agreeing (proven by the
   03 reliability review's mid-054 crash probe). A migration that FAILS leaves
   the database at the previous migration; do not retry blindly — read the
   error, because 047's refusal over a plaintext binding is a data problem and
   not a transient one.
8. **Recovery.** 047 is NOT rollback safe: there is no down-migration. Recovery
   is RESTORE FROM BACKUP, which is why step 4 is not optional.
9. **Restart ordering.** Migrator instance first and confirmed at the expected
   ledger id; then readers; then writers; then maintenance mode off.

### The clear-content residual — the determination (K-14)

**Determination: (B) outside the W1.3 erasure contract, and blocking later
production privacy claims.** No PII detector is introduced, and none is
pretended to.

What `alias_plaintext_in_record_content` actually guards, read from the code
and pinned by X-10: ONE mutation, `assign_alias`, checking the normalized and
observed alias as CONTIGUOUS case-insensitive substrings anywhere in the
proposed content. It is not applied to `create` or `correct`.

**Supported semantics, measured:**

- A subject erasure destroys the subject's own content on every version it ever
  had, whether an identifier in it was contiguous or split across fields, plus
  its alias envelopes, blind indexes and data keys, across the whole canonical
  merge set.
- An `assign_alias` whose successor content carries the alias contiguously is
  refused, and spends nothing.

**Limitations, measured:**

- An identifier in ANOTHER record's content survives the subject's erasure,
  contiguous or split. That record is not in the subject's canonical merge set.
- No detection of an identifier assembled across fields, encoded,
  transliterated or paraphrased, in any record.
- X-10 pins the exact surviving locations — `memory_record_versions.payload`
  and the `memory_records_retrievable` VIEW over it, i.e. one physical row —
  and asserts the subject's own rows keep nothing. A change that puts the
  identifier anywhere else fails that test rather than becoming a footnote.

**Why it is not simply fixed:** reaching it needs either a reverse index of
subject identifiers — which is the very material the vault exists to keep out
of the clear — or a detector that recognises an identifier assembled across
fields. Producers are responsible for not writing subject identifiers into
ordinary content, and the store cannot verify that they have not.

### The alias-id residual (K-18)

`aliasId` is chosen by the PRODUCER, and a producer may put the address in it:
`alias.victim.person.example.com` is accepted, and after a verified erasure
`victim.person` still appears in `memory_alias_bindings.alias_id`, in record
payloads and in receipts. The contract regex blocks `@`, which stops the
obvious form and not the deliberate one.

**BOUNDED_AND_PROVEN_NONBLOCKING, and disclosed rather than closed.** The
bound: an alias id is opaque to every control in W1.3 — nothing resolves,
compares or indexes on it as an identifier — so this is a residual in
EVIDENCE, not a path to resolving an erased subject. The same producer
responsibility as K-14 applies, and the same reason applies for not "fixing"
it: refusing a producer-chosen id that MIGHT encode subject material needs the
detector this wave does not have. A derived, keyed alias id would close it and
is a W1.4-or-later change, not a quiet edit here.

### What this round did NOT prove

- **K-21, fd and memory exhaustion: NOT_VERIFIED.** Not attempted, not
  rounded up.
- **Production cloud KMS/HSM: NOT PROVEN**, and explicitly outside the local
  W1.3 certification boundary. Every key result here is against the local test
  provider.
- **Production: NOT CERTIFIED. Fortress: NOT CERTIFIED.** Nothing is pushed,
  merged or deployed.
- **Remote CI: not proven.** Only local runs.

### THE MUTATION SWEEP, AND THE THREE CONTROLS IT FOUND UNTESTED

39 targeted mutants, each removing or inverting ONE control this round added or
repaired, run in a DISPOSABLE worktree against its OWN PostgreSQL database.
The implementation worktree was never mutated. Every mutant is judged by the
WATCHDOG rather than by `node --test`, because a mutant that HANGS has to be a
verdict and not a wait — M-18, which reintroduces the K-02 defect, leaks a
pooled connection per erasure and runs for ever; the watchdog turns that into
FAIL, which is the doctrine working.

Two methodology errors in the sweep itself, recorded because a sweep whose own
harness is wrong is worse than no sweep:

- the first run passed `--test-name-pattern` to the watchdog, which refuses
  unknown flags with exit 2 — and six mutants were recorded KILLED on the
  strength of a refusal to run anything at all. The empty verdict line gave it
  away. Every mutant is now run against the WHOLE target file, which is also
  the stronger question: the mutant has to be caught by the suite, not by the
  one test expected to catch it;
- two mutants did not compile and one was a no-op that left the timer in the
  race it claimed to remove. All three were re-specified and re-run.

Final classification at the swept SHA: **36 KILLED, 1 INVALID_MUTANT, 2
REAL_SURVIVOR, 0 environment-blocked, 0 structurally-unreachable.** Both
survivors were real, and both were the same shape — a control whose only tests
reached it through a DIFFERENT code path:

| Mutant | The control nothing was driving | Falsifier now in the suite |
| --- | --- | --- |
| M-08 | `askProvider`'s PROVIDER_DOES_NOT_OWN_KEY branch — the PRE-CHECK's answer for a key this store cannot speak for. S-10 and K-9 reach provider-mismatch through the COMPLETION PASS, which has its own branch and never calls `askProvider`. | **S-11**: a merged-in key destroyed honestly by its owning provider, and a survivor's erasure attempted by a store speaking for a different provider — refused `key_destruction_not_proven`, obligation named PROVIDER_DOES_NOT_OWN_KEY, with the owning store as positive control |
| M-23 | Migration 055's evidence trigger clause `s.decision = 'PROVEN_DESTROYED'`. S-3 proves a STILL_UNKNOWN settlement writes no destruction evidence — but that is the STORE declining to insert. The DATABASE's clause, which is what makes "only PROVEN_DESTROYED may satisfy erasure" a property rather than a convention, had nothing driving it. | **S-12**: the insert attempted DIRECTLY as the settler role, past the store, and refused by the trigger; no evidence row appears; the completion pass still counts the key unproven; a PROVEN_DESTROYED settlement on a second key is the positive control |
| M-29 | `releaseClient`'s destroy decision. The wedged-transport test goes through `pool.query()`, and pg-pool already passes the error to `release()` there, so it destroys the client whatever `releaseClient` decides. Every store transaction checks a client out EXPLICITLY and depends on `releaseClient` instead. | **K-05 (second test)**: the decision asserted directly for six ambiguous and five ordinary error classes, plus a real checked-out client whose backend is killed mid-transaction — destroyed, pool left with no idle client, and the pool still serving |

Each survivor's repair produced a new descendant SHA and the sweep was re-run
against it. The sweep's own defects above are why its first two runs are not
cited as evidence anywhere.

### K-21 UPDATED — fd exhaustion EXECUTED, memory exhaustion still NOT_VERIFIED

Disclosed NOT_VERIFIED by the reliability reviews of both 03581a3 and 8a0bf05,
each time because OS-level exhaustion on a shared host was outside a safe
budget. Attempted here inside a CONTAINED CHILD PROCESS whose resource ceiling
is its own. Evidence: `aaliyah-w13-evidence/k21-probes/`.

- **fd exhaustion: EXECUTED.** A child with a lowered HARD limit burns
  descriptors until the kernel returns EMFILE, gives none back, and only then
  asks a pool for a connection. The pool fails with a catchable `EMFILE`: it
  does not hang, it does not take the process down, and the process exits
  cleanly. Two earlier versions of the probe were wrong and are kept for the
  reason — hogging with sockets exhausts nothing, because a failed connect
  releases its descriptor immediately, and `ulimit -n` alone is ignored,
  because Node raises RLIMIT_NOFILE to the hard limit at startup.
  **NOT a regression test**, and that is named rather than glossed: a test that
  lowers a hard fd limit is host-dependent, and a test that can come back
  "inconclusive" is a skip in disguise, which this suite's watchdog counts as
  a failure.
- **memory exhaustion: STILL NOT_VERIFIED.** With a 24 MB heap the child
  THRASHED rather than aborting and was still thrashing after five minutes; it
  was killed, and the database was confirmed clean afterwards (no
  idle-in-transaction session, no advisory lock on the probe's key, no witness
  table) — a real observation about crash cleanup, but not the one the probe
  was for. Not rounded up. A V8 heap abort is uncatchable in-process, so the
  properties worth proving are that an aborted process leaves no torn state and
  cannot be read as a pass; both are proven elsewhere (P-6, and the watchdog's
  process-exit and SIGKILL attacks) but not under memory pressure specifically.

---

## W1.3 SIXTH HOSTILE CHAIN — `86d33c9`, AND WHAT THE GAUNTLET FOUND

Five reviewers ran against `86d33c9` in isolated immutable worktrees with
isolated databases. **Three returned blocking verdicts.** Every finding below
was substantiated, and three of them are defects in the previous round's own
remediation — including one register claim that was simply false.

| Reviewer | Verdict at `86d33c9` |
| --- | --- |
| Test Falsifiability | **BLOCK** — one HIGH nondeterminism, one structural gap, one MEDIUM survivor |
| Security | **BLOCK** — one HIGH tenant crossover, one LOW over-grant, one LOW disclosed residual |
| Reliability | **RELIABILITY_RED** — one HIGH, reopening K-06 |
| Integration Marshal | **BLOCK** — one HIGH, plus three lower findings |
| Red Team | **BLOCK** — 2 HIGH, 6 MEDIUM, 3 LOW, and three real mutation survivors |

| ID | Sev | Reviewer | Finding | Disposition | Proven by |
| --- | --- | --- | --- | --- | --- |
| G-01 | HIGH | Reliability | **K-06 REOPENED.** The register claimed `LOCK TABLE` would "bind a migrator running an OLDER build". It does not: an advisory lock serializes only participants that take it, an older build races the `CREATE TABLE` directly, and `LOCK TABLE` cannot protect a table that does not exist yet. 10 trials out of 10 on a fresh database, and the instance that died was THIS one. Steady state raced cleanly 5/5. | **CLOSED.** This build no longer tries to win that race; it TOLERATES losing it. Ledger creation moved out of the transaction and swallows `42P07`/`23505` after confirming the ledger is really there. See the retraction above. | The reviewer's own probe as a test: the real migrator against a simulated pre-K-06 build, 10 fresh-database trials and 5 steady-state ones. FAILS against `86d33c9`, passes after — verified in a disposable worktree |
| G-02 | HIGH | Security | **TENANT CROSSOVER.** `settlementProven` took ONE scope — from the first row of the batch — and returned a map keyed by `key_ref` ALONE, which the caller applied to EVERY row. `src/server.ts` runs the completion pass unfiltered at boot, so one tenant's sound PROVEN_DESTROYED settlement satisfied a DIFFERENT tenant's identical key reference: the second tenant's live key reported resolved, NO obligation recorded. The same root cause silently IGNORES other tenants' valid settlements when the ordering goes the other way. Nothing makes a key reference globally unique — `memory_pii_key_erasures_once` is UNIQUE per scope. | **CLOSED.** Matched three columns wide (tenant, workspace, key_ref) in one round trip, and the map is keyed by the whole scope. Both callers pass their own rows' scopes. | S-13, which builds the collision deliberately, forces the batch ordering the defect needs, and asserts BOTH halves: the unsettled tenant is unproven with an obligation, and the settled tenant's own settlement still answers for its own key. FAILS against `86d33c9`, passes after |
| G-03 | LOW | Security | The MUTATION role held `UPDATE (… settled_by)` on the obligation ledger and could rewrite a row to claim a settlement that does not exist. Wider than any mutator code path writes. | **CLOSED.** `settled_by` removed from the mutator's column grant; only the settler names a settlement. Confined to the advisory ledger either way — the erasure verdict reads evidence and settlements, not obligations. | The declared privilege map, which lost exactly that one column entry |
| G-04 | LOW | Security | `enterMemoryRole` deliberately KEEPS operator-configured session schemas, and the stores name their tables unqualified — so a session `search_path` an OPERATOR controls still shadows them. | **BOUNDED_AND_PROVEN_NONBLOCKING, DISCLOSED.** See "The kept-schema residual" below. The attacker-reachable vector (`$user`) is closed and the reviewer re-confirmed ATK-P1 refused; reaching this needs operator-level control of the session path, which is the disclosed trust boundary. | The reviewer's own execution: ATK-P1 closed, `ALTER ROLE … SET search_path` inert under `SET LOCAL ROLE`, all 35 SECURITY DEFINER functions pinned |
| G-05 | HIGH | Test Falsifiability | **NONDETERMINISM.** Four clean full-suite runs gave PASS, FAIL, PASS, PASS. Root-caused, not dismissed as load: the privileges suite released the shared advisory lock BEFORE its final "everything is restored" comparison, and the K-10 boot test takes the same key and transiently revokes exactly two privileges. The failing diff named precisely those two and nothing else. | **CLOSED.** Both trailing comparisons moved inside the lock. This is the SECOND time this exact window appeared in this round — the first was found by the implementer, and the fix did not cover the other two call sites. | The reviewer's empirical hit plus the code path; the comparisons now sit inside the `try` that holds the lock |
| G-06 | — | Test Falsifiability | **NO INDEPENDENT DISCRIMINATION PROOF.** The 39-mutant sweep is the implementer's own. Per the gate's contract that does not satisfy it, and the same absence was flagged at `8a0bf05` and answered by self-certification. | **ADDRESSED by dispatching an independent `mutation-fuzz` reviewer** against the exact SHA, as an eighth reviewer. Its verdict is recorded with the others. | Reviewer 8's report |
| G-07 | MEDIUM | Test Falsifiability | A mutant removing the `COALESCE(d.datacl, acldefault(...))` NULL fallback in the privilege map SURVIVED: `datacl` is NULL only for the bootstrap `postgres` database, and every database created with `CREATE DATABASE` inherits a non-null ACL from `template1`, so the NULL branch is unreachable under this harness. The K-08 entry cites that line as proof that the implicit PUBLIC CONNECT/TEMPORARY is stated. | **STRUCTURALLY_UNREACHABLE_WITH_PROOF, and the K-08 wording is corrected.** The `COALESCE` is KEPT — it is correct for a bootstrap database and costs nothing — but it is no longer cited as tested. What IS tested is that the `databases` section reports `GRANT CREATE ON DATABASE` (W1), which is the widening that mattered. | The reviewer's surviving mutant, and the W1 positive control that does discriminate |
| G-08 | HIGH | Integration | **AN EDITED MIGRATION IS SILENT.** The ledger recorded only an id, so changing an already-applied migration's SQL was undetectable — proven against the real compiled runner by weakening a function 055 defines and re-running, which reported success with the weakened definition live. W1BR-014 covers the row-deleted variant, not this one. And it is not hypothetical: it happened in this round, and was noticed only because T-1 happens to assert a property of one of those functions. | **CLOSED** by migration 057: the ledger records a digest of the SQL applied, and the runner refuses before applying anything when an applied migration's content no longer matches. | INT-DIGEST: a fresh apply is fully digested in ONE run (the first version of the fix left every row undigested until a second run), re-running is a clean no-op, and a changed digest is refused with the ledger untouched |
| G-09 | MEDIUM | Integration | No HTTP or CLI surface lets an operator LIST or SETTLE `memory_key_destruction_obligations` against a running instance — only raw SQL. K-01's disposition says "listable", which is true at the service layer and not operationally. | **DISCLOSED, and the K-01 wording is corrected below.** `listKeyDestructionObligations` and `settleKeyDestruction` exist on the service; no route or command reaches them. An operator surface needs an authorization design and belongs to a later wave, not to a quiet edit here. | The reviewer booted the real `dist/src/server.js` and searched the routes |
| G-10 | LOW | Integration | A stray `freeze-suite-last.json` from the superseded `7847904` sat in this candidate's evidence folder and could be mistaken for a third data point. | **CLOSED.** Removed, and the checksum file regenerated. | The evidence directory's `SHA256SUMS` |
| G-11 | LOW | Integration | An ambient `AALIYAH_DATABASE_URL` reroutes unrelated unit tests through `applicationStoreFromEnv()`'s singleton to a shared Postgres store, deterministically failing four tests. Only Postgres-specific files should set it. Cost the reviewer two full-suite runs. | **DISCLOSED** below, so the next reviewer does not pay for it again. Not a candidate defect: the suite's own contract is that `AALIYAH_TEST_DATABASE_URL` is the one to export. | The reviewer root-caused it to `src/persistence/applicationState.ts` and reproduced the clean result with only the test variable set |

### The kept-schema residual (G-04)

`enterMemoryRole` strips `"$user"` and forces `pg_temp` last, and KEEPS every
other schema the session was configured with. That is deliberate, and the
trade-off is worth stating plainly rather than leaving in a code comment:

- what it closes: the attacker-reachable vector. A role granted CREATE on the
  database can create a schema named after itself, and `"$user"` used to put it
  first on the path — ATK-P1. With `"$user"` gone, and with `SET LOCAL ROLE`
  ignoring a role's own `ALTER ROLE … SET search_path`, an entered role has no
  way to influence name resolution at all. The security reviewer re-confirmed
  both.
- what it keeps open: an operator who controls the SESSION path — through a
  connection string, `ALTER DATABASE … SET`, or a compromised login role that
  can both `ALTER ROLE` itself and create a schema — can still shadow an
  unqualified name. That is the same trust boundary as a DBA, and it is where
  this residual lives.
- why it is kept: an explicit schema list on a connection string is a
  deployment decision, and a store that silently discarded it would be
  overriding its operator. It is also the mechanism a dozen tests use to point
  a read-back pool at a deliberately divergent schema, which is how this store
  proves it never reports success on a read-back that disagrees with the
  commit — the single most important property in the file.
- the falsifier, if the trade is ever judged wrong: schema-qualify every
  identifier the stores issue, or discard all non-public schemas. Either
  removes the residual, and the second one costs those tests their mechanism.

### Corrected: K-01's "listable" (G-09)

The obligation ledger is listable through the memory service
(`listKeyDestructionObligations`) and settleable through it
(`settleKeyDestruction`). **Neither is reachable from outside the process**:
there is no HTTP route and no CLI command. An operator facing an
`ERASURE_PENDING_SETTLEMENT` today reads `memory_key_destruction_obligations`
with SQL. That is a real operational gap, it is disclosed rather than closed,
and it does not change what the state MEANS — which is the part Option B
required.

### For the next reviewer: do not export `AALIYAH_DATABASE_URL` (G-11)

Export `AALIYAH_TEST_DATABASE_URL` and nothing else. With
`AALIYAH_DATABASE_URL` also set, `applicationStoreFromEnv()`'s process-wide
singleton (`src/persistence/applicationState.ts`) reroutes unrelated unit tests
to a shared Postgres store and four of them fail deterministically. The
Postgres-specific files set what they need themselves. Two reviewers have now
lost runs to this; it is written down so a third does not.

### THE RED TEAM'S VERDICT AT `86d33c9`: BLOCK — 2 HIGH, 6 MEDIUM, 3 LOW

It could not break C1, the invariant its predecessor broke, and said so with
its limits named. Everything else it attacked, it broke.

| ID | Sev | Finding | Disposition | Proven by |
| --- | --- | --- | --- | --- |
| B1 | HIGH | **`erasure_authorization_id` was unverified free text.** `memory_key_destruction_settlements_scope_unique` is UNIQUE (tenant, workspace, key_ref, erasure_authorization_id) and IS the whole of "action-specific". A settlement already refused as `settlement_already_resolved` was accepted by editing that one string to an id nobody ever issued — 0 rows in the nonce table, 0 in the receipts table — and a STILL_UNKNOWN key became ERASED. | **CLOSED.** The trigger now requires the id to be the authorization the TOMBSTONE records as having witnessed that erasure. S-3b's subject is enforced against real state instead of against a string. The authority/verifier identities remain unresolved — see "What settlement still does not prove" below. | S-3 and S-3b, which had to be rebuilt around real authorizations once the string stopped being free; the trigger's own refusal message |
| B2 | HIGH | **The settler wrote UNLABELLED destruction evidence, so 055's PROVEN_DESTROYED clause never ran.** The clause sat inside `IF NEW.settlement_receipt_id IS NOT NULL`. Same insert as S-12 with the label NULL → ACCEPTED; provider key `active`; `aaliyah_memory_unerased_merged_records()` returned 0 rows — the database believed an unerased subject erased. The clause guarded the labelling CONVENTION, not the evidence. | **CLOSED.** The settler has NO INSERT on the evidence table. The labelled row is written by `aaliyah_memory_record_settled_destruction`, a SECURITY DEFINER function that reads the settlement and supplies every column from it, refusing any decision but PROVEN_DESTROYED. There is no unlabelled row the settler can write because there is no INSERT it can issue. | S-12, rewritten: the settler's insert is refused `permission denied` with the label AND without it, and the one path that can write refuses a STILL_UNKNOWN settlement |
| B3 | MEDIUM | **`enterMemoryRole` did not strip `$user`.** It compared literal lowercase strings; a search_path carries the casing whoever set it wrote, so `$User`/`$USER` survived and still resolved to the current role's schema, delivered through `PGOPTIONS`. ATK-P1's HARM did not reproduce — the erasure SQL is `public.`-qualified and all 44 guards pin their own path — but the claim was false, and K-07's own assertion was case-SENSITIVE and could not see it. | **CLOSED.** Compared with `lower()`. The K-07 test now starts from `$User` and asserts case-insensitively. | The K-07 path test, which now fails without the `lower()` |
| B4 | MEDIUM | **Five more widenings, all invisible.** The worst: a `RULE … DO INSTEAD NOTHING` on `memory_pii_key_erasures` silently swallowed an insert the guard must reject — rows 0 to 0, trigger never fired. `tgenabled` was added for that class and does not cover it: a rule does not disable a trigger, it removes the write the trigger would have seen. `pg_rules`/`pg_rewrite` appeared nowhere in the repo. Also PG16 membership options, `ALTER FUNCTION … RESET search_path` (proconfig), `pg_parameter_acl`, and type/domain ACLs. | **CLOSED.** Five new declared sections: `rules`, `functionConfig`, `membershipOptions`, `parameterPrivileges`, `typePrivileges`. The declared map asserts rules/parameters/types/membership-options are EMPTY and that all 45 `aaliyah_*` functions still carry a pinned path. | A positive control applying the rule, the `RESET search_path`, a parameter grant and a `WITH ADMIN` membership, each reported by name and reverted |
| B5 | MEDIUM | **A FOCUSED run affirmed `boundToCommit: true, ignored: []` for a git-ignored file** — a positive assertion about a binding nobody checked, in the evidence a reviewer reads. FULL_SUITE correctly refused the same file (K-19 works). Also one-directional: `tracked − discovered` was never computed, and the walk goes only two levels deep, so a tracked test in a deeper directory would silently not run. | **CLOSED.** FOCUSED records `boundToCommit: null` — not checked, not claimed. FULL_SUITE now also refuses `DISCOVERY_MISSED_TRACKED_TESTS`: every tracked `tests/**/*.test.ts` must be in the discovered set. 83 tracked, 83 discovered at this SHA — measured, not assumed. | The watchdog's own evidence object, and the discovery guard |
| B6 | MEDIUM | **Three real survivors against all 1058 tests**, one exploited. **M10**: `throw MutationAborted("merged_keys_changed_during_proof")` → `continue` survived, and that string appeared in NO test — it is the only control closing the unsound direction of the K-02 proof-before-transaction design. **M3**: dropping `settlement.sound` in the COMPLETION PASS survived AND was exploited to `verified:true, keysPending:0` with the key `active` and the pre-erasure copy still decrypting, while S-9 still passed. **M1**: the `$User` case above. | **CLOSED.** RTX-M10 forces a key into scope between the proof phase and the commit and requires the transient refusal. RTX-M3 drives an unsound settlement through the COMPLETION pass, which S-9 reached only via the pre-check. | RTX-M10, RTX-M3, and the K-07 path test |
| B7 | MEDIUM | **The obligation ledger blamed the PROVIDER for a settlement-resolved key.** `clearHealedObligations` wrote `resolved_by='PROVIDER'` for rows the SETTLEMENT branch pushed, with the provider never asked — falsifying this register's own claim that "the two are never the same value". Also `policy_version` had no constraint, so "versioned" was a column rather than a property. | **CLOSED.** A settlement-proven key is no longer pushed to the provider-healing list; `settleKeyDestruction` already closes its obligation correctly. `policy_version` is constrained to the known set. | S-3 asserts `resolved_by` is null while unresolved; S-2 asserts `SETTLEMENT`; S-10 asserts `PROVIDER`; the `policy_known` CHECK |
| B8 | MEDIUM | **`key_version` and `decided_at` were unchecked.** `keyVersion: 999999` for a version-1 key and `decidedAt: 2099-01-01` were both accepted, contradicting the trigger's own header claim that the key "really does belong to that provider AND VERSION". | **CLOSED.** The trigger checks the version against the binding; a CHECK bounds `decided_at` to now plus one minute of clock skew. | The trigger's refusal message and the `decided_not_future` CHECK |
| B9 | LOW | After a verified erasure the full address is gone everywhere, but producer-chosen FIELD NAMES from the subject's own content survive in `memory_tombstones.payload` — outside X-10's pinned two locations, in a table the owner cannot delete from. `MemoryFieldNameSchema` blocks `.` and `@`, so a contiguous address cannot reach it. | **BOUNDED_AND_PROVEN_NONBLOCKING, DISCLOSED** as a K-18-class residual: producer-chosen identifiers that survive in evidence. Same bound, same reason, and now its own entry rather than a gap in K-14's. | The reviewer's own execution; `MemoryFieldNameSchema` |
| B10 | LOW | K-12's bound is narrower than written: the map's `memberships` section IS an assertion on cluster-wide role state, so a cluster-scoped GRANT issued from another database on the same cluster breaks it. The reviewer fired it accidentally — 3 assertions failed, 243/246, and removing the grant restored 246/246. | **K-12's wording corrected.** The advisory lock covers the per-database class; the map's role-state sections are themselves cluster-scoped assertions, which is the concrete instance K-12 warned a future author about, now named. | The reviewer's accidental reproduction |

### What settlement still does not prove (B1's residual)

The settlement trigger now resolves the binding, the committed erasure, the key
version and the erasure authorization against real state. It does **not**
resolve `settlement_authority_id` or `verifier_principal_id` against anything:
they are caller-supplied strings, and "independently authorized, independently
verified" therefore rests on a `CHECK` that the two differ, plus a database
role that only a settler can enter.

That is a real limit and it is stated rather than implied. Making those two
identities resolvable needs a principal/authorization model for settlement —
the same class as W1BR-002, which this register already holds open for W1.6 —
and inventing a narrower one inside W1.3 would be a second authorization path
with none of the first one's evidence. **Disposition: DISCLOSED, deferred, and
NOT claimed as enforced.**

### Corrected: K-12's bound (B10)

`lockSharedMemoryTables` covers the per-database class — `TRUNCATE`, table
`GRANT`s, `LOCK TABLE`. It cannot cover cluster-scoped DDL. The concrete
instance, which K-12 previously described only in the abstract: the declared
privilege map's `roleAttributes`, `memberships` and `membershipOptions`
sections ARE assertions about cluster-wide role state, so a `GRANT` of a memory
role issued from ANY database on the same cluster breaks the privileges suite
wherever it runs. A reviewer fired exactly that by accident. The existing
mitigation is unchanged — every reviewer gets its own container — and the
boundary is now written down concretely instead of as a warning.

---

## W1.3 SEVENTH PASS — THE 54-MUTANT SWEEP AT `a3d1d0e`

The sweep that followed the sixth chain's remediation. Denominator 54, judged
by the watchdog in a disposable worktree on an isolated database (port 54521).

    TALLY {"KILLED": 45, "INVALID_MUTANT": 3, "REAL_SURVIVOR": 6}

### THE PATTERN, FOR THE FOURTH TIME

Every one of M-40, M-47, M-50 and M-51 is a control **added during gauntlet
remediation with no test that reaches it**. M-08, M-23, M-29, M3, M10 and M1
were the same defect in the three previous sweeps. The tests that were supposed
to cover them exist and pass; they simply arrive at the outcome by another
route:

| survivor | the control | why the "covering" test cannot see it |
|---|---|---|
| M-40 | the settlement is bound to the tombstone's authorization (B1) | S-3b was rebuilt with REAL authorizations, so deleting the check changes nothing it asserts; S-5 forges the id but is refused by the spent NONCE first, before the authorization is consulted |
| M-47 | a settlement-resolved key is not attributed to the provider (B7) | every settlement test stops at the receipt; none ran a completion pass OVER an already-settled key |
| M-50 | a FOCUSED run records `boundToCommit: null` (B5) | the only discovery assertions run the FULL suite |
| M-51 | `DISCOVERY_MISSED_TRACKED_TESTS` (B5) | no fixture had ever put a tracked test file out of the two-level walk's reach |
| M-23 | migration 055's trigger clause, as distinct from its function | both existing assertions go through `aaliyah_memory_record_settled_destruction`; the trigger on the table was never driven with a labelled row |

The lesson is not "add tests". It is that a test which asserts the right
OUTCOME proves nothing about a control it does not traverse, and a control
added at the end of a review round is exactly the kind that gets one.

### DISPOSITIONS

| id | disposition |
|---|---|
| M-40 | **CLOSED** — `S-4c` drives a first settlement, fresh nonce, fresh receipt, whose ONLY defect is an authorization nobody issued. Refused `settlement_not_evidence_bound`; nothing written; the subject stays NOT ERASED; the real authorization is accepted as the positive control. |
| M-47 | **CLOSED** — `S-2` now runs a completion pass over the settled key and asserts `resolvedBy === "SETTLEMENT"`. The second defense (`clearHealedObligations`' `state = 'KEY_DESTRUCTION_NOT_PROVEN'` filter) is held by the NEW mutant **M-55**, so neither half is unfalsifiable. |
| M-50 | **CLOSED** — `testWatchdog.test.ts` asserts a FOCUSED run's `boundToCommit` is `null` and explicitly `notEqual` to `true`. `null` is the finding; it is not a weaker `true`. |
| M-51 | **CLOSED** — a probe at `tests/deep/nested/`, staged INTENT-TO-ADD so `git ls-files` reports it while no blob is written, three levels down where `tests/*/*.test.ts` cannot reach. Refused `DISCOVERY_MISSED_TRACKED_TESTS` before any spawn; the tree is restored and re-asserted clean in `finally`. |
| M-23 | **CLOSED** — reached at the clause rather than at the function. The MUTATOR holds INSERT on `memory_pii_key_erasures` (it is how ordinary provider-confirmed evidence is written) and chooses the label, so a `key_destroyed` row labelled with a STILL_UNKNOWN settlement's receipt is a reachable path, and the trigger clause is the only thing on it. |
| M-30 | **RETIRED — the code it mutated was DELETED.** See below. |
| M-02, M-11, M-54 | **INVALID_MUTANT, re-specified.** M-02 and M-11 anchored on text this round rewrote (`lower()` added for case-insensitive `$user` stripping; the decision filter moved into the three-column `JOIN unnest(...)` form). M-54's anchor was mangled by the DRIVER: a unicode NUL escape inside a non-raw Python string collapsed to one NUL byte, so it could never match the six characters the file contains. All three now resolve exactly once. **Fourth driver defect this sweep** — the reason INVALID_MUTANT is never a silent category. |

### M-30: A MECHANISM REMOVED BECAUSE NOTHING COULD FALSIFY IT

M-30 deleted the migrator's session advisory lock and no test failed. The lock
was added in the fifth chain to cover the ledger's `CREATE TABLE` against a
racing migrator. G-01 then made that creation **tolerate** a lost race
(`LEDGER_RACE_LOST = {42P07, 23505}`) — and with tolerance in place the
advisory lock covers nothing `LOCK TABLE ... ACCESS EXCLUSIVE` does not: by the
time the transaction opens the table exists, which is the only state a table
lock can be taken on.

So there was no property left for a test to hold it to. The choice was between
keeping an unfalsifiable mechanism and removing it; this register's standard is
enforceability rather than intent, so it is **removed**, along with
`LEDGER_LOCK_KEY` and the session-unlock in the `finally` block. The
`RESET lock_timeout` on a healthy connection stays — that is real session state
this runner sets.

**M-30b** replaces it against the mechanism that now actually serializes
migrators: deleting the `LOCK TABLE` must break the concurrent-migrator tests.

A second finding fell out of writing M-51's test. `boundToCommit` was
`verified && ignored.length === 0` — so a run **refused** for
`DISCOVERY_MISSED_TRACKED_TESTS` recorded `boundToCommit: true`: the executed
set declared bound to the commit, in the very evidence file saying a committed
test never ran. It now requires `missing.length === 0` too, and **M-56** holds
that. A test written for a refusal caught a false claim sitting next to it.

### STATE AFTER THIS PASS

Suite 1069/1069, guards 8/8, denominator now 56. Production NOT CERTIFIED.
Fortress NOT CERTIFIED. Nothing pushed, merged or deployed. Every gauntlet
verdict from the sixth chain is bound to a SUPERSEDED tree and must be re-run.

---

## W1.3 EIGHTH PASS — THE 56-MUTANT SWEEP AT `97bb476`

    TALLY {"KILLED": 54, "REAL_SURVIVOR": 2}

All six of the seventh pass's survivors and all three of its invalid mutants
are closed: M-02, M-11 and M-54 now resolve and die; M-23, M-40, M-50 and M-51
are killed by the falsifiers written for them; M-30b kills where retired M-30
could not. Two survivors remain, and they are the same finding twice.

### M-47 AND M-55: A MUTUALLY-MASKING PAIR

Both survived with `1069/1069 PASS` and `fail=0`, including the `S-2`
completion-pass assertion written the round before *specifically* to kill M-47.
The reason is structural, not a missing test:

    `provenDestroyed` has EXACTLY ONE consumer — `clearHealedObligations`.

    M-47 re-adds the `provenDestroyed.push(row)` red-team B7 removed.
         Invisible: `clearHealedObligations`' UPDATE is restricted to
         `state = 'KEY_DESTRUCTION_NOT_PROVEN'`, and a settled obligation is
         `PROVEN_DESTROYED`, so the pushed row reaches a statement that matches
         nothing.

    M-55 removes that `state` filter.
         Invisible: the settlement branch does not put the row in the list in
         the first place.

Remove **either** and nothing changes.

> **CORRECTED BY THE NINTH SECTION — DO NOT RELY ON THE NEXT SENTENCE.** This
> passage claimed that removing BOTH produces `resolved_by = 'PROVIDER'`. Two
> reviewers falsified that independently by execution (red team RT-3, security
> SEC-08): migration **055**'s `..._resolution_named` CHECK refuses the write
> on its own, whatever the application layer and 058 do. It was a masking
> TRIPLE and the third mechanism is the load-bearing one. The classification of
> M-47/M-55 stands; this proof does not. See the ninth section.

Remove **both** and a key proven by a
SETTLEMENT is recorded as `resolved_by = 'PROVIDER'` — a provider that, in the
`NO_VAULT` case, was never asked at all. There is a third guard of the same
invariant too: `recordObligations`' `ON CONFLICT ... WHERE settled_by IS NULL`.

**Three overlapping application-layer guards, and not one of them falsifiable.**
By this register's standard that means the invariant had no control — only
correct behaviour, which is not the same thing and does not survive a
refactor.

### MIGRATION 058, WHICH IS WHERE THE INVARIANT BELONGED

The founder's settlement requirements already say a receipt is **immutable
after completion**. That was enforced for the settlement ROW (the append-only
trigger on `memory_key_destruction_settlements`) and merely *observed* for the
OBLIGATION it resolves. So the invariant moves into the database:

`058_settled_obligation_resolution_immutable` adds
`aaliyah_memory_settled_obligation_frozen()`, a BEFORE UPDATE row trigger that
refuses any change to `state`, `resolved_by`, `settled_by` or
`not_proven_reason` once `settled_by IS NOT NULL`. `observations` and
`last_observed_at` stay writable on purpose: recording that a pass looked again
is not a change to the resolution, and the completion pass does exactly that.

This binds **every** caller, including the admin connection — which is what
made the first version of the test fail, because it tried to un-settle a row to
build its own control.

| id | disposition |
|---|---|
| M-60 | **CLOSED** — `S-2c` drives the refusal as `aaliyah_memory_mutator`, with the exact UPDATE `clearHealedObligations` would issue with both guards gone. |
| M-61 | **CLOSED** — `S-2c`'s second positive control: an UNSETTLED obligation is still freely provider-healed, so a blanket freeze fails too. Without it the trigger could refuse everything and the test would still pass. |
| M-47 | **STRUCTURALLY_UNREACHABLE_WITH_PROOF** — proof above, recorded in the driver's `UNREACHABLE_WITH_PROOF` map, not in prose only. |
| M-55 | **STRUCTURALLY_UNREACHABLE_WITH_PROOF** — same pair. |

The driver now carries that classification as data. If a mutant declared
unreachable is ever KILLED it is reported as
`DECLARED_UNREACHABLE_BUT_KILLED` — a finding about the RECORD — rather than
quietly counted as a pass. Priority EIGHT permits this classification; it does
not permit it silently.

`S-2c` also pins something the privilege map already enforced but no test had
stated: the grants on `memory_key_destruction_obligations` are COLUMN-level.
The mutator may write `state` / `resolved_by` / `not_proven_reason` — that is
ordinary provider healing — and **only the settler may write `settled_by`**. So
the settlement pointer is out of the mutator's reach by privilege, before the
trigger is consulted at all. Each case in `S-2c` runs as the role that actually
holds the grant, so no refusal is a permission error wearing a trigger's
clothes.

### TWO DEFECTS FOUND BY WRITING TESTS, NOT BY THE SWEEP

1. `boundToCommit` was `verified && ignored.length === 0`, so a run **refused**
   for `DISCOVERY_MISSED_TRACKED_TESTS` recorded `boundToCommit: true` — the
   executed set declared bound to the commit in the very evidence file saying a
   committed test never ran. Now requires `missing.length === 0`. Held by M-56.
2. The watchdog exits 2 when it cannot WRITE its evidence — correct, and
   untested. A passing suite whose evidence cannot be recorded must not exit 0;
   that is priority TWO's "monitor failure reporting GREEN". Now tested, held
   by M-59.

And one correction to this round's own work: the first version of the migrator
session-state test compared `SHOW lock_timeout` on a **different** pool. A GUC
is per-session, so it proved nothing. It now asks the migrator's own
`max: 1` pool, which hands back the same backend, and asserts restoration to
the BASELINE rather than to a literal `0` — the watchdog sets `1min` through
PGOPTIONS, so `0` was never the right expectation. Held by M-57 and M-58.

### AN OBSERVED INCOMPLETE RUN, RECORDED RATHER THAN DISCARDED

One full-suite run during this pass was refused with:

    TESTS_NEVER_FINISHED: tests/wave1PoolResiliencePostgres.integration.test.ts queued=15 finished=14
    FILES_WITHOUT_TESTS: tests/wave1TrustedMemoryPostgres.integration.test.ts

It did not reproduce: the two runs before and after it were 1069/1069 and
1072/1072. The probable cause is host contention — the mutation sweep's own
PostgreSQL container was still up on port 54521 alongside the suite's on 54520,
and the pool-resilience file deliberately wedges sockets and lowers the file
descriptor ceiling.

It is recorded because it is a **positive** result for priority TWO: a run in
which one file never finished and another registered zero tests was **refused**,
not reported green. Both refusals are watchdog controls with tests
(`FILES_WITHOUT_TESTS` and the never-finished accounting), and this is the first
time either has fired on the real suite rather than on a fixture.

### STATE AFTER THIS PASS

Suite 1072/1072, guards 8/8, mutation denominator 61. Migrations 001..058.
Contracts still pinned at `7d576681` (a `cp -R` of this session's earlier
provisioning followed a gauntlet symlink back into the contracts worktree and
left an untracked nested copy; it was removed, no tracked file changed, and the
release guard caught it). Production NOT CERTIFIED. Fortress NOT CERTIFIED.
Nothing pushed, merged or deployed.

---

## W1.3 NINTH — THE a9d203d GAUNTLET, AND A CORRECTION TO THIS REGISTER

Four of the eight gates ran against `a9d203d` before the candidate was
withdrawn. **All four returned BLOCK.** Integration, independent
mutation/fuzz, Release Guardian and AEGIS were never dispatched: a candidate
with four blocking verdicts is not a subject for a certification gate.

    reliability          BLOCK   1 CRITICAL, 1 HIGH, 1 LOW
    test falsifiability  BLOCK   1 real survivor + gate contract unmet
    red-team destroyer   BLOCK   2 HIGH, 6 real survivors, 3 MEDIUM, 6 LOW
    security             BLOCK   4 HIGH, 4 MEDIUM, 1 LOW

### FIRST, THE CORRECTION — THIS REGISTER PUBLISHED A FALSE PROOF

The EIGHTH pass classified M-47 and M-55 `STRUCTURALLY_UNREACHABLE_WITH_PROOF`
and stated:

> "Remove **both** and a key proven by a SETTLEMENT is recorded as
> `resolved_by = 'PROVIDER'`"

**That is false, and two reviewers falsified it independently** — the red team
(RT-3) and security (SEC-08), each by execution, neither having seen the
other's work. With both application guards removed AND 058's trigger dropped,
the exact statement `clearHealedObligations` issues is still refused:

    ERROR: violates check constraint
           "memory_key_destruction_obligations_resolution_named"

That CHECK comes from migration **055** and predates both mutants. It requires
`(resolved_by = 'SETTLEMENT') = (settled_by IS NOT NULL)`, so setting
`resolved_by = 'PROVIDER'` on a row with `settled_by` set is a violation
whatever the application layer does. Security's positive control — drop the
trigger AND the CHECK — then returned `UPDATE 1` and `resolved_by = PROVIDER`,
which identifies the load-bearing guard exactly.

So it was a masking **triple**, not a pair, and the third mechanism is the one
that actually holds. Consequences, stated plainly:

- The **classification** of M-47 and M-55 stands. They are unreachable.
- The **proof** was wrong and is replaced by the text above, naming 055.
- **Migration 058 was written against an exploit that cannot occur.** It is
  still a real control — security executed three writes that 055's CHECK
  permits and only the trigger refuses (`not_proven_reason` rewritten on a
  settled row, `settled_by` repointed by the settler, `state` moved to
  `PROVEN_NOT_DESTROYED`) — but its stated justification in migration 058 and
  in the eighth-pass entry was not the reason it was needed.
- **`S-2c`'s discrimination is narrower than credited**: two of its five
  refusal statements are caught by 055's CHECK, not by 058's trigger. The test
  does not distinguish them, so it over-credits the trigger.
- And per **SEC-02**, 058 has a cost the eighth pass did not see: it makes a
  FORGED settled obligation unrepairable, by anyone, including the owner.

How this happened is worth recording, because it is the same failure the
register keeps describing in the code. I enumerated the guards by reading the
two the mutants touched, reasoned about their interaction, and wrote the
conclusion down as a proof — **without executing the removal of both.** A proof
by reasoning about masking is exactly the kind of claim this register's own
standard says to execute. `UNREACHABLE_WITH_PROOF` must be earned by running
the combination, not by arguing it.

### THE FINDINGS

Severity as the reviewer assigned it. `CLOSED` means a falsifier exists that
was verified to FAIL against `a9d203d` and pass after the fix.

| id | sev | gate | finding | status |
|---|---|---|---|---|
| REL-1 | CRITICAL | reliability | Six persistence modules released pooled clients with a bare `client.release()` across twelve sites. pg-pool evicts only when an error is PASSED to `release()` or `_queryable` has already flipped, and pg sets that flag only on a real socket error — so a client-side `Query read timeout` left a connected socket with an abandoned query on the wire, returned to the idle pool. Reproduced against a wedged proxy on `findUnresolved()`, the path `src/server.ts` calls at BOOT: `idleCount:1`, next caller hung. | **CLOSED** |
| REL-2 | HIGH | reliability | `runMailMigrations` had TWO cleanup paths. The ledger-creation phase's catch released without resetting the raised `lock_timeout`, so a real failure (42501) returned a healthy connection carrying a 120s bound. My own "success AND refusal" test covered only the second block. | **CLOSED** |
| REL-3 | LOW | reliability | `completePendingErasures` has no positive "ran, nothing to do" log line, so a silent success and a silent skip look identical. | OPEN |
| TST-1 | — | test | The store's self-verification pre-check was dead: the catch remapped the database's `..._independent_verifier` violation to the same rejection value, so disabling the pre-check left 124/124 passing including `S-4`, the test that claims two-layer enforcement. Sixth instance of the masking pattern. | **CLOSED** |
| RT-1 | HIGH | red team | `evidence` was typed `unknown` and validated NOWHERE — `evidence jsonb NOT NULL` accepts the jsonb value `null`. A settlement with no evidence was recorded, digested to `sha256("null")`, counted sound, wrote destruction evidence, and returned `{verified:true, keysDestroyed:1}` for a subject whose key the provider still reported ACTIVE. | **CLOSED** |
| RT-2 | HIGH | red team | One transaction and one silent catch for a whole obligation batch: with the upsert's `settled_by IS NULL` guard removed, a settled row's refusal rolled back EVERY other key's obligation while the reported counts stayed identical. The ledger is the operator's only route out of `ERASURE_PENDING_SETTLEMENT`. | **CLOSED** |
| SEC-01 | HIGH | security | `settleKeyDestruction` never asks the provider. A settlement is accepted over a key whose provider is AVAILABLE and reports it ALIVE, and that flips `aaliyah_memory_unerased_merged_records` from refuse to accept. The claim in 055 that "the provider's own answer always wins, and a settlement stands in only where the provider structurally cannot answer" is false in both halves. | OPEN |
| SEC-02 | HIGH | security | 055 withholds `settled_by` from the mutator's UPDATE grant and says why — but the INSERT grant one line above is TABLE-level, covering every column. The mutation role forges a SETTLED obligation naming a settlement that does not exist; `UNIQUE (tenant, workspace, key_ref)` then means the honest pass can never record the real state, and **058 makes the forgery unrepairable by anyone including the owner**. | OPEN |
| SEC-03 | HIGH | security | The settlement replay short-circuit compares 7 of 22 columns — not tenant, workspace, subject, authorization or tombstone — and returns `{recorded:true, replay:true}` BEFORE the insert, skipping `scope_unique` and `aaliyah_memory_settlement_binds_real_key()`. The same receipt id under ANOTHER TENANT is reported as a successful replay. | OPEN |
| SEC-04 | HIGH | security | `evidence` is free text on an append-only table, so plaintext an erasure removed survives permanently in the artifact that completes the erasure. Migration 055 names this exact hazard six lines from the column and then constrains the DIGEST instead. Migration 059 constrains the SHAPE but still permits prose. | OPEN |

#### SEC-05, ATTEMPTED AND WITHDRAWN — WHY THE OBVIOUS FIX DOES NOT WORK YET

Schema-qualifying the store's SQL was attempted on 2026-09-18 and **reverted**.
The mechanical change is small — 73 references across seven persistence
modules, plus 27 more in `applicationStore` and `idempotencyStore` — and it
typechecks. It then fails **22 tests**, all of them the read-back divergence
cases in `wave1AliasRegistryPostgres` and `wave1TrustedMemoryPostgres`.

The reason is worth writing down, because it is the finding underneath the
finding. Those tests prove that a read-back whose content diverges from what
was committed is reported UNKNOWN rather than success — and the way they
CREATE that divergence is a dedicated pool whose `search_path` puts a shadow
schema ahead of `public`. Their own comment defends the choice: it "leaves the
production read path completely untouched — no injected failure hook, no
stubbed client". That instinct is right, but the capability it relies on is
**exactly the capability SEC-05 says must not exist**. The fixtures depend on
the vulnerability.

So the fix is not one change but two, and they must land together:

1. Qualify the store's SQL (and, separately, decide whether
   `enterMemoryRole` should stop preserving operator-configured schemas at
   all — that closes the class rather than the instances, and breaks the same
   22 tests for the same reason).
2. Re-found the divergence fixtures on a seam that does not require schema
   resolution to be subvertible. `readBackPool` is already an injection point
   (`wave1AliasRegistryStore.ts:376`), so the honest replacement is to perturb
   the REAL row in `public` on the read-back connection — which is what a
   divergence actually is — rather than to redirect the read elsewhere.

Attempting (1) alone leaves the tree red, and attempting it by weakening the
tests would be the same defect this register keeps recording. Recorded here
rather than half-applied.

**Two migration edits were also reverted as part of this**: the mechanical pass
qualified role names inside `REVOKE … FROM <role>` statements in
`migrations.ts`, which is a syntax error, and would in any case have changed
the content of already-applied migrations and tripped 057's digest guard on
every existing database. A reminder that a regex over SQL does not know what a
noun is.

| SEC-05 | MEDIUM | security | 85 of 99 store SQL statements are unqualified; a shadowed `memory_pii_key_erasures` made the boot pass report all-zero counters over a live key, and `server.ts` logs only non-zero counters, so it is silent AND fail-open. `pool.ts`'s stated reason this is safe ("the erasure SQL is public.-qualified") is false. | OPEN |
| SEC-06 | MEDIUM | security | `pg_db_role_setting` is in no section of the declared privilege map. `ALTER DATABASE … SET session_replication_role='replica'` disables all 44 triggers including 058, leaves `tgenabled` at `'O'`, and produces ZERO map diff — strictly more powerful than the `DISABLE TRIGGER` the map does catch. Superuser precondition. | OPEN |
| SEC-07 | MEDIUM | security | A SECURITY DEFINER function planted in `pg_catalog` — FIRST on every pinned path — is invisible to all five function sections of the map, and was used to read a table the reader is denied. This is K-16/W3, the finding the map was rewritten to catch. | OPEN |
| SEC-08 | — | security | The register's M-47/M-55 proof is factually wrong. Corrected above. | **CLOSED** |
| SEC-09 | LOW | security | `pg_roles.rolconfig` and RLS state also produce zero map diff; harm not demonstrated. | OPEN |
| RT-M4 | — | red team | The three-column `unnest` JOIN the register names as the G-02 fix can be removed with 240/240 passing: `S-13` proves only the other half (the scoped map key). An asymmetrically masked pair, on the fix for the previous round's HIGH. | OPEN |
| RT-M11 | — | red team | The evidence digest's key sort matters only for realistic evidence; every fixture is jsonb-order-invariant by accident, so removing the sort makes every REAL settlement unsound and no test notices. | OPEN |
| RT-M14/15 | — | red team | Two further mutually-masking pairs with 055's CHECK and trigger, where the error mapper returns the same rejection so `S-4`/`S-4b` cannot tell which layer refused. | OPEN |
| RT-M10, RT-M3 | — | red team | Untested guards. | OPEN |
| RT-6 | MEDIUM | red team | A sound settlement is IGNORED by the completion pass whenever a provider is configured and answers `unknown` — K-09's own case. Fails closed, but falsifies settlement as "the bounded way out". | OPEN |
| RT-7 | MEDIUM | red team | A `PROVEN_DESTROYED` settlement is irrevocable: both correction paths are refused and `settlementProven` ignores contradicting decisions. With 058 this is now permanent. | OPEN |
| RT-8 | MEDIUM | red team | `predecessor_state` is a hardcoded literal and settlement is not gated on the state it claims to resolve — recorded for a key with ZERO obligations. | OPEN |
| RT-13 | LOW | red team | A detected forgery over a live key is counted in `contradictions` and never in `notProven`, so `deleteRecord` labels it `erasure_incomplete` — "not finished yet" — for a subject that is not erased. | OPEN |
| RT-14 | LOW | red team | `decided_not_future` bounds only the future; `decidedAt: 1970-01-01` is accepted. | OPEN |

### WHAT THIS MEANS FOR THE W1.3 GREEN LAW

**W1.3 is RED**, and not by one finding. Four independent gates blocked, three
of them on the settlement subsystem that OPTION B introduced — the part of this
work with the least review history. Two separate HIGH findings (RT-1, SEC-01)
each let a subject be represented as ERASED, or flip the database's own erasure
guard, over a key that was demonstrably alive. That is the precise outcome the
founder's decision exists to prevent.

The pattern across all four reports is one thing: **this subsystem's invariants
were enforced in the application layer, and the application layer is where
masking lives.** Every fix that moved an invariant into the database
(migrations 055, 058, 059) is falsifiable; nearly every fix that stayed in
TypeScript turned out to be masked by something else that produced the same
observable answer.

Production: NOT CERTIFIED. Fortress: NOT CERTIFIED. Nothing pushed, merged or
deployed. No gate may be re-run against `a9d203d`: remediation creates a new
descendant, and every verdict above is bound to a tree that no longer exists.

---

## PENDING DELIVERABLE — CHECK-CONSTRAINT DROP-TEST AUDIT

**Founder request, 2026-09-18. Gated on the suite reaching full green.**

Report, from a **freshly migrated** database (not a database tests have run
against — fixtures disable and re-enable triggers, so a used database is not a
clean subject):

1. the exact count of CHECK constraints in `pg_constraint` (`contype = 'c'`),
   enumerated, not summarised;
2. how many of those have a **drop-test**: a test that FAILS when that specific
   constraint is dropped.

The handoff asserts **67 untested**. An independent reader could not reproduce
that number from source, so it is currently an unverified claim and must be
treated as one until (1) and (2) are measured.

**Method, and its cost, stated before it is run.** (2) is a constraint-level
mutation sweep: for each constraint, drop it in a disposable database, run the
suite (or a discriminating subset), and record whether anything fails. That is
one run per constraint. At the current suite size this is hours of wall clock,
not minutes, and it must run in a disposable worktree and database — never
against the implementation database, whose constraints are what the rest of the
suite relies on.

**Why the number matters rather than being bookkeeping.** This round produced
three separate findings where a database constraint was the ONLY thing holding
an invariant while the application layer got the credit: the
`..._resolution_named` CHECK from migration 055 (which falsified this register's
own published proof about M-47/M-55), the `..._independent_verifier` CHECK
behind the dead self-verification pre-check, and migration 023's CHECKs that
make a column/payload mismatch unrepresentable. A CHECK with no drop-test is an
invariant nobody has confirmed is load-bearing — and this register has now been
wrong in both directions about exactly that.

---

## DEFERRED, SCHEDULED — APPROVAL-REVIEW DOUBLE COUNT (OUT OF W1.3 SCOPE)

**MEDIUM · production-reachable · NOT a Trusted Memory defect · founder-scheduled
as the FIRST change after W1.3 certification and BEFORE any repo
consolidation.**

Found by the independent mutation/fuzz gate against `w13-candidate-2`, outside
its mutation sweep, by ordinary execution of the unmutated candidate. Verified
here independently.

### The defect

`createPostgresApplicationStore`'s `approvals.insert`
(`src/persistence/postgres/applicationStore.ts`) omits `reviewed_at` from its
INSERT column list entirely. `approvalFromRow` then synthesises `reviewedAt`
from the database's own `created_at`:

    reviewedAt: new Date(row.created_at as string).toISOString(),

So a caller-supplied `reviewedAt` is silently discarded and replaced.

`listApprovalReviews` (`src/services/followup/recordApprovalReview.ts`)
de-duplicates the in-process bucket against the durable read-back on

    taskId + threadId + reviewedAt

Because the persisted `reviewedAt` is a different instant from the one the
caller supplied, the cached record and the stored record never compare equal
and **every review is counted twice**. The Postgres-backed application store is
what production always uses.

Effect: corrupted approval-review audit trails. Tenant scoping holds; no PII or
erasure boundary is crossed.

### Why it is NOT being fixed in the W1.3 candidate

Follow-up approvals are a different subsystem. Folding the fix into the frozen
candidate would put an approvals change into a diff that seven Trusted Memory
gates were designed to attack — none of them would be attacking it. Scope
discipline is the point of the freeze.

### Why it is NOT merely "logged"

The fix is scheduled as the FIRST change after W1.3 certifies and before the
monorepo consolidation, with its own small gate. A known audit-trail defect
must not become the base the monorepo is built on, which is how "known, logged,
deferred" becomes "carried over". Persisting `reviewedAt` is a one-line change;
the gate around it is what takes the time.

### Relationship to G-11

G-11 records "do not export AALIYAH_DATABASE_URL globally" and calls the
resulting failures an environment mistake rather than a candidate defect. That
disclosure stops one level short: the environment mistake is what makes the
Postgres store run in those unit tests, and the double count underneath it is a
real defect reachable in production without any environment mistake at all.

---

## STANDING RULES (founder, effective 2026-09-19)

Three respins in 24 hours, all test-only, all the same defect class in the same
test: an assertion that reads like a proof and cannot fail. The production
search_path fix has been unchanged since `8958d09`. These rules tighten the
loop that kept finding them one at a time.

### RULE 1 — TEST-ONLY RESPINS DO NOT STOP FOR A DECISION

A fix that changes **no production code** and **no scope**: respin
automatically. Tag the new candidate, record the reason here, continue. Do not
stop for approval.

STOP, and ask, only for:
  - a change to production code,
  - a change of scope,
  - a finding that needs founder judgement.

Verification that a respin qualifies is mechanical and must be shown:
`git diff <prev-tag> <new-tag> -- src/` must be EMPTY.

### RULE 2 — ONE ASSERTION-REACHABILITY SWEEP, NOT ONE PER ROUND

Before the seven reviewers: for EVERY assertion in the W1.3 hardening tests,
prove it can fail by mutating exactly what it checks. Fix every unreachable one
in a SINGLE commit.

This is what a fourth round would have found anyway. Three rounds each found
one: the specific assertions unreachable behind an equality; their ordering
hiding which protection broke; and `assert.equal(leaked, before)` sitting under
a comment claiming "nothing leaked onto the pooled connection" while every path
ended in ROLLBACK, which PostgreSQL treats identically for `SET` and
`SET LOCAL`.

### RULE 3 — RE-RUN SCOPE FOLLOWS WHAT CHANGED

  test-only change      -> suite + destroyer step + mutation/fuzz SCOPED to
                           what the changed test covers
  production-code change -> full gates 1-3

Record which case applied and WHY, here, every time. Nothing is skipped
silently.

**This is a scoping rule, not a shortcut.** If it cannot be said CONFIDENTLY
what a changed test covers, the answer is the full re-run. Uncertainty resolves
toward more verification, never less — which is the whole reason the doctrine
says a changed subject invalidates certification for the changed code.

---

## OPEN — SUITE TEST-COUNT DISCREPANCY (1086 vs 1087)

**Unattributed. Named here rather than dropped, per the founder's rule that a
nondeterministic test in a security suite is a defect until its cause is
named.**

During candidate-3 flake characterisation, one full-suite run reported **1087**
tests with 1 failure where every other run at the same SHA reported **1086**.
The count, not just the outcome, differed.

    run A   tests=1087  pass=1086  fail=1
    run B   tests=1086  pass=1086  fail=0
    run C   tests=1086  pass=1086  fail=0
    run D   tests=1086  pass=1085  fail=1   <- the 42710 migrator race (now fixed)
    run E   tests=1086  pass=1086  fail=0

Runs D and E are explained: that is the intermittent
`type "aaliyah_mail_migrations" already exists` crash, fixed by restoring the
advisory lock. **Run A is not explained.** A differing DENOMINATOR is a
different defect from a differing outcome: it means a test was discovered or
emitted that usually is not.

**Leading hypothesis, unproven.** The assertion-reachability tool spawns a
nested `node --test`, and one of its own negative controls deliberately runs a
FAILING fixture. If that inner run's result ever reaches the outer runner, the
arithmetic is exactly +1 test and +1 failure. The tool now strips
`NODE_TEST_CONTEXT`, which is the mechanism that would allow such leakage, and
the count has been stable at 1088 across three consecutive runs since. That is
consistent with the hypothesis and does not prove it: run A predates the strip,
so the fix may have removed the cause or merely stopped reproducing it.

**Why it stays open.** The watchdog's whole premise is that the executed set is
the commit's set — `DISCOVERY_MISSED_TRACKED_TESTS`, `boundToCommit`, the
discovery binding. A run that can silently report one more test than the commit
contains is a hole in that premise, whatever produced it.

**Handed to the seven reviewers as a named input**, alongside the migrator.

---

## ROOT CAUSE — THE MIGRATOR LOCK WAS DELETED AS A MUTATION CLOSURE

**Verified from git, not from memory.**

    git log -S 'pg_advisory_lock(hashtextextended' -- src/persistence/postgres/migrations.ts

    c2e5747  restore the migrator's advisory lock — I removed a real control
    97bb476  close the 54-mutant sweep's six survivors, retire one mechanism
    99aa656  a client-side ceiling, and migrators that serialize before the ledger exists

The lock was added in `99aa656` to fix K-06, deleted in **`97bb476`** on
2026-09-17, and restored in `c2e5747` tonight.

`97bb476`'s own commit body states the reasoning:

> "M-30 is retired rather than covered. It deleted the migrator's session
> advisory lock and nothing failed, because G-01's tolerant ledger creation
> left the lock covering nothing LOCK TABLE does not. An unfalsifiable
> mechanism is a claim, not a control, so it is removed."

**Two errors, compounding.**

1. **The inference was backwards.** A surviving mutant is evidence about the
   TESTS before it is evidence about the code. "Nothing failed when I deleted
   this" meant the suite did not cover the lock, not that the lock covered
   nothing. The correct response was to write the missing detector — which is
   now `K-06c`, and which takes about forty lines.

2. **The redundancy claim was false.** `LOCK TABLE` was assumed to make the
   advisory lock redundant. It cannot: `LOCK TABLE` needs a table, and the
   table is precisely what the migrators are racing to create. The advisory
   lock needs no table, which is the entire reason it was taken first. The
   race it prevents reappeared as an intermittent
   `type "aaliyah_mail_migrations" already exists` — SQLSTATE 42710, a code the
   tolerance did not even list.

### EVERY CANDIDATE CARRIED IT, AND EVERY GATE PASSED

`97bb476` is an ancestor of **all four** candidates, confirmed by
`git merge-base --is-ancestor`:

    w13-candidate-1  YES        w13-candidate-3  YES
    w13-candidate-2  YES        w13-candidate-4  YES (fixed at e71b51e)

So the exploit replay, the destroyer step and independent mutation/fuzz all ran
against candidates 1, 2 and 3 — a migrator carrying a live production race —
and **none of them found it**. It was found by a flake in a full-suite run.

**That is a finding about the gates, not only about the migrator.** Two gaps,
both now named:

- **No gate attacks the migrator under contention.** The race needs load: six
  concurrent migrators across eight fresh databases produced 0 crashes in 48 on
  an idle machine, while the full suite reproduced it roughly 1 run in 5. Every
  gate ran the migrator quiescent. **Remedied**: the destroyer step now
  includes the migrator under contention.
- **No gate treats "mechanism removed because nothing detected its removal" as
  a red flag in the history.** The commit said so in plain words and three
  rounds of review read past it.

## STANDING RULE — A SURVIVING MUTANT IS NEVER CLOSED BY DELETION

A mutant that survives is closed in exactly one of two ways:

1. **Add a detector.** Write the test that fails when the mechanism is removed.
2. **Prove the mechanism redundant, IN WRITING, and review that proof as a
   PRODUCTION CHANGE** — because deleting a mechanism is one. The proof must be
   EXECUTED, not argued: this register has already published one
   unreachability proof that two reviewers falsified by running the
   combination it merely reasoned about.

**Never by deleting the mechanism because nothing objected.** Silence from a
test suite is a statement about the suite.

### AUDIT OF EVERY PRIOR CLOSURE OF THIS SHAPE ON THIS BRANCH

Listed for the reviewers. `8a0bf05..e71b51e` searched for retirements,
deletions and redundancy claims.

| closure | what was deleted | how it was justified | status |
|---|---|---|---|
| **M-30** (`97bb476`) | the migrator's session advisory lock | "nothing failed" + a FALSE `LOCK TABLE` redundancy claim | **DEFECT. Restored `c2e5747`; detector `K-06c`; falsifier verified.** |
| **TST-1** (`cb392e8`) | the store's self-verification pre-check in `settleKeyDestruction` | redundancy proven by EXECUTION — an independent reviewer disabled it alone and 124/124 still passed, because the catch remapped the database's own `..._independent_verifier` violation to the identical rejection value | **Meets the rule.** Both surviving layers are independently falsifiable: `S-4`'s raw insert holds the DB CHECK, `S-4`'s store call holds the translation. The independent mutation/fuzz gate re-confirmed it by dropping the CHECK live. **Re-verify under the new rule.** |
| **M-47 / M-55** (eighth pass) | nothing deleted — classified `STRUCTURALLY_UNREACHABLE_WITH_PROOF` | proof by REASONING about masking | **Proof was FALSE.** Falsified independently by the red team (RT-3) and security (SEC-08): migration 055's `..._resolution_named` CHECK refuses the write on its own. Corrected; classification survived, reasoning did not. Same root error as M-30, without the deletion. |

The common thread across all three is closing a finding by argument where
execution was available.

---

## GATES 1–3 AGAINST `e71b51e` (w13-candidate-4) — ALL PASS

Run in the builder's session. The seven reviewers and AEGIS deliberately are
NOT, for the reason in the handoff.

### Gate 1 — exploit replay: DEAD

The durable reproducer on a fresh cluster, then the store's real
`enterMemoryRole` as the poisoned role, with the shadow schema, the planted
`aaliyah_memory_unerased_merged_records` and the mutator's EXECUTE on the fake
all still present:

    inherits:     opsched, public
    STORE PIN:    pg_catalog, public, pg_temp
    table ->      public
    guard helper -> public
    fabricated rows visible: 0
    path after COMMIT: opsched, public   (the pin is transaction-local)

### Gate 2 — 8 destroyers, 8 DETECTED, each by its own named assertion

    D1 pin removed entirely            the pin never ran...
    D2 pg_temp-last removed            pg_temp is not last
    D3 $user restored                  $user survived in some casing
    D4 old inheriting pin              a session-chosen schema survived
    D5 pin not transaction-local       the pin is not transaction-local...
    D6 migrator advisory lock removed  no migrator ever waited on the ledger...
    D7 42710 dropped from tolerance    already exists (42710)
    D8 lock removed, UNDER CONTENTION  no migrator ever waited on the ledger...

`pool.ts` and `migrations.ts` restored byte-for-byte. **D8 closes the gap that
let the M-30 defect through three candidates**: every prior gate ran the
migrator quiescent, and the race needs load — 0 crashes in 48 idle, ~1 run in 5
under full-suite pressure.

### Gate 3 — independent mutation/fuzz: MUTATION_GREEN, 10 killed, 0 survivors

`aaliyah-w13-evidence/e71b51e/reviews/06-mutation-fuzz.md`. Its own hygiene
claims verified from outside: worktree clean at the SHA, no stray databases,
guards 8/8 after all mutation activity.

Most load-bearing results:

- **MUT-1, the exact M-30 deletion, KILLED by K-06c.** The defect that survived
  three candidates is now caught by a single-point mutation.
- **MUT-4** (inverting the tolerance's presence re-check) was killed twice —
  by K-06b, and by a REAL load crash in `K-06 REOPENED` on
  `pg_type_typname_nsp_index`. That is the original K-06 signature reproducing
  under contention, which corroborates the root-cause analysis independently.
- **M-47/M-55 re-executed at THIS SHA, two ways** rather than carried forward:
  isolated SQL with every trigger on the obligations table disabled, proving
  055's bare CHECK alone still refuses (23514); and full-stack with both
  mutants applied to the real source, 132/132 still passing. The register's
  earlier proof of this was falsified once, so it is never inherited.
- SEC-01's provider-contradiction gate re-inverted → KILLED, 17/132 red
  including `S-4f`.
- 537-input fuzz of the tolerated-SQLSTATE boundary: 0 mismatches. Load fuzz at
  8 new-build + 3 old-build concurrent migrators × 5 trials: clean.

**Disclosed by the reviewer rather than hidden:** its first baseline run used
the mutant-judging bound (`--test-timeout-ms 60000`) on the BASELINE and got a
false FAIL on a legitimately slow pool-resilience test; re-run with defaults,
clean. Correct handling — a harness setting that changes what a measurement
means is exactly what this round keeps tripping over.

**Explicitly NOT covered by gate 3**, carried forward: `pool.ts`'s K-05 guard
was observed passing but not itself mutated; no traversal / tenant-escape /
replay attacks outside the migrator and settlement surfaces; concurrency fuzz
was 5 trials at one concentration, not a sweep; `S-2e` and `S-6b` were observed
passing but NOT independently mutated, so they are an observation and not a
control this gate verified.

---

## ADJUDICATED — W1.3 candidate-4 (`e71b51e`) IS **RED. NOT CERTIFIED.**

Full document: `aaliyah-w13-evidence/e71b51e/AEGIS-ADJUDICATION.md`, committed
verbatim. Rendered by an independent adjudicator seat — cloud clone of origin,
not the builder, not the coordinator, not any gate, saw no work being produced.
Subject `e71b51e`, contracts `7d57668`, evidence `reviews/` at `1b0499f`.

**Five of seven gates block.** The Test Falsifiability gate carries a Critical
(F5) sufficient on its own under the weakest-mandatory-domain rule. Production:
NOT CERTIFIED. Fortress: NOT CERTIFIED.

### WHAT STANDS

**The migrator fix of this round is SOUND.** Gate 3 reproduced the race at will
without the lock — 15,965 lost races in 21,600 — and eliminated it with the lock,
0 in 9,600. Crash recovery clean. Both restored controls have named detectors.
The work recorded two sections above in `ROOT CAUSE — THE MIGRATOR LOCK WAS
DELETED AS A MUTATION CLOSURE` survives adjudication intact.

### WHAT BLOCKS — FIVE ROOT CAUSES, NOT TWENTY FINDINGS

- **RC-1 the measuring instrument is unreliable.** Three gates, three
  denominators, one SHA: gate 1 saw 1088/1088 zero times in five runs, gate 3
  once in five, gate 5 took 118 failures then 471/471 on a recreated database.
  Until this is repaired, EVERY pass claim of this round is unproven — including
  this register's own `GATES 1–3 AGAINST e71b51e — ALL PASS` section and the
  coordinator's three clean serial runs. That section is not withdrawn; it is
  **suspended pending a working instrument.**
- **RC-2 the ledger is trusted where effects should be verified.** It certifies
  schemas never applied; the pre-057 upgrade path launders an edited migration
  permanently. Nothing reads back what the migrator claims it did.
- **RC-3 controls without detectors are STILL shipping** — two days after this
  branch adopted the standing rule against exactly that. 17 CHECK constraints,
  3 pool bounds, the G-02 tenant-crossover JOIN, and the migrator lock's
  ORDERING (the lock is held, but no destroyer reorders, so K-06c cannot see a
  reorder).
- **RC-4 builder-produced gate evidence is forgeable** by one git command.
  `assume-unchanged` is invisible to `git status`, on which the hygiene claims
  rest. Confirmed by reading: no such check exists in `scripts/` or CI.
- **RC-5 tenant isolation has no database backstop.** Disclosed at
  `migrations.ts:25-27`, outside W1.3's claim. Founder decision, below.

### THE PENDING CHECK-CONSTRAINT AUDIT IS ANSWERED

The `PENDING DELIVERABLE — CHECK-CONSTRAINT DROP-TEST AUDIT` section above
recorded that an independent reader could not reproduce the **67 untested**
figure. Gate 7 (Data & Persistence) settles it:

    population   162 CHECK constraints
    untested     17
    triggers     0 of 56

**The "67" figure is WITHDRAWN.** It appears above at three places in this
register and is superseded wherever it appears. Of the 17, the **8** that are
the sole enforcement on the key-destruction settlement path get drop-tests
first; the other 9 take a detector or an executed redundancy proof.

### DISPUTES RESOLVED, SEVERITIES MOVED

- RT-M4 / the G-02 three-column unnest JOIN: **Important and blocking.** Gate 4
  stands over gate 2. The axes differed — exploitability today vs detectability,
  and the standing rule governs detectability.
- The migrator: gate 3 (SOUND) and gate 4 (lock defeated by reordering) **both
  stand.** The code is correct; the detector cannot see a reorder.
- The 1086/1087 denominator: **OPEN as a root cause, closed as a risk** once a
  committed test-name manifest makes a delta a refusal instead of a mystery.
- D-05 (no RLS): **down** to non-blocking for W1.3 — a disclosed limitation
  outside the claimed boundary is not a defect in the candidate. It is a defect
  in the product plan if Aaliyah ships multi-tenant. Founder decision B.
- SEC-E (privilege map blind to SECURITY DEFINER bodies): Medium, scheduled.

### PROCESS FINDINGS

1. **Reviewer independence found what builder-run gates missed, for the second
   candidate running.** Gates 1–3 passed on candidates 1, 2, 3 AND 4. The seven
   independent gates blocked candidate-4 five ways. The separation is not a
   formality, and R4.2 makes it permanent: gates 1–3 are never again run by the
   builder's session.
2. **Concurrent dispatch corrupted timing evidence** — load 76 on 14 CPUs, by
   the coordinator's own account. Next round: at most two gates concurrent,
   timing-sensitive gates (1, 3) alone on a quiet host.
3. **The same defect shape, SIXTH time.** A control whose removal nothing
   detects, or an assertion that cannot fail. It has now appeared in tests, in
   verification tooling, in a published proof, and in the hygiene evidence
   itself. R3 and R4 are the standing rule's enforcement.

### THE WORK ORDER

`docs/W13_R1_WORK_ORDER.md`. **R1 — repair the instrument — gates everything
else.** Nothing but R1 until its acceptance is met: five consecutive full-suite
runs, serial, quiet host, pristine database, executed set equal to a committed
manifest, all PASS; then five more on a used database; both cells reported.

R2 (ledger integrity), R3 (controls without detectors), R4 (provenance) follow.
Candidate-5 returns to the adjudicator seat, with gates 1–3 run by the review
side.

### FOUNDER DECISIONS OUTSTANDING

- **A.** Merge/split identity semantics. Unchanged from the handoff. Blocks W1.4.
- **B.** Database-enforced tenant isolation. Adjudicator recommends RLS on all
  21 `memory_%` tables as a scheduled W1.4 item, NOT folded into W1.3.
- **C.** Confirm Data & Persistence as the permanent seventh gate. The
  coordinator inferred it because only six gate files existed, and it produced
  the D-09 headline.

### FOUNDER DECISION C — ANSWERED 2026-09-20

**Data & Persistence is CONFIRMED as the permanent seventh gate.** It is no
longer an inference by the coordinator; it is a named, standing gate of the
review set, and candidate-5 is reviewed by all seven on that basis.

This closes the anomaly that the gate which produced the D-09 headline — and
which settles this register's previously-unreproducible CHECK-constraint
figures at 162 / 17 / 0-of-56 — existed only because the coordinator noticed
six gate files where seven were expected. The CHECK-constraint drop-test audit
belongs to this gate structurally and is now owned rather than orphaned.

**A (merge/split identity semantics) and B (database-enforced tenant isolation)
remain OPEN.** B carries the adjudicator's recommendation — RLS on all 21
`memory_%` tables as a scheduled W1.4 item, not folded into W1.3 — and is
deferred deliberately for consideration, not by oversight. Neither blocks R1.

### BRANCH WRITER HANDOFF — R1

**Sole-writer discipline, effective at this commit.** The session that recorded
the adjudication and issued the work order is **read-only on this branch** from
here. A fresh builder session opens in `~/aaliyah-w13/aaliyah-wave1-core` with
`docs/W13_R1_WORK_ORDER.md` as its first input and is the **sole writer** until
R1 acceptance is met.

The reason is this round's own lesson rather than preference: two writers on one
branch is how evidence is lost, and this branch's findings have repeatedly been
about records that could not be trusted to mean what they said. The retiring
session's reasoning is already in this register and in the commit messages,
which is where it belongs — it is not carried forward in a context window.

Note this is distinct from, and narrower than, **R4.2**: R4.2 bars the BUILDER
from running gates 1–3 at all, permanently. This entry only fixes who may write
to the branch during R1.

---

## R1 — OVERNIGHT BUILDER RUN 2026-09-20/21: R1.1 DONE, R1.2 PREMISE DID NOT REPRODUCE, STOPPED

Builder session, sole writer. Every measurement below was produced by
`aaliyah-w13-evidence/r1/tools/run-suite.sh` against the builder's own
PostgreSQL 16.14 container `aaliyah-w13-r1` on `127.0.0.1:54610`, serial, one
suite at a time, no reviewer environment running. Server logging set to
`log_statement=ddl` and `log_line_prefix='%m [%p] db=%d app=%a '` for every
run, so each administrator termination carries a pid and a database. Every
run's evidence JSON, spec output, cluster fingerprint and server log is in
`aaliyah-w13-evidence/r1/runs/`; the index is `runs/INDEX.tsv`.

### R1.1 — DONE (`fe78fd0`, proof `7cbc691`)

K-05 now releases before it asserts; the hand-release store test (F6) and the
wedged-transport test close the wedging proxy before draining; every
`pool.end()` in those three tests is bounded (`endWithin`, 15 s).

    BEFORE (98321de), K-05 inverted:  FAIL scope=FOCUSED — HUNG_WORKER, NO_SUMMARY,
                                      K-05 timed out 240002ms, failures[] EMPTY
    AFTER (fe78fd0), K-05 assert.fail: FAIL tests=17 pass=16 fail=1 — reported in 8.68ms, named
    AFTER (fe78fd0), gate 1's D3 mutant: FAIL tests=17 pass=15 fail=2 — F6's own message at 70s

**NEW FINDING, not fixed (production code outside R1).** The reason K-05's
assertion can fail at all is NOT the terminate racing the next query (0 of 800
here). pg rejects the next query on a terminated client in one of TWO real
shapes: `57P01` (787/800) or the UN-CODED `Client has encountered a connection
error and is not queryable` (13/800; 100/100 once the backend is already gone).
`isConnectionAmbiguous` (`src/persistence/postgres/pool.ts`) does not classify
the second. pg-pool evicts that client anyway (`pg-pool/index.js:392`,
`!client._queryable`), so production still destroys it — the classifier is
incomplete and K-05 is timing-dependent on it. Observed live: the plain
inversion of K-05 PASSED on one run (`r1.1-after-k05-inverted`), i.e. the
un-inverted test would have failed. **Closing it needs a change to `pool.ts`,
which R1 does not name. Handed to the founder.**

### R1.2 — PREMISE RE-EXECUTED, DID NOT REPRODUCE → STOP (work order R1.2.1)

At `7cbc691` (R1.1 only), full suite, serial, quiet host (load 1.8-7.1):

    P1 pristine  WATCHDOG VERDICT: FAIL scope=FULL_SUITE tests=1088 pass=1087 fail=1 cancelled=0 skipped=0 todo=0
    U1 used      WATCHDOG VERDICT: FAIL scope=FULL_SUITE tests=1088 pass=1087 fail=1 cancelled=0 skipped=0 todo=0
    U2 used      WATCHDOG VERDICT: PASS scope=FULL_SUITE tests=1088 pass=1088 fail=0 cancelled=0 skipped=0 todo=0

The one failure in P1 and U1 is the SAME test, in both states:
`R-1 K-02 (probe1)` — "a transaction stayed open 1003ms / 929ms across a
1500ms provider call". A used database produced a PASS; a pristine one
produced the failure. **A used database does not change the verdict here.**
Per the work order: stop and report; the root cause is elsewhere.

**What the premise run DID find — the cause of the one failure, EXECUTED.**
probe1 measures the oldest `idle in transaction` session in the WHOLE
database, not its own. Instrumented in a disposable worktree only
(`r1/probes/k02-probe1-culprit-diagnostic.DIAGNOSTIC-ONLY.patch`, never
committed to tests), three more used runs: PASS, PASS, FAIL. On the FAIL:

    R1-DIAG probe1 maxIdleTxMs=995 culprit={"pid":4002,"state":"idle in transaction",
      "q":"UPDATE watchdog_fixture_78003 SET id = 1 WHERE id = 1","age":995}

That session belongs to `tests/testWatchdog.test.ts`'s DB-blocking fixtures,
running in parallel against the same `aaliyah_test`. **K-02 probe1 fails on
another FILE's transaction.** That is shared-database contamination — but
structural and per-run, not residual state, which is why pristine vs used
made no difference. Neither file is named in R1; not fixed.

Sample-size disclosure: two used runs plus three diagnostic used runs, one
pristine. Gate 5's I-9 "used" was a database left by a SIGTERMed run, a
different state from "the database left by the previous run", which is the
definition this run was given. The I-9 shape was NOT tested under that other
definition.

### R1.5 — ISSUER NAMED, EXECUTED

Every termination in P1/U1/U2 attributed from the server log:

    P1  7 on aaliyah_test   3 on aaliyah_concurrent_n5
    U1  7 on aaliyah_test
    U2  7 on aaliyah_test

The 7 on `aaliyah_test` are the pool-resilience file's own deliberate
`pg_terminate_backend` calls (6 probes + K-05). The 3 on
`aaliyah_concurrent_n5` land in the SAME millisecond as the replay file's own
`DROP DATABASE aaliyah_concurrent_n5 WITH (FORCE)` (pid 1711): sockets of that
test's pools still open after `pool.end()` resolved. The n5 pools carry an
`'error'` listener, so nothing failed. **The POSITIVE CONTROL runs the same
teardown with NO listener.** Isolated repro of its exact teardown
(`r1/probes/positive-control-teardown.cjs`): 200 iterations, **2 uncaught
57P01 after `end()` resolved, matching 2 server-side terminations on that
database 1:1**. The issuer of gate 3's R-14 is the positive control's OWN
`withFreshDatabase` cleanup, not another file. Not fixed (stopped).

### R1.3 / R1.4 / R1.6 — DRAFTED, NOT EXECUTED, NOT COMMITTED TO THE TREE

`aaliyah-w13-evidence/r1/wip/R1.3-R1.4-R1.6-UNEXECUTED.patch` applies cleanly
to `7cbc691`. It has NEVER been run. Contents: a committed-manifest
denominator with SYNTHETIC_FILE_ENTRIES / DENOMINATOR_NOT_PINNED /
MANIFEST_DELTA refusals, `DISCOVERY_VACUOUS`, a manifest file-set check in
`--verify-discovery`, the `ci-guards.sh` private temp file, R1.4's subset
assertion against an exported `LEDGER_RACE_LOST`, and eight watchdog tests.
It contains no manifest yet: generating one needs a clean full run.

### ASSUMPTIONS TAKEN WITHOUT AN ANSWER (conservative reading, recorded)

1. **The 2×2's "concurrent" column was not run.** The run rules forbid a suite
   concurrent with another suite. Only the serial column was measured.
2. "Used" = the database the previous run left (the run's definition), not a
   database left by a killed run.
3. R1.4 requires referencing the production constant, so the draft exports
   `LEDGER_RACE_LOST` from `migrations.ts` (named in R1.4; no runtime change).
   Unexecuted.
4. The adjudication says guard 8 must FAIL "when zero tests executed"; taken
   literally that fails it always (it runs no tests). The work order's reading
   (FAIL on an empty DISCOVERED set; vacuous ≠ verified) was drafted.
5. The `DISCOVERY_VACUOUS` path is not reachable through the entrypoint at
   this SHA (`usage()` exits 2 on zero FULL_SUITE files first). The draft makes
   it reachable as a FAIL.
6. The builder used its own container on :54610, not any reviewer container.

---

## R1 — CONTINUED 2026-09-21 AFTER FOUNDER ANSWERS: R1 ACCEPTANCE MET at `fa14db0`

### FOUNDER ANSWERS AND RULE CHANGE (2026-09-21, ~03:00)

1. R1.5 is the main thread; the K-02 probe1 fix is in R1 scope. R1's scope is
   "the instrument", not a file list. Test-only.
2. `isConnectionAmbiguous` may classify pg's "not queryable" rejection as
   ambiguous — ONLY that exact pg shape, never code-less errors generally.
   Separate commit, own detector, recorded here as a production change.
3. Test I-9 against a database left by a KILLED run (gate 5's actual
   condition). If it reproduces, R1.2 returns as "refuse a database left by
   abnormal exit"; if not, I-9 closes as not reproduced.

**RULE CHANGE, standing:** a premise that fails to reproduce stops ITS OWN
item only. Every independent item continues. (The overnight run stopped the
whole run at 22:15 and left R1.3/R1.4/R1.6 unexecuted for five hours.)

Builder's reading, recorded: the founder's note described the 57P01 as K-02
probe1's; the report named two DISTINCT defects — the 57P01 is the replay
POSITIVE CONTROL's own FORCE-drop (R1.5), and K-02 probe1 is cross-file
contamination. Answer 1 was applied to both; both are test-only.

### WHAT LANDED

| item | commit(s) | executed proof |
|---|---|---|
| R1.3 manifest + refusals | `f54adc1`, `27b545e`, manifest `565d6d3` | 9 mutants, 9 killed (`d0b4c14`); M7 survived first, detector added |
| R1.4 full LEDGER_RACE_LOST | `f54adc1` | mutant dropping 23505 killed by R1.4's control, K-06b, K-06 REOPENED |
| R1.6 vacuous discovery, private temp file | `f54adc1` | M1/M1b killed; guard 8 PASS on the real repo |
| R1.5 listeners where missing | `d65cb05` | isolated: no listener 2 uncaught / 2 terminations; listener 0 uncaught / 4 absorbed / 4 terminations |
| K-02 probe1 scoped to own sessions | `7eadfa1`, proof `3859022` | old probe FAILS on another session (1493ms); scoped PASSES it and still FAILS the store's own held tx (1473ms) |
| **PRODUCTION: pool.ts** | `fd7432a`, proof `e045070` | K-05b kills "shape unrecognised" and "widened to code-less" |
| I-9 after a killed run | `fa14db0` | 3/3 PASS after SIGTERM at 45/90/150s — **NOT REPRODUCED, CLOSED** |

### PRODUCTION CHANGE — `src/persistence/postgres/pool.ts` (`fd7432a`)

`isConnectionAmbiguous` returns true for an error whose message is EXACTLY
`PG_NOT_QUERYABLE_AFTER_CONNECTION_ERROR` = "Client has encountered a
connection error and is not queryable" (node-postgres, pg/lib/client.js).
Nothing else changed. `LEDGER_RACE_LOST` in `migrations.ts` is now exported
(`f54adc1`), no runtime change. `.aegis-frozen.sha256` covers neither file.
**Candidate-5 is therefore a production-code descendant: full gates 1–3 run
by the review side (register rule 3, R4.2).**

### I-9 — CLOSED AS NOT REPRODUCED

Two definitions of "used", both measured, neither changes the verdict:
the database a clean previous run left (`fd71d4d`: the single failure was
K-02 probe1 in both states, and a used run passed), and the database a
SIGTERMed run left (3/3 PASS, with real residue: 60 ledger rows, 99
record versions). R1.2's harness refusal was NOT built. Gate 5's 118
failures remain unexplained by database state; the two contamination
mechanisms R1 found are the better-supported candidates, unproven for that
specific run.

### R1 ACCEPTANCE — MET at `fa14db0` (`9e83dd3`)

Five pristine, then five used, serial, quiet host, clean tree, executed set
equal to the committed manifest every run:

    pristine 1-5  WATCHDOG VERDICT: PASS scope=FULL_SUITE tests=1098 pass=1098 fail=0 cancelled=0 skipped=0 todo=0   (x5)
    used 1-5      WATCHDOG VERDICT: PASS scope=FULL_SUITE tests=1098 pass=1098 fail=0 cancelled=0 skipped=0 todo=0   (x5)

80 server-side terminations across the ten, all attributed (8 per run, all
deliberate). The used cell PASSED: the I-9 hypothesis is falsified, as the
work order anticipated.

### WHAT R1 DID NOT COVER

- The 2×2's CONCURRENT column: never run (run rules forbid concurrent suites).
- `boundToCommit` still excludes `untracked` (RT4-5's field-level point). The
  manifest now refuses the attack it enabled, but the field is unchanged — R4.
- `ci-guards.sh` still writes `/tmp/frozen.out` and
  `/tmp/contracts-provenance.out` (I-4's other two paths) — R4.3.
- The pool-resilience `adminPool` still has no client-side bound (gate 3
  R-13 point 2).
- Gates 1–3 at the new SHA: not run here, by R4.2.
