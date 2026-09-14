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

## Cross-cutting note carried forward from the W1.3 review

The W1.3 candidate's suite was green while 25 of 31 applied mutations survived,
including a mutant that deleted 71 of 73 lines of runtime verification. Any
entry above that is later claimed CLOSED must be closed with tests that
**fail when the control is deleted** — not merely tests that pass while it is
present. See founder authorization Part G, mandatory mutation targets.
