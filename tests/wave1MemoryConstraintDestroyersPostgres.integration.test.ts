import assert from "node:assert/strict";
import test, { after, before, beforeEach } from "node:test";
import { Pool } from "pg";

import { runMailMigrations } from "../src/persistence/postgres/migrations";
import {
  lockSharedMemoryTables,
  type SharedTableLock,
} from "./support/sharedMemoryTables";

/**
 * EVERY CHECK CONSTRAINT, INDIVIDUALLY DESTROYED.
 *
 * A mutation sweep reported that 67 of the CHECK constraints on the five
 * memory tables had never been drop-tested: the store cannot produce a row
 * that violates them — that is what the store is for — so the constraints had
 * no reachable input from the suite and no killing test. A replica, a restored
 * backup, a migration, or a service that bypasses the store has no store in
 * front of it, and those constraints are the only thing standing there.
 *
 * Each case below writes a row DIRECTLY, as the table owner, that is valid in
 * every respect except the one constraint it names, and pins that constraint
 * by name. Dropping the constraint makes the row land and the case fail.
 *
 * THE POSITIVE CONTROL PER TABLE IS WHAT MAKES THE REST MEAN ANYTHING. It
 * inserts the unmodified base row and asserts the failure is NOT a
 * `check_violation` — for the tables whose AFTER triggers demand a consumed
 * authorization, the base row reaches those triggers, which proves every CHECK
 * on the way passed. Without it, all of these would pass against a table that
 * rejected everything.
 */

const DB_URL =
  process.env.AALIYAH_TEST_DATABASE_URL ??
  "postgres://postgres:test@127.0.0.1:54329/aaliyah_test";

const SCOPE = {
  tenantId: "tenant-destroy",
  workspaceId: "workspace-destroy",
  principalId: "principal-destroy",
  userId: "user-destroy",
};
const RECORD_ID = "record-destroy-001";
const DIGEST_A = `sha256:${"a".repeat(64)}`;
const DIGEST_B = `sha256:${"b".repeat(64)}`;

let adminPool: Pool;
let sharedTableLock: SharedTableLock;

before(async () => {
  adminPool = new Pool({ connectionString: DB_URL, max: 4 });
  sharedTableLock = await lockSharedMemoryTables(adminPool);
  await runMailMigrations(adminPool);
  // `memory_alias_bindings` carries a FOREIGN KEY onto the tenant's alias
  // policy — absence is refusal, by design. Without this row the base binding
  // is refused by the FK and never reaches the CHECK layer at all, which the
  // positive control is what caught.
  await adminPool.query(
    `INSERT INTO memory_alias_tenant_policy
       (tenant_id, cross_workspace_policy, set_by_actor_id, policy_version)
     VALUES ($1, 'workspace_isolated', 'actor.memory-steward', 'alias-policy/v1')
     ON CONFLICT DO NOTHING`,
    [SCOPE.tenantId],
  );
});

after(async () => {
  await sharedTableLock.release();
  await adminPool.end();
});

beforeEach(async () => {
  await adminPool.query(
    `TRUNCATE memory_identity_edges,
              memory_alias_bindings,
              memory_record_versions,
              memory_authorization_receipts,
              memory_authorization_nonces,
              memory_mutation_receipts,
              memory_mutation_attempts,
              memory_tombstones
     RESTART IDENTITY`,
  );
});

type Row = Record<string, unknown>;

/** Insert a row built from a column map. Values are bound, never interpolated. */
async function insertRow(table: string, row: Row): Promise<void> {
  const columns = Object.keys(row);
  const values = columns.map((c) => {
    const v = row[c];
    return v !== null && typeof v === "object" ? JSON.stringify(v) : v;
  });
  const placeholders = columns.map((c, i) => {
    const v = row[c];
    return v !== null && typeof v === "object" ? `$${i + 1}::jsonb` : `$${i + 1}`;
  });
  await adminPool.query(
    `INSERT INTO ${table} (${columns.join(", ")})
     VALUES (${placeholders.join(", ")})`,
    values,
  );
}

/**
 * Declare one destroyer. `mutate` receives a fresh base row and returns the
 * row that must violate exactly `constraint`.
 */
type Destroyer = { constraint: string; why: string; mutate(row: Row): Row };

function destroyers(
  table: string,
  base: () => Row,
  cases: readonly Destroyer[],
  positiveControl: { expect: RegExp; note: string },
): void {
  test(`${table}: the base row passes every CHECK — ${positiveControl.note}`, async () => {
    // Without this, every case below would pass against a table that refused
    // all inserts for some entirely unrelated reason.
    await assert.rejects(
      () => insertRow(table, base()),
      (error: unknown) => {
        assert.match(String(error), positiveControl.expect);
        assert.doesNotMatch(String(error), /violates check constraint/);
        return true;
      },
    );
  });

  for (const destroyer of cases) {
    test(`${table}: ${destroyer.constraint} — ${destroyer.why}`, async () => {
      await assert.rejects(
        () => insertRow(table, destroyer.mutate(base())),
        (error: unknown) => {
          // Pinned by NAME. A generic "it failed" would pass when the row was
          // refused by a different constraint entirely, which is exactly how a
          // constraint appears covered while never having been exercised.
          assert.match(String(error), new RegExp(destroyer.constraint));
          return true;
        },
      );
    });
  }
}

// ---------------------------------------------------------------------------
// memory_authorization_nonces
// ---------------------------------------------------------------------------

function nonceBase(): Row {
  return {
    tenant_id: SCOPE.tenantId,
    workspace_id: SCOPE.workspaceId,
    binding_digest: DIGEST_A,
    authorization_id: "destroy-auth-000000000001",
    action: "correct",
    target_record_id: RECORD_ID,
    issued_at: new Date(Date.now() - 60_000).toISOString(),
    expires_at: new Date(Date.now() + 3_600_000).toISOString(),
  };
}

test("memory_authorization_nonces: the base row is ACCEPTED, so the cases below are not passing on a broken table", async () => {
  // This table has no witness trigger, so its positive control is a real
  // insert rather than a reached-the-trigger failure.
  await insertRow("memory_authorization_nonces", nonceBase());
  const count = await adminPool.query(
    `SELECT count(*)::int AS n FROM memory_authorization_nonces`,
  );
  assert.equal(count.rows[0].n, 1);
});

for (const destroyer of [
  {
    constraint: "memory_authorization_nonces_digest_form",
    why: "a binding digest that is not a sha256 reference",
    mutate: (r: Row) => ({ ...r, binding_digest: "not-a-digest" }),
  },
  {
    constraint: "memory_authorization_nonces_window",
    why: "an expiry at or before issuance is a token that was never live",
    mutate: (r: Row) => ({ ...r, expires_at: r.issued_at }),
  },
  {
    constraint: "memory_authorization_nonces_max_validity",
    why: "a token good for longer than a day is an approval that outlives its review",
    mutate: (r: Row) => ({
      ...r,
      expires_at: new Date(Date.now() + 25 * 3_600_000).toISOString(),
    }),
  },
  {
    constraint: "memory_authorization_nonces_consumption_witness",
    why: "consumed with no receipt naming what consumed it is an unattributable spend",
    mutate: (r: Row) => ({ ...r, consumed_at: new Date().toISOString() }),
  },
  {
    constraint: "memory_authorization_nonces_not_both",
    why: "a token cannot be both spent and revoked",
    mutate: (r: Row) => ({
      ...r,
      consumed_at: new Date().toISOString(),
      consumed_by_mutation_receipt_id: "mutation.destroy",
      revoked_at: new Date().toISOString(),
    }),
  },
]) {
  test(`memory_authorization_nonces: ${destroyer.constraint} — ${destroyer.why}`, async () => {
    await assert.rejects(
      () => insertRow("memory_authorization_nonces", destroyer.mutate(nonceBase())),
      (error: unknown) => {
        assert.match(String(error), new RegExp(destroyer.constraint));
        return true;
      },
    );
  });
}

// ---------------------------------------------------------------------------
// memory_record_versions
// ---------------------------------------------------------------------------

function versionPayload(overrides: Row = {}): Row {
  return {
    schemaVersion: "aaliyah.trusted-memory.record/v1",
    recordId: RECORD_ID,
    version: 1,
    state: "active",
    scope: { ...SCOPE },
    content: { note: "destroyer" },
    contentDigest: DIGEST_A,
    predecessorDigest: null,
    authorizationId: "destroy-auth-000000000001",
    mutationReceiptId: "mutation.destroy.001",
    createdAt: new Date().toISOString(),
    ...overrides,
  };
}

function versionBase(): Row {
  return {
    tenant_id: SCOPE.tenantId,
    workspace_id: SCOPE.workspaceId,
    principal_id: SCOPE.principalId,
    user_id: SCOPE.userId,
    record_id: RECORD_ID,
    version: 1,
    state: "active",
    content_digest: DIGEST_A,
    predecessor_digest: null,
    authorization_id: "destroy-auth-000000000001",
    mutation_receipt_id: "mutation.destroy.001",
    payload: versionPayload(),
  };
}

destroyers(
  "memory_record_versions",
  versionBase,
  [
    {
      constraint: "memory_record_versions_content_digest_form",
      why: "a content digest that is not a sha256 reference",
      mutate: (r) => ({
        ...r,
        content_digest: "sha256:short",
        payload: versionPayload({ contentDigest: "sha256:short" }),
      }),
    },
    {
      constraint: "memory_record_versions_predecessor_digest_form",
      why: "a predecessor digest that is not a sha256 reference",
      mutate: (r) => ({
        ...r,
        version: 2,
        predecessor_digest: "nonsense",
        payload: versionPayload({ version: 2, predecessorDigest: "nonsense" }),
      }),
    },
    {
      constraint: "memory_record_versions_version_positive",
      why: "version zero is a chain that starts before its own beginning",
      // Carries a predecessor on purpose: version 0 with a NULL predecessor
      // violates `genesis_predecessor` too, and that one fires first, so the
      // case would have been pinned to a constraint it was not testing.
      mutate: (r) => ({
        ...r,
        version: 0,
        predecessor_digest: DIGEST_B,
        payload: versionPayload({ version: 0, predecessorDigest: DIGEST_B }),
      }),
    },
    {
      constraint: "memory_record_versions_state_domain",
      why: "a state outside active/deleted",
      mutate: (r) => ({
        ...r,
        state: "archived",
        payload: versionPayload({ state: "archived" }),
      }),
    },
    {
      constraint: "memory_record_versions_genesis_predecessor",
      why: "a genesis that names a predecessor is a forged chain link",
      mutate: (r) => ({
        ...r,
        predecessor_digest: DIGEST_B,
        payload: versionPayload({ predecessorDigest: DIGEST_B }),
      }),
    },
    {
      constraint: "memory_record_versions_erasure_witness",
      why: "content erased with no tombstone accounting for it",
      mutate: (r) => ({ ...r, content_erased_at: new Date().toISOString() }),
    },
    {
      constraint: "memory_record_versions_record_binding",
      why: "a payload naming a different record than its column",
      mutate: (r) => ({ ...r, payload: versionPayload({ recordId: "record-other" }) }),
    },
    {
      constraint: "memory_record_versions_version_binding",
      why: "a payload naming a different version than its column",
      mutate: (r) => ({ ...r, payload: versionPayload({ version: 9 }) }),
    },
    {
      constraint: "memory_record_versions_state_binding",
      why: "a payload naming a different state than its column",
      mutate: (r) => ({ ...r, payload: versionPayload({ state: "deleted" }) }),
    },
    {
      constraint: "memory_record_versions_content_digest_binding",
      why: "a payload naming a different content digest than its column",
      mutate: (r) => ({ ...r, payload: versionPayload({ contentDigest: DIGEST_B }) }),
    },
    {
      constraint: "memory_record_versions_predecessor_digest_binding",
      why: "a payload naming a predecessor its column does not",
      mutate: (r) => ({
        ...r,
        payload: versionPayload({ predecessorDigest: DIGEST_B }),
      }),
    },
    {
      constraint: "memory_record_versions_authorization_binding",
      why: "a payload naming a different authorization than its column",
      mutate: (r) => ({
        ...r,
        payload: versionPayload({ authorizationId: "destroy-auth-000000000002" }),
      }),
    },
    {
      constraint: "memory_record_versions_mutation_receipt_binding",
      why: "a payload naming a different mutation receipt than its column",
      mutate: (r) => ({
        ...r,
        payload: versionPayload({ mutationReceiptId: "mutation.other" }),
      }),
    },
    {
      constraint: "memory_record_versions_tenant_binding",
      why: "a payload claiming a tenant its column does not",
      mutate: (r) => ({
        ...r,
        payload: versionPayload({ scope: { ...SCOPE, tenantId: "tenant-other" } }),
      }),
    },
    {
      constraint: "memory_record_versions_workspace_binding",
      why: "a payload claiming a workspace its column does not",
      mutate: (r) => ({
        ...r,
        payload: versionPayload({
          scope: { ...SCOPE, workspaceId: "workspace-other" },
        }),
      }),
    },
    {
      constraint: "memory_record_versions_principal_binding",
      why: "a payload claiming a principal its column does not — the ownership half",
      mutate: (r) => ({
        ...r,
        payload: versionPayload({
          scope: { ...SCOPE, principalId: "principal-other" },
        }),
      }),
    },
    {
      constraint: "memory_record_versions_user_binding",
      why: "a payload claiming a user its column does not — the ownership half",
      mutate: (r) => ({
        ...r,
        payload: versionPayload({ scope: { ...SCOPE, userId: "user-other" } }),
      }),
    },
  ],
  {
    expect: /no consumed authorization witnesses this record version/,
    note: "it reaches the witness trigger, which only runs once every CHECK has held",
  },
);

// ---------------------------------------------------------------------------
// memory_authorization_receipts
// ---------------------------------------------------------------------------

function receiptPayload(overrides: Row = {}): Row {
  return {
    schemaVersion: "aaliyah.trusted-memory/v1",
    authorizationId: "destroy-auth-000000000001",
    action: "correct",
    targetRecordId: RECORD_ID,
    scope: { ...SCOPE },
    nonce: { bindingDigest: DIGEST_A },
    ...overrides,
  };
}

function receiptBase(): Row {
  return {
    tenant_id: SCOPE.tenantId,
    workspace_id: SCOPE.workspaceId,
    principal_id: SCOPE.principalId,
    user_id: SCOPE.userId,
    authorization_id: "destroy-auth-000000000001",
    action: "correct",
    target_record_id: RECORD_ID,
    binding_digest: DIGEST_A,
    issued_at: new Date(Date.now() - 60_000).toISOString(),
    expires_at: new Date(Date.now() + 3_600_000).toISOString(),
    payload: receiptPayload(),
  };
}

test("memory_authorization_receipts: the base row is ACCEPTED, so the cases below are not passing on a broken table", async () => {
  await insertRow("memory_authorization_receipts", receiptBase());
  const count = await adminPool.query(
    `SELECT count(*)::int AS n FROM memory_authorization_receipts`,
  );
  assert.equal(count.rows[0].n, 1);
});

for (const destroyer of [
  {
    constraint: "memory_authorization_receipts_binding_digest_form",
    why: "a binding digest that is not a sha256 reference",
    mutate: (r: Row) => ({
      ...r,
      binding_digest: "sha256:nope",
      payload: receiptPayload({ nonce: { bindingDigest: "sha256:nope" } }),
    }),
  },
  {
    constraint: "memory_authorization_receipts_window",
    why: "an approval that expires at or before it was issued",
    mutate: (r: Row) => ({ ...r, expires_at: r.issued_at }),
  },
  {
    constraint: "memory_authorization_receipts_max_validity",
    why: "an approval good for longer than a day outlives its own review",
    mutate: (r: Row) => ({
      ...r,
      expires_at: new Date(Date.now() + 25 * 3_600_000).toISOString(),
    }),
  },
  {
    constraint: "memory_authorization_receipts_consumed_after_issue",
    why: "spent before it was granted",
    mutate: (r: Row) => ({
      ...r,
      consumed_at: new Date(Date.now() - 120_000).toISOString(),
    }),
  },
  {
    constraint: "memory_authorization_receipts_revoked_after_issue",
    why: "revoked before it was granted",
    mutate: (r: Row) => ({
      ...r,
      revoked_at: new Date(Date.now() - 120_000).toISOString(),
    }),
  },
  {
    constraint: "memory_authorization_receipts_not_both",
    why: "an approval cannot be both spent and revoked",
    mutate: (r: Row) => ({
      ...r,
      consumed_at: new Date().toISOString(),
      revoked_at: new Date().toISOString(),
    }),
  },
  {
    constraint: "memory_authorization_receipts_authorization_binding",
    why: "a payload naming a different authorization than its column",
    mutate: (r: Row) => ({
      ...r,
      payload: receiptPayload({ authorizationId: "destroy-auth-000000000002" }),
    }),
  },
  {
    constraint: "memory_authorization_receipts_action_binding",
    why: "a payload naming a different action than its column — the substitution",
    mutate: (r: Row) => ({ ...r, payload: receiptPayload({ action: "delete" }) }),
  },
  {
    constraint: "memory_authorization_receipts_target_binding",
    why: "a payload naming a different record than its column",
    mutate: (r: Row) => ({
      ...r,
      payload: receiptPayload({ targetRecordId: "record-other" }),
    }),
  },
  {
    constraint: "memory_authorization_receipts_nonce_binding",
    why: "a payload naming a different out-of-band token than its column",
    mutate: (r: Row) => ({
      ...r,
      payload: receiptPayload({ nonce: { bindingDigest: DIGEST_B } }),
    }),
  },
  {
    constraint: "memory_authorization_receipts_tenant_binding",
    why: "a payload claiming a tenant its column does not",
    mutate: (r: Row) => ({
      ...r,
      payload: receiptPayload({ scope: { ...SCOPE, tenantId: "tenant-other" } }),
    }),
  },
  {
    constraint: "memory_authorization_receipts_workspace_binding",
    why: "a payload claiming a workspace its column does not",
    mutate: (r: Row) => ({
      ...r,
      payload: receiptPayload({
        scope: { ...SCOPE, workspaceId: "workspace-other" },
      }),
    }),
  },
  {
    constraint: "memory_authorization_receipts_principal_binding",
    why: "a payload claiming a principal its column does not",
    mutate: (r: Row) => ({
      ...r,
      payload: receiptPayload({
        scope: { ...SCOPE, principalId: "principal-other" },
      }),
    }),
  },
  {
    constraint: "memory_authorization_receipts_user_binding",
    why: "a payload claiming a user its column does not",
    mutate: (r: Row) => ({
      ...r,
      payload: receiptPayload({ scope: { ...SCOPE, userId: "user-other" } }),
    }),
  },
]) {
  test(`memory_authorization_receipts: ${destroyer.constraint} — ${destroyer.why}`, async () => {
    await assert.rejects(
      () =>
        insertRow("memory_authorization_receipts", destroyer.mutate(receiptBase())),
      (error: unknown) => {
        assert.match(String(error), new RegExp(destroyer.constraint));
        return true;
      },
    );
  });
}

// ---------------------------------------------------------------------------
// memory_tombstones
// ---------------------------------------------------------------------------

/**
 * EXACTLY the eighteen members the contract requires, no more and no fewer.
 * A BEFORE trigger counts them and fires ahead of every CHECK constraint, so a
 * payload missing one refuses for a reason that has nothing to do with the
 * constraint under test — which is precisely what happened on the first pass
 * here, and what a too-loose positive control let through.
 */
/**
 * Run with `memory_tombstones_structural` disabled, ALWAYS putting it back.
 *
 * That trigger is BEFORE INSERT and demands the target already be a deleted
 * record carrying a consumed authorization, so while it is enabled NO row
 * reaches the CHECK layer at all and none of the constraints below have a
 * reachable input. They are a distinct layer — a replica or a restored backup
 * may carry the constraints without the trigger — so they are exercised with
 * it stood down. The trigger's OWN behaviour is proven in
 * tests/wave1MemoryHoldErasurePostgres.integration.test.ts and is not what
 * these cases claim to cover.
 *
 * Restored in `finally`: a failure between the two statements would otherwise
 * leave the structural guard OFF for every test that ran afterwards in the
 * same database, silently unenforced and still green.
 */
async function withoutTombstoneStructuralGuard<T>(
  run: () => Promise<T>,
): Promise<T> {
  // Migration 044's scope binding is the same kind of layer: it resolves the
  // base row's authorization, which this CHECK-layer fixture deliberately does
  // not issue. Stood down with the structural guard, and its own behaviour is
  // proven in tests/wave1MemoryIdentityPostgres.integration.test.ts (C4).
  await adminPool.query(
    `ALTER TABLE memory_tombstones
       DISABLE TRIGGER memory_tombstones_structural,
       DISABLE TRIGGER memory_tombstones_zz_authorization_scope`,
  );
  try {
    return await run();
  } finally {
    await adminPool.query(
      `ALTER TABLE memory_tombstones
         ENABLE TRIGGER memory_tombstones_structural,
         ENABLE TRIGGER memory_tombstones_zz_authorization_scope`,
    );
  }
}

function tombstonePayload(overrides: Row = {}): Row {
  return {
    schemaVersion: "aaliyah.trusted-memory/v1",
    tombstoneId: "tombstone-destroy-001",
    scope: { ...SCOPE },
    targetRecordId: RECORD_ID,
    targetVersion: 1,
    tombstoneVersion: 2,
    deletionAuthority: { authorizationId: "destroy-auth-000000000001" },
    reason: "subject_erasure_request",
    reasonEvidenceRef: "matter:erasure-request/0001",
    effectiveAt: new Date().toISOString(),
    retention: { legalHoldState: { state: "none" } },
    retainedFieldNames: [],
    destroyedFieldNames: ["subject.identifier"],
    derivedData: [],
    cacheIndexPropagation: "unknown",
    downstreamPropagation: [],
    restorationEligibility: { kind: "ineligible_payload_destroyed" },
    tombstoneDigest: DIGEST_A,
    ...overrides,
  };
}

function tombstoneBase(): Row {
  return {
    tenant_id: SCOPE.tenantId,
    workspace_id: SCOPE.workspaceId,
    principal_id: SCOPE.principalId,
    user_id: SCOPE.userId,
    tombstone_id: "tombstone-destroy-001",
    target_record_id: RECORD_ID,
    target_version: 1,
    tombstone_version: 2,
    authorization_id: "destroy-auth-000000000001",
    mutation_receipt_id: "mutation.destroy.001",
    reason: "subject_erasure_request",
    effective_at: new Date().toISOString(),
    retain_until: null,
    legal_hold_state: "none",
    cache_index_propagation: "unknown",
    restoration_eligibility_kind: "ineligible_payload_destroyed",
    tombstone_digest: DIGEST_A,
    payload: tombstonePayload(),
  };
}

function tombstoneDestroyers(cases: readonly Destroyer[]): void {
  test("memory_tombstones: the base row is ACCEPTED once the structural guard stands down, so the cases below are not passing on a table that refuses everything", async () => {
    await withoutTombstoneStructuralGuard(async () => {
      await insertRow("memory_tombstones", tombstoneBase());
      const count = await adminPool.query(
        `SELECT count(*)::int AS n FROM memory_tombstones`,
      );
      assert.equal(count.rows[0].n, 1);
    });
  });

  for (const destroyer of cases) {
    test(`memory_tombstones: ${destroyer.constraint} — ${destroyer.why}`, async () => {
      await withoutTombstoneStructuralGuard(async () => {
        await assert.rejects(
          () => insertRow("memory_tombstones", destroyer.mutate(tombstoneBase())),
          (error: unknown) => {
            assert.match(String(error), new RegExp(destroyer.constraint));
            return true;
          },
        );
      });
    });
  }
}

tombstoneDestroyers([
    {
      constraint: "memory_tombstones_digest_form",
      why: "a tombstone digest that is not a sha256 reference",
      mutate: (r) => ({
        ...r,
        tombstone_digest: "sha256:no",
        payload: tombstonePayload({ tombstoneDigest: "sha256:no" }),
      }),
    },
    {
      constraint: "memory_tombstones_versions_ordered",
      why: "a tombstone at or below the version it destroys",
      mutate: (r) => ({
        ...r,
        tombstone_version: 1,
        payload: tombstonePayload({ tombstoneVersion: 1 }),
      }),
    },
    {
      constraint: "memory_tombstones_hold_state_domain",
      why: "a hold state outside none/held/released",
      mutate: (r) => ({
        ...r,
        legal_hold_state: "pending",
        payload: tombstonePayload({
          retention: { legalHoldState: { state: "pending" } },
        }),
      }),
    },
    {
      constraint: "memory_tombstones_not_under_hold",
      why: "DESTROYING HELD EVIDENCE — a tombstone may never record an active hold",
      mutate: (r) => ({
        ...r,
        legal_hold_state: "held",
        payload: tombstonePayload({
          retention: { legalHoldState: { state: "held" } },
        }),
      }),
    },
    {
      constraint: "memory_tombstones_reason_domain",
      why: "a destruction reason outside the closed vocabulary",
      mutate: (r) => ({
        ...r,
        reason: "because_we_felt_like_it",
        payload: tombstonePayload({ reason: "because_we_felt_like_it" }),
      }),
    },
    {
      constraint: "memory_tombstones_propagation_domain",
      why: "a propagation state outside the closed vocabulary",
      mutate: (r) => ({
        ...r,
        cache_index_propagation: "probably_fine",
        payload: tombstonePayload({ cacheIndexPropagation: "probably_fine" }),
      }),
    },
    {
      constraint: "memory_tombstones_restoration_domain",
      why: "claiming a destroyed payload could be restored",
      mutate: (r) => ({
        ...r,
        restoration_eligibility_kind: "eligible",
        payload: tombstonePayload({
          restorationEligibility: { kind: "eligible" },
        }),
      }),
    },
    {
      constraint: "memory_tombstones_destroyed_not_empty",
      why: "a destruction that names nothing it destroyed",
      mutate: (r) => ({
        ...r,
        payload: tombstonePayload({ destroyedFieldNames: [] }),
      }),
    },
    {
      constraint: "memory_tombstones_id_binding",
      why: "a payload naming a different tombstone than its column",
      mutate: (r) => ({
        ...r,
        payload: tombstonePayload({ tombstoneId: "tombstone-other" }),
      }),
    },
    {
      constraint: "memory_tombstones_target_binding",
      why: "a payload naming a different record than its column",
      mutate: (r) => ({
        ...r,
        payload: tombstonePayload({ targetRecordId: "record-other" }),
      }),
    },
    {
      constraint: "memory_tombstones_target_version_binding",
      why: "a payload naming a different destroyed version than its column",
      mutate: (r) => ({ ...r, payload: tombstonePayload({ targetVersion: 7 }) }),
    },
    {
      constraint: "memory_tombstones_tombstone_version_binding",
      why: "a payload naming a different tombstone version than its column",
      mutate: (r) => ({
        ...r,
        payload: tombstonePayload({ tombstoneVersion: 9 }),
      }),
    },
    {
      constraint: "memory_tombstones_authorization_binding",
      why: "a payload naming a different destruction authority than its column",
      mutate: (r) => ({
        ...r,
        payload: tombstonePayload({
          deletionAuthority: { authorizationId: "destroy-auth-000000000002" },
        }),
      }),
    },
    {
      constraint: "memory_tombstones_reason_binding",
      why: "a payload naming a different reason than its column",
      mutate: (r) => ({
        ...r,
        payload: tombstonePayload({ reason: "retention_expiry" }),
      }),
    },
    {
      constraint: "memory_tombstones_hold_state_binding",
      why: "a payload naming a different hold state than its column",
      mutate: (r) => ({
        ...r,
        payload: tombstonePayload({
          retention: { legalHoldState: { state: "released" } },
        }),
      }),
    },
    {
      constraint: "memory_tombstones_propagation_binding",
      why: "a payload naming a different propagation state than its column",
      mutate: (r) => ({
        ...r,
        payload: tombstonePayload({ cacheIndexPropagation: "complete" }),
      }),
    },
    {
      constraint: "memory_tombstones_restoration_binding",
      why: "a payload naming a different restoration verdict than its column",
      mutate: (r) => ({
        ...r,
        payload: tombstonePayload({
          restorationEligibility: { kind: "something_else" },
        }),
      }),
    },
    {
      constraint: "memory_tombstones_digest_binding",
      why: "a payload naming a different tombstone digest than its column",
      mutate: (r) => ({
        ...r,
        payload: tombstonePayload({ tombstoneDigest: DIGEST_B }),
      }),
    },
    {
      constraint: "memory_tombstones_tenant_binding",
      why: "a payload claiming a tenant its column does not",
      mutate: (r) => ({
        ...r,
        payload: tombstonePayload({ scope: { ...SCOPE, tenantId: "tenant-other" } }),
      }),
    },
    {
      constraint: "memory_tombstones_workspace_binding",
      why: "a payload claiming a workspace its column does not",
      mutate: (r) => ({
        ...r,
        payload: tombstonePayload({
          scope: { ...SCOPE, workspaceId: "workspace-other" },
        }),
      }),
    },
    {
      constraint: "memory_tombstones_principal_binding",
      why: "a payload claiming a principal its column does not",
      mutate: (r) => ({
        ...r,
        payload: tombstonePayload({
          scope: { ...SCOPE, principalId: "principal-other" },
        }),
      }),
    },
    {
      constraint: "memory_tombstones_user_binding",
      why: "a payload claiming a user its column does not",
      mutate: (r) => ({
        ...r,
        payload: tombstonePayload({ scope: { ...SCOPE, userId: "user-other" } }),
      }),
    },
]);

// ---------------------------------------------------------------------------
// memory_alias_bindings
// ---------------------------------------------------------------------------

const ALIAS = "dana@example.com";
const PARTICIPANT = "record-destroy-participant";

function bindingPayload(overrides: Row = {}): Row {
  return {
    schemaVersion: "aaliyah.trusted-memory/v1",
    aliasId: "alias-destroy-001",
    scope: { ...SCOPE },
    crossWorkspacePolicy: "workspace_isolated",
    scopeKey: SCOPE.workspaceId,
    canonicalParticipantId: PARTICIPANT,
    subjectParticipantId: PARTICIPANT,
    normalizedAlias: ALIAS,
    skeleton: ALIAS,
    authorizationId: "destroy-auth-000000000001",
    mutationReceiptId: "mutation.destroy.001",
    ...overrides,
  };
}

function bindingBase(): Row {
  return {
    tenant_id: SCOPE.tenantId,
    workspace_id: SCOPE.workspaceId,
    principal_id: SCOPE.principalId,
    user_id: SCOPE.userId,
    cross_workspace_policy: "workspace_isolated",
    scope_key: SCOPE.workspaceId,
    alias_id: "alias-destroy-001",
    normalized_alias: ALIAS,
    skeleton: ALIAS,
    skeleton_algorithm: "core-alias-skeleton/v1",
    normalization_profile: "core-alias-normalization/v1",
    canonical_participant_id: PARTICIPANT,
    registrable_domain: "example.com",
    script_code: "Latn",
    restriction_level: "ascii_only",
    subject_participant_id: PARTICIPANT,
    source_evidence_ref: "identity:verification/participant",
    source_evidence_digest: DIGEST_A,
    observed_at: new Date(Date.now() - 60_000).toISOString(),
    fresh_until: new Date(Date.now() + 3_600_000).toISOString(),
    authorization_id: "destroy-auth-000000000001",
    mutation_receipt_id: "mutation.destroy.001",
    bound_at: new Date().toISOString(),
    payload: bindingPayload(),
  };
}

destroyers(
  "memory_alias_bindings",
  bindingBase,
  [
    {
      constraint: "memory_alias_bindings_evidence_digest_form",
      why: "identity evidence whose digest is not a sha256 reference",
      mutate: (r) => ({ ...r, source_evidence_digest: "sha256:nope" }),
    },
    {
      constraint: "memory_alias_bindings_freshness_window",
      why: "evidence that goes stale at or before it was observed",
      mutate: (r) => ({ ...r, fresh_until: r.observed_at }),
    },
    {
      constraint: "memory_alias_bindings_workspace_not_sentinel",
      why: "a workspace literally named '*' would collide with the tenant-wide scope key",
      mutate: (r) => ({
        ...r,
        workspace_id: "*",
        scope_key: "*",
        payload: bindingPayload({
          scope: { ...SCOPE, workspaceId: "*" },
          scopeKey: "*",
        }),
      }),
    },
    {
      constraint: "memory_alias_bindings_scope_key_derivation",
      why: "a scope key that is not derived from the policy it claims",
      mutate: (r) => ({
        ...r,
        scope_key: "*",
        payload: bindingPayload({ scopeKey: "*" }),
      }),
    },
    {
      constraint: "memory_alias_bindings_removal_witness",
      why: "retired with nothing naming what retired it",
      mutate: (r) => ({ ...r, removed_at: new Date().toISOString() }),
    },
    {
      constraint: "memory_alias_bindings_removal_after_binding",
      why: "retired before it was ever bound",
      mutate: (r) => ({
        ...r,
        removed_at: new Date(Date.now() - 120_000).toISOString(),
        removed_by_mutation_receipt_id: "mutation.destroy.remove",
        removed_authorization_id: "destroy-auth-000000000002",
      }),
    },
    {
      constraint: "memory_alias_bindings_alias_id_binding",
      why: "a payload naming a different alias id than its column",
      mutate: (r) => ({ ...r, payload: bindingPayload({ aliasId: "alias-other" }) }),
    },
    {
      constraint: "memory_alias_bindings_normalized_binding",
      why: "a payload naming a different normalized alias than its column",
      mutate: (r) => ({
        ...r,
        payload: bindingPayload({ normalizedAlias: "other@example.com" }),
      }),
    },
    {
      constraint: "memory_alias_bindings_skeleton_binding",
      why: "a payload naming a different confusable skeleton than its column",
      mutate: (r) => ({ ...r, payload: bindingPayload({ skeleton: "other" }) }),
    },
    {
      constraint: "memory_alias_bindings_participant_binding",
      why: "a payload pointing the alias at a different identity than its column",
      mutate: (r) => ({
        ...r,
        payload: bindingPayload({ canonicalParticipantId: "record-other" }),
      }),
    },
    {
      constraint: "memory_alias_bindings_subject_binding",
      why: "a payload naming a different evidence subject than its column",
      mutate: (r) => ({
        ...r,
        payload: bindingPayload({ subjectParticipantId: "record-other" }),
      }),
    },
    {
      constraint: "memory_alias_bindings_policy_binding",
      why: "a payload claiming a different cross-workspace policy than its column",
      mutate: (r) => ({
        ...r,
        payload: bindingPayload({ crossWorkspacePolicy: "tenant_exclusive" }),
      }),
    },
    {
      constraint: "memory_alias_bindings_scope_key_binding",
      why: "a payload naming a different scope key than its column",
      mutate: (r) => ({ ...r, payload: bindingPayload({ scopeKey: "*" }) }),
    },
    {
      constraint: "memory_alias_bindings_authorization_binding",
      why: "a payload naming a different authorization than its column",
      mutate: (r) => ({
        ...r,
        payload: bindingPayload({ authorizationId: "destroy-auth-000000000002" }),
      }),
    },
    {
      constraint: "memory_alias_bindings_mutation_receipt_binding",
      why: "a payload naming a different mutation receipt than its column",
      mutate: (r) => ({
        ...r,
        payload: bindingPayload({ mutationReceiptId: "mutation.other" }),
      }),
    },
    {
      constraint: "memory_alias_bindings_tenant_binding",
      why: "a payload claiming a tenant its column does not",
      mutate: (r) => ({
        ...r,
        payload: bindingPayload({ scope: { ...SCOPE, tenantId: "tenant-other" } }),
      }),
    },
    {
      constraint: "memory_alias_bindings_workspace_binding",
      why: "a payload claiming a workspace its column does not",
      mutate: (r) => ({
        ...r,
        payload: bindingPayload({
          scope: { ...SCOPE, workspaceId: "workspace-other" },
        }),
      }),
    },
    {
      constraint: "memory_alias_bindings_principal_binding",
      why: "a payload claiming a principal its column does not",
      mutate: (r) => ({
        ...r,
        payload: bindingPayload({
          scope: { ...SCOPE, principalId: "principal-other" },
        }),
      }),
    },
    {
      constraint: "memory_alias_bindings_user_binding",
      why: "a payload claiming a user its column does not",
      mutate: (r) => ({
        ...r,
        payload: bindingPayload({ scope: { ...SCOPE, userId: "user-other" } }),
      }),
    },
  ],
  {
    expect: /no consumed authorization witnesses/,
    note: "it reaches the witness trigger, which only runs once every CHECK has held",
  },
);

// ---------------------------------------------------------------------------
// THE FOUR CONSTRAINTS THAT CANNOT BE ISOLATED, STATED RATHER THAN HIDDEN.
// ---------------------------------------------------------------------------

test("a non-object payload is refused on every table — though NEVER by the constraint written for it", async () => {
  // DISCLOSED MASKED CONSTRAINTS. `<table>_payload_object` exists on four
  // tables and not one of them can be violated in isolation: every payload
  // binding reads `payload ->> 'x'`, which is NULL for an array or a scalar,
  // so the bindings refuse a non-object payload before the object check is
  // ever reached. A drop-test confirms it — removing any of the four changes
  // nothing observable.
  //
  // They are reported as SURVIVING constraints, not claimed as covered. What
  // is proven here is the property that actually matters: a non-object payload
  // does not land on any of them.
  const cases: ReadonlyArray<[string, Row]> = [
    ["memory_record_versions", versionBase()],
    ["memory_authorization_receipts", receiptBase()],
    ["memory_tombstones", tombstoneBase()],
    ["memory_alias_bindings", bindingBase()],
  ];
  for (const [table, base] of cases) {
    const attempt = async () => {
      await assert.rejects(
        () => insertRow(table, { ...base, payload: ["nope"] }),
        new RegExp(`violates check constraint "${table}_`),
        `${table} must refuse a non-object payload`,
      );
    };
    // The tombstone structural trigger is BEFORE INSERT and refuses a
    // non-object payload on its member count, ahead of the CHECK layer
    // entirely — so the constraint being discussed is reached only with that
    // guard stood down.
    if (table === "memory_tombstones") {
      await withoutTombstoneStructuralGuard(attempt);
    } else {
      await attempt();
    }
    const count = await adminPool.query(
      `SELECT count(*)::int AS n FROM ${table}`,
    );
    assert.equal(count.rows[0].n, 0, `${table} must hold no row`);
  }
});
