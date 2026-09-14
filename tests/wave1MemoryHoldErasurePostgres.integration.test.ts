import assert from "node:assert/strict";
import test, { after, before, beforeEach } from "node:test";
import { Pool } from "pg";

import {
  MEMORY_ALIAS_NORMALIZATION_VERSION,
  MEMORY_AUTHORIZATION_NONCE_SCHEMA_VERSION,
  MEMORY_CONFUSABLE_SKELETON_ALGORITHM,
  CanonicalAliasIdentitySchema,
  LegalHoldSchema,
  MemoryAuthorizationReceiptSchema,
  WAVE1_TRUSTED_MEMORY_CONTRACT_VERSION,
  Wave1SubjectBoundEvidenceSchema,
  legalHoldRestricts,
  canonicalDigest,
  memoryAuthorizationNonce,
  type CanonicalAliasIdentity,
  type LegalHold,
  type MemoryAuthorizationReceipt,
  type MemoryExpectedHead,
  type MemoryScope,
  type Wave1SubjectBoundEvidence,
} from "@aaliyah/contracts/v1";

import {
  aliasAssignmentDigest,
  aliasRemovalDigest,
} from "../src/application/memory/wave1AliasRegistry";
import {
  aliasRestrictionLevel,
  coreAliasSkeleton,
  coreNormalizeAlias,
  determineAliasScript,
  isInternationalizedDomain,
  splitEmailAlias,
} from "../src/application/memory/wave1AliasSkeleton";
import {
  MEMORY_DELETION_ORDER_SCHEMA_VERSION,
  MEMORY_RETAINED_ENVELOPE_FIELD_NAMES,
  MEMORY_TOMBSTONE_DIGEST_SCHEMA_VERSION,
  memoryTombstoneDigest,
} from "../src/application/memory/wave1MemoryErasure";
import {
  MEMORY_RECORD_VERSION_SCHEMA_VERSION,
  memoryContentDigest,
} from "../src/application/memory/wave1TrustedMemory";
import { runMailMigrations } from "../src/persistence/postgres/migrations";
import { createMailDbPool } from "../src/persistence/postgres/pool";
import { createPostgresAliasRegistryStore } from "../src/persistence/postgres/wave1AliasRegistryStore";
import { createPostgresLegalHoldStore } from "../src/persistence/postgres/wave1LegalHoldStore";
import { createPostgresTrustedMemoryStore } from "../src/persistence/postgres/wave1TrustedMemoryStore";
import {
  lockSharedMemoryTables,
  type SharedTableLock,
} from "./support/sharedMemoryTables";

/**
 * Wave 1.3 PART F — LEGAL HOLDS AND REAL ERASURE, against a REAL PostgreSQL 16.
 *
 * TWO CONFIRMED DEFECTS ARE THE SUBJECT OF THIS FILE, and both were live.
 *
 *   1. LEGAL HOLDS WERE NOT ENFORCED. `legalHoldRestricts` was never called
 *      anywhere in Core and the contract's `legal_hold_active` abort reason was
 *      unreachable. Before that, the hold gated DELETION ONLY, so `correct` —
 *      whose schema REQUIRES the content to change — was a supported, audited
 *      path to spoliating held evidence.
 *
 *   2. `delete()` WAS NOT ERASURE. It advanced the head to a `deleted` label
 *      and destroyed nothing; an earlier review found an "erased" record still
 *      holding "SENSITIVE: CEO divorce settlement terms" verbatim.
 *
 * WHAT THAT MEANS FOR HOW THESE TESTS ARE WRITTEN. Two things, deliberately:
 *
 *   * ERASURE IS ASSERTED BY DIRECT SQL, NOT THROUGH THE STORE. A store that
 *     filters erased content out of its own reads would pass a store-level
 *     assertion while the plaintext sat on disk — which is exactly the shape of
 *     the defect. Every erasure assertion below reads
 *     `memory_record_versions` as the OWNER and searches the raw jsonb text.
 *
 *   * EVERY HOLD REFUSAL IS PROVEN TWICE: once through the store, which is
 *     ergonomics and accounting, and once as a HOSTILE DIRECT WRITE under the
 *     `aaliyah_memory_mutator` role, which is the enforcement point. A control
 *     that only refuses callers of `mutate()` is not a control against the
 *     threat model this repository has already had executed against it.
 *
 * Every negative assertion carries a matcher. A bare `assert.rejects` passes
 * when the code throws for a completely unrelated reason, which is how a
 * control appears tested while never having been exercised once.
 */

const DB_URL =
  process.env.AALIYAH_TEST_DATABASE_URL ??
  "postgres://postgres:test@127.0.0.1:54329/aaliyah_test";

/** The value the original defect left readable. It must never survive here. */
const SENSITIVE = "SENSITIVE: CEO divorce settlement terms";

const EVIDENCE_DIGEST = `sha256:${"d".repeat(64)}`;
const CORPUS_REF = "corpus:alias-protected-domains/v1";

const TENANT = "tenant-hold";

const SCOPE: MemoryScope = {
  tenantId: TENANT,
  workspaceId: "workspace-hold",
  principalId: "principal-hold",
  userId: "user-hold",
};

/** A second principal in the same workspace. Used for read isolation. */
const OTHER_SCOPE: MemoryScope = { ...SCOPE, principalId: "principal-other" };

const RECORD_ID = "record-hold-001";
const FREE_RECORD_ID = "record-free-001";

/**
 * A real relation the tombstone read-back resolves to FIRST, holding no rows.
 *
 * It exists so "the deletion's accounting was independently read back" has a
 * falsifiable negative: with the read-back pointed here, a deletion that
 * committed perfectly still cannot produce a tombstone on an independent
 * session, and the store must refuse to call that a success. Forcing it this
 * way leaves the production read path completely untouched — no injected
 * failure hook, no stubbed client — and it is the pattern the two existing
 * memory suites already use.
 */
const EMPTY_TOMBSTONE_SCHEMA = "memory_tombstone_shadow";

let adminPool: Pool;
let writePool: Pool;
let readPool: Pool;
let shadowTombstonePool: Pool;
let sharedTableLock: SharedTableLock;

function store() {
  return createPostgresTrustedMemoryStore(writePool, readPool);
}

function holds() {
  return createPostgresLegalHoldStore(writePool, readPool);
}

function aliases() {
  return createPostgresAliasRegistryStore(writePool, readPool);
}

before(async () => {
  adminPool = createMailDbPool({
    AALIYAH_DATABASE_URL: DB_URL,
  } as NodeJS.ProcessEnv);
  // See tests/support/sharedMemoryTables.ts: `node --test` runs files in
  // parallel and three files now TRUNCATE these tables.
  sharedTableLock = await lockSharedMemoryTables(adminPool);
  await runMailMigrations(adminPool);
  writePool = createMailDbPool({
    AALIYAH_DATABASE_URL: DB_URL,
  } as NodeJS.ProcessEnv);
  readPool = createMailDbPool({
    AALIYAH_DATABASE_URL: DB_URL,
  } as NodeJS.ProcessEnv);

  await adminPool.query(
    `DROP SCHEMA IF EXISTS ${EMPTY_TOMBSTONE_SCHEMA} CASCADE`,
  );
  await adminPool.query(`CREATE SCHEMA ${EMPTY_TOMBSTONE_SCHEMA}`);
  await adminPool.query(
    `CREATE TABLE ${EMPTY_TOMBSTONE_SCHEMA}.memory_tombstones
       (LIKE public.memory_tombstones INCLUDING DEFAULTS)`,
  );
  await adminPool.query(
    `GRANT USAGE ON SCHEMA ${EMPTY_TOMBSTONE_SCHEMA}
       TO aaliyah_memory_reader, aaliyah_memory_mutator`,
  );
  await adminPool.query(
    `GRANT SELECT ON ${EMPTY_TOMBSTONE_SCHEMA}.memory_tombstones
       TO aaliyah_memory_reader, aaliyah_memory_mutator`,
  );
  shadowTombstonePool = new Pool({
    connectionString: DB_URL,
    max: 4,
    options: `-c search_path=${EMPTY_TOMBSTONE_SCHEMA},public`,
  });
});

after(async () => {
  await shadowTombstonePool.end();
  await readPool.end();
  await writePool.end();
  await adminPool.query(
    `DROP SCHEMA IF EXISTS ${EMPTY_TOMBSTONE_SCHEMA} CASCADE`,
  );
  await adminPool.query(
    `TRUNCATE memory_record_versions,
              memory_authorization_receipts,
              memory_authorization_nonces,
              memory_mutation_receipts,
              memory_alias_bindings,
              memory_alias_tenant_policy,
              memory_alias_protected_domains,
              memory_tombstones,
              memory_legal_hold_carve_outs,
              memory_legal_hold_records,
              memory_legal_hold_subjects,
              memory_legal_holds,
              memory_retention_obligations
     RESTART IDENTITY`,
  );
  await sharedTableLock.release();
  await adminPool.end();
});

beforeEach(async () => {
  await adminPool.query(
    `TRUNCATE memory_record_versions,
              memory_authorization_receipts,
              memory_authorization_nonces,
              memory_mutation_receipts,
              memory_alias_bindings,
              memory_alias_tenant_policy,
              memory_alias_protected_domains,
              memory_tombstones,
              memory_legal_hold_carve_outs,
              memory_legal_hold_records,
              memory_legal_hold_subjects,
              memory_legal_holds,
              memory_retention_obligations
     RESTART IDENTITY`,
  );
  genesisCounter = 0;
  authorizationCounter = 0;
});

// ---------------------------------------------------------------------------
// Fixtures. Every one of them writes through the least-privilege role that the
// production path would use, so a test cannot pass because the fixture had
// more authority than the code under test.
// ---------------------------------------------------------------------------

let authorizationCounter = 0;
function nextAuthorizationId(): string {
  authorizationCounter += 1;
  // MemoryAuthorizationIdSchema demands >= 26 characters.
  return `auth-hold-${String(authorizationCounter).padStart(21, "0")}`;
}

function isoOffset(ms: number): string {
  return new Date(Date.now() + ms).toISOString();
}

type HeldAction =
  | "correct"
  | "delete"
  | "restore"
  | "promote"
  | "assign_alias"
  | "remove_alias";

function authorization(input: {
  action: HeldAction;
  scope?: MemoryScope;
  targetRecordId?: string;
  expectedHead: MemoryExpectedHead;
  proposedContent?: unknown;
  proposedContentDigest?: string;
}): MemoryAuthorizationReceipt {
  const scope = input.scope ?? SCOPE;
  const targetRecordId = input.targetRecordId ?? RECORD_ID;
  const authorizationId = nextAuthorizationId();
  const proposedContentDigest =
    input.proposedContentDigest ?? memoryContentDigest(input.proposedContent);
  const bindingDigest = memoryAuthorizationNonce({
    bindingSchemaVersion: MEMORY_AUTHORIZATION_NONCE_SCHEMA_VERSION,
    authorizationId,
    action: input.action,
    scope,
    targetRecordId,
    expectedHead: input.expectedHead,
    proposedContentDigest,
  });
  return MemoryAuthorizationReceiptSchema.parse({
    schemaVersion: WAVE1_TRUSTED_MEMORY_CONTRACT_VERSION,
    authorizationId,
    action: input.action,
    approverAuthorityId: "authority.memory-steward",
    approverActorId: "actor.memory-steward",
    scope,
    targetRecordId,
    expectedHead: input.expectedHead,
    proposedContentDigest,
    nonce: {
      bindingSchemaVersion: MEMORY_AUTHORIZATION_NONCE_SCHEMA_VERSION,
      bindingDigest,
    },
    issuedAt: isoOffset(-60_000),
    expiresAt: isoOffset(3_600_000),
    revokedAt: null,
    consumedAt: null,
    policyVersion: "memory-policy/v1",
    evidenceDigest: EVIDENCE_DIGEST,
  });
}

/** Issue the receipt row AND the out-of-band nonce row, under the ISSUER role. */
async function issue(
  receipt: MemoryAuthorizationReceipt,
): Promise<MemoryAuthorizationReceipt> {
  const client = await adminPool.connect();
  try {
    await client.query("BEGIN");
    await client.query('SET LOCAL ROLE "aaliyah_memory_issuer"');
    await client.query(
      `INSERT INTO memory_authorization_receipts
         (tenant_id, workspace_id, principal_id, user_id, authorization_id,
          action, target_record_id, binding_digest, issued_at, expires_at,
          revoked_at, consumed_at, payload)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NULL,NULL,$11)`,
      [
        receipt.scope.tenantId,
        receipt.scope.workspaceId,
        receipt.scope.principalId,
        receipt.scope.userId,
        receipt.authorizationId,
        receipt.action,
        receipt.targetRecordId,
        receipt.nonce.bindingDigest,
        receipt.issuedAt,
        receipt.expiresAt,
        JSON.stringify(receipt),
      ],
    );
    await client.query(
      `INSERT INTO memory_authorization_nonces
         (tenant_id, workspace_id, binding_digest, authorization_id, action,
          target_record_id, issued_at, expires_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [
        receipt.scope.tenantId,
        receipt.scope.workspaceId,
        receipt.nonce.bindingDigest,
        receipt.authorizationId,
        receipt.action,
        receipt.targetRecordId,
        receipt.issuedAt,
        receipt.expiresAt,
      ],
    );
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
  return receipt;
}

async function runAs(
  role: string,
  sql: string,
  params: unknown[] = [],
): Promise<void> {
  const client = await adminPool.connect();
  try {
    await client.query("BEGIN");
    await client.query(`SET LOCAL ROLE "${role}"`);
    await client.query(sql, params);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Mint a nonce and SPEND it, so a row appended outside the store still carries
 * the witness migration 034 requires. Issued as the ISSUER and spent as the
 * MUTATOR, because a fixture that used the owner for both would not notice if
 * the privilege split it depends on stopped existing.
 */
async function witnessAppend(input: {
  authorizationId: string;
  mutationReceiptId: string;
  recordId: string;
  scope?: MemoryScope;
  action: string;
}): Promise<void> {
  const scope = input.scope ?? SCOPE;
  const bindingDigest = memoryContentDigest(input.authorizationId);
  await runAs(
    "aaliyah_memory_issuer",
    `INSERT INTO memory_authorization_nonces
       (tenant_id, workspace_id, binding_digest, authorization_id, action,
        target_record_id, issued_at, expires_at)
     VALUES ($1,$2,$3,$4,$5,$6, now() - interval '1 minute',
             now() + interval '1 hour')`,
    [
      scope.tenantId,
      scope.workspaceId,
      bindingDigest,
      input.authorizationId,
      input.action,
      input.recordId,
    ],
  );
  await runAs(
    "aaliyah_memory_mutator",
    `UPDATE memory_authorization_nonces
        SET consumed_at = now(), consumed_by_mutation_receipt_id = $2
      WHERE binding_digest = $1 AND consumed_at IS NULL`,
    [bindingDigest, input.mutationReceiptId],
  );
}

let genesisCounter = 0;

/** Seed version 1 of a record. `create` is not a store method in this wave. */
async function seedGenesis(
  content: unknown,
  options: { scope?: MemoryScope; recordId?: string } = {},
): Promise<string> {
  const scope = options.scope ?? SCOPE;
  const recordId = options.recordId ?? RECORD_ID;
  const digest = memoryContentDigest(content);
  genesisCounter += 1;
  const authorizationId = `genesis-hold-${String(genesisCounter).padStart(16, "0")}`;
  const mutationReceiptId = `mutation.genesis.${genesisCounter}`;
  await witnessAppend({
    authorizationId,
    mutationReceiptId,
    recordId,
    scope,
    action: "create",
  });
  const payload = {
    schemaVersion: MEMORY_RECORD_VERSION_SCHEMA_VERSION,
    recordId,
    version: 1,
    state: "active",
    scope,
    content,
    contentDigest: digest,
    predecessorDigest: null,
    authorizationId,
    mutationReceiptId,
    createdAt: isoOffset(-120_000),
  };
  await adminPool.query(
    `INSERT INTO memory_record_versions
       (tenant_id, workspace_id, principal_id, user_id, record_id, version,
        state, content_digest, predecessor_digest, authorization_id,
        mutation_receipt_id, payload)
     VALUES ($1,$2,$3,$4,$5,1,'active',$6,NULL,$7,$8,$9)`,
    [
      scope.tenantId,
      scope.workspaceId,
      scope.principalId,
      scope.userId,
      recordId,
      digest,
      authorizationId,
      mutationReceiptId,
      JSON.stringify(payload),
    ],
  );
  return digest;
}

function headOf(version: number, contentDigest: string): MemoryExpectedHead {
  return { kind: "version", version, contentDigest };
}

function deletionOrder(
  reason:
    | "subject_erasure_request"
    | "retention_expiry"
    | "erroneous_record" = "subject_erasure_request",
) {
  return {
    schemaVersion: MEMORY_DELETION_ORDER_SCHEMA_VERSION,
    reason,
    reasonEvidenceRef: "matter:erasure-request/0001",
  } as const;
}

let holdCounter = 0;

function legalHold(input: {
  coverage: LegalHold["coverage"];
  scope?: MemoryScope;
  holdId?: string;
  carveOutActions?: readonly string[];
}): LegalHold {
  holdCounter += 1;
  const issuedAt = isoOffset(-120_000);
  return LegalHoldSchema.parse({
    schemaVersion: WAVE1_TRUSTED_MEMORY_CONTRACT_VERSION,
    holdId: input.holdId ?? `hold-${String(holdCounter).padStart(6, "0")}`,
    scope: input.scope ?? SCOPE,
    matterRef: "matter:acme-v-globex/2026",
    issuingAuthorityId: "authority.general-counsel",
    issuedAt,
    coverage: input.coverage,
    status: { state: "active" },
    carveOuts: (input.carveOutActions ?? []).map((action) => ({
      action,
      orderRef: "order:court/2026-0117",
      grantingAuthorityId: "authority.court",
      grantedAt: isoOffset(-60_000),
    })),
  });
}

/** Place a hold and prove it landed, so no test depends on a silent failure. */
async function placeHold(hold: LegalHold, scope: MemoryScope = SCOPE) {
  const result = await holds().placeHold(scope, hold);
  assert.equal(result.rejection, null);
  assert.equal(result.recorded, true);
  return hold;
}

/**
 * Index a typed row array and REFUSE to be undefined.
 *
 * `rows[0]` on a typed array is `T | undefined` under this repository's
 * compiler settings, and silencing that with `!` would let a test that
 * expected a row and got none pass its `assert.ok(undefined?.x)` by accident.
 * This throws instead, so a missing row is a failure and not a skipped
 * assertion.
 */
function at<T>(rows: readonly T[], index: number): T {
  const row = rows[index];
  if (row === undefined) {
    throw new Error(`expected a row at index ${index}, found none`);
  }
  return row;
}

/** Every version row of a record, as the OWNER sees the raw bytes. */
async function rawVersions(
  recordId = RECORD_ID,
  scope: MemoryScope = SCOPE,
): Promise<
  Array<{
    version: number;
    state: string;
    content_digest: string;
    predecessor_digest: string | null;
    payload_text: string;
    content_erased_at: Date | null;
    erasure_tombstone_id: string | null;
  }>
> {
  const result = await adminPool.query(
    `SELECT version, state, content_digest, predecessor_digest,
            payload::text AS payload_text, content_erased_at,
            erasure_tombstone_id
       FROM memory_record_versions
      WHERE tenant_id = $1 AND workspace_id = $2 AND record_id = $3
      ORDER BY version ASC`,
    [scope.tenantId, scope.workspaceId, recordId],
  );
  return result.rows;
}

// ---------------------------------------------------------------------------
// 1. A HOLD RESTRICTS EVERY ACTION, NOT ONLY DELETE.
// ---------------------------------------------------------------------------

test("deletion is refused under an active legal hold, and the abort reason is the contract's", async () => {
  const genesis = await seedGenesis({ note: SENSITIVE });
  await placeHold(
    legalHold({ coverage: { kind: "records", recordIds: [RECORD_ID] } }),
  );
  const order = deletionOrder();
  const receipt = await issue(
    authorization({
      action: "delete",
      expectedHead: headOf(1, genesis),
      proposedContent: order,
    }),
  );

  const result = await store().delete({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: order,
    mutationReceiptId: "mutation.hold.delete",
  });

  assert.equal(result.verified, false);
  assert.equal(result.rejection, "legal_hold_active");
  assert.equal(result.tombstone, null);
  // `legal_hold_active` was unreachable before Part F. This is the assertion
  // that says it is reachable now, on a durable receipt.
  assert.ok(result.receipt);
  assert.equal(result.receipt.outcome.status, "ABORTED_NO_MUTATION");
  assert.ok(result.receipt.outcome.status === "ABORTED_NO_MUTATION");
  assert.equal(result.receipt.outcome.abortReason, "legal_hold_active");
  // Nothing was destroyed and nothing was appended.
  const versions = await rawVersions();
  assert.equal(versions.length, 1);
  assert.ok(at(versions, 0).payload_text.includes(SENSITIVE));
});

test("THE SPOLIATION PATH: a CORRECTION is refused under an active legal hold", async () => {
  // The confirmed defect. A correction MUST change the content — the
  // authorization schema refuses one that does not — so a hold that gated
  // deletion alone left a fully supported, fully audited way to rewrite the
  // evidence it existed to preserve.
  const genesis = await seedGenesis({ note: SENSITIVE });
  await placeHold(
    legalHold({ coverage: { kind: "records", recordIds: [RECORD_ID] } }),
  );
  const rewritten = { note: "nothing to see here" };
  const receipt = await issue(
    authorization({
      action: "correct",
      expectedHead: headOf(1, genesis),
      proposedContent: rewritten,
    }),
  );

  const result = await store().correct({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: rewritten,
    mutationReceiptId: "mutation.hold.correct",
  });

  assert.equal(result.verified, false);
  assert.equal(result.rejection, "legal_hold_active");
  const versions = await rawVersions();
  assert.equal(versions.length, 1);
  assert.ok(at(versions, 0).payload_text.includes(SENSITIVE));
});

test("promote is refused under an active legal hold", async () => {
  const genesis = await seedGenesis({ note: SENSITIVE });
  await placeHold({
    ...legalHold({ coverage: { kind: "entire_scope" } }),
  });
  const promoted = { note: SENSITIVE, standing: "canonical" };
  const receipt = await issue(
    authorization({
      action: "promote",
      expectedHead: headOf(1, genesis),
      proposedContent: promoted,
    }),
  );

  const result = await store().promote({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: promoted,
    mutationReceiptId: "mutation.hold.promote",
  });

  assert.equal(result.rejection, "legal_hold_active");
  assert.equal((await rawVersions()).length, 1);
});

test("restore is refused under an active legal hold", async () => {
  // Delete FIRST, then place the hold, so the record is genuinely deletable
  // and the only thing standing between it and restoration is the hold.
  const genesis = await seedGenesis({ note: SENSITIVE });
  const order = deletionOrder();
  const deleteReceipt = await issue(
    authorization({
      action: "delete",
      expectedHead: headOf(1, genesis),
      proposedContent: order,
    }),
  );
  const deleted = await store().delete({
    actor: SCOPE,
    authorizationId: deleteReceipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: order,
    mutationReceiptId: "mutation.holdrestore.delete",
  });
  assert.equal(deleted.verified, true);

  await placeHold(
    legalHold({ coverage: { kind: "records", recordIds: [RECORD_ID] } }),
  );
  const restored = { note: "reinstated" };
  const restoreReceipt = await issue(
    authorization({
      action: "restore",
      expectedHead: headOf(2, memoryContentDigest(order)),
      proposedContent: restored,
    }),
  );

  const result = await store().restore({
    actor: SCOPE,
    authorizationId: restoreReceipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: restored,
    mutationReceiptId: "mutation.holdrestore.restore",
  });

  assert.equal(result.rejection, "legal_hold_active");
  assert.equal((await rawVersions()).length, 2);
});

test("a hold that does not cover this record does not refuse it, so the check is coverage and not a blanket refusal", async () => {
  const genesis = await seedGenesis({ note: "free" }, {
    recordId: FREE_RECORD_ID,
  });
  await placeHold(
    legalHold({ coverage: { kind: "records", recordIds: [RECORD_ID] } }),
  );
  const next = { note: "corrected" };
  const receipt = await issue(
    authorization({
      action: "correct",
      targetRecordId: FREE_RECORD_ID,
      expectedHead: headOf(1, genesis),
      proposedContent: next,
    }),
  );

  const result = await store().correct({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: FREE_RECORD_ID,
    proposedContent: next,
    mutationReceiptId: "mutation.uncovered.correct",
  });

  assert.equal(result.rejection, null);
  assert.equal(result.verified, true);
});

test("a RELEASED hold no longer restricts, and the release is recorded", async () => {
  const genesis = await seedGenesis({ note: "original" });
  const hold = await placeHold(
    legalHold({ coverage: { kind: "records", recordIds: [RECORD_ID] } }),
  );
  const released = await holds().releaseHold({
    actor: SCOPE,
    holdId: hold.holdId,
    releasedAt: isoOffset(0),
    releasingAuthorityId: "authority.court",
    releaseOrderRef: "order:court/2026-0118",
  });
  assert.equal(released.rejection, null);
  assert.equal(released.recorded, true);

  const next = { note: "corrected after release" };
  const receipt = await issue(
    authorization({
      action: "correct",
      expectedHead: headOf(1, genesis),
      proposedContent: next,
    }),
  );
  const result = await store().correct({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: next,
    mutationReceiptId: "mutation.released.correct",
  });
  assert.equal(result.rejection, null);
  assert.equal(result.verified, true);

  const view = await holds().readHold(SCOPE, hold.holdId);
  assert.equal(view?.hold.status.state, "released");
  assert.ok(view && view.hold.status.state === "released");
  assert.equal(view.hold.status.releaseOrderRef, "order:court/2026-0118");
});

// ---------------------------------------------------------------------------
// 2. ALIAS ACTIONS ARE HELD TOO. Same hold, same lookup, different path.
// ---------------------------------------------------------------------------

const PARTICIPANT = "participant-hold-001";

async function setAliasPolicy(scope: MemoryScope = SCOPE): Promise<void> {
  await adminPool.query(
    `INSERT INTO memory_alias_tenant_policy
       (tenant_id, cross_workspace_policy, set_by_actor_id, policy_version)
     VALUES ($1,'workspace_isolated','actor.alias-steward','alias-policy/v1')
     ON CONFLICT (tenant_id) DO NOTHING`,
    [scope.tenantId],
  );
}

function evidenceFor(participantId: string): Wave1SubjectBoundEvidence {
  return Wave1SubjectBoundEvidenceSchema.parse({
    evidenceRef: "identity:verification/participant-record",
    evidenceDigest: EVIDENCE_DIGEST,
    observedAt: isoOffset(-60_000),
    freshUntil: isoOffset(3_600_000),
    subjectParticipantId: participantId,
  });
}

function aliasIdentity(input: {
  aliasId: string;
  observedAlias: string;
  participantId: string;
  evidence: Wave1SubjectBoundEvidence;
  scope?: MemoryScope;
}): CanonicalAliasIdentity {
  const scope = input.scope ?? SCOPE;
  const normalized = coreNormalizeAlias(input.observedAlias);
  const determination = determineAliasScript(normalized);
  const host = splitEmailAlias(normalized)?.domain ?? "example.com";
  return CanonicalAliasIdentitySchema.parse({
    schemaVersion: WAVE1_TRUSTED_MEMORY_CONTRACT_VERSION,
    aliasId: input.aliasId,
    scope,
    canonicalParticipantId: input.participantId,
    observedAlias: input.observedAlias,
    normalizationVersion: MEMORY_ALIAS_NORMALIZATION_VERSION,
    normalizedAlias: input.observedAlias.normalize("NFC").toLowerCase(),
    skeletonAlgorithm: MEMORY_CONFUSABLE_SKELETON_ALGORITHM,
    skeleton: coreAliasSkeleton(normalized),
    scriptDetermination: determination,
    restrictionLevel: aliasRestrictionLevel(normalized, determination),
    lookalikeDomain: {
      registrableDomain: host,
      isInternationalized: isInternationalizedDomain(host),
      risk: "none_detected",
      comparedCorpusRef: CORPUS_REF,
      determinedAt: isoOffset(-30_000),
    },
    sourceEvidenceRef: input.evidence.evidenceRef,
    sourceEvidenceDigest: input.evidence.evidenceDigest,
    observedAt: input.evidence.observedAt,
    freshUntil: input.evidence.freshUntil,
    verifyingAuthorityId: "authority.identity-steward",
    verifyingActorId: "actor.identity-steward",
    determinedAt: isoOffset(-30_000),
    dispositionProposal: "propose_accept",
  });
}

async function prepareAssign(aliasId: string, observedAlias: string) {
  await setAliasPolicy();
  const genesis = await seedGenesis(
    { participant: PARTICIPANT, generation: 1 },
    { recordId: PARTICIPANT },
  );
  const evidence = evidenceFor(PARTICIPANT);
  const alias = aliasIdentity({
    aliasId,
    observedAlias,
    participantId: PARTICIPANT,
    evidence,
  });
  const content = { participant: PARTICIPANT, generation: 2 };
  const receipt = await issue(
    authorization({
      action: "assign_alias",
      targetRecordId: PARTICIPANT,
      expectedHead: headOf(1, genesis),
      proposedContentDigest: aliasAssignmentDigest({
        record: content,
        alias,
        evidence,
      }),
    }),
  );
  return { alias, evidence, content, receipt };
}

test("assign_alias is refused under an active legal hold covering the participant record", async () => {
  const prepared = await prepareAssign("alias-held-001", "ceo@example.com");
  await placeHold(
    legalHold({ coverage: { kind: "records", recordIds: [PARTICIPANT] } }),
  );

  const result = await aliases().assignAlias({
    actor: SCOPE,
    authorizationId: prepared.receipt.authorizationId,
    participantRecordId: PARTICIPANT,
    alias: prepared.alias,
    evidence: prepared.evidence,
    proposedContent: prepared.content,
    mutationReceiptId: "mutation.hold.assign",
  });

  assert.equal(result.verified, false);
  // The alias store does not carry a `legal_hold_active` branch of its own;
  // the DATABASE refuses the append, which is the enforcement point, and the
  // store reports the refusal it saw. Asserted as `storage_rejected`
  // deliberately rather than rounded up into a friendlier name.
  assert.equal(result.rejection, "storage_rejected");
  const bindings = await adminPool.query(
    `SELECT count(*)::int AS n FROM memory_alias_bindings WHERE alias_id = $1`,
    ["alias-held-001"],
  );
  assert.equal(bindings.rows[0].n, 0);
});

test("remove_alias is refused under a hold placed after the binding", async () => {
  const prepared = await prepareAssign("alias-held-002", "cfo@example.com");
  const bound = await aliases().assignAlias({
    actor: SCOPE,
    authorizationId: prepared.receipt.authorizationId,
    participantRecordId: PARTICIPANT,
    alias: prepared.alias,
    evidence: prepared.evidence,
    proposedContent: prepared.content,
    mutationReceiptId: "mutation.hold.removeprep",
  });
  assert.equal(bound.verified, true, "the honest bind must succeed first");

  await placeHold(
    legalHold({ coverage: { kind: "records", recordIds: [PARTICIPANT] } }),
  );

  const headDigest = memoryContentDigest(prepared.content);
  const removalContent = { participant: PARTICIPANT, generation: 3 };
  const removal = await issue(
    authorization({
      action: "remove_alias",
      targetRecordId: PARTICIPANT,
      expectedHead: headOf(2, headDigest),
      proposedContentDigest: aliasRemovalDigest({
        record: removalContent,
        aliasId: "alias-held-002",
      }),
    }),
  );

  const result = await aliases().removeAlias({
    actor: SCOPE,
    authorizationId: removal.authorizationId,
    participantRecordId: PARTICIPANT,
    aliasId: "alias-held-002",
    proposedContent: removalContent,
    mutationReceiptId: "mutation.hold.remove",
  });

  assert.equal(result.verified, false);
  assert.equal(result.rejection, "storage_rejected");
  const active = await adminPool.query(
    `SELECT removed_at FROM memory_alias_bindings WHERE alias_id = $1`,
    ["alias-held-002"],
  );
  assert.equal(active.rows[0].removed_at, null);
});

test("a SUBJECTS hold refuses an alias binding for the participant it names", async () => {
  const prepared = await prepareAssign("alias-held-003", "coo@example.com");
  await placeHold(
    legalHold({
      coverage: { kind: "subjects", canonicalParticipantIds: [PARTICIPANT] },
    }),
  );

  const result = await aliases().assignAlias({
    actor: SCOPE,
    authorizationId: prepared.receipt.authorizationId,
    participantRecordId: PARTICIPANT,
    alias: prepared.alias,
    evidence: prepared.evidence,
    proposedContent: prepared.content,
    mutationReceiptId: "mutation.subjects.assign",
  });

  assert.equal(result.verified, false);
  assert.equal(result.rejection, "storage_rejected");
});

// ---------------------------------------------------------------------------
// 3. THE ENFORCEMENT POINT: a hostile writer that never calls the store.
// ---------------------------------------------------------------------------

/** Append a version directly, as the mutator, with a real consumed witness. */
async function hostileAppend(input: {
  action: string;
  state?: "active" | "deleted";
  version: number;
  predecessorDigest: string | null;
  content: unknown;
  recordId?: string;
  scope?: MemoryScope;
  label: string;
}): Promise<void> {
  const scope = input.scope ?? SCOPE;
  const recordId = input.recordId ?? RECORD_ID;
  const authorizationId = `hostile-${input.label}`.padEnd(26, "0");
  const mutationReceiptId = `mutation.hostile.${input.label}`;
  await witnessAppend({
    authorizationId,
    mutationReceiptId,
    recordId,
    scope,
    action: input.action,
  });
  const digest = memoryContentDigest(input.content);
  const payload = {
    schemaVersion: MEMORY_RECORD_VERSION_SCHEMA_VERSION,
    recordId,
    version: input.version,
    state: input.state ?? "active",
    scope,
    content: input.content,
    contentDigest: digest,
    predecessorDigest: input.predecessorDigest,
    authorizationId,
    mutationReceiptId,
    createdAt: isoOffset(0),
  };
  await runAs(
    "aaliyah_memory_mutator",
    `INSERT INTO memory_record_versions
       (tenant_id, workspace_id, principal_id, user_id, record_id, version,
        state, content_digest, predecessor_digest, authorization_id,
        mutation_receipt_id, payload)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
    [
      scope.tenantId,
      scope.workspaceId,
      scope.principalId,
      scope.userId,
      recordId,
      input.version,
      payload.state,
      digest,
      input.predecessorDigest,
      authorizationId,
      mutationReceiptId,
      JSON.stringify(payload),
    ],
  );
}

test("a hostile direct INSERT as the mutator role is refused for a held record", async () => {
  const genesis = await seedGenesis({ note: SENSITIVE });
  const hold = await placeHold(
    legalHold({ coverage: { kind: "records", recordIds: [RECORD_ID] } }),
  );

  await assert.rejects(
    () =>
      hostileAppend({
        action: "correct",
        version: 2,
        predecessorDigest: genesis,
        content: { note: "rewritten by a writer that never called the store" },
        label: "held",
      }),
    new RegExp(`legal hold ${hold.holdId} restricts correct on this record`),
  );
  assert.equal((await rawVersions()).length, 1);
});

test("every restricted action is refused for a direct writer, one statement each", async () => {
  const genesis = await seedGenesis({ note: SENSITIVE });
  const hold = await placeHold(
    legalHold({ coverage: { kind: "entire_scope" } }),
  );
  for (const action of [
    "create",
    "correct",
    "delete",
    "restore",
    "promote",
    "assign_alias",
    "remove_alias",
    "merge_identity",
    "split_identity",
  ] as const) {
    await assert.rejects(
      () =>
        hostileAppend({
          action,
          state: action === "delete" ? "deleted" : "active",
          version: 2,
          predecessorDigest: genesis,
          content:
            action === "delete" ? deletionOrder() : { note: "attempted" },
          label: `every-${action}`,
        }),
      new RegExp(`legal hold ${hold.holdId} restricts ${action} on this record`),
      `an entire-scope hold must restrict ${action}`,
    );
  }
  assert.equal((await rawVersions()).length, 1);
});

test("a hostile direct INSERT into memory_alias_bindings is refused for a held participant", async () => {
  await setAliasPolicy();
  const hold = await placeHold(
    legalHold({
      coverage: { kind: "subjects", canonicalParticipantIds: [PARTICIPANT] },
    }),
  );
  const authorizationId = "hostile-binding-000000000000";
  const mutationReceiptId = "mutation.hostile.binding";
  await witnessAppend({
    authorizationId,
    mutationReceiptId,
    recordId: PARTICIPANT,
    action: "assign_alias",
  });
  const payload = {
    schemaVersion: WAVE1_TRUSTED_MEMORY_CONTRACT_VERSION,
    scope: SCOPE,
    aliasId: "alias-hostile-001",
    normalizedAlias: "ceo@example.com",
    skeleton: "ceo@example.com",
    canonicalParticipantId: PARTICIPANT,
    subjectParticipantId: PARTICIPANT,
    crossWorkspacePolicy: "workspace_isolated",
    scopeKey: SCOPE.workspaceId,
    authorizationId,
    mutationReceiptId,
  };
  await assert.rejects(
    () =>
      runAs(
        "aaliyah_memory_mutator",
        `INSERT INTO memory_alias_bindings
           (tenant_id, workspace_id, principal_id, user_id,
            cross_workspace_policy, scope_key, alias_id, normalized_alias,
            skeleton, skeleton_algorithm, normalization_profile,
            canonical_participant_id, registrable_domain, script_code,
            restriction_level, subject_participant_id, source_evidence_ref,
            source_evidence_digest, observed_at, fresh_until, authorization_id,
            mutation_receipt_id, bound_at, payload)
         VALUES ($1,$2,$3,$4,'workspace_isolated',$5,'alias-hostile-001',
                 'ceo@example.com','ceo@example.com',$6,$7,$8,'example.com',
                 'Latn','ascii_only',$8,'identity:verification/x',$9,
                 now() - interval '1 minute', now() + interval '1 hour',
                 $10,$11, now(), $12)`,
        [
          SCOPE.tenantId,
          SCOPE.workspaceId,
          SCOPE.principalId,
          SCOPE.userId,
          SCOPE.workspaceId,
          MEMORY_CONFUSABLE_SKELETON_ALGORITHM,
          MEMORY_ALIAS_NORMALIZATION_VERSION,
          PARTICIPANT,
          EVIDENCE_DIGEST,
          authorizationId,
          mutationReceiptId,
          JSON.stringify(payload),
        ],
      ),
    new RegExp(
      `legal hold ${hold.holdId} restricts assign_alias on this participant`,
    ),
  );
});

// ---------------------------------------------------------------------------
// 4. CARVE-OUTS: exactly what they name, and nothing more.
// ---------------------------------------------------------------------------

test("a carve-out permits exactly the action it names and nothing more", async () => {
  const genesis = await seedGenesis({ note: "original" });
  await placeHold(
    legalHold({
      coverage: { kind: "records", recordIds: [RECORD_ID] },
      carveOutActions: ["promote"],
    }),
  );

  // The carved-out action is permitted.
  const promoted = { note: "original", standing: "canonical" };
  const promoteReceipt = await issue(
    authorization({
      action: "promote",
      expectedHead: headOf(1, genesis),
      proposedContent: promoted,
    }),
  );
  const promotion = await store().promote({
    actor: SCOPE,
    authorizationId: promoteReceipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: promoted,
    mutationReceiptId: "mutation.carve.promote",
  });
  assert.equal(promotion.rejection, null);
  assert.equal(promotion.verified, true);

  // And NOTHING else is. One statement per action, so each is killable.
  const promotedDigest = memoryContentDigest(promoted);
  const correction = { note: "rewritten" };
  const correctReceipt = await issue(
    authorization({
      action: "correct",
      expectedHead: headOf(2, promotedDigest),
      proposedContent: correction,
    }),
  );
  assert.equal(
    (
      await store().correct({
        actor: SCOPE,
        authorizationId: correctReceipt.authorizationId,
        recordId: RECORD_ID,
        proposedContent: correction,
        mutationReceiptId: "mutation.carve.correct",
      })
    ).rejection,
    "legal_hold_active",
  );

  const order = deletionOrder();
  const deleteReceipt = await issue(
    authorization({
      action: "delete",
      expectedHead: headOf(2, promotedDigest),
      proposedContent: order,
    }),
  );
  assert.equal(
    (
      await store().delete({
        actor: SCOPE,
        authorizationId: deleteReceipt.authorizationId,
        recordId: RECORD_ID,
        proposedContent: order,
        mutationReceiptId: "mutation.carve.delete",
      })
    ).rejection,
    "legal_hold_active",
  );

  assert.equal((await rawVersions()).length, 2);
});

test("a carve-out for a content-destroying action cannot be stored at all", async () => {
  for (const action of [
    "delete",
    "correct",
    "merge_identity",
    "split_identity",
  ] as const) {
    // The CONTRACT refuses to build one.
    assert.equal(
      LegalHoldSchema.safeParse({
        schemaVersion: WAVE1_TRUSTED_MEMORY_CONTRACT_VERSION,
        holdId: "hold-carve-illegal",
        scope: SCOPE,
        matterRef: "matter:acme-v-globex/2026",
        issuingAuthorityId: "authority.general-counsel",
        issuedAt: isoOffset(-120_000),
        coverage: { kind: "entire_scope" },
        status: { state: "active" },
        carveOuts: [
          {
            action,
            orderRef: "order:court/2026-0117",
            grantingAuthorityId: "authority.court",
            grantedAt: isoOffset(-60_000),
          },
        ],
      }).success,
      false,
      `the contract must refuse a carve-out for ${action}`,
    );
    // And so does the DATABASE, for a writer that never loads the contract.
    await adminPool.query(
      `INSERT INTO memory_legal_holds
         (tenant_id, workspace_id, principal_id, user_id, hold_id, matter_ref,
          issuing_authority_id, issued_at, coverage_kind, status_state, payload)
       VALUES ($1,$2,$3,$4,$5,'matter:acme-v-globex/2026',
               'authority.general-counsel', now() - interval '1 hour',
               'entire_scope','active',$6)
       ON CONFLICT DO NOTHING`,
      [
        SCOPE.tenantId,
        SCOPE.workspaceId,
        SCOPE.principalId,
        SCOPE.userId,
        "hold-carve-db",
        JSON.stringify({
          scope: SCOPE,
          holdId: "hold-carve-db",
          matterRef: "matter:acme-v-globex/2026",
          issuingAuthorityId: "authority.general-counsel",
          coverage: { kind: "entire_scope" },
          status: { state: "active" },
        }),
      ],
    );
    await assert.rejects(
      () =>
        adminPool.query(
          `INSERT INTO memory_legal_hold_carve_outs
             (tenant_id, workspace_id, hold_id, action, order_ref,
              granting_authority_id, granted_at)
           VALUES ($1,$2,'hold-carve-db',$3,'order:court/2026-0117',
                   'authority.court', now())`,
          [SCOPE.tenantId, SCOPE.workspaceId, action],
        ),
      /memory_legal_hold_carve_outs_never/,
      `the database must refuse a carve-out for ${action}`,
    );
  }
});

test("the store refuses to place a hold whose carve-out names a forbidden action", async () => {
  // `legalHoldRestricts` is the contract's declaration reader. Asserting it
  // here is what ties the store's behaviour to the function that used to have
  // no caller at all.
  const hold = legalHold({
    coverage: { kind: "entire_scope" },
    carveOutActions: ["promote"],
  });
  assert.equal(legalHoldRestricts(hold, "promote"), false);
  assert.equal(legalHoldRestricts(hold, "delete"), true);
  assert.equal(legalHoldRestricts(hold, "correct"), true);

  const forged = {
    ...hold,
    carveOuts: [
      {
        action: "delete",
        orderRef: "order:court/2026-0117",
        grantingAuthorityId: "authority.court",
        grantedAt: isoOffset(-60_000),
      },
    ],
  };
  const result = await holds().placeHold(SCOPE, forged);
  assert.equal(result.recorded, false);
  // `hold_malformed`, not `hold_carve_out_forbidden`: the CONTRACT refuses the
  // value before the store's own redundant check ever sees it. Recorded as
  // observed rather than as expected.
  assert.equal(result.rejection, "hold_malformed");
});

// ---------------------------------------------------------------------------
// 5. ERASURE. Asserted by direct SQL against the raw bytes.
// ---------------------------------------------------------------------------

test("a permitted delete destroys the content of EVERY prior version, proven by direct SQL", async () => {
  const genesis = await seedGenesis({
    note: SENSITIVE,
    settlement: "eight figures",
  });
  const corrected = { note: SENSITIVE, settlement: "nine figures" };
  const correctReceipt = await issue(
    authorization({
      action: "correct",
      expectedHead: headOf(1, genesis),
      proposedContent: corrected,
    }),
  );
  assert.equal(
    (
      await store().correct({
        actor: SCOPE,
        authorizationId: correctReceipt.authorizationId,
        recordId: RECORD_ID,
        proposedContent: corrected,
        mutationReceiptId: "mutation.erase.correct",
      })
    ).verified,
    true,
  );

  // Two versions, both holding the sensitive value. This is the pre-state the
  // assertion below is meaningful against.
  const before = await rawVersions();
  assert.equal(before.length, 2);
  assert.ok(before.every((row) => row.payload_text.includes(SENSITIVE)));

  const order = deletionOrder();
  const deleteReceipt = await issue(
    authorization({
      action: "delete",
      expectedHead: headOf(2, memoryContentDigest(corrected)),
      proposedContent: order,
    }),
  );
  const result = await store().delete({
    actor: SCOPE,
    authorizationId: deleteReceipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: order,
    mutationReceiptId: "mutation.erase.delete",
    tombstoneId: "tombstone-erase-001",
  });
  assert.equal(result.rejection, null);
  assert.equal(result.verified, true);

  // READ AS THE OWNER, FROM THE TABLE, NOT THROUGH THE STORE.
  const rows = await rawVersions();
  assert.equal(rows.length, 3);
  for (const row of rows) {
    assert.ok(
      !row.payload_text.includes(SENSITIVE),
      `version ${row.version} still holds the destroyed value`,
    );
    assert.ok(!row.payload_text.includes("eight figures"));
    assert.ok(!row.payload_text.includes("nine figures"));
  }
  // Not one row anywhere in the table, not just not in this record's rows.
  const anywhere = await adminPool.query(
    `SELECT count(*)::int AS n FROM memory_record_versions
      WHERE payload::text LIKE '%' || $1 || '%'`,
    [SENSITIVE],
  );
  assert.equal(anywhere.rows[0].n, 0);

  // The erasure is witnessed on the row, once, by the tombstone that ordered
  // it. The deleted head itself is not erased: it carries the deletion order,
  // which is what makes the chain's last content digest meaningful.
  assert.equal(at(rows, 0).erasure_tombstone_id, "tombstone-erase-001");
  assert.equal(at(rows, 1).erasure_tombstone_id, "tombstone-erase-001");
  assert.notEqual(at(rows, 0).content_erased_at, null);
  assert.notEqual(at(rows, 1).content_erased_at, null);
  assert.equal(at(rows, 2).content_erased_at, null);
  assert.equal(at(rows, 2).state, "deleted");
});

test("the tombstone accounts for what was destroyed and does NOT contain it", async () => {
  await seedGenesis({ note: SENSITIVE, settlement: "eight figures" });
  const order = deletionOrder();
  const receipt = await issue(
    authorization({
      action: "delete",
      expectedHead: headOf(
        1,
        memoryContentDigest({ note: SENSITIVE, settlement: "eight figures" }),
      ),
      proposedContent: order,
    }),
  );
  const result = await store().delete({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: order,
    mutationReceiptId: "mutation.tombstone.001",
    tombstoneId: "tombstone-accounting-001",
  });
  assert.equal(result.rejection, null);
  const tombstone = result.tombstone;
  assert.ok(tombstone, "a verified deletion must return a tombstone");

  assert.equal(tombstone.targetRecordId, RECORD_ID);
  assert.equal(tombstone.targetVersion, 1);
  assert.equal(tombstone.tombstoneVersion, 2);
  assert.equal(tombstone.reason, "subject_erasure_request");
  assert.equal(tombstone.retention.legalHoldState.state, "none");
  assert.equal(
    tombstone.restorationEligibility.kind,
    "ineligible_payload_destroyed",
  );
  assert.equal(tombstone.cacheIndexPropagation, "unknown");
  assert.equal(tombstone.derivedData.length, 7);
  assert.ok(
    tombstone.derivedData.every((entry) => entry.disposition === "unknown"),
  );
  // The FIELD NAMES, computed from what was actually stored.
  assert.deepEqual(tombstone.destroyedFieldNames, [
    "content_note",
    "content_settlement",
  ]);
  assert.deepEqual(
    tombstone.retainedFieldNames,
    MEMORY_RETAINED_ENVELOPE_FIELD_NAMES,
  );
  // The contract's own rule: no name may be in both lists.
  for (const name of tombstone.destroyedFieldNames) {
    assert.ok(!tombstone.retainedFieldNames.includes(name));
  }
  // THE DIGEST BINDS THE ACCOUNT. Recomputed here, not trusted.
  const { tombstoneDigest, ...withoutDigest } = tombstone;
  assert.equal(tombstoneDigest, memoryTombstoneDigest(withoutDigest));

  // THE PAYLOAD IS NOT IN THE TOMBSTONE. Serialized whole and searched — this
  // is the assertion that fails if the destroyed value ever leaks into the
  // accounting, which is exactly the reviewed defect.
  const serialized = JSON.stringify(tombstone);
  assert.ok(!serialized.includes(SENSITIVE));
  assert.ok(!serialized.includes("eight figures"));
  assert.ok(!serialized.includes("divorce"));
  // And not on disk either.
  const stored = await adminPool.query(
    `SELECT payload::text AS payload_text FROM memory_tombstones
      WHERE tombstone_id = $1`,
    ["tombstone-accounting-001"],
  );
  assert.ok(!stored.rows[0].payload_text.includes(SENSITIVE));

  // INDEPENDENTLY READ BACK, on the read-back pool under the SELECT-only role.
  const readBack = await store().readTombstone(SCOPE, "tombstone-accounting-001");
  assert.deepEqual(readBack, tombstone);
  // And not by another principal in the same workspace.
  assert.equal(
    await store().readTombstone(OTHER_SCOPE, "tombstone-accounting-001"),
    null,
  );
});

test("the database refuses a tombstone that carries free-form text", async () => {
  // The NEGATIVE CONTROL for the structural rule. Written directly, as the
  // mutator, with a payload that is a valid tombstone in every respect except
  // that one identifier has been replaced by the destroyed sentence.
  await seedGenesis({ note: SENSITIVE });
  const order = deletionOrder();
  const receipt = await issue(
    authorization({
      action: "delete",
      expectedHead: headOf(1, memoryContentDigest({ note: SENSITIVE })),
      proposedContent: order,
    }),
  );
  const deleted = await store().delete({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: order,
    mutationReceiptId: "mutation.freetext.001",
    tombstoneId: "tombstone-freetext-001",
  });
  const baseline = deleted.tombstone;
  assert.ok(baseline);

  const leaking = {
    ...baseline,
    tombstoneId: "tombstone-freetext-002",
    reasonEvidenceRef: SENSITIVE,
  };
  await assert.rejects(
    () =>
      runAs(
        "aaliyah_memory_mutator",
        `INSERT INTO memory_tombstones
           (tenant_id, workspace_id, principal_id, user_id, tombstone_id,
            target_record_id, target_version, tombstone_version,
            authorization_id, mutation_receipt_id, reason, effective_at,
            retain_until, legal_hold_state, cache_index_propagation,
            restoration_eligibility_kind, tombstone_digest, payload)
         VALUES ($1,$2,$3,$4,'tombstone-freetext-002',$5,1,2,$6,$7,
                 'subject_erasure_request', now(), NULL, 'none', 'unknown',
                 'ineligible_payload_destroyed',$8,$9)`,
        [
          SCOPE.tenantId,
          SCOPE.workspaceId,
          SCOPE.principalId,
          SCOPE.userId,
          RECORD_ID,
          receipt.authorizationId,
          "mutation.freetext.001",
          baseline.tombstoneDigest,
          JSON.stringify(leaking),
        ],
      ),
    /a tombstone may not carry free-form text/,
  );

  // And a member NAMED for a payload is refused on its own, so the two
  // controls are separable.
  const smuggling = {
    ...baseline,
    tombstoneId: "tombstone-freetext-003",
    content: "ceo-divorce-settlement",
  };
  await assert.rejects(
    () =>
      runAs(
        "aaliyah_memory_mutator",
        `INSERT INTO memory_tombstones
           (tenant_id, workspace_id, principal_id, user_id, tombstone_id,
            target_record_id, target_version, tombstone_version,
            authorization_id, mutation_receipt_id, reason, effective_at,
            retain_until, legal_hold_state, cache_index_propagation,
            restoration_eligibility_kind, tombstone_digest, payload)
         VALUES ($1,$2,$3,$4,'tombstone-freetext-003',$5,1,2,$6,$7,
                 'subject_erasure_request', now(), NULL, 'none', 'unknown',
                 'ineligible_payload_destroyed',$8,$9)`,
        [
          SCOPE.tenantId,
          SCOPE.workspaceId,
          SCOPE.principalId,
          SCOPE.userId,
          RECORD_ID,
          receipt.authorizationId,
          "mutation.freetext.001",
          baseline.tombstoneDigest,
          JSON.stringify(smuggling),
        ],
      ),
    /a tombstone must carry exactly the contract member set/,
  );
});

test("a deleted version may not carry the record; its content must be a deletion order", async () => {
  const genesis = await seedGenesis({ note: SENSITIVE });
  await assert.rejects(
    () =>
      hostileAppend({
        action: "delete",
        state: "deleted",
        version: 2,
        predecessorDigest: genesis,
        content: { note: SENSITIVE },
        label: "order",
      }),
    /the content of a deleted version must be a deletion order/,
  );
  // Through the store, the same content is refused with a named rejection.
  const receipt = await issue(
    authorization({
      action: "delete",
      expectedHead: headOf(1, genesis),
      proposedContent: { note: SENSITIVE },
    }),
  );
  const result = await store().delete({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: { note: SENSITIVE },
    mutationReceiptId: "mutation.order.bad",
  });
  assert.equal(result.rejection, "deletion_order_malformed");
});

test("DELETED CANNOT BE A LABEL: a deleted head with an unerased predecessor is refused at COMMIT", async () => {
  // The deferred constraint trigger, exercised by the only writer that can
  // reach it — one that marks a record deleted and never erases anything.
  const genesis = await seedGenesis({ note: SENSITIVE });
  await assert.rejects(
    () =>
      hostileAppend({
        action: "delete",
        state: "deleted",
        version: 2,
        predecessorDigest: genesis,
        content: deletionOrder(),
        label: "label",
      }),
    /a deletion must erase every prior version of the record/,
  );
  const rows = await rawVersions();
  assert.equal(rows.length, 1);
  assert.ok(at(rows, 0).payload_text.includes(SENSITIVE));
});

test("a deletion is refused while a retention obligation is unexpired, and permitted once it lapses", async () => {
  await seedGenesis({ note: SENSITIVE });
  const genesisDigest = memoryContentDigest({ note: SENSITIVE });
  const imposed = await holds().imposeRetention(SCOPE, {
    obligationId: "retention-001",
    recordId: RECORD_ID,
    policyRef: "policy:retention/seven-years",
    imposingAuthorityId: "authority.records-manager",
    imposedAt: isoOffset(-60_000),
    retainUntil: isoOffset(3_600_000),
  });
  assert.equal(imposed.rejection, null);

  const order = deletionOrder("retention_expiry");
  const blocked = await issue(
    authorization({
      action: "delete",
      expectedHead: headOf(1, genesisDigest),
      proposedContent: order,
    }),
  );
  const refused = await store().delete({
    actor: SCOPE,
    authorizationId: blocked.authorizationId,
    recordId: RECORD_ID,
    proposedContent: order,
    mutationReceiptId: "mutation.retention.blocked",
  });
  assert.equal(refused.rejection, "retention_obligation_active");
  assert.ok(at(await rawVersions(), 0).payload_text.includes(SENSITIVE));

  // A SECOND record carrying only a LAPSED obligation. An obligation row is
  // append-only — it cannot be deleted by anyone, which is itself the point —
  // so the permitted case needs its own record. The live obligation is what
  // refuses above, so dropping the `retain_until > now()` predicate would let
  // this record's twin through; that is what the pair separates.
  const lapsedGenesis = await seedGenesis(
    { note: "expired retention" },
    { recordId: FREE_RECORD_ID },
  );
  await holds().imposeRetention(SCOPE, {
    obligationId: "retention-002",
    recordId: FREE_RECORD_ID,
    policyRef: "policy:retention/seven-years",
    imposingAuthorityId: "authority.records-manager",
    imposedAt: isoOffset(-7_200_000),
    retainUntil: isoOffset(-3_600_000),
  });
  const allowed = await issue(
    authorization({
      action: "delete",
      targetRecordId: FREE_RECORD_ID,
      expectedHead: headOf(1, lapsedGenesis),
      proposedContent: order,
    }),
  );
  const result = await store().delete({
    actor: SCOPE,
    authorizationId: allowed.authorizationId,
    recordId: FREE_RECORD_ID,
    proposedContent: order,
    mutationReceiptId: "mutation.retention.allowed",
    tombstoneId: "tombstone-retention-001",
  });
  assert.equal(result.rejection, null);
  assert.equal(result.verified, true);
  // The lapsed obligation is RECORDED on the tombstone, because "nothing ever
  // bound this record" and "an obligation bound it and expired" are different
  // facts about a destruction.
  assert.notEqual(result.tombstone?.retention.retainUntil, null);
});

// ---------------------------------------------------------------------------
// 6. ORDINARY RETRIEVAL, AND THE CHAIN AFTER ERASURE.
// ---------------------------------------------------------------------------

test("a deleted record is excluded from ordinary retrieval but still has a head", async () => {
  const genesis = await seedGenesis({ note: SENSITIVE });
  assert.equal(
    (await store().retrieve(SCOPE, RECORD_ID))?.version,
    1,
    "the record must be retrievable before it is deleted",
  );

  const order = deletionOrder();
  const receipt = await issue(
    authorization({
      action: "delete",
      expectedHead: headOf(1, genesis),
      proposedContent: order,
    }),
  );
  assert.equal(
    (
      await store().delete({
        actor: SCOPE,
        authorizationId: receipt.authorizationId,
        recordId: RECORD_ID,
        proposedContent: order,
        mutationReceiptId: "mutation.retrieval.delete",
        tombstoneId: "tombstone-retrieval-001",
      })
    ).verified,
    true,
  );

  assert.equal(await store().retrieve(SCOPE, RECORD_ID), null);
  // `readHead` DELIBERATELY still answers: a compare-and-swap has to be able
  // to see the head it is swapping against, or restoration is impossible.
  const head = await store().readHead(SCOPE, RECORD_ID);
  assert.equal(head?.state, "deleted");
  assert.equal(head?.version, 2);
});

test("the chain's integrity properties still hold after an erasure", async () => {
  const genesis = await seedGenesis({ note: SENSITIVE, revision: 1 });
  const corrected = { note: SENSITIVE, revision: 2 };
  const correctReceipt = await issue(
    authorization({
      action: "correct",
      expectedHead: headOf(1, genesis),
      proposedContent: corrected,
    }),
  );
  await store().correct({
    actor: SCOPE,
    authorizationId: correctReceipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: corrected,
    mutationReceiptId: "mutation.chain.correct",
  });
  const order = deletionOrder();
  const deleteReceipt = await issue(
    authorization({
      action: "delete",
      expectedHead: headOf(2, memoryContentDigest(corrected)),
      proposedContent: order,
    }),
  );
  assert.equal(
    (
      await store().delete({
        actor: SCOPE,
        authorizationId: deleteReceipt.authorizationId,
        recordId: RECORD_ID,
        proposedContent: order,
        mutationReceiptId: "mutation.chain.delete",
        tombstoneId: "tombstone-chain-001",
      })
    ).verified,
    true,
  );

  // MIGRATION 034's PROPERTIES, RE-DERIVED FROM THE ROWS THEMSELVES.
  const rows = await rawVersions();
  assert.equal(rows.length, 3);
  assert.deepEqual(
    rows.map((row) => row.version),
    [1, 2, 3],
  );
  assert.equal(at(rows, 0).predecessor_digest, null);
  for (let index = 1; index < rows.length; index += 1) {
    assert.equal(
      at(rows, index).predecessor_digest,
      at(rows, index - 1).content_digest,
      `version ${at(rows, index).version} must link to its predecessor`,
    );
  }
  // The digests are the ORIGINAL ones: erasure did not rewrite them, which is
  // precisely why the linkage above is still checkable.
  assert.equal(at(rows, 0).content_digest, genesis);
  assert.equal(at(rows, 1).content_digest, memoryContentDigest(corrected));
  assert.equal(at(rows, 2).content_digest, memoryContentDigest(order));
  // Every version is still witnessed by a consumed authorization, which is
  // what migration 034's trigger requires of every appended row.
  const unwitnessed = await adminPool.query(
    `SELECT count(*)::int AS n
       FROM memory_record_versions AS v
      WHERE v.record_id = $1
        AND NOT EXISTS (SELECT 1 FROM memory_authorization_nonces AS n
                         WHERE n.tenant_id = v.tenant_id
                           AND n.authorization_id = v.authorization_id
                           AND n.consumed_at IS NOT NULL
                           AND n.consumed_by_mutation_receipt_id
                               = v.mutation_receipt_id)`,
    [RECORD_ID],
  );
  assert.equal(unwitnessed.rows[0].n, 0);
  // And the append-only guard still refuses an ordinary rewrite afterwards.
  await assert.rejects(
    () =>
      adminPool.query(
        // Version 3 is the deleted head and is NOT erased, so this reaches
        // the generic append-only refusal rather than the erased-row one.
        `UPDATE memory_record_versions SET content_digest = $1 WHERE version = 3`,
        [`sha256:${"9".repeat(64)}`],
      ),
    /UPDATE on memory_record_versions is forbidden/,
  );
  // And an erased version is refused with its own, more specific message.
  await assert.rejects(
    () =>
      adminPool.query(
        `UPDATE memory_record_versions SET content_digest = $1 WHERE version = 1`,
        [`sha256:${"9".repeat(64)}`],
      ),
    /an erased record version is immutable/,
  );
});

test("erasure may null the content and nothing else, for every writer including the owner", async () => {
  const genesis = await seedGenesis({ note: SENSITIVE });
  const order = deletionOrder();
  const receipt = await issue(
    authorization({
      action: "delete",
      expectedHead: headOf(1, genesis),
      proposedContent: order,
    }),
  );
  assert.equal(
    (
      await store().delete({
        actor: SCOPE,
        authorizationId: receipt.authorizationId,
        recordId: RECORD_ID,
        proposedContent: order,
        mutationReceiptId: "mutation.rewrite.delete",
        tombstoneId: "tombstone-rewrite-001",
      })
    ).verified,
    true,
  );

  // An erased version is immutable, including un-erasing it.
  await assert.rejects(
    () =>
      adminPool.query(
        `UPDATE memory_record_versions
            SET content_erased_at = NULL, erasure_tombstone_id = NULL
          WHERE version = 1`,
      ),
    /an erased record version is immutable/,
  );
  // A fresh record cannot be erased without a tombstone that names it.
  const other = await seedGenesis({ note: "other" }, {
    recordId: FREE_RECORD_ID,
  });
  assert.ok(other);
  await assert.rejects(
    () =>
      adminPool.query(
        `UPDATE memory_record_versions
            SET payload = jsonb_set(payload, '{content}', 'null'::jsonb),
                content_erased_at = now(),
                erasure_tombstone_id = 'tombstone-does-not-exist'
          WHERE record_id = $1`,
        [FREE_RECORD_ID],
      ),
    /no tombstone authorizes this erasure/,
  );
  // And an "erasure" that also rewrites the chain metadata is refused.
  await assert.rejects(
    () =>
      adminPool.query(
        `UPDATE memory_record_versions
            SET payload = jsonb_set(payload, '{content}', 'null'::jsonb),
                content_erased_at = now(),
                erasure_tombstone_id = 'tombstone-rewrite-001',
                content_digest = $2
          WHERE record_id = $1 AND version = 1`,
        [FREE_RECORD_ID, `sha256:${"8".repeat(64)}`],
      ),
    /erasure may not rewrite the chain metadata/,
  );
});

// ---------------------------------------------------------------------------
// 7. RESTORATION IS A SEPARATE AUTHORITY.
// ---------------------------------------------------------------------------

async function deleteThen(mutationReceiptId: string, tombstoneId: string) {
  const genesis = await seedGenesis({ note: SENSITIVE });
  const order = deletionOrder();
  const receipt = await issue(
    authorization({
      action: "delete",
      expectedHead: headOf(1, genesis),
      proposedContent: order,
    }),
  );
  const result = await store().delete({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: order,
    mutationReceiptId,
    tombstoneId,
  });
  assert.equal(result.verified, true, "the deletion must succeed first");
  return { deletedDigest: memoryContentDigest(order) };
}

test("a DELETE authorization cannot restore, and the database refuses it too", async () => {
  const { deletedDigest } = await deleteThen(
    "mutation.restore.seed",
    "tombstone-restore-001",
  );
  const restored = { note: "reinstated" };
  // A delete authorization aimed at the restore call site.
  const deleteAuth = await issue(
    authorization({
      action: "delete",
      expectedHead: headOf(2, deletedDigest),
      proposedContent: restored,
    }),
  );
  const throughStore = await store().restore({
    actor: SCOPE,
    authorizationId: deleteAuth.authorizationId,
    recordId: RECORD_ID,
    proposedContent: restored,
    mutationReceiptId: "mutation.restore.wrongauth",
  });
  assert.equal(throughStore.rejection, "authorization_action_mismatch");

  // And for a writer that never calls the store: a `delete` nonce cannot
  // produce an active version, so it cannot lift a deletion.
  await assert.rejects(
    () =>
      hostileAppend({
        action: "delete",
        state: "active",
        version: 3,
        predecessorDigest: deletedDigest,
        content: restored,
        label: "deleterestore",
      }),
    /a delete authorization may only produce a deleted version/,
  );
  // The mirror: a `restore` nonce cannot produce a deleted version, so a
  // restore authorization cannot be used to destroy.
  await assert.rejects(
    () =>
      hostileAppend({
        action: "restore",
        state: "deleted",
        version: 3,
        predecessorDigest: deletedDigest,
        content: deletionOrder(),
        label: "restoredelete",
      }),
    /only a delete authorization may produce a deleted version/,
  );
  assert.equal((await rawVersions()).length, 2);
});

test("a RESTORE authorization restores, and does not bring the destroyed payload back", async () => {
  const { deletedDigest } = await deleteThen(
    "mutation.restore.ok.seed",
    "tombstone-restore-002",
  );
  const restored = { note: "reinstated, without the destroyed payload" };
  const restoreAuth = await issue(
    authorization({
      action: "restore",
      expectedHead: headOf(2, deletedDigest),
      proposedContent: restored,
    }),
  );
  const result = await store().restore({
    actor: SCOPE,
    authorizationId: restoreAuth.authorizationId,
    recordId: RECORD_ID,
    proposedContent: restored,
    mutationReceiptId: "mutation.restore.ok",
  });
  assert.equal(result.rejection, null);
  assert.equal(result.verified, true);

  const head = await store().readHead(SCOPE, RECORD_ID);
  assert.equal(head?.state, "active");
  assert.equal(head?.version, 3);
  const retrieved = await store().retrieve(SCOPE, RECORD_ID);
  assert.deepEqual(retrieved?.content, restored);

  // THE DESTROYED PAYLOAD IS STILL GONE. Restoration returns the RECORD to an
  // active state; it does not resurrect what was erased, which is exactly what
  // the tombstone's `ineligible_payload_destroyed` says.
  const rows = await rawVersions();
  assert.equal(rows.length, 3);
  assert.ok(rows.every((row) => !row.payload_text.includes(SENSITIVE)));
});

test("a restore is refused when the head is not deleted", async () => {
  const genesis = await seedGenesis({ note: "still here" });
  const restored = { note: "restoring something that was never deleted" };
  const restoreAuth = await issue(
    authorization({
      action: "restore",
      expectedHead: headOf(1, genesis),
      proposedContent: restored,
    }),
  );
  const result = await store().restore({
    actor: SCOPE,
    authorizationId: restoreAuth.authorizationId,
    recordId: RECORD_ID,
    proposedContent: restored,
    mutationReceiptId: "mutation.restore.notdeleted",
  });
  assert.equal(result.rejection, "restore_head_not_deleted");
  assert.equal((await rawVersions()).length, 1);
});

test("a deleted record cannot be corrected back into existence", async () => {
  const { deletedDigest } = await deleteThen(
    "mutation.correctdeleted.seed",
    "tombstone-correctdeleted-001",
  );
  const rewritten = { note: "resurrected by correction" };
  const correctAuth = await issue(
    authorization({
      action: "correct",
      expectedHead: headOf(2, deletedDigest),
      proposedContent: rewritten,
    }),
  );
  const result = await store().correct({
    actor: SCOPE,
    authorizationId: correctAuth.authorizationId,
    recordId: RECORD_ID,
    proposedContent: rewritten,
    mutationReceiptId: "mutation.correctdeleted",
  });
  assert.equal(result.rejection, "record_deleted");
  await assert.rejects(
    () =>
      hostileAppend({
        action: "correct",
        version: 3,
        predecessorDigest: deletedDigest,
        content: rewritten,
        label: "correctdeleted",
      }),
    /a deleted record may only be restored/,
  );
});

// ---------------------------------------------------------------------------
// 8. PRIVILEGE: the restrained party cannot lift its own restraint.
// ---------------------------------------------------------------------------

test("the mutation role can read a hold and can do nothing else to one", async () => {
  const hold = await placeHold(
    legalHold({ coverage: { kind: "records", recordIds: [RECORD_ID] } }),
  );
  const client = await adminPool.connect();
  try {
    await client.query("BEGIN");
    await client.query('SET LOCAL ROLE "aaliyah_memory_mutator"');
    const readable = await client.query(
      `SELECT hold_id FROM memory_legal_holds WHERE hold_id = $1`,
      [hold.holdId],
    );
    assert.equal(readable.rows[0].hold_id, hold.holdId);
    for (const [statement, matcher] of [
      [
        `UPDATE memory_legal_holds SET status_state = 'released'`,
        /permission denied for table memory_legal_holds/,
      ],
      [
        `DELETE FROM memory_legal_holds`,
        /permission denied for table memory_legal_holds/,
      ],
      [
        `DELETE FROM memory_legal_hold_records`,
        /permission denied for table memory_legal_hold_records/,
      ],
      [
        `INSERT INTO memory_legal_hold_carve_outs
           (tenant_id, workspace_id, hold_id, action, order_ref,
            granting_authority_id, granted_at)
         VALUES ('t','w','h','promote','order:x/1','authority.x', now())`,
        /permission denied for table memory_legal_hold_carve_outs/,
      ],
      [
        `DELETE FROM memory_retention_obligations`,
        /permission denied for table memory_retention_obligations/,
      ],
    ] as Array<[string, RegExp]>) {
      await assert.rejects(() => client.query(statement), matcher);
      await client.query("ROLLBACK");
      await client.query("BEGIN");
      await client.query('SET LOCAL ROLE "aaliyah_memory_mutator"');
    }
  } finally {
    await client.query("ROLLBACK").catch(() => undefined);
    client.release();
  }
});

test("a released hold cannot be made active again, by anyone, including the owner", async () => {
  const hold = await placeHold(
    legalHold({ coverage: { kind: "records", recordIds: [RECORD_ID] } }),
  );
  await holds().releaseHold({
    actor: SCOPE,
    holdId: hold.holdId,
    releasedAt: isoOffset(0),
    releasingAuthorityId: "authority.court",
    releaseOrderRef: "order:court/2026-0118",
  });
  await assert.rejects(
    () =>
      adminPool.query(
        `UPDATE memory_legal_holds SET status_state = 'active',
                released_at = NULL, releasing_authority_id = NULL,
                release_order_ref = NULL
          WHERE hold_id = $1`,
        [hold.holdId],
      ),
    /a released legal hold is immutable/,
  );
  await assert.rejects(
    () =>
      adminPool.query(`DELETE FROM memory_legal_holds WHERE hold_id = $1`, [
        hold.holdId,
      ]),
    /DELETE on memory_legal_holds is forbidden/,
  );
});

test("releasing a hold may not rewrite its coverage", async () => {
  const hold = await placeHold(
    legalHold({ coverage: { kind: "records", recordIds: [RECORD_ID] } }),
  );
  await assert.rejects(
    () =>
      adminPool.query(
        `UPDATE memory_legal_holds
            SET status_state = 'released', released_at = now(),
                releasing_authority_id = 'authority.court',
                release_order_ref = 'order:court/2026-0118',
                matter_ref = 'matter:something-else/2026'
          WHERE hold_id = $1`,
        [hold.holdId],
      ),
    /releasing a hold may not rewrite its coverage/,
  );
  // A coverage row cannot be deleted out from under an active hold either.
  await assert.rejects(
    () =>
      adminPool.query(
        `DELETE FROM memory_legal_hold_records WHERE hold_id = $1`,
        [hold.holdId],
      ),
    /DELETE on memory_legal_hold_records is forbidden/,
  );
});

test("the hold-evaluation guard refuses an append whose action cannot be resolved", async () => {
  // Reachable only with migration 034's witness guard switched off, which is
  // itself the negative control: with it on, an unwitnessed append never gets
  // this far. Without this test the branch has no killing input at all.
  await seedGenesis({ note: "original" });
  await adminPool.query(
    `ALTER TABLE memory_record_versions
       DISABLE TRIGGER memory_record_versions_authorized_append`,
  );
  try {
    const content = { note: "unwitnessed" };
    const digest = memoryContentDigest(content);
    await assert.rejects(
      () =>
        runAs(
          "aaliyah_memory_mutator",
          `INSERT INTO memory_record_versions
             (tenant_id, workspace_id, principal_id, user_id, record_id,
              version, state, content_digest, predecessor_digest,
              authorization_id, mutation_receipt_id, payload)
           VALUES ($1,$2,$3,$4,$5,2,'active',$6,$7,
                   'auth-does-not-exist-000000','mutation.ghost',$8)`,
          [
            SCOPE.tenantId,
            SCOPE.workspaceId,
            SCOPE.principalId,
            SCOPE.userId,
            RECORD_ID,
            digest,
            memoryContentDigest({ note: "original" }),
            JSON.stringify({
              schemaVersion: MEMORY_RECORD_VERSION_SCHEMA_VERSION,
              recordId: RECORD_ID,
              version: 2,
              state: "active",
              scope: SCOPE,
              content,
              contentDigest: digest,
              predecessorDigest: memoryContentDigest({ note: "original" }),
              authorizationId: "auth-does-not-exist-000000",
              mutationReceiptId: "mutation.ghost",
              createdAt: isoOffset(0),
            }),
          ],
        ),
      /a legal hold cannot be evaluated/,
    );
  } finally {
    await adminPool.query(
      `ALTER TABLE memory_record_versions
         ENABLE TRIGGER memory_record_versions_authorized_append`,
    );
  }
});

// ---------------------------------------------------------------------------
// 9. REAL CONCURRENCY.
// ---------------------------------------------------------------------------

test("a delete and a correction racing the same head: exactly one commits", async () => {
  const genesis = await seedGenesis({ note: SENSITIVE });
  const corrected = { note: "corrected" };
  const order = deletionOrder();
  const correctAuth = await issue(
    authorization({
      action: "correct",
      expectedHead: headOf(1, genesis),
      proposedContent: corrected,
    }),
  );
  const deleteAuth = await issue(
    authorization({
      action: "delete",
      expectedHead: headOf(1, genesis),
      proposedContent: order,
    }),
  );

  // Two stores, two pools, two real connections. A simulated race proves the
  // simulation is deterministic and nothing else.
  const storeA = store();
  const storeB = createPostgresTrustedMemoryStore(adminPool, readPool);

  const [correction, deletion] = await Promise.all([
    storeA.correct({
      actor: SCOPE,
      authorizationId: correctAuth.authorizationId,
      recordId: RECORD_ID,
      proposedContent: corrected,
      mutationReceiptId: "mutation.race.correct",
    }),
    storeB.delete({
      actor: SCOPE,
      authorizationId: deleteAuth.authorizationId,
      recordId: RECORD_ID,
      proposedContent: order,
      mutationReceiptId: "mutation.race.delete",
      tombstoneId: "tombstone-race-001",
    }),
  ]);

  const winners = [correction, deletion].filter((r) => r.verified);
  assert.equal(winners.length, 1, "exactly one of the two may commit");
  const loser = [correction, deletion].find((r) => !r.verified);
  assert.ok(loser);
  // The loser read the winner's head and failed its compare-and-swap. If the
  // DELETE won, the correction is additionally refused because a deleted
  // record may only be restored; both are honest refusals and neither is a
  // silent success.
  assert.ok(
    loser.rejection === "head_mismatch" || loser.rejection === "record_deleted",
    `unexpected loser rejection: ${loser.rejection}`,
  );
  assert.equal((await rawVersions()).length, 2);

  if (deletion.verified) {
    // If the deletion won, the erasure is complete and the correction never
    // wrote the content it was carrying.
    const rows = await rawVersions();
    assert.ok(rows.every((row) => !row.payload_text.includes(SENSITIVE)));
    assert.ok(deletion.tombstone);
  } else {
    // If the correction won, nothing was destroyed and no tombstone exists.
    assert.equal(deletion.tombstone, null);
    const tombstones = await adminPool.query(
      `SELECT count(*)::int AS n FROM memory_tombstones`,
    );
    assert.equal(tombstones.rows[0].n, 0);
  }
});

/**
 * Build a tombstone row BY HAND, past the contract.
 *
 * `MemoryTombstoneSchema` refuses to construct a tombstone that admits an
 * active hold or claims an escrow, so a test that went through
 * `buildTombstone` could never reach the database constraints that say the
 * same thing. These two are not one control tested twice: the contract binds a
 * producer that loads it, and the CHECK binds every writer. The forged value
 * keeps every payload binding consistent with its columns, so the constraint
 * under test is the one that reports.
 */
async function forgeTombstoneRow(overrides: {
  tombstoneId: string;
  legalHoldState?: unknown;
  restorationEligibility?: unknown;
}): Promise<{ forged: Record<string, unknown>; digest: string }> {
  const genesis = await seedGenesis({ note: SENSITIVE });
  const order = deletionOrder();
  const receipt = await issue(
    authorization({
      action: "delete",
      expectedHead: headOf(1, genesis),
      proposedContent: order,
    }),
  );
  const real = await store().delete({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: order,
    mutationReceiptId: "mutation.forge.seed",
    tombstoneId: "tombstone-forge-seed",
  });
  assert.ok(real.tombstone, "the honest deletion must succeed first");
  const forged: Record<string, unknown> = {
    ...real.tombstone,
    tombstoneId: overrides.tombstoneId,
  };
  if (overrides.legalHoldState !== undefined) {
    forged.retention = {
      retainUntil: null,
      legalHoldState: overrides.legalHoldState,
    };
  }
  if (overrides.restorationEligibility !== undefined) {
    forged.restorationEligibility = overrides.restorationEligibility;
  }
  return { forged, digest: real.tombstone.tombstoneDigest };
}

async function insertTombstoneRow(
  forged: Record<string, unknown>,
  digest: string,
  columns: {
    legalHoldState?: string;
    restorationEligibilityKind?: string;
  },
): Promise<void> {
  await runAs(
    "aaliyah_memory_mutator",
    `INSERT INTO memory_tombstones
       (tenant_id, workspace_id, principal_id, user_id, tombstone_id,
        target_record_id, target_version, tombstone_version, authorization_id,
        mutation_receipt_id, reason, effective_at, retain_until,
        legal_hold_state, cache_index_propagation,
        restoration_eligibility_kind, tombstone_digest, payload)
     VALUES ($1,$2,$3,$4,$5,$6,1,2,$7,'mutation.forge.seed',
             'subject_erasure_request', now(), NULL, $8, 'unknown', $9,
             $10, $11)`,
    [
      SCOPE.tenantId,
      SCOPE.workspaceId,
      SCOPE.principalId,
      SCOPE.userId,
      forged.tombstoneId,
      RECORD_ID,
      (forged.deletionAuthority as { authorizationId: string }).authorizationId,
      columns.legalHoldState ?? "none",
      columns.restorationEligibilityKind ?? "ineligible_payload_destroyed",
      digest,
      JSON.stringify(forged),
    ],
  );
}

// ---------------------------------------------------------------------------
// 10. CONTROLS THAT THE TESTS ABOVE COVERED FOR. Each of these exists because
// removing the control it names left the suite GREEN, which means the control
// had no evidence behind it.
// ---------------------------------------------------------------------------

test("a deletion whose accounting cannot be read back independently is NOT a success", async () => {
  // The read-back pool resolves `memory_tombstones` to an empty relation, so
  // the write commits and the accounting is unreadable on an independent
  // session. Without this, a store that simply trusted its own write would
  // pass every other assertion in this file.
  const genesis = await seedGenesis({ note: SENSITIVE });
  const order = deletionOrder();
  const receipt = await issue(
    authorization({
      action: "delete",
      expectedHead: headOf(1, genesis),
      proposedContent: order,
    }),
  );
  const blind = createPostgresTrustedMemoryStore(writePool, shadowTombstonePool);
  const result = await blind.delete({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: order,
    mutationReceiptId: "mutation.blindreadback.1",
    tombstoneId: "tombstone-blind-001",
  });
  assert.equal(result.verified, false);
  assert.equal(result.rejection, "erasure_incomplete");
  assert.equal(result.tombstone, null);
  // The row IS on disk in `public`; the point is that the store did not claim
  // success on evidence it could not obtain independently.
  const stored = await adminPool.query(
    `SELECT count(*)::int AS n FROM memory_tombstones WHERE tombstone_id = $1`,
    ["tombstone-blind-001"],
  );
  assert.equal(stored.rows[0].n, 1);
});

test("the tombstone digest is the canonical digest of the tombstone, computed independently", async () => {
  // Recomputing with `memoryTombstoneDigest` alone proves only that the
  // function agrees with itself: a mutant that returns a constant passes such
  // a test. This recomputes from the CONTRACT's `canonicalDigest` directly.
  const genesis = await seedGenesis({ note: SENSITIVE, settlement: "eight" });
  const order = deletionOrder();
  const receipt = await issue(
    authorization({
      action: "delete",
      expectedHead: headOf(1, genesis),
      proposedContent: order,
    }),
  );
  const result = await store().delete({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: order,
    mutationReceiptId: "mutation.digest.1",
    tombstoneId: "tombstone-digest-001",
  });
  const tombstone = result.tombstone;
  assert.ok(tombstone);
  const { tombstoneDigest, ...withoutDigest } = tombstone;
  assert.equal(
    tombstoneDigest,
    canonicalDigest({
      schemaVersion: MEMORY_TOMBSTONE_DIGEST_SCHEMA_VERSION,
      value: withoutDigest,
    }),
  );
  // And the helper agrees with the contract, so the two are not two rules.
  assert.equal(tombstoneDigest, memoryTombstoneDigest(withoutDigest));
  // A digest that ignored its input would collide across two tombstones.
  assert.notEqual(tombstoneDigest, `sha256:${"0".repeat(64)}`);
});

test("a hold may not be filed under a scope that is not the placing actor's", async () => {
  const foreign = legalHold({
    coverage: { kind: "entire_scope" },
    scope: { ...SCOPE, tenantId: "tenant-somebody-else" },
  });
  const result = await holds().placeHold(SCOPE, foreign);
  assert.equal(result.recorded, false);
  assert.equal(result.rejection, "hold_scope_mismatch");
  const rows = await adminPool.query(
    `SELECT count(*)::int AS n FROM memory_legal_holds`,
  );
  assert.equal(rows.rows[0].n, 0);
  // Each dimension on its own, so one comparison cannot cover for another.
  for (const dimension of [
    "workspaceId",
    "principalId",
    "userId",
  ] as const) {
    const drifted = legalHold({
      coverage: { kind: "entire_scope" },
      scope: { ...SCOPE, [dimension]: `${SCOPE[dimension]}-other` },
    });
    assert.equal(
      (await holds().placeHold(SCOPE, drifted)).rejection,
      "hold_scope_mismatch",
      `a hold naming another ${dimension} must be refused`,
    );
  }
});

test("an already released hold cannot be released again", async () => {
  const hold = await placeHold(
    legalHold({ coverage: { kind: "records", recordIds: [RECORD_ID] } }),
  );
  const first = await holds().releaseHold({
    actor: SCOPE,
    holdId: hold.holdId,
    releasedAt: isoOffset(0),
    releasingAuthorityId: "authority.court",
    releaseOrderRef: "order:court/2026-0118",
  });
  assert.equal(first.recorded, true);
  const second = await holds().releaseHold({
    actor: SCOPE,
    holdId: hold.holdId,
    releasedAt: isoOffset(1_000),
    releasingAuthorityId: "authority.court",
    releaseOrderRef: "order:court/2026-0119",
  });
  assert.equal(second.recorded, false);
  assert.equal(second.rejection, "hold_not_active");
  // Releasing a hold that does not exist is a DIFFERENT answer.
  assert.equal(
    (
      await holds().releaseHold({
        actor: SCOPE,
        holdId: "hold-does-not-exist",
        releasedAt: isoOffset(0),
        releasingAuthorityId: "authority.court",
        releaseOrderRef: "order:court/2026-0120",
      })
    ).rejection,
    "hold_not_found",
  );
});

test("a deletion order may not carry free text in its evidence reference", async () => {
  // The evidence reference is the ONE string member of a deletion order, and
  // therefore the one place the destroyed sentence could ride along into the
  // head of a deleted record.
  const genesis = await seedGenesis({ note: SENSITIVE });
  const leaking = {
    schemaVersion: MEMORY_DELETION_ORDER_SCHEMA_VERSION,
    reason: "subject_erasure_request" as const,
    reasonEvidenceRef: SENSITIVE,
  };
  const receipt = await issue(
    authorization({
      action: "delete",
      expectedHead: headOf(1, genesis),
      proposedContent: leaking,
    }),
  );
  const result = await store().delete({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: leaking,
    mutationReceiptId: "mutation.orderleak.1",
  });
  assert.equal(result.rejection, "deletion_order_malformed");
  // And the database refuses the same content for a direct writer.
  await assert.rejects(
    () =>
      hostileAppend({
        action: "delete",
        state: "deleted",
        version: 2,
        predecessorDigest: genesis,
        content: leaking,
        label: "orderleak",
      }),
    /the content of a deleted version must be a deletion order/,
  );
  assert.equal((await rawVersions()).length, 1);
});

test("a tombstone that admits an ACTIVE hold is unrepresentable", async () => {
  // Built by hand, because `MemoryTombstoneSchema` refuses to construct one:
  // this is the database half of the same rule, for a writer that never loads
  // the contract.
  const { forged, digest } = await forgeTombstoneRow({
    tombstoneId: "tombstone-held-001",
    legalHoldState: { state: "held", holdId: "hold-000001" },
  });
  await assert.rejects(
    () => insertTombstoneRow(forged, digest, { legalHoldState: "held" }),
    /memory_tombstones_not_under_hold/,
  );
});

test("a tombstone cannot claim the destroyed payload is restorable from an escrow", async () => {
  const { forged, digest } = await forgeTombstoneRow({
    tombstoneId: "tombstone-escrow-001",
    restorationEligibility: {
      kind: "eligible_from_escrow",
      restorableUntil: isoOffset(86_400_000),
      escrowRef: "escrow:vault/0001",
      custodianAuthorityId: "authority.custodian",
    },
  });
  await assert.rejects(
    () =>
      insertTombstoneRow(forged, digest, {
        restorationEligibilityKind: "eligible_from_escrow",
      }),
    /memory_tombstones_restoration_domain/,
  );
});

test("the tombstone log refuses UPDATE and DELETE", async () => {
  await deleteThen("mutation.tsimmutable.seed", "tombstone-immutable-001");
  await assert.rejects(
    () =>
      adminPool.query(
        `UPDATE memory_tombstones SET reason = 'duplicate_record'
          WHERE tombstone_id = $1`,
        ["tombstone-immutable-001"],
      ),
    /UPDATE on memory_tombstones is forbidden/,
  );
  await assert.rejects(
    () => adminPool.query(`DELETE FROM memory_tombstones`),
    /DELETE on memory_tombstones is forbidden/,
  );
});

test("an erasure marker without the tombstone that ordered it is unrepresentable", async () => {
  // The CHECK, exercised on INSERT — the BEFORE UPDATE guard refuses the
  // update form first, so INSERT is the only path that reaches this
  // constraint.
  await seedGenesis({ note: SENSITIVE });
  const content = { note: "orphan erasure marker" };
  const digest = memoryContentDigest(content);
  await assert.rejects(
    () =>
      adminPool.query(
        `INSERT INTO memory_record_versions
           (tenant_id, workspace_id, principal_id, user_id, record_id, version,
            state, content_digest, predecessor_digest, authorization_id,
            mutation_receipt_id, payload, content_erased_at,
            erasure_tombstone_id)
         VALUES ($1,$2,$3,$4,$5,2,'active',$6,$7,'auth-orphan-0000000000000000',
                 'mutation.orphan',$8, now(), NULL)`,
        [
          SCOPE.tenantId,
          SCOPE.workspaceId,
          SCOPE.principalId,
          SCOPE.userId,
          RECORD_ID,
          digest,
          memoryContentDigest({ note: SENSITIVE }),
          JSON.stringify({
            schemaVersion: MEMORY_RECORD_VERSION_SCHEMA_VERSION,
            recordId: RECORD_ID,
            version: 2,
            state: "active",
            scope: SCOPE,
            content,
            contentDigest: digest,
            predecessorDigest: memoryContentDigest({ note: SENSITIVE }),
            authorizationId: "auth-orphan-0000000000000000",
            mutationReceiptId: "mutation.orphan",
            createdAt: isoOffset(0),
          }),
        ],
      ),
    /memory_record_versions_erasure_witness/,
  );
});

test("a retention obligation cannot be edited or deleted, by anyone, including the owner", async () => {
  // A retention clock that the party wanting to delete can wind back is not a
  // clock. There is no DELETE grant for any role and the trigger refuses it
  // for the owner as well.
  await seedGenesis({ note: SENSITIVE });
  assert.equal(
    (
      await holds().imposeRetention(SCOPE, {
        obligationId: "retention-immutable-001",
        recordId: RECORD_ID,
        policyRef: "policy:retention/seven-years",
        imposingAuthorityId: "authority.records-manager",
        imposedAt: isoOffset(-60_000),
        retainUntil: isoOffset(3_600_000),
      })
    ).recorded,
    true,
  );
  await assert.rejects(
    () =>
      adminPool.query(
        `UPDATE memory_retention_obligations
            SET retain_until = now() - interval '1 day'
          WHERE obligation_id = $1`,
        ["retention-immutable-001"],
      ),
    /UPDATE on memory_retention_obligations is forbidden/,
  );
  await assert.rejects(
    () =>
      adminPool.query(
        `DELETE FROM memory_retention_obligations WHERE obligation_id = $1`,
        ["retention-immutable-001"],
      ),
    /DELETE on memory_retention_obligations is forbidden/,
  );
});

test("a hold's coverage rows and carve-outs are append-only", async () => {
  const hold = await placeHold(
    legalHold({
      coverage: { kind: "subjects", canonicalParticipantIds: [PARTICIPANT] },
      carveOutActions: ["promote"],
    }),
  );
  // Narrowing a hold by editing which subject it covers.
  await assert.rejects(
    () =>
      adminPool.query(
        `UPDATE memory_legal_hold_subjects
            SET canonical_participant_id = 'participant-nobody'
          WHERE hold_id = $1`,
        [hold.holdId],
      ),
    /UPDATE on memory_legal_hold_subjects is forbidden/,
  );
  await assert.rejects(
    () =>
      adminPool.query(
        `DELETE FROM memory_legal_hold_subjects WHERE hold_id = $1`,
        [hold.holdId],
      ),
    /DELETE on memory_legal_hold_subjects is forbidden/,
  );
  // WIDENING a carve-out to cover an action the court never granted.
  await assert.rejects(
    () =>
      adminPool.query(
        `UPDATE memory_legal_hold_carve_outs SET action = 'restore'
          WHERE hold_id = $1`,
        [hold.holdId],
      ),
    /UPDATE on memory_legal_hold_carve_outs is forbidden/,
  );
  await assert.rejects(
    () =>
      adminPool.query(
        `DELETE FROM memory_legal_hold_carve_outs WHERE hold_id = $1`,
        [hold.holdId],
      ),
    /DELETE on memory_legal_hold_carve_outs is forbidden/,
  );
});

test("a SUBJECTS hold blocks record-level mutation in its scope, because the record cannot be matched to a subject", async () => {
  // DELIBERATE OVER-BLOCKING, AND THE ONLY HONEST OPTION HERE. A hold whose
  // coverage is `subjects` names canonical participant ids. A
  // `memory_record_versions` row carries no participant edge — there is no
  // record -> participant relation in this schema — so the record-level guard
  // CANNOT evaluate subject coverage precisely. It treats an active subjects
  // hold as covering the whole (tenant, workspace) scope instead. That refuses
  // writes the hold may not have meant to reach; the alternative is a
  // subject-scoped hold that is silently unenforced against the record chain,
  // which is the defect this whole file exists to close.
  //
  // The alias path, which DOES carry `canonical_participant_id`, is matched
  // precisely — proven by the subjects test further up.
  const genesis = await seedGenesis({ note: SENSITIVE });
  await placeHold(
    legalHold({
      coverage: {
        kind: "subjects",
        canonicalParticipantIds: ["participant-somebody-else"],
      },
    }),
  );
  const next = { note: "rewritten" };
  const receipt = await issue(
    authorization({
      action: "correct",
      expectedHead: headOf(1, genesis),
      proposedContent: next,
    }),
  );
  const result = await store().correct({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: next,
    mutationReceiptId: "mutation.subjects.overblock",
  });
  assert.equal(result.rejection, "legal_hold_active");
  assert.equal((await rawVersions()).length, 1);
});

// ---------------------------------------------------------------------------
// W1.3 Part B3 — THE WITNESS-BEARING TABLES 037 ADDED.
//
// `memory_tombstones` carries `authorization_id` and `mutation_receipt_id`
// and, until migration 038, NOTHING checked either of them: a tombstone's
// attribution was decoration, and one receipt id could account for any number
// of destructions. And Part F's action-to-state binding, which was reviewed by
// READING, gets the branch it was missing a killing test for.
// ---------------------------------------------------------------------------

/** A structurally perfect tombstone row, written directly as the mutator. */
async function insertTombstoneAs(input: {
  tombstoneId: string;
  authorizationId: string;
  mutationReceiptId: string;
  payload: Record<string, unknown>;
  digest: string;
  targetVersion?: number;
  tombstoneVersion?: number;
}): Promise<void> {
  await runAs(
    "aaliyah_memory_mutator",
    `INSERT INTO memory_tombstones
       (tenant_id, workspace_id, principal_id, user_id, tombstone_id,
        target_record_id, target_version, tombstone_version, authorization_id,
        mutation_receipt_id, reason, effective_at, retain_until,
        legal_hold_state, cache_index_propagation,
        restoration_eligibility_kind, tombstone_digest, payload)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,
             'subject_erasure_request', now(), NULL, 'none', 'unknown',
             'ineligible_payload_destroyed', $11, $12)`,
    [
      SCOPE.tenantId,
      SCOPE.workspaceId,
      SCOPE.principalId,
      SCOPE.userId,
      input.tombstoneId,
      RECORD_ID,
      input.targetVersion ?? 1,
      input.tombstoneVersion ?? 2,
      input.authorizationId,
      input.mutationReceiptId,
      input.digest,
      JSON.stringify(input.payload),
    ],
  );
}

/** Delete for real through the store, and hand back the tombstone it wrote. */
async function honestDeletion(input: {
  mutationReceiptId: string;
  tombstoneId: string;
}) {
  const genesis = await seedGenesis({ note: SENSITIVE });
  const order = deletionOrder();
  const receipt = await issue(
    authorization({
      action: "delete",
      expectedHead: headOf(1, genesis),
      proposedContent: order,
    }),
  );
  const result = await store().delete({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: order,
    mutationReceiptId: input.mutationReceiptId,
    tombstoneId: input.tombstoneId,
  });
  assert.equal(result.verified, true, "the honest deletion must succeed first");
  const tombstone = result.tombstone;
  assert.ok(tombstone);
  return { tombstone, receipt };
}

test("B3 a tombstone with no consumed delete authorization behind it is refused", async () => {
  // Migration 037 checked the tombstone's SHAPE, its target's state, the holds
  // and the retention clock. It never checked that the destruction it accounts
  // for was APPROVED, so the mutator could file an account of a deletion
  // naming an authorization that was never spent — or never existed.
  const { tombstone } = await honestDeletion({
    mutationReceiptId: "mutation.b3.tombstone.seed",
    tombstoneId: "tombstone-b3-seed",
  });
  const unwitnessed = {
    ...tombstone,
    tombstoneId: "tombstone-b3-unwitnessed",
  } as Record<string, unknown>;
  await assert.rejects(
    () =>
      insertTombstoneAs({
        tombstoneId: "tombstone-b3-unwitnessed",
        authorizationId: "never-spent-0000000000000001",
        mutationReceiptId: "mutation.b3.never",
        payload: unwitnessed,
        digest: tombstone.tombstoneDigest,
      }),
    /no consumed delete authorization witnesses this tombstone/,
  );
  const stored = await adminPool.query(
    `SELECT count(*)::int AS n FROM memory_tombstones`,
  );
  assert.equal(stored.rows[0].n, 1);
});

test("B3 a tombstone witnessed by a CORRECT authorization is refused; destruction needs a delete", async () => {
  // The sharper case: the approval is real, it was spent, and it names this
  // record — but it approved a correction. A destruction accounted for by an
  // approval to edit is not accounted for.
  const { tombstone } = await honestDeletion({
    mutationReceiptId: "mutation.b3.wrongaction.seed",
    tombstoneId: "tombstone-b3-wrongaction-seed",
  });
  await witnessAppend({
    authorizationId: "correct-b3-00000000000000001",
    mutationReceiptId: "mutation.b3.correct",
    recordId: RECORD_ID,
    action: "correct",
  });
  const mislabelled = {
    ...tombstone,
    tombstoneId: "tombstone-b3-wrongaction",
  } as Record<string, unknown>;
  await assert.rejects(
    () =>
      insertTombstoneAs({
        tombstoneId: "tombstone-b3-wrongaction",
        authorizationId: "correct-b3-00000000000000001",
        mutationReceiptId: "mutation.b3.correct",
        payload: mislabelled,
        digest: tombstone.tombstoneDigest,
      }),
    /no consumed delete authorization witnesses this tombstone/,
  );
});

/** Several statements, ONE transaction, under one least-privilege role. */
async function runAsTransaction(
  role: string,
  steps: ReadonlyArray<{ sql: string; params?: unknown[] }>,
): Promise<void> {
  const client = await adminPool.connect();
  try {
    await client.query("BEGIN");
    await client.query(`SET LOCAL ROLE "${role}"`);
    for (const step of steps) {
      await client.query(step.sql, step.params ?? []);
    }
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

test("B3 one consumed authorization accounts for exactly ONE tombstone", async () => {
  // THE H-1 SHAPE ON THE TABLE 037 ADDED, and the construction is the honest
  // one rather than the convenient one. `memory_tombstones_version_unique`
  // already bounds tombstones per (record, version), so the only way to charge
  // TWO destructions to ONE mutation receipt id is a record that is deleted,
  // restored and deleted again: the second destruction is appended under its
  // own fresh approval — it has to be, `memory_record_versions_receipt_unique`
  // sees to that — and then its TOMBSTONE is filed under the FIRST
  // deletion's receipt id. The witness passes, because the first deletion's
  // nonce really does name this record and really was spent on a delete. What
  // is wrong is the accounting: one receipt id, two destructions, and anyone
  // reconciling receipts against tombstones is told a number that is false.
  const { tombstone: first, receipt: firstAuth } = await honestDeletion({
    mutationReceiptId: "mutation.b3.onetomb",
    tombstoneId: "tombstone-b3-onetomb",
  });
  assert.equal(first.tombstoneVersion, 2);

  // Restore, so the record has a live head to destroy a second time.
  const restoreContent = { note: "reinstated" };
  const restoreAuth = await issue(
    authorization({
      action: "restore",
      expectedHead: headOf(2, memoryContentDigest(deletionOrder())),
      proposedContent: restoreContent,
    }),
  );
  const restored = await store().restore({
    actor: SCOPE,
    authorizationId: restoreAuth.authorizationId,
    recordId: RECORD_ID,
    proposedContent: restoreContent,
    mutationReceiptId: "mutation.b3.onetomb.restore",
  });
  assert.equal(restored.verified, true);

  // The second destruction, written directly so the filer chooses the receipt
  // id the tombstone is charged to. Its VERSION append carries its own fresh
  // approval; only the tombstone reaches back to the first one.
  await witnessAppend({
    authorizationId: "seconddelete-0000000000000001",
    mutationReceiptId: "mutation.b3.seconddelete",
    recordId: RECORD_ID,
    action: "delete",
  });
  const order = deletionOrder();
  const orderDigest = memoryContentDigest(order);
  const secondDeleted = {
    schemaVersion: MEMORY_RECORD_VERSION_SCHEMA_VERSION,
    recordId: RECORD_ID,
    version: 4,
    state: "deleted",
    scope: SCOPE,
    content: order,
    contentDigest: orderDigest,
    predecessorDigest: memoryContentDigest(restoreContent),
    authorizationId: "seconddelete-0000000000000001",
    mutationReceiptId: "mutation.b3.seconddelete",
    createdAt: isoOffset(0),
  };
  const secondTombstone = (authorizationId: string) => ({
    ...first,
    tombstoneId: "tombstone-b3-onetomb-again",
    targetVersion: 3,
    tombstoneVersion: 4,
    deletionAuthority: { ...first.deletionAuthority, authorizationId },
  });
  const steps = (authorizationId: string, receiptId: string) => [
    {
      sql: `INSERT INTO memory_record_versions
              (tenant_id, workspace_id, principal_id, user_id, record_id,
               version, state, content_digest, predecessor_digest,
               authorization_id, mutation_receipt_id, payload)
            VALUES ($1,$2,$3,$4,$5,4,'deleted',$6,$7,$8,$9,$10)`,
      params: [
        SCOPE.tenantId,
        SCOPE.workspaceId,
        SCOPE.principalId,
        SCOPE.userId,
        RECORD_ID,
        orderDigest,
        memoryContentDigest(restoreContent),
        "seconddelete-0000000000000001",
        "mutation.b3.seconddelete",
        JSON.stringify(secondDeleted),
      ],
    },
    {
      sql: `INSERT INTO memory_tombstones
              (tenant_id, workspace_id, principal_id, user_id, tombstone_id,
               target_record_id, target_version, tombstone_version,
               authorization_id, mutation_receipt_id, reason, effective_at,
               retain_until, legal_hold_state, cache_index_propagation,
               restoration_eligibility_kind, tombstone_digest, payload)
            VALUES ($1,$2,$3,$4,'tombstone-b3-onetomb-again',$5,3,4,$6,$7,
                    'subject_erasure_request', now(), NULL, 'none', 'unknown',
                    'ineligible_payload_destroyed',$8,$9)`,
      params: [
        SCOPE.tenantId,
        SCOPE.workspaceId,
        SCOPE.principalId,
        SCOPE.userId,
        RECORD_ID,
        authorizationId,
        receiptId,
        first.tombstoneDigest,
        JSON.stringify(secondTombstone(authorizationId)),
      ],
    },
    {
      sql: `UPDATE memory_record_versions
               SET payload = jsonb_set(payload, '{content}', 'null'::jsonb),
                   content_erased_at = now(),
                   erasure_tombstone_id = 'tombstone-b3-onetomb-again'
             WHERE tenant_id = $1 AND workspace_id = $2 AND record_id = $3
               AND version <= 3 AND content_erased_at IS NULL`,
      params: [SCOPE.tenantId, SCOPE.workspaceId, RECORD_ID],
    },
  ];

  await assert.rejects(
    () =>
      runAsTransaction(
        "aaliyah_memory_mutator",
        steps(firstAuth.authorizationId, "mutation.b3.onetomb"),
      ),
    /duplicate key value violates unique constraint "memory_tombstones_receipt_unique"/,
  );
  assert.equal((await rawVersions()).length, 3);

  // POSITIVE CONTROL: the SAME transaction, with the tombstone charged to the
  // approval that actually authorized THIS destruction, is accepted. The index
  // refuses the reuse and nothing else.
  await runAsTransaction(
    "aaliyah_memory_mutator",
    steps("seconddelete-0000000000000001", "mutation.b3.seconddelete"),
  );
  const stored = await adminPool.query(
    `SELECT tombstone_id, mutation_receipt_id FROM memory_tombstones
      ORDER BY tombstone_version`,
  );
  assert.deepEqual(stored.rows, [
    {
      tombstone_id: "tombstone-b3-onetomb",
      mutation_receipt_id: "mutation.b3.onetomb",
    },
    {
      tombstone_id: "tombstone-b3-onetomb-again",
      mutation_receipt_id: "mutation.b3.seconddelete",
    },
  ]);
});

test("B3 Part F's action-state guard refuses a RESTORE onto a head that was never deleted", async () => {
  // THE BRANCH THAT HAD NO KILLING TEST. Part F's
  // `aaliyah_memory_action_state_guard` pins four bindings and three of them
  // were already exercised against a direct writer. "restore may only follow a
  // deleted head" was only ever proven through the STORE, where it is a
  // TypeScript comparison — so the DATABASE half of it was a control nobody
  // had tried to kill.
  const genesis = await seedGenesis({ note: "never deleted" });
  await assert.rejects(
    () =>
      hostileAppend({
        action: "restore",
        state: "active",
        version: 2,
        predecessorDigest: genesis,
        content: { note: "restoring what was never deleted" },
        label: "restorelive",
      }),
    /restore may only follow a deleted head/,
  );
  assert.equal((await rawVersions()).length, 1);
});

test("B3 Part F's action-state guard still ALLOWS the four bindings it exists to permit", async () => {
  // A guard that refused everything would pass every negative above. This is
  // the positive control for all four branches, one statement each, all
  // written by a direct writer that never calls the store.
  const genesis = await seedGenesis({ note: "original" });
  // 1. non-delete -> active.
  await hostileAppend({
    action: "correct",
    state: "active",
    version: 2,
    predecessorDigest: genesis,
    content: { note: "corrected" },
    label: "allowcorrect",
  });
  const corrected = memoryContentDigest({ note: "corrected" });
  // 2. delete -> deleted, over an erased predecessor set. The deferred
  //    `deletion_erases` trigger means this has to carry its own erasure, so
  //    it is done through the store, which is the only writer that does the
  //    whole transaction.
  const order = deletionOrder();
  const deleteAuth = await issue(
    authorization({
      action: "delete",
      expectedHead: headOf(2, corrected),
      proposedContent: order,
    }),
  );
  const deleted = await store().delete({
    actor: SCOPE,
    authorizationId: deleteAuth.authorizationId,
    recordId: RECORD_ID,
    proposedContent: order,
    mutationReceiptId: "mutation.b3.allow.delete",
    tombstoneId: "tombstone-b3-allow",
  });
  assert.equal(deleted.verified, true);
  // 3. restore -> active, after a deleted head.
  await hostileAppend({
    action: "restore",
    state: "active",
    version: 4,
    predecessorDigest: memoryContentDigest(order),
    content: { note: "reinstated" },
    label: "allowrestore",
  });
  const rows = await rawVersions();
  assert.deepEqual(
    rows.map((row) => row.state),
    ["active", "active", "deleted", "active"],
  );
});
