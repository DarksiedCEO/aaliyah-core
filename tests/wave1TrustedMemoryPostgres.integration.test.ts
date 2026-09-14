import assert from "node:assert/strict";
import test, { after, before, beforeEach } from "node:test";
import { Pool } from "pg";

import {
  MEMORY_AUTHORIZATION_NONCE_SCHEMA_VERSION,
  MemoryAuthorizationReceiptSchema,
  WAVE1_TRUSTED_MEMORY_CONTRACT_VERSION,
  memoryAuthorizationNonce,
  type MemoryAuthorizationReceipt,
  type MemoryExpectedHead,
  type MemoryScope,
} from "@aaliyah/contracts/v1";

import {
  MEMORY_RECORD_VERSION_SCHEMA_VERSION,
  memoryContentDigest,
  type TrustedMemoryActor,
} from "../src/application/memory/wave1TrustedMemory";
import { runMailMigrations } from "../src/persistence/postgres/migrations";
import { createMailDbPool } from "../src/persistence/postgres/pool";
import { createPostgresTrustedMemoryStore } from "../src/persistence/postgres/wave1TrustedMemoryStore";
import {
  lockSharedMemoryTables,
  type SharedTableLock,
} from "./support/sharedMemoryTables";

/**
 * Wave 1.3 trusted memory, against a REAL PostgreSQL 16.
 *
 * No mocks, no fakes, no in-memory stand-in. Concurrency is proven with real
 * promises racing real connections against real rows, because a simulated race
 * proves that the simulation is deterministic and nothing else.
 *
 * Every negative assertion carries a matcher: a bare `assert.rejects` passes
 * when the code throws for a completely unrelated reason, which is how a
 * control appears tested while never having been exercised once.
 */

const DB_URL =
  process.env.AALIYAH_TEST_DATABASE_URL ??
  "postgres://postgres:test@127.0.0.1:54329/aaliyah_test";

/** Schema the read-back pool is pointed at when a test needs to force divergence. */
const SHADOW_SCHEMA = "memory_readback_shadow";

/** Same shape, no CHECK constraints. See the note in `before`. */
const UNCHECKED_SCHEMA = "memory_readback_unchecked";

const EVIDENCE_DIGEST = `sha256:${"b".repeat(64)}`;

const SCOPE: MemoryScope = {
  tenantId: "tenant-memory",
  workspaceId: "workspace-memory",
  principalId: "principal-memory",
  userId: "user-memory",
};

const RECORD_ID = "record-memory-001";

let writePool: Pool;
let readPool: Pool;
let shadowReadPool: Pool;
let uncheckedReadPool: Pool;
let adminPool: Pool;
// See tests/support/sharedMemoryTables.ts: this file TRUNCATEs tables another
// suite also TRUNCATEs, and `node --test` runs files in parallel.
let sharedTableLock: SharedTableLock;

function store(options?: { readBack?: Pool }) {
  return createPostgresTrustedMemoryStore(
    writePool,
    options?.readBack ?? readPool,
  );
}

before(async () => {
  adminPool = createMailDbPool({
    AALIYAH_DATABASE_URL: DB_URL,
  } as NodeJS.ProcessEnv);
  sharedTableLock = await lockSharedMemoryTables(adminPool);
  await runMailMigrations(adminPool);
  writePool = createMailDbPool({
    AALIYAH_DATABASE_URL: DB_URL,
  } as NodeJS.ProcessEnv);
  readPool = createMailDbPool({
    AALIYAH_DATABASE_URL: DB_URL,
  } as NodeJS.ProcessEnv);

  // A real second relation the read-back resolves to first, used only by the
  // divergence tests. Forcing divergence this way keeps the production read
  // path completely untouched — no injected failure hook, no stubbed client.
  await adminPool.query(`DROP SCHEMA IF EXISTS ${SHADOW_SCHEMA} CASCADE`);
  await adminPool.query(`CREATE SCHEMA ${SHADOW_SCHEMA}`);
  await adminPool.query(
    `CREATE TABLE ${SHADOW_SCHEMA}.memory_record_versions
       (LIKE public.memory_record_versions INCLUDING ALL)`,
  );
  await adminPool.query(
    `GRANT USAGE ON SCHEMA ${SHADOW_SCHEMA}
       TO aaliyah_memory_reader, aaliyah_memory_mutator`,
  );
  await adminPool.query(
    `GRANT SELECT ON ${SHADOW_SCHEMA}.memory_record_versions
       TO aaliyah_memory_reader, aaliyah_memory_mutator`,
  );
  shadowReadPool = new Pool({
    connectionString: DB_URL,
    max: 4,
    options: `-c search_path=${SHADOW_SCHEMA},public`,
  });

  // A relation shaped like the real one but WITHOUT its CHECK constraints.
  // In `public`, migration 023 makes a row whose columns disagree with its
  // jsonb payload physically unrepresentable — which would leave the
  // application-level binding check with no reachable input and therefore no
  // killing test. A replica, a restored backup, or a table created by
  // something other than these migrations has no such guarantee, so the check
  // is exercised against a relation that has no guarantee either.
  await adminPool.query(`DROP SCHEMA IF EXISTS ${UNCHECKED_SCHEMA} CASCADE`);
  await adminPool.query(`CREATE SCHEMA ${UNCHECKED_SCHEMA}`);
  await adminPool.query(
    // DEFAULTS (so the surrogate key still works) but explicitly NOT
    // CONSTRAINTS: the CHECKs are the thing being removed.
    `CREATE TABLE ${UNCHECKED_SCHEMA}.memory_record_versions
       (LIKE public.memory_record_versions INCLUDING DEFAULTS)`,
  );
  await adminPool.query(
    `GRANT USAGE ON SCHEMA ${UNCHECKED_SCHEMA} TO aaliyah_memory_reader`,
  );
  await adminPool.query(
    `GRANT SELECT ON ${UNCHECKED_SCHEMA}.memory_record_versions
       TO aaliyah_memory_reader`,
  );
  uncheckedReadPool = new Pool({
    connectionString: DB_URL,
    max: 2,
    options: `-c search_path=${UNCHECKED_SCHEMA},public`,
  });
});

after(async () => {
  await uncheckedReadPool.end();
  await shadowReadPool.end();
  await readPool.end();
  await writePool.end();
  await adminPool.query(`DROP SCHEMA IF EXISTS ${SHADOW_SCHEMA} CASCADE`);
  await adminPool.query(`DROP SCHEMA IF EXISTS ${UNCHECKED_SCHEMA} CASCADE`);
  await sharedTableLock.release();
  await adminPool.end();
});

beforeEach(async () => {
  await adminPool.query(
    `TRUNCATE memory_record_versions,
              memory_authorization_receipts,
              memory_authorization_nonces,
              memory_mutation_receipts
     RESTART IDENTITY`,
  );
  await adminPool.query(
    `TRUNCATE ${SHADOW_SCHEMA}.memory_record_versions RESTART IDENTITY`,
  );
  await adminPool.query(
    `TRUNCATE ${UNCHECKED_SCHEMA}.memory_record_versions RESTART IDENTITY`,
  );
  genesisCounter = 0;
});

let authorizationCounter = 0;
function nextAuthorizationId(): string {
  authorizationCounter += 1;
  // MemoryAuthorizationIdSchema demands >= 26 characters.
  return `auth-${String(authorizationCounter).padStart(24, "0")}`;
}

function isoOffset(ms: number): string {
  return new Date(Date.now() + ms).toISOString();
}

/** Build a structurally valid, correctly nonce-bound authorization receipt. */
function authorization(input: {
  action: "correct" | "delete";
  scope?: MemoryScope;
  targetRecordId?: string;
  expectedHead: MemoryExpectedHead;
  proposedContent: unknown;
  authorizationId?: string;
  issuedAt?: string;
  expiresAt?: string;
  revokedAt?: string | null;
  consumedAt?: string | null;
}): MemoryAuthorizationReceipt {
  const scope = input.scope ?? SCOPE;
  const targetRecordId = input.targetRecordId ?? RECORD_ID;
  const authorizationId = input.authorizationId ?? nextAuthorizationId();
  const proposedContentDigest = memoryContentDigest(input.proposedContent);
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
    issuedAt: input.issuedAt ?? isoOffset(-60_000),
    expiresAt: input.expiresAt ?? isoOffset(3_600_000),
    revokedAt: input.revokedAt ?? null,
    consumedAt: input.consumedAt ?? null,
    policyVersion: "memory-policy/v1",
    evidenceDigest: EVIDENCE_DIGEST,
  });
}

/**
 * Issue an authorization: the receipt row AND the out-of-band nonce row.
 * Written under the ISSUER role, which is exactly the split migration 029
 * establishes — the mutator cannot do this and a test that used the owner
 * would never notice if it could.
 */
async function issue(
  receipt: MemoryAuthorizationReceipt,
  overrides: {
    nonceAction?: string;
    nonceTargetRecordId?: string;
    nonceAuthorizationId?: string;
    nonceExpiresAt?: string;
    nonceRevokedAt?: string | null;
    receiptExpiresAt?: string;
    receiptRevokedAt?: string | null;
    receiptConsumedAt?: string | null;
    skipNonceRow?: boolean;
  } = {},
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
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
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
        overrides.receiptExpiresAt ?? receipt.expiresAt,
        // `??` would swallow an EXPLICIT null here and fall through to the
        // receipt's own value, which is how a "revoked in the payload only"
        // fixture quietly revokes the column too and makes the payload check
        // unkillable. Presence, not nullishness.
        "receiptRevokedAt" in overrides
          ? overrides.receiptRevokedAt
          : receipt.revokedAt,
        "receiptConsumedAt" in overrides
          ? overrides.receiptConsumedAt
          : receipt.consumedAt,
        JSON.stringify(receipt),
      ],
    );
    if (!overrides.skipNonceRow) {
      await client.query(
        `INSERT INTO memory_authorization_nonces
           (tenant_id, workspace_id, binding_digest, authorization_id, action,
            target_record_id, issued_at, expires_at, revoked_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        [
          receipt.scope.tenantId,
          receipt.scope.workspaceId,
          receipt.nonce.bindingDigest,
          overrides.nonceAuthorizationId ?? receipt.authorizationId,
          overrides.nonceAction ?? receipt.action,
          overrides.nonceTargetRecordId ?? receipt.targetRecordId,
          receipt.issuedAt,
          overrides.nonceExpiresAt ?? receipt.expiresAt,
          "nonceRevokedAt" in overrides
            ? overrides.nonceRevokedAt
            : receipt.revokedAt,
        ],
      );
    }
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
  return receipt;
}

/** Run one statement under a named least-privilege role, in its own transaction. */
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
 * Mint an authorization nonce and SPEND it, so a row appended outside the
 * store still carries the witness migration 034 requires of every writer.
 *
 * Written with the ISSUER role and spent with the MUTATOR role, because a
 * fixture that used the owner for both would not notice if the privilege split
 * it depends on stopped existing. A test that wants to prove the guard REFUSES
 * an unwitnessed append simply does not call this.
 */
async function witnessAppend(input: {
  authorizationId: string;
  mutationReceiptId: string;
  recordId?: string;
  scope?: MemoryScope;
  action?: string;
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
      input.action ?? "correct",
      input.recordId ?? RECORD_ID,
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

/**
 * Drop a named trigger for the duration of one block and put it back, ALWAYS.
 *
 * Three sites used to disable the append-only trigger with a bare pair of
 * statements: a failure between them left the trigger OFF for every test that
 * ran afterwards in the same database, so the append-only control would have
 * been silently unenforced and the suite still green.
 */
async function withTriggerDisabled<T>(
  table: string,
  trigger: string,
  run: () => Promise<T>,
): Promise<T> {
  await adminPool.query(`ALTER TABLE ${table} DISABLE TRIGGER ${trigger}`);
  try {
    return await run();
  } finally {
    await adminPool.query(`ALTER TABLE ${table} ENABLE TRIGGER ${trigger}`);
  }
}

let genesisCounter = 0;

/** Seed version 1 of a record. `create` is a later assignment. */
async function seedGenesis(
  content: unknown,
  options: { scope?: MemoryScope; recordId?: string; schema?: string } = {},
): Promise<string> {
  const scope = options.scope ?? SCOPE;
  const recordId = options.recordId ?? RECORD_ID;
  const digest = memoryContentDigest(content);
  genesisCounter += 1;
  // Distinct per call: a nonce is globally unique on its authorization id, and
  // every genesis now spends one.
  const authorizationId = `genesis-${String(genesisCounter).padStart(21, "0")}`;
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
    `INSERT INTO ${options.schema ?? "public"}.memory_record_versions
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
      payload.authorizationId,
      payload.mutationReceiptId,
      JSON.stringify(payload),
    ],
  );
  return digest;
}

function headOf(version: number, contentDigest: string): MemoryExpectedHead {
  return { kind: "version", version, contentDigest };
}

async function countVersions(recordId = RECORD_ID): Promise<number> {
  const result = await adminPool.query(
    `SELECT count(*)::int AS n FROM memory_record_versions WHERE record_id = $1`,
    [recordId],
  );
  return result.rows[0].n as number;
}

async function nonceConsumedAt(bindingDigest: string): Promise<Date | null> {
  const result = await adminPool.query(
    `SELECT consumed_at FROM memory_authorization_nonces WHERE binding_digest = $1`,
    [bindingDigest],
  );
  return (result.rows[0]?.consumed_at as Date | null) ?? null;
}

async function receiptStatuses(
  mutationReceiptId: string,
): Promise<Array<{ phase: string; status: string }>> {
  const result = await adminPool.query(
    `SELECT phase, outcome_status FROM memory_mutation_receipts
      WHERE mutation_receipt_id = $1 ORDER BY id ASC`,
    [mutationReceiptId],
  );
  return result.rows.map((row: { phase: string; outcome_status: string }) => ({
    phase: row.phase,
    status: row.outcome_status,
  }));
}

// ---------------------------------------------------------------------------
// Happy path, and what "verified" is allowed to mean.
// ---------------------------------------------------------------------------

test("a correction commits, reads back on an independent session, and only then reports verified", async () => {
  const genesis = await seedGenesis({ note: "original", revision: 1 });
  const next = { note: "corrected", revision: 2 };
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
    mutationReceiptId: "mutation.correct.001",
  });

  assert.equal(result.rejection, null);
  assert.equal(result.verified, true);
  assert.equal(result.receipt?.outcome.status, "COMMITTED_AND_READ_BACK");
  assert.ok(result.receipt && result.receipt.outcome.status === "COMMITTED_AND_READ_BACK");
  assert.equal(result.receipt.outcome.resultingHead.version, 2);
  assert.equal(result.receipt.outcome.readBackSource, "independent_session");
  assert.equal(
    result.receipt.outcome.readBackDigest,
    memoryContentDigest(next),
  );

  const head = await store().readHead(SCOPE, RECORD_ID);
  assert.equal(head?.version, 2);
  assert.equal(head?.state, "active");
  assert.equal(head?.predecessorDigest, genesis);
  assert.equal(head?.contentDigest, memoryContentDigest(next));

  // The durable receipt log is append-only and passes through UNKNOWN first.
  assert.deepEqual(await receiptStatuses("mutation.correct.001"), [
    { phase: "pending", status: "UNKNOWN_PENDING_RECONCILIATION" },
    { phase: "terminal", status: "COMMITTED_AND_READ_BACK" },
  ]);
  assert.notEqual(await nonceConsumedAt(receipt.nonce.bindingDigest), null);
});

test("a delete advances the head to a deleted state without destroying the prior version", async () => {
  const genesis = await seedGenesis({ note: "original" });
  const tombstoneResidue = { note: "redacted" };
  const receipt = await issue(
    authorization({
      action: "delete",
      expectedHead: headOf(1, genesis),
      proposedContent: tombstoneResidue,
    }),
  );

  const result = await store().delete({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: tombstoneResidue,
    mutationReceiptId: "mutation.delete.001",
  });

  assert.equal(result.verified, true);
  const head = await store().readHead(SCOPE, RECORD_ID);
  assert.equal(head?.state, "deleted");
  assert.equal(head?.version, 2);
  // Stated honestly: this is a state transition, not erasure. Version 1 is
  // still on disk and no tombstone exists yet.
  assert.equal(await countVersions(), 2);
});

// ---------------------------------------------------------------------------
// Real concurrency.
// ---------------------------------------------------------------------------

test("two concurrent corrections against the same head: exactly one commits, the other is refused", async () => {
  const genesis = await seedGenesis({ note: "original" });
  const contentA = { note: "writer-a" };
  const contentB = { note: "writer-b" };
  const authA = await issue(
    authorization({
      action: "correct",
      expectedHead: headOf(1, genesis),
      proposedContent: contentA,
    }),
  );
  const authB = await issue(
    authorization({
      action: "correct",
      expectedHead: headOf(1, genesis),
      proposedContent: contentB,
    }),
  );

  const storeA = store();
  const storeB = createPostgresTrustedMemoryStore(adminPool, readPool);

  const [resultA, resultB] = await Promise.all([
    storeA.correct({
      actor: SCOPE,
      authorizationId: authA.authorizationId,
      recordId: RECORD_ID,
      proposedContent: contentA,
      mutationReceiptId: "mutation.race.a",
    }),
    storeB.correct({
      actor: SCOPE,
      authorizationId: authB.authorizationId,
      recordId: RECORD_ID,
      proposedContent: contentB,
      mutationReceiptId: "mutation.race.b",
    }),
  ]);

  const winners = [resultA, resultB].filter((r) => r.verified);
  const losers = [resultA, resultB].filter((r) => !r.verified);
  assert.equal(winners.length, 1, "exactly one writer may win");
  assert.equal(losers.length, 1);
  const loser = losers[0];
  assert.ok(loser, "one writer must be refused");
  assert.equal(loser.rejection, "head_mismatch");
  assert.equal(loser.receipt?.outcome.status, "ABORTED_NO_MUTATION");

  // The loser spent nothing: its nonce is still unconsumed after its rollback.
  const loserAuth = loser === resultA ? authA : authB;
  assert.equal(await nonceConsumedAt(loserAuth.nonce.bindingDigest), null);
  assert.equal(await countVersions(), 2);
  const head = await store().readHead(SCOPE, RECORD_ID);
  assert.equal(head?.version, 2);
});

test("two concurrent attempts on the SAME authorization consume it exactly once", async () => {
  const genesis = await seedGenesis({ note: "original" });
  const next = { note: "corrected" };
  const receipt = await issue(
    authorization({
      action: "correct",
      expectedHead: headOf(1, genesis),
      proposedContent: next,
    }),
  );

  const storeA = store();
  const storeB = createPostgresTrustedMemoryStore(adminPool, readPool);
  const [resultA, resultB] = await Promise.all([
    storeA.correct({
      actor: SCOPE,
      authorizationId: receipt.authorizationId,
      recordId: RECORD_ID,
      proposedContent: next,
      mutationReceiptId: "mutation.double.a",
    }),
    storeB.correct({
      actor: SCOPE,
      authorizationId: receipt.authorizationId,
      recordId: RECORD_ID,
      proposedContent: next,
      mutationReceiptId: "mutation.double.b",
    }),
  ]);

  assert.equal([resultA, resultB].filter((r) => r.verified).length, 1);
  const loser = [resultA, resultB].find((r) => !r.verified);
  assert.equal(loser?.rejection, "authorization_already_consumed");
  assert.equal(await countVersions(), 2);
});

// ---------------------------------------------------------------------------
// Replay and nonce rotation.
// ---------------------------------------------------------------------------

test("replaying a consumed authorization is refused the second time", async () => {
  const genesis = await seedGenesis({ note: "original" });
  const next = { note: "corrected" };
  const receipt = await issue(
    authorization({
      action: "correct",
      expectedHead: headOf(1, genesis),
      proposedContent: next,
    }),
  );

  const first = await store().correct({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: next,
    mutationReceiptId: "mutation.replay.1",
  });
  assert.equal(first.verified, true);

  // Put the record back on the head the authorization expects, so the ONLY
  // thing standing between the replay and a second mutation is consumption.
  await withTriggerDisabled(
    "memory_record_versions",
    "memory_record_versions_append_only",
    () =>
      adminPool.query(`DELETE FROM memory_record_versions WHERE version = 2`),
  );
  assert.equal(await countVersions(), 1);

  const second = await store().correct({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: next,
    mutationReceiptId: "mutation.replay.2",
  });
  assert.equal(second.verified, false);
  assert.equal(second.rejection, "authorization_already_consumed");
  assert.equal(await countVersions(), 1);
});

test("a spent nonce still refuses the mutation when the receipt row is forged back to unconsumed", async () => {
  // This is the control that the sequential replay test cannot reach: the
  // receipt row claims the authorization was never spent, and only the atomic
  // UPDATE's rowCount says otherwise.
  const genesis = await seedGenesis({ note: "original" });
  const next = { note: "corrected" };
  const receipt = await issue(
    authorization({
      action: "correct",
      expectedHead: headOf(1, genesis),
      proposedContent: next,
    }),
  );
  assert.equal(
    (
      await store().correct({
        actor: SCOPE,
        authorizationId: receipt.authorizationId,
        recordId: RECORD_ID,
        proposedContent: next,
        mutationReceiptId: "mutation.forge.1",
      })
    ).verified,
    true,
  );

  await withTriggerDisabled(
    "memory_record_versions",
    "memory_record_versions_append_only",
    () =>
      adminPool.query(`DELETE FROM memory_record_versions WHERE version = 2`),
  );
  // Migration 035 makes consumption irreversible for EVERY writer, the owner
  // included, so the forgery this test depends on has to be staged with the
  // control switched off — which is itself the negative control for it.
  await assert.rejects(
    () =>
      adminPool.query(
        `UPDATE memory_authorization_receipts SET consumed_at = NULL
          WHERE authorization_id = $1`,
        [receipt.authorizationId],
      ),
    /consumption is irreversible on memory_authorization_receipts/,
  );
  await withTriggerDisabled(
    "memory_authorization_receipts",
    "memory_authorization_receipts_consumption_monotonic",
    () =>
      adminPool.query(
        `UPDATE memory_authorization_receipts SET consumed_at = NULL
          WHERE authorization_id = $1`,
        [receipt.authorizationId],
      ),
  );

  const replay = await store().correct({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: next,
    mutationReceiptId: "mutation.forge.2",
  });
  assert.equal(replay.verified, false);
  assert.equal(replay.rejection, "authorization_already_consumed");
  assert.equal(await countVersions(), 1);
});

test("rotating the nonce cannot produce a usable authorization", async () => {
  const genesis = await seedGenesis({ note: "original" });
  const next = { note: "corrected" };
  const honest = authorization({
    action: "correct",
    expectedHead: headOf(1, genesis),
    proposedContent: next,
  });

  // A rotated nonce does not even parse: the receipt no longer matches its
  // own token. This is the contracts-level half of the defence.
  assert.throws(
    () =>
      MemoryAuthorizationReceiptSchema.parse({
        ...honest,
        nonce: {
          bindingSchemaVersion: MEMORY_AUTHORIZATION_NONCE_SCHEMA_VERSION,
          bindingDigest: `sha256:${"c".repeat(64)}`,
        },
      }),
    /authorization nonce must be bound to this authorization/,
  );

  // And the Core-level half: a fresh authorization id yields a fresh, valid
  // receipt with a fresh binding digest — but no ISSUED nonce row, so there is
  // nothing to consume and the store refuses rather than inventing one.
  const rotated = authorization({
    action: "correct",
    expectedHead: headOf(1, genesis),
    proposedContent: next,
  });
  await issue(rotated, { skipNonceRow: true });
  const result = await store().correct({
    actor: SCOPE,
    authorizationId: rotated.authorizationId,
    recordId: RECORD_ID,
    proposedContent: next,
    mutationReceiptId: "mutation.rotate.1",
  });
  assert.equal(result.verified, false);
  assert.equal(result.rejection, "nonce_missing");
  assert.equal(await countVersions(), 1);
});

test("a nonce row that disagrees with its receipt is refused rather than reconciled", async () => {
  const genesis = await seedGenesis({ note: "original" });
  const next = { note: "corrected" };
  const receipt = await issue(
    authorization({
      action: "correct",
      expectedHead: headOf(1, genesis),
      proposedContent: next,
    }),
    { nonceAction: "delete" },
  );
  const result = await store().correct({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: next,
    mutationReceiptId: "mutation.disagree.1",
  });
  assert.equal(result.rejection, "nonce_disagrees_with_receipt");
  assert.equal(await countVersions(), 1);
});

// ---------------------------------------------------------------------------
// Compare-and-swap.
// ---------------------------------------------------------------------------

test("a stale expected head is rejected", async () => {
  const genesis = await seedGenesis({ note: "original" });
  const first = { note: "first correction" };
  const authFirst = await issue(
    authorization({
      action: "correct",
      expectedHead: headOf(1, genesis),
      proposedContent: first,
    }),
  );
  await store().correct({
    actor: SCOPE,
    authorizationId: authFirst.authorizationId,
    recordId: RECORD_ID,
    proposedContent: first,
    mutationReceiptId: "mutation.stale.0",
  });

  // Issued against version 1, presented when the head is already version 2.
  const stale = { note: "stale correction" };
  const authStale = await issue(
    authorization({
      action: "correct",
      expectedHead: headOf(1, genesis),
      proposedContent: stale,
    }),
  );
  const result = await store().correct({
    actor: SCOPE,
    authorizationId: authStale.authorizationId,
    recordId: RECORD_ID,
    proposedContent: stale,
    mutationReceiptId: "mutation.stale.1",
  });
  assert.equal(result.rejection, "head_mismatch");
  assert.equal(result.receipt?.outcome.status, "ABORTED_NO_MUTATION");
  assert.equal(await countVersions(), 2);
});

test("a forged predecessor digest is rejected even when the version lines up", async () => {
  await seedGenesis({ note: "original" });
  const next = { note: "corrected" };
  const forged = await issue(
    authorization({
      action: "correct",
      expectedHead: headOf(1, `sha256:${"d".repeat(64)}`),
      proposedContent: next,
    }),
  );
  const result = await store().correct({
    actor: SCOPE,
    authorizationId: forged.authorizationId,
    recordId: RECORD_ID,
    proposedContent: next,
    mutationReceiptId: "mutation.predecessor.1",
  });
  assert.equal(result.rejection, "head_mismatch");
  assert.equal(await countVersions(), 1);
});

test("a forged successor is rejected: the content must digest to what was authorized", async () => {
  const genesis = await seedGenesis({ note: "original" });
  const authorized = { note: "the approved correction" };
  const substituted = { note: "not the approved correction" };
  const receipt = await issue(
    authorization({
      action: "correct",
      expectedHead: headOf(1, genesis),
      proposedContent: authorized,
    }),
  );
  const result = await store().correct({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: substituted,
    mutationReceiptId: "mutation.successor.1",
  });
  assert.equal(result.rejection, "proposed_content_digest_mismatch");
  assert.equal(await countVersions(), 1);
  assert.equal(await nonceConsumedAt(receipt.nonce.bindingDigest), null);
});

test("a record with no versions cannot be corrected", async () => {
  const receipt = await issue(
    authorization({
      action: "correct",
      expectedHead: headOf(1, `sha256:${"e".repeat(64)}`),
      proposedContent: { note: "x" },
    }),
  );
  const result = await store().correct({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: { note: "x" },
    mutationReceiptId: "mutation.missing.1",
  });
  assert.equal(result.rejection, "head_mismatch");
});

// ---------------------------------------------------------------------------
// Scope. One test per dimension, because a dimension with no killing test is
// a dimension nobody has checked.
// ---------------------------------------------------------------------------

for (const dimension of [
  "tenantId",
  "workspaceId",
  "principalId",
  "userId",
] as const) {
  test(`a mutation across ${dimension} is rejected`, async () => {
    const genesis = await seedGenesis({ note: "original" });
    const next = { note: "corrected" };
    const receipt = await issue(
      authorization({
        action: "correct",
        expectedHead: headOf(1, genesis),
        proposedContent: next,
      }),
    );
    const attacker: TrustedMemoryActor = {
      ...SCOPE,
      [dimension]: `${SCOPE[dimension]}-other`,
    };
    const result = await store().correct({
      actor: attacker,
      authorizationId: receipt.authorizationId,
      recordId: RECORD_ID,
      proposedContent: next,
      mutationReceiptId: `mutation.scope.${dimension.toLowerCase()}`,
    });
    assert.equal(result.verified, false);
    assert.equal(result.rejection, "authorization_scope_mismatch");
    assert.equal(await countVersions(), 1);
    assert.equal(await nonceConsumedAt(receipt.nonce.bindingDigest), null);
  });
}

test("an authorization for another record cannot be redirected", async () => {
  const genesis = await seedGenesis({ note: "original" });
  await seedGenesis({ note: "other" }, { recordId: "record-memory-002" });
  const next = { note: "corrected" };
  const receipt = await issue(
    authorization({
      action: "correct",
      targetRecordId: "record-memory-002",
      expectedHead: headOf(1, genesis),
      proposedContent: next,
    }),
  );
  const result = await store().correct({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: next,
    mutationReceiptId: "mutation.target.1",
  });
  assert.equal(result.rejection, "authorization_target_mismatch");
  assert.equal(await countVersions(), 1);
});

test("an authorization for correct cannot perform a delete", async () => {
  const genesis = await seedGenesis({ note: "original" });
  const next = { note: "corrected" };
  const receipt = await issue(
    authorization({
      action: "correct",
      expectedHead: headOf(1, genesis),
      proposedContent: next,
    }),
  );
  const result = await store().delete({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: next,
    mutationReceiptId: "mutation.action.1",
  });
  assert.equal(result.rejection, "authorization_action_mismatch");
  assert.equal(await countVersions(), 1);
});

test("an unknown authorization id is refused and emits no receipt to hide behind", async () => {
  await seedGenesis({ note: "original" });
  const result = await store().correct({
    actor: SCOPE,
    authorizationId: nextAuthorizationId(),
    recordId: RECORD_ID,
    proposedContent: { note: "x" },
    mutationReceiptId: "mutation.unknown.1",
  });
  assert.equal(result.verified, false);
  assert.equal(result.rejection, "authorization_not_found");
  assert.equal(result.receipt, null);
  assert.equal(await countVersions(), 1);
});

// ---------------------------------------------------------------------------
// Expiry and revocation, per stored source.
// ---------------------------------------------------------------------------

test("an expired authorization is rejected (payload, column and nonce all expired)", async () => {
  const genesis = await seedGenesis({ note: "original" });
  const next = { note: "corrected" };
  const receipt = await issue(
    authorization({
      action: "correct",
      expectedHead: headOf(1, genesis),
      proposedContent: next,
      issuedAt: isoOffset(-7_200_000),
      expiresAt: isoOffset(-3_600_000),
    }),
  );
  const result = await store().correct({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: next,
    mutationReceiptId: "mutation.expired.all",
  });
  assert.equal(result.rejection, "authorization_expired");
  assert.equal(result.receipt?.outcome.status, "ABORTED_NO_MUTATION");
  assert.ok(result.receipt && result.receipt.outcome.status === "ABORTED_NO_MUTATION");
  assert.equal(result.receipt.outcome.abortReason, "authorization_expired");
  assert.equal(await countVersions(), 1);
});

test("expiry takes the earliest reading: an expired jsonb payload beats live columns", async () => {
  const genesis = await seedGenesis({ note: "original" });
  const next = { note: "corrected" };
  const receipt = await issue(
    authorization({
      action: "correct",
      expectedHead: headOf(1, genesis),
      proposedContent: next,
      issuedAt: isoOffset(-7_200_000),
      expiresAt: isoOffset(-3_600_000),
    }),
    {
      receiptExpiresAt: isoOffset(3_600_000),
      nonceExpiresAt: isoOffset(3_600_000),
    },
  );
  const result = await store().correct({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: next,
    mutationReceiptId: "mutation.expired.payload",
  });
  assert.equal(result.rejection, "authorization_expired");
});

test("expiry takes the earliest reading: an expired receipt column beats a live payload", async () => {
  const genesis = await seedGenesis({ note: "original" });
  const next = { note: "corrected" };
  const receipt = await issue(
    authorization({
      action: "correct",
      expectedHead: headOf(1, genesis),
      proposedContent: next,
      issuedAt: isoOffset(-7_200_000),
      expiresAt: isoOffset(3_600_000),
    }),
    { receiptExpiresAt: isoOffset(-3_600_000) },
  );
  const result = await store().correct({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: next,
    mutationReceiptId: "mutation.expired.column",
  });
  assert.equal(result.rejection, "authorization_expired");
});

test("expiry takes the earliest reading: an expired nonce row beats a live receipt", async () => {
  const genesis = await seedGenesis({ note: "original" });
  const next = { note: "corrected" };
  const receipt = await issue(
    authorization({
      action: "correct",
      expectedHead: headOf(1, genesis),
      proposedContent: next,
      issuedAt: isoOffset(-7_200_000),
      expiresAt: isoOffset(3_600_000),
    }),
    { nonceExpiresAt: isoOffset(-3_600_000) },
  );
  const result = await store().correct({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: next,
    mutationReceiptId: "mutation.expired.nonce",
  });
  assert.equal(result.rejection, "authorization_expired");
});

test("a revoked authorization is rejected (revoked in the jsonb payload)", async () => {
  const genesis = await seedGenesis({ note: "original" });
  const next = { note: "corrected" };
  const receipt = await issue(
    authorization({
      action: "correct",
      expectedHead: headOf(1, genesis),
      proposedContent: next,
      revokedAt: isoOffset(-30_000),
    }),
    { receiptRevokedAt: null, nonceRevokedAt: null },
  );
  const result = await store().correct({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: next,
    mutationReceiptId: "mutation.revoked.payload",
  });
  assert.equal(result.rejection, "authorization_revoked");
  assert.ok(result.receipt && result.receipt.outcome.status === "ABORTED_NO_MUTATION");
  assert.equal(result.receipt.outcome.abortReason, "authorization_revoked");
  assert.equal(await countVersions(), 1);
});

test("a revoked authorization is rejected (revoked on the receipt row only)", async () => {
  const genesis = await seedGenesis({ note: "original" });
  const next = { note: "corrected" };
  const receipt = await issue(
    authorization({
      action: "correct",
      expectedHead: headOf(1, genesis),
      proposedContent: next,
    }),
  );
  const client = await adminPool.connect();
  try {
    await client.query("BEGIN");
    await client.query('SET LOCAL ROLE "aaliyah_memory_revoker"');
    await client.query(
      `UPDATE memory_authorization_receipts SET revoked_at = now()
        WHERE authorization_id = $1`,
      [receipt.authorizationId],
    );
    await client.query("COMMIT");
  } finally {
    client.release();
  }
  const result = await store().correct({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: next,
    mutationReceiptId: "mutation.revoked.column",
  });
  assert.equal(result.rejection, "authorization_revoked");
  assert.equal(await countVersions(), 1);
});

test("a revoked authorization is rejected (revoked on the nonce row only)", async () => {
  const genesis = await seedGenesis({ note: "original" });
  const next = { note: "corrected" };
  const receipt = await issue(
    authorization({
      action: "correct",
      expectedHead: headOf(1, genesis),
      proposedContent: next,
    }),
  );
  const client = await adminPool.connect();
  try {
    await client.query("BEGIN");
    await client.query('SET LOCAL ROLE "aaliyah_memory_revoker"');
    await client.query(
      `UPDATE memory_authorization_nonces SET revoked_at = now()
        WHERE binding_digest = $1`,
      [receipt.nonce.bindingDigest],
    );
    await client.query("COMMIT");
  } finally {
    client.release();
  }
  const result = await store().correct({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: next,
    mutationReceiptId: "mutation.revoked.nonce",
  });
  assert.equal(result.rejection, "authorization_revoked");
  assert.equal(await countVersions(), 1);
});

// ---------------------------------------------------------------------------
// Read-back.
// ---------------------------------------------------------------------------

test("a read-back that disagrees with the commit reports divergence, never success", async () => {
  const genesis = await seedGenesis({ note: "original" });
  const next = { note: "corrected" };
  const receipt = await issue(
    authorization({
      action: "correct",
      expectedHead: headOf(1, genesis),
      proposedContent: next,
    }),
  );
  // The read-back session resolves memory_record_versions to a shadow relation
  // holding a genuinely different version 2.
  await seedGenesis({ note: "original" }, { schema: SHADOW_SCHEMA });
  await adminPool.query(
    `INSERT INTO ${SHADOW_SCHEMA}.memory_record_versions
       (tenant_id, workspace_id, principal_id, user_id, record_id, version,
        state, content_digest, predecessor_digest, authorization_id,
        mutation_receipt_id, payload)
     VALUES ($1,$2,$3,$4,$5,2,'active',$6,$7,$8,$9,$10)`,
    [
      SCOPE.tenantId,
      SCOPE.workspaceId,
      SCOPE.principalId,
      SCOPE.userId,
      RECORD_ID,
      memoryContentDigest({ note: "something else entirely" }),
      genesis,
      receipt.authorizationId,
      "mutation.diverge.1",
      JSON.stringify({
        schemaVersion: MEMORY_RECORD_VERSION_SCHEMA_VERSION,
        recordId: RECORD_ID,
        version: 2,
        state: "active",
        scope: SCOPE,
        content: { note: "something else entirely" },
        contentDigest: memoryContentDigest({ note: "something else entirely" }),
        predecessorDigest: genesis,
        authorizationId: receipt.authorizationId,
        mutationReceiptId: "mutation.diverge.1",
        createdAt: isoOffset(0),
      }),
    ],
  );

  const result = await store({ readBack: shadowReadPool }).correct({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: next,
    mutationReceiptId: "mutation.diverge.1",
  });

  assert.equal(result.verified, false);
  assert.equal(result.rejection, "read_back_diverged");
  assert.equal(result.receipt?.outcome.status, "COMMITTED_READ_BACK_DIVERGED");
  assert.deepEqual(await receiptStatuses("mutation.diverge.1"), [
    { phase: "pending", status: "UNKNOWN_PENDING_RECONCILIATION" },
    { phase: "terminal", status: "COMMITTED_READ_BACK_DIVERGED" },
  ]);
});

test("a read-back that finds nothing reports UNKNOWN, never success", async () => {
  const genesis = await seedGenesis({ note: "original" });
  const next = { note: "corrected" };
  const receipt = await issue(
    authorization({
      action: "correct",
      expectedHead: headOf(1, genesis),
      proposedContent: next,
    }),
  );
  // The shadow relation is empty: the commit landed in public, the read-back
  // looks somewhere that has no row at all.
  const result = await store({ readBack: shadowReadPool }).correct({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: next,
    mutationReceiptId: "mutation.unknown.readback",
  });

  assert.equal(result.verified, false);
  assert.equal(result.rejection, "unknown_outcome");
  assert.equal(
    result.receipt?.outcome.status,
    "UNKNOWN_PENDING_RECONCILIATION",
  );
  assert.ok(
    result.receipt &&
      result.receipt.outcome.status === "UNKNOWN_PENDING_RECONCILIATION",
  );
  assert.equal(result.receipt.outcome.lastObservedPhase, "read_back_attempted");
  assert.equal(result.receipt.outcome.reconciliationState, "open");
  // The mutation DID commit. The point is that the outcome is not reported as
  // success, and that the durable log says so too.
  assert.equal(await countVersions(), 2);
  assert.deepEqual(await receiptStatuses("mutation.unknown.readback"), [
    { phase: "pending", status: "UNKNOWN_PENDING_RECONCILIATION" },
    { phase: "terminal", status: "UNKNOWN_PENDING_RECONCILIATION" },
  ]);
});

test("the post-commit read-back pool must be independent of the mutation pool", () => {
  assert.throws(
    () => createPostgresTrustedMemoryStore(writePool, writePool),
    /read-back pool must be independent/,
  );
});

// ---------------------------------------------------------------------------
// Canonicalisation: this is why the digest exists.
// ---------------------------------------------------------------------------

test("jsonb key reordering does not break verification", async () => {
  // Genesis is written with keys in one order; the authorization is computed
  // from the same content spelled in another. PostgreSQL jsonb stores object
  // keys in its own order, so a stringify-and-hash would fail here.
  const genesis = await seedGenesis({ alpha: "a", beta: "b", gamma: 3 });
  assert.equal(
    genesis,
    memoryContentDigest({ gamma: 3, beta: "b", alpha: "a" }),
    "canonical digest must be insensitive to key order",
  );

  const nextOrderA = { zulu: "z", alpha: "a", mike: 13 };
  const nextOrderB = { mike: 13, zulu: "z", alpha: "a" };
  const receipt = await issue(
    authorization({
      action: "correct",
      expectedHead: headOf(1, memoryContentDigest({ gamma: 3, beta: "b", alpha: "a" })),
      proposedContent: nextOrderA,
    }),
  );
  const result = await store().correct({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: nextOrderB,
    mutationReceiptId: "mutation.keyorder.1",
  });
  assert.equal(result.rejection, null);
  assert.equal(result.verified, true);

  const head = await store().readHead(SCOPE, RECORD_ID);
  assert.equal(head?.contentDigest, memoryContentDigest(nextOrderA));
});

// ---------------------------------------------------------------------------
// Atomicity, the numeric domain, and the privilege boundary.
// ---------------------------------------------------------------------------

test("a storage rejection rolls back the whole transaction and leaves no partial state", async () => {
  const genesis = await seedGenesis({ note: "original" });
  // A fractional JSON number: digestible in JavaScript, and refused by the
  // database because jsonb would store a value Node cannot faithfully read
  // back (W1BR-006). The failure lands AFTER the nonce has been consumed and
  // AFTER the pending receipt was prepared, which is exactly the window this
  // test exists to cover.
  const next = { note: "corrected", ratio: 0.1 };
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
    mutationReceiptId: "mutation.rollback.1",
  });

  assert.equal(result.verified, false);
  assert.equal(result.rejection, "storage_rejected");
  // Nothing partial survived: no new version, the nonce is unspent, the
  // receipt is unconsumed, and no pending receipt row exists.
  assert.equal(await countVersions(), 1);
  assert.equal(await nonceConsumedAt(receipt.nonce.bindingDigest), null);
  const consumed = await adminPool.query(
    `SELECT consumed_at FROM memory_authorization_receipts WHERE authorization_id = $1`,
    [receipt.authorizationId],
  );
  assert.equal(consumed.rows[0].consumed_at, null);
  assert.deepEqual(
    (await receiptStatuses("mutation.rollback.1")).map((r) => r.phase),
    ["terminal"],
  );
  const head = await store().readHead(SCOPE, RECORD_ID);
  assert.equal(head?.version, 1);
});

test("the database refuses inexact jsonb numbers from ANY writer, not just from Core", async () => {
  // The exclusivity of the receipt path is enforced by the database, so it
  // holds for psql, for a rogue service, and for anything that never imports
  // this package.
  //
  // The offending numbers are injected as RAW JSON TEXT on purpose. A
  // JavaScript literal cannot express them: `2.0` IS `2` in JavaScript and
  // `0.1000000000000000000001` IS `0.1`, so a fixture built with
  // JSON.stringify would quietly test something else. That collapse is
  // precisely W1BR-006, and it is why the guard has to live in the database
  // rather than in a Node-side validator.
  const digest = `sha256:${"f".repeat(64)}`;
  // Migration 034 requires a spent authorization behind every appended row.
  // The numeric domain is what THIS test is about, so the append is made
  // legitimate in every other respect and the only thing left to refuse it is
  // the numeric trigger.
  await witnessAppend({
    authorizationId: "direct-0000000000000000000001",
    mutationReceiptId: "mutation.direct",
    recordId: "record-direct-001",
  });
  const payload = (contentJson: string) =>
    [
      `{"schemaVersion":"${MEMORY_RECORD_VERSION_SCHEMA_VERSION}"`,
      `"recordId":"record-direct-001"`,
      `"version":1`,
      `"state":"active"`,
      `"scope":${JSON.stringify(SCOPE)}`,
      `"content":${contentJson}`,
      `"contentDigest":"${digest}"`,
      `"predecessorDigest":null`,
      `"authorizationId":"direct-0000000000000000000001"`,
      `"mutationReceiptId":"mutation.direct"`,
      `"createdAt":"${isoOffset(0)}"}`,
    ].join(",");
  const insert = (contentJson: string) =>
    adminPool.query(
      `INSERT INTO memory_record_versions
         (tenant_id, workspace_id, principal_id, user_id, record_id, version,
          state, content_digest, predecessor_digest, authorization_id,
          mutation_receipt_id, payload)
       VALUES ($1,$2,$3,$4,'record-direct-001',1,'active',$5,NULL,
               'direct-0000000000000000000001','mutation.direct',$6::jsonb)`,
      [
        SCOPE.tenantId,
        SCOPE.workspaceId,
        SCOPE.principalId,
        SCOPE.userId,
        digest,
        payload(contentJson),
      ],
    );

  // Stored exactly by jsonb, collapsed to 0.1 by Node. Same digest as 0.1.
  await assert.rejects(
    () => insert(`{"ratio":0.1000000000000000000001}`),
    /outside the exact numeric domain/,
  );
  // An ordinary fraction: the whole class is refused, not just the exotic one.
  await assert.rejects(
    () => insert(`{"ratio":0.1}`),
    /outside the exact numeric domain/,
  );
  // Beyond Number.MAX_SAFE_INTEGER: Node reads 9007199254740992.
  await assert.rejects(
    () => insert(`{"big":9007199254740993}`),
    /outside the exact numeric domain/,
  );
  // jsonb keeps the text `2.0`; Node would render `2` and digest differently.
  await assert.rejects(
    () => insert(`{"trailing":2.0}`),
    /outside the exact numeric domain/,
  );
  // And nested, so the guard is not a shallow top-level scan.
  await assert.rejects(
    () => insert(`{"a":{"b":[{"c":1.5}]}}`),
    /outside the exact numeric domain/,
  );
  // A safe integer is accepted, so this is a domain restriction and not a
  // blanket refusal that would pass the assertions above by rejecting all.
  await insert(`{"count":42,"nested":{"list":[1,-7,0]}}`);
  assert.equal(await countVersions("record-direct-001"), 1);
});

test("the database refuses a row whose jsonb payload disagrees with its columns", async () => {
  // Migration 023 binds the payload to the relational columns with CHECK
  // constraints. Core never writes a row that violates them, so without this
  // test those constraints have no evidence behind them: dropping any of them
  // leaves the suite green and the next writer free to lie in jsonb about who
  // a row belongs to.
  const content = { note: "original" };
  const digest = memoryContentDigest(content);
  await witnessAppend({
    authorizationId: "binding-0000000000000000000001",
    mutationReceiptId: "mutation.binding",
    recordId: "record-binding-001",
  });
  const row = (payloadOverrides: Record<string, unknown>) =>
    adminPool.query(
      `INSERT INTO memory_record_versions
         (tenant_id, workspace_id, principal_id, user_id, record_id, version,
          state, content_digest, predecessor_digest, authorization_id,
          mutation_receipt_id, payload)
       VALUES ($1,$2,$3,$4,'record-binding-001',1,'active',$5,NULL,
               'binding-0000000000000000000001','mutation.binding',$6)`,
      [
        SCOPE.tenantId,
        SCOPE.workspaceId,
        SCOPE.principalId,
        SCOPE.userId,
        digest,
        JSON.stringify({
          schemaVersion: MEMORY_RECORD_VERSION_SCHEMA_VERSION,
          recordId: "record-binding-001",
          version: 1,
          state: "active",
          scope: SCOPE,
          content,
          contentDigest: digest,
          predecessorDigest: null,
          authorizationId: "binding-0000000000000000000001",
          mutationReceiptId: "mutation.binding",
          createdAt: isoOffset(0),
          ...payloadOverrides,
        }),
      ],
    );

  await assert.rejects(
    () => row({ scope: { ...SCOPE, tenantId: "tenant-somebody-else" } }),
    /memory_record_versions_tenant_binding/,
  );
  await assert.rejects(
    () => row({ scope: { ...SCOPE, workspaceId: "workspace-somebody-else" } }),
    /memory_record_versions_workspace_binding/,
  );
  await assert.rejects(
    () => row({ scope: { ...SCOPE, principalId: "principal-somebody-else" } }),
    /memory_record_versions_principal_binding/,
  );
  await assert.rejects(
    () => row({ scope: { ...SCOPE, userId: "user-somebody-else" } }),
    /memory_record_versions_user_binding/,
  );
  await assert.rejects(
    () => row({ contentDigest: `sha256:${"1".repeat(64)}` }),
    /memory_record_versions_content_digest_binding/,
  );
  await assert.rejects(
    () => row({ recordId: "record-somewhere-else" }),
    /memory_record_versions_record_binding/,
  );
  await assert.rejects(
    () => row({ version: 99 }),
    /memory_record_versions_version_binding/,
  );
  await assert.rejects(
    () => row({ state: "deleted" }),
    /memory_record_versions_state_binding/,
  );
  await assert.rejects(
    () => row({ predecessorDigest: `sha256:${"2".repeat(64)}` }),
    /memory_record_versions_predecessor_digest_binding/,
  );
  // The consistent row is accepted, so the constraints are bindings and not a
  // blanket refusal that would satisfy every assertion above.
  await row({});
  assert.equal(await countVersions("record-binding-001"), 1);
});

test("the mutation role can consume a nonce and can do nothing else to it", async () => {
  const client = await adminPool.connect();
  try {
    for (const [statement, matcher] of [
      [
        `INSERT INTO memory_authorization_nonces
           (tenant_id, workspace_id, binding_digest, authorization_id, action,
            target_record_id, issued_at, expires_at)
         VALUES ('t','w','sha256:${"a".repeat(64)}','a','correct','r',now(),now()+interval '1 hour')`,
        /permission denied for table memory_authorization_nonces/,
      ],
      [
        `UPDATE memory_authorization_nonces SET expires_at = now() + interval '1 hour'`,
        /permission denied for table memory_authorization_nonces/,
      ],
      [
        `UPDATE memory_authorization_nonces SET revoked_at = NULL`,
        /permission denied for table memory_authorization_nonces/,
      ],
      [
        `UPDATE memory_authorization_nonces SET binding_digest = 'sha256:${"a".repeat(64)}'`,
        /permission denied for table memory_authorization_nonces/,
      ],
      [
        `INSERT INTO memory_authorization_receipts
           (tenant_id, workspace_id, principal_id, user_id, authorization_id,
            action, target_record_id, binding_digest, issued_at, expires_at, payload)
         VALUES ('t','w','p','u','a','correct','r','sha256:${"a".repeat(64)}',
                 now(), now()+interval '1 hour', '{}')`,
        /permission denied for table memory_authorization_receipts/,
      ],
    ] as Array<[string, RegExp]>) {
      await client.query("BEGIN");
      try {
        await client.query('SET LOCAL ROLE "aaliyah_memory_mutator"');
        await assert.rejects(() => client.query(statement), matcher);
      } finally {
        // A failed assertion must not hand a client back to the pool with an
        // open transaction on it. That contaminates whichever test picks the
        // connection up next, and turns one honest failure into several
        // dishonest ones.
        await client.query("ROLLBACK");
      }
    }

    // The one thing it MAY do.
    await client.query("BEGIN");
    try {
      await client.query('SET LOCAL ROLE "aaliyah_memory_mutator"');
      await client.query(
        `UPDATE memory_authorization_nonces
            SET consumed_at = now(), consumed_by_mutation_receipt_id = 'm'
          WHERE false`,
      );
    } finally {
      await client.query("ROLLBACK");
    }
  } finally {
    client.release();
  }
});

test("the issuer cannot consume and the reader cannot write", async () => {
  const client = await adminPool.connect();
  try {
    await client.query("BEGIN");
    try {
      await client.query('SET LOCAL ROLE "aaliyah_memory_issuer"');
      await assert.rejects(
        () =>
          client.query(
            `UPDATE memory_authorization_nonces SET consumed_at = now() WHERE false`,
          ),
        /permission denied for table memory_authorization_nonces/,
      );
    } finally {
      await client.query("ROLLBACK");
    }

    await client.query("BEGIN");
    try {
      await client.query('SET LOCAL ROLE "aaliyah_memory_reader"');
      await assert.rejects(
        () =>
          client.query(
            `INSERT INTO memory_mutation_receipts
               (tenant_id, workspace_id, principal_id, user_id, mutation_receipt_id,
                phase, authorization_id, consumed_nonce_digest, action,
                target_record_id, outcome_status, emitted_at, payload)
             VALUES ('t','w','p','u','m','terminal','a','sha256:${"a".repeat(64)}',
                     'correct','r','ABORTED_NO_MUTATION', now(), '{}')`,
          ),
        /permission denied for table memory_mutation_receipts/,
      );
    } finally {
      await client.query("ROLLBACK");
    }
  } finally {
    client.release();
  }
});

test("the version chain and the mutation receipt log refuse UPDATE and DELETE", async () => {
  const genesis = await seedGenesis({ note: "original" });
  const next = { note: "corrected" };
  const receipt = await issue(
    authorization({
      action: "correct",
      expectedHead: headOf(1, genesis),
      proposedContent: next,
    }),
  );
  await store().correct({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: next,
    mutationReceiptId: "mutation.immutable.1",
  });

  await assert.rejects(
    () =>
      adminPool.query(
        `UPDATE memory_record_versions SET content_digest = $1 WHERE version = 2`,
        [`sha256:${"9".repeat(64)}`],
      ),
    /UPDATE on memory_record_versions is forbidden/,
  );
  await assert.rejects(
    () => adminPool.query(`DELETE FROM memory_record_versions WHERE version = 2`),
    /DELETE on memory_record_versions is forbidden/,
  );
  await assert.rejects(
    () =>
      adminPool.query(
        `UPDATE memory_mutation_receipts SET outcome_status = 'COMMITTED_AND_READ_BACK'
          WHERE phase = 'pending'`,
      ),
    /UPDATE on memory_mutation_receipts is forbidden/,
  );
  await assert.rejects(
    () => adminPool.query(`DELETE FROM memory_mutation_receipts`),
    /DELETE on memory_mutation_receipts is forbidden/,
  );
});

test("a malformed request never reaches the database", async () => {
  const result = await store().correct({
    actor: SCOPE,
    authorizationId: nextAuthorizationId(),
    recordId: "SENSITIVE: CEO divorce settlement terms",
    proposedContent: {},
    mutationReceiptId: "mutation.malformed.1",
  });
  assert.equal(result.rejection, "request_malformed");
  assert.equal(result.receipt, null);
});

// ---------------------------------------------------------------------------
// Controls that the tests above cover for each other. Each of these exists
// because deleting the control it names left the suite GREEN, which means the
// control had no evidence behind it.
// ---------------------------------------------------------------------------

test("a head at the WRONG VERSION is rejected even when its content digest matches", async () => {
  // Without this, the version half of the compare-and-swap has no killing
  // test: every other head-mismatch case also has a mismatched digest, so the
  // digest comparison covers for the version comparison.
  const genesis = await seedGenesis({ note: "original" });
  const second = { note: "second" };
  const authFirst = await issue(
    authorization({
      action: "correct",
      expectedHead: headOf(1, genesis),
      proposedContent: second,
    }),
  );
  await store().correct({
    actor: SCOPE,
    authorizationId: authFirst.authorizationId,
    recordId: RECORD_ID,
    proposedContent: second,
    mutationReceiptId: "mutation.versiononly.0",
  });
  const headNow = await store().readHead(SCOPE, RECORD_ID);
  assert.equal(headNow?.version, 2);

  // Expected head names version 1 but carries the digest the head ACTUALLY
  // has. Only the version comparison can refuse this.
  const third = { note: "third" };
  const skewed = await issue(
    authorization({
      action: "correct",
      expectedHead: headOf(1, memoryContentDigest(second)),
      proposedContent: third,
    }),
  );
  const result = await store().correct({
    actor: SCOPE,
    authorizationId: skewed.authorizationId,
    recordId: RECORD_ID,
    proposedContent: third,
    mutationReceiptId: "mutation.versiononly.1",
  });
  assert.equal(result.verified, false);
  assert.equal(result.rejection, "head_mismatch");
  assert.equal(await countVersions(), 2);
});

test("a receipt row marked consumed refuses the mutation even when its nonce is unspent", async () => {
  // The mutation role holds UPDATE on the nonce's consumed_at, so "reset the
  // nonce and replay" is a reachable attack. The receipt-side pre-check is
  // what refuses it, and without this test deleting that pre-check is free.
  const genesis = await seedGenesis({ note: "original" });
  const next = { note: "corrected" };
  const receipt = await issue(
    authorization({
      action: "correct",
      expectedHead: headOf(1, genesis),
      proposedContent: next,
    }),
  );
  assert.equal(
    (
      await store().correct({
        actor: SCOPE,
        authorizationId: receipt.authorizationId,
        recordId: RECORD_ID,
        proposedContent: next,
        mutationReceiptId: "mutation.resetnonce.1",
      })
    ).verified,
    true,
  );

  await withTriggerDisabled(
    "memory_record_versions",
    "memory_record_versions_append_only",
    () =>
      adminPool.query(`DELETE FROM memory_record_versions WHERE version = 2`),
  );
  // Same as above: resurrecting a spent nonce is refused by the database now,
  // so the state this control is tested against has to be staged deliberately.
  await assert.rejects(
    () =>
      adminPool.query(
        `UPDATE memory_authorization_nonces
            SET consumed_at = NULL, consumed_by_mutation_receipt_id = NULL
          WHERE binding_digest = $1`,
        [receipt.nonce.bindingDigest],
      ),
    /consumption is irreversible on memory_authorization_nonces/,
  );
  await withTriggerDisabled(
    "memory_authorization_nonces",
    "memory_authorization_nonces_consumption_monotonic",
    () =>
      adminPool.query(
        `UPDATE memory_authorization_nonces
            SET consumed_at = NULL, consumed_by_mutation_receipt_id = NULL
          WHERE binding_digest = $1`,
        [receipt.nonce.bindingDigest],
      ),
  );
  assert.equal(await nonceConsumedAt(receipt.nonce.bindingDigest), null);

  const replay = await store().correct({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: next,
    mutationReceiptId: "mutation.resetnonce.2",
  });
  assert.equal(replay.verified, false);
  assert.equal(replay.rejection, "authorization_already_consumed");
  assert.equal(await countVersions(), 1);
});

test("a receipt whose jsonb payload is already consumed is refused", async () => {
  const genesis = await seedGenesis({ note: "original" });
  const next = { note: "corrected" };
  const receipt = await issue(
    authorization({
      action: "correct",
      expectedHead: headOf(1, genesis),
      proposedContent: next,
      consumedAt: isoOffset(-30_000),
    }),
    { receiptConsumedAt: null },
  );
  const stored = await adminPool.query(
    `SELECT consumed_at FROM memory_authorization_receipts WHERE authorization_id = $1`,
    [receipt.authorizationId],
  );
  assert.equal(stored.rows[0].consumed_at, null, "only the payload is consumed");

  const result = await store().correct({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: next,
    mutationReceiptId: "mutation.payloadconsumed.1",
  });
  assert.equal(result.rejection, "authorization_already_consumed");
  assert.equal(await countVersions(), 1);
});

test("a read-back whose CONTENT matches but whose post-state does not is UNKNOWN, not success", async () => {
  const genesis = await seedGenesis({ note: "original" });
  const next = { note: "corrected" };
  const receipt = await issue(
    authorization({
      action: "correct",
      expectedHead: headOf(1, genesis),
      proposedContent: next,
    }),
  );
  // The shadow head carries EXACTLY the authorized content, so the digest
  // comparison is satisfied — and sits at version 9 with a predecessor that
  // was never the head. Only the post-state comparison can catch this.
  const nextDigest = memoryContentDigest(next);
  const bogusPredecessor = `sha256:${"7".repeat(64)}`;
  await adminPool.query(
    `INSERT INTO ${SHADOW_SCHEMA}.memory_record_versions
       (tenant_id, workspace_id, principal_id, user_id, record_id, version,
        state, content_digest, predecessor_digest, authorization_id,
        mutation_receipt_id, payload)
     VALUES ($1,$2,$3,$4,$5,9,'active',$6,$7,$8,$9,$10)`,
    [
      SCOPE.tenantId,
      SCOPE.workspaceId,
      SCOPE.principalId,
      SCOPE.userId,
      RECORD_ID,
      nextDigest,
      bogusPredecessor,
      receipt.authorizationId,
      "mutation.poststate.1",
      JSON.stringify({
        schemaVersion: MEMORY_RECORD_VERSION_SCHEMA_VERSION,
        recordId: RECORD_ID,
        version: 9,
        state: "active",
        scope: SCOPE,
        content: next,
        contentDigest: nextDigest,
        predecessorDigest: bogusPredecessor,
        authorizationId: receipt.authorizationId,
        mutationReceiptId: "mutation.poststate.1",
        createdAt: isoOffset(0),
      }),
    ],
  );

  const result = await store({ readBack: shadowReadPool }).correct({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: next,
    mutationReceiptId: "mutation.poststate.1",
  });
  assert.equal(result.verified, false);
  assert.equal(result.rejection, "unknown_outcome");
  assert.equal(
    result.receipt?.outcome.status,
    "UNKNOWN_PENDING_RECONCILIATION",
  );
});

test("a row whose columns disagree with its payload is refused, not reconciled", async () => {
  // Migration 023's CHECK constraints make this unrepresentable in `public`.
  // Against a relation without them it is trivially representable, which is
  // the case the application-level binding check exists for.
  await adminPool.query(
    `INSERT INTO ${UNCHECKED_SCHEMA}.memory_record_versions
       (tenant_id, workspace_id, principal_id, user_id, record_id, version,
        state, content_digest, predecessor_digest, authorization_id,
        mutation_receipt_id, payload)
     VALUES ($1,$2,$3,$4,$5,1,'active',$6,NULL,$7,$8,$9)`,
    [
      SCOPE.tenantId,
      SCOPE.workspaceId,
      SCOPE.principalId,
      SCOPE.userId,
      RECORD_ID,
      memoryContentDigest({ note: "original" }),
      "genesis-000000000000000000000",
      "mutation.genesis",
      JSON.stringify({
        schemaVersion: MEMORY_RECORD_VERSION_SCHEMA_VERSION,
        recordId: RECORD_ID,
        // The payload claims version 7; the column says 1.
        version: 7,
        state: "active",
        scope: SCOPE,
        content: { note: "original" },
        contentDigest: memoryContentDigest({ note: "original" }),
        predecessorDigest: null,
        authorizationId: "genesis-000000000000000000000",
        mutationReceiptId: "mutation.genesis",
        createdAt: isoOffset(-120_000),
      }),
    ],
  );

  await assert.rejects(
    () =>
      createPostgresTrustedMemoryStore(writePool, uncheckedReadPool).readHead(
        SCOPE,
        RECORD_ID,
      ),
    /record row and payload binding mismatch/,
  );
});

test("a role option that is not a plain identifier is refused at construction", () => {
  assert.throws(
    () =>
      createPostgresTrustedMemoryStore(writePool, readPool, {
        mutationRole: 'postgres"; DROP TABLE memory_record_versions; --',
      }),
    /mutationRole is not a valid role identifier/,
  );
  assert.throws(
    () =>
      createPostgresTrustedMemoryStore(writePool, readPool, {
        readBackRole: "Reader",
      }),
    /readBackRole is not a valid role identifier/,
  );
});

// ---------------------------------------------------------------------------
// W1.3 Part B2 — WHAT MAY BE APPENDED.
//
// Migration 029 constrains WHO may write. Everything below is about WHAT, and
// every one of these was EXECUTED as an exploit against 34ac77f before it was
// a test: the least-privilege mutator forged a record chain and a terminal
// success receipt, an authorization for one principal took over another
// principal's record, a spent approval was resurrected, a healthy write was
// filed as a storage divergence, record content reached the server log, and an
// unknown authorization id left no trace at all.
// ---------------------------------------------------------------------------

/** Run a statement as the least-privilege mutation role and return the error. */
async function asMutator(sql: string, params: unknown[] = []): Promise<void> {
  await runAs("aaliyah_memory_mutator", sql, params);
}

const FORGED_VERSION_SQL = `INSERT INTO memory_record_versions
   (tenant_id, workspace_id, principal_id, user_id, record_id, version,
    state, content_digest, predecessor_digest, authorization_id,
    mutation_receipt_id, payload)
 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`;

function versionPayload(input: {
  recordId: string;
  version: number;
  contentDigest: string;
  predecessorDigest: string | null;
  authorizationId: string;
  mutationReceiptId: string;
  scope?: MemoryScope;
  content?: unknown;
  state?: string;
}): string {
  return JSON.stringify({
    schemaVersion: MEMORY_RECORD_VERSION_SCHEMA_VERSION,
    recordId: input.recordId,
    version: input.version,
    state: input.state ?? "active",
    scope: input.scope ?? SCOPE,
    content: input.content ?? { note: "appended" },
    contentDigest: input.contentDigest,
    predecessorDigest: input.predecessorDigest,
    authorizationId: input.authorizationId,
    mutationReceiptId: input.mutationReceiptId,
    createdAt: isoOffset(0),
  });
}

test("H-1 the mutation role cannot append a version behind an authorization that was never consumed", async () => {
  // EXECUTED against 34ac77f: this INSERT was ACCEPTED. There was no foreign
  // key on memory_record_versions (pg_constraint contype='f' returned zero
  // rows) and nothing tied a version to a consumed nonce, so the contained
  // role could write history for an authorization that does not exist.
  const genesis = await seedGenesis({ note: "original" });
  const digest = `sha256:${"2".repeat(64)}`;
  await assert.rejects(
    () =>
      asMutator(FORGED_VERSION_SQL, [
        SCOPE.tenantId,
        SCOPE.workspaceId,
        SCOPE.principalId,
        SCOPE.userId,
        RECORD_ID,
        2,
        "active",
        digest,
        genesis,
        "auth-does-not-exist-00000000",
        "mutation.forged",
        versionPayload({
          recordId: RECORD_ID,
          version: 2,
          contentDigest: digest,
          predecessorDigest: genesis,
          authorizationId: "auth-does-not-exist-00000000",
          mutationReceiptId: "mutation.forged",
        }),
      ]),
    /no consumed authorization witnesses this record version/,
  );
  assert.equal(await countVersions(), 1);
});

test("H-1 an authorization that exists but was never SPENT is not a witness either", async () => {
  // The sharper case: the authorization is real and live. What the guard
  // requires is CONSUMPTION, because minting is the issuer's privilege and
  // spending is the mutator's — an unspent approval is not evidence that this
  // particular append was the one it approved.
  const genesis = await seedGenesis({ note: "original" });
  const next = { note: "corrected" };
  const receipt = await issue(
    authorization({
      action: "correct",
      expectedHead: headOf(1, genesis),
      proposedContent: next,
    }),
  );
  const digest = memoryContentDigest(next);
  await assert.rejects(
    () =>
      asMutator(FORGED_VERSION_SQL, [
        SCOPE.tenantId,
        SCOPE.workspaceId,
        SCOPE.principalId,
        SCOPE.userId,
        RECORD_ID,
        2,
        "active",
        digest,
        genesis,
        receipt.authorizationId,
        "mutation.unspent",
        versionPayload({
          recordId: RECORD_ID,
          version: 2,
          contentDigest: digest,
          predecessorDigest: genesis,
          authorizationId: receipt.authorizationId,
          mutationReceiptId: "mutation.unspent",
          content: next,
        }),
      ]),
    /no consumed authorization witnesses this record version/,
  );
  assert.equal(await nonceConsumedAt(receipt.nonce.bindingDigest), null);
  assert.equal(await countVersions(), 1);
});

test("H-1 a consumed authorization witnesses ONE mutation receipt, not any append", async () => {
  // Negative control for the control: the nonce IS consumed, by a different
  // mutation receipt id. Without this the guard could be satisfied by any
  // spent approval in the tenant.
  const genesis = await seedGenesis({ note: "original" });
  await witnessAppend({
    authorizationId: "spent-00000000000000000000001",
    mutationReceiptId: "mutation.something.else",
    recordId: RECORD_ID,
  });
  const digest = `sha256:${"3".repeat(64)}`;
  await assert.rejects(
    () =>
      asMutator(FORGED_VERSION_SQL, [
        SCOPE.tenantId,
        SCOPE.workspaceId,
        SCOPE.principalId,
        SCOPE.userId,
        RECORD_ID,
        2,
        "active",
        digest,
        genesis,
        "spent-00000000000000000000001",
        "mutation.not.the.witnessed.one",
        versionPayload({
          recordId: RECORD_ID,
          version: 2,
          contentDigest: digest,
          predecessorDigest: genesis,
          authorizationId: "spent-00000000000000000000001",
          mutationReceiptId: "mutation.not.the.witnessed.one",
        }),
      ]),
    /no consumed authorization witnesses this record version/,
  );
  assert.equal(await countVersions(), 1);
});

test("H-1 the mutation role cannot mint a terminal COMMITTED_AND_READ_BACK", async () => {
  // EXECUTED against 34ac77f: ACCEPTED, for an authorization that did not
  // exist. `COMMITTED_AND_READ_BACK` is the system's ONLY success signal and
  // the contained role could write it at will.
  await seedGenesis({ note: "original" });
  const forged = {
    schemaVersion: WAVE1_TRUSTED_MEMORY_CONTRACT_VERSION,
    mutationReceiptId: "mutation.forged.receipt",
    authorizationId: "auth-does-not-exist-00000000",
    consumedNonceDigest: `sha256:${"3".repeat(64)}`,
    action: "correct",
    scope: SCOPE,
    targetRecordId: RECORD_ID,
    outcome: { status: "COMMITTED_AND_READ_BACK" },
  };
  await assert.rejects(
    () =>
      asMutator(
        `INSERT INTO memory_mutation_receipts
           (tenant_id, workspace_id, principal_id, user_id, mutation_receipt_id,
            phase, authorization_id, consumed_nonce_digest, action,
            target_record_id, outcome_status, emitted_at, payload)
         VALUES ($1,$2,$3,$4,$5,'terminal',$6,$7,'correct',$8,
                 'COMMITTED_AND_READ_BACK', now(), $9)`,
        [
          SCOPE.tenantId,
          SCOPE.workspaceId,
          SCOPE.principalId,
          SCOPE.userId,
          forged.mutationReceiptId,
          forged.authorizationId,
          forged.consumedNonceDigest,
          RECORD_ID,
          JSON.stringify(forged),
        ],
      ),
    /a committed outcome requires a consumed authorization/,
  );
  assert.deepEqual(await receiptStatuses("mutation.forged.receipt"), []);
});

test("H-1 a committed outcome cannot be claimed without the record version it claims", async () => {
  // The residual half of the forgery: the mutator CAN burn a live approval
  // (that is a denial of service, disclosed) — so a consumed nonce alone must
  // not be enough to mint a success. The record version has to be there too.
  await seedGenesis({ note: "original" });
  await witnessAppend({
    authorizationId: "burned-0000000000000000000001",
    mutationReceiptId: "mutation.burned",
    recordId: RECORD_ID,
  });
  const nonceDigest = memoryContentDigest("burned-0000000000000000000001");
  const forged = {
    schemaVersion: WAVE1_TRUSTED_MEMORY_CONTRACT_VERSION,
    mutationReceiptId: "mutation.burned",
    authorizationId: "burned-0000000000000000000001",
    consumedNonceDigest: nonceDigest,
    action: "correct",
    scope: SCOPE,
    targetRecordId: RECORD_ID,
    outcome: { status: "COMMITTED_AND_READ_BACK" },
  };
  await assert.rejects(
    () =>
      asMutator(
        `INSERT INTO memory_mutation_receipts
           (tenant_id, workspace_id, principal_id, user_id, mutation_receipt_id,
            phase, authorization_id, consumed_nonce_digest, action,
            target_record_id, outcome_status, emitted_at, payload)
         VALUES ($1,$2,$3,$4,$5,'terminal',$6,$7,'correct',$8,
                 'COMMITTED_AND_READ_BACK', now(), $9)`,
        [
          SCOPE.tenantId,
          SCOPE.workspaceId,
          SCOPE.principalId,
          SCOPE.userId,
          forged.mutationReceiptId,
          forged.authorizationId,
          nonceDigest,
          RECORD_ID,
          JSON.stringify(forged),
        ],
      ),
    /a committed outcome requires the record version it claims/,
  );
});

test("H-1 an ABORTED attempt is still recordable, so the guard is not a blanket refusal", async () => {
  // If the outcome guard refused every receipt it would pass the tests above
  // while destroying the abort trail. ABORTED_NO_MUTATION is exactly the row a
  // party that consumed nothing MUST be able to write.
  await seedGenesis({ note: "original" });
  const aborted = {
    schemaVersion: WAVE1_TRUSTED_MEMORY_CONTRACT_VERSION,
    mutationReceiptId: "mutation.abort.direct",
    authorizationId: "auth-does-not-exist-00000000",
    consumedNonceDigest: `sha256:${"4".repeat(64)}`,
    action: "correct",
    scope: SCOPE,
    targetRecordId: RECORD_ID,
    outcome: { status: "ABORTED_NO_MUTATION" },
  };
  await asMutator(
    `INSERT INTO memory_mutation_receipts
       (tenant_id, workspace_id, principal_id, user_id, mutation_receipt_id,
        phase, authorization_id, consumed_nonce_digest, action,
        target_record_id, outcome_status, emitted_at, payload)
     VALUES ($1,$2,$3,$4,$5,'terminal',$6,$7,'correct',$8,
             'ABORTED_NO_MUTATION', now(), $9)`,
    [
      SCOPE.tenantId,
      SCOPE.workspaceId,
      SCOPE.principalId,
      SCOPE.userId,
      aborted.mutationReceiptId,
      aborted.authorizationId,
      aborted.consumedNonceDigest,
      RECORD_ID,
      JSON.stringify(aborted),
    ],
  );
  assert.deepEqual(await receiptStatuses("mutation.abort.direct"), [
    { phase: "terminal", status: "ABORTED_NO_MUTATION" },
  ]);
});

test("H-1 a version that does not succeed the head is refused, even with a real witness", async () => {
  // EXECUTED against 34ac77f: with the chain at v4 the mutator inserted v99
  // and then v5, both ACCEPTED, and because the head query orders by surrogate
  // id the head became v5 carrying the GENESIS predecessor digest. Nothing
  // checked contiguity and nothing checked linkage.
  const genesis = await seedGenesis({ note: "original" });
  await witnessAppend({
    authorizationId: "future-0000000000000000000001",
    mutationReceiptId: "mutation.future",
    recordId: RECORD_ID,
  });
  const digest = `sha256:${"5".repeat(64)}`;
  await assert.rejects(
    () =>
      asMutator(FORGED_VERSION_SQL, [
        SCOPE.tenantId,
        SCOPE.workspaceId,
        SCOPE.principalId,
        SCOPE.userId,
        RECORD_ID,
        99,
        "active",
        digest,
        genesis,
        "future-0000000000000000000001",
        "mutation.future",
        versionPayload({
          recordId: RECORD_ID,
          version: 99,
          contentDigest: digest,
          predecessorDigest: genesis,
          authorizationId: "future-0000000000000000000001",
          mutationReceiptId: "mutation.future",
        }),
      ]),
    /a record version must be exactly one past the head/,
  );
  assert.equal(await countVersions(), 1);
});

test("H-1 a successor that does not link to the head content digest is refused", async () => {
  const genesis = await seedGenesis({ note: "original" });
  assert.notEqual(genesis, `sha256:${"6".repeat(64)}`);
  await witnessAppend({
    authorizationId: "unlinked-000000000000000000001",
    mutationReceiptId: "mutation.unlinked",
    recordId: RECORD_ID,
  });
  const digest = `sha256:${"7".repeat(64)}`;
  await assert.rejects(
    () =>
      asMutator(FORGED_VERSION_SQL, [
        SCOPE.tenantId,
        SCOPE.workspaceId,
        SCOPE.principalId,
        SCOPE.userId,
        RECORD_ID,
        2,
        "active",
        digest,
        `sha256:${"6".repeat(64)}`,
        "unlinked-000000000000000000001",
        "mutation.unlinked",
        versionPayload({
          recordId: RECORD_ID,
          version: 2,
          contentDigest: digest,
          predecessorDigest: `sha256:${"6".repeat(64)}`,
          authorizationId: "unlinked-000000000000000000001",
          mutationReceiptId: "mutation.unlinked",
        }),
      ]),
    /a record version must link to the head content digest/,
  );
  assert.equal(await countVersions(), 1);
});

test("H-1 a chain cannot be started anywhere but version 1", async () => {
  await witnessAppend({
    authorizationId: "nogenesis-00000000000000000001",
    mutationReceiptId: "mutation.nogenesis",
    recordId: "record-nogenesis-001",
  });
  const digest = `sha256:${"8".repeat(64)}`;
  await assert.rejects(
    () =>
      asMutator(FORGED_VERSION_SQL, [
        SCOPE.tenantId,
        SCOPE.workspaceId,
        SCOPE.principalId,
        SCOPE.userId,
        "record-nogenesis-001",
        4,
        "active",
        digest,
        `sha256:${"9".repeat(64)}`,
        "nogenesis-00000000000000000001",
        "mutation.nogenesis",
        versionPayload({
          recordId: "record-nogenesis-001",
          version: 4,
          contentDigest: digest,
          predecessorDigest: `sha256:${"9".repeat(64)}`,
          authorizationId: "nogenesis-00000000000000000001",
          mutationReceiptId: "mutation.nogenesis",
        }),
      ]),
    /a record chain must begin at version 1/,
  );
  assert.equal(await countVersions("record-nogenesis-001"), 0);
});

// ---------------------------------------------------------------------------
// H-2 — cross-principal / cross-user record takeover.
// ---------------------------------------------------------------------------

const VICTIM_SCOPE: MemoryScope = {
  ...SCOPE,
  principalId: "principal-victim",
  userId: "user-victim",
};
const ATTACKER_SCOPE: MemoryScope = {
  ...SCOPE,
  principalId: "principal-attacker",
  userId: "user-attacker",
};
const TAKEOVER_RECORD = "record-victim-001";

test("H-2 an authorization for another principal cannot take over a record", async () => {
  // EXECUTED against 34ac77f: `verified: true`. The four scope comparisons are
  // actor <-> AUTHORIZATION and were never actor <-> TARGET RECORD, the CAS
  // filtered on tenant/workspace/record only, and the read-back compared the
  // observed scope against the AUTHORIZATION — so it CONFIRMED the takeover.
  const genesis = await seedGenesis(
    { secret: "victim data" },
    { scope: VICTIM_SCOPE, recordId: TAKEOVER_RECORD },
  );
  const next = { secret: "overwritten by attacker" };
  const receipt = await issue(
    authorization({
      action: "correct",
      scope: ATTACKER_SCOPE,
      targetRecordId: TAKEOVER_RECORD,
      expectedHead: headOf(1, genesis),
      proposedContent: next,
    }),
  );
  const result = await store().correct({
    actor: ATTACKER_SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: TAKEOVER_RECORD,
    proposedContent: next,
    mutationReceiptId: "mutation.takeover.1",
  });
  assert.equal(result.verified, false);
  assert.equal(result.rejection, "record_owner_mismatch");
  assert.equal(await countVersions(TAKEOVER_RECORD), 1);
  assert.equal(await nonceConsumedAt(receipt.nonce.bindingDigest), null);
});

test("H-2 the same authorization cannot DELETE another principal's record either", async () => {
  const genesis = await seedGenesis(
    { secret: "victim data" },
    { scope: VICTIM_SCOPE, recordId: TAKEOVER_RECORD },
  );
  const next = { secret: "victim data" };
  const receipt = await issue(
    authorization({
      action: "delete",
      scope: ATTACKER_SCOPE,
      targetRecordId: TAKEOVER_RECORD,
      expectedHead: headOf(1, genesis),
      proposedContent: next,
    }),
  );
  const result = await store().delete({
    actor: ATTACKER_SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: TAKEOVER_RECORD,
    proposedContent: next,
    mutationReceiptId: "mutation.takeover.2",
  });
  assert.equal(result.rejection, "record_owner_mismatch");
  assert.equal(await countVersions(TAKEOVER_RECORD), 1);
});

for (const dimension of ["principalId", "userId"] as const) {
  test(`H-2 a record whose ${dimension} is not the actor's is refused on that dimension alone`, async () => {
    // The owner and the actor agree on every dimension EXCEPT this one, so
    // exactly one of the two ownership comparisons can refuse it. Without a
    // test per dimension, deleting one of them is free.
    const owner: MemoryScope = { ...SCOPE, [dimension]: `${SCOPE[dimension]}-owner` };
    const actor: MemoryScope = { ...SCOPE, [dimension]: `${SCOPE[dimension]}-actor` };
    const recordId = `record-owner-${dimension.toLowerCase()}`;
    const genesis = await seedGenesis(
      { secret: "owned" },
      { scope: owner, recordId },
    );
    const next = { secret: "taken" };
    const receipt = await issue(
      authorization({
        action: "correct",
        scope: actor,
        targetRecordId: recordId,
        expectedHead: headOf(1, genesis),
        proposedContent: next,
      }),
    );
    const result = await store().correct({
      actor,
      authorizationId: receipt.authorizationId,
      recordId,
      proposedContent: next,
      mutationReceiptId: `mutation.owner.${dimension.toLowerCase()}`,
    });
    assert.equal(result.verified, false);
    assert.equal(result.rejection, "record_owner_mismatch");
    assert.equal(await countVersions(recordId), 1);
  });
}

test("H-2 the OWNER is still allowed, so the check is ownership and not a blanket refusal", async () => {
  const genesis = await seedGenesis(
    { secret: "victim data" },
    { scope: VICTIM_SCOPE, recordId: TAKEOVER_RECORD },
  );
  const next = { secret: "corrected by the owner" };
  const receipt = await issue(
    authorization({
      action: "correct",
      scope: VICTIM_SCOPE,
      targetRecordId: TAKEOVER_RECORD,
      expectedHead: headOf(1, genesis),
      proposedContent: next,
    }),
  );
  const result = await store().correct({
    actor: VICTIM_SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: TAKEOVER_RECORD,
    proposedContent: next,
    mutationReceiptId: "mutation.takeover.3",
  });
  assert.equal(result.verified, true);
  assert.equal(result.rejection, null);
  assert.equal(await countVersions(TAKEOVER_RECORD), 2);
});

test("H-2 the database refuses a chain that changes principal or user mid-way", async () => {
  // The application half above is in wave1TrustedMemoryStore.mutate(). This is
  // the half that binds a writer which never goes through it.
  const genesis = await seedGenesis(
    { secret: "victim data" },
    { scope: VICTIM_SCOPE, recordId: TAKEOVER_RECORD },
  );
  await witnessAppend({
    authorizationId: "takeover-000000000000000000001",
    mutationReceiptId: "mutation.takeover.db",
    recordId: TAKEOVER_RECORD,
    scope: ATTACKER_SCOPE,
  });
  const digest = `sha256:${"a".repeat(64)}`;
  await assert.rejects(
    () =>
      asMutator(FORGED_VERSION_SQL, [
        ATTACKER_SCOPE.tenantId,
        ATTACKER_SCOPE.workspaceId,
        ATTACKER_SCOPE.principalId,
        ATTACKER_SCOPE.userId,
        TAKEOVER_RECORD,
        2,
        "active",
        digest,
        genesis,
        "takeover-000000000000000000001",
        "mutation.takeover.db",
        versionPayload({
          recordId: TAKEOVER_RECORD,
          version: 2,
          contentDigest: digest,
          predecessorDigest: genesis,
          authorizationId: "takeover-000000000000000000001",
          mutationReceiptId: "mutation.takeover.db",
          scope: ATTACKER_SCOPE,
        }),
      ]),
    /a record chain may not change principal or user/,
  );
  assert.equal(await countVersions(TAKEOVER_RECORD), 1);
});

// ---------------------------------------------------------------------------
// M-5 — readHead is scoped to the actor, all four dimensions.
// ---------------------------------------------------------------------------

test("M-5 readHead does not return another principal's head", async () => {
  // EXECUTED against 34ac77f: an actor from another principal in the same
  // workspace read the record's head INCLUDING the owner's identity.
  await seedGenesis(
    { secret: "victim data" },
    { scope: VICTIM_SCOPE, recordId: TAKEOVER_RECORD },
  );
  assert.equal(await store().readHead(ATTACKER_SCOPE, TAKEOVER_RECORD), null);
  // One assertion per dimension. Dropping EITHER predicate has to fail a
  // named assertion, or one of the two is untested and free to delete.
  assert.equal(
    await store().readHead(
      { ...VICTIM_SCOPE, principalId: "principal-somebody-else" },
      TAKEOVER_RECORD,
    ),
    null,
    "the principal predicate",
  );
  assert.equal(
    await store().readHead(
      { ...VICTIM_SCOPE, userId: "user-somebody-else" },
      TAKEOVER_RECORD,
    ),
    null,
    "the user predicate",
  );
  const owned = await store().readHead(VICTIM_SCOPE, TAKEOVER_RECORD);
  assert.equal(owned?.version, 1);
  assert.equal(owned?.scope.principalId, VICTIM_SCOPE.principalId);
});

// ---------------------------------------------------------------------------
// M-2 — consumption is irreversible and the two sources are really separate.
// ---------------------------------------------------------------------------

test("M-2 a spent nonce cannot be un-spent, by anyone, including the owner", async () => {
  // EXECUTED against 34ac77f as the MUTATOR: consume, un-consume (both columns
  // back to NULL, which satisfies the consumption_witness CHECK), re-consume.
  const genesis = await seedGenesis({ note: "original" });
  const next = { note: "corrected" };
  const receipt = await issue(
    authorization({
      action: "correct",
      expectedHead: headOf(1, genesis),
      proposedContent: next,
    }),
  );
  assert.equal(
    (
      await store().correct({
        actor: SCOPE,
        authorizationId: receipt.authorizationId,
        recordId: RECORD_ID,
        proposedContent: next,
        mutationReceiptId: "mutation.monotonic.1",
      })
    ).verified,
    true,
  );
  await assert.rejects(
    () =>
      asMutator(
        `UPDATE memory_authorization_nonces
            SET consumed_at = NULL, consumed_by_mutation_receipt_id = NULL
          WHERE binding_digest = $1`,
        [receipt.nonce.bindingDigest],
      ),
    /consumption is irreversible on memory_authorization_nonces/,
  );
  await assert.rejects(
    () =>
      adminPool.query(
        `UPDATE memory_authorization_nonces SET consumed_at = now()
          WHERE binding_digest = $1`,
        [receipt.nonce.bindingDigest],
      ),
    /consumption is irreversible on memory_authorization_nonces/,
  );
  await assert.rejects(
    () =>
      asMutator(
        `UPDATE memory_authorization_nonces
            SET consumed_by_mutation_receipt_id = 'mutation.somebody.else'
          WHERE binding_digest = $1`,
        [receipt.nonce.bindingDigest],
      ),
    /a consumption witness is irreversible on memory_authorization_nonces/,
  );
  assert.notEqual(await nonceConsumedAt(receipt.nonce.bindingDigest), null);
});

test("M-2 the mutation role no longer holds the receipt's consumption column", async () => {
  // 029 granted UPDATE(consumed_at) on BOTH the nonce and the receipt to one
  // role, which is why "the sources are under different privileges" was false.
  const genesis = await seedGenesis({ note: "original" });
  const receipt = await issue(
    authorization({
      action: "correct",
      expectedHead: headOf(1, genesis),
      proposedContent: { note: "corrected" },
    }),
  );
  await assert.rejects(
    () =>
      asMutator(
        `UPDATE memory_authorization_receipts SET consumed_at = now()
          WHERE authorization_id = $1`,
        [receipt.authorizationId],
      ),
    /permission denied for table memory_authorization_receipts/,
  );
});

test("M-2 the database mirrors consumption onto the receipt, so the two sources agree", async () => {
  const genesis = await seedGenesis({ note: "original" });
  const next = { note: "corrected" };
  const receipt = await issue(
    authorization({
      action: "correct",
      expectedHead: headOf(1, genesis),
      proposedContent: next,
    }),
  );
  assert.equal(
    (
      await store().correct({
        actor: SCOPE,
        authorizationId: receipt.authorizationId,
        recordId: RECORD_ID,
        proposedContent: next,
        mutationReceiptId: "mutation.mirror.1",
      })
    ).verified,
    true,
  );
  const stored = await adminPool.query(
    `SELECT consumed_at FROM memory_authorization_receipts
      WHERE authorization_id = $1`,
    [receipt.authorizationId],
  );
  assert.notEqual(stored.rows[0].consumed_at, null);
  assert.equal(
    (stored.rows[0].consumed_at as Date).getTime(),
    (await nonceConsumedAt(receipt.nonce.bindingDigest))?.getTime(),
  );
});

// ---------------------------------------------------------------------------
// M-1 — the numeric-domain trigger resolves its own helper.
// ---------------------------------------------------------------------------

test("M-1 shadowing the helper in the caller's search_path does not defeat the numeric domain", async () => {
  // EXECUTED against 34ac77f: a non-superuser with CREATE on a schema of its
  // own declared a stub named `aaliyah_memory_jsonb_numbers`, put that schema
  // first on its search_path, and stored 0.1000000000000000000001 — the exact
  // W1BR-006 value. The trigger function called the helper UNQUALIFIED, was
  // not SECURITY DEFINER and pinned no search_path.
  const role = "atk_shadow_role";
  const schema = "atk_shadow_schema";
  // Roles are CLUSTER objects, so this has to be idempotent in both
  // directions: `DROP ROLE` fails while any grant still names the role, and a
  // run that died between the grant and the drop would otherwise poison every
  // later run in this database. `DROP OWNED BY` removes the owned objects AND
  // the privileges in one statement.
  const dropRole = async () => {
    await adminPool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await adminPool.query(
      `DO $do$
       BEGIN
         IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${role}') THEN
           DROP OWNED BY ${role};
           DROP ROLE ${role};
         END IF;
       END
       $do$`,
    );
  };
  await dropRole();
  await adminPool.query(`CREATE ROLE ${role} NOLOGIN`);
  try {
    await adminPool.query(`CREATE SCHEMA ${schema} AUTHORIZATION ${role}`);
    await adminPool.query(
      `GRANT INSERT, SELECT ON memory_record_versions TO ${role}`,
    );
    await adminPool.query(
      `GRANT USAGE, SELECT ON SEQUENCE memory_record_versions_id_seq TO ${role}`,
    );
    const client = await adminPool.connect();
    try {
      await client.query("BEGIN");
      await client.query(`SET LOCAL ROLE "${role}"`);
      await client.query(
        `CREATE FUNCTION ${schema}.aaliyah_memory_jsonb_numbers(doc jsonb)
           RETURNS SETOF text LANGUAGE sql IMMUTABLE
           AS $fn$ SELECT NULL::text WHERE false $fn$`,
      );
      await client.query(`SET LOCAL search_path = ${schema}, public`);
      const digest = `sha256:${"b".repeat(64)}`;
      const payload = [
        `{"schemaVersion":"${MEMORY_RECORD_VERSION_SCHEMA_VERSION}"`,
        `"recordId":"record-shadow-001"`,
        `"version":1`,
        `"state":"active"`,
        `"scope":${JSON.stringify(SCOPE)}`,
        `"content":{"balance":0.1000000000000000000001}`,
        `"contentDigest":"${digest}"`,
        `"predecessorDigest":null`,
        `"authorizationId":"shadow-0000000000000000000001"`,
        `"mutationReceiptId":"mutation.shadow"`,
        `"createdAt":"${isoOffset(0)}"}`,
      ].join(",");
      await assert.rejects(
        () =>
          client.query(
            `INSERT INTO memory_record_versions
               (tenant_id, workspace_id, principal_id, user_id, record_id,
                version, state, content_digest, predecessor_digest,
                authorization_id, mutation_receipt_id, payload)
             VALUES ($1,$2,$3,$4,'record-shadow-001',1,'active',$5,NULL,
                     'shadow-0000000000000000000001','mutation.shadow',
                     $6::jsonb)`,
            [
              SCOPE.tenantId,
              SCOPE.workspaceId,
              SCOPE.principalId,
              SCOPE.userId,
              digest,
              payload,
            ],
          ),
        /outside the exact numeric domain/,
      );
    } finally {
      // ROLLBACK in a finally, or a failed assertion hands a connection back
      // to the pool with a transaction still open on it.
      await client.query("ROLLBACK").catch(() => undefined);
      client.release();
    }
    assert.equal(await countVersions("record-shadow-001"), 0);
  } finally {
    await dropRole();
  }
});

// ---------------------------------------------------------------------------
// M-4 — a rejection may name the class and never the record.
// ---------------------------------------------------------------------------

test("M-4 the numeric rejection does not carry the offending value", async () => {
  // EXECUTED against 34ac77f through the store's own production path with
  // {patientSsnLastFour: 6789, coPayAmount: 4211.37}: the PostgreSQL server log
  // recorded "jsonb number 4211.37 is outside the exact numeric domain". 731
  // such lines already existed in that container's log.
  const genesis = await seedGenesis({ note: "original" });
  const secret = { patientSsnLastFour: 6789, coPayAmount: 4211.37 };
  const receipt = await issue(
    authorization({
      action: "correct",
      expectedHead: headOf(1, genesis),
      proposedContent: secret,
    }),
  );
  const result = await store().correct({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: secret,
    mutationReceiptId: "mutation.leak.1",
  });
  assert.equal(result.rejection, "storage_rejected");

  // And directly, so the MESSAGE itself is the thing under assertion.
  await witnessAppend({
    authorizationId: "leak-000000000000000000000001",
    mutationReceiptId: "mutation.leak.direct",
    recordId: "record-leak-001",
  });
  const digest = `sha256:${"c".repeat(64)}`;
  await assert.rejects(
    () =>
      adminPool.query(
        `INSERT INTO memory_record_versions
           (tenant_id, workspace_id, principal_id, user_id, record_id, version,
            state, content_digest, predecessor_digest, authorization_id,
            mutation_receipt_id, payload)
         VALUES ($1,$2,$3,$4,'record-leak-001',1,'active',$5,NULL,
                 'leak-000000000000000000000001','mutation.leak.direct',
                 $6::jsonb)`,
        [
          SCOPE.tenantId,
          SCOPE.workspaceId,
          SCOPE.principalId,
          SCOPE.userId,
          digest,
          [
            `{"schemaVersion":"${MEMORY_RECORD_VERSION_SCHEMA_VERSION}"`,
            `"recordId":"record-leak-001"`,
            `"version":1`,
            `"state":"active"`,
            `"scope":${JSON.stringify(SCOPE)}`,
            `"content":{"coPayAmount":4211.37}`,
            `"contentDigest":"${digest}"`,
            `"predecessorDigest":null`,
            `"authorizationId":"leak-000000000000000000000001"`,
            `"mutationReceiptId":"mutation.leak.direct"`,
            `"createdAt":"${isoOffset(0)}"}`,
          ].join(","),
        ],
      ),
    (error: unknown) => {
      const message = (error as Error).message;
      assert.match(message, /outside the exact numeric domain/);
      assert.doesNotMatch(
        message,
        /4211\.37/,
        "the rejection must name the class, never the record",
      );
      return true;
    },
  );
});

// ---------------------------------------------------------------------------
// M-3 — a concurrent append is not a storage divergence.
// ---------------------------------------------------------------------------

test("M-3 an append landing between COMMIT and read-back is not reported as divergence", async () => {
  // EXECUTED against 34ac77f, deterministically: `pg_advisory_xact_lock`
  // releases at COMMIT, the read-back runs afterwards on another pool taking
  // ORDER BY id DESC LIMIT 1, and the digest comparison came BEFORE the
  // post-state comparison — so a correct, committed mutation was durably
  // recorded as COMMITTED_READ_BACK_DIVERGED, the strongest alarm in the
  // system, for a healthy write.
  const genesis = await seedGenesis({ n: 0 });
  const next = { n: 1 };
  const receipt = await issue(
    authorization({
      action: "correct",
      expectedHead: headOf(1, genesis),
      proposedContent: next,
    }),
  );
  // One connection, occupied, so the read-back is forced to queue behind the
  // concurrent append instead of racing it.
  const singleReadBack = new Pool({ connectionString: DB_URL, max: 1 });
  const held = await singleReadBack.connect();
  try {
    const pending = createPostgresTrustedMemoryStore(
      writePool,
      singleReadBack,
    ).correct({
      actor: SCOPE,
      authorizationId: receipt.authorizationId,
      recordId: RECORD_ID,
      proposedContent: next,
      mutationReceiptId: "mutation.concurrent.1",
    });
    for (let attempt = 0; attempt < 2000; attempt += 1) {
      if ((await countVersions()) >= 2) break;
      await new Promise((resolve) => setTimeout(resolve, 2));
    }
    assert.equal(await countVersions(), 2);
    const head2 = await adminPool.query(
      `SELECT content_digest FROM memory_record_versions
        WHERE record_id = $1 AND version = 2`,
      [RECORD_ID],
    );
    // A LEGITIMATE third version, witnessed like any other append.
    await witnessAppend({
      authorizationId: "concurrent-00000000000000000001",
      mutationReceiptId: "mutation.concurrent.interleaved",
      recordId: RECORD_ID,
    });
    const thirdDigest = memoryContentDigest({ n: 2 });
    await adminPool.query(
      `INSERT INTO memory_record_versions
         (tenant_id, workspace_id, principal_id, user_id, record_id, version,
          state, content_digest, predecessor_digest, authorization_id,
          mutation_receipt_id, payload)
       VALUES ($1,$2,$3,$4,$5,3,'active',$6,$7,$8,$9,$10)`,
      [
        SCOPE.tenantId,
        SCOPE.workspaceId,
        SCOPE.principalId,
        SCOPE.userId,
        RECORD_ID,
        thirdDigest,
        head2.rows[0].content_digest,
        "concurrent-00000000000000000001",
        "mutation.concurrent.interleaved",
        versionPayload({
          recordId: RECORD_ID,
          version: 3,
          contentDigest: thirdDigest,
          predecessorDigest: head2.rows[0].content_digest,
          authorizationId: "concurrent-00000000000000000001",
          mutationReceiptId: "mutation.concurrent.interleaved",
          content: { n: 2 },
        }),
      ],
    );
    held.release();
    const result = await pending;
    assert.equal(result.verified, false);
    assert.notEqual(
      result.rejection,
      "read_back_diverged",
      "a healthy write must never be filed as a storage divergence",
    );
    assert.equal(result.rejection, "unknown_outcome");
    assert.equal(
      result.receipt?.outcome.status,
      "UNKNOWN_PENDING_RECONCILIATION",
    );
    assert.deepEqual(await receiptStatuses("mutation.concurrent.1"), [
      { phase: "pending", status: "UNKNOWN_PENDING_RECONCILIATION" },
      { phase: "terminal", status: "UNKNOWN_PENDING_RECONCILIATION" },
    ]);
  } finally {
    await singleReadBack.end();
  }
});

// ---------------------------------------------------------------------------
// L-1 — the attempt that used to leave no trace.
// ---------------------------------------------------------------------------

test("L-1 an unknown authorization id leaves a durable, attributable attempt", async () => {
  // EXECUTED against 34ac77f: `authorization_not_found` wrote ZERO rows to
  // memory_mutation_receipts. Cross-tenant attempts WERE logged; guessing at
  // ids — the highest-volume attack against an id-only lookup — was not.
  await seedGenesis({ note: "original" });
  const result = await store().correct({
    actor: SCOPE,
    authorizationId: nextAuthorizationId(),
    recordId: RECORD_ID,
    proposedContent: { note: "x" },
    mutationReceiptId: "mutation.enumerate.1",
  });
  assert.equal(result.rejection, "authorization_not_found");
  // The CALLER still gets nothing to hide behind.
  assert.equal(result.receipt, null);
  assert.deepEqual(await receiptStatuses("mutation.enumerate.1"), [
    { phase: "terminal", status: "ABORTED_NO_MUTATION" },
  ]);
  const row = await adminPool.query(
    `SELECT tenant_id, principal_id, user_id, consumed_nonce_digest,
            payload->'outcome'->>'abortReason' AS abort_reason
       FROM memory_mutation_receipts
      WHERE mutation_receipt_id = 'mutation.enumerate.1'`,
  );
  // Filed under the ACTOR, never under the scope it was reaching for, and
  // marked unresolved by a digest no nonce can carry.
  assert.equal(row.rows[0].tenant_id, SCOPE.tenantId);
  assert.equal(row.rows[0].principal_id, SCOPE.principalId);
  assert.equal(row.rows[0].user_id, SCOPE.userId);
  assert.equal(row.rows[0].consumed_nonce_digest, `sha256:${"0".repeat(64)}`);
  assert.equal(row.rows[0].abort_reason, "policy_rejected");
  assert.equal(await countVersions(), 1);
});

test("L-1 a malformed authorization id is refused before it reaches the database", async () => {
  const result = await store().correct({
    actor: SCOPE,
    authorizationId: "SENSITIVE: not an id",
    recordId: RECORD_ID,
    proposedContent: {},
    mutationReceiptId: "mutation.enumerate.2",
  });
  assert.equal(result.rejection, "request_malformed");
  assert.equal(result.receipt, null);
  assert.deepEqual(await receiptStatuses("mutation.enumerate.2"), []);
});
