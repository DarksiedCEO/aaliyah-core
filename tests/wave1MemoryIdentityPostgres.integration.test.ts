import assert from "node:assert/strict";
import test, { after, before, beforeEach } from "node:test";
import { Pool } from "pg";

import {
  MEMORY_AUTHORIZATION_NONCE_SCHEMA_VERSION,
  MemoryAuthorizationReceiptSchema,
  WAVE1_TRUSTED_MEMORY_CONTRACT_VERSION,
  memoryAuthorizationNonce,
  type MemoryAction,
  type MemoryAuthorizationReceipt,
  type MemoryExpectedHead,
  type MemoryScope,
} from "@aaliyah/contracts/v1";

import {
  MEMORY_IDENTITY_MERGE_ORDER_SCHEMA_VERSION,
  MEMORY_IDENTITY_SPLIT_ORDER_SCHEMA_VERSION,
} from "../src/application/memory/wave1MemoryIdentity";
import { MEMORY_DELETION_ORDER_SCHEMA_VERSION } from "../src/application/memory/wave1MemoryErasure";
import { memoryContentDigest } from "../src/application/memory/wave1TrustedMemory";
import { runMailMigrations } from "../src/persistence/postgres/migrations";
import { createPostgresTrustedMemoryStore } from "../src/persistence/postgres/wave1TrustedMemoryStore";
import { createPostgresIdentityGraph } from "../src/persistence/postgres/wave1IdentityGraphStore";
import {
  MEMORY_CANONICAL_RESOLUTION_MAX_DEPTH,
  createWave1MemoryService,
} from "../src/application/memory/wave1MemoryService";
import {
  lockSharedMemoryTables,
  type SharedTableLock,
} from "./support/sharedMemoryTables";
import { assertCheckConstraintsKill, assertUniqueIndexKills } from "./support/uniquenessDestroyer";

/**
 * IDENTITY MERGE AND SPLIT, AGAINST A REAL DATABASE.
 *
 * The design constraint these prove out: one authorization produces exactly
 * ONE record version, so neither operation can write to both records. Each
 * appends one version to the record its authorization targets and writes one
 * append-only identity edge, in the same transaction.
 *
 * Every refusal below pins its exact reason. A bare "it failed" would pass
 * against a store that refused every merge, which is the shape a broken one
 * takes.
 */

const DB_URL =
  process.env.AALIYAH_TEST_DATABASE_URL ??
  "postgres://postgres:test@127.0.0.1:54329/aaliyah_test";

const SCOPE: MemoryScope = {
  tenantId: "tenant-identity",
  workspaceId: "workspace-identity",
  principalId: "principal-identity",
  userId: "user-identity",
};

const ALICE = "record-identity-alice";
const ALIAS_OF_ALICE = "record-identity-alice-dup";
const EVIDENCE_DIGEST = `sha256:${"b".repeat(64)}`;

let adminPool: Pool;
let writePool: Pool;
let readPool: Pool;
let sharedTableLock: SharedTableLock;
let authCounter = 0;

before(async () => {
  adminPool = new Pool({ connectionString: DB_URL, max: 8 });
  sharedTableLock = await lockSharedMemoryTables(adminPool);
  await runMailMigrations(adminPool);
  writePool = new Pool({ connectionString: DB_URL, max: 8 });
  readPool = new Pool({ connectionString: DB_URL, max: 4 });
});

after(async () => {
  await readPool.end();
  await writePool.end();
  await sharedTableLock.release();
  await adminPool.end();
});

beforeEach(async () => {
  await adminPool.query(
    `TRUNCATE memory_identity_edges,
              memory_record_versions,
              memory_authorization_receipts,
              memory_authorization_nonces,
              memory_mutation_receipts,
              memory_mutation_attempts,
              memory_tombstones,
              memory_legal_hold_carve_outs,
              memory_legal_hold_records,
              memory_legal_hold_subjects,
              memory_legal_holds
     RESTART IDENTITY`,
  );
  authCounter = 0;
});

function store() {
  return createPostgresTrustedMemoryStore(writePool, readPool);
}

function isoOffset(ms: number): string {
  return new Date(Date.now() + ms).toISOString();
}

function authorization(input: {
  action: MemoryAction;
  targetRecordId: string;
  expectedHead: MemoryExpectedHead;
  proposedContent: unknown;
  scope?: MemoryScope;
}): MemoryAuthorizationReceipt {
  const scope = input.scope ?? SCOPE;
  authCounter += 1;
  const authorizationId = `identity-auth-${String(authCounter).padStart(14, "0")}`;
  const proposedContentDigest = memoryContentDigest(input.proposedContent);
  const bindingDigest = memoryAuthorizationNonce({
    bindingSchemaVersion: MEMORY_AUTHORIZATION_NONCE_SCHEMA_VERSION,
    authorizationId,
    action: input.action,
    scope,
    targetRecordId: input.targetRecordId,
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
    targetRecordId: input.targetRecordId,
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

async function runAs(role: string, sql: string, params: unknown[] = []) {
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
        receipt.expiresAt,
        receipt.revokedAt,
        receipt.consumedAt,
        JSON.stringify(receipt),
      ],
    );
    await client.query(
      `INSERT INTO memory_authorization_nonces
         (tenant_id, workspace_id, binding_digest, authorization_id, action,
          target_record_id, issued_at, expires_at, revoked_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [
        receipt.scope.tenantId,
        receipt.scope.workspaceId,
        receipt.nonce.bindingDigest,
        receipt.authorizationId,
        receipt.action,
        receipt.targetRecordId,
        receipt.issuedAt,
        receipt.expiresAt,
        receipt.revokedAt,
      ],
    );
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
  return receipt;
}

/** Bring a record into existence through the real `create` protocol. */
async function createRecord(
  recordId: string,
  content: unknown,
  scope: MemoryScope = SCOPE,
): Promise<string> {
  const receipt = await issue(
    authorization({
      action: "create",
      targetRecordId: recordId,
      expectedHead: { kind: "no_prior_version" },
      proposedContent: content,
      scope,
    }),
  );
  const result = await store().create({
    actor: scope,
    authorizationId: receipt.authorizationId,
    recordId,
    proposedContent: content,
    mutationReceiptId: `mutation.create.${recordId}`,
  });
  assert.equal(result.rejection, null);
  assert.equal(result.verified, true);
  return memoryContentDigest(content);
}

/**
 * Issue an authorization and SPEND its nonce, without going through the store.
 *
 * A raw write needs a real witness, or migration 034's guard refuses it first
 * and whatever control the test is actually aiming at is never reached. Two of
 * these tests passed for exactly that wrong reason until a mutation sweep of
 * the triggers showed the trigger could be dropped with nothing going red.
 */
async function spendAuthorization(input: {
  action: MemoryAction;
  targetRecordId: string;
  expectedHead: MemoryExpectedHead;
  proposedContent: unknown;
  mutationReceiptId: string;
}): Promise<string> {
  const receipt = await issue(
    authorization({
      action: input.action,
      targetRecordId: input.targetRecordId,
      expectedHead: input.expectedHead,
      proposedContent: input.proposedContent,
    }),
  );
  await runAs(
    "aaliyah_memory_mutator",
    `UPDATE memory_authorization_nonces
        SET consumed_at = now(), consumed_by_mutation_receipt_id = $2
      WHERE binding_digest = $1 AND consumed_at IS NULL`,
    [receipt.nonce.bindingDigest, input.mutationReceiptId],
  );
  return receipt.authorizationId;
}

function mergeOrder(survivorRecordId: string, reason = "duplicate_participant") {
  return {
    schemaVersion: MEMORY_IDENTITY_MERGE_ORDER_SCHEMA_VERSION,
    reason,
    reasonEvidenceRef: "matter:identity-merge/0001",
    survivorRecordId,
  };
}

function splitOrder(splitRecordId: string) {
  return {
    schemaVersion: MEMORY_IDENTITY_SPLIT_ORDER_SCHEMA_VERSION,
    reason: "conflated_participants",
    reasonEvidenceRef: "matter:identity-split/0001",
    splitRecordId,
  };
}

async function edgesFor(fromRecordId: string) {
  const result = await adminPool.query(
    `SELECT kind, from_record_id, to_record_id, from_version, authorization_id,
            mutation_receipt_id, reason, reason_evidence_ref
       FROM memory_identity_edges
      WHERE from_record_id = $1
      ORDER BY id`,
    [fromRecordId],
  );
  return result.rows;
}

async function countVersions(recordId: string): Promise<number> {
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

/** Spend a merge/split authorization through the store. */
async function runIdentity(input: {
  action: "merge_identity" | "split_identity";
  targetRecordId: string;
  headVersion: number;
  headDigest: string;
  order: unknown;
  mutationReceiptId: string;
}) {
  const receipt = await issue(
    authorization({
      action: input.action,
      targetRecordId: input.targetRecordId,
      expectedHead: {
        kind: "version",
        version: input.headVersion,
        contentDigest: input.headDigest,
      },
      proposedContent: input.order,
    }),
  );
  const call =
    input.action === "merge_identity"
      ? store().mergeIdentity
      : store().splitIdentity;
  const result = await call({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: input.targetRecordId,
    proposedContent: input.order,
    mutationReceiptId: input.mutationReceiptId,
  });
  return { receipt, result };
}

// ---------------------------------------------------------------------------
// merge_identity
// ---------------------------------------------------------------------------

test("a merge appends one version to the ABSORBED record, writes one edge, and leaves the survivor alone", async () => {
  const survivor = await createRecord(ALICE, { name: "Alice", source: "crm" });
  const absorbed = await createRecord(ALIAS_OF_ALICE, { name: "A. Smith" });

  const { result } = await runIdentity({
    action: "merge_identity",
    targetRecordId: ALIAS_OF_ALICE,
    headVersion: 1,
    headDigest: absorbed,
    order: mergeOrder(ALICE),
    mutationReceiptId: "mutation.merge.001",
  });

  assert.equal(result.rejection, null);
  assert.equal(result.verified, true);

  // ONE version on the absorbed record ...
  assert.equal(await countVersions(ALIAS_OF_ALICE), 2);
  // ... and NONE on the survivor. One authorization, one record version.
  assert.equal(await countVersions(ALICE), 1);
  const survivorHead = await store().readHead(SCOPE, ALICE);
  assert.equal(survivorHead?.version, 1);
  assert.equal(survivorHead?.contentDigest, survivor);

  const edges = await edgesFor(ALIAS_OF_ALICE);
  assert.equal(edges.length, 1);
  assert.equal(edges[0].kind, "merged_into");
  assert.equal(edges[0].to_record_id, ALICE);
  assert.equal(edges[0].from_version, 2);
  assert.equal(edges[0].reason, "duplicate_participant");
  assert.equal(edges[0].mutation_receipt_id, "mutation.merge.001");
});

test("a merged-away record is FROZEN: no further version, and its history survives", async () => {
  await createRecord(ALICE, { name: "Alice" });
  const absorbed = await createRecord(ALIAS_OF_ALICE, { name: "A. Smith" });
  await runIdentity({
    action: "merge_identity",
    targetRecordId: ALIAS_OF_ALICE,
    headVersion: 1,
    headDigest: absorbed,
    order: mergeOrder(ALICE),
    mutationReceiptId: "mutation.merge.frozen",
  });

  const head = await store().readHead(SCOPE, ALIAS_OF_ALICE);
  const next = { name: "A. Smith", note: "edited after the merge" };
  const receipt = await issue(
    authorization({
      action: "correct",
      targetRecordId: ALIAS_OF_ALICE,
      expectedHead: {
        kind: "version",
        version: 2,
        contentDigest: head!.contentDigest,
      },
      proposedContent: next,
    }),
  );
  const result = await store().correct({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: ALIAS_OF_ALICE,
    proposedContent: next,
    mutationReceiptId: "mutation.merge.afteredit",
  });

  assert.equal(result.verified, false);
  assert.equal(result.rejection, "record_merged_away");
  // Refused BEFORE consumption, so the approval is not burned.
  assert.equal(await nonceConsumedAt(receipt.nonce.bindingDigest), null);
  // The record is frozen, NOT destroyed. A merge is not a quiet deletion.
  assert.equal(await countVersions(ALIAS_OF_ALICE), 2);
  assert.equal((await store().retrieve(SCOPE, ALIAS_OF_ALICE))?.version, 2);
});

test("the DATABASE refuses a version on a merged-away record, for writers that never come through the store", async () => {
  await createRecord(ALICE, { name: "Alice" });
  const absorbed = await createRecord(ALIAS_OF_ALICE, { name: "A. Smith" });
  await runIdentity({
    action: "merge_identity",
    targetRecordId: ALIAS_OF_ALICE,
    headVersion: 1,
    headDigest: absorbed,
    order: mergeOrder(ALICE),
    mutationReceiptId: "mutation.merge.dbfreeze",
  });
  const frozenHead = await store().readHead(SCOPE, ALIAS_OF_ALICE);
  const next = { name: "A. Smith", note: "raw edit" };
  // A REAL witness, so migration 034's guard is satisfied and the freeze is
  // the only control left that can refuse this.
  const authorizationId = await spendAuthorization({
    action: "correct",
    targetRecordId: ALIAS_OF_ALICE,
    expectedHead: {
      kind: "version",
      version: 2,
      contentDigest: frozenHead!.contentDigest,
    },
    proposedContent: next,
    mutationReceiptId: "mutation.raw.frozen",
  });

  await assert.rejects(
    () =>
      runAs(
        "aaliyah_memory_mutator",
        `INSERT INTO memory_record_versions
           (tenant_id, workspace_id, principal_id, user_id, record_id, version,
            state, content_digest, predecessor_digest, authorization_id,
            mutation_receipt_id, payload)
         VALUES ($1::text,$2::text,$3::text,$4::text,$5::text,3,'active',
                 $6::text,$7::text,$8::text,'mutation.raw.frozen',
                 jsonb_build_object(
                   'recordId',$5::text,'version','3','state','active',
                   'contentDigest',$6::text,'predecessorDigest',$7::text,
                   'authorizationId',$8::text,
                   'mutationReceiptId','mutation.raw.frozen',
                   'scope', jsonb_build_object('tenantId',$1::text,
                                               'workspaceId',$2::text,
                                               'principalId',$3::text,
                                               'userId',$4::text)))`,
        [
          SCOPE.tenantId,
          SCOPE.workspaceId,
          SCOPE.principalId,
          SCOPE.userId,
          ALIAS_OF_ALICE,
          memoryContentDigest(next),
          frozenHead!.contentDigest,
          authorizationId,
        ],
      ),
    // PINNED to the freeze alone. This assertion previously also accepted the
    // witness guard's message, so dropping the freeze trigger changed nothing
    // and the test still passed.
    /merged into another accepts no further versions/,
  );
  assert.equal(await countVersions(ALIAS_OF_ALICE), 2);
});

test("the DATABASE refuses a SECOND merge edge for one record, even with a valid witness", async () => {
  // The app-level freeze refuses this before the index is reached, so the
  // unique index had no test at all until the sweep said so. This goes around
  // the store entirely.
  await createRecord(ALICE, { name: "Alice" });
  await createRecord("record-identity-third", { name: "Third" });
  const absorbed = await createRecord(ALIAS_OF_ALICE, { name: "A. Smith" });
  await runIdentity({
    action: "merge_identity",
    targetRecordId: ALIAS_OF_ALICE,
    headVersion: 1,
    headDigest: absorbed,
    order: mergeOrder(ALICE),
    mutationReceiptId: "mutation.merge.first",
  });
  const head = await store().readHead(SCOPE, ALIAS_OF_ALICE);
  const authorizationId = await spendAuthorization({
    action: "merge_identity",
    targetRecordId: ALIAS_OF_ALICE,
    expectedHead: {
      kind: "version",
      version: 2,
      contentDigest: head!.contentDigest,
    },
    proposedContent: mergeOrder("record-identity-third"),
    mutationReceiptId: "mutation.merge.rawsecond",
  });

  await assert.rejects(
    () =>
      runAs(
        "aaliyah_memory_mutator",
        `INSERT INTO memory_identity_edges
           (tenant_id, workspace_id, principal_id, user_id, kind,
            from_record_id, to_record_id, from_version, authorization_id,
            mutation_receipt_id, reason, reason_evidence_ref, effective_at,
            payload)
         VALUES ($1::text,$2::text,$3::text,$4::text,'merged_into',
                 $5::text,$6::text,3,$7::text,'mutation.merge.rawsecond',
                 'duplicate_participant','matter:identity-merge/0002', now(),
                 jsonb_build_object('kind','merged_into',
                   'fromRecordId',$5::text,'toRecordId',$6::text,
                   'authorizationId',$7::text))`,
        [
          SCOPE.tenantId,
          SCOPE.workspaceId,
          SCOPE.principalId,
          SCOPE.userId,
          ALIAS_OF_ALICE,
          "record-identity-third",
          authorizationId,
        ],
      ),
    /memory_identity_edges_merged_once/,
  );
  assert.equal((await edgesFor(ALIAS_OF_ALICE)).length, 1);
});

test("a record can be merged away at most once", async () => {
  await createRecord(ALICE, { name: "Alice" });
  const third = await createRecord("record-identity-third", { name: "Third" });
  const absorbed = await createRecord(ALIAS_OF_ALICE, { name: "A. Smith" });
  await runIdentity({
    action: "merge_identity",
    targetRecordId: ALIAS_OF_ALICE,
    headVersion: 1,
    headDigest: absorbed,
    order: mergeOrder(ALICE),
    mutationReceiptId: "mutation.merge.once",
  });
  assert.equal(third.length > 0, true);

  const head = await store().readHead(SCOPE, ALIAS_OF_ALICE);
  const { result } = await runIdentity({
    action: "merge_identity",
    targetRecordId: ALIAS_OF_ALICE,
    headVersion: 2,
    headDigest: head!.contentDigest,
    order: mergeOrder("record-identity-third"),
    mutationReceiptId: "mutation.merge.twice",
  });

  // Refused by the freeze before it ever reaches the unique index — an
  // identity pointing two ways at once is a graph nobody can read.
  assert.equal(result.verified, false);
  assert.equal(result.rejection, "record_merged_away");
  assert.equal((await edgesFor(ALIAS_OF_ALICE)).length, 1);
});

test("a merge naming ITSELF is refused", async () => {
  const absorbed = await createRecord(ALIAS_OF_ALICE, { name: "A. Smith" });

  const { result } = await runIdentity({
    action: "merge_identity",
    targetRecordId: ALIAS_OF_ALICE,
    headVersion: 1,
    headDigest: absorbed,
    order: mergeOrder(ALIAS_OF_ALICE),
    mutationReceiptId: "mutation.merge.self",
  });

  // A self-edge would freeze the record against every future mutation while
  // reading as a legitimate graph entry.
  assert.equal(result.verified, false);
  assert.equal(result.rejection, "identity_counterparty_invalid");
  assert.equal(await countVersions(ALIAS_OF_ALICE), 1);
  assert.equal((await edgesFor(ALIAS_OF_ALICE)).length, 0);
});

test("a merge naming a record that does not exist is refused", async () => {
  const absorbed = await createRecord(ALIAS_OF_ALICE, { name: "A. Smith" });

  const { result } = await runIdentity({
    action: "merge_identity",
    targetRecordId: ALIAS_OF_ALICE,
    headVersion: 1,
    headDigest: absorbed,
    order: mergeOrder("record-identity-nobody"),
    mutationReceiptId: "mutation.merge.missing",
  });

  assert.equal(result.verified, false);
  assert.equal(result.rejection, "identity_counterparty_missing");
  assert.equal(await countVersions(ALIAS_OF_ALICE), 1);
});

test("a merge cannot reach into ANOTHER PRINCIPAL's record", async () => {
  const foreign: MemoryScope = { ...SCOPE, principalId: "principal-other" };
  await createRecord("record-identity-foreign", { name: "Someone else" }, foreign);
  const absorbed = await createRecord(ALIAS_OF_ALICE, { name: "A. Smith" });

  const { result } = await runIdentity({
    action: "merge_identity",
    targetRecordId: ALIAS_OF_ALICE,
    headVersion: 1,
    headDigest: absorbed,
    order: mergeOrder("record-identity-foreign"),
    mutationReceiptId: "mutation.merge.foreign",
  });

  // The record exists — just not for this actor. A graph-level version of the
  // takeover migration 039 closed for genesis.
  assert.equal(result.verified, false);
  assert.equal(result.rejection, "identity_counterparty_missing");
  assert.equal((await edgesFor(ALIAS_OF_ALICE)).length, 0);
});

test("a merge whose authorized content is not an identity order is refused, and the token is not burned", async () => {
  await createRecord(ALICE, { name: "Alice" });
  const absorbed = await createRecord(ALIAS_OF_ALICE, { name: "A. Smith" });

  const { receipt, result } = await runIdentity({
    action: "merge_identity",
    targetRecordId: ALIAS_OF_ALICE,
    headVersion: 1,
    headDigest: absorbed,
    order: { survivorRecordId: ALICE },
    mutationReceiptId: "mutation.merge.malformed",
  });

  assert.equal(result.verified, false);
  assert.equal(result.rejection, "identity_order_malformed");
  assert.equal(await nonceConsumedAt(receipt.nonce.bindingDigest), null);
  assert.equal(await countVersions(ALIAS_OF_ALICE), 1);
});

test("a merge authorization cannot be spent as a correction, or the reverse", async () => {
  await createRecord(ALICE, { name: "Alice" });
  const absorbed = await createRecord(ALIAS_OF_ALICE, { name: "A. Smith" });
  const order = mergeOrder(ALICE);
  const receipt = await issue(
    authorization({
      action: "merge_identity",
      targetRecordId: ALIAS_OF_ALICE,
      expectedHead: { kind: "version", version: 1, contentDigest: absorbed },
      proposedContent: order,
    }),
  );

  const asCorrect = await store().correct({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: ALIAS_OF_ALICE,
    proposedContent: order,
    mutationReceiptId: "mutation.merge.assubstitute",
  });

  assert.equal(asCorrect.verified, false);
  assert.equal(asCorrect.rejection, "authorization_action_mismatch");
  assert.equal(await nonceConsumedAt(receipt.nonce.bindingDigest), null);
});

// ---------------------------------------------------------------------------
// split_identity
// ---------------------------------------------------------------------------

test("a split appends one version to the SOURCE and records the edge to an existing record", async () => {
  const source = await createRecord(ALICE, { name: "Alice and Bob, conflated" });
  await createRecord("record-identity-bob", { name: "Bob" });

  const { result } = await runIdentity({
    action: "split_identity",
    targetRecordId: ALICE,
    headVersion: 1,
    headDigest: source,
    order: splitOrder("record-identity-bob"),
    mutationReceiptId: "mutation.split.001",
  });

  assert.equal(result.rejection, null);
  assert.equal(result.verified, true);
  assert.equal(await countVersions(ALICE), 2);
  // The split-off record is untouched: it was created under its own
  // authorization, which is the only way one authorization stays one mutation.
  assert.equal(await countVersions("record-identity-bob"), 1);

  const edges = await edgesFor(ALICE);
  assert.equal(edges.length, 1);
  assert.equal(edges[0].kind, "split_to");
  assert.equal(edges[0].to_record_id, "record-identity-bob");
});

test("a split record is NOT frozen: the source stays mutable afterwards", async () => {
  // The asymmetry with merge is the point. A split says "some of this was
  // somebody else"; the source is still a live identity.
  const source = await createRecord(ALICE, { name: "Alice and Bob" });
  await createRecord("record-identity-bob", { name: "Bob" });
  await runIdentity({
    action: "split_identity",
    targetRecordId: ALICE,
    headVersion: 1,
    headDigest: source,
    order: splitOrder("record-identity-bob"),
    mutationReceiptId: "mutation.split.mutable",
  });

  const head = await store().readHead(SCOPE, ALICE);
  const next = { name: "Alice" };
  const receipt = await issue(
    authorization({
      action: "correct",
      targetRecordId: ALICE,
      expectedHead: {
        kind: "version",
        version: 2,
        contentDigest: head!.contentDigest,
      },
      proposedContent: next,
    }),
  );
  const result = await store().correct({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: ALICE,
    proposedContent: next,
    mutationReceiptId: "mutation.split.aftercorrect",
  });

  assert.equal(result.rejection, null);
  assert.equal(result.verified, true);
  assert.equal(await countVersions(ALICE), 3);
});

test("a split naming a record that does not exist is refused", async () => {
  const source = await createRecord(ALICE, { name: "Alice and Bob" });

  const { result } = await runIdentity({
    action: "split_identity",
    targetRecordId: ALICE,
    headVersion: 1,
    headDigest: source,
    order: splitOrder("record-identity-nobody"),
    mutationReceiptId: "mutation.split.missing",
  });

  assert.equal(result.verified, false);
  assert.equal(result.rejection, "identity_counterparty_missing");
  assert.equal((await edgesFor(ALICE)).length, 0);
});

// ---------------------------------------------------------------------------
// The database carries the same rules, for writers that never come through
// the store.
// ---------------------------------------------------------------------------

test("an identity edge with no consumed authorization behind it is refused", async () => {
  await createRecord(ALICE, { name: "Alice" });
  await createRecord(ALIAS_OF_ALICE, { name: "A. Smith" });

  await assert.rejects(
    () =>
      runAs(
        "aaliyah_memory_mutator",
        `INSERT INTO memory_identity_edges
           (tenant_id, workspace_id, principal_id, user_id, kind,
            from_record_id, to_record_id, from_version, authorization_id,
            mutation_receipt_id, reason, reason_evidence_ref, effective_at,
            payload)
         VALUES ($1,$2,$3,$4,'merged_into',$5,$6,2,'unwitnessed-00000001',
                 'mutation.edge.unwitnessed','duplicate_participant',
                 'matter:x/0001', now(),
                 jsonb_build_object('kind','merged_into',
                   'fromRecordId',$5::text,'toRecordId',$6::text,
                   'authorizationId','unwitnessed-00000001'))`,
        [
          SCOPE.tenantId,
          SCOPE.workspaceId,
          SCOPE.principalId,
          SCOPE.userId,
          ALIAS_OF_ALICE,
          ALICE,
        ],
      ),
    /no consumed authorization witnesses this identity edge/,
  );
  assert.equal((await edgesFor(ALIAS_OF_ALICE)).length, 0);
});

test("a merge edge cannot be written under a split authorization", async () => {
  const source = await createRecord(ALICE, { name: "Alice" });
  await createRecord("record-identity-bob", { name: "Bob" });
  // Spend a REAL split authorization, which leaves a consumed nonce whose
  // action is `split_identity`.
  await runIdentity({
    action: "split_identity",
    targetRecordId: ALICE,
    headVersion: 1,
    headDigest: source,
    order: splitOrder("record-identity-bob"),
    mutationReceiptId: "mutation.split.forkind",
  });
  const spent = await adminPool.query(
    `SELECT authorization_id FROM memory_authorization_nonces
      WHERE consumed_by_mutation_receipt_id = 'mutation.split.forkind'`,
  );

  await assert.rejects(
    () =>
      runAs(
        "aaliyah_memory_mutator",
        `INSERT INTO memory_identity_edges
           (tenant_id, workspace_id, principal_id, user_id, kind,
            from_record_id, to_record_id, from_version, authorization_id,
            mutation_receipt_id, reason, reason_evidence_ref, effective_at,
            payload)
         VALUES ($1,$2,$3,$4,'merged_into',$5,$6,2,$7,
                 'mutation.split.forkind','duplicate_participant',
                 'matter:x/0001', now(),
                 jsonb_build_object('kind','merged_into',
                   'fromRecordId',$5::text,'toRecordId',$6::text,
                   'authorizationId',$7::text))`,
        [
          SCOPE.tenantId,
          SCOPE.workspaceId,
          SCOPE.principalId,
          SCOPE.userId,
          ALICE,
          "record-identity-bob",
          spent.rows[0].authorization_id,
        ],
      ),
    /a merge edge requires a merge_identity authorization|receipt_unique/,
  );
});

test("an identity edge cannot name a record outside the actor's scope", async () => {
  const foreign: MemoryScope = { ...SCOPE, principalId: "principal-other" };
  await createRecord("record-identity-foreign", { name: "Elsewhere" }, foreign);
  const source = await createRecord(ALICE, { name: "Alice" });
  await createRecord("record-identity-bob", { name: "Bob" });
  await runIdentity({
    action: "split_identity",
    targetRecordId: ALICE,
    headVersion: 1,
    headDigest: source,
    order: splitOrder("record-identity-bob"),
    mutationReceiptId: "mutation.split.forscope",
  });
  const spent = await adminPool.query(
    `SELECT authorization_id FROM memory_authorization_nonces
      WHERE consumed_by_mutation_receipt_id = 'mutation.split.forscope'`,
  );

  await assert.rejects(
    () =>
      runAs(
        "aaliyah_memory_mutator",
        `INSERT INTO memory_identity_edges
           (tenant_id, workspace_id, principal_id, user_id, kind,
            from_record_id, to_record_id, from_version, authorization_id,
            mutation_receipt_id, reason, reason_evidence_ref, effective_at,
            payload)
         VALUES ($1,$2,$3,$4,'split_to',$5,$6,2,$7,
                 'mutation.split.forscope','conflated_participants',
                 'matter:x/0001', now(),
                 jsonb_build_object('kind','split_to',
                   'fromRecordId',$5::text,'toRecordId',$6::text,
                   'authorizationId',$7::text))`,
        [
          SCOPE.tenantId,
          SCOPE.workspaceId,
          SCOPE.principalId,
          SCOPE.userId,
          ALICE,
          "record-identity-foreign",
          spent.rows[0].authorization_id,
        ],
      ),
    /must name a record in the same scope|receipt_unique/,
  );
});

test("a self-edge is refused by the database as well as by the store", async () => {
  await createRecord(ALICE, { name: "Alice" });

  await assert.rejects(
    () =>
      adminPool.query(
        `INSERT INTO memory_identity_edges
           (tenant_id, workspace_id, principal_id, user_id, kind,
            from_record_id, to_record_id, from_version, authorization_id,
            mutation_receipt_id, reason, reason_evidence_ref, effective_at,
            payload)
         VALUES ($1,$2,$3,$4,'merged_into',$5,$5,2,'a-0000000000000000001',
                 'mutation.edge.self','duplicate_participant',
                 'matter:x/0001', now(),
                 jsonb_build_object('kind','merged_into',
                   'fromRecordId',$5::text,'toRecordId',$5::text,
                   'authorizationId','a-0000000000000000001'))`,
        [
          SCOPE.tenantId,
          SCOPE.workspaceId,
          SCOPE.principalId,
          SCOPE.userId,
          ALICE,
        ],
      ),
    /memory_identity_edges_not_self/,
  );
});

test("a written identity edge cannot be rewritten or deleted, by anyone", async () => {
  await createRecord(ALICE, { name: "Alice" });
  const absorbed = await createRecord(ALIAS_OF_ALICE, { name: "A. Smith" });
  await runIdentity({
    action: "merge_identity",
    targetRecordId: ALIAS_OF_ALICE,
    headVersion: 1,
    headDigest: absorbed,
    order: mergeOrder(ALICE),
    mutationReceiptId: "mutation.merge.appendonly",
  });

  await assert.rejects(
    () =>
      adminPool.query(
        `UPDATE memory_identity_edges SET to_record_id = 'record-identity-third'`,
      ),
    /UPDATE on memory_identity_edges is forbidden; this table is append-only/,
  );
  await assert.rejects(
    () => adminPool.query(`DELETE FROM memory_identity_edges`),
    /DELETE on memory_identity_edges is forbidden; this table is append-only/,
  );
  assert.equal((await edgesFor(ALIAS_OF_ALICE)).length, 1);
});

test("ONE AUTHORIZATION CANNOT PRODUCE TWO RECORD VERSIONS — the constraint the design rests on", async () => {
  // Stated as a test because the whole merge/split shape follows from it: if
  // this were false, a merge could write to both records under one approval.
  const source = await createRecord(ALICE, { name: "Alice" });
  await createRecord("record-identity-bob", { name: "Bob" });
  await runIdentity({
    action: "split_identity",
    targetRecordId: ALICE,
    headVersion: 1,
    headDigest: source,
    order: splitOrder("record-identity-bob"),
    mutationReceiptId: "mutation.split.oneauth",
  });
  const spent = await adminPool.query(
    `SELECT authorization_id FROM memory_authorization_nonces
      WHERE consumed_by_mutation_receipt_id = 'mutation.split.oneauth'`,
  );

  // The same authorization, a DIFFERENT receipt id, aimed at the other record.
  await assert.rejects(
    () =>
      runAs(
        "aaliyah_memory_mutator",
        `INSERT INTO memory_record_versions
           (tenant_id, workspace_id, principal_id, user_id, record_id, version,
            state, content_digest, predecessor_digest, authorization_id,
            mutation_receipt_id, payload)
         VALUES ($1::text,$2::text,$3::text,$4::text,'record-identity-bob',2,
                 'active',$5::text,$6::text,$7::text,'mutation.split.second',
                 jsonb_build_object(
                   'recordId','record-identity-bob','version','2',
                   'state','active','contentDigest',$5::text,
                   'predecessorDigest',$6::text,'authorizationId',$7::text,
                   'mutationReceiptId','mutation.split.second',
                   'scope', jsonb_build_object('tenantId',$1::text,
                                               'workspaceId',$2::text,
                                               'principalId',$3::text,
                                               'userId',$4::text)))`,
        [
          SCOPE.tenantId,
          SCOPE.workspaceId,
          SCOPE.principalId,
          SCOPE.userId,
          `sha256:${"c".repeat(64)}`,
          memoryContentDigest({ name: "Bob" }),
          spent.rows[0].authorization_id,
        ],
      ),
    /no consumed authorization witnesses this record version/,
  );
  assert.equal(await countVersions("record-identity-bob"), 1);
});

// ---------------------------------------------------------------------------
// S — AN IDENTITY CHANGE IS SERIALIZED ON BOTH RECORDS (red team, b3efc82).
//
// Each race below is DRIVEN, not hoped for: a table lock or an open
// transaction holds one writer at a known point while the other is started,
// and `pg_stat_activity` proves the second is where the test says it is before
// anything is released. A race that did not happen fails the test rather than
// passing it.
// ---------------------------------------------------------------------------

async function lockWaiters(): Promise<number> {
  const result = await adminPool.query(
    `SELECT count(*)::int AS n
       FROM pg_stat_activity
      WHERE datname = current_database()
        AND wait_event_type = 'Lock'
        AND cardinality(pg_blocking_pids(pid)) > 0
        AND (query LIKE '%pg_advisory_xact_lock%'
             OR query LIKE '%INSERT INTO memory_identity_edges%'
             OR query LIKE '%INSERT INTO memory_tombstones%'
             OR query LIKE '%INSERT INTO memory_record_versions%')`,
  );
  return result.rows[0].n as number;
}

/** Wait until `n` memory writers are blocked, or until `settled()` says one finished. */
async function untilBlocked(n: number, settled: () => boolean = () => false): Promise<void> {
  const deadline = Date.now() + 4_000;
  while (Date.now() < deadline) {
    if ((await lockWaiters()) >= n || settled()) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error(`the interleaving did not happen: fewer than ${n} blocked writers`);
}

function tracked<T>(promise: Promise<T>): { promise: Promise<T>; settled: () => boolean } {
  let done = false;
  const wrapped = promise.finally(() => {
    done = true;
  });
  return { promise: wrapped, settled: () => done };
}

async function mergeAuthorization(target: string, targetDigest: string, survivor: string) {
  const order = mergeOrder(survivor);
  const receipt = await issue(
    authorization({
      action: "merge_identity",
      targetRecordId: target,
      expectedHead: { kind: "version", version: 1, contentDigest: targetDigest },
      proposedContent: order,
    }),
  );
  return { receipt, order };
}

test("S-1 merge A->B racing merge B->A cannot close a cycle: one commits, the other is refused as merged-away", async () => {
  const bob = "record-identity-bob";
  const alice = await createRecord(ALICE, { name: "Alice" });
  const bobDigest = await createRecord(bob, { name: "Bob" });
  const aToB = await mergeAuthorization(ALICE, alice, bob);
  const bToA = await mergeAuthorization(bob, bobDigest, ALICE);

  // Gate: nothing may write an identity edge until released. The first merge
  // gets as far as its edge INSERT and waits there, holding what it holds.
  const gate = await adminPool.connect();
  await gate.query("BEGIN");
  await gate.query("LOCK TABLE memory_identity_edges IN SHARE ROW EXCLUSIVE MODE");
  let first: ReturnType<typeof tracked>;
  let second: ReturnType<typeof tracked>;
  try {
    first = tracked(
      store().mergeIdentity({
        actor: SCOPE,
        authorizationId: aToB.receipt.authorizationId,
        recordId: ALICE,
        proposedContent: aToB.order,
        mutationReceiptId: "mutation.race.a-to-b",
      }),
    );
    await untilBlocked(1);
    second = tracked(
      store().mergeIdentity({
        actor: SCOPE,
        authorizationId: bToA.receipt.authorizationId,
        recordId: bob,
        proposedContent: bToA.order,
        mutationReceiptId: "mutation.race.b-to-a",
      }),
    );
    // Before the fix the second merge held only its FROM lock, passed every
    // unlocked check, and queued behind the gate at its own edge INSERT. After
    // it, the second waits on the first's lock of the shared pair.
    await untilBlocked(2);
  } finally {
    await gate.query("COMMIT");
    gate.release();
  }
  type MergeResult = Awaited<ReturnType<ReturnType<typeof store>["mergeIdentity"]>>;
  const results = (await Promise.all([first!.promise, second!.promise])) as MergeResult[];

  const verified = results.filter((r) => r.verified);
  assert.equal(verified.length, 1, JSON.stringify(results.map((r) => r.rejection)));
  const refused = results.find((r) => !r.verified)!;
  // PINNED. A database deadlock abort would also leave one merge standing, as
  // `storage_rejected`; that is the trigger backstop catching what the store
  // should have serialized, and it must not pass for the store's fix.
  assert.equal(refused.rejection, "identity_counterparty_merged_away");
  const edges = await adminPool.query(`SELECT from_record_id, to_record_id FROM memory_identity_edges`);
  assert.equal(edges.rowCount, 1);
});

test("S-2 merge A->B racing delete B cannot merge into a destroyed record", async () => {
  const bob = "record-identity-bob";
  const alice = await createRecord(ALICE, { name: "Alice" });
  const bobDigest = await createRecord(bob, { name: "Bob" });
  const deletion = {
    schemaVersion: MEMORY_DELETION_ORDER_SCHEMA_VERSION,
    reason: "subject_erasure_request",
    reasonEvidenceRef: "matter:erasure-request/0001",
  };
  const deleteReceipt = await issue(
    authorization({
      action: "delete",
      targetRecordId: bob,
      expectedHead: { kind: "version", version: 1, contentDigest: bobDigest },
      proposedContent: deletion,
    }),
  );
  const merge = await mergeAuthorization(ALICE, alice, bob);

  // Gate on tombstones: the deletion holds B's lock, has written B's deleted
  // head, and waits before COMMIT.
  const gate = await adminPool.connect();
  await gate.query("BEGIN");
  await gate.query("LOCK TABLE memory_tombstones IN SHARE ROW EXCLUSIVE MODE");
  let destroy: ReturnType<typeof tracked>;
  let merging: ReturnType<typeof tracked>;
  try {
    destroy = tracked(
      store().delete({
        actor: SCOPE,
        authorizationId: deleteReceipt.authorizationId,
        recordId: bob,
        proposedContent: deletion,
        mutationReceiptId: "mutation.race.delete-b",
      }),
    );
    await untilBlocked(1);
    merging = tracked(
      store().mergeIdentity({
        actor: SCOPE,
        authorizationId: merge.receipt.authorizationId,
        recordId: ALICE,
        proposedContent: merge.order,
        mutationReceiptId: "mutation.race.merge-into-b",
      }),
    );
    // Before the fix the merge read B's head unlocked — still `active`, the
    // deletion uncommitted — and COMMITTED here without ever blocking.
    await untilBlocked(2, merging.settled);
  } finally {
    await gate.query("COMMIT");
    gate.release();
  }
  const deleted = (await destroy!.promise) as { verified: boolean; rejection: string | null };
  const merged = (await merging!.promise) as { verified: boolean; rejection: string | null };

  assert.equal(deleted.verified, true, deleted.rejection ?? "");
  assert.equal(merged.verified, false, "a merge into a destroyed record committed");
  // PINNED to the store's refusal, not the trigger's (`storage_rejected`).
  assert.equal(merged.rejection, "identity_counterparty_missing");
  assert.equal((await edgesFor(ALICE)).length, 0);
  assert.equal(await countVersions(ALICE), 1);
  assert.equal(await nonceConsumedAt(merge.receipt.nonce.bindingDigest), null);
});

/** A mutator-role transaction left OPEN, so a second writer can be raced against it. */
async function openMutatorTransaction() {
  const client = await adminPool.connect();
  await client.query("BEGIN");
  await client.query('SET LOCAL ROLE "aaliyah_memory_mutator"');
  return client;
}

const RAW_EDGE_SQL = `INSERT INTO memory_identity_edges
   (tenant_id, workspace_id, principal_id, user_id, kind,
    from_record_id, to_record_id, from_version, authorization_id,
    mutation_receipt_id, reason, reason_evidence_ref, effective_at, payload)
 VALUES ($1::text,$2::text,$3::text,$4::text,'merged_into',
         $5::text,$6::text,2,$7::text,$8::text,
         'duplicate_participant','matter:identity-merge/0003', now(),
         jsonb_build_object('kind','merged_into',
           'fromRecordId',$5::text,'toRecordId',$6::text,
           'authorizationId',$7::text))`;

function rawEdgeParams(from: string, to: string, authorizationId: string, receipt: string) {
  return [
    SCOPE.tenantId,
    SCOPE.workspaceId,
    SCOPE.principalId,
    SCOPE.userId,
    from,
    to,
    authorizationId,
    receipt,
  ];
}

test("S-3 the DATABASE serializes reverse merge edges from writers that bypass the store: no cycle", async () => {
  const bob = "record-identity-bob";
  const alice = await createRecord(ALICE, { name: "Alice" });
  const bobDigest = await createRecord(bob, { name: "Bob" });
  const aAuth = await spendAuthorization({
    action: "merge_identity",
    targetRecordId: ALICE,
    expectedHead: { kind: "version", version: 1, contentDigest: alice },
    proposedContent: mergeOrder(bob),
    mutationReceiptId: "mutation.rawrace.a",
  });
  const bAuth = await spendAuthorization({
    action: "merge_identity",
    targetRecordId: bob,
    expectedHead: { kind: "version", version: 1, contentDigest: bobDigest },
    proposedContent: mergeOrder(ALICE),
    mutationReceiptId: "mutation.rawrace.b",
  });

  const one = await openMutatorTransaction();
  const two = await openMutatorTransaction();
  try {
    await one.query(RAW_EDGE_SQL, rawEdgeParams(ALICE, bob, aAuth, "mutation.rawrace.a"));
    const reverse = tracked(
      two.query(RAW_EDGE_SQL, rawEdgeParams(bob, ALICE, bAuth, "mutation.rawrace.b")),
    );
    // Before migration 043 the reverse insert did not wait: its unlocked read
    // could not see the uncommitted A->B edge, and it returned at once.
    await untilBlocked(1, reverse.settled);
    await one.query("COMMIT");
    await assert.rejects(
      reverse.promise,
      /a merge may not name a record that was itself merged away/,
    );
    await two.query("ROLLBACK");
  } finally {
    await one.query("ROLLBACK").catch(() => undefined);
    await two.query("ROLLBACK").catch(() => undefined);
    one.release();
    two.release();
  }
  const edges = await adminPool.query(`SELECT from_record_id FROM memory_identity_edges`);
  assert.deepEqual(edges.rows.map((r: { from_record_id: string }) => r.from_record_id), [ALICE]);
});

test("S-4 the DATABASE makes a version racing a merge edge on the same record wait, then refuses it", async () => {
  const bob = "record-identity-bob";
  const alice = await createRecord(ALICE, { name: "Alice" });
  await createRecord(bob, { name: "Bob" });
  const mergeAuth = await spendAuthorization({
    action: "merge_identity",
    targetRecordId: ALICE,
    expectedHead: { kind: "version", version: 1, contentDigest: alice },
    proposedContent: mergeOrder(bob),
    mutationReceiptId: "mutation.rawrace.merge",
  });
  const next = { name: "Alice", note: "raced edit" };
  const correctAuth = await spendAuthorization({
    action: "correct",
    targetRecordId: ALICE,
    expectedHead: { kind: "version", version: 1, contentDigest: alice },
    proposedContent: next,
    mutationReceiptId: "mutation.rawrace.correct",
  });

  const edgeTx = await openMutatorTransaction();
  const versionTx = await openMutatorTransaction();
  try {
    await edgeTx.query(RAW_EDGE_SQL, rawEdgeParams(ALICE, bob, mergeAuth, "mutation.rawrace.merge"));
    const version = tracked(
      versionTx.query(
        `INSERT INTO memory_record_versions
           (tenant_id, workspace_id, principal_id, user_id, record_id, version,
            state, content_digest, predecessor_digest, authorization_id,
            mutation_receipt_id, payload)
         VALUES ($1::text,$2::text,$3::text,$4::text,$5::text,2,'active',
                 $6::text,$7::text,$8::text,'mutation.rawrace.correct',
                 jsonb_build_object(
                   'recordId',$5::text,'version','2','state','active',
                   'contentDigest',$6::text,'predecessorDigest',$7::text,
                   'authorizationId',$8::text,
                   'mutationReceiptId','mutation.rawrace.correct',
                   'scope', jsonb_build_object('tenantId',$1::text,
                                               'workspaceId',$2::text,
                                               'principalId',$3::text,
                                               'userId',$4::text)))`,
        [
          SCOPE.tenantId,
          SCOPE.workspaceId,
          SCOPE.principalId,
          SCOPE.userId,
          ALICE,
          memoryContentDigest(next),
          alice,
          correctAuth,
        ],
      ),
    );
    await untilBlocked(1, version.settled);
    await edgeTx.query("COMMIT");
    await assert.rejects(version.promise, /merged into another accepts no further versions/);
    await versionTx.query("ROLLBACK");
  } finally {
    await edgeTx.query("ROLLBACK").catch(() => undefined);
    await versionTx.query("ROLLBACK").catch(() => undefined);
    edgeTx.release();
    versionTx.release();
  }
  assert.equal(await countVersions(ALICE), 1);
});

test("S-5 the DATABASE refuses an edge into a record whose head is deleted", async () => {
  const bob = "record-identity-bob";
  const alice = await createRecord(ALICE, { name: "Alice" });
  const bobDigest = await createRecord(bob, { name: "Bob" });
  const deletion = {
    schemaVersion: MEMORY_DELETION_ORDER_SCHEMA_VERSION,
    reason: "subject_erasure_request",
    reasonEvidenceRef: "matter:erasure-request/0001",
  };
  const deleteReceipt = await issue(
    authorization({
      action: "delete",
      targetRecordId: bob,
      expectedHead: { kind: "version", version: 1, contentDigest: bobDigest },
      proposedContent: deletion,
    }),
  );
  const deleted = await store().delete({
    actor: SCOPE,
    authorizationId: deleteReceipt.authorizationId,
    recordId: bob,
    proposedContent: deletion,
    mutationReceiptId: "mutation.delete.bob",
  });
  assert.equal(deleted.verified, true, deleted.rejection ?? "");
  const mergeAuth = await spendAuthorization({
    action: "merge_identity",
    targetRecordId: ALICE,
    expectedHead: { kind: "version", version: 1, contentDigest: alice },
    proposedContent: mergeOrder(bob),
    mutationReceiptId: "mutation.raw.into-deleted",
  });
  await assert.rejects(
    () =>
      runAs(
        "aaliyah_memory_mutator",
        RAW_EDGE_SQL,
        rawEdgeParams(ALICE, bob, mergeAuth, "mutation.raw.into-deleted"),
      ),
    /may not name a record whose head is not active/,
  );
  assert.equal((await edgesFor(ALICE)).length, 0);
});

// ---------------------------------------------------------------------------
// C4 — A MUTATED ROW CARRIES ITS AUTHORIZATION'S SCOPE (security, b3efc82).
//
// The adversary is a holder of `aaliyah_memory_mutator` writing directly — the
// party migrations 034/038/039 already defend against. Each case holds every
// OTHER guard satisfied, so the refusal pinned is the one under test.
// ---------------------------------------------------------------------------

const VICTIM_SCOPE: MemoryScope = {
  ...SCOPE,
  principalId: "principal-victim",
  userId: "user-victim",
};

/** Issue an authorization in ANY scope, for ANY target, and spend it. */
async function spendScoped(input: {
  scope: MemoryScope;
  action: MemoryAction;
  targetRecordId: string;
  expectedHead: MemoryExpectedHead;
  proposedContent: unknown;
  mutationReceiptId: string;
}): Promise<string> {
  const receipt = await issue(
    authorization({
      action: input.action,
      targetRecordId: input.targetRecordId,
      expectedHead: input.expectedHead,
      proposedContent: input.proposedContent,
      scope: input.scope,
    }),
  );
  await runAs(
    "aaliyah_memory_mutator",
    `UPDATE memory_authorization_nonces
        SET consumed_at = now(), consumed_by_mutation_receipt_id = $2
      WHERE binding_digest = $1 AND consumed_at IS NULL`,
    [receipt.nonce.bindingDigest, input.mutationReceiptId],
  );
  return receipt.authorizationId;
}

function scopedEdgeParams(
  scope: MemoryScope,
  from: string,
  to: string,
  authorizationId: string,
  receipt: string,
) {
  return [
    scope.tenantId,
    scope.workspaceId,
    scope.principalId,
    scope.userId,
    from,
    to,
    authorizationId,
    receipt,
  ];
}

test("C4-1 an edge filed under the VICTIM's scope, witnessed by an authorization in the ATTACKER's, is refused", async () => {
  // Security PoC B. The victim owns both records, so the edge's FROM owner
  // agrees with the edge; only the authorization's scope does not.
  const victimRecord = "record-identity-victim";
  const victimOther = "record-identity-victim-2";
  const victimDigest = await createRecord(victimRecord, { name: "Victim" }, VICTIM_SCOPE);
  await createRecord(victimOther, { name: "Victim, elsewhere" }, VICTIM_SCOPE);
  // A merge authorization issued in the attacker's scope that names the
  // victim's record. Nothing in the database forbids issuing one.
  const foreign = await spendScoped({
    scope: SCOPE,
    action: "merge_identity",
    targetRecordId: victimRecord,
    expectedHead: { kind: "version", version: 1, contentDigest: victimDigest },
    proposedContent: mergeOrder(victimOther),
    mutationReceiptId: "mutation.c4.poc-b",
  });

  await assert.rejects(
    () =>
      runAs(
        "aaliyah_memory_mutator",
        RAW_EDGE_SQL,
        scopedEdgeParams(VICTIM_SCOPE, victimRecord, victimOther, foreign, "mutation.c4.poc-b"),
      ),
    /a memory_identity_edges row must carry the scope of the authorization that witnesses it/,
  );
  assert.equal((await edgesFor(victimRecord)).length, 0);

  // The impact that no longer lands: the victim's own correction still works.
  const next = { name: "Victim", note: "still mine" };
  const own = await issue(
    authorization({
      action: "correct",
      targetRecordId: victimRecord,
      expectedHead: { kind: "version", version: 1, contentDigest: victimDigest },
      proposedContent: next,
      scope: VICTIM_SCOPE,
    }),
  );
  const corrected = await store().correct({
    actor: VICTIM_SCOPE,
    authorizationId: own.authorizationId,
    recordId: victimRecord,
    proposedContent: next,
    mutationReceiptId: "mutation.c4.victim-correct",
  });
  assert.equal(corrected.verified, true, corrected.rejection ?? "");
});

test("C4-2 an edge may only leave a record its owner holds, whichever scope it claims", async () => {
  // Security PoC A: the attacker's OWN authorization, for its OWN record,
  // spent on an edge filed under the victim's scope.
  const attackerRecord = "record-identity-attacker";
  const victimRecord = "record-identity-victim";
  const attackerDigest = await createRecord(attackerRecord, { name: "Attacker" });
  const victimDigest = await createRecord(victimRecord, { name: "Victim" }, VICTIM_SCOPE);
  const own = await spendScoped({
    scope: SCOPE,
    action: "merge_identity",
    targetRecordId: attackerRecord,
    expectedHead: { kind: "version", version: 1, contentDigest: attackerDigest },
    proposedContent: mergeOrder(victimRecord),
    mutationReceiptId: "mutation.c4.poc-a",
  });
  await assert.rejects(
    () =>
      runAs(
        "aaliyah_memory_mutator",
        RAW_EDGE_SQL,
        scopedEdgeParams(VICTIM_SCOPE, attackerRecord, victimRecord, own, "mutation.c4.poc-a"),
      ),
    /an identity edge may only leave a record its owner holds/,
  );

  // The mirror: filed under the ATTACKER's scope (so the authorization's
  // scope agrees), leaving the VICTIM's record through a foreign-target grant.
  const attackerOther = "record-identity-attacker-2";
  await createRecord(attackerOther, { name: "Attacker, elsewhere" });
  const foreign = await spendScoped({
    scope: SCOPE,
    action: "merge_identity",
    targetRecordId: victimRecord,
    expectedHead: { kind: "version", version: 1, contentDigest: victimDigest },
    proposedContent: mergeOrder(attackerOther),
    mutationReceiptId: "mutation.c4.poc-a-mirror",
  });
  await assert.rejects(
    () =>
      runAs(
        "aaliyah_memory_mutator",
        RAW_EDGE_SQL,
        scopedEdgeParams(SCOPE, victimRecord, attackerOther, foreign, "mutation.c4.poc-a-mirror"),
      ),
    /an identity edge may only leave a record its owner holds/,
  );
  assert.equal((await edgesFor(attackerRecord)).length, 0);
  assert.equal((await edgesFor(victimRecord)).length, 0);
});

test("C4-3 a later VERSION of somebody else's record cannot be appended under a foreign-target authorization", async () => {
  // Migration 039 bound GENESIS to its authorization's scope and nothing
  // later: continuity with the predecessor agreed with the victim's principal,
  // and the witness only resolved the target.
  const victimRecord = "record-identity-victim";
  const victimDigest = await createRecord(victimRecord, { name: "Victim" }, VICTIM_SCOPE);
  const forged = { name: "Victim", note: "written by somebody else" };
  const foreign = await spendScoped({
    scope: SCOPE,
    action: "correct",
    targetRecordId: victimRecord,
    expectedHead: { kind: "version", version: 1, contentDigest: victimDigest },
    proposedContent: forged,
    mutationReceiptId: "mutation.c4.version",
  });
  await assert.rejects(
    () =>
      runAs(
        "aaliyah_memory_mutator",
        `INSERT INTO memory_record_versions
           (tenant_id, workspace_id, principal_id, user_id, record_id, version,
            state, content_digest, predecessor_digest, authorization_id,
            mutation_receipt_id, payload)
         VALUES ($1::text,$2::text,$3::text,$4::text,$5::text,2,'active',
                 $6::text,$7::text,$8::text,'mutation.c4.version',
                 jsonb_build_object(
                   'recordId',$5::text,'version','2','state','active',
                   'contentDigest',$6::text,'predecessorDigest',$7::text,
                   'authorizationId',$8::text,
                   'mutationReceiptId','mutation.c4.version',
                   'scope', jsonb_build_object('tenantId',$1::text,
                                               'workspaceId',$2::text,
                                               'principalId',$3::text,
                                               'userId',$4::text)))`,
        [
          VICTIM_SCOPE.tenantId,
          VICTIM_SCOPE.workspaceId,
          VICTIM_SCOPE.principalId,
          VICTIM_SCOPE.userId,
          victimRecord,
          memoryContentDigest(forged),
          victimDigest,
          foreign,
        ],
      ),
    /a memory_record_versions row must carry the scope of the authorization that witnesses it/,
  );
  assert.equal(await countVersions(victimRecord), 1);
});

test("C4-4 the scope binding is attached, enabled, and last-firing on every table a mutation writes", async () => {
  // Behaviour is proven above (versions, edges) and in the alias registry
  // suite (bindings). A TOMBSTONE mismatch is not reachable on its own: a
  // second tombstone for a deleted version collides with the tombstone
  // uniqueness constraints first, and a deleted version written under a
  // mismatched scope is refused by the version binding. So for tombstones the
  // attachment itself is what is pinned — a dropped or disabled trigger fails
  // here.
  const expected = [
    ["memory_record_versions", "memory_record_versions_zz_authorization_scope"],
    ["memory_identity_edges", "memory_identity_edges_zz_authorization_scope"],
    ["memory_tombstones", "memory_tombstones_zz_authorization_scope"],
    ["memory_alias_bindings", "memory_alias_bindings_zz_authorization_scope"],
  ];
  for (const [table, trigger] of expected) {
    const found = await adminPool.query(
      `SELECT t.tgenabled, p.proname,
              (t.tgtype & 1) = 1 AS for_each_row,
              (t.tgtype & 4) = 4 AS on_insert,
              (t.tgtype & 2) = 0 AS after
         FROM pg_trigger t
         JOIN pg_class c ON c.oid = t.tgrelid
         JOIN pg_proc p ON p.oid = t.tgfoid
        WHERE c.relname = $1 AND t.tgname = $2`,
      [table, trigger],
    );
    assert.equal(found.rowCount, 1, `${trigger} is missing`);
    const row = found.rows[0];
    assert.equal(row.tgenabled, "O", `${trigger} is not enabled`);
    assert.equal(row.proname, "aaliyah_memory_row_in_authorization_scope");
    assert.deepEqual([row.for_each_row, row.on_insert, row.after], [true, true, true]);
    const later = await adminPool.query(
      `SELECT t.tgname FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
        WHERE c.relname = $1 AND NOT t.tgisinternal
          AND (t.tgtype & 2) = 0 AND (t.tgtype & 4) = 4
          AND t.tgname > $2`,
      [table, trigger],
    );
    assert.deepEqual(later.rows, [], `${trigger} must fire last`);
  }
  const removal = await adminPool.query(
    `SELECT t.tgenabled FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
      WHERE c.relname = 'memory_alias_bindings'
        AND t.tgname = 'memory_alias_bindings_removal_authorization_scope'`,
  );
  assert.equal(removal.rows[0]?.tgenabled, "O");
});

test("U-2 both identity-edge unique indexes refuse the one duplicate each exists for", async () => {
  await createRecord(ALICE, { name: "Alice" });
  const absorbed = await createRecord(ALIAS_OF_ALICE, { name: "A. Smith" });
  const { result } = await runIdentity({
    action: "merge_identity",
    targetRecordId: ALIAS_OF_ALICE,
    headVersion: 1,
    headDigest: absorbed,
    order: mergeOrder(ALICE),
    mutationReceiptId: "mutation.unique.edge",
  });
  assert.equal(result.verified, true);
  await createRecord("record-identity-third", { name: "Third" });

  await assertUniqueIndexKills(adminPool, {
    table: "memory_identity_edges",
    index: "memory_identity_edges_merged_once",
    where: "mutation_receipt_id = $1",
    params: ["mutation.unique.edge"],
    freshen: () => ({ mutation_receipt_id: "mutation.unique.edge.dup", to_record_id: "record-identity-third", payload: { toRecordId: "record-identity-third" } }),
    positive: () => ({
      mutation_receipt_id: "mutation.unique.edge.dup",
      from_record_id: "record-identity-third",
      payload: { fromRecordId: "record-identity-third" },
    }),
  });
  await assertUniqueIndexKills(adminPool, {
    table: "memory_identity_edges",
    index: "memory_identity_edges_receipt_unique",
    where: "mutation_receipt_id = $1",
    params: ["mutation.unique.edge"],
    // A SPLIT edge from another record: neither the merged-once index nor the
    // self-edge check can be what refuses it.
    freshen: () => ({
      kind: "split_to",
      from_record_id: "record-identity-third",
      payload: { kind: "split_to", fromRecordId: "record-identity-third" },
    }),
    positive: () => ({
      kind: "split_to",
      from_record_id: "record-identity-third",
      mutation_receipt_id: "mutation.unique.edge.dup",
      payload: { kind: "split_to", fromRecordId: "record-identity-third" },
    }),
  });
});

test("C6 M4: every identity-edge payload binding refuses an ABSENT and a NULL member, not only a different one", async () => {
  // Executed against b3efc82: `CHECK (payload ->> 'kind' = kind)` passed for a
  // payload with no `kind`, and for `kind: null`.
  const bob = "record-identity-bob";
  const alice = await createRecord(ALICE, { name: "Alice" });
  await createRecord(bob, { name: "Bob" });
  const authorizationId = await spendAuthorization({
    action: "merge_identity",
    targetRecordId: ALICE,
    expectedHead: { kind: "version", version: 1, contentDigest: alice },
    proposedContent: mergeOrder(bob),
    mutationReceiptId: "mutation.c6.bindings",
  });
  const full = {
    kind: "merged_into",
    fromRecordId: ALICE,
    toRecordId: bob,
    authorizationId,
  };
  const insertWith = (payload: Record<string, unknown>) =>
    runAs(
      "aaliyah_memory_mutator",
      `INSERT INTO memory_identity_edges
         (tenant_id, workspace_id, principal_id, user_id, kind,
          from_record_id, to_record_id, from_version, authorization_id,
          mutation_receipt_id, reason, reason_evidence_ref, effective_at,
          payload)
       VALUES ($1,$2,$3,$4,'merged_into',$5,$6,2,$7,'mutation.c6.bindings',
               'duplicate_participant','matter:identity-merge/0006', now(), $8)`,
      [
        SCOPE.tenantId,
        SCOPE.workspaceId,
        SCOPE.principalId,
        SCOPE.userId,
        ALICE,
        bob,
        authorizationId,
        JSON.stringify(payload),
      ],
    );
  const members: Array<[keyof typeof full, string]> = [
    ["kind", "memory_identity_edges_kind_binding"],
    ["fromRecordId", "memory_identity_edges_from_binding"],
    ["toRecordId", "memory_identity_edges_to_binding"],
    ["authorizationId", "memory_identity_edges_authorization_binding"],
  ];
  for (const [member, constraint] of members) {
    const absent: Record<string, unknown> = { ...full };
    delete absent[member];
    await assert.rejects(() => insertWith(absent), new RegExp(constraint));
    await assert.rejects(() => insertWith({ ...full, [member]: null }), new RegExp(constraint));
  }
  // Positive control: the complete payload passes every binding and lands.
  await insertWith(full);
  assert.equal((await edgesFor(ALICE)).length, 1);
});

test("C4-5 the scope binding refuses a mismatch in ONE dimension at a time: principal, user, workspace", async () => {
  // Each dimension is its own conjunct in the trigger; a test that changed
  // principal and user together could not tell whether either was checked.
  const cases: Array<[string, MemoryScope]> = [
    ["principal", { ...SCOPE, principalId: "principal-only-other" }],
    ["user", { ...SCOPE, userId: "user-only-other" }],
    ["workspace", { ...SCOPE, workspaceId: "workspace-only-other" }],
  ];
  for (const [dimension, authorizationScope] of cases) {
    const target = `record-identity-scope-${dimension}`;
    const digest = await createRecord(target, { name: dimension });
    const authorizationId = await spendScoped({
      scope: authorizationScope,
      action: "correct",
      targetRecordId: target,
      expectedHead: { kind: "version", version: 1, contentDigest: digest },
      proposedContent: { name: dimension, edited: true },
      mutationReceiptId: `mutation.c4.dimension.${dimension}`,
    });
    await assert.rejects(
      () =>
        runAs(
          "aaliyah_memory_mutator",
          `INSERT INTO memory_record_versions
             (tenant_id, workspace_id, principal_id, user_id, record_id, version,
              state, content_digest, predecessor_digest, authorization_id,
              mutation_receipt_id, payload)
           VALUES ($1::text,$2::text,$3::text,$4::text,$5::text,2,'active',
                   $6::text,$7::text,$8::text,$9::text,
                   jsonb_build_object(
                     'recordId',$5::text,'version','2','state','active',
                     'contentDigest',$6::text,'predecessorDigest',$7::text,
                     'authorizationId',$8::text,
                     'mutationReceiptId',$9::text,
                     'scope', jsonb_build_object('tenantId',$1::text,
                                                 'workspaceId',$2::text,
                                                 'principalId',$3::text,
                                                 'userId',$4::text)))`,
          [
            SCOPE.tenantId,
            SCOPE.workspaceId,
            SCOPE.principalId,
            SCOPE.userId,
            target,
            memoryContentDigest({ name: dimension, edited: true }),
            digest,
            authorizationId,
            `mutation.c4.dimension.${dimension}`,
          ],
        ),
      /a memory_record_versions row must carry the scope of the authorization that witnesses it/,
      `a ${dimension}-only mismatch was accepted`,
    );
  }
});

test("C4-6 an edge's FROM owner is checked on principal AND user independently", async () => {
  for (const [dimension, ownerScope] of [
    ["principal", { ...SCOPE, principalId: "principal-owner-other" }],
    ["user", { ...SCOPE, userId: "user-owner-other" }],
  ] as Array<[string, MemoryScope]>) {
    const foreignRecord = `record-identity-owner-${dimension}`;
    const mine = `record-identity-mine-${dimension}`;
    const foreignDigest = await createRecord(foreignRecord, { name: dimension }, ownerScope);
    await createRecord(mine, { name: "mine" });
    const authorizationId = await spendScoped({
      scope: SCOPE,
      action: "merge_identity",
      targetRecordId: foreignRecord,
      expectedHead: { kind: "version", version: 1, contentDigest: foreignDigest },
      proposedContent: mergeOrder(mine),
      mutationReceiptId: `mutation.c4.owner.${dimension}`,
    });
    await assert.rejects(
      () =>
        runAs(
          "aaliyah_memory_mutator",
          RAW_EDGE_SQL,
          scopedEdgeParams(SCOPE, foreignRecord, mine, authorizationId, `mutation.c4.owner.${dimension}`),
        ),
      /an identity edge may only leave a record its owner holds/,
      `a ${dimension}-only owner mismatch was accepted`,
    );
  }
});

test("S-7 the store takes an identity pair's locks in ONE order, so opposite merges cannot deadlock", async () => {
  // Survivor C3-07: reversing the lock order changed nothing S-1 observed,
  // because there the first merge already held both locks. Here the arrival
  // order is forced. PostgreSQL grants a contended advisory lock in queue
  // order, so with a gate held on ALICE:
  //   - merge BOB->ALICE queues on ALICE first;
  //   - merge ALICE->BOB queues second.
  // In sorted order both queue on ALICE and neither holds BOB, so the first
  // proceeds to BOB and the second refuses as merged-away. In any other order
  // ALICE->BOB takes BOB before queuing on ALICE, the first then waits on BOB
  // while the second waits on ALICE, and PostgreSQL aborts one as a deadlock —
  // `storage_rejected`, which this test refuses to accept.
  const bob = "record-identity-bob";
  assert.ok(ALICE < bob, "the test's premise: ALICE sorts first");
  const alice = await createRecord(ALICE, { name: "Alice" });
  const bobDigest = await createRecord(bob, { name: "Bob" });
  const aToB = await mergeAuthorization(ALICE, alice, bob);
  const bToA = await mergeAuthorization(bob, bobDigest, ALICE);

  const gate = await adminPool.connect();
  await gate.query("BEGIN");
  await gate.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [
    [SCOPE.tenantId, SCOPE.workspaceId, ALICE].join(String.fromCharCode(0x1f)),
  ]);
  let first: ReturnType<typeof tracked>;
  let second: ReturnType<typeof tracked>;
  try {
    first = tracked(
      store().mergeIdentity({
        actor: SCOPE,
        authorizationId: bToA.receipt.authorizationId,
        recordId: bob,
        proposedContent: bToA.order,
        mutationReceiptId: "mutation.order.b-to-a",
      }),
    );
    await untilBlocked(1);
    second = tracked(
      store().mergeIdentity({
        actor: SCOPE,
        authorizationId: aToB.receipt.authorizationId,
        recordId: ALICE,
        proposedContent: aToB.order,
        mutationReceiptId: "mutation.order.a-to-b",
      }),
    );
    await untilBlocked(2);
  } finally {
    await gate.query("COMMIT");
    gate.release();
  }
  type MergeResult = Awaited<ReturnType<ReturnType<typeof store>["mergeIdentity"]>>;
  const results = (await Promise.all([first!.promise, second!.promise])) as MergeResult[];
  assert.deepEqual(
    results.map((r) => r.rejection).sort(),
    ["identity_counterparty_merged_away", null].sort(),
    JSON.stringify(results.map((r) => r.rejection)),
  );
});

test("C8 every CHECK on memory_identity_edges refuses the one row it exists for (from a real merge edge)", async () => {
  // Priority 6: all 8 CHECKs on the table W1.3 introduced were outside the
  // original destroyer population and survived a DROP.
  await createRecord(ALICE, { name: "Alice" });
  const absorbed = await createRecord(ALIAS_OF_ALICE, { name: "A. Smith" });
  const { result } = await runIdentity({
    action: "merge_identity",
    targetRecordId: ALIAS_OF_ALICE,
    headVersion: 1,
    headDigest: absorbed,
    order: mergeOrder(ALICE),
    mutationReceiptId: "mutation.checks.edge",
  });
  assert.equal(result.verified, true);
  await assertCheckConstraintsKill(adminPool, {
    table: "memory_identity_edges",
    where: "mutation_receipt_id = $1",
    params: ["mutation.checks.edge"],
    nonObjectColumn: "payload",
    fresh: () => ({
      mutation_receipt_id: "mutation.checks.edge.fresh",
      from_record_id: "record-identity-fresh",
      payload: { fromRecordId: "record-identity-fresh" },
    }),
    cases: [
      { constraint: "memory_identity_edges_kind_domain", violate: () => ({ kind: "absorbed", payload: { kind: "absorbed" } }) },
      { constraint: "memory_identity_edges_not_self", violate: (r) => ({ to_record_id: r.from_record_id, payload: { toRecordId: r.from_record_id } }) },
      { constraint: "memory_identity_edges_version_positive", violate: () => ({ from_version: 0 }) },
      { constraint: "memory_identity_edges_kind_binding", violate: () => ({ payload: { kind: "split_to" } }) },
      { constraint: "memory_identity_edges_from_binding", violate: () => ({ payload: { fromRecordId: "record-elsewhere" } }) },
      { constraint: "memory_identity_edges_to_binding", violate: () => ({ payload: { toRecordId: "record-elsewhere" } }) },
      { constraint: "memory_identity_edges_authorization_binding", violate: () => ({ payload: { authorizationId: "someone-else-0000000000001" } }) },
    ],
  });
});

test("C9 the numeric-domain trigger guards identity-edge payloads: fractional refused, integer accepted", async () => {
  // P6 survivor TRG memory_identity_edges_exact_numbers: no test ever sent an
  // edge payload carrying a number JavaScript cannot represent exactly.
  const bob = "record-identity-bob";
  const alice = await createRecord(ALICE, { name: "Alice" });
  await createRecord(bob, { name: "Bob" });
  const authorizationId = await spendAuthorization({
    action: "merge_identity",
    targetRecordId: ALICE,
    expectedHead: { kind: "version", version: 1, contentDigest: alice },
    proposedContent: mergeOrder(bob),
    mutationReceiptId: "mutation.c9.numeric",
  });
  const insert = (extra: Record<string, unknown>) =>
    runAs(
      "aaliyah_memory_mutator",
      `INSERT INTO memory_identity_edges
         (tenant_id, workspace_id, principal_id, user_id, kind, from_record_id, to_record_id,
          from_version, authorization_id, mutation_receipt_id, reason, reason_evidence_ref,
          effective_at, payload)
       VALUES ($1,$2,$3,$4,'merged_into',$5,$6,2,$7,'mutation.c9.numeric',
               'duplicate_participant','matter:identity-merge/0009', now(), $8)`,
      [SCOPE.tenantId, SCOPE.workspaceId, SCOPE.principalId, SCOPE.userId, ALICE, bob, authorizationId,
       JSON.stringify({ kind: "merged_into", fromRecordId: ALICE, toRecordId: bob, authorizationId, ...extra })],
    );
  await assert.rejects(() => insert({ weight: 0.5 }), /outside the exact numeric domain/);
  await insert({ weight: 2 });
  assert.equal((await edgesFor(ALICE)).length, 1);
});

// ---------------------------------------------------------------------------
// D — NO MERGE MAY MAKE AN IDENTITY UNRESOLVABLE (red team M3, 2b2e554)
// ---------------------------------------------------------------------------

function chainIds(n: number): string[] {
  return Array.from({ length: n }, (_, i) => `record-chain-${String(i).padStart(2, "0")}`);
}

async function mergeAtHead(from: string, to: string, receiptId: string, deleting = store()) {
  const head = await store().readHead(SCOPE, from);
  assert.ok(head);
  const order = mergeOrder(to);
  const receipt = await issue(
    authorization({
      action: "merge_identity",
      targetRecordId: from,
      expectedHead: { kind: "version", version: head.version, contentDigest: head.contentDigest },
      proposedContent: order,
    }),
  );
  const result = await deleting.mergeIdentity({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: from,
    proposedContent: order,
    mutationReceiptId: receiptId,
  });
  return { receipt, result };
}

function resolver() {
  return createWave1MemoryService({
    store: store(),
    aliases: { resolveAlias: async () => null },
    identityGraph: createPostgresIdentityGraph(readPool),
    reconciler: { reconcileAll: async () => [] },
  });
}

test("D-1 a chain of exactly the resolver's depth resolves; a merge that would lengthen it is refused before consumption", async () => {
  assert.equal(MEMORY_CANONICAL_RESOLUTION_MAX_DEPTH, 16);
  const ids = chainIds(18);
  for (const id of ids) await createRecord(id, { id });
  for (let i = 0; i < 16; i += 1) {
    const { result } = await mergeAtHead(ids[i]!, ids[i + 1]!, `mutation.d1.${i}`);
    assert.equal(result.verified, true, `merge ${i}: ${result.rejection}`);
  }
  // 16 hops: the off-by-one refused this.
  assert.equal(await resolver().canonicalIdentity(SCOPE, ids[0]!), ids[16]);

  const tail = await mergeAtHead(ids[16]!, ids[17]!, "mutation.d1.tail");
  assert.equal(tail.result.rejection, "identity_chain_too_deep");
  assert.equal(await nonceConsumedAt(tail.receipt.nonce.bindingDigest), null);

  // Positive control: a merge INTO the chain's canonical record branches the
  // graph without lengthening any chain (migration 042 already refuses a merge
  // into an absorbed record, so a chain can only grow at its canonical end).
  await createRecord("record-chain-branch", { id: "branch" });
  const branch = await mergeAtHead("record-chain-branch", ids[16]!, "mutation.d1.branch");
  assert.equal(branch.result.verified, true, branch.result.rejection ?? "");
  // Every identity on the graph still resolves.
  assert.equal(await resolver().canonicalIdentity(SCOPE, ids[0]!), ids[16]);
  assert.equal(await resolver().canonicalIdentity(SCOPE, "record-chain-branch"), ids[16]);
});

test("D-2 the DATABASE refuses the 17th hop with NO application involved at all", async () => {
  // ---- WHY THIS NO LONGER BLINDS THE STORE BY SHADOWING --------------
  //
  // This test used to prove the database half by DECEIVING the application:
  // it created `d2_shadow.aaliyah_memory_merge_chain_hops(...)` returning 1,
  // ran `GRANT USAGE ON SCHEMA d2_shadow TO aaliyah_memory_mutator` and
  // `GRANT EXECUTE` on the planted function, and pointed a pool's
  // `search_path` at it so the store's own cap check read a false hop count.
  //
  // That is precisely the function-shadowing attack this round closed — the
  // same shape that redirected `aaliyah_memory_unerased_merged_records`, the
  // erasure guard's helper — and the fixture was issuing the enabling grants
  // itself. The store's pinned path is now the constant
  // `pg_catalog, public, pg_temp`, so a planted function cannot be reached.
  //
  // It was also never necessary. `aaliyah_memory_merge_chain_guard()` calls
  // `public.aaliyah_memory_merge_chain_hops(...)` SCHEMA-QUALIFIED and is
  // SECURITY DEFINER with its own pinned path, so the DATABASE's check was
  // never blindable in the first place. Removing the application entirely is a
  // stronger statement than lying to it: the INSERT the store would issue is
  // issued directly, as the mutation role, and the trigger must still refuse.
  const ids = chainIds(18);
  for (const id of ids) await createRecord(id, { id });
  for (let i = 0; i < 16; i += 1) {
    const { result } = await mergeAtHead(ids[i]!, ids[i + 1]!, `mutation.d2.${i}`);
    assert.equal(result.verified, true, `merge ${i}: ${result.rejection}`);
  }

  // The PROSPECTIVE edge would be the 17th hop. The function's third and
  // fourth arguments are the edge's `from` and `to`, and it returns
  // incoming(from) + 1 + outgoing(to) — so 16 behind ids[16], plus this edge,
  // plus 0 ahead of ids[17]. Asserted, because a cap test that has not reached
  // the cap proves nothing.
  const hops = await adminPool.query(
    `SELECT public.aaliyah_memory_merge_chain_hops($1,$2,$3,$4) AS n`,
    [SCOPE.tenantId, SCOPE.workspaceId, ids[16]!, ids[17]!],
  );
  assert.equal(
    Number(hops.rows[0].n),
    17,
    "fixture precondition: the next edge must be the 17th hop",
  );

  // A REAL, CONSUMED authorization for this exact merge, so the
  // authorization-witness trigger and the scope trigger are genuinely
  // satisfied. Without it the row is refused for reasons that have nothing to
  // do with the cap — which is how this test first failed twice, on the
  // payload-binding CHECKs and then on the witness trigger.
  const head16 = await store().readHead(SCOPE, ids[16]!);
  assert.ok(head16);
  const authId = await spendAuthorization({
    action: "merge_identity",
    targetRecordId: ids[16]!,
    expectedHead: {
      kind: "version",
      version: head16.version,
      contentDigest: head16.contentDigest,
    },
    proposedContent: mergeOrder(ids[17]!),
    mutationReceiptId: "mutation.d2.direct",
  });

  await assert.rejects(
    () =>
      runAs(
        "aaliyah_memory_mutator",
        `INSERT INTO memory_identity_edges
           (tenant_id, workspace_id, principal_id, user_id, kind,
            from_record_id, to_record_id, from_version,
            authorization_id, mutation_receipt_id, reason,
            reason_evidence_ref, effective_at, payload)
         VALUES ($1,$2,$3,$4,'merged_into',$5,$6,1,
                 $8,'mutation.d2.direct',
                 'duplicate_participant','identity:verification/participant-record',
                 now(), $7::jsonb)`,
        [
          SCOPE.tenantId, SCOPE.workspaceId, SCOPE.principalId, SCOPE.userId,
          ids[16]!, ids[17]!,
          // The jsonb-to-column binding CHECKs fire BEFORE the AFTER trigger,
          // so the payload has to satisfy all four of them or the row is
          // refused for a reason that has nothing to do with the cap:
          //   ..._authorization_binding, ..._from_binding,
          //   ..._to_binding, ..._kind_binding
          JSON.stringify({
            authorizationId: authId,
            fromRecordId: ids[16]!,
            toRecordId: ids[17]!,
            kind: "merged_into",
          }),
          authId,
        ],
      ),
    /merge chain|chain length|hops/i,
    "the database accepted a 17th hop",
  );

  // And nothing landed.
  assert.equal((await edgesFor(ids[16]!)).length, 0);
});
