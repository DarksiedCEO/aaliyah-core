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
  localMemoryIntegrityProvider,
  memoryIntegrityMessage,
} from "../src/crypto/memoryIntegrity";
import { MEMORY_DELETION_ORDER_SCHEMA_VERSION } from "../src/application/memory/wave1MemoryErasure";
import { memoryContentDigest } from "../src/application/memory/wave1TrustedMemory";
import { runMailMigrations } from "../src/persistence/postgres/migrations";
import { createPostgresTrustedMemoryStore } from "../src/persistence/postgres/wave1TrustedMemoryStore";
import {
  lockSharedMemoryTables,
  type SharedTableLock,
} from "./support/sharedMemoryTables";

/**
 * W1BR-008 — THE UNKEYED DIGEST, MEASURED RATHER THAN ASSERTED.
 *
 * The register records the oracle: `canonicalDigest` is an unkeyed SHA-256, so
 * anyone holding a record's `contentDigest` can confirm guessed content
 * offline. These tests establish the EXACT bound, because a residual that is
 * described but never executed is a residual nobody has measured.
 *
 * The sharp edge, and it is not in the register's original statement: ERASURE
 * DOES NOT DESTROY THE DIGEST. `delete` nulls `payload.content`, and leaves
 * `content_digest` standing — in the erased row, and again in the successor's
 * `predecessor_digest`, where it is structurally load-bearing as the chain
 * link. So after a subject erasure request the content is gone and the ability
 * to CONFIRM what it was is not.
 *
 * The contrast at the end is what makes the closure path more than a claim: the
 * same guess against the keyed primitive confirms nothing.
 */

const DB_URL =
  process.env.AALIYAH_TEST_DATABASE_URL ??
  "postgres://postgres:test@127.0.0.1:54329/aaliyah_test";

const SCOPE: MemoryScope = {
  tenantId: "tenant-oracle",
  workspaceId: "workspace-oracle",
  principalId: "principal-oracle",
  userId: "user-oracle",
};
const RECORD_ID = "record-oracle-001";

/** Low-entropy, exactly the shape the register says this path carries. */
const SECRET = { nationalId: "123-45-6789", status: "verified" };

let adminPool: Pool;
let writePool: Pool;
let readPool: Pool;
let sharedTableLock: SharedTableLock;
let authCounter = 0;

before(async () => {
  adminPool = new Pool({ connectionString: DB_URL, max: 6 });
  sharedTableLock = await lockSharedMemoryTables(adminPool);
  await runMailMigrations(adminPool);
  writePool = new Pool({ connectionString: DB_URL, max: 6 });
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
              memory_tombstones
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
  expectedHead: MemoryExpectedHead;
  proposedContent: unknown;
}): MemoryAuthorizationReceipt {
  authCounter += 1;
  const authorizationId = `oracle-auth-${String(authCounter).padStart(15, "0")}`;
  const proposedContentDigest = memoryContentDigest(input.proposedContent);
  return MemoryAuthorizationReceiptSchema.parse({
    schemaVersion: WAVE1_TRUSTED_MEMORY_CONTRACT_VERSION,
    authorizationId,
    action: input.action,
    approverAuthorityId: "authority.memory-steward",
    approverActorId: "actor.memory-steward",
    scope: SCOPE,
    targetRecordId: RECORD_ID,
    expectedHead: input.expectedHead,
    proposedContentDigest,
    nonce: {
      bindingSchemaVersion: MEMORY_AUTHORIZATION_NONCE_SCHEMA_VERSION,
      bindingDigest: memoryAuthorizationNonce({
        bindingSchemaVersion: MEMORY_AUTHORIZATION_NONCE_SCHEMA_VERSION,
        authorizationId,
        action: input.action,
        scope: SCOPE,
        targetRecordId: RECORD_ID,
        expectedHead: input.expectedHead,
        proposedContentDigest,
      }),
    },
    issuedAt: isoOffset(-60_000),
    expiresAt: isoOffset(3_600_000),
    revokedAt: null,
    consumedAt: null,
    policyVersion: "memory-policy/v1",
    evidenceDigest: `sha256:${"b".repeat(64)}`,
  });
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
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NULL,NULL,$11)`,
      [
        SCOPE.tenantId,
        SCOPE.workspaceId,
        SCOPE.principalId,
        SCOPE.userId,
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
        SCOPE.tenantId,
        SCOPE.workspaceId,
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
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
  return receipt;
}

/** Create the record, then erase it under a real subject-erasure order. */
async function createThenErase(): Promise<{ digest: string }> {
  const createReceipt = await issue(
    authorization({
      action: "create",
      expectedHead: { kind: "no_prior_version" },
      proposedContent: SECRET,
    }),
  );
  const created = await store().create({
    actor: SCOPE,
    authorizationId: createReceipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: SECRET,
    mutationReceiptId: "mutation.oracle.create",
  });
  assert.equal(created.verified, true);
  const digest = memoryContentDigest(SECRET);

  const order = {
    schemaVersion: MEMORY_DELETION_ORDER_SCHEMA_VERSION,
    reason: "subject_erasure_request" as const,
    reasonEvidenceRef: "matter:erasure-request/oracle-0001",
  };
  const deleteReceipt = await issue(
    authorization({
      action: "delete",
      expectedHead: { kind: "version", version: 1, contentDigest: digest },
      proposedContent: order,
    }),
  );
  const deleted = await store().delete({
    actor: SCOPE,
    authorizationId: deleteReceipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: order,
    mutationReceiptId: "mutation.oracle.delete",
  });
  assert.equal(deleted.rejection, null);
  assert.equal(deleted.verified, true);
  return { digest };
}

// ---------------------------------------------------------------------------
// What erasure DOES destroy.
// ---------------------------------------------------------------------------

test("erasure destroys the content: the plaintext is gone from every version", async () => {
  await createThenErase();

  const rows = await adminPool.query(
    `SELECT version, payload ->> 'content' AS content, content_erased_at
       FROM memory_record_versions
      WHERE record_id = $1 ORDER BY version`,
    [RECORD_ID],
  );
  assert.equal(rows.rowCount, 2);
  // Version 1 held the secret and no longer does.
  assert.equal(rows.rows[0].content, null);
  assert.notEqual(rows.rows[0].content_erased_at, null);
  // Version 2 is the TOMBSTONE version, and it legitimately carries content —
  // the deletion ORDER, which is a reason and an evidence reference. Asserting
  // "no version carries content" was wrong and would have failed a correct
  // system. What must hold is that the order carries none of the secret.
  const tombstoneContent = String(rows.rows[1].content ?? "");
  assert.doesNotMatch(tombstoneContent, /123-45-6789/);
  assert.match(tombstoneContent, /subject_erasure_request/);
  // And ordinary retrieval answers nothing at all.
  assert.equal(await store().retrieve(SCOPE, RECORD_ID), null);
});

// ---------------------------------------------------------------------------
// What erasure does NOT destroy — the residual, executed.
// ---------------------------------------------------------------------------

test("W1BR-008: the digest of the ERASED content survives erasure, in two places", async () => {
  const { digest } = await createThenErase();

  const rows = await adminPool.query(
    `SELECT version, content_digest, predecessor_digest
       FROM memory_record_versions
      WHERE record_id = $1 ORDER BY version`,
    [RECORD_ID],
  );
  // 1. On the erased version itself.
  assert.equal(rows.rows[0].content_digest, digest);
  // 2. And again on the tombstone version, as the chain link. This one is
  //    STRUCTURALLY load-bearing: it is what makes the chain verifiable, so it
  //    cannot simply be nulled without breaking the property the chain exists
  //    for. That is why closing this needs a KEYED construction rather than a
  //    deletion.
  assert.equal(rows.rows[1].predecessor_digest, digest);
});

test("W1BR-008: a party holding the surviving digest CONFIRMS the erased content offline", async () => {
  const { digest } = await createThenErase();

  // No database access, no key, no store. Just the digest and a guess.
  const guess = { nationalId: "123-45-6789", status: "verified" };
  assert.equal(
    memoryContentDigest(guess),
    digest,
    "the guess is confirmed — this IS the oracle",
  );

  // And a wrong guess is rejected, which is what makes enumeration work: the
  // oracle answers precisely, so a small guess space is searchable.
  assert.notEqual(
    memoryContentDigest({ nationalId: "123-45-6780", status: "verified" }),
    digest,
  );
});

test("W1BR-008 BOUND: the store does not hand that digest to another principal", async () => {
  await createThenErase();

  // The narrowing that IS in place. `readHead` and `retrieve` filter on all
  // four scope dimensions, so obtaining the digest THROUGH THE STORE requires
  // already being the principal who owns the record.
  const intruder = { ...SCOPE, principalId: "principal-intruder" };
  assert.equal(await store().readHead(intruder, RECORD_ID), null);
  assert.equal(await store().retrieve(intruder, RECORD_ID), null);

  // The owner still cannot retrieve it either — it is erased — but CAN see the
  // head, which is where the digest is exposed to a legitimate caller.
  const head = await store().readHead(SCOPE, RECORD_ID);
  assert.notEqual(head, null);
  assert.equal(head?.state, "deleted");
});

test("W1BR-008 BOUND: the exposure is to a party with STORED-STATE access, not to a caller", async () => {
  const { digest } = await createThenErase();

  // Stated precisely, because the difference decides the severity: the oracle
  // is reachable by anyone who can read the rows — a backup, a replica, a log
  // that captured a receipt — not by an ordinary API caller who is scoped out
  // by the four predicates above.
  const fromBackup = await adminPool.query(
    `SELECT content_digest FROM memory_record_versions
      WHERE record_id = $1 ORDER BY version LIMIT 1`,
    [RECORD_ID],
  );
  assert.equal(fromBackup.rows[0].content_digest, digest);
});

// ---------------------------------------------------------------------------
// The closure path, demonstrated rather than promised.
// ---------------------------------------------------------------------------

test("W1BR-008 CLOSURE: the same guess against the KEYED primitive confirms nothing", async () => {
  const { digest } = await createThenErase();

  const provider = localMemoryIntegrityProvider({
    keyId: "key.memory-integrity",
    versions: [{ version: 1, key: Buffer.alloc(32, 0xa1) }],
  });
  const message = memoryIntegrityMessage({
    domain: "aaliyah.trusted-memory.record-content/v1",
    tenantId: SCOPE.tenantId,
    workspaceId: SCOPE.workspaceId,
    principalId: SCOPE.principalId,
    userId: SCOPE.userId,
    subjectId: RECORD_ID,
    sequence: 1,
    payload: Buffer.from(JSON.stringify(SECRET), "utf8"),
  });
  const tag = await provider.sign(message);

  // A guesser holding the TAG, guessing correctly, still cannot confirm:
  // reproducing it requires the key, which is not in the database.
  assert.notEqual(tag.tag, digest);
  const attacker = localMemoryIntegrityProvider({
    keyId: "key.memory-integrity",
    versions: [{ version: 1, key: Buffer.alloc(32, 0xcc) }],
  });
  assert.notEqual((await attacker.sign(message)).tag, tag.tag);

  // The holder of the real key still verifies it, so the tag remains an
  // integrity control and not merely an opaque value.
  assert.equal(await provider.verify(message, tag), true);
});

test("W1BR-008 STATUS: the stored digest is STILL the unkeyed one — the primitive is not wired in", async () => {
  // This test exists so the residual cannot quietly be believed closed because
  // a keyed primitive was merged. Nothing in the store consults it yet.
  const { digest } = await createThenErase();
  assert.equal(digest, memoryContentDigest(SECRET));
  assert.match(digest, /^sha256:[a-f0-9]{64}$/);

  const columns = await adminPool.query(
    `SELECT column_name FROM information_schema.columns
      WHERE table_name = 'memory_record_versions'
        AND column_name IN ('content_tag','key_id','key_version','tag_algorithm')`,
  );
  assert.equal(
    columns.rowCount,
    0,
    "no keyed-tag column exists yet; W1BR-008 is bounded, not closed",
  );
});
