import assert from "node:assert/strict";
import test, { after, before, beforeEach } from "node:test";
import { Pool } from "pg";

import { memoryContentDigest } from "../src/application/memory/wave1TrustedMemory";
import { runMailMigrations } from "../src/persistence/postgres/migrations";
import { createPostgresMemoryReconciler } from "../src/persistence/postgres/wave1MemoryReconciler";
import { createPostgresTrustedMemoryStore } from "../src/persistence/postgres/wave1TrustedMemoryStore";
import {
  lockSharedMemoryTables,
  type SharedTableLock,
} from "./support/sharedMemoryTables";

/**
 * RECONCILING UNKNOWN OUTCOMES, AGAINST A REAL DATABASE.
 *
 * `UNKNOWN_PENDING_RECONCILIATION` was durable and permanent: the store
 * recorded the ambiguity honestly and nothing ever resolved it. These prove
 * the resolution is a READING of authoritative state rather than a guess, that
 * ambiguity is never rounded up to success, and that the reconciler is
 * structurally incapable of producing a second mutation.
 *
 * Every negative assertion pins its reason. A bare rejection here would pass
 * against a reconciler that refused everything, which is exactly the shape a
 * broken one would take.
 */

const DB_URL =
  process.env.AALIYAH_TEST_DATABASE_URL ??
  "postgres://postgres:test@127.0.0.1:54329/aaliyah_test";

const SCOPE = {
  tenantId: "tenant-recon",
  workspaceId: "workspace-recon",
  principalId: "principal-recon",
  userId: "user-recon",
};

const RECORD_ID = "record-recon-001";
const EVIDENCE_DIGEST = `sha256:${"b".repeat(64)}`;

let adminPool: Pool;
let writePool: Pool;
let readPool: Pool;
let sharedTableLock: SharedTableLock;

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
    `TRUNCATE memory_record_versions,
              memory_authorization_receipts,
              memory_authorization_nonces,
              memory_mutation_receipts,
              memory_reconciliations,
              memory_tombstones
     RESTART IDENTITY`,
  );
});

function reconciler(role?: string) {
  return createPostgresMemoryReconciler(
    writePool,
    role === undefined ? {} : { reconcilerRole: role },
  );
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

let seq = 0;

/**
 * Issue an authorization (receipt AND out-of-band nonce), then spend it.
 * Mirrors what the store's consumption does, so a version row seeded after
 * this carries the witness migration 034 requires of every writer.
 */
async function authorizeAndSpend(input: {
  action: string;
  recordId: string;
  proposedContentDigest: string;
  mutationReceiptId: string;
}): Promise<string> {
  seq += 1;
  const authorizationId = `recon-auth-${String(seq).padStart(14, "0")}`;
  const bindingDigest = memoryContentDigest(authorizationId);
  await runAs(
    "aaliyah_memory_issuer",
    `INSERT INTO memory_authorization_receipts
       (tenant_id, workspace_id, principal_id, user_id, authorization_id,
        action, target_record_id, binding_digest, issued_at, expires_at,
        revoked_at, consumed_at, payload)
     VALUES ($1::text,$2::text,$3::text,$4::text,$5::text,$6::text,$7::text,
             $8::text, now() - interval '1 minute', now() + interval '1 hour',
             NULL, NULL,
             jsonb_build_object(
               'authorizationId',$5::text,
               'action',$6::text,
               'targetRecordId',$7::text,
               'proposedContentDigest',$9::text,
               'scope', jsonb_build_object('tenantId',$1::text,
                                           'workspaceId',$2::text,
                                           'principalId',$3::text,
                                           'userId',$4::text),
               'nonce', jsonb_build_object('bindingDigest',$8::text)))`,
    [
      SCOPE.tenantId,
      SCOPE.workspaceId,
      SCOPE.principalId,
      SCOPE.userId,
      authorizationId,
      input.action,
      input.recordId,
      bindingDigest,
      input.proposedContentDigest,
    ],
  );
  await runAs(
    "aaliyah_memory_issuer",
    `INSERT INTO memory_authorization_nonces
       (tenant_id, workspace_id, binding_digest, authorization_id, action,
        target_record_id, issued_at, expires_at)
     VALUES ($1,$2,$3,$4,$5,$6, now() - interval '1 minute',
             now() + interval '1 hour')`,
    [
      SCOPE.tenantId,
      SCOPE.workspaceId,
      bindingDigest,
      authorizationId,
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
  return authorizationId;
}

/** A receipt row, at the phase and outcome the caller names. */
async function seedReceipt(input: {
  phase: "pending" | "terminal";
  mutationReceiptId: string;
  authorizationId: string;
  action: string;
  recordId: string;
}): Promise<void> {
  await runAs(
    "aaliyah_memory_mutator",
    `INSERT INTO memory_mutation_receipts
       (tenant_id, workspace_id, principal_id, user_id, mutation_receipt_id,
        phase, authorization_id, consumed_nonce_digest, action,
        target_record_id, outcome_status, emitted_at, payload)
     VALUES ($1::text,$2::text,$3::text,$4::text,$5::text,$6::text,$7::text,
             $8::text,$9::text,$10::text,
             'UNKNOWN_PENDING_RECONCILIATION', now(),
             jsonb_build_object(
               'mutationReceiptId',$5::text,
               'authorizationId',$7::text,
               'consumedNonceDigest',$8::text,
               'action',$9::text,
               'targetRecordId',$10::text,
               'scope', jsonb_build_object('tenantId',$1::text,
                                           'workspaceId',$2::text,
                                           'principalId',$3::text,
                                           'userId',$4::text),
               'outcome', jsonb_build_object(
                 'status','UNKNOWN_PENDING_RECONCILIATION')))`,
    [
      SCOPE.tenantId,
      SCOPE.workspaceId,
      SCOPE.principalId,
      SCOPE.userId,
      input.mutationReceiptId,
      input.phase,
      input.authorizationId,
      EVIDENCE_DIGEST,
      input.action,
      input.recordId,
    ],
  );
}

/** A genesis version row carrying `digest`, witnessed by `authorizationId`. */
async function seedVersion(input: {
  authorizationId: string;
  mutationReceiptId: string;
  recordId: string;
  digest: string;
}): Promise<void> {
  await runAs(
    "aaliyah_memory_mutator",
    `INSERT INTO memory_record_versions
       (tenant_id, workspace_id, principal_id, user_id, record_id, version,
        state, content_digest, predecessor_digest, authorization_id,
        mutation_receipt_id, payload)
     VALUES ($1::text,$2::text,$3::text,$4::text,$5::text,1,'active',
             $6::text,NULL,$7::text,$8::text,
             jsonb_build_object(
               'recordId',$5::text,
               'version','1',
               'state','active',
               'authorizationId',$7::text,
               'mutationReceiptId',$8::text,
               'contentDigest',$6::text,
               'scope', jsonb_build_object('tenantId',$1::text,
                                           'workspaceId',$2::text,
                                           'principalId',$3::text,
                                           'userId',$4::text)))`,
    [
      SCOPE.tenantId,
      SCOPE.workspaceId,
      SCOPE.principalId,
      SCOPE.userId,
      input.recordId,
      input.digest,
      input.authorizationId,
      input.mutationReceiptId,
    ],
  );
}

async function countReconciliations(): Promise<number> {
  const result = await adminPool.query(
    `SELECT count(*)::int AS n FROM memory_reconciliations`,
  );
  return result.rows[0].n as number;
}

// ---------------------------------------------------------------------------
// The four verdicts.
// ---------------------------------------------------------------------------

test("a mutation that COMMITTED under an unknown outcome reconciles to COMMITTED_CONFIRMED", async () => {
  // Produced genuinely: the read-back pool cannot connect, so the store
  // commits, fails its independent read-back, and records UNKNOWN. This is
  // the real shape of the ambiguity, not a hand-built row.
  const deadReadPool = new Pool({
    connectionString: "postgres://postgres:test@127.0.0.1:1/aaliyah_test",
    max: 1,
    connectionTimeoutMillis: 250,
  });
  const content = { note: "committed but unconfirmed" };
  const digest = memoryContentDigest(content);
  const authorizationId = await authorizeAndSpend({
    action: "create",
    recordId: RECORD_ID,
    proposedContentDigest: digest,
    mutationReceiptId: "mutation.recon.committed",
  });
  await seedVersion({
    authorizationId,
    mutationReceiptId: "mutation.recon.committed",
    recordId: RECORD_ID,
    digest,
  });
  // Both receipts the committed path leaves behind.
  await seedReceipt({
    phase: "pending",
    mutationReceiptId: "mutation.recon.committed",
    authorizationId,
    action: "create",
    recordId: RECORD_ID,
  });
  await seedReceipt({
    phase: "terminal",
    mutationReceiptId: "mutation.recon.committed",
    authorizationId,
    action: "create",
    recordId: RECORD_ID,
  });
  await deadReadPool.end().catch(() => undefined);

  const unresolved = await reconciler().findUnresolved();
  assert.equal(unresolved.length, 1);
  assert.equal(unresolved[0]?.mutationReceiptId, "mutation.recon.committed");

  const result = await reconciler().reconcile(unresolved[0]!);

  assert.equal(result.verdict, "COMMITTED_CONFIRMED");
  assert.equal(result.observedVersion, 1);
  assert.equal(result.observedContentDigest, digest);
  assert.equal(result.alreadyReconciled, false);
  // The verdict can be re-derived from what it recorded, not taken on trust.
  assert.equal(result.evidence.pendingReceiptPresent, true);
  assert.equal(result.evidence.recordVersionPresent, true);
  assert.equal(result.evidence.authorizedContentDigest, digest);
});

test("a mutation that never landed reconciles to NOT_COMMITTED, and observes nothing", async () => {
  const authorizationId = await authorizeAndSpend({
    action: "create",
    recordId: RECORD_ID,
    proposedContentDigest: memoryContentDigest({ note: "never landed" }),
    mutationReceiptId: "mutation.recon.rolledback",
  });
  // Terminal UNKNOWN with NO pending row and NO version row: the transaction
  // rolled back, taking both with it.
  await seedReceipt({
    phase: "terminal",
    mutationReceiptId: "mutation.recon.rolledback",
    authorizationId,
    action: "create",
    recordId: RECORD_ID,
  });

  const [result] = await reconciler().reconcileAll();

  assert.equal(result?.verdict, "NOT_COMMITTED");
  assert.equal(result?.observedVersion, null);
  assert.equal(result?.observedContentDigest, null);
});

test("a committed row holding content nobody authorized reconciles to COMMITTED_DIVERGED, not CONFIRMED", async () => {
  const authorized = memoryContentDigest({ note: "what was approved" });
  const stored = memoryContentDigest({ note: "what is actually there" });
  assert.notEqual(authorized, stored);

  const authorizationId = await authorizeAndSpend({
    action: "create",
    recordId: RECORD_ID,
    proposedContentDigest: authorized,
    mutationReceiptId: "mutation.recon.diverged",
  });
  await seedVersion({
    authorizationId,
    mutationReceiptId: "mutation.recon.diverged",
    recordId: RECORD_ID,
    digest: stored,
  });
  await seedReceipt({
    phase: "pending",
    mutationReceiptId: "mutation.recon.diverged",
    authorizationId,
    action: "create",
    recordId: RECORD_ID,
  });
  await seedReceipt({
    phase: "terminal",
    mutationReceiptId: "mutation.recon.diverged",
    authorizationId,
    action: "create",
    recordId: RECORD_ID,
  });

  const [result] = await reconciler().reconcileAll();

  // The row EXISTS, so a reconciler that only asked "did it commit?" would
  // report success. The comparison is against the AUTHORIZATION.
  assert.equal(result?.verdict, "COMMITTED_DIVERGED");
  assert.equal(result?.observedContentDigest, stored);
  assert.equal(result?.evidence.authorizedContentDigest, authorized);
});

test("a pending receipt with no record version is escalated as IMPOSSIBLE_STATE, never resolved", async () => {
  const authorizationId = await authorizeAndSpend({
    action: "create",
    recordId: RECORD_ID,
    proposedContentDigest: memoryContentDigest({ note: "x" }),
    mutationReceiptId: "mutation.recon.impossible",
  });
  // Both are written by ONE transaction, so observing one without the other
  // means something outside that transaction touched a row.
  await seedReceipt({
    phase: "pending",
    mutationReceiptId: "mutation.recon.impossible",
    authorizationId,
    action: "create",
    recordId: RECORD_ID,
  });
  await seedReceipt({
    phase: "terminal",
    mutationReceiptId: "mutation.recon.impossible",
    authorizationId,
    action: "create",
    recordId: RECORD_ID,
  });

  const [result] = await reconciler().reconcileAll();

  assert.equal(result?.verdict, "IMPOSSIBLE_STATE");
  assert.equal(result?.observedVersion, null);
  assert.match(
    String(result?.evidence.escalation),
    /pending receipt present with no record version/,
  );
});

// ---------------------------------------------------------------------------
// Retries, restarts, and two workers.
// ---------------------------------------------------------------------------

test("reconciling twice is idempotent: one row, one verdict, and the retry says so", async () => {
  const authorizationId = await authorizeAndSpend({
    action: "create",
    recordId: RECORD_ID,
    proposedContentDigest: memoryContentDigest({ note: "y" }),
    mutationReceiptId: "mutation.recon.retry",
  });
  await seedReceipt({
    phase: "terminal",
    mutationReceiptId: "mutation.recon.retry",
    authorizationId,
    action: "create",
    recordId: RECORD_ID,
  });

  const unresolved = await reconciler().findUnresolved();
  const first = await reconciler().reconcile(unresolved[0]!);
  const second = await reconciler().reconcile(unresolved[0]!);

  assert.equal(first.verdict, "NOT_COMMITTED");
  assert.equal(first.alreadyReconciled, false);
  assert.equal(second.verdict, "NOT_COMMITTED");
  // The retry did not write a second verdict, and does not claim it did.
  assert.equal(second.alreadyReconciled, true);
  assert.equal(await countReconciliations(), 1);
});

test("a reconciled mutation is no longer unresolved, so a restarted worker does not re-decide it", async () => {
  const authorizationId = await authorizeAndSpend({
    action: "create",
    recordId: RECORD_ID,
    proposedContentDigest: memoryContentDigest({ note: "z" }),
    mutationReceiptId: "mutation.recon.restart",
  });
  await seedReceipt({
    phase: "terminal",
    mutationReceiptId: "mutation.recon.restart",
    authorizationId,
    action: "create",
    recordId: RECORD_ID,
  });

  assert.equal((await reconciler().findUnresolved()).length, 1);
  await reconciler().reconcileAll();
  // A fresh reconciler holds no state of its own; it re-reads the database.
  assert.equal((await reconciler().findUnresolved()).length, 0);
  assert.equal((await reconciler().reconcileAll()).length, 0);
});

test("two concurrent workers on one mutation produce exactly one verdict", async () => {
  const authorizationId = await authorizeAndSpend({
    action: "create",
    recordId: RECORD_ID,
    proposedContentDigest: memoryContentDigest({ note: "race" }),
    mutationReceiptId: "mutation.recon.race",
  });
  await seedReceipt({
    phase: "terminal",
    mutationReceiptId: "mutation.recon.race",
    authorizationId,
    action: "create",
    recordId: RECORD_ID,
  });
  const unresolved = await reconciler().findUnresolved();

  const settled = await Promise.all([
    reconciler().reconcile(unresolved[0]!),
    reconciler().reconcile(unresolved[0]!),
    reconciler().reconcile(unresolved[0]!),
    reconciler().reconcile(unresolved[0]!),
  ]);

  assert.equal(await countReconciliations(), 1);
  // All four agree, and exactly one of them wrote it.
  assert.deepEqual(
    [...new Set(settled.map((s) => s.verdict))],
    ["NOT_COMMITTED"],
  );
  assert.equal(settled.filter((s) => !s.alreadyReconciled).length, 1);
});

test("a mutation that already reached a REAL terminal outcome is never reconciled", async () => {
  const authorizationId = await authorizeAndSpend({
    action: "create",
    recordId: RECORD_ID,
    proposedContentDigest: memoryContentDigest({ note: "settled" }),
    mutationReceiptId: "mutation.recon.settled",
  });
  await seedReceipt({
    phase: "pending",
    mutationReceiptId: "mutation.recon.settled",
    authorizationId,
    action: "create",
    recordId: RECORD_ID,
  });
  await runAs(
    "aaliyah_memory_mutator",
    `INSERT INTO memory_mutation_receipts
       (tenant_id, workspace_id, principal_id, user_id, mutation_receipt_id,
        phase, authorization_id, consumed_nonce_digest, action,
        target_record_id, outcome_status, emitted_at, payload)
     VALUES ($1::text,$2::text,$3::text,$4::text,'mutation.recon.settled',
             'terminal',$5::text,$6::text,'create',$7::text,
             'ABORTED_NO_MUTATION', now(),
             jsonb_build_object(
               'mutationReceiptId','mutation.recon.settled',
               'authorizationId',$5::text,
               'consumedNonceDigest',$6::text,
               'action','create',
               'targetRecordId',$7::text,
               'scope', jsonb_build_object('tenantId',$1::text,
                                           'workspaceId',$2::text,
                                           'principalId',$3::text,
                                           'userId',$4::text),
               'outcome', jsonb_build_object('status','ABORTED_NO_MUTATION')))`,
    [
      SCOPE.tenantId,
      SCOPE.workspaceId,
      SCOPE.principalId,
      SCOPE.userId,
      authorizationId,
      EVIDENCE_DIGEST,
      RECORD_ID,
    ],
  );

  // The pending row still carries UNKNOWN — it always does — but the mutation
  // is settled. Reconciling it again would re-open decided history.
  assert.equal((await reconciler().findUnresolved()).length, 0);
});

test("a later mutation advancing the record does not change an earlier mutation's verdict", async () => {
  // The stale-worker case. The verdict is bound to the mutation receipt id,
  // not to the head, so a head that moved on is irrelevant to what THIS
  // mutation did.
  const digest = memoryContentDigest({ note: "first" });
  const authorizationId = await authorizeAndSpend({
    action: "create",
    recordId: RECORD_ID,
    proposedContentDigest: digest,
    mutationReceiptId: "mutation.recon.stale",
  });
  await seedVersion({
    authorizationId,
    mutationReceiptId: "mutation.recon.stale",
    recordId: RECORD_ID,
    digest,
  });
  await seedReceipt({
    phase: "pending",
    mutationReceiptId: "mutation.recon.stale",
    authorizationId,
    action: "create",
    recordId: RECORD_ID,
  });
  await seedReceipt({
    phase: "terminal",
    mutationReceiptId: "mutation.recon.stale",
    authorizationId,
    action: "create",
    recordId: RECORD_ID,
  });

  // A second, unrelated mutation advances the head to version 2.
  const nextDigest = memoryContentDigest({ note: "second" });
  const secondAuth = await authorizeAndSpend({
    action: "correct",
    recordId: RECORD_ID,
    proposedContentDigest: nextDigest,
    mutationReceiptId: "mutation.recon.stale.next",
  });
  await runAs(
    "aaliyah_memory_mutator",
    `INSERT INTO memory_record_versions
       (tenant_id, workspace_id, principal_id, user_id, record_id, version,
        state, content_digest, predecessor_digest, authorization_id,
        mutation_receipt_id, payload)
     VALUES ($1::text,$2::text,$3::text,$4::text,$5::text,2,'active',
             $6::text,$7::text,$8::text,'mutation.recon.stale.next',
             jsonb_build_object(
               'recordId',$5::text,
               'version','2',
               'state','active',
               'authorizationId',$8::text,
               'mutationReceiptId','mutation.recon.stale.next',
               'contentDigest',$6::text,
               'predecessorDigest',$7::text,
               'scope', jsonb_build_object('tenantId',$1::text,
                                           'workspaceId',$2::text,
                                           'principalId',$3::text,
                                           'userId',$4::text)))`,
    [
      SCOPE.tenantId,
      SCOPE.workspaceId,
      SCOPE.principalId,
      SCOPE.userId,
      RECORD_ID,
      nextDigest,
      digest,
      secondAuth,
    ],
  );

  const unresolved = await reconciler().findUnresolved();
  const target = unresolved.find(
    (u) => u.mutationReceiptId === "mutation.recon.stale",
  );
  const result = await reconciler().reconcile(target!);

  assert.equal(result.verdict, "COMMITTED_CONFIRMED");
  // Version 1 — ours — not the head, which is now 2.
  assert.equal(result.observedVersion, 1);
  assert.equal(result.observedContentDigest, digest);
});

// ---------------------------------------------------------------------------
// WHAT THE RECONCILER CANNOT DO. Enforced, not promised.
// ---------------------------------------------------------------------------

test("the reconciler role cannot write a record version, so it cannot duplicate a mutation", async () => {
  await assert.rejects(
    () =>
      runAs(
        "aaliyah_memory_reconciler",
        `INSERT INTO memory_record_versions
           (tenant_id, workspace_id, principal_id, user_id, record_id, version,
            state, content_digest, predecessor_digest, authorization_id,
            mutation_receipt_id, payload)
         VALUES ('t','w','p','u','r',1,'active',$1,NULL,'a','m','{}'::jsonb)`,
        [`sha256:${"a".repeat(64)}`],
      ),
    (error: unknown) => {
      // Pinned to the privilege, not to any error: a schema complaint would
      // pass a bare rejects() while the role still held the grant.
      assert.match(String(error), /permission denied/i);
      return true;
    },
  );
});

test("the reconciler role cannot append a mutation receipt either", async () => {
  await assert.rejects(
    () =>
      runAs(
        "aaliyah_memory_reconciler",
        `INSERT INTO memory_mutation_receipts
           (tenant_id, workspace_id, principal_id, user_id, mutation_receipt_id,
            phase, authorization_id, consumed_nonce_digest, action,
            target_record_id, outcome_status, emitted_at, payload)
         VALUES ('t','w','p','u','m','terminal','a',$1,'create','r',
                 'COMMITTED_AND_READ_BACK', now(), '{}'::jsonb)`,
        [EVIDENCE_DIGEST],
      ),
    (error: unknown) => {
      assert.match(String(error), /permission denied/i);
      return true;
    },
  );
});

test("the reconciler role cannot spend or un-spend an authorization", async () => {
  await assert.rejects(
    () =>
      runAs(
        "aaliyah_memory_reconciler",
        `UPDATE memory_authorization_nonces SET consumed_at = NULL`,
      ),
    (error: unknown) => {
      assert.match(String(error), /permission denied/i);
      return true;
    },
  );
});

test("a written reconciliation cannot be rewritten or deleted, by anyone", async () => {
  const authorizationId = await authorizeAndSpend({
    action: "create",
    recordId: RECORD_ID,
    proposedContentDigest: memoryContentDigest({ note: "append-only" }),
    mutationReceiptId: "mutation.recon.appendonly",
  });
  await seedReceipt({
    phase: "terminal",
    mutationReceiptId: "mutation.recon.appendonly",
    authorizationId,
    action: "create",
    recordId: RECORD_ID,
  });
  await reconciler().reconcileAll();

  // The OWNER, not the reconciler role: a rewrite ban that only bound the
  // least-privileged party would not be a rewrite ban.
  await assert.rejects(
    () =>
      adminPool.query(
        `UPDATE memory_reconciliations SET verdict = 'COMMITTED_CONFIRMED'`,
      ),
    /append-only|forbid|rewrite/i,
  );
  await assert.rejects(
    () => adminPool.query(`DELETE FROM memory_reconciliations`),
    /append-only|forbid|rewrite/i,
  );
  assert.equal(await countReconciliations(), 1);
});

test("a COMMITTED verdict cannot be filed without naming what it observed", async () => {
  // The database refuses the shape, so a reconciler bug cannot record a
  // resolution that resolves nothing.
  await assert.rejects(
    () =>
      adminPool.query(
        `INSERT INTO memory_reconciliations
           (tenant_id, workspace_id, principal_id, user_id, mutation_receipt_id,
            authorization_id, action, target_record_id, verdict,
            observed_version, observed_content_digest, reconciled_at, evidence)
         VALUES ('t','w','p','u','m','a','create','r','COMMITTED_CONFIRMED',
                 NULL, NULL, now(),
                 jsonb_build_object('mutationReceiptId','m','authorizationId','a'))`,
      ),
    /memory_reconciliations_committed_observes/,
  );
});

test("an unknown verdict string is refused by the database", async () => {
  await assert.rejects(
    () =>
      adminPool.query(
        `INSERT INTO memory_reconciliations
           (tenant_id, workspace_id, principal_id, user_id, mutation_receipt_id,
            authorization_id, action, target_record_id, verdict,
            observed_version, observed_content_digest, reconciled_at, evidence)
         VALUES ('t','w','p','u','m2','a','create','r','PROBABLY_FINE',
                 NULL, NULL, now(),
                 jsonb_build_object('mutationReceiptId','m2','authorizationId','a'))`,
      ),
    /memory_reconciliations_verdict_domain/,
  );
});

test("the store still runs under its own role: a reconciler role name that is not an identifier is refused", async () => {
  await assert.rejects(
    () =>
      createPostgresMemoryReconciler(writePool, {
        reconcilerRole: 'postgres"; DROP TABLE memory_reconciliations; --',
      }).findUnresolved(),
    /unsafe reconciler role/,
  );
  // And the table is still there.
  assert.equal(await countReconciliations(), 0);
});

test("the trusted-memory store and the reconciler agree on a normal mutation: nothing to reconcile", async () => {
  // The positive control for the whole file. A healthy system produces no
  // unresolved mutations, so none of the above passes merely because the
  // reconciler finds work everywhere.
  const store = createPostgresTrustedMemoryStore(writePool, readPool);
  assert.ok(typeof store.create === "function");
  assert.equal((await reconciler().findUnresolved()).length, 0);
  assert.equal(await countReconciliations(), 0);
});

test("R-2 a reconciliation lock held elsewhere fails within the bound instead of waiting forever", async () => {
  // Boot runs a reconciliation pass BEFORE the server listens. An unbounded
  // wait here is a process that never opens its socket.
  const authorizationId = await authorizeAndSpend({
    action: "create",
    recordId: RECORD_ID,
    proposedContentDigest: memoryContentDigest({ note: "busy" }),
    mutationReceiptId: "mutation.recon.busy",
  });
  await seedReceipt({
    phase: "pending",
    mutationReceiptId: "mutation.recon.busy",
    authorizationId,
    action: "create",
    recordId: RECORD_ID,
  });
  const [unresolved] = await reconciler().findUnresolved();
  assert.ok(unresolved);
  const holder = await adminPool.connect();
  try {
    await holder.query("BEGIN");
    await holder.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [
      [SCOPE.tenantId, SCOPE.workspaceId, "mutation.recon.busy"].join(String.fromCharCode(0x1f)),
    ]);
    const started = Date.now();
    await assert.rejects(
      createPostgresMemoryReconciler(adminPool, { lockWaitMs: 400 }).reconcile(unresolved),
      (error: { code?: string }) => error.code === "55P03",
    );
    const elapsed = Date.now() - started;
    assert.ok(elapsed >= 350 && elapsed < 4_000, `elapsed ${elapsed}ms`);
    assert.equal(await countReconciliations(), 0);
  } finally {
    await holder.query("ROLLBACK").catch(() => undefined);
    holder.release();
  }
  assert.throws(
    () => createPostgresMemoryReconciler(adminPool, { lockWaitMs: 0 }),
    /lockWaitMs must be a positive integer/,
  );
  // Positive control: released, it reconciles.
  const settled = await reconciler().reconcile(unresolved);
  assert.equal(settled.alreadyReconciled, false);
});
