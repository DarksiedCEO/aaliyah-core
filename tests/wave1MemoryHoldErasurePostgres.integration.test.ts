import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test, { after, before, beforeEach } from "node:test";
import { Pool } from "pg";

import { enterMemoryRole } from "../src/persistence/postgres/pool";
import { settlementEvidenceDigest } from "../src/persistence/postgres/wave1TrustedMemoryStore";

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
  MemoryAliasPiiErased,
  aliasAssignmentCommitment,
  aliasAssignmentDigest,
  aliasRemovalDigest,
} from "../src/application/memory/wave1AliasRegistry";
import {
  MemoryPiiEnvelopeInvalid,
  MemoryPiiKeyDestroyed,
  MemoryPiiScopeMismatch,
  aliasEnvelopeAssociatedData,
  createLocalTestPiiKeyProvider,
  type PiiEnvelope,
} from "../src/crypto/memoryPiiKeys";
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
import { MEMORY_IDENTITY_MERGE_ORDER_SCHEMA_VERSION } from "../src/application/memory/wave1MemoryIdentity";
import { createPostgresAliasRegistryStore } from "../src/persistence/postgres/wave1AliasRegistryStore";
import { createPostgresWave1MemoryService } from "../src/persistence/postgres/wave1IdentityGraphStore";
import { createPostgresLegalHoldStore } from "../src/persistence/postgres/wave1LegalHoldStore";
import { createPostgresTrustedMemoryStore } from "../src/persistence/postgres/wave1TrustedMemoryStore";
import {
  lockSharedMemoryTables,
  type SharedTableLock,
} from "./support/sharedMemoryTables";
import { TEST_PII_KEYS, testAliasAssignmentDigest } from "./support/piiKeys";
import { assertCheckConstraintsKill, assertUniqueIndexKills } from "./support/uniquenessDestroyer";

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
  return createPostgresTrustedMemoryStore(writePool, readPool, { piiKeys: TEST_PII_KEYS });
}

function holds() {
  return createPostgresLegalHoldStore(writePool, readPool);
}

function aliases() {
  return createPostgresAliasRegistryStore(writePool, readPool, { piiKeys: TEST_PII_KEYS });
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
    options: `${process.env.PGOPTIONS ?? ""} -c search_path=${EMPTY_TOMBSTONE_SCHEMA},public`,
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
              memory_mutation_attempts,
              memory_alias_bindings,
              memory_alias_blind_indexes,
              memory_pii_key_erasures,
              memory_alias_tenant_policy,
              memory_alias_protected_domains,
              memory_tombstones,
              memory_identity_edges,
              memory_legal_hold_carve_outs,
              memory_legal_hold_records,
              memory_legal_hold_subjects,
              memory_legal_holds,
              memory_retention_obligations,
              memory_key_destruction_settlements,
              memory_key_destruction_obligations,
              memory_pii_key_audits
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
              memory_mutation_attempts,
              memory_alias_bindings,
              memory_alias_blind_indexes,
              memory_pii_key_erasures,
              memory_alias_tenant_policy,
              memory_alias_protected_domains,
              memory_tombstones,
              memory_identity_edges,
              memory_legal_hold_carve_outs,
              memory_legal_hold_records,
              memory_legal_hold_subjects,
              memory_legal_holds,
              memory_retention_obligations,
              memory_key_destruction_settlements,
              memory_key_destruction_obligations,
              memory_pii_key_audits
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
  | "remove_alias"
  | "merge_identity";

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
  // THE AUTHORIZATION THAT WITNESSES A GENESIS MUST NAME ITS SCOPE.
  //
  // Migration 039 binds version 1's (tenant, workspace, principal, user) to
  // the receipt its authorization id resolves to. Seeding a chain root with a
  // spent nonce and no stored authorization is exactly the shape the security
  // review forged, so the fixture issues the receipt too rather than writing
  // rows the protocol could not have written.
  await runAs(
    "aaliyah_memory_issuer",
    `INSERT INTO memory_authorization_receipts
       (tenant_id, workspace_id, principal_id, user_id, authorization_id,
        action, target_record_id, binding_digest, issued_at, expires_at,
        revoked_at, consumed_at, payload)
     VALUES ($1::text,$2::text,$3::text,$4::text,$5::text,$6::text,
             $7::text,$8::text,
             now() - interval '1 minute', now() + interval '1 hour',
             NULL, NULL,
             jsonb_build_object(
               'authorizationId', $5::text,
               'action', $6::text,
               'targetRecordId', $7::text,
               'scope', jsonb_build_object('tenantId',$1::text,
                                           'workspaceId',$2::text,
                                           'principalId',$3::text,
                                           'userId',$4::text),
               'nonce', jsonb_build_object('bindingDigest',$8::text)))
     ON CONFLICT DO NOTHING`,
    [
      scope.tenantId,
      scope.workspaceId,
      scope.principalId,
      scope.userId,
      input.authorizationId,
      input.action,
      input.recordId,
      bindingDigest,
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
      proposedContentDigest: await testAliasAssignmentDigest({
        record: content,
        alias: alias,
        evidence: evidence,
        scope: SCOPE,
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
            cross_workspace_policy, scope_key, alias_id,
            skeleton_algorithm, normalization_profile,
            canonical_participant_id, script_code,
            restriction_level, subject_participant_id, source_evidence_ref,
            source_evidence_digest, observed_at, fresh_until, authorization_id,
            mutation_receipt_id, bound_at, payload,
            pii_envelope, pii_key_ref, pii_key_version)
         VALUES ($1,$2,$3,$4,'workspace_isolated',$5,'alias-hostile-001',
                 $6,$7,$8,
                 'Latn','ascii_only',$8,'identity:verification/x',$9,
                 now() - interval '1 minute', now() + interval '1 hour',
                 $10,$11, now(), $12,
                 '{"keyRef":"pii-key:raw","keyVersion":1}'::jsonb,'pii-key:raw',1)`,
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
  // ---- HOW THE READ-BACK IS BLINDED, AND WHY IT CHANGED -------------
  // This used to point the read-back pool at a shadow schema holding an empty
  // `memory_tombstones`, via `search_path`. That fixture stopped working
  // because the defect it relied on was FIXED: `enterMemoryRole` now pins
  // `search_path` to `pg_catalog, public, pg_temp`, so no injected schema is
  // on the path at all (red team B2 / security NEW-1, K-07).
  //
  // The property under test is unchanged and still load-bearing, so the
  // blinding is now a PRIVILEGE rather than a name-resolution trick — which is
  // strictly harder to talk your way around. SELECT on `memory_tombstones` is
  // revoked from the read-back role for the duration, so the tombstone read is
  // denied while the head read-back (a different table) still works, which is
  // exactly the half-blind state the property is about. The whole file holds
  // the shared-table lock, so this catalog change cannot be observed by
  // another file on this database.
  await adminPool.query(
    `REVOKE SELECT ON memory_tombstones FROM aaliyah_memory_reader`,
  );
  let result;
  try {
    const blind = createPostgresTrustedMemoryStore(writePool, readPool);
    result = await blind.delete({
      actor: SCOPE,
      authorizationId: receipt.authorizationId,
      recordId: RECORD_ID,
      proposedContent: order,
      mutationReceiptId: "mutation.blindreadback.1",
      tombstoneId: "tombstone-blind-001",
    });
  } finally {
    await adminPool.query(
      `GRANT SELECT ON memory_tombstones TO aaliyah_memory_reader`,
    );
  }
  assert.equal(result.verified, false);
  assert.equal(result.rejection, "erasure_incomplete");
  assert.equal(result.tombstone, null);
  // POSITIVE CONTROL: with the grant restored, the very same accounting reads
  // back — so the refusal above is the blinding and not the deletion.
  assert.notEqual(await store().readTombstone(SCOPE, "tombstone-blind-001"), null);
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

test("U-3 every tombstone, legal-hold and retention unique index refuses the one duplicate it exists for", async () => {
  // Real rows: an honest deletion, three holds covering records, subjects and
  // a carve-out, and a retention obligation — each through its own store.
  await deleteThen("mutation.unique.delete", "tombstone-unique-001");
  await placeHold(legalHold({ coverage: { kind: "records", recordIds: [FREE_RECORD_ID] }, holdId: "hold-unique-records", carveOutActions: ["promote"] }));
  await placeHold(legalHold({ coverage: { kind: "subjects", canonicalParticipantIds: ["participant-unique-001"] }, holdId: "hold-unique-subjects" }));
  const imposed = await holds().imposeRetention(SCOPE, {
    obligationId: "retention-unique-001",
    recordId: FREE_RECORD_ID,
    policyRef: "policy:retention/seven-years",
    imposingAuthorityId: "authority.records-manager",
    imposedAt: isoOffset(-60_000),
    retainUntil: isoOffset(3_600_000),
  });
  assert.equal(imposed.rejection, null);

  await assertUniqueIndexKills(adminPool, {
    table: "memory_tombstones",
    index: "memory_tombstones_unique",
    where: "tombstone_id = $1",
    params: ["tombstone-unique-001"],
    freshen: (row) => ({
      mutation_receipt_id: "mutation.unique.dup",
      tombstone_version: Number(row.tombstone_version) + 10,
      target_version: Number(row.target_version) + 10,
      payload: { tombstoneVersion: Number(row.tombstone_version) + 10, targetVersion: Number(row.target_version) + 10 },
    }),
    positive: (row) => ({
      mutation_receipt_id: "mutation.unique.dup",
      tombstone_version: Number(row.tombstone_version) + 10,
      target_version: Number(row.target_version) + 10,
      tombstone_id: "tombstone-unique-dup",
      payload: { tombstoneVersion: Number(row.tombstone_version) + 10, targetVersion: Number(row.target_version) + 10, tombstoneId: "tombstone-unique-dup" },
    }),
  });
  await assertUniqueIndexKills(adminPool, {
    table: "memory_tombstones",
    index: "memory_tombstones_version_unique",
    where: "tombstone_id = $1",
    params: ["tombstone-unique-001"],
    freshen: () => ({ mutation_receipt_id: "mutation.unique.dup", tombstone_id: "tombstone-unique-dup", payload: { tombstoneId: "tombstone-unique-dup" } }),
    positive: (row) => ({
      mutation_receipt_id: "mutation.unique.dup",
      tombstone_id: "tombstone-unique-dup",
      tombstone_version: Number(row.tombstone_version) + 10,
      target_version: Number(row.target_version) + 10,
      payload: { tombstoneId: "tombstone-unique-dup", tombstoneVersion: Number(row.tombstone_version) + 10, targetVersion: Number(row.target_version) + 10 },
    }),
  });
  await assertUniqueIndexKills(adminPool, {
    table: "memory_tombstones",
    index: "memory_tombstones_receipt_unique",
    where: "tombstone_id = $1",
    params: ["tombstone-unique-001"],
    freshen: (row) => ({
      tombstone_id: "tombstone-unique-dup",
      tombstone_version: Number(row.tombstone_version) + 10,
      target_version: Number(row.target_version) + 10,
      payload: { tombstoneId: "tombstone-unique-dup", tombstoneVersion: Number(row.tombstone_version) + 10, targetVersion: Number(row.target_version) + 10 },
    }),
    positive: (row) => ({
      tombstone_id: "tombstone-unique-dup",
      tombstone_version: Number(row.tombstone_version) + 10,
      target_version: Number(row.target_version) + 10,
      mutation_receipt_id: "mutation.unique.dup",
      payload: { tombstoneId: "tombstone-unique-dup", tombstoneVersion: Number(row.tombstone_version) + 10, targetVersion: Number(row.target_version) + 10 },
    }),
  });
  await assertUniqueIndexKills(adminPool, {
    table: "memory_legal_holds",
    index: "memory_legal_holds_unique",
    where: "hold_id = $1",
    params: ["hold-unique-records"],
    freshen: () => ({}),
    positive: () => ({ hold_id: "hold-unique-dup", payload: { holdId: "hold-unique-dup" } }),
  });
  await assertUniqueIndexKills(adminPool, {
    table: "memory_legal_hold_records",
    index: "memory_legal_hold_records_unique",
    where: "hold_id = $1",
    params: ["hold-unique-records"],
    freshen: () => ({}),
    positive: () => ({ record_id: "record-unique-other" }),
  });
  await assertUniqueIndexKills(adminPool, {
    table: "memory_legal_hold_subjects",
    index: "memory_legal_hold_subjects_unique",
    where: "hold_id = $1",
    params: ["hold-unique-subjects"],
    freshen: () => ({}),
    positive: () => ({ canonical_participant_id: "participant-unique-other" }),
  });
  await assertUniqueIndexKills(adminPool, {
    table: "memory_legal_hold_carve_outs",
    index: "memory_legal_hold_carve_outs_unique",
    where: "hold_id = $1",
    params: ["hold-unique-records"],
    freshen: () => ({}),
    positive: () => ({ action: "restore" }),
  });
  await assertUniqueIndexKills(adminPool, {
    table: "memory_retention_obligations",
    index: "memory_retention_obligations_unique",
    where: "obligation_id = $1",
    params: ["retention-unique-001"],
    freshen: () => ({}),
    positive: () => ({ obligation_id: "retention-unique-dup" }),
  });
});

test("U-3 memory_legal_holds_fk_target is STRUCTURALLY REDUNDANT as a uniqueness control, and the premise is pinned", async () => {
  // (tenant, workspace, hold_id, coverage_kind) is a superset of
  // `memory_legal_holds_unique`'s (tenant, workspace, hold_id): no duplicate
  // can reach it alone. It exists as the target of the coverage-kind foreign
  // keys, which is proven by those foreign keys refusing a mismatched child —
  // not by uniqueness. Disclosed survivor for a DROP INDEX; the premise is
  // what is pinned here.
  const found = await adminPool.query(
    `SELECT pg_get_indexdef(ix.indexrelid) AS def, ix.indisunique
       FROM pg_index ix JOIN pg_class i ON i.oid = ix.indexrelid
      WHERE i.relname = 'memory_legal_holds_unique'`,
  );
  assert.equal(found.rows[0]?.indisunique, true);
  assert.match(found.rows[0]?.def as string, /\(tenant_id, workspace_id, hold_id\)$/);
});

// ---------------------------------------------------------------------------
// P — ALIAS PII ERASURE (red team BREAK 4 against b3efc82; founder decision).
//
// Every test here asks one question of the WHOLE database, not of one column:
// after an authorized erasure, can the address be recovered, confirmed, or
// read from anywhere this system stores data? Plus the refusals: a hold, a
// retention obligation, a crash, an unavailable provider — none of which may
// be reported as an erasure.
// ---------------------------------------------------------------------------

const VICTIM_ADDRESS = "Victim.Person@Example.com";
const VICTIM_NORMALIZED = "victim.person@example.com";

/** Every text, varchar and jsonb column of every public table that contains `needle`. */
async function plaintextSightings(needle: string): Promise<string[]> {
  const columns = await adminPool.query(
    `SELECT table_name, column_name
       FROM information_schema.columns
      WHERE table_schema = 'public'
        AND data_type IN ('text', 'jsonb', 'character varying', 'json')`,
  );
  const hits: string[] = [];
  for (const { table_name, column_name } of columns.rows as Array<{ table_name: string; column_name: string }>) {
    const found = await adminPool.query(
      `SELECT count(*)::int AS n FROM public."${table_name}"
        WHERE strpos(lower("${column_name}"::text), lower($1)) > 0`,
      [needle],
    );
    if ((found.rows[0].n as number) > 0) hits.push(`${table_name}.${column_name}`);
  }
  return hits;
}

/** Bind VICTIM_ADDRESS to PARTICIPANT through the honest path. */
async function bindVictimAddress(aliasId = "alias-pii-001") {
  const prepared = await prepareAssign(aliasId, VICTIM_ADDRESS);
  const bound = await aliases().assignAlias({
    actor: SCOPE,
    authorizationId: prepared.receipt.authorizationId,
    participantRecordId: PARTICIPANT,
    alias: prepared.alias,
    evidence: prepared.evidence,
    proposedContent: prepared.content,
    mutationReceiptId: `mutation.pii.bind.${aliasId}`,
  });
  assert.equal(bound.verified, true, bound.rejection ?? "");
  return prepared;
}

/** Issue a subject-erasure deletion of PARTICIPANT at its current head. */
async function eraseParticipant(receiptId: string, tombstoneId: string) {
  const head = await store().readHead(SCOPE, PARTICIPANT);
  assert.ok(head);
  const order = deletionOrder("subject_erasure_request");
  const receipt = await issue(
    authorization({
      action: "delete",
      targetRecordId: PARTICIPANT,
      expectedHead: headOf(head.version, head.contentDigest),
      proposedContent: order,
    }),
  );
  return {
    receipt,
    result: await store().delete({
      actor: SCOPE,
      authorizationId: receipt.authorizationId,
      recordId: PARTICIPANT,
      proposedContent: order,
      mutationReceiptId: receiptId,
      tombstoneId,
    }),
  };
}

async function bindingState(aliasId: string) {
  const row = await adminPool.query(
    `SELECT pii_envelope, pii_key_ref, pii_key_version, pii_erased_at,
            pii_erasure_tombstone_id, removed_at, mutation_receipt_id, alias_id
       FROM memory_alias_bindings WHERE alias_id = $1`,
    [aliasId],
  );
  return row.rows[0] as {
    pii_envelope: unknown;
    pii_key_ref: string;
    pii_key_version: number;
    alias_id: string;
    pii_erased_at: Date | null;
    pii_erasure_tombstone_id: string | null;
    removed_at: Date | null;
    mutation_receipt_id: string;
  };
}

async function indexValues(bindingReceiptId: string): Promise<Array<string | null>> {
  const rows = await adminPool.query(
    `SELECT index_value FROM memory_alias_blind_indexes
      WHERE binding_mutation_receipt_id = $1 ORDER BY id`,
    [bindingReceiptId],
  );
  return rows.rows.map((r: { index_value: string | null }) => r.index_value);
}

const DATA_SCOPE = { tenantId: SCOPE.tenantId, workspaceId: SCOPE.workspaceId };

async function nonceConsumedAt(bindingDigest: string): Promise<Date | null> {
  const result = await adminPool.query(
    `SELECT consumed_at FROM memory_authorization_nonces WHERE binding_digest = $1`,
    [bindingDigest],
  );
  return (result.rows[0]?.consumed_at as Date | null) ?? null;
}

test("P-1 BREAK 4: a subject erasure destroys the address EVERYWHERE the database stores data, and says so", async () => {
  await bindVictimAddress();
  // Sanity: the alias resolves before erasure, and NOT because it is stored in
  // plaintext — the address is nowhere in the database even while live.
  assert.equal((await aliases().resolveAlias(SCOPE, VICTIM_NORMALIZED))?.binding.canonicalParticipantId, PARTICIPANT);
  assert.deepEqual(await plaintextSightings(VICTIM_NORMALIZED), []);
  assert.deepEqual(await plaintextSightings("victim.person"), []);

  const { result } = await eraseParticipant("mutation.pii.erase.1", "tombstone-pii-001");
  assert.equal(result.verified, true, result.rejection ?? "");
  assert.deepEqual(result.aliasErasure, {
    bindingsErased: 1,
    keysDestroyed: 1,
    keysPending: 0,
    keysNotProven: 0,
    notProvenReasons: {},
  });

  // EXECUTED against b3efc82: `resolveAlias` still answered with the address.
  assert.equal(await aliases().resolveAlias(SCOPE, VICTIM_NORMALIZED), null);
  await assert.rejects(
    aliases().readAliasBinding(SCOPE, "alias-pii-001"),
    (error: unknown) => error instanceof MemoryAliasPiiErased && error.erasureTombstoneId === "tombstone-pii-001",
  );
  assert.deepEqual(await plaintextSightings(VICTIM_NORMALIZED), []);
  assert.deepEqual(await plaintextSightings("victim.person"), []);
  const state = await bindingState("alias-pii-001");
  assert.equal(state.pii_envelope, null);
  assert.ok(state.pii_erased_at !== null && state.removed_at !== null);
  // The non-PII evidence that it happened survives.
  const events = await adminPool.query(
    `SELECT event FROM memory_pii_key_erasures WHERE tombstone_id = 'tombstone-pii-001' ORDER BY id`,
  );
  assert.deepEqual(events.rows.map((r: { event: string }) => r.event), ["erasure_committed", "key_destroyed"]);
});

test("P-2 a ciphertext COPY taken before erasure — a backup, a replica — no longer decrypts", async () => {
  await bindVictimAddress();
  const before = await bindingState("alias-pii-001");
  const copied = before.pii_envelope as PiiEnvelope;
  assert.ok(!JSON.stringify(copied).toLowerCase().includes("victim"));
  const { result } = await eraseParticipant("mutation.pii.erase.2", "tombstone-pii-002");
  assert.equal(result.verified, true);
  await assert.rejects(
    TEST_PII_KEYS.decrypt({
      scope: DATA_SCOPE,
      envelope: copied,
      associatedData: aliasEnvelopeAssociatedData({
        tenantId: SCOPE.tenantId,
        workspaceId: SCOPE.workspaceId,
        aliasId: "alias-pii-001",
        mutationReceiptId: before.mutation_receipt_id,
      }),
    }),
    MemoryPiiKeyDestroyed,
  );
  assert.equal(await TEST_PII_KEYS.dataKeyState({ scope: DATA_SCOPE, keyRef: before.pii_key_ref }), "destroyed");
});

test("P-3 the blind index is not queryable after erasure, even by someone holding the index key", async () => {
  const prepared = await bindVictimAddress();
  const bindingReceipt = (await bindingState("alias-pii-001")).mutation_receipt_id;
  const live = await indexValues(bindingReceipt);
  assert.equal(live.length, 2);
  assert.ok(live.every((value) => value !== null && /^bi1\./.test(value)));
  // A raw SHA-256 of the address, the dictionary attack, is not what is stored.
  assert.ok(!live.includes(createHash("sha256").update(VICTIM_NORMALIZED).digest("base64url")));
  const { result } = await eraseParticipant("mutation.pii.erase.3", "tombstone-pii-003");
  assert.equal(result.verified, true);
  assert.deepEqual(await indexValues(bindingReceipt), [null, null]);
  const recomputed = await TEST_PII_KEYS.blindIndexesForLookup({
    scope: { tenantId: SCOPE.tenantId, scopeKey: SCOPE.workspaceId },
    purpose: "alias.normalized",
    value: prepared.alias.normalizedAlias,
  });
  const stillThere = await adminPool.query(
    `SELECT count(*)::int AS n FROM memory_alias_blind_indexes WHERE index_value = ANY($1::text[])`,
    [recomputed],
  );
  assert.equal(stillThere.rows[0].n, 0);
});

test("P-4 a LEGAL HOLD on the subject refuses erasure: nothing is erased, nothing is reported erased, the key lives", async () => {
  await bindVictimAddress();
  await placeHold(legalHold({ coverage: { kind: "subjects", canonicalParticipantIds: [PARTICIPANT] } }));
  const before = await bindingState("alias-pii-001");
  const { result } = await eraseParticipant("mutation.pii.held", "tombstone-pii-held");
  assert.equal(result.verified, false);
  assert.equal(result.rejection, "legal_hold_active");
  assert.equal(result.aliasErasure, null);
  const after = await bindingState("alias-pii-001");
  assert.notEqual(after.pii_envelope, null);
  assert.equal(after.pii_erased_at, null);
  assert.equal(await TEST_PII_KEYS.dataKeyState({ scope: DATA_SCOPE, keyRef: before.pii_key_ref }), "active");
  assert.equal((await aliases().resolveAlias(SCOPE, VICTIM_NORMALIZED))?.binding.normalizedAlias, VICTIM_NORMALIZED);
});

test("P-5 an unexpired RETENTION obligation refuses erasure, and it is never reported as erased", async () => {
  await bindVictimAddress();
  const imposed = await holds().imposeRetention(SCOPE, {
    obligationId: "retention-pii-001",
    recordId: PARTICIPANT,
    policyRef: "policy:retention/seven-years",
    imposingAuthorityId: "authority.records-manager",
    imposedAt: isoOffset(-60_000),
    retainUntil: isoOffset(3_600_000),
  });
  assert.equal(imposed.rejection, null);
  const { result } = await eraseParticipant("mutation.pii.retained", "tombstone-pii-retained");
  assert.equal(result.verified, false);
  assert.equal(result.rejection, "retention_obligation_active");
  assert.equal(result.aliasErasure, null);
  assert.notEqual((await bindingState("alias-pii-001")).pii_envelope, null);
  const committed = await adminPool.query(`SELECT count(*)::int AS n FROM memory_pii_key_erasures`);
  assert.equal(committed.rows[0].n, 0);
});

test("P-6 a CRASH mid-erasure leaves nothing half-erased: the whole transaction, alias half included, rolls back", async () => {
  await bindVictimAddress();
  const before = await bindingState("alias-pii-001");
  // A failure injected at COMMIT, after the binding and index updates and the
  // erasure record were all written inside the deleting transaction.
  await adminPool.query(`
    CREATE OR REPLACE FUNCTION public.test_crash_at_commit() RETURNS trigger
      LANGUAGE plpgsql AS $fn$ BEGIN RAISE EXCEPTION 'injected crash at commit'; END; $fn$;
    DROP TRIGGER IF EXISTS test_crash_at_commit ON memory_pii_key_erasures;
    CREATE CONSTRAINT TRIGGER test_crash_at_commit AFTER INSERT ON memory_pii_key_erasures
      DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.test_crash_at_commit();`);
  try {
    const { result } = await eraseParticipant("mutation.pii.crash", "tombstone-pii-crash");
    assert.equal(result.verified, false);
    assert.notEqual(result.rejection, null);
  } finally {
    await adminPool.query(`DROP TRIGGER IF EXISTS test_crash_at_commit ON memory_pii_key_erasures;
      DROP FUNCTION IF EXISTS public.test_crash_at_commit();`);
  }
  const after = await bindingState("alias-pii-001");
  assert.deepEqual(after.pii_envelope, before.pii_envelope);
  assert.equal(after.pii_erased_at, null);
  assert.equal((await indexValues(after.mutation_receipt_id)).filter((v) => v === null).length, 0);
  assert.equal(await TEST_PII_KEYS.dataKeyState({ scope: DATA_SCOPE, keyRef: before.pii_key_ref }), "active");
  // And the retry, with a fresh authorization, erases completely.
  const retried = await eraseParticipant("mutation.pii.crash.retry", "tombstone-pii-crash-retry");
  assert.equal(retried.result.verified, true, retried.result.rejection ?? "");
});

test("P-7 an UNAVAILABLE key provider: the database half commits, the deletion is NOT reported erased, and completion finishes it", async () => {
  await bindVictimAddress();
  const before = await bindingState("alias-pii-001");
  TEST_PII_KEYS.setAvailable(false);
  let result;
  try {
    ({ result } = await eraseParticipant("mutation.pii.outage", "tombstone-pii-outage"));
  } finally {
    TEST_PII_KEYS.setAvailable(true);
  }
  assert.equal(result.verified, false);
  // FOUNDER DECISION, OPTION B: a provider outage is one of the conditions in
  // which destruction cannot be PROVEN, so the subject is not erased and the
  // answer says which of the two it is. `erasure_incomplete` would say "not
  // finished yet" about a state that is "not establishable from here".
  assert.equal(result.rejection, "key_destruction_not_proven");
  assert.deepEqual(result.aliasErasure, {
    bindingsErased: 1,
    keysDestroyed: 0,
    keysPending: 1,
    keysNotProven: 1,
    notProvenReasons: { PROVIDER_UNAVAILABLE: 1 },
  });
  // The database has forgotten; the key has not been destroyed yet.
  assert.equal((await bindingState("alias-pii-001")).pii_envelope, null);
  assert.equal(await TEST_PII_KEYS.dataKeyState({ scope: DATA_SCOPE, keyRef: before.pii_key_ref }), "active");

  const completed = await store().completePendingAliasErasures();
  assert.deepEqual(completed, { destroyed: 1, repaired: 0, contradictions: 0, pending: 0, notProven: 0, notProvenReasons: {} });
  assert.equal(await TEST_PII_KEYS.dataKeyState({ scope: DATA_SCOPE, keyRef: before.pii_key_ref }), "destroyed");
  // Idempotent.
  assert.deepEqual(await store().completePendingAliasErasures(), { destroyed: 0, repaired: 0, contradictions: 0, pending: 0, notProven: 0, notProvenReasons: {} });
});

test("P-8 the DATABASE refuses to commit a deletion that leaves the subject's alias unerased, whoever writes it", async () => {
  await bindVictimAddress();
  // An honest deletion of ANOTHER record supplies a structurally valid
  // tombstone row to copy; the copy is aimed at PARTICIPANT, whose alias is
  // still live, with every other tombstone guard stood down so the deferred
  // alias check is the only thing left that can refuse the COMMIT.
  await deleteThen("mutation.pii.other-delete", "tombstone-pii-other");
  const client = await adminPool.connect();
  try {
    await client.query("BEGIN");
    await client.query(`ALTER TABLE memory_tombstones
      DISABLE TRIGGER memory_tombstones_structural,
      DISABLE TRIGGER memory_tombstones_zz_authorization_scope`);
    await client.query(
      `INSERT INTO memory_tombstones
         (tenant_id, workspace_id, principal_id, user_id, tombstone_id, target_record_id,
          target_version, tombstone_version, authorization_id, mutation_receipt_id, reason,
          effective_at, retain_until, legal_hold_state, cache_index_propagation,
          restoration_eligibility_kind, tombstone_digest, payload)
       SELECT tenant_id, workspace_id, principal_id, user_id, 'tombstone-pii-forged', $1,
              target_version, tombstone_version, authorization_id, 'mutation.pii.forged', reason,
              effective_at, retain_until, legal_hold_state, cache_index_propagation,
              restoration_eligibility_kind, tombstone_digest,
              jsonb_set(jsonb_set(payload, '{tombstoneId}', '"tombstone-pii-forged"'),
                        '{targetRecordId}', to_jsonb($1::text))
         FROM memory_tombstones WHERE tombstone_id = 'tombstone-pii-other'`,
      [PARTICIPANT],
    );
    await assert.rejects(client.query("COMMIT"), /a deleted participant may not keep an unerased alias/);
  } finally {
    await client.query("ROLLBACK").catch(() => undefined);
    client.release();
  }
  assert.notEqual((await bindingState("alias-pii-001")).pii_envelope, null);
});

test("P-9 an erasure UPDATE with no tombstone of the participant behind it is refused, for the mutation role", async () => {
  await bindVictimAddress();
  await assert.rejects(
    () =>
      runAs(
        "aaliyah_memory_mutator",
        `UPDATE memory_alias_bindings
            SET pii_envelope = NULL, pii_erased_at = now(),
                pii_erasure_tombstone_id = 'tombstone-never-written', removed_at = now()
          WHERE alias_id = 'alias-pii-001'`,
      ),
    /no tombstone of this participant witnesses this erasure/,
  );
  assert.notEqual((await bindingState("alias-pii-001")).pii_envelope, null);
});

test("P-10 an erased binding, and its erased index entries, are immutable and undeletable by the owner", async () => {
  await bindVictimAddress();
  const { result } = await eraseParticipant("mutation.pii.immutable", "tombstone-pii-immutable");
  assert.equal(result.verified, true);
  const receipt = (await bindingState("alias-pii-001")).mutation_receipt_id;
  await assert.rejects(
    adminPool.query(`UPDATE memory_alias_bindings SET pii_envelope = '{"keyRef":"x","keyVersion":1}'::jsonb WHERE alias_id = 'alias-pii-001'`),
    /an erased alias binding is immutable/,
  );
  await assert.rejects(
    adminPool.query(`DELETE FROM memory_alias_bindings WHERE alias_id = 'alias-pii-001'`),
    /DELETE on memory_alias_bindings is forbidden/,
  );
  await assert.rejects(
    adminPool.query(`UPDATE memory_alias_blind_indexes SET active = true WHERE binding_mutation_receipt_id = $1`, [receipt]),
    /an erased index entry is immutable/,
  );
  await assert.rejects(
    adminPool.query(`DELETE FROM memory_alias_blind_indexes WHERE binding_mutation_receipt_id = $1`, [receipt]),
    /DELETE on memory_alias_blind_indexes is forbidden/,
  );
  await assert.rejects(
    adminPool.query(`DELETE FROM memory_pii_key_erasures`),
    /DELETE on memory_pii_key_erasures is forbidden; this table is append-only/,
  );
});

test("P-11 RESTORING the erased record does not bring the address back", async () => {
  await bindVictimAddress();
  const { result } = await eraseParticipant("mutation.pii.restore-seed", "tombstone-pii-restore");
  assert.equal(result.verified, true);
  const head = await store().readHead(SCOPE, PARTICIPANT);
  assert.equal(head?.state, "deleted");
  const restoreContent = { participant: PARTICIPANT, restored: true };
  const restore = await issue(
    authorization({
      action: "restore",
      targetRecordId: PARTICIPANT,
      expectedHead: headOf(head!.version, head!.contentDigest),
      proposedContent: restoreContent,
    }),
  );
  const restored = await store().restore({
    actor: SCOPE,
    authorizationId: restore.authorizationId,
    recordId: PARTICIPANT,
    proposedContent: restoreContent,
    mutationReceiptId: "mutation.pii.restore",
  });
  assert.equal(restored.verified, true, restored.rejection ?? "");
  assert.equal(await aliases().resolveAlias(SCOPE, VICTIM_NORMALIZED), null);
  await assert.rejects(aliases().readAliasBinding(SCOPE, "alias-pii-001"), MemoryAliasPiiErased);
  assert.deepEqual(await plaintextSightings(VICTIM_NORMALIZED), []);
});

/**
 * RT5-R1 / K-03 — THE BREAK, AND THE FALSIFIER FOR IT.
 *
 * Red team against 8a0bf05, HIGH, executed, reproduced twice and once more in
 * a merged variant. It needs nothing privileged: an ordinary provider outage
 * plus one `restore`.
 *
 *   1. bind the subject's address;
 *   2. subject-erase it while the provider is down — the database half
 *      commits, the key stays live, and the erasure correctly says so;
 *   3. restore the record;
 *   4. subject-erase it AGAIN.
 *
 * At 8a0bf05 step 4 answered `verified:true {0,0,0}` while the key was still
 * `active` and a ciphertext copy taken before step 2 still decrypted to
 * `victim.person@example.com`. The reason was arithmetic, not crypto: the
 * alias UPDATE only touches bindings where `pii_erased_at IS NULL`, and step 2
 * had already set it — so step 4 wrote NO new `erasure_committed` rows, and
 * the accounting, scoped to step 4's OWN tombstone, had an empty denominator.
 * A key nobody counted is a key nobody destroyed.
 *
 * The falsifier the reviewer named: count pending keys over every
 * `erasure_committed` without `key_destroyed` for the target's bindings
 * REGARDLESS OF TOMBSTONE. That is what `destroyCommittedAliasKeys` now does,
 * scoped to the subject's canonical merge set.
 */
async function restoreRecord(recordId: string, tag: string): Promise<void> {
  const head = await store().readHead(SCOPE, recordId);
  assert.equal(head?.state, "deleted", "the record must be deleted before it is restored");
  const content = { participant: recordId, restored: tag };
  const receipt = await issue(
    authorization({
      action: "restore",
      targetRecordId: recordId,
      expectedHead: headOf(head!.version, head!.contentDigest),
      proposedContent: content,
    }),
  );
  const restored = await store().restore({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId,
    proposedContent: content,
    mutationReceiptId: `mutation.${tag}.restore`,
  });
  assert.equal(restored.verified, true, restored.rejection ?? "");
}

const decryptCopy = (copied: PiiEnvelope, mutationReceiptId: string) =>
  TEST_PII_KEYS.decrypt({
    scope: DATA_SCOPE,
    envelope: copied,
    associatedData: aliasEnvelopeAssociatedData({
      tenantId: SCOPE.tenantId,
      workspaceId: SCOPE.workspaceId,
      aliasId: "alias-pii-001",
      mutationReceiptId,
    }),
  });

for (const first of ["subject_erasure_request", "retention_expiry"] as const) {
  test(`RT5-R1 K-03: with the provider BACK, the second erasure after a ${first} + restore is verified ONLY because the key is really destroyed`, async () => {
    // The reviewer's literal sequence. Its falsifier: "Re-running RT5-R1 must
    // then show verified:false, or a refusal, WHILE THE KEY IS ACTIVE." The
    // invariant is the conjunction — never verified over a live key — and the
    // subject-scoped denominator satisfies it the better way: the second
    // erasure now SEES the first tombstone's pending key, finishes destroying
    // it, and only then reports success.
    await bindVictimAddress();
    const before = await bindingState("alias-pii-001");
    const copied = before.pii_envelope as PiiEnvelope;
    TEST_PII_KEYS.setAvailable(false);
    try {
      const { result } = await eraseRecordAtHead(PARTICIPANT, "mutation.rt5r1.first", "tombstone-rt5r1-first", first);
      assert.equal(result.verified, false);
      assert.equal(result.rejection, "key_destruction_not_proven");
      assert.equal(result.aliasErasure?.keysPending, 1);
    } finally {
      TEST_PII_KEYS.setAvailable(true);
    }
    assert.equal(
      await TEST_PII_KEYS.dataKeyState({ scope: DATA_SCOPE, keyRef: before.pii_key_ref }),
      "active",
      "fixture precondition: the outage must have left the key alive",
    );
    await restoreRecord(PARTICIPANT, "rt5r1");

    const second = await eraseRecordAtHead(PARTICIPANT, "mutation.rt5r1.second", "tombstone-rt5r1-second");
    // THE DENOMINATOR IS NOT EMPTY. At 8a0bf05 this answered
    // `true null {0,0,0}`: the alias UPDATE touches only bindings where
    // `pii_erased_at IS NULL`, the first attempt had already set it, so this
    // erasure wrote no evidence of its own and the tombstone-scoped
    // accounting had nothing to count.
    assert.equal(second.result.aliasErasure?.bindingsErased, 1, JSON.stringify(second.result.aliasErasure));
    assert.equal(second.result.aliasErasure?.keysPending, 0, JSON.stringify(second.result.aliasErasure));
    // AND THE INVARIANT: verified only with the key genuinely gone, and the
    // copy taken before any of this no longer decrypting. This is the exact
    // assertion the break failed.
    assert.equal(second.result.verified, true, second.result.rejection ?? "");
    assert.equal(
      await TEST_PII_KEYS.dataKeyState({ scope: DATA_SCOPE, keyRef: before.pii_key_ref }),
      "destroyed",
    );
    await assert.rejects(decryptCopy(copied, before.mutation_receipt_id), MemoryPiiKeyDestroyed);
  });

  test(`RT5-R1b K-03: with the provider STILL DOWN, the second erasure after a ${first} + restore is NOT erased, and counts the first attempt's key`, async () => {
    // The same sequence with the outage still in force at step 4 — the case
    // that isolates the DENOMINATOR from the completion pass. Nothing can
    // destroy the key here, so a `verified:true` would be the break itself.
    await bindVictimAddress();
    const before = await bindingState("alias-pii-001");
    const copied = before.pii_envelope as PiiEnvelope;
    TEST_PII_KEYS.setAvailable(false);
    let second;
    try {
      const { result } = await eraseRecordAtHead(PARTICIPANT, "mutation.rt5r1b.first", "tombstone-rt5r1b-first", first);
      assert.equal(result.rejection, "key_destruction_not_proven");
      TEST_PII_KEYS.setAvailable(true);
      await restoreRecord(PARTICIPANT, "rt5r1b");
      TEST_PII_KEYS.setAvailable(false);
      second = await eraseRecordAtHead(PARTICIPANT, "mutation.rt5r1b.second", "tombstone-rt5r1b-second");
    } finally {
      TEST_PII_KEYS.setAvailable(true);
    }
    assert.equal(
      second.result.verified,
      false,
      `reported success over the record's OWN live key: ${JSON.stringify(second.result.aliasErasure)}`,
    );
    assert.equal(second.result.rejection, "key_destruction_not_proven");
    // The first attempt's key, counted by an erasure that wrote no evidence
    // of its own: {0,0,0} at 8a0bf05.
    assert.equal(second.result.aliasErasure?.bindingsErased, 1, JSON.stringify(second.result.aliasErasure));
    assert.equal(second.result.aliasErasure?.keysPending, 1, JSON.stringify(second.result.aliasErasure));
    assert.equal(second.result.aliasErasure?.keysNotProven, 1, JSON.stringify(second.result.aliasErasure));
    assert.equal(
      await TEST_PII_KEYS.dataKeyState({ scope: DATA_SCOPE, keyRef: before.pii_key_ref }),
      "active",
    );
    // The harm the `verified:true` was hiding: the copy still decrypts.
    assert.equal(typeof (await decryptCopy(copied, before.mutation_receipt_id)), "string");

    // POSITIVE CONTROL: the completion pass finishes it and the copy dies.
    const completed = await store().completePendingAliasErasures();
    assert.equal(completed.destroyed, 1, JSON.stringify(completed));
    await assert.rejects(decryptCopy(copied, before.mutation_receipt_id), MemoryPiiKeyDestroyed);
  });
}

test("RT5-R2 K-03: the merged variant — an ABSORBED record's second erasure does not report erased over its own live key", async () => {
  // The reviewer's third reproduction. The survivor was already refused by
  // 054; the ABSORBED record's own re-erasure was the one that answered
  // `true null {0,0,0}`.
  await bindVictimAddress();
  const before = await bindingState("alias-pii-001");
  TEST_PII_KEYS.setAvailable(false);
  try {
    const { result } = await eraseRecordAtHead(PARTICIPANT, "mutation.rt5r2.first", "tombstone-rt5r2-first");
    assert.equal(result.rejection, "key_destruction_not_proven");
  } finally {
    TEST_PII_KEYS.setAvailable(true);
  }
  await restoreRecord(PARTICIPANT, "rt5r2");
  // Merge the restored record into the survivor, then erase it again — with
  // the provider still down, so nothing can legitimately finish the key and a
  // `verified:true` could only be the accounting failing to count it.
  //
  // The merge is built here rather than through `absorbVictim`, which binds
  // the address as part of merging: the order the reviewer's reproducer needs
  // is bind, erase, restore, THEN merge — and an absorbed record cannot be
  // restored, because `record_merged_away` closes it to everything but a
  // subject erasure.
  await seedGenesis({ participant: SURVIVOR, generation: 1 }, { recordId: SURVIVOR });
  await mergeParticipantInto(SURVIVOR, "mutation.rt5r2.merge");
  TEST_PII_KEYS.setAvailable(false);
  let second;
  try {
    second = await eraseRecordAtHead(PARTICIPANT, "mutation.rt5r2.second", "tombstone-rt5r2-second");
  } finally {
    TEST_PII_KEYS.setAvailable(true);
  }
  assert.equal(
    second.result.verified,
    false,
    `the absorbed record reported success over its own live key: ${JSON.stringify(second.result.aliasErasure)}`,
  );
  assert.equal(second.result.aliasErasure?.keysPending, 1, JSON.stringify(second.result.aliasErasure));
  assert.equal(
    await TEST_PII_KEYS.dataKeyState({ scope: DATA_SCOPE, keyRef: before.pii_key_ref }),
    "active",
  );
});

test("P-12 a REPEATED or REPLAYED erasure changes nothing and records nothing new", async () => {
  await bindVictimAddress();
  const first = await eraseParticipant("mutation.pii.first", "tombstone-pii-first");
  assert.equal(first.result.verified, true);
  const replay = await store().delete({
    actor: SCOPE,
    authorizationId: first.receipt.authorizationId,
    recordId: PARTICIPANT,
    proposedContent: deletionOrder("subject_erasure_request"),
    mutationReceiptId: "mutation.pii.replay",
    tombstoneId: "tombstone-pii-replay",
  });
  assert.equal(replay.verified, false);
  const again = await eraseParticipant("mutation.pii.again", "tombstone-pii-again");
  assert.equal(again.result.verified, false);
  assert.equal(again.result.rejection, "record_deleted");
  const events = await adminPool.query(`SELECT count(*)::int AS n FROM memory_pii_key_erasures`);
  assert.equal(events.rows[0].n, 2);
});

test("P-13 an envelope moved to another tenant's row, or to another binding, does not decrypt", async () => {
  await bindVictimAddress();
  const original = await bindingState("alias-pii-001");
  await bindVictimAddress2();
  const other = await bindingState("alias-pii-002");
  // Same tenant, different binding: the associated data binds the alias id and
  // receipt, so a swapped envelope fails authentication.
  await assert.rejects(
    TEST_PII_KEYS.decrypt({
      scope: DATA_SCOPE,
      envelope: original.pii_envelope as PiiEnvelope,
      associatedData: aliasEnvelopeAssociatedData({
        tenantId: SCOPE.tenantId,
        workspaceId: SCOPE.workspaceId,
        aliasId: "alias-pii-002",
        mutationReceiptId: other.mutation_receipt_id,
      }),
    }),
    MemoryPiiEnvelopeInvalid,
  );
  // Another tenant's scope: the key refuses to be used outside the scope it
  // was issued to.
  await assert.rejects(
    TEST_PII_KEYS.decrypt({
      scope: { tenantId: "tenant-elsewhere", workspaceId: SCOPE.workspaceId },
      envelope: original.pii_envelope as PiiEnvelope,
      associatedData: "anything",
    }),
    MemoryPiiScopeMismatch,
  );
});

async function bindVictimAddress2() {
  // A second participant and address, for the tests that need two bindings.
  await setAliasPolicy();
  const participant = "participant-hold-002";
  const genesis = await seedGenesis({ participant, generation: 1 }, { recordId: participant });
  const evidence = evidenceFor(participant);
  const alias = aliasIdentity({ aliasId: "alias-pii-002", observedAlias: "other.person@example.com", participantId: participant, evidence });
  const content = { participant, generation: 2 };
  const receipt = await issue(
    authorization({
      action: "assign_alias",
      targetRecordId: participant,
      expectedHead: headOf(1, genesis),
      proposedContentDigest: await testAliasAssignmentDigest({ record: content, alias, evidence, scope: SCOPE }),
    }),
  );
  const bound = await aliases().assignAlias({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    participantRecordId: participant,
    alias,
    evidence,
    proposedContent: content,
    mutationReceiptId: "mutation.pii.bind.alias-pii-002",
  });
  assert.equal(bound.verified, true, bound.rejection ?? "");
}

test("P-14 erasing ONE subject leaves every other subject's alias intact and resolvable", async () => {
  await bindVictimAddress();
  await bindVictimAddress2();
  const { result } = await eraseParticipant("mutation.pii.scope", "tombstone-pii-scope");
  assert.equal(result.verified, true);
  assert.deepEqual(result.aliasErasure, {
    bindingsErased: 1,
    keysDestroyed: 1,
    keysPending: 0,
    keysNotProven: 0,
    notProvenReasons: {},
  });
  assert.equal(await aliases().resolveAlias(SCOPE, VICTIM_NORMALIZED), null);
  assert.equal((await aliases().resolveAlias(SCOPE, "other.person@example.com"))?.binding.aliasId, "alias-pii-002");
});

test("P-15 the alias may not ride along in the record's content, and refusing it spends nothing", async () => {
  await setAliasPolicy();
  const genesis = await seedGenesis({ participant: PARTICIPANT, generation: 1 }, { recordId: PARTICIPANT });
  const evidence = evidenceFor(PARTICIPANT);
  const alias = aliasIdentity({ aliasId: "alias-pii-leak", observedAlias: VICTIM_ADDRESS, participantId: PARTICIPANT, evidence });
  const content = { participant: PARTICIPANT, note: `contact: ${VICTIM_ADDRESS.toUpperCase()}` };
  const receipt = await issue(
    authorization({
      action: "assign_alias",
      targetRecordId: PARTICIPANT,
      expectedHead: headOf(1, genesis),
      proposedContentDigest: await testAliasAssignmentDigest({ record: content, alias, evidence, scope: SCOPE }),
    }),
  );
  const result = await aliases().assignAlias({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    participantRecordId: PARTICIPANT,
    alias,
    evidence,
    proposedContent: content,
    mutationReceiptId: "mutation.pii.leak",
  });
  assert.equal(result.rejection, "alias_plaintext_in_record_content");
  assert.equal(await nonceConsumedAt(receipt.nonce.bindingDigest), null);
});

test("P-16 the AUTHORIZATION RECEIPT is not an offline oracle: its digest is not reproducible from the address without the key", async () => {
  const prepared = await bindVictimAddress();
  const stored = await adminPool.query(
    `SELECT payload->>'proposedContentDigest' AS digest FROM memory_authorization_receipts
      WHERE authorization_id = $1`,
    [prepared.receipt.authorizationId],
  );
  // The pre-047 construction: an unkeyed digest over the alias itself.
  const unkeyed = canonicalDigest({
    schemaVersion: `${WAVE1_TRUSTED_MEMORY_CONTRACT_VERSION}#alias-assignment`,
    value: { record: prepared.content, alias: prepared.alias, evidence: prepared.evidence },
  });
  assert.notEqual(stored.rows[0].digest, unkeyed);
  // An attacker-chosen commitment key does not reproduce it either.
  const attacker = createLocalTestPiiKeyProvider({ rootKey: Buffer.alloc(32, 1) });
  const forgedCommitment = await aliasAssignmentCommitment({ piiKeys: attacker, scope: SCOPE, alias: prepared.alias });
  assert.notEqual(
    stored.rows[0].digest,
    aliasAssignmentDigest({ record: prepared.content, aliasCommitment: forgedCommitment, evidence: prepared.evidence }),
  );
  // The holder of the real key does reproduce it, so the digest still binds.
  assert.equal(
    stored.rows[0].digest,
    await testAliasAssignmentDigest({ record: prepared.content, alias: prepared.alias, evidence: prepared.evidence, scope: SCOPE }),
  );
});

test("P-17 ROTATION: after a new index key version, an alias bound under the old one still resolves and still collides", async () => {
  await bindVictimAddress();
  const indexScope = { tenantId: SCOPE.tenantId, scopeKey: SCOPE.workspaceId };
  TEST_PII_KEYS.rotateBlindIndexKey(indexScope, "alias.normalized");
  TEST_PII_KEYS.rotateBlindIndexKey(indexScope, "alias.skeleton");
  assert.equal((await aliases().resolveAlias(SCOPE, VICTIM_NORMALIZED))?.binding.aliasId, "alias-pii-001");
  // The same address for another participant, written under v1 AND v2 entries,
  // collides with the v1 entry.
  await setAliasPolicy();
  const participant = "participant-hold-003";
  const genesis = await seedGenesis({ participant, generation: 1 }, { recordId: participant });
  const evidence = evidenceFor(participant);
  const alias = aliasIdentity({ aliasId: "alias-pii-rotated", observedAlias: VICTIM_ADDRESS, participantId: participant, evidence });
  const content = { participant, generation: 2 };
  const receipt = await issue(
    authorization({
      action: "assign_alias",
      targetRecordId: participant,
      expectedHead: headOf(1, genesis),
      proposedContentDigest: await testAliasAssignmentDigest({ record: content, alias, evidence, scope: SCOPE }),
    }),
  );
  const collided = await aliases().assignAlias({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    participantRecordId: participant,
    alias,
    evidence,
    proposedContent: content,
    mutationReceiptId: "mutation.pii.rotated",
  });
  assert.equal(collided.rejection, "alias_already_bound");
});

test("P-18 a lookup RACING an erasure sees the whole binding or nothing — never a half-erased one — and nothing after", async () => {
  await bindVictimAddress();
  // Gate: the deleting transaction has erased the binding and its indexes but
  // cannot record the erasure, so it holds everything uncommitted.
  const gate = await adminPool.connect();
  await gate.query("BEGIN");
  await gate.query("LOCK TABLE memory_pii_key_erasures IN SHARE ROW EXCLUSIVE MODE");
  let erasing: Promise<Awaited<ReturnType<typeof eraseParticipant>>>;
  try {
    erasing = eraseParticipant("mutation.pii.race", "tombstone-pii-race");
    const deadline = Date.now() + 4_000;
    for (;;) {
      const waiting = await adminPool.query(
        `SELECT count(*)::int AS n FROM pg_stat_activity
          WHERE datname = current_database() AND wait_event_type = 'Lock'
            AND query LIKE '%INSERT INTO memory_pii_key_erasures%'`,
      );
      if ((waiting.rows[0].n as number) >= 1) break;
      if (Date.now() > deadline) throw new Error("the erasure never reached the gate");
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    // MID-ERASURE, on the independent read pool: the committed state is the
    // pre-erasure one, and it is served whole — decryptable, not blanked.
    const during = await aliases().resolveAlias(SCOPE, VICTIM_NORMALIZED);
    assert.equal(during?.binding.normalizedAlias, VICTIM_NORMALIZED);
    const view = await aliases().readAliasBinding(SCOPE, "alias-pii-001");
    assert.equal(view?.binding.claimed.observedAlias, VICTIM_ADDRESS);
  } finally {
    await gate.query("COMMIT");
    gate.release();
  }
  const { result } = await erasing!;
  assert.equal(result.verified, true, result.rejection ?? "");
  assert.equal(await aliases().resolveAlias(SCOPE, VICTIM_NORMALIZED), null);
  await assert.rejects(aliases().readAliasBinding(SCOPE, "alias-pii-001"), MemoryAliasPiiErased);
});

test("P-19 no CACHE outlives an erasure: the executive memory service answers from the database every time", async () => {
  await bindVictimAddress();
  const service = createPostgresWave1MemoryService(writePool, readPool, { piiKeys: TEST_PII_KEYS });
  const before = await service.resolveExecutiveContext({ actor: SCOPE, normalizedAlias: VICTIM_NORMALIZED });
  assert.equal(before?.canonicalRecordId, PARTICIPANT);
  const { result } = await eraseParticipant("mutation.pii.cache", "tombstone-pii-cache");
  assert.equal(result.verified, true);
  // The SAME service instance, asked again.
  assert.equal(
    await service.resolveExecutiveContext({ actor: SCOPE, normalizedAlias: VICTIM_NORMALIZED }),
    null,
  );
});

test("C8 every CHECK on the legal-hold and retention tables refuses the one row it exists for (from real holds)", async () => {
  // Priority 6: none of these CHECKs was in the original destroyer
  // population, and dropping them left the suite green.
  await placeHold(legalHold({ coverage: { kind: "records", recordIds: [FREE_RECORD_ID] }, holdId: "hold-checks-records", carveOutActions: ["promote"] }));
  await placeHold(legalHold({ coverage: { kind: "subjects", canonicalParticipantIds: ["participant-checks-001"] }, holdId: "hold-checks-subjects" }));
  const imposed = await holds().imposeRetention(SCOPE, {
    obligationId: "retention-checks-001",
    recordId: FREE_RECORD_ID,
    policyRef: "policy:retention/seven-years",
    imposingAuthorityId: "authority.records-manager",
    imposedAt: isoOffset(-60_000),
    retainUntil: isoOffset(3_600_000),
  });
  assert.equal(imposed.rejection, null);

  const freshHold = { hold_id: "hold-checks-fresh", payload: { holdId: "hold-checks-fresh" } };
  await assertCheckConstraintsKill(adminPool, {
    table: "memory_legal_holds",
    where: "hold_id = $1",
    params: ["hold-checks-records"],
    nonObjectColumn: "payload",
    fresh: () => freshHold,
    cases: [
      { constraint: "memory_legal_holds_coverage_domain", violate: () => ({ coverage_kind: "everything", payload: { coverage: { kind: "everything" } } }) },
      { constraint: "memory_legal_holds_status_domain", violate: () => ({ status_state: "suspended", payload: { status: { state: "suspended" } } }) },
      {
        constraint: "memory_legal_holds_release_witness",
        violate: () => ({ status_state: "released", payload: { status: { state: "released" } } }),
      },
      {
        constraint: "memory_legal_holds_release_after_issue",
        violate: (r) => ({
          status_state: "released",
          released_at: new Date(Date.parse(String(r.issued_at)) - 60_000).toISOString(),
          releasing_authority_id: "authority.general-counsel",
          release_order_ref: "order:court/2026-0200",
          payload: { status: { state: "released" } },
        }),
      },
      { constraint: "memory_legal_holds_authority_binding", violate: () => ({ payload: { issuingAuthorityId: "authority.someone-else" } }) },
      { constraint: "memory_legal_holds_coverage_binding", violate: () => ({ payload: { coverage: { kind: "subjects" } } }) },
      { constraint: "memory_legal_holds_hold_binding", violate: () => ({ payload: { holdId: "hold-elsewhere" } }) },
      { constraint: "memory_legal_holds_matter_binding", violate: () => ({ payload: { matterRef: "matter:elsewhere/2026" } }) },
      { constraint: "memory_legal_holds_principal_binding", violate: () => ({ payload: { scope: { principalId: "principal-elsewhere" } } }) },
      { constraint: "memory_legal_holds_status_binding", violate: () => ({ payload: { status: { state: "released" } } }) },
      { constraint: "memory_legal_holds_tenant_binding", violate: () => ({ payload: { scope: { tenantId: "tenant-elsewhere" } } }) },
      { constraint: "memory_legal_holds_user_binding", violate: () => ({ payload: { scope: { userId: "user-elsewhere" } } }) },
      { constraint: "memory_legal_holds_workspace_binding", violate: () => ({ payload: { scope: { workspaceId: "workspace-elsewhere" } } }) },
    ],
  });
  await assertCheckConstraintsKill(adminPool, {
    table: "memory_legal_hold_records",
    where: "hold_id = $1",
    params: ["hold-checks-records"],
    fresh: () => ({ record_id: "record-checks-fresh" }),
    cases: [{ constraint: "memory_legal_hold_records_kind", violate: () => ({ coverage_kind: "subjects" }) }],
  });
  await assertCheckConstraintsKill(adminPool, {
    table: "memory_legal_hold_subjects",
    where: "hold_id = $1",
    params: ["hold-checks-subjects"],
    fresh: () => ({ canonical_participant_id: "participant-checks-fresh" }),
    cases: [{ constraint: "memory_legal_hold_subjects_kind", violate: () => ({ coverage_kind: "records" }) }],
  });
  await assertCheckConstraintsKill(adminPool, {
    table: "memory_legal_hold_carve_outs",
    where: "hold_id = $1",
    params: ["hold-checks-records"],
    fresh: () => ({ action: "assign_alias" }),
    cases: [
      { constraint: "memory_legal_hold_carve_outs_action_domain", violate: () => ({ action: "rewrite" }) },
      // THE CARVE-OUT A COURT MAY NEVER GRANT: destroying held evidence.
      { constraint: "memory_legal_hold_carve_outs_never", violate: () => ({ action: "delete" }) },
    ],
  });
  await assertCheckConstraintsKill(adminPool, {
    table: "memory_retention_obligations",
    where: "obligation_id = $1",
    params: ["retention-checks-001"],
    fresh: () => ({ obligation_id: "retention-checks-fresh" }),
    cases: [{ constraint: "memory_retention_obligations_window", violate: (r) => ({ retain_until: r.imposed_at }) }],
  });
});

// ---------------------------------------------------------------------------
// C9 — survivors of the Priority 6 sweep at 7825b89, closed.
// ---------------------------------------------------------------------------

test("C9 the mutation role is refused by PRIVILEGE on tombstones, key-erasure evidence and index entries it may not rewrite", async () => {
  // P6 survivors G-11, G-12, G-14: every existing test of these tables ran as
  // the OWNER, so widening the mutator's grants was masked by the append-only
  // and guard triggers and nothing noticed.
  await bindVictimAddress();
  const { result } = await eraseParticipant("mutation.c9.grants", "tombstone-c9-grants");
  assert.equal(result.verified, true);
  const receipt = (await bindingState("alias-pii-001")).mutation_receipt_id;
  for (const [sql, table] of [
    [`UPDATE memory_tombstones SET reason = 'erroneous_record'`, "memory_tombstones"],
    [`DELETE FROM memory_tombstones`, "memory_tombstones"],
    [`UPDATE memory_pii_key_erasures SET event = 'key_destroyed'`, "memory_pii_key_erasures"],
    [`DELETE FROM memory_pii_key_erasures`, "memory_pii_key_erasures"],
    [`DELETE FROM memory_alias_blind_indexes`, "memory_alias_blind_indexes"],
    [`UPDATE memory_alias_blind_indexes SET purpose = 'alias.skeleton'`, "memory_alias_blind_indexes"],
  ] as const) {
    await assert.rejects(() => runAs("aaliyah_memory_mutator", sql), new RegExp(`permission denied for table ${table}`));
  }
  // Positive control: the columns the mutator IS granted on index entries
  // reach the guard trigger, which refuses on its own terms.
  await assert.rejects(
    () => runAs("aaliyah_memory_mutator", `UPDATE memory_alias_blind_indexes SET active = true WHERE binding_mutation_receipt_id = $1`, [receipt]),
    /an erased index entry is immutable/,
  );
});

test("C9 every legal-hold child row must belong to a real hold of its coverage kind (the three foreign keys)", async () => {
  // P6 survivors: FK carve_outs/records/subjects, and memory_legal_holds_fk_target
  // which two of them reference. No test ever wrote an orphan child row.
  await placeHold(legalHold({ coverage: { kind: "records", recordIds: [FREE_RECORD_ID] }, holdId: "hold-c9-records" }));
  await placeHold(legalHold({ coverage: { kind: "subjects", canonicalParticipantIds: ["participant-c9"] }, holdId: "hold-c9-subjects" }));
  const insert = (sql: string, params: unknown[]) => adminPool.query(sql, params);
  const records = `INSERT INTO memory_legal_hold_records (tenant_id, workspace_id, hold_id, coverage_kind, record_id) VALUES ($1,$2,$3,'records',$4)`;
  const subjects = `INSERT INTO memory_legal_hold_subjects (tenant_id, workspace_id, hold_id, coverage_kind, canonical_participant_id) VALUES ($1,$2,$3,'subjects',$4)`;
  const carveOuts = `INSERT INTO memory_legal_hold_carve_outs (tenant_id, workspace_id, hold_id, action, order_ref, granting_authority_id, granted_at) VALUES ($1,$2,$3,'promote','order:court/2026-0999','authority.court', now())`;
  const expectFk = async (sql: string, params: unknown[], constraint: string) => {
    await assert.rejects(() => insert(sql, params), (error: unknown) => {
      const e = error as { code?: string; constraint?: string };
      assert.equal(e.code, "23503", String(error));
      assert.equal(e.constraint, constraint);
      return true;
    });
  };
  // A hold that does not exist.
  await expectFk(records, [SCOPE.tenantId, SCOPE.workspaceId, "hold-never-placed", "record-c9-a"], "memory_legal_hold_records_hold_fk");
  await expectFk(subjects, [SCOPE.tenantId, SCOPE.workspaceId, "hold-never-placed", "participant-c9-a"], "memory_legal_hold_subjects_hold_fk");
  await expectFk(carveOuts, [SCOPE.tenantId, SCOPE.workspaceId, "hold-never-placed"], "memory_legal_hold_carve_outs_hold_fk");
  // A real hold of the WRONG coverage kind: records under a subjects hold, subjects under a records hold.
  await expectFk(records, [SCOPE.tenantId, SCOPE.workspaceId, "hold-c9-subjects", "record-c9-b"], "memory_legal_hold_records_hold_fk");
  await expectFk(subjects, [SCOPE.tenantId, SCOPE.workspaceId, "hold-c9-records", "participant-c9-b"], "memory_legal_hold_subjects_hold_fk");
  // Positive controls: the matching rows land.
  await insert(records, [SCOPE.tenantId, SCOPE.workspaceId, "hold-c9-records", "record-c9-c"]);
  await insert(subjects, [SCOPE.tenantId, SCOPE.workspaceId, "hold-c9-subjects", "participant-c9-c"]);
  await insert(carveOuts, [SCOPE.tenantId, SCOPE.workspaceId, "hold-c9-records"]);
});

test("C9 a provider that CLAIMS destruction without destroying is caught: the deletion stays incomplete and nothing is recorded destroyed", async () => {
  // P6 survivor P3-04: the store re-reads key state after `destroyDataKey`, and
  // removing that confirmation went unnoticed because the local provider never
  // lies. This one does.
  await bindVictimAddress();
  const before = await bindingState("alias-pii-001");
  const liar = {
    ...TEST_PII_KEYS,
    destroyDataKey: async () => ({ state: "destroyed" as const, destroyedAt: new Date().toISOString() }),
  };
  const head = await store().readHead(SCOPE, PARTICIPANT);
  const order = deletionOrder("subject_erasure_request");
  const receipt = await issue(
    authorization({ action: "delete", targetRecordId: PARTICIPANT, expectedHead: headOf(head!.version, head!.contentDigest), proposedContent: order }),
  );
  const result = await createPostgresTrustedMemoryStore(writePool, readPool, { piiKeys: liar }).delete({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: PARTICIPANT,
    proposedContent: order,
    mutationReceiptId: "mutation.c9.liar",
    tombstoneId: "tombstone-c9-liar",
  });
  assert.equal(result.verified, false);
  // The lie is a CONTRADICTION, not a delay: `destroyDataKey` returned
  // success and `dataKeyState` then said the key was alive.
  assert.equal(result.rejection, "key_destruction_not_proven");
  assert.deepEqual(result.aliasErasure, {
    bindingsErased: 1,
    keysDestroyed: 0,
    keysPending: 1,
    keysNotProven: 1,
    notProvenReasons: { CONTRADICTORY_EVIDENCE: 1 },
  });
  assert.equal(await TEST_PII_KEYS.dataKeyState({ scope: DATA_SCOPE, keyRef: before.pii_key_ref }), "active");
  const destroyed = await adminPool.query(`SELECT count(*)::int AS n FROM memory_pii_key_erasures WHERE event = 'key_destroyed'`);
  assert.equal(destroyed.rows[0].n, 0);
  // Positive control: the honest provider finishes the same erasure.
  assert.deepEqual(await store().completePendingAliasErasures(), { destroyed: 1, repaired: 0, contradictions: 0, pending: 0, notProven: 0, notProvenReasons: {} });
});

test("C9 an index entry that matches a lookup but belongs to ANOTHER binding is refused, never resolved", async () => {
  // P6 survivor P3-05: removing the check that the matched binding decrypts
  // to the requested address changed nothing any test observed.
  await bindVictimAddress2();
  const other = await bindingState("alias-pii-002");
  const indexScope = { tenantId: SCOPE.tenantId, scopeKey: SCOPE.workspaceId };
  // A new key version, so the planted entry cannot collide with binding 002's
  // own version-1 entry on (binding, purpose, version).
  TEST_PII_KEYS.rotateBlindIndexKey(indexScope, "alias.normalized");
  const [ghostIndex] = await TEST_PII_KEYS.blindIndexesForLookup({ scope: indexScope, purpose: "alias.normalized", value: "ghost.person@example.com" });
  await adminPool.query(
    `INSERT INTO memory_alias_blind_indexes
       (tenant_id, workspace_id, scope_key, alias_id, binding_mutation_receipt_id, purpose, key_version, index_value)
     VALUES ($1,$2,$3,'alias-pii-002',$4,'alias.normalized',$5,$6)`,
    [SCOPE.tenantId, SCOPE.workspaceId, SCOPE.workspaceId, other.mutation_receipt_id, Number(ghostIndex!.split(".")[1]), ghostIndex],
  );
  await assert.rejects(
    aliases().resolveAlias(SCOPE, "ghost.person@example.com"),
    /a blind index matched a binding that is not this alias/,
  );
  // Positive control: the binding's own address still resolves.
  assert.equal((await aliases().resolveAlias(SCOPE, "other.person@example.com"))?.binding.aliasId, "alias-pii-002");
});

// ---------------------------------------------------------------------------
// X — A MERGE DOES NOT PUT A SUBJECT BEYOND ERASURE (red team BREAK A, 2b2e554)
//
// P's address is bound; P is merged into S. Before: erasing S reported
// verified with nothing erased, P could not be erased by anyone, and the
// address stayed resolvable under a live key.
// ---------------------------------------------------------------------------

const SURVIVOR = "participant-survivor-001";

async function mergeParticipantInto(survivor: string, receiptId: string) {
  await mergeRecordInto(PARTICIPANT, survivor, receiptId);
}

/** `mergeParticipantInto` for any pair, so a test can build several merges. */
async function mergeRecordInto(from: string, survivor: string, receiptId: string) {
  const head = await store().readHead(SCOPE, from);
  assert.ok(head);
  const order = {
    schemaVersion: MEMORY_IDENTITY_MERGE_ORDER_SCHEMA_VERSION,
    reason: "duplicate_participant",
    reasonEvidenceRef: "matter:identity-merge/0001",
    survivorRecordId: survivor,
  };
  const receipt = await issue(
    authorization({
      action: "merge_identity",
      targetRecordId: from,
      expectedHead: headOf(head.version, head.contentDigest),
      proposedContent: order,
    }),
  );
  const merged = await store().mergeIdentity({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: from,
    proposedContent: order,
    mutationReceiptId: receiptId,
  });
  assert.equal(merged.verified, true, merged.rejection ?? "");
}

async function eraseRecordAtHead(
  recordId: string,
  receiptId: string,
  tombstoneId: string,
  reason: Parameters<typeof deletionOrder>[0] = "subject_erasure_request",
  deleting = store(),
) {
  const head = await store().readHead(SCOPE, recordId);
  assert.ok(head);
  const order = deletionOrder(reason);
  const receipt = await issue(
    authorization({
      action: "delete",
      targetRecordId: recordId,
      expectedHead: headOf(head.version, head.contentDigest),
      proposedContent: order,
    }),
  );
  const result = await deleting.delete({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId,
    proposedContent: order,
    mutationReceiptId: receiptId,
    tombstoneId,
  });
  return { receipt, result };
}

async function nonceConsumed(authorizationId: string): Promise<boolean> {
  const row = await adminPool.query(
    `SELECT consumed_at FROM memory_authorization_nonces WHERE authorization_id = $1`,
    [authorizationId],
  );
  return row.rows[0].consumed_at !== null;
}

/** Merge PARTICIPANT (carrying VICTIM_ADDRESS) into SURVIVOR. */
async function absorbVictim(receiptId: string) {
  await bindVictimAddress();
  await seedGenesis({ participant: SURVIVOR, generation: 1 }, { recordId: SURVIVOR });
  await mergeParticipantInto(SURVIVOR, receiptId);
}

test("X-1 erasing a SURVIVOR is refused while a record merged into it still holds the subject's address; nothing is consumed", async () => {
  await absorbVictim("mutation.x1.merge");
  const { receipt, result } = await eraseRecordAtHead(SURVIVOR, "mutation.x1.erase", "tombstone-x1");
  assert.equal(result.verified, false);
  assert.equal(result.rejection, "merged_records_not_erased");
  assert.equal(await nonceConsumed(receipt.authorizationId), false);
  assert.equal((await store().readHead(SCOPE, SURVIVOR))?.state, "active");
  const tombstones = await adminPool.query(`SELECT count(*)::int AS n FROM memory_tombstones`);
  assert.equal(tombstones.rows[0].n, 0);
});

test("X-1b erasing a SURVIVOR is refused while a record merged into it keeps CONTENT, even with no alias at all", async () => {
  // Sweep survivor FX-04 at f59a6f7: X-1 always gave the absorbed record an
  // alias, so the binding branch alone refused and dropping the live-head
  // check changed nothing. Here there is no binding anywhere.
  await seedGenesis({ participant: PARTICIPANT, generation: 1, note: SENSITIVE }, { recordId: PARTICIPANT });
  await seedGenesis({ participant: SURVIVOR, generation: 1 }, { recordId: SURVIVOR });
  await mergeParticipantInto(SURVIVOR, "mutation.x1b.merge");
  assert.equal((await adminPool.query(`SELECT count(*)::int AS n FROM memory_alias_bindings`)).rows[0].n, 0);
  const { receipt, result } = await eraseRecordAtHead(SURVIVOR, "mutation.x1b.erase", "tombstone-x1b");
  assert.equal(result.rejection, "merged_records_not_erased");
  assert.equal(await nonceConsumed(receipt.authorizationId), false);
  // Positive control: erase the absorbed record's content first, then the survivor.
  const { result: absorbed } = await eraseRecordAtHead(PARTICIPANT, "mutation.x1b.erase.absorbed", "tombstone-x1b-absorbed");
  assert.equal(absorbed.verified, true, absorbed.rejection ?? "");
  const { result: survivor } = await eraseRecordAtHead(SURVIVOR, "mutation.x1b.erase.survivor", "tombstone-x1b-survivor");
  assert.equal(survivor.verified, true, survivor.rejection ?? "");
});

test("X-2 the ABSORBED record accepts a subject erasure that destroys its content, address and key; then the survivor erases", async () => {
  await absorbVictim("mutation.x2.merge");
  const before = await bindingState("alias-pii-001");
  const { result } = await eraseRecordAtHead(PARTICIPANT, "mutation.x2.erase.absorbed", "tombstone-x2-absorbed");
  assert.equal(result.verified, true, result.rejection ?? "");
  assert.deepEqual(result.aliasErasure, {
    bindingsErased: 1,
    keysDestroyed: 1,
    keysPending: 0,
    keysNotProven: 0,
    notProvenReasons: {},
  });
  const after = await bindingState("alias-pii-001");
  assert.equal(after.pii_envelope, null);
  assert.equal(after.pii_erasure_tombstone_id, "tombstone-x2-absorbed");
  assert.equal(await TEST_PII_KEYS.dataKeyState({ scope: DATA_SCOPE, keyRef: before.pii_key_ref }), "destroyed");
  assert.equal(await aliases().resolveAlias(SCOPE, VICTIM_NORMALIZED), null);
  const content = await adminPool.query(
    `SELECT count(*)::int AS n FROM memory_record_versions
      WHERE record_id = $1 AND state <> 'deleted' AND content_erased_at IS NULL`,
    [PARTICIPANT],
  );
  assert.equal(content.rows[0].n, 0);
  assert.deepEqual(await plaintextSightings(VICTIM_NORMALIZED), []);
  // Merge is not deletion, and erasure is not un-merging: the edge stays.
  const edges = await adminPool.query(
    `SELECT count(*)::int AS n FROM memory_identity_edges WHERE from_record_id = $1 AND kind = 'merged_into'`,
    [PARTICIPANT],
  );
  assert.equal(edges.rows[0].n, 1);
  // Positive control for X-1: with the absorbed record erased, the survivor erases.
  const { result: survivor } = await eraseRecordAtHead(SURVIVOR, "mutation.x2.erase.survivor", "tombstone-x2-survivor");
  assert.equal(survivor.verified, true, survivor.rejection ?? "");
});

test("X-3 the absorbed record stays frozen to every OTHER deletion reason, refused before consumption", async () => {
  await absorbVictim("mutation.x3.merge");
  const { receipt, result } = await eraseRecordAtHead(
    PARTICIPANT,
    "mutation.x3.erase",
    "tombstone-x3",
    "erroneous_record",
  );
  assert.equal(result.rejection, "record_merged_away");
  assert.equal(await nonceConsumed(receipt.authorizationId), false);
  assert.notEqual((await bindingState("alias-pii-001")).pii_envelope, null);
});

test("X-4 the DATABASE freeze admits a deletion on an absorbed record only when its order is a subject erasure", async () => {
  await absorbVictim("mutation.x4.merge");
  const head = await store().readHead(SCOPE, PARTICIPANT);
  assert.ok(head);
  const append = (reason: Parameters<typeof deletionOrder>[0], label: string) =>
    hostileAppend({
      action: "delete",
      state: "deleted",
      version: head.version + 1,
      predecessorDigest: head.contentDigest,
      content: deletionOrder(reason),
      recordId: PARTICIPANT,
      label,
    });
  await assert.rejects(() => append("erroneous_record", "x4-erroneous"), /a record merged into another accepts no further versions/);
  // Positive control: the subject erasure passes the freeze and meets the
  // ordinary deletion guards instead — a bare deleted label is still refused.
  await assert.rejects(() => append("subject_erasure_request", "x4-subject"), (error: unknown) => {
    assert.doesNotMatch(String(error), /accepts no further versions/);
    assert.match(String(error), /a deletion must erase every prior version of the record/);
    return true;
  });
});

/**
 * ---- THE DATABASE IS THE BACKSTOP, AND WHY THIS TEST CHANGED SHAPE ------
 *
 * X-5 and X-8 used to neutralise the store's own pre-check by starting it on
 * `search_path=<shadow>,public`, so its unqualified
 * `aaliyah_memory_unerased_merged_records` call resolved to an empty stub
 * while the SECURITY DEFINER trigger still read `public`. That fixture no
 * longer works, and it no longer works because the defect it depended on was
 * FIXED: `enterMemoryRole` pins `search_path` to `pg_catalog, public, pg_temp`
 * on every transaction, so `"$user"` and any injected schema are off the path
 * entirely (red team B2 / security NEW-1, K-07 — where the same shadowing
 * trick let a survivor's erasure verify over a LIVE key).
 *
 * With the path pinned, the store's pre-check and the trigger call the SAME
 * function and cannot be made to disagree. So the trigger's independent value
 * is no longer "it catches a store whose check was fooled" — it is the thing
 * the store's own comment always claimed: it binds A WRITER THAT NEVER COMES
 * THROUGH THE STORE. That is what these two now test, the same way P-8 tests
 * the alias guard: a structurally valid tombstone row, written directly as the
 * mutation role with every unrelated guard stood down, so the merged-erasure
 * guard is the only thing left that can refuse.
 *
 * Each has a POSITIVE CONTROL, because a refusal that fires for every row
 * proves nothing.
 */
async function forgeSurvivorTombstone(
  targetRecordId: string,
  tombstoneId: string,
  copyFrom: string,
): Promise<void> {
  // ONE TRANSACTION, ALWAYS ROLLED BACK.
  //
  // The merged-erasure guard is an immediate AFTER INSERT trigger, so the
  // INSERT statement itself is the whole experiment — a COMMIT would add no
  // evidence and would leave a real tombstone in a database eleven later
  // tests share. Committing is how the first version of this helper broke
  // three unrelated tombstone-guard tests: it persisted both the forged rows
  // and, on the success path, the stood-down triggers.
  const client = await adminPool.connect();
  try {
    await client.query("BEGIN");
    await client.query(`ALTER TABLE memory_tombstones
      DISABLE TRIGGER memory_tombstones_structural,
      DISABLE TRIGGER memory_tombstones_zz_authorization_scope`);
    await client.query(
      `INSERT INTO memory_tombstones
         (tenant_id, workspace_id, principal_id, user_id, tombstone_id, target_record_id,
          target_version, tombstone_version, authorization_id, mutation_receipt_id, reason,
          effective_at, retain_until, legal_hold_state, cache_index_propagation,
          restoration_eligibility_kind, tombstone_digest, payload)
       SELECT tenant_id, workspace_id, principal_id, user_id, $2, $1,
              target_version, tombstone_version, authorization_id, $2 || '.receipt',
              'subject_erasure_request',
              effective_at, retain_until, legal_hold_state, cache_index_propagation,
              restoration_eligibility_kind, tombstone_digest,
              jsonb_set(jsonb_set(payload, '{tombstoneId}', to_jsonb($2::text)),
                        '{targetRecordId}', to_jsonb($1::text))
         FROM memory_tombstones WHERE tombstone_id = $3`,
      [targetRecordId, tombstoneId, copyFrom],
    );
  } finally {
    await client.query("ROLLBACK").catch(() => undefined);
    client.release();
  }
}

async function rejectsSurvivorTombstone(
  targetRecordId: string,
  tombstoneId: string,
  copyFrom: string,
  pattern: RegExp,
): Promise<void> {
  await assert.rejects(
    () => forgeSurvivorTombstone(targetRecordId, tombstoneId, copyFrom),
    pattern,
  );
}

test("X-5 the DATABASE refuses a subject-erasure tombstone for a survivor whose merged-in record is unerased, written by a writer that never came through the store", async () => {
  await absorbVictim("mutation.x5.merge");
  // A structurally valid tombstone to copy, from an honest deletion of an
  // unrelated record.
  await deleteThen("mutation.x5.other-delete", "tombstone-x5-other");
  await rejectsSurvivorTombstone(
    SURVIVOR,
    "tombstone-x5-forged",
    "tombstone-x5-other",
    /a subject erasure may not complete while a record merged into it is not erased/,
  );
  assert.equal((await store().readHead(SCOPE, SURVIVOR))?.state, "active");

  // POSITIVE CONTROL: the very same forged write, once the merged-in record
  // really is erased, is ACCEPTED by the trigger — so the refusal above is
  // about the merge and not about writing a tombstone directly.
  await eraseRecordAtHead(PARTICIPANT, "mutation.x5.erase.absorbed", "tombstone-x5-absorbed");
  await forgeSurvivorTombstone(SURVIVOR, "tombstone-x5-allowed", "tombstone-x5-other");
});

test("K-5 RED TEAM RT2-H1: a spent CORRECT authorization cannot also witness a binding that resurrects an ERASED participant's address", async () => {
  await bindVictimAddress();
  const original = (await adminPool.query(`SELECT * FROM memory_alias_bindings WHERE alias_id = 'alias-pii-001'`)).rows[0];
  const originalIndexes = (
    await adminPool.query(
      `SELECT purpose, key_version, index_value, scope_key FROM memory_alias_blind_indexes
        WHERE alias_id = 'alias-pii-001' ORDER BY id`,
    )
  ).rows;
  const { result: erased } = await eraseParticipant("mutation.k5.erase", "tombstone-k5");
  assert.equal(erased.verified, true, erased.rejection ?? "");

  const genesis = await seedGenesis({ note: "another record" });
  const content = { note: "another record, corrected" };
  const receipt = await issue(authorization({ action: "correct", expectedHead: headOf(1, genesis), proposedContent: content }));
  const corrected = await store().correct({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: RECORD_ID,
    proposedContent: content,
    mutationReceiptId: "mutation.k5",
  });
  assert.equal(corrected.verified, true, corrected.rejection ?? "");

  const o = original;
  const steps = [
    {
      sql: `INSERT INTO memory_alias_bindings
              (tenant_id, workspace_id, principal_id, user_id, cross_workspace_policy, scope_key, alias_id,
               skeleton_algorithm, normalization_profile, canonical_participant_id, script_code,
               restriction_level, subject_participant_id, source_evidence_ref, source_evidence_digest,
               observed_at, fresh_until, authorization_id, mutation_receipt_id, bound_at, payload,
               pii_envelope, pii_key_ref, pii_key_version)
            VALUES ($1,$2,$3,$4,$5,$6,'alias-k5',$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,'mutation.k5',$18,$19,$20,$21,$22)`,
      params: [
        o.tenant_id, o.workspace_id, o.principal_id, o.user_id, o.cross_workspace_policy, o.scope_key,
        o.skeleton_algorithm, o.normalization_profile, o.canonical_participant_id, o.script_code,
        o.restriction_level, o.subject_participant_id, o.source_evidence_ref, o.source_evidence_digest,
        o.observed_at, o.fresh_until, receipt.authorizationId, o.bound_at,
        JSON.stringify({ ...o.payload, aliasId: "alias-k5", mutationReceiptId: "mutation.k5", authorizationId: receipt.authorizationId }),
        JSON.stringify(o.pii_envelope), o.pii_key_ref, o.pii_key_version,
      ],
    },
    ...originalIndexes.map((index) => ({
      sql: `INSERT INTO memory_alias_blind_indexes
              (tenant_id, workspace_id, scope_key, alias_id, binding_mutation_receipt_id, purpose, key_version, index_value)
            VALUES ($1,$2,$3,'alias-k5','mutation.k5',$4,$5,$6)`,
      params: [o.tenant_id, o.workspace_id, index.scope_key, index.purpose, index.key_version, index.index_value],
    })),
  ];
  await assert.rejects(
    () => runAsTransaction("aaliyah_memory_mutator", steps),
    /an alias binding must be witnessed by a spent assign_alias authorization for its own participant/,
  );
  const unerased = await adminPool.query(`SELECT count(*)::int AS n FROM memory_alias_bindings WHERE pii_erased_at IS NULL`);
  assert.equal(unerased.rows[0].n, 0);
  assert.equal(await aliases().resolveAlias(SCOPE, VICTIM_NORMALIZED), null);
});

test("K-6 RED TEAM RT2-K1: a key_destroyed row forged for a LIVE key does not stop the completion pass from destroying it", async () => {
  await bindVictimAddress();
  const before = await bindingState("alias-pii-001");
  const copied = before.pii_envelope as PiiEnvelope;
  TEST_PII_KEYS.setAvailable(false);
  let result;
  try {
    ({ result } = await eraseParticipant("mutation.k6", "tombstone-k6"));
  } finally {
    TEST_PII_KEYS.setAvailable(true);
  }
  assert.equal(result.rejection, "key_destruction_not_proven");
  assert.deepEqual(result.aliasErasure, {
    bindingsErased: 1,
    keysDestroyed: 0,
    keysPending: 1,
    keysNotProven: 1,
    notProvenReasons: { PROVIDER_UNAVAILABLE: 1 },
  });

  // The key_destroyed guard binds the tombstone as well as the key: evidence
  // naming another tombstone is refused (P6 branch survivor BM4).
  await assert.rejects(
    () =>
      runAs(
        "aaliyah_memory_mutator",
        `INSERT INTO memory_pii_key_erasures (tenant_id, workspace_id, tombstone_id, alias_id, binding_mutation_receipt_id, key_ref, provider_id, event)
         SELECT tenant_id, workspace_id, 'tombstone-k6-other', alias_id, binding_mutation_receipt_id, key_ref, provider_id, 'key_destroyed'
           FROM memory_pii_key_erasures WHERE tombstone_id = 'tombstone-k6' AND event = 'erasure_committed'`,
      ),
    /a key is recorded destroyed only after its erasure committed/,
  );
  // The forgery the database cannot see: the right tombstone, a live key.
  await runAs(
    "aaliyah_memory_mutator",
    `INSERT INTO memory_pii_key_erasures (tenant_id, workspace_id, tombstone_id, alias_id, binding_mutation_receipt_id, key_ref, provider_id, event)
     SELECT tenant_id, workspace_id, tombstone_id, alias_id, binding_mutation_receipt_id, key_ref, provider_id, 'key_destroyed'
       FROM memory_pii_key_erasures WHERE tombstone_id = 'tombstone-k6' AND event = 'erasure_committed'`,
  );
  assert.equal(await TEST_PII_KEYS.dataKeyState({ scope: DATA_SCOPE, keyRef: before.pii_key_ref }), "active");

  assert.deepEqual(await store().completePendingAliasErasures(), {
    // The forged row already occupied the evidence slot, so the insert
    // conflicts and `destroyed` (rows that actually landed, K-11) cannot see
    // it. `repaired` is the number that must not be silent here: a forged
    // `key_destroyed` was detected and the live key really was destroyed.
    destroyed: 0,
    repaired: 1,
    contradictions: 1,
    pending: 0,
    notProven: 0,
    notProvenReasons: {},
  });
  assert.equal(await TEST_PII_KEYS.dataKeyState({ scope: DATA_SCOPE, keyRef: before.pii_key_ref }), "destroyed");
  await assert.rejects(
    TEST_PII_KEYS.decrypt({
      scope: DATA_SCOPE,
      envelope: copied,
      associatedData: aliasEnvelopeAssociatedData({
        tenantId: SCOPE.tenantId,
        workspaceId: SCOPE.workspaceId,
        aliasId: "alias-pii-001",
        mutationReceiptId: before.mutation_receipt_id,
      }),
    }),
    MemoryPiiKeyDestroyed,
  );
  // Idempotent: a second pass finds the evidence true and does nothing.
  assert.deepEqual(await store().completePendingAliasErasures(), { destroyed: 0, repaired: 0, contradictions: 0, pending: 0, notProven: 0, notProvenReasons: {} });
});

/** Bind `<n>.person@example.com` to its own participant, honestly. */
async function bindNumberedParticipant(n: number) {
  return bindNumberedParticipantAs(
    `participant-starve-${n}`,
    `alias-starve-${n}`,
    `person${n}@example.com`,
    `mutation.starve.bind.${n}`,
  );
}

/**
 * `bindNumberedParticipant` for any record and alias, so a test can build
 * several independently bound participants.
 */
async function bindNumberedParticipantAs(
  participant: string,
  aliasId: string,
  observedAlias: string,
  bindReceiptId: string,
) {
  await setAliasPolicy();
  const genesis = await seedGenesis({ participant, generation: 1 }, { recordId: participant });
  const evidence = evidenceFor(participant);
  const alias = aliasIdentity({ aliasId, observedAlias, participantId: participant, evidence });
  const content = { participant, generation: 2 };
  const receipt = await issue(
    authorization({
      action: "assign_alias",
      targetRecordId: participant,
      expectedHead: headOf(1, genesis),
      proposedContentDigest: await testAliasAssignmentDigest({ record: content, alias, evidence, scope: SCOPE }),
    }),
  );
  const bound = await aliases().assignAlias({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    participantRecordId: participant,
    alias,
    evidence,
    proposedContent: content,
    mutationReceiptId: bindReceiptId,
  });
  assert.equal(bound.verified, true, bound.rejection ?? "");
  const keyRef = (await bindingState(aliasId)).pii_key_ref;
  return { participant, keyRef };
}

async function forgeKeyDestroyed(tombstoneId: string) {
  await runAs(
    "aaliyah_memory_mutator",
    `INSERT INTO memory_pii_key_erasures (tenant_id, workspace_id, tombstone_id, alias_id, binding_mutation_receipt_id, key_ref, provider_id, event)
     SELECT tenant_id, workspace_id, tombstone_id, alias_id, binding_mutation_receipt_id, key_ref, provider_id, 'key_destroyed'
       FROM memory_pii_key_erasures WHERE tombstone_id = $1 AND event = 'erasure_committed'`,
    [tombstoneId],
  );
}

async function eraseDuringOutage(participant: string, tag: string) {
  TEST_PII_KEYS.setAvailable(false);
  try {
    const { result } = await eraseRecordAtHead(participant, `mutation.starve.${tag}`, `tombstone-starve-${tag}`);
    // OPTION B: an outage cannot prove destruction, so it is named as such.
    assert.equal(result.rejection, "key_destruction_not_proven");
  } finally {
    TEST_PII_KEYS.setAvailable(true);
  }
}

test("K-7 a forged key_destroyed row is audited on every pass, however many SETTLED rows sit ahead of it", async () => {
  // Red team F2 against 3ba769f (RT3-KSTARVE), at batch limit 1 instead of 100.
  const settled = await bindNumberedParticipant(1);
  const { result } = await eraseRecordAtHead(settled.participant, "mutation.starve.settled", "tombstone-starve-settled");
  assert.equal(result.verified, true, result.rejection ?? "");
  const victim = await bindNumberedParticipant(2);
  await eraseDuringOutage(victim.participant, "victim");
  await forgeKeyDestroyed("tombstone-starve-victim");
  assert.equal(await TEST_PII_KEYS.dataKeyState({ scope: DATA_SCOPE, keyRef: victim.keyRef }), "active");

  assert.deepEqual(await store().completePendingAliasErasures(1), {
    // The forged row already occupied the evidence slot, so the insert
    // conflicts and `destroyed` (rows that actually landed, K-11) cannot see
    // it. `repaired` is the number that must not be silent here: a forged
    // `key_destroyed` was detected and the live key really was destroyed.
    destroyed: 0,
    repaired: 1,
    contradictions: 1,
    pending: 0,
    notProven: 0,
    notProvenReasons: {},
  });
  assert.equal(await TEST_PII_KEYS.dataKeyState({ scope: DATA_SCOPE, keyRef: victim.keyRef }), "destroyed");
  // Positive control: the settled key was, and stays, destroyed; a further pass finds nothing to do.
  assert.equal(await TEST_PII_KEYS.dataKeyState({ scope: DATA_SCOPE, keyRef: settled.keyRef }), "destroyed");
  assert.deepEqual(await store().completePendingAliasErasures(1), { destroyed: 0, repaired: 0, contradictions: 0, pending: 0, notProven: 0, notProvenReasons: {} });
});

test("K-8 a forged key_destroyed row is audited on every pass, however many PENDING erasures are ahead of it", async () => {
  // Reliability MEDIUM against 3ba769f: the audit shared one LIMIT with the
  // pending work, so a backlog at the limit starved it.
  const pending = await bindNumberedParticipant(3);
  await eraseDuringOutage(pending.participant, "pending");
  const victim = await bindNumberedParticipant(4);
  await eraseDuringOutage(victim.participant, "victim4");
  await forgeKeyDestroyed("tombstone-starve-victim4");

  assert.deepEqual(await store().completePendingAliasErasures(1), {
    // The genuinely pending key: a new `key_destroyed` row landed.
    destroyed: 1,
    // The forged one: the evidence slot was taken, so this is where it shows.
    repaired: 1,
    contradictions: 1,
    pending: 0,
    notProven: 0,
    notProvenReasons: {},
  });
  assert.equal(await TEST_PII_KEYS.dataKeyState({ scope: DATA_SCOPE, keyRef: victim.keyRef }), "destroyed");
  assert.equal(await TEST_PII_KEYS.dataKeyState({ scope: DATA_SCOPE, keyRef: pending.keyRef }), "destroyed");
});

test("X-6 SECURITY 03581a3 ATK-C1: a survivor's erasure is refused while a merged-in key is still live after an outage, and succeeds once it is destroyed", async () => {
  await absorbVictim("mutation.x6.merge");
  const before = await bindingState("alias-pii-001");
  const copied = before.pii_envelope as PiiEnvelope;
  TEST_PII_KEYS.setAvailable(false);
  try {
    const { result } = await eraseRecordAtHead(PARTICIPANT, "mutation.x6.erase.absorbed", "tombstone-x6-absorbed");
    assert.equal(result.rejection, "key_destruction_not_proven");
  } finally {
    TEST_PII_KEYS.setAvailable(true);
  }
  const refused = await eraseRecordAtHead(SURVIVOR, "mutation.x6.erase.survivor", "tombstone-x6-survivor");
  assert.equal(refused.result.verified, false);
  assert.equal(refused.result.rejection, "merged_records_not_erased");
  assert.equal(await nonceConsumed(refused.receipt.authorizationId), false);
  assert.equal(await TEST_PII_KEYS.dataKeyState({ scope: DATA_SCOPE, keyRef: before.pii_key_ref }), "active");
  // Positive control: the completion pass destroys the key; the survivor then erases.
  assert.deepEqual(await store().completePendingAliasErasures(), { destroyed: 1, repaired: 0, contradictions: 0, pending: 0, notProven: 0, notProvenReasons: {} });
  const { result } = await eraseRecordAtHead(SURVIVOR, "mutation.x6.erase.survivor.2", "tombstone-x6-survivor-2");
  assert.equal(result.verified, true, result.rejection ?? "");
  await assert.rejects(
    TEST_PII_KEYS.decrypt({
      scope: DATA_SCOPE,
      envelope: copied,
      associatedData: aliasEnvelopeAssociatedData({
        tenantId: SCOPE.tenantId,
        workspaceId: SCOPE.workspaceId,
        aliasId: "alias-pii-001",
        mutationReceiptId: before.mutation_receipt_id,
      }),
    }),
    MemoryPiiKeyDestroyed,
  );
});

test("X-7 a FORGED key_destroyed row for the merged-in key does not let the survivor's erasure through: the store asks the provider", async () => {
  await absorbVictim("mutation.x7.merge");
  const before = await bindingState("alias-pii-001");
  TEST_PII_KEYS.setAvailable(false);
  try {
    const { result } = await eraseRecordAtHead(PARTICIPANT, "mutation.x7.erase.absorbed", "tombstone-x7-absorbed");
    assert.equal(result.rejection, "key_destruction_not_proven");
  } finally {
    TEST_PII_KEYS.setAvailable(true);
  }
  await forgeKeyDestroyed("tombstone-x7-absorbed");
  const refused = await eraseRecordAtHead(SURVIVOR, "mutation.x7.erase.survivor", "tombstone-x7-survivor");
  assert.equal(refused.result.rejection, "merged_records_not_erased");
  assert.equal(await nonceConsumed(refused.receipt.authorizationId), false);
  assert.equal(await TEST_PII_KEYS.dataKeyState({ scope: DATA_SCOPE, keyRef: before.pii_key_ref }), "active");
});

test("X-8 the DATABASE refuses a subject-erasure tombstone for a survivor whose merged-in erasure has NO key_destroyed evidence", async () => {
  // Migration 054's own clause, exercised through a writer that never came
  // through the store — see the note above `forgeSurvivorTombstone`. The
  // absorbed record IS erased (its binding has `pii_erased_at`), so 051's
  // clause is satisfied; only the missing destruction evidence is left.
  await absorbVictim("mutation.x8.merge");
  await deleteThen("mutation.x8.other-delete", "tombstone-x8-other");
  TEST_PII_KEYS.setAvailable(false);
  try {
    const { result } = await eraseRecordAtHead(PARTICIPANT, "mutation.x8.erase.absorbed", "tombstone-x8-absorbed");
    assert.equal(result.rejection, "key_destruction_not_proven");
  } finally {
    TEST_PII_KEYS.setAvailable(true);
  }
  const evidence = await adminPool.query(
    `SELECT count(*)::int AS n FROM memory_pii_key_erasures
      WHERE event = 'key_destroyed' AND tombstone_id = 'tombstone-x8-absorbed'`,
  );
  assert.equal(evidence.rows[0].n, 0, "precondition: the key must have no destruction evidence");

  await rejectsSurvivorTombstone(
    SURVIVOR,
    "tombstone-x8-forged",
    "tombstone-x8-other",
    /a subject erasure may not complete while a record merged into it is not erased/,
  );
  assert.equal((await store().readHead(SCOPE, SURVIVOR))?.state, "active");

  // POSITIVE CONTROL: the same forged write, once the completion pass has
  // destroyed the key and recorded it, is accepted. So the refusal is about
  // the missing destruction evidence specifically — which is the clause
  // migration 054 adds, and the one a mutant that neuters it must break.
  const completed = await store().completePendingAliasErasures();
  assert.equal(completed.pending, 0, JSON.stringify(completed));
  await forgeSurvivorTombstone(SURVIVOR, "tombstone-x8-allowed", "tombstone-x8-other");
});

test("ATK-P1 K-07: a mutator that can CREATE a schema named after itself cannot shadow the store's reads", async () => {
  // ---- THE REPRODUCER, FROM THE SECURITY REVIEW OF 8a0bf05 -----------
  // NEW-1 / red team B2, MEDIUM, EXECUTED with a working proof of concept.
  // The store named its tables unqualified under `SET LOCAL ROLE`, on
  // PostgreSQL's default `"$user", public` path. Granted CREATE on the
  // database, the mutator created a schema called `aaliyah_memory_mutator` —
  // which `"$user"` resolves to FIRST — put an empty `memory_identity_edges`
  // in it, and the survivor's subject erasure then reported `true null` with
  // the merged-in key still `active` and a ciphertext copy decrypting to
  // `victim.person@example.com`.
  //
  // `enterMemoryRole` now strips `"$user"` from the path. The grant is still
  // a grant, the schema is still creatable, and the shadow is simply never
  // consulted.
  await absorbVictim("mutation.atkp1.merge");
  const before = await bindingState("alias-pii-001");
  TEST_PII_KEYS.setAvailable(false);
  try {
    const { result } = await eraseRecordAtHead(PARTICIPANT, "mutation.atkp1.absorbed", "tombstone-atkp1-absorbed");
    assert.equal(result.rejection, "key_destruction_not_proven");
  } finally {
    TEST_PII_KEYS.setAvailable(true);
  }
  // The forged evidence: the database now says the merged-in key is destroyed.
  await forgeKeyDestroyed("tombstone-atkp1-absorbed");

  // NEGATIVE CONTROL FIRST, so the refusal below is not just "it was refused
  // anyway": without the grant, creating the schema is denied outright.
  await assert.rejects(
    () => runAs("aaliyah_memory_mutator", `CREATE SCHEMA aaliyah_memory_mutator`),
    /permission denied/,
  );

  await adminPool.query(
    `DO $do$ BEGIN EXECUTE format('GRANT CREATE ON DATABASE %I TO aaliyah_memory_mutator', current_database()); END $do$`,
  );
  try {
    // The attacker's own session, as the mutator, exactly as ATK-P1 did it.
    await runAs("aaliyah_memory_mutator", `CREATE SCHEMA aaliyah_memory_mutator`);
    await runAs(
      "aaliyah_memory_mutator",
      `CREATE TABLE aaliyah_memory_mutator.memory_identity_edges
         (LIKE public.memory_identity_edges)`,
    );
    // FIXTURE PRECONDITION: the shadow really would win on the default path.
    const shadowed = await adminPool.query(
      `SELECT to_regclass('memory_identity_edges')::text AS resolved`,
    );
    assert.equal(shadowed.rows[0].resolved, "memory_identity_edges");

    const refused = await eraseRecordAtHead(SURVIVOR, "mutation.atkp1.survivor", "tombstone-atkp1-survivor");
    // The provider is available and says the key is ALIVE, so this is the
    // honest "merged-in record is not erased" refusal — NOT a settlement
    // question, and certainly not a success.
    assert.equal(refused.result.verified, false);
    assert.equal(refused.result.rejection, "merged_records_not_erased");
    assert.equal(await nonceConsumed(refused.receipt.authorizationId), false);
    assert.equal((await store().readHead(SCOPE, SURVIVOR))?.state, "active");
    assert.equal(
      await TEST_PII_KEYS.dataKeyState({ scope: DATA_SCOPE, keyRef: before.pii_key_ref }),
      "active",
    );
  } finally {
    await runAs("aaliyah_memory_mutator", `DROP SCHEMA IF EXISTS aaliyah_memory_mutator CASCADE`).catch(
      () => undefined,
    );
    await adminPool.query(`DROP SCHEMA IF EXISTS aaliyah_memory_mutator CASCADE`);
    await adminPool.query(
      `DO $do$ BEGIN EXECUTE format('REVOKE CREATE ON DATABASE %I FROM aaliyah_memory_mutator', current_database()); END $do$`,
    );
  }
});

test("K-07: the pinned path drops \"$user\" and pg_temp's precedence, and KEEPS what the operator configured", async () => {
  // The three properties `enterMemoryRole` exists for, read back from the
  // SERVER inside the transaction rather than from the string it sent.
  const probe = new Pool({
    connectionString: DB_URL,
    max: 1,
    // `$User` deliberately, not `$user`. Red team B3 / mutant M1: the strip
    // compared literal lowercase strings, and PostgreSQL carries the casing
    // the caller wrote — so `$User` survived and still resolved to the current
    // role's schema, while this test's own assertion was case-SENSITIVE and
    // could not see it.
    options: `${process.env.PGOPTIONS ?? ""} -c search_path="$User",operator_choice,public`,
  });
  try {
    const client = await probe.connect();
    try {
      await client.query("BEGIN");
      const before = (await client.query(`SELECT current_setting('search_path') AS p`)).rows[0].p as string;
      assert.match(before, /\$user/i, "fixture precondition: the session must start with $user on the path");
      await enterMemoryRole(client, "aaliyah_memory_reader");
      const after = (await client.query(`SELECT current_setting('search_path') AS p`)).rows[0].p as string;
      // 1. `"$user"` is GONE — the attack surface ATK-P1 used — in ANY casing.
      assert.doesNotMatch(after, /\$user/i, after);
      // 2. `pg_temp` is LAST, not first-by-omission.
      assert.match(after, /, pg_temp$/, after);
      // 3. The operator's own schema is still there, in order. A store that
      //    silently discarded it would be overriding its operator, and would
      //    break every read-back-divergence fixture in this repository.
      assert.equal(after, "pg_catalog, operator_choice, public, pg_temp");
      await client.query("ROLLBACK");
      // 4. SET LOCAL: nothing leaked onto the pooled connection.
      const leaked = (await client.query(`SELECT current_setting('search_path') AS p`)).rows[0].p as string;
      assert.equal(leaked, before);
    } finally {
      client.release();
    }
  } finally {
    await probe.end();
  }
});

test("X-9 K-23: the merged-key check walks the WHOLE chain — a key three hops away is asked about, not just the nearest", async () => {
  // Founder FOURTH priority: the erasure contract must hold "across every
  // in-scope identity/key/alias in the canonical merge set", and the earlier
  // claim that alias erasure was closed did not survive identity merge. Every
  // other X-test uses a ONE-HOP merge, so a scope that walked a single edge
  // instead of the transitive closure would pass all of them.
  //
  //   leaf -> mid -> near -> SURVIVOR
  //
  // All three levels are erased HONESTLY, so the database's evidence says
  // every key is destroyed and its own helper is satisfied. The survivor's
  // erasure then runs against a provider that can speak for `near` and `mid`
  // but answers `unknown` for the LEAF's key — the shape of a partially
  // migrated key provider. A one-edge scope asks only about `near`, is told
  // "destroyed", and lets the survivor through. The recursive scope asks about
  // the leaf as well.
  //
  // The cap that bounds this recursion at 16 hops is proven by D-1/D-2 in the
  // identity suite; this proves the recursion itself reaches past hop one.
  const levels = ["x9-leaf", "x9-mid", "x9-near"];
  const keyOf = new Map<string, string>();
  for (const [i, level] of levels.entries()) {
    const bound = await bindNumberedParticipantAs(
      `participant-${level}`, `alias-${level}`, `person-${level}@example.com`, `mutation.x9.bind.${i}`,
    );
    keyOf.set(level, bound.keyRef);
  }
  await seedGenesis({ participant: SURVIVOR, generation: 1 }, { recordId: SURVIVOR });
  // Built from the FAR end inwards, because both endpoints of a merge must
  // still be roots: migration 042 refuses a merge INTO a record that was
  // itself merged away.
  await mergeRecordInto("participant-x9-leaf", "participant-x9-mid", "mutation.x9.merge.leaf");
  await mergeRecordInto("participant-x9-mid", "participant-x9-near", "mutation.x9.merge.mid");
  await mergeRecordInto("participant-x9-near", SURVIVOR, "mutation.x9.merge.near");
  // Erased leaf-first, which is the only order the chain allows: a record with
  // an unerased record merged into it is refused.
  for (const level of levels) {
    const erased = await eraseRecordAtHead(`participant-${level}`, `mutation.x9.erase.${level}`, `tombstone-x9-${level}`);
    assert.equal(erased.result.verified, true, `${level}: ${erased.result.rejection ?? ""}`);
  }
  // FIXTURE PRECONDITION: the database is fully satisfied. Every key has
  // destruction evidence, so nothing here depends on the DB helper refusing.
  const evidenced = await adminPool.query(
    `SELECT count(*)::int AS n FROM memory_pii_key_erasures WHERE event = 'key_destroyed'`,
  );
  assert.equal(evidenced.rows[0].n, levels.length);

  const leafKey = keyOf.get("x9-leaf")!;
  const asked: string[] = [];
  const partial = {
    ...TEST_PII_KEYS,
    dataKeyState: async (input: Parameters<typeof TEST_PII_KEYS.dataKeyState>[0]) => {
      asked.push(input.keyRef);
      // The provider that does not hold the oldest key any more.
      return input.keyRef === leafKey ? ("unknown" as const) : TEST_PII_KEYS.dataKeyState(input);
    },
  } as typeof TEST_PII_KEYS;

  const refused = await eraseRecordAtHead(
    SURVIVOR, "mutation.x9.survivor", "tombstone-x9-survivor", "subject_erasure_request",
    createPostgresTrustedMemoryStore(writePool, readPool, { piiKeys: partial }),
  );
  // THE ASSERTION. A one-edge scope never asks this question at all.
  assert.ok(asked.includes(leafKey), `the leaf's key was never asked about: ${JSON.stringify(asked)}`);
  assert.equal(
    refused.result.verified,
    false,
    "the survivor was erased while a key three hops away could not be confirmed",
  );
  assert.equal(refused.result.rejection, "key_destruction_not_proven");
  assert.equal(await nonceConsumed(refused.receipt.authorizationId), false);
  const obligations = await store().listKeyDestructionObligations({ actor: SCOPE });
  assert.deepEqual(
    obligations.map((o) => o.keyRef),
    [leafKey],
    "only the unprovable key becomes an obligation",
  );
  assert.equal(obligations[0]!.notProvenReason, "PROVIDER_ANSWERED_UNKNOWN");

  // POSITIVE CONTROL: the same survivor, asked of a provider that can speak
  // for all three, erases. So the refusal is that one key and not the depth.
  const allowed = await eraseRecordAtHead(SURVIVOR, "mutation.x9.survivor.ok", "tombstone-x9-ok");
  assert.equal(allowed.result.verified, true, allowed.result.rejection ?? "");
  // And no level's address survives anywhere in the database.
  for (const level of levels) {
    assert.deepEqual(await plaintextSightings(`person-${level}@example.com`), []);
  }
});

test("X-10 K-14: the MEASURABLE boundary of what a subject erasure reaches in ordinary record content", async () => {
  // ---- THE DISCLOSED RESIDUAL, MEASURED RATHER THAN DESCRIBED --------
  //
  // The 8a0bf05 reports disclose that "an address split across multiple
  // ordinary content fields may remain in clear record content until that
  // record itself is deleted", and the founder's SIXTH priority asks for an
  // explicit determination with measurable semantics — not a magical PII
  // detector.
  //
  // This test IS the determination. Reading the code first showed the
  // disclosure understates it in one way and overstates it in another, so
  // both are pinned here:
  //
  //   `alias_plaintext_in_record_content` guards ONE mutation —
  //   `assign_alias` — and checks the normalized and observed alias as
  //   CONTIGUOUS, case-insensitive substrings anywhere in the proposed
  //   content. It is not applied to `create` or `correct` at all.
  //
  // What that actually means, and what this test proves:
  //
  //   1. SUPPORTED: a subject erasure destroys the subject's OWN content on
  //      every version — contiguous address, split address, anything. Writing
  //      an identifier into the subject's own record is NOT a residual.
  //   2. NOT SUPPORTED: the same identifier in ANOTHER record's content
  //      survives, contiguous or split. That record is not in the subject's
  //      canonical merge set, and subject erasure does not reach outside it.
  //   3. Why it is not simply fixed: reaching it needs either a reverse index
  //      of subject identifiers — which is the very material the vault exists
  //      to keep out of the clear — or a detector that recognises an
  //      identifier assembled across fields. Neither is in W1.3.
  //
  // DETERMINATION: option (B). Outside the W1.3 erasure contract, and
  // BLOCKING later production privacy claims. Recorded in
  // docs/WAVE1_BLOCKER_REGISTER.md and surfaced to AEGIS as a residual, not
  // as a closed finding.
  await bindVictimAddress();
  const local = VICTIM_NORMALIZED.split("@")[0]!;
  const domain = VICTIM_NORMALIZED.split("@")[1]!;

  // (1) The subject's OWN content, carrying the address contiguously. Note
  // that `correct` accepts it — the guard is on `assign_alias` only — which is
  // itself part of the measurement.
  const subjectHead = await store().readHead(SCOPE, PARTICIPANT);
  const leaking = { participant: PARTICIPANT, note: `reach me at ${VICTIM_ADDRESS}`, part: local, rest: domain };
  const correctReceipt = await issue(
    authorization({
      action: "correct",
      targetRecordId: PARTICIPANT,
      expectedHead: headOf(subjectHead!.version, subjectHead!.contentDigest),
      proposedContent: leaking,
    }),
  );
  const corrected = await store().correct({
    actor: SCOPE,
    authorizationId: correctReceipt.authorizationId,
    recordId: PARTICIPANT,
    proposedContent: leaking,
    mutationReceiptId: "mutation.x10.correct",
  });
  assert.equal(corrected.verified, true, corrected.rejection ?? "");
  assert.notDeepEqual(await plaintextSightings(VICTIM_NORMALIZED), [], "fixture precondition");

  // (2) ANOTHER record, carrying the same address contiguously AND split
  // across two fields.
  await seedGenesis(
    { note: `cc: ${VICTIM_ADDRESS}`, localPart: local, domainPart: domain },
    { recordId: "participant-x10-bystander" },
  );

  const erased = await eraseRecordAtHead(PARTICIPANT, "mutation.x10.erase", "tombstone-x10");
  assert.equal(erased.result.verified, true, erased.result.rejection ?? "");

  // ---- WHAT THE CONTRACT DELIVERS -----------------------------------
  // The subject's own content is gone from every version it ever had.
  // Asserted as ABSENCE OF THE IDENTIFIER, not as "content is null": the
  // deletion appends its own final version whose content is the deletion
  // ORDER, which legitimately is not null and carries no subject material.
  const subjectRows = await adminPool.query(
    `SELECT count(*)::int AS n FROM memory_record_versions
      WHERE record_id = $1
        AND (payload->'content')::text ILIKE '%' || $2 || '%'`,
    [PARTICIPANT, local],
  );
  assert.equal(subjectRows.rows[0].n, 0, "the subject's own content must not keep the identifier on any version");
  // The alias, its index and its key are gone.
  assert.equal(await aliases().resolveAlias(SCOPE, VICTIM_NORMALIZED), null);

  // ---- WHAT THE CONTRACT DOES NOT DELIVER, EXACTLY ------------------
  // The bystander's content still holds the address, contiguously and split.
  const bystander = await adminPool.query(
    `SELECT payload->'content' AS content FROM memory_record_versions
      WHERE record_id = 'participant-x10-bystander' ORDER BY version DESC LIMIT 1`,
  );
  const content = JSON.stringify(bystander.rows[0].content);
  assert.ok(content.includes(local), `the residual is the point of this test: ${content}`);
  assert.ok(content.includes(domain), content);
  // Stated as a measurement rather than a hope: the ONLY record still holding
  // it is the one outside the subject's canonical merge set.
  const sightings = await plaintextSightings(VICTIM_NORMALIZED);
  assert.deepEqual(
    [...sightings].sort(),
    // ONE physical residual, surfaced twice: `memory_records_retrievable` is a
    // VIEW over `memory_record_versions`. Named exactly, so a future change
    // that puts the identifier anywhere else — an index, a receipt, a
    // tombstone, another table — is a failure here rather than a footnote.
    ["memory_record_versions.payload", "memory_records_retrievable.payload"],
    `unexpected residual locations: ${JSON.stringify(sightings)}`,
  );
  // And it is exactly the bystander: the subject's own rows hold nothing.
  const whose = await adminPool.query(
    `SELECT DISTINCT record_id FROM memory_record_versions
      WHERE (payload->'content')::text ILIKE '%' || $1 || '%' ORDER BY record_id`,
    [local],
  );
  assert.deepEqual(whose.rows.map((r) => r.record_id), ["participant-x10-bystander"]);
});

test("RTX-M10: a key that enters scope BETWEEN the proof phase and the commit is refused, not accepted", async () => {
  // ---- A REAL MUTATION SURVIVOR (red team B6, M10) ------------------
  // `throw new MutationAborted("merged_keys_changed_during_proof")` could be
  // changed to `continue` and all 1058 tests still passed. That string
  // appeared in NO test in the repository — and it is the ONLY control closing
  // the unsound direction of the K-02 design: the provider is asked BEFORE the
  // transaction opens, which is sound for a key that answered "destroyed"
  // because destruction latches, and says nothing at all about a key that was
  // never asked about.
  //
  // The window is forced rather than raced: the provider blocks on its first
  // question, a new in-scope key is added while it is blocked, and the
  // transaction's re-read under the record's lock then sees a key the proof
  // phase never answered for.
  await absorbVictim("mutation.m10.merge");
  const erased = await eraseRecordAtHead(PARTICIPANT, "mutation.m10.absorbed", "tombstone-m10-absorbed");
  assert.equal(erased.result.verified, true, erased.result.rejection ?? "");

  let release: (() => void) | undefined;
  let blocked = 0;
  const blocking = {
    ...TEST_PII_KEYS,
    dataKeyState: async (input: Parameters<typeof TEST_PII_KEYS.dataKeyState>[0]) => {
      if (blocked === 0) {
        blocked += 1;
        await new Promise<void>((resolve) => {
          release = resolve;
        });
      }
      return TEST_PII_KEYS.dataKeyState(input);
    },
  } as typeof TEST_PII_KEYS;

  // A second in-scope key, added while the proof phase is waiting. Written as
  // the admin with the binding guards stood down and RE-ENABLED before the
  // commit, because what is being tested is the store's reaction to a key
  // appearing late, not how it got there.
  const addLateKey = async () => {
    const client = await adminPool.connect();
    try {
      await client.query("BEGIN");
      await client.query(`ALTER TABLE memory_alias_bindings DISABLE TRIGGER USER`);
      await client.query(`ALTER TABLE memory_pii_key_erasures DISABLE TRIGGER USER`);
      await client.query(
        `INSERT INTO memory_alias_bindings
           (tenant_id, workspace_id, principal_id, user_id, cross_workspace_policy,
            scope_key, alias_id, skeleton_algorithm, normalization_profile,
            canonical_participant_id, script_code, restriction_level,
            subject_participant_id, source_evidence_ref, source_evidence_digest,
            observed_at, fresh_until, authorization_id, mutation_receipt_id,
            bound_at, removed_at, removed_by_mutation_receipt_id,
            removed_authorization_id, payload, created_at, pii_envelope,
            pii_key_ref, pii_key_version, pii_erased_at, pii_erasure_tombstone_id)
         SELECT tenant_id, workspace_id, principal_id, user_id, cross_workspace_policy,
                scope_key, 'alias-m10-late', skeleton_algorithm, normalization_profile,
                canonical_participant_id, script_code, restriction_level,
                subject_participant_id, source_evidence_ref, source_evidence_digest,
                observed_at, fresh_until, authorization_id,
                'mutation.m10.late.bind',
                bound_at, removed_at, removed_by_mutation_receipt_id,
                removed_authorization_id,
                jsonb_set(
                  jsonb_set(payload, '{aliasId}', '"alias-m10-late"'),
                  '{mutationReceiptId}', '"mutation.m10.late.bind"'),
                created_at, pii_envelope,
                'pii-key:local-test/v1:m10-late-key', pii_key_version,
                pii_erased_at, pii_erasure_tombstone_id
           FROM memory_alias_bindings
          WHERE alias_id = 'alias-pii-001' AND tenant_id = $1`,
        [SCOPE.tenantId],
      );
      // BOTH events. The late key has to satisfy the DATABASE's own helper —
      // `aaliyah_memory_unerased_merged_records` refuses a merged-in key with
      // no destruction evidence, and would refuse this erasure as
      // `merged_records_not_erased` long before the store's subset guard ran.
      // The guard under test is the one that catches a key the PROOF PHASE
      // never asked about, which is a different thing from an unerased one.
      for (const event of ["erasure_committed", "key_destroyed"]) {
        await client.query(
          `INSERT INTO memory_pii_key_erasures
             (tenant_id, workspace_id, tombstone_id, alias_id,
              binding_mutation_receipt_id, key_ref, provider_id, event)
           VALUES ($1, $2, 'tombstone-m10-absorbed', 'alias-m10-late',
                   'mutation.m10.late.bind', 'pii-key:local-test/v1:m10-late-key',
                   $3, $4)`,
          [SCOPE.tenantId, SCOPE.workspaceId, TEST_PII_KEYS.providerId, event],
        );
      }
      await client.query(`ALTER TABLE memory_alias_bindings ENABLE TRIGGER USER`);
      await client.query(`ALTER TABLE memory_pii_key_erasures ENABLE TRIGGER USER`);
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  };

  const attempt = eraseRecordAtHead(
    SURVIVOR, "mutation.m10.survivor", "tombstone-m10-survivor", "subject_erasure_request",
    createPostgresTrustedMemoryStore(writePool, readPool, { piiKeys: blocking }),
  );
  // Wait until the proof phase is actually blocked, then widen the scope.
  const waitedFrom = Date.now();
  while (release === undefined && Date.now() - waitedFrom < 20_000) {
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  assert.ok(release, "the provider never blocked: the window this test needs did not open");
  await addLateKey();
  release();
  const refused = await attempt;

  // THE ASSERTION. A key nobody asked about must never pass for a key that
  // answered.
  assert.equal(
    refused.result.verified,
    false,
    "a key that entered scope after the proof phase was accepted",
  );
  assert.equal(refused.result.rejection, "merged_keys_changed_during_proof");
  assert.equal(await nonceConsumed(refused.receipt.authorizationId), false);
  // TRANSIENT BY CONSTRUCTION. The refusal above says "a key appeared that
  // nobody asked about"; a retry ASKS about it, so that reason cannot survive
  // the retry. Here the late key is one the test provider never issued, so the
  // retry's honest answer is that its destruction is not provable — a
  // different refusal, from the settlement path, which is the point: the
  // transient reason does not persist and does not become an acceptance.
  const retried = await eraseRecordAtHead(SURVIVOR, "mutation.m10.retry", "tombstone-m10-retry");
  assert.equal(retried.result.verified, false, "the unprovable late key was accepted on retry");
  assert.equal(retried.result.rejection, "key_destruction_not_proven");
  const obligations = await store().listKeyDestructionObligations({ actor: SCOPE });
  assert.ok(
    obligations.some((o) => o.keyRef === "pii-key:local-test/v1:m10-late-key"),
    `the late key got no obligation: ${JSON.stringify(obligations.map((o) => o.keyRef))}`,
  );

  // The guards really came back on.
  const enabled = await adminPool.query(
    `SELECT count(*)::int AS n FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
      WHERE NOT t.tgisinternal AND t.tgenabled <> 'O'
        AND c.relname IN ('memory_alias_bindings', 'memory_pii_key_erasures')`,
  );
  assert.equal(enabled.rows[0].n, 0, "the fixture left a guard disabled");
});

test("RTX-M3: an UNSOUND settlement is refused by the COMPLETION PASS too, not only by the pre-check", async () => {
  // ---- A REAL MUTATION SURVIVOR (red team B6, M3) -------------------
  // Dropping `settlement.sound` from the COMPLETION PASS's branch survived all
  // 1058 tests — and the reviewer exploited it: with that one line gone, S-9
  // STILL PASSED while a re-erasure returned `verified:true, keysPending:0`
  // with the key `active` and the pre-erasure copy still decrypting.
  //
  // The same shape as M-08 and M-23 for the third time: S-9 reaches the
  // soundness check only through the PRE-CHECK, so the completion pass's copy
  // of it was claimed and never driven. This drives it.
  const bound = await bindNumberedParticipantAs(
    "participant-m3", "alias-m3", "person-m3@example.com", "mutation.m3.bind",
  );
  const binding = await bindingState("alias-m3");
  TEST_PII_KEYS.setAvailable(false);
  let erased;
  try {
    erased = await eraseRecordAtHead("participant-m3", "mutation.m3.erase", "tombstone-m3");
    assert.equal(erased.result.rejection, "key_destruction_not_proven");
  } finally {
    TEST_PII_KEYS.setAvailable(true);
  }
  // A settlement whose digest is not the digest of its own evidence. Written
  // by the settler directly, because the store always computes the digest
  // correctly — so this is the only way the state is reachable.
  await runAs(
    "aaliyah_memory_settler",
    `INSERT INTO memory_key_destruction_settlements
       (settlement_receipt_id, tenant_id, workspace_id, subject_record_id, alias_id,
        key_ref, key_version, provider_id, binding_mutation_receipt_id,
        erasure_authorization_id, erasure_tombstone_id, destruction_attempt_id,
        evidence, evidence_digest, settlement_authority_id, verifier_principal_id,
        decision, policy_version, nonce, predecessor_state, successor_state, decided_at)
     VALUES ('settlement-m3-liar',$1,$2,'participant-m3','alias-m3',$3,$4,$5,
             'mutation.m3.bind',$6,'tombstone-m3','attempt',
             $7::jsonb,$8,'authority','verifier','PROVEN_DESTROYED',
             'aaliyah.key-destruction-settlement/v1','nonce-m3-liar',
             'ERASURE_PENDING_SETTLEMENT','PROVEN_DESTROYED',now())`,
    [
      SCOPE.tenantId, SCOPE.workspaceId, binding.pii_key_ref, binding.pii_key_version,
      TEST_PII_KEYS.providerId, erased.receipt.authorizationId,
      JSON.stringify({ kind: "certificate", statement: "trust me" }),
      settlementEvidenceDigest({ kind: "something", else: "entirely" }),
    ],
  );

  // THE ASSERTION, through the COMPLETION PASS and a store that cannot ask the
  // provider — the exact path M3 left undefended.
  const pass = await NO_VAULT().completePendingAliasErasures();
  assert.equal(
    pass.notProven,
    1,
    `an unsound settlement was counted as proof by the completion pass: ${JSON.stringify(pass)}`,
  );
  assert.deepEqual(pass.notProvenReasons, { CONTRADICTORY_EVIDENCE: 1 });
  assert.equal(pass.pending, 1, JSON.stringify(pass));
  // Nothing was recorded destroyed, and the key is alive.
  const evidence = await adminPool.query(
    `SELECT count(*)::int AS n FROM memory_pii_key_erasures
      WHERE key_ref = $1 AND event = 'key_destroyed'`,
    [bound.keyRef],
  );
  assert.equal(evidence.rows[0].n, 0);
  assert.equal(await TEST_PII_KEYS.dataKeyState({ scope: DATA_SCOPE, keyRef: bound.keyRef }), "active");

  // POSITIVE CONTROL: the owning provider's own pass destroys it for real, so
  // the refusal above is the unsound settlement and not a store that refuses
  // everything.
  const honest = await store().completePendingAliasErasures();
  assert.equal(honest.destroyed, 1, JSON.stringify(honest));
  assert.equal(await TEST_PII_KEYS.dataKeyState({ scope: DATA_SCOPE, keyRef: bound.keyRef }), "destroyed");
});

// ---------------------------------------------------------------------------
// R — NO PROVIDER CALL HOLDS A DATABASE CONNECTION (reliability K-02)
// ---------------------------------------------------------------------------

test("R-1 K-02 (probe1): no transaction and no record lock is held ACROSS a slow provider call", async () => {
  // ---- WHAT WAS OBSERVED AT 8a0bf05 ---------------------------------
  // Reliability review, CRITICAL, executed. The survivor-erasure provider
  // calls ran inside the open `mutate()` transaction, holding the record's
  // `pg_advisory_xact_lock` and a pool connection. probe1 polled
  // `pg_stat_activity`/`pg_locks` and saw `observedIdleInTransaction: true`
  // and `observedAdvisoryLock: true` for the whole call, and measured
  // `elapsed_ms: 6029` — the slot was held for the provider's full latency,
  // FOUR SECONDS after PostgreSQL had already killed the session on
  // `idle_in_transaction_session_timeout`, because the DB's own bound cannot
  // release a connection the client is still awaiting.
  await absorbVictim("mutation.r1.merge");
  const erased = await eraseRecordAtHead(PARTICIPANT, "mutation.r1.absorbed", "tombstone-r1-absorbed");
  assert.equal(erased.result.verified, true, erased.result.rejection ?? "");

  let asked = false;
  const slow = {
    ...TEST_PII_KEYS,
    dataKeyState: async (input: Parameters<typeof TEST_PII_KEYS.dataKeyState>[0]) => {
      asked = true;
      await new Promise((resolve) => setTimeout(resolve, 1_500));
      return TEST_PII_KEYS.dataKeyState(input);
    },
  } as typeof TEST_PII_KEYS;

  // MEASURED AS A DURATION, NOT AS A FLAG. Every multi-statement transaction
  // is briefly `idle in transaction` between its own statements, so the
  // presence of one proves nothing. The finding was that a transaction stayed
  // open FOR THE PROVIDER'S WHOLE LATENCY, so the measurement is the oldest
  // open transaction's age, and the bound is a fraction of the hang.
  const HANG_MS = 1_500;
  const observed = { maxIdleTxMs: 0, maxAdvisoryMs: 0, samples: 0 };
  const poll = setInterval(() => {
    void adminPool
      .query(
        `SELECT
           COALESCE((SELECT max(EXTRACT(EPOCH FROM (clock_timestamp() - xact_start)) * 1000)
                       FROM pg_stat_activity
                      WHERE datname = current_database() AND state = 'idle in transaction'
                        AND pid <> pg_backend_pid()), 0)::float8 AS idle_tx_ms,
           -- ALSO A DURATION, for the same reason. A record's advisory lock
           -- is legitimately held for the few statements of an ordinary
           -- mutation, so its PRESENCE proves nothing; what the finding was
           -- about is the lock being held ACROSS the provider call. Excludes
           -- this file's own shared-table lock, held for its whole run
           -- (tests/support/sharedMemoryTables.ts, key 728133001 — classid is
           -- the key's high word, objid its low word).
           -- ...AND ONLY WHERE THE HOLDER IS WAITING ON SOMETHING OUTSIDE THE
           -- DATABASE. A transaction that is actively running statements holds
           -- the record lock for as long as its statements take, which under a
           -- full-suite load is legitimately a second or more. probe1's
           -- signature was the two together: the lock held WHILE the session
           -- sat idle in transaction, because the client was awaiting a
           -- provider. Measuring the lock alone failed this test under
           -- concurrency for a reason that was not the finding.
           COALESCE((SELECT max(EXTRACT(EPOCH FROM (clock_timestamp() - a.xact_start)) * 1000)
                       FROM pg_locks AS l
                       JOIN pg_stat_activity AS a ON a.pid = l.pid
                      WHERE l.locktype = 'advisory'
                        AND l.database = (SELECT oid FROM pg_database WHERE datname = current_database())
                        AND l.pid <> pg_backend_pid()
                        AND a.state = 'idle in transaction'
                        AND a.xact_start IS NOT NULL
                        AND NOT (l.classid = 0 AND l.objid = 728133001)), 0)::float8 AS advisory_ms`,
      )
      .then((r) => {
        observed.samples += 1;
        const age = Number(r.rows[0].idle_tx_ms);
        if (age > observed.maxIdleTxMs) observed.maxIdleTxMs = age;
        const lockAge = Number(r.rows[0].advisory_ms);
        if (lockAge > observed.maxAdvisoryMs) observed.maxAdvisoryMs = lockAge;
      })
      .catch(() => undefined);
  }, 100);

  let result;
  try {
    result = await eraseRecordAtHead(
      SURVIVOR, "mutation.r1.survivor", "tombstone-r1-survivor", "subject_erasure_request",
      createPostgresTrustedMemoryStore(writePool, readPool, { piiKeys: slow }),
    );
  } finally {
    clearInterval(poll);
  }
  assert.equal(result.result.verified, true, result.result.rejection ?? "");
  assert.ok(asked, "fixture precondition: the slow provider must actually have been consulted");
  assert.ok(observed.samples >= 5, `the poller must have sampled during the wait: ${observed.samples}`);
  // THE ASSERTIONS THAT FAILED AT 8a0bf05: no transaction stayed open across
  // the provider call, and the record's advisory lock was never held during it.
  assert.ok(
    observed.maxIdleTxMs < HANG_MS / 2,
    `a transaction stayed open ${Math.round(observed.maxIdleTxMs)}ms across a ${HANG_MS}ms provider call`,
  );
  assert.ok(
    observed.maxAdvisoryMs < HANG_MS / 2,
    `a record advisory lock was held ${Math.round(observed.maxAdvisoryMs)}ms across a ${HANG_MS}ms provider call`,
  );
});

test("R-2 K-02 (probe2): concurrent erasures with a hung provider do NOT exhaust the pool for an unrelated mutation", async () => {
  // ---- WHAT WAS OBSERVED AT 8a0bf05 ---------------------------------
  // probe2: three ordinary, authorized survivor erasures against three
  // DIFFERENT unlocked records, with a 5000ms provider hang, saturated a
  // three-connection mutation pool. A completely unrelated `correct()` on an
  // unlocked fourth record, fired 300ms later, FAILED OUTRIGHT with "timeout
  // exceeded when trying to connect" at t=2805ms. Scaled to production
  // (`pool.max: 10`) that is a full write-path outage for every tenant sharing
  // the pool, caused by nothing worse than KMS latency and reachable by
  // ordinary GDPR-shaped traffic.
  //
  // The falsifier the reviewer named: re-run probe2 — the unrelated mutation
  // should complete despite the provider still being hung.
  const HANG_MS = 3_000;
  const CONCURRENCY = 3;
  // A pool as small as the concurrency, so exhaustion is the DEFAULT outcome
  // unless the provider call is genuinely outside the transaction.
  const smallWrite = new Pool({ connectionString: DB_URL, max: CONCURRENCY });
  smallWrite.on("error", () => undefined);
  const smallRead = new Pool({ connectionString: DB_URL, max: 2 });
  smallRead.on("error", () => undefined);
  try {
    const survivors: string[] = [];
    for (let i = 0; i < CONCURRENCY; i += 1) {
      const absorbed = `participant-r2-absorbed-${i}`;
      const survivor = `participant-r2-survivor-${i}`;
      await bindNumberedParticipantAs(absorbed, `alias-r2-${i}`, `person-r2-${i}@example.com`, `mutation.r2.bind.${i}`);
      await seedGenesis({ participant: survivor, generation: 1 }, { recordId: survivor });
      await mergeRecordInto(absorbed, survivor, `mutation.r2.merge.${i}`);
      const e = await eraseRecordAtHead(absorbed, `mutation.r2.absorbed.${i}`, `tombstone-r2-absorbed-${i}`);
      assert.equal(e.result.verified, true, e.result.rejection ?? "");
      survivors.push(survivor);
    }
    // An unrelated record for the mutation that must NOT be starved.
    const bystanderGenesis = await seedGenesis({ note: "bystander" }, { recordId: "participant-r2-bystander" });

    const hung = {
      ...TEST_PII_KEYS,
      dataKeyState: async (input: Parameters<typeof TEST_PII_KEYS.dataKeyState>[0]) => {
        await new Promise((resolve) => setTimeout(resolve, HANG_MS));
        return TEST_PII_KEYS.dataKeyState(input);
      },
    } as typeof TEST_PII_KEYS;
    const hangingStore = createPostgresTrustedMemoryStore(smallWrite, smallRead, { piiKeys: hung });
    const bystanderStore = createPostgresTrustedMemoryStore(smallWrite, smallRead, { piiKeys: TEST_PII_KEYS });

    const erasures = survivors.map((survivor, i) =>
      eraseRecordAtHead(
        survivor, `mutation.r2.erase.${i}`, `tombstone-r2-erase-${i}`, "subject_erasure_request", hangingStore,
      ),
    );
    // Fired while every erasure is still waiting on the provider.
    await new Promise((resolve) => setTimeout(resolve, 300));
    const startedAt = Date.now();
    const content = { note: "bystander corrected" };
    const receipt = await issue(
      authorization({
        action: "correct",
        targetRecordId: "participant-r2-bystander",
        expectedHead: headOf(1, bystanderGenesis),
        proposedContent: content,
      }),
    );
    const bystander = await bystanderStore.correct({
      actor: SCOPE,
      authorizationId: receipt.authorizationId,
      recordId: "participant-r2-bystander",
      proposedContent: content,
      mutationReceiptId: "mutation.r2.bystander",
    });
    const bystanderMs = Date.now() - startedAt;
    assert.equal(bystander.verified, true, bystander.rejection ?? "");
    // It must not merely succeed — it must succeed WHILE the provider is still
    // hung, which is what proves the slot was never held.
    assert.ok(
      bystanderMs < HANG_MS,
      `the unrelated mutation waited ${bystanderMs}ms for a ${HANG_MS}ms provider hang`,
    );
    const settled = await Promise.all(erasures);
    for (const e of settled) assert.equal(e.result.verified, true, e.result.rejection ?? "");
  } finally {
    await smallWrite.end().catch(() => undefined);
    await smallRead.end().catch(() => undefined);
  }
});

test("R-3 K-04 (probe3): the settled-key audit is BOUNDED per pass, and round-robins so every key is still reached", async () => {
  // ---- WHAT WAS OBSERVED AT 8a0bf05 ---------------------------------
  // Reliability review, HIGH, executed. The evidenced-key audit had no `LIMIT`
  // at all: probe3 seeded 150 honestly-erased participants and a completion
  // pass with NOTHING pending made exactly 150 `dataKeyState()` calls — and an
  // immediate second pass made the same 150 again. Unconditional, unbounded,
  // growing forever with the store's all-time erasure volume, and awaited by
  // `server.ts` before `app.listen()`.
  const SEEDED = 7;
  const LIMIT = 2;
  const keys: string[] = [];
  for (let i = 0; i < SEEDED; i += 1) {
    const bound = await bindNumberedParticipantAs(
      `participant-r3-${i}`, `alias-r3-${i}`, `person-r3-${i}@example.com`, `mutation.r3.bind.${i}`,
    );
    const erased = await eraseRecordAtHead(bound.participant, `mutation.r3.erase.${i}`, `tombstone-r3-${i}`);
    assert.equal(erased.result.verified, true, erased.result.rejection ?? "");
    keys.push(bound.keyRef);
  }
  // Every key is settled: nothing is pending, so the ONLY work a pass can do
  // is the audit — which is exactly probe3's setup.
  const asked: string[] = [];
  const counting = {
    ...TEST_PII_KEYS,
    dataKeyState: async (input: Parameters<typeof TEST_PII_KEYS.dataKeyState>[0]) => {
      asked.push(input.keyRef);
      return TEST_PII_KEYS.dataKeyState(input);
    },
  } as typeof TEST_PII_KEYS;
  const bounded = createPostgresTrustedMemoryStore(writePool, readPool, {
    piiKeys: counting,
    evidencedAuditLimit: LIMIT,
  });

  const first = await bounded.completePendingAliasErasures();
  assert.deepEqual(first, {
    destroyed: 0, repaired: 0, contradictions: 0, pending: 0, notProven: 0, notProvenReasons: {},
  });
  // BOUNDED: the cost of a pass does not depend on how much was ever erased.
  assert.equal(asked.length, LIMIT, `audited ${asked.length} keys under a limit of ${LIMIT}`);

  // ROUND-ROBIN: the next pass audits DIFFERENT keys, so a bound does not turn
  // into "the same first N keys forever" — which would be a different way of
  // not auditing, and no better. Least-recently-audited first is also what
  // stops a forged row hiding behind volume (security F2 of 03581a3), proven
  // separately by K-7 and K-8.
  const seen = new Set(asked);
  for (let pass = 0; pass < Math.ceil(SEEDED / LIMIT); pass += 1) {
    asked.length = 0;
    await bounded.completePendingAliasErasures();
    assert.ok(asked.length <= LIMIT, `pass ${pass} audited ${asked.length}`);
    for (const keyRef of asked) seen.add(keyRef);
  }
  assert.equal(seen.size, SEEDED, `only ${seen.size} of ${SEEDED} keys were ever audited`);
});

test("R-4 K-04 (probe4): one hung provider call is bounded by the store's own deadline, not by the provider", async () => {
  // probe4 at 8a0bf05: one evidenced key with a 4000ms provider hang took
  // `elapsed_ms: 8010` — exactly the sum of the two hangs the pass performs —
  // with nothing internal bounding it shorter. This is the call `server.ts`
  // awaits before `app.listen()`, so a hung provider blocked startup
  // indefinitely.
  const bound = await bindNumberedParticipantAs(
    "participant-r4", "alias-r4", "person-r4@example.com", "mutation.r4.bind",
  );
  TEST_PII_KEYS.setAvailable(false);
  try {
    const { result } = await eraseRecordAtHead("participant-r4", "mutation.r4.erase", "tombstone-r4");
    assert.equal(result.rejection, "key_destruction_not_proven");
  } finally {
    TEST_PII_KEYS.setAvailable(true);
  }
  const DEADLINE_MS = 400;
  // A provider that NEVER settles. Nothing but the store's own deadline can
  // end these calls, which is exactly what probe4 showed was missing.
  let calls = 0;
  const hung = {
    ...TEST_PII_KEYS,
    dataKeyState: () => {
      calls += 1;
      return new Promise<never>(() => {});
    },
    destroyDataKey: () => {
      calls += 1;
      return new Promise<never>(() => {});
    },
  } as unknown as typeof TEST_PII_KEYS;
  const store0 = createPostgresTrustedMemoryStore(writePool, readPool, {
    piiKeys: hung,
    providerDeadlineMs: DEADLINE_MS,
  });
  const startedAt = Date.now();
  const outcome = await store0.completePendingAliasErasures();
  const elapsed = Date.now() - startedAt;
  assert.ok(calls >= 1, "fixture precondition: the hung provider must have been called");
  // ABANDONED, and named. A provider that never answers cannot be proven.
  assert.equal(outcome.notProven, 1, JSON.stringify(outcome));
  assert.deepEqual(outcome.notProvenReasons, { PROVIDER_TIMEOUT: 1 });
  // BOUNDED: one pending key costs at most one deadline per call it makes,
  // and the pass returns rather than hanging the process that awaits it.
  assert.ok(
    elapsed < DEADLINE_MS * 6,
    `a hung provider took ${elapsed}ms under a ${DEADLINE_MS}ms per-call deadline`,
  );
  assert.equal(
    await TEST_PII_KEYS.dataKeyState({ scope: DATA_SCOPE, keyRef: bound.keyRef }),
    "active",
    "nothing may be recorded destroyed on an answer that never arrived",
  );
});

test("R-5 K-11: two racing completion passes report the destructions that ACTUALLY landed, never more", async () => {
  // Reliability review of 03581a3, MEDIUM: `destroyed` was incremented
  // unconditionally after `ON CONFLICT DO NOTHING`, so two racing passes over
  // ten keys reported 15 and 16 destroyed between them. The ledger was right
  // and the number the function RETURNED was not — and that number is what a
  // caller reads to decide whether an erasure finished.
  const PENDING = 6;
  for (let i = 0; i < PENDING; i += 1) {
    await bindNumberedParticipantAs(
      `participant-r5-${i}`, `alias-r5-${i}`, `person-r5-${i}@example.com`, `mutation.r5.bind.${i}`,
    );
    TEST_PII_KEYS.setAvailable(false);
    try {
      const { result } = await eraseRecordAtHead(`participant-r5-${i}`, `mutation.r5.erase.${i}`, `tombstone-r5-${i}`);
      assert.equal(result.rejection, "key_destruction_not_proven");
    } finally {
      TEST_PII_KEYS.setAvailable(true);
    }
  }
  const committed = await adminPool.query(
    `SELECT count(*)::int AS n FROM memory_pii_key_erasures WHERE event = 'erasure_committed'`,
  );
  assert.equal(committed.rows[0].n, PENDING, "fixture precondition: exactly this many keys are pending");

  const [a, b] = await Promise.all([
    store().completePendingAliasErasures(),
    store().completePendingAliasErasures(),
  ]);
  const landed = await adminPool.query(
    `SELECT count(*)::int AS n FROM memory_pii_key_erasures WHERE event = 'key_destroyed'`,
  );
  assert.equal(landed.rows[0].n, PENDING, "every pending key must end up destroyed exactly once");
  // THE ASSERTION THAT FAILED AT 8a0bf05: the two passes' reported totals sum
  // to what the ledger actually holds, not to more.
  assert.equal(
    a.destroyed + b.destroyed,
    PENDING,
    `two racing passes reported ${a.destroyed} + ${b.destroyed} destructions over ${PENDING} keys`,
  );
  assert.equal(a.pending + b.pending, 0, `${JSON.stringify(a)} / ${JSON.stringify(b)}`);
});

// ---------------------------------------------------------------------------
// S — KEY-DESTRUCTION SETTLEMENT (founder decision, OPTION B; K-01, K-09)
// ---------------------------------------------------------------------------

const NO_VAULT = () => createPostgresTrustedMemoryStore(writePool, readPool, { piiKeys: null });

/** A settlement request with every field the decision requires bound. */
function settlementFor(
  binding: { alias_id: string; mutation_receipt_id: string; pii_key_ref: string; pii_key_version: number },
  tombstoneId: string,
  authorizationId: string,
  overrides: Partial<Parameters<ReturnType<typeof NO_VAULT>["settleKeyDestruction"]>[0]> = {},
) {
  return {
    settlementReceiptId: "settlement-001",
    tenantId: SCOPE.tenantId,
    workspaceId: SCOPE.workspaceId,
    subjectRecordId: PARTICIPANT,
    aliasId: binding.alias_id,
    keyRef: binding.pii_key_ref,
    keyVersion: binding.pii_key_version,
    providerId: TEST_PII_KEYS.providerId,
    bindingMutationReceiptId: binding.mutation_receipt_id,
    erasureAuthorizationId: authorizationId,
    erasureTombstoneId: tombstoneId,
    destructionAttemptId: "attempt-001",
    evidence: {
      kind: "provider_decommission_certificate",
      statement: "the owning key provider was decommissioned; its HSM partition was destroyed",
      witnessedAt: "2026-09-17T00:00:00.000Z",
    },
    settlementAuthorityId: "principal-data-protection-officer",
    verifierPrincipalId: "principal-independent-auditor",
    decision: "PROVEN_DESTROYED" as const,
    nonce: "settlement-nonce-001",
    decidedAt: new Date("2026-09-17T01:00:00.000Z"),
    ...overrides,
  };
}

/**
 * The state K-01 and K-09 describe: a merged-in key whose erasure really did
 * commit, whose destruction this store cannot establish. Returns the binding
 * and the absorbed record's erasure authorization, which a settlement binds.
 */
async function survivorWithAnUnprovableMergedKey(): Promise<{
  binding: { alias_id: string; mutation_receipt_id: string; pii_key_ref: string; pii_key_version: number };
  tombstoneId: string;
  authorizationId: string;
}> {
  await absorbVictim("mutation.s.merge");
  const binding = await bindingState("alias-pii-001");
  // The absorbed record is erased HONESTLY: provider destroys the key and the
  // evidence records it. Nothing here is forged.
  const erased = await eraseRecordAtHead(PARTICIPANT, "mutation.s.absorbed", "tombstone-s-absorbed");
  assert.equal(erased.result.verified, true, erased.result.rejection ?? "");
  assert.equal(
    await TEST_PII_KEYS.dataKeyState({ scope: DATA_SCOPE, keyRef: binding.pii_key_ref }),
    "destroyed",
    "fixture precondition: the merged-in key really is destroyed",
  );
  return {
    binding: binding as never,
    tombstoneId: "tombstone-s-absorbed",
    authorizationId: erased.receipt.authorizationId,
  };
}

test("S-1 K-01: with NO key provider, a survivor whose merged-in key was genuinely destroyed is NOT ERASED — and not silently refused either", async () => {
  // ---- THE CRITICAL FINDING, REPRODUCED ------------------------------
  // Integration review of 8a0bf05: `piiKeys: null` is the ACTUAL production
  // wiring (src/server.ts, no production KMS provisioned). `state` was forced
  // to null, null is never "destroyed", so this erasure was refused
  // `merged_records_not_erased` FOREVER — including the survivor's own
  // content — with no retry, no completion pass and no admin action that
  // could change it, and no disclosure anywhere in the register.
  const { binding } = await survivorWithAnUnprovableMergedKey();

  const refused = await eraseRecordAtHead(
    SURVIVOR, "mutation.s1.survivor", "tombstone-s1-survivor", "subject_erasure_request", NO_VAULT(),
  );
  assert.equal(refused.result.verified, false);
  // NOT `merged_records_not_erased`: the merged-in record IS erased. What is
  // missing is proof about a key, and the answer says so.
  assert.equal(refused.result.rejection, "key_destruction_not_proven");
  assert.equal(await nonceConsumed(refused.receipt.authorizationId), false);

  // AND THE STATE IS FINDABLE. This is the part that turns a permanent,
  // unexplained refusal into something an operator can act on.
  const obligations = await NO_VAULT().listKeyDestructionObligations({ actor: SCOPE });
  assert.equal(obligations.length, 1, JSON.stringify(obligations));
  assert.equal(obligations[0]!.keyRef, binding.pii_key_ref);
  assert.equal(obligations[0]!.state, "KEY_DESTRUCTION_NOT_PROVEN");
  assert.equal(obligations[0]!.notProvenReason, "NO_PROVIDER_CONFIGURED");
  assert.equal(obligations[0]!.resolvedBy, null);
  assert.equal(obligations[0]!.settledBy, null);

  // POSITIVE CONTROL: a store that CAN ask the provider erases the same
  // survivor immediately. So the refusal is the missing provider, not the
  // merge — which is exactly the distinction that was collapsed.
  const allowed = await eraseRecordAtHead(SURVIVOR, "mutation.s1.survivor.ok", "tombstone-s1-ok");
  assert.equal(allowed.result.verified, true, allowed.result.rejection ?? "");
});

test("S-2 K-01/K-09: a PROVEN_DESTROYED settlement satisfies the key-destruction contract, and the survivor then erases", async () => {
  const { binding, tombstoneId, authorizationId } = await survivorWithAnUnprovableMergedKey();
  const store0 = NO_VAULT();
  const first = await eraseRecordAtHead(
    SURVIVOR, "mutation.s2.refused", "tombstone-s2-refused", "subject_erasure_request", store0,
  );
  assert.equal(first.result.rejection, "key_destruction_not_proven");

  const settled = await store0.settleKeyDestruction(
    settlementFor(binding, tombstoneId, authorizationId),
  );
  assert.deepEqual(settled, {
    recorded: true,
    replay: false,
    evidenceDigest: settlementEvidenceDigest(
      settlementFor(binding, tombstoneId, authorizationId).evidence,
    ),
  });

  // The obligation is CLOSED, and it names HOW — a settlement, not a provider.
  const obligations = await store0.listKeyDestructionObligations({ actor: SCOPE });
  assert.equal(obligations[0]!.state, "PROVEN_DESTROYED");
  assert.equal(obligations[0]!.resolvedBy, "SETTLEMENT");
  assert.equal(obligations[0]!.settledBy, "settlement-001");

  // ---- AND A LATER COMPLETION PASS MUST NOT RE-BLAME THE PROVIDER ----
  // Red team B7 against 86d33c9: the settlement branch of
  // `destroyCommittedAliasKeys` pushed the row onto `provenDestroyed`, which
  // feeds `clearHealedObligations` and writes `resolved_by = 'PROVIDER'` — so
  // a key proven by a SETTLEMENT was attributed to a provider that was never
  // asked (this store has none at all). The mutation sweep then re-added that
  // one line with nothing failing, because no test had ever run a pass OVER an
  // already-settled key: every settlement test stopped at the receipt.
  //
  // `resolvedBy` is the field an auditor reads to learn whether destruction
  // was witnessed or adjudicated. Those are not interchangeable.
  const pass = await store0.completePendingAliasErasures();
  const after = await store0.listKeyDestructionObligations({ actor: SCOPE });
  const settledOne = after.find((o) => o.keyRef === binding.pii_key_ref);
  assert.ok(settledOne !== undefined, `the obligation vanished: ${JSON.stringify(after)}`);
  assert.equal(
    settledOne.resolvedBy,
    "SETTLEMENT",
    `a settled key was re-attributed after a pass: ${JSON.stringify({ pass, settledOne })}`,
  );
  assert.equal(settledOne.settledBy, "settlement-001");
  assert.equal(settledOne.state, "PROVEN_DESTROYED");

  // No NEW destruction evidence here, and that is correct: this key was
  // destroyed honestly, so a provider-confirmed `key_destroyed` row already
  // holds the one slot `memory_pii_key_erasures_once` allows. What the
  // settlement supplies is the answer the STORE could not get. S-2b covers
  // the other state, where the settlement is what writes the evidence.
  const evidence = await adminPool.query(
    `SELECT settlement_receipt_id FROM memory_pii_key_erasures
      WHERE key_ref = $1 AND event = 'key_destroyed'`,
    [binding.pii_key_ref],
  );
  assert.equal(evidence.rowCount, 1);
  assert.equal(evidence.rows[0].settlement_receipt_id, null);

  // AND THE ERASURE NOW PROCEEDS, on the same store that could not ask.
  const second = await eraseRecordAtHead(
    SURVIVOR, "mutation.s2.allowed", "tombstone-s2-allowed", "subject_erasure_request", store0,
  );
  assert.equal(second.result.verified, true, second.result.rejection ?? "");
});

test("S-2c: a SETTLED obligation's resolution is immutable, enforced by the database (M-47/M-55)", async () => {
  // ---- TWO MUTATION SURVIVORS THAT MASKED EACH OTHER -----------------
  // The seventh pass's sweep found BOTH of the application guards on this
  // invariant surviving, and the reason is structural rather than a missing
  // test. `provenDestroyed` has exactly ONE consumer, `clearHealedObligations`.
  // So:
  //
  //   M-47 re-adds the `provenDestroyed.push(row)` that red-team B7 removed —
  //        invisible, because `clearHealedObligations` filters on
  //        `state = 'KEY_DESTRUCTION_NOT_PROVEN'` and a settled row is not in
  //        that state.
  //   M-55 removes that filter — invisible, because the settlement branch does
  //        not put the row in the list in the first place.
  //
  // Remove EITHER alone and nothing changes. Remove BOTH and a key proven by a
  // SETTLEMENT is recorded as resolved by a PROVIDER that was never asked. No
  // single-point mutation can be observed, so by this register's standard
  // neither guard is a control, however correct the behaviour is.
  //
  // The founder's settlement requirements already say a receipt is "immutable
  // after completion". That held for the settlement ROW and not for the
  // OBLIGATION it resolves, so migration 058 puts the invariant in the
  // database, where ONE statement can falsify it and where it binds every
  // caller rather than one call site. This test is that statement.
  const { binding, tombstoneId, authorizationId } = await survivorWithAnUnprovableMergedKey();
  const store0 = NO_VAULT();
  const refused = await eraseRecordAtHead(
    SURVIVOR, "mutation.s2c.refused", "tombstone-s2c-refused", "subject_erasure_request", store0,
  );
  assert.equal(refused.result.rejection, "key_destruction_not_proven");
  const settled = await store0.settleKeyDestruction(
    settlementFor(binding, tombstoneId, authorizationId),
  );
  assert.equal(settled.recorded, true, JSON.stringify(settled));

  const row = async () => {
    const r = await adminPool.query(
      `SELECT state, resolved_by, settled_by, observations
         FROM memory_key_destruction_obligations WHERE key_ref = $1`,
      [binding.pii_key_ref],
    );
    assert.equal(r.rowCount, 1);
    return r.rows[0];
  };
  const settledRow = await row();
  assert.equal(settledRow.resolved_by, "SETTLEMENT");
  assert.equal(settledRow.settled_by, "settlement-001");

  // ---- THE MUTATOR IS THE ROLE THAT RUNS `clearHealedObligations` ----
  // It holds UPDATE on this table, which is how provider-healed obligations
  // are closed. So this is the exact statement that function would issue with
  // both guards gone — not a hypothetical.
  await assert.rejects(
    () =>
      runAs(
        "aaliyah_memory_mutator",
        `UPDATE memory_key_destruction_obligations
            SET state = 'PROVEN_DESTROYED', not_proven_reason = 'SETTLED',
                resolved_by = 'PROVIDER', last_observed_at = now()
          WHERE key_ref = $1`,
        [binding.pii_key_ref],
      ),
    /a settled obligation resolution is immutable/,
    "a settlement-resolved obligation was re-attributed to the provider",
  );
  // Every field of the resolution is frozen, not just `resolved_by` — and each
  // is attempted AS THE ROLE THAT ACTUALLY HOLDS THE GRANT, so the refusal is
  // the trigger's and not a privilege error wearing its clothes. The grants are
  // column-level: the mutator may write state / resolved_by /
  // not_proven_reason (that is provider healing), and only the SETTLER may
  // write `settled_by`.
  for (const [role, column, value] of [
    ["aaliyah_memory_mutator", "state", "'KEY_DESTRUCTION_NOT_PROVEN'"],
    ["aaliyah_memory_mutator", "not_proven_reason", "'PROVIDER_UNAVAILABLE'"],
    ["aaliyah_memory_settler", "settled_by", "'settlement-forged'"],
    ["aaliyah_memory_settler", "resolved_by", "'PROVIDER'"],
  ] as const) {
    await assert.rejects(
      () =>
        runAs(
          role,
          `UPDATE memory_key_destruction_obligations SET ${column} = ${value} WHERE key_ref = $1`,
          [binding.pii_key_ref],
        ),
      /a settled obligation resolution is immutable/,
      `${column} was mutable on a settled obligation by ${role}`,
    );
  }
  // AND THE COLUMN GRANT IS THE FIRST LINE, INDEPENDENTLY OF THE TRIGGER:
  // the mutator cannot name `settled_by` at all, so even a future edit to the
  // trigger leaves the settlement pointer out of its reach.
  await assert.rejects(
    () =>
      runAs(
        "aaliyah_memory_mutator",
        `UPDATE memory_key_destruction_obligations SET settled_by = 'settlement-forged' WHERE key_ref = $1`,
        [binding.pii_key_ref],
      ),
    /permission denied for table memory_key_destruction_obligations/,
    "the mutator could name settled_by",
  );
  const unchanged = await row();
  assert.equal(unchanged.state, "PROVEN_DESTROYED");
  assert.equal(unchanged.resolved_by, "SETTLEMENT");
  assert.equal(unchanged.settled_by, "settlement-001");

  // ---- POSITIVE CONTROL, BOTH DIRECTIONS -----------------------------
  // (1) An OBSERVATIONAL write is still allowed on a settled row: recording
  // that a pass looked again is not a change to the resolution, and the
  // completion pass does exactly this.
  await runAs(
    "aaliyah_memory_mutator",
    `UPDATE memory_key_destruction_obligations
        SET observations = observations + 1, last_observed_at = now()
      WHERE key_ref = $1`,
    [binding.pii_key_ref],
  );
  const observed = await row();
  assert.equal(
    observed.observations,
    (settledRow.observations as number) + 1,
    "an observational write was refused on a settled obligation",
  );
  assert.equal(observed.resolved_by, "SETTLEMENT");

  // (2) An UNSETTLED obligation is freely resolvable by the provider — the
  // trigger refuses only what is already SETTLED, so ordinary healing (the
  // transient-outage case, which is the common one) still works. Without this
  // control the trigger could be a blanket freeze and this test would still
  // pass.
  // A SECOND, genuinely unsettled obligation, because the settled one cannot be
  // un-settled: the trigger binds the admin connection too, which is the point
  // of putting the invariant in the database rather than in a role's grants.
  const spare = await bindNumberedParticipantAs(
    "participant-s2c", "alias-s2c", "person-s2c@example.com", "mutation.s2c.bind",
  );
  TEST_PII_KEYS.setAvailable(false);
  try {
    const spareRefused = await eraseRecordAtHead(
      "participant-s2c", "mutation.s2c.spare", "tombstone-s2c-spare",
    );
    assert.equal(spareRefused.result.rejection, "key_destruction_not_proven");
  } finally {
    TEST_PII_KEYS.setAvailable(true);
  }
  const unsettled = await adminPool.query(
    `SELECT settled_by FROM memory_key_destruction_obligations WHERE key_ref = $1`,
    [spare.keyRef],
  );
  assert.equal(unsettled.rowCount, 1, "fixture precondition: the spare key needs an obligation");
  assert.equal(unsettled.rows[0].settled_by, null, "fixture precondition: it must be UNSETTLED");
  await runAs(
    "aaliyah_memory_mutator",
    `UPDATE memory_key_destruction_obligations
        SET state = 'PROVEN_DESTROYED', not_proven_reason = 'SETTLED',
            resolved_by = 'PROVIDER'
      WHERE key_ref = $1 AND settled_by IS NULL`,
    [spare.keyRef],
  );
  const healed = await adminPool.query(
    `SELECT resolved_by FROM memory_key_destruction_obligations WHERE key_ref = $1`,
    [spare.keyRef],
  );
  assert.equal(
    healed.rows[0]?.resolved_by,
    "PROVIDER",
    "the trigger blocked ordinary provider healing of an UNSETTLED obligation",
  );
});

test("S-2b K-01: the PERMANENT case — no provider AND no destruction evidence — is settleable, and the settlement writes the evidence", async () => {
  // ---- RV5-U-7, THE INTEGRATION REVIEW'S OTHER HALF ------------------
  // The absorbed record's erasure half-committed during a provider outage, so
  // its key has `erasure_committed` and NO `key_destroyed`. With
  // `piiKeys: null` the completion pass returns `{destroyed:0, pending:1}` and
  // always will, and the survivor's erasure is refused by the DATABASE's own
  // helper — with, at 8a0bf05, no retry, no pass and no admin action that
  // could ever change it.
  await absorbVictim("mutation.s2b.merge");
  const binding = await bindingState("alias-pii-001");
  TEST_PII_KEYS.setAvailable(false);
  let absorbed;
  try {
    absorbed = await eraseRecordAtHead(PARTICIPANT, "mutation.s2b.absorbed", "tombstone-s2b-absorbed");
    assert.equal(absorbed.result.rejection, "key_destruction_not_proven");
  } finally {
    TEST_PII_KEYS.setAvailable(true);
  }
  const store0 = NO_VAULT();
  // With no provider, nothing completes it — for ever.
  assert.deepEqual(await store0.completePendingAliasErasures(), {
    destroyed: 0,
    repaired: 0,
    contradictions: 0,
    pending: 1,
    notProven: 1,
    notProvenReasons: { NO_PROVIDER_CONFIGURED: 1 },
  });
  const refused = await eraseRecordAtHead(
    SURVIVOR, "mutation.s2b.refused", "tombstone-s2b-refused", "subject_erasure_request", store0,
  );
  // The DATABASE's helper refuses here, before the provider question: the
  // merged-in record really has no destruction evidence.
  assert.equal(refused.result.rejection, "merged_records_not_erased");

  // THE WAY OUT. Independently authorized, independently verified, bound to
  // this exact binding and this exact committed erasure.
  const settled = await store0.settleKeyDestruction(
    settlementFor(binding, "tombstone-s2b-absorbed", absorbed.receipt.authorizationId, {
      settlementReceiptId: "settlement-s2b",
      nonce: "nonce-s2b",
    }),
  );
  assert.equal(settled.recorded, true, JSON.stringify(settled));
  // Here the settlement IS what writes the evidence — and it is labelled, so
  // no auditor can mistake it for a provider confirmation.
  const evidence = await adminPool.query(
    `SELECT settlement_receipt_id FROM memory_pii_key_erasures
      WHERE key_ref = $1 AND event = 'key_destroyed'`,
    [binding.pii_key_ref],
  );
  assert.equal(evidence.rowCount, 1);
  assert.equal(evidence.rows[0].settlement_receipt_id, "settlement-s2b");
  // The completion pass now agrees, and the survivor erases.
  const completed = await store0.completePendingAliasErasures();
  assert.equal(completed.pending, 0, JSON.stringify(completed));
  const allowed = await eraseRecordAtHead(
    SURVIVOR, "mutation.s2b.allowed", "tombstone-s2b-allowed", "subject_erasure_request", store0,
  );
  assert.equal(allowed.result.verified, true, allowed.result.rejection ?? "");
});

test("S-3: STILL_UNKNOWN remains unresolved — it settles nothing and the erasure stays refused", async () => {
  // "Only PROVEN_DESTROYED may satisfy the key-destruction portion of verified
  // erasure. STILL_UNKNOWN remains unresolved." Enforced by the database: only
  // a PROVEN_DESTROYED settlement can produce destruction evidence, so there
  // is no path from any of these decisions to erased.
  //
  // One PARTICIPANT PER DECISION, each with its own real erasure
  // authorization. The earlier version reused one key and varied the
  // `erasureAuthorizationId` string to dodge `scope_unique` — which stopped
  // working, correctly, when red team B1 made that id resolve against the
  // tombstone that actually witnessed the erasure.
  const store0 = NO_VAULT();
  for (const decision of ["STILL_UNKNOWN", "PROVIDER_UNAVAILABLE", "EVIDENCE_INSUFFICIENT", "RETENTION_BLOCKED"] as const) {
    const slug = decision.toLowerCase().replace(/_/g, "-");
    const bound = await bindNumberedParticipantAs(
      `participant-s3-${slug}`, `alias-s3-${slug}`, `person-s3-${slug}@example.com`, `mutation.s3.bind.${slug}`,
    );
    const binding = await bindingState(`alias-s3-${slug}`);
    TEST_PII_KEYS.setAvailable(false);
    let erased;
    try {
      erased = await eraseRecordAtHead(
        `participant-s3-${slug}`, `mutation.s3.erase.${slug}`, `tombstone-s3-${slug}`,
      );
      assert.equal(erased.result.rejection, "key_destruction_not_proven", decision);
    } finally {
      TEST_PII_KEYS.setAvailable(true);
    }
    const recorded = await store0.settleKeyDestruction(
      settlementFor(binding as never, `tombstone-s3-${slug}`, erased.receipt.authorizationId, {
        subjectRecordId: `participant-s3-${slug}`,
        decision,
        settlementReceiptId: `settlement-${slug}`,
        nonce: `nonce-${slug}`,
      }),
    );
    assert.deepEqual(recorded.recorded, true, `${decision}: ${JSON.stringify(recorded)}`);

    // Unresolved: the obligation stays open and names no settlement.
    const obligations = await adminPool.query(
      `SELECT state, settled_by, resolved_by FROM memory_key_destruction_obligations
        WHERE key_ref = $1`,
      [bound.keyRef],
    );
    assert.equal(obligations.rowCount, 1, decision);
    assert.equal(obligations.rows[0].state, "KEY_DESTRUCTION_NOT_PROVEN", decision);
    assert.equal(obligations.rows[0].settled_by, null, decision);
    assert.equal(obligations.rows[0].resolved_by, null, decision);
    // And NO destruction evidence exists for it.
    const evidence = await adminPool.query(
      `SELECT count(*)::int AS n FROM memory_pii_key_erasures
        WHERE key_ref = $1 AND event = 'key_destroyed'`,
      [bound.keyRef],
    );
    assert.equal(evidence.rows[0].n, 0, `${decision} produced destruction evidence`);
    // The completion pass still counts it unproven, whatever was decided.
    const pass = await store0.completePendingAliasErasures();
    assert.ok(pass.notProven >= 1, `${decision}: ${JSON.stringify(pass)}`);
  }
});

test("S-3b: ONE settlement per key per erasure request — a second is refused, never an overwrite", async () => {
  // Action-specific, as the founder decision requires: an authorization that
  // settled one key cannot be reused to settle it again with a different
  // answer, and the refusal says so instead of silently replacing a decision.
  const { binding, tombstoneId, authorizationId } = await survivorWithAnUnprovableMergedKey();
  const store0 = NO_VAULT();
  const first = await store0.settleKeyDestruction(
    settlementFor(binding, tombstoneId, authorizationId, { decision: "STILL_UNKNOWN" }),
  );
  assert.equal(first.recorded, true, JSON.stringify(first));
  const second = await store0.settleKeyDestruction(
    settlementFor(binding, tombstoneId, authorizationId, {
      decision: "PROVEN_DESTROYED",
      settlementReceiptId: "settlement-second",
      nonce: "nonce-second",
    }),
  );
  assert.deepEqual(second, { recorded: false, rejection: "settlement_already_resolved" });
  // And the first decision stands: STILL_UNKNOWN settled nothing, so the key
  // is still unproven and the erasure is still refused.
  const refused = await eraseRecordAtHead(
    SURVIVOR, "mutation.s3b.survivor", "tombstone-s3b-survivor", "subject_erasure_request", store0,
  );
  assert.equal(refused.result.rejection, "key_destruction_not_proven");
});

test("S-12: only a PROVEN_DESTROYED settlement can record destruction, and the settler has no INSERT at all", async () => {
  // ---- TWO MUTATION SURVIVORS, ONE AFTER THE OTHER -----------------
  // M-23 (implementer's sweep): migration 055's evidence trigger requires
  // `s.decision = 'PROVEN_DESTROYED'`; weakening it to `IS NOT NULL` left
  // every test passing, because S-3 proves only that the STORE declines to
  // insert.
  //
  // B2 (red team against 86d33c9, HIGH): the first fix for that put the clause
  // inside `IF NEW.settlement_receipt_id IS NOT NULL`, so the settler simply
  // left the label NULL and the row was ACCEPTED —
  // `aaliyah_memory_unerased_merged_records()` then returned 0 rows for a
  // subject whose key was still active. The clause guarded the labelling
  // CONVENTION, not the evidence.
  //
  // So the settler has no INSERT on the evidence table at all, and the labelled
  // row is written by a SECURITY DEFINER function that supplies every column
  // from the settlement itself. Both halves are asserted here.
  const a = await bindNumberedParticipantAs(
    "participant-s12-a", "alias-s12-a", "person-s12-a@example.com", "mutation.s12.bind.a",
  );
  const b = await bindNumberedParticipantAs(
    "participant-s12-b", "alias-s12-b", "person-s12-b@example.com", "mutation.s12.bind.b",
  );
  const bindingA = await bindingState("alias-s12-a");
  const bindingB = await bindingState("alias-s12-b");
  TEST_PII_KEYS.setAvailable(false);
  let erasedA;
  let erasedB;
  try {
    erasedA = await eraseRecordAtHead("participant-s12-a", "mutation.s12.erase.a", "tombstone-s12-a");
    erasedB = await eraseRecordAtHead("participant-s12-b", "mutation.s12.erase.b", "tombstone-s12-b");
    assert.equal(erasedA.result.rejection, "key_destruction_not_proven");
    assert.equal(erasedB.result.rejection, "key_destruction_not_proven");
  } finally {
    TEST_PII_KEYS.setAvailable(true);
  }
  const store0 = NO_VAULT();
  const unresolved = await store0.settleKeyDestruction(
    settlementFor(bindingA as never, "tombstone-s12-a", erasedA.receipt.authorizationId, {
      subjectRecordId: "participant-s12-a",
      decision: "STILL_UNKNOWN",
      settlementReceiptId: "settlement-s12-a",
      nonce: "nonce-s12-a",
    }),
  );
  assert.equal(unresolved.recorded, true, JSON.stringify(unresolved));
  const resolved = await store0.settleKeyDestruction(
    settlementFor(bindingB as never, "tombstone-s12-b", erasedB.receipt.authorizationId, {
      subjectRecordId: "participant-s12-b",
      decision: "PROVEN_DESTROYED",
      settlementReceiptId: "settlement-s12-b",
      nonce: "nonce-s12-b",
    }),
  );
  assert.equal(resolved.recorded, true, JSON.stringify(resolved));

  // (1) B2: the settler cannot write evidence directly AT ALL — labelled or
  // not. This is the assertion the old version of this test could not make,
  // because the settler held INSERT and simply omitted the label.
  for (const label of ["'settlement-s12-b'", "NULL"]) {
    await assert.rejects(
      () =>
        runAs(
          "aaliyah_memory_settler",
          `INSERT INTO memory_pii_key_erasures
             (tenant_id, workspace_id, tombstone_id, alias_id,
              binding_mutation_receipt_id, key_ref, provider_id, event,
              settlement_receipt_id)
           SELECT tenant_id, workspace_id, tombstone_id, alias_id,
                  binding_mutation_receipt_id, key_ref, provider_id,
                  'key_destroyed', ${label}
             FROM memory_pii_key_erasures
            WHERE key_ref = $1 AND event = 'erasure_committed'`,
          [a.keyRef],
        ),
      /permission denied for table memory_pii_key_erasures/,
      `the settler could insert evidence with label ${label}`,
    );
  }

  // (2) M-23: the one path that CAN write it refuses a settlement whose
  // decision does not satisfy erasure.
  await assert.rejects(
    () =>
      runAs(
        "aaliyah_memory_settler",
        `SELECT public.aaliyah_memory_record_settled_destruction('settlement-s12-a')`,
      ),
    /only a PROVEN_DESTROYED settlement records destruction/,
  );
  const forA = await adminPool.query(
    `SELECT count(*)::int AS n FROM memory_pii_key_erasures
      WHERE key_ref = $1 AND event = 'key_destroyed'`,
    [a.keyRef],
  );
  assert.equal(forA.rows[0].n, 0, "a STILL_UNKNOWN settlement produced destruction evidence");
  // The trigger raises ONE message for every reason its PERFORM finds nothing,
  // so a provider or scope mismatch would refuse the insert below too — and
  // the mutant would survive while this test still passed. Pin the
  // precondition explicitly: every column the clause matches on ALREADY
  // agrees, and the DECISION is the only thing left to refuse it.
  const bound = await adminPool.query(
    `SELECT s.decision, s.provider_id = e.provider_id AS provider_agrees,
            (s.tenant_id = e.tenant_id AND s.workspace_id = e.workspace_id
              AND s.key_ref = e.key_ref) AS scope_agrees
       FROM memory_key_destruction_settlements AS s
       JOIN memory_pii_key_erasures AS e
         ON e.key_ref = s.key_ref AND e.event = 'erasure_committed'
      WHERE s.settlement_receipt_id = 'settlement-s12-a'`,
  );
  assert.equal(bound.rowCount, 1, "fixture precondition: the settlement and the evidence row must pair up");
  assert.equal(bound.rows[0].provider_agrees, true, "fixture precondition: provider must already agree");
  assert.equal(bound.rows[0].scope_agrees, true, "fixture precondition: scope must already agree");
  assert.equal(bound.rows[0].decision, "STILL_UNKNOWN", "fixture precondition: the decision is the defect");

  // (3) M-23 AT THE CLAUSE, not at the function. Two things enforce this:
  // `aaliyah_memory_record_settled_destruction` (asserted above) and the
  // INSERT trigger on the table. The sweep weakened the TRIGGER's
  // `s.decision = 'PROVEN_DESTROYED'` to `IS NOT NULL` and every test still
  // passed, because both assertions above go through the function. The
  // MUTATOR holds INSERT on this table — it is how ordinary provider-confirmed
  // destruction evidence is written — and the label is whatever the caller
  // supplies, so this path is reachable and the clause is the only thing on it.
  await assert.rejects(
    () =>
      runAs(
        "aaliyah_memory_mutator",
        `INSERT INTO memory_pii_key_erasures
           (tenant_id, workspace_id, tombstone_id, alias_id,
            binding_mutation_receipt_id, key_ref, provider_id, event,
            settlement_receipt_id)
         SELECT tenant_id, workspace_id, tombstone_id, alias_id,
                binding_mutation_receipt_id, key_ref, provider_id,
                'key_destroyed', 'settlement-s12-a'
           FROM memory_pii_key_erasures
          WHERE key_ref = $1 AND event = 'erasure_committed'`,
        [a.keyRef],
      ),
    /settled destruction evidence needs a PROVEN_DESTROYED settlement for that exact key/,
    "a STILL_UNKNOWN settlement labelled a destruction row",
  );
  const stillNone = await adminPool.query(
    `SELECT count(*)::int AS n FROM memory_pii_key_erasures
      WHERE key_ref = $1 AND event = 'key_destroyed'`,
    [a.keyRef],
  );
  assert.equal(stillNone.rows[0].n, 0);

  const pass = await store0.completePendingAliasErasures();
  assert.ok(pass.notProven >= 1, JSON.stringify(pass));

  // POSITIVE CONTROL: B's PROVEN_DESTROYED settlement DID produce labelled
  // evidence, through the same function.
  const forB = await adminPool.query(
    `SELECT settlement_receipt_id FROM memory_pii_key_erasures
      WHERE key_ref = $1 AND event = 'key_destroyed'`,
    [b.keyRef],
  );
  assert.equal(forB.rowCount, 1);
  assert.equal(forB.rows[0].settlement_receipt_id, "settlement-s12-b");
});

test("S-13: a settlement answers ONLY for its own tenant's key, even when a key reference collides", async () => {
  // ---- WHAT THE SECURITY REVIEW OF 86d33c9 FOUND, HIGH, EXECUTED ----
  // `settlementProven` took ONE scope — derived from the FIRST row of the
  // batch — and returned a map keyed by `key_ref` ALONE, which the caller then
  // applied to every row in the batch. `src/server.ts` runs the completion
  // pass with NO tenant filter at boot, so one tenant's sound
  // PROVEN_DESTROYED settlement satisfied a DIFFERENT tenant's identical key
  // reference: the second tenant's live key was reported resolved and NO
  // obligation was recorded for it. The same root cause has a quieter second
  // effect whenever the ordering goes the other way — every other tenant's
  // valid settlement is simply ignored.
  //
  // Nothing in the schema makes a key reference globally unique:
  // `memory_pii_key_erasures_once` is UNIQUE (tenant, workspace, key_ref,
  // event), which says a key is unique WITHIN a scope and says nothing across
  // scopes. So the collision is built here deliberately rather than waited for.
  const { binding, tombstoneId, authorizationId } = await survivorWithAnUnprovableMergedKey();
  const store0 = NO_VAULT();
  // A refused attempt FIRST, so the first tenant has an obligation for the
  // positive control to close. An obligation records what a real attempt could
  // not establish; a settlement does not conjure one into being.
  const refused = await eraseRecordAtHead(
    SURVIVOR, "mutation.s13.refused", "tombstone-s13-refused", "subject_erasure_request", store0,
  );
  assert.equal(refused.result.rejection, "key_destruction_not_proven");
  const settled = await store0.settleKeyDestruction(
    settlementFor(binding, tombstoneId, authorizationId),
  );
  assert.equal(settled.recorded, true, JSON.stringify(settled));

  // A SECOND TENANT holding the SAME key reference, with its erasure committed
  // and NO settlement of its own. Copied from the first tenant's real rows —
  // so every shape is one the store itself produced — with the guards stood
  // down for the copy and RE-ENABLED before the commit, because committing
  // with them down leaves them down for every later test in this file.
  const OTHER_TENANT = "tenant-hold-second";
  // The second tenant needs its own cross-workspace policy row, because
  // `memory_alias_bindings_policy_fk` makes a binding reference one. Real
  // tenant state, not a hole punched through a constraint.
  await setAliasPolicy({ ...SCOPE, tenantId: OTHER_TENANT });
  const client = await adminPool.connect();
  try {
    await client.query("BEGIN");
    // ALL user triggers, named as a class rather than one at a time: the copy
    // is a fixture and every guard on the table would refuse it for a
    // different reason. `ENABLE TRIGGER USER` below restores exactly this set.
    await client.query(`ALTER TABLE memory_alias_bindings DISABLE TRIGGER USER`);
    await client.query(`ALTER TABLE memory_pii_key_erasures DISABLE TRIGGER USER`);
    // Every column but the surrogate key, so the copy gets its own `id`.
    await client.query(
      `INSERT INTO memory_alias_bindings
         (tenant_id, workspace_id, principal_id, user_id, cross_workspace_policy,
          scope_key, alias_id, skeleton_algorithm, normalization_profile,
          canonical_participant_id, script_code, restriction_level,
          subject_participant_id, source_evidence_ref, source_evidence_digest,
          observed_at, fresh_until, authorization_id, mutation_receipt_id,
          bound_at, removed_at, removed_by_mutation_receipt_id,
          removed_authorization_id, payload, created_at, pii_envelope,
          pii_key_ref, pii_key_version, pii_erased_at, pii_erasure_tombstone_id)
       SELECT $1, workspace_id, principal_id, user_id, cross_workspace_policy,
              scope_key, alias_id, skeleton_algorithm, normalization_profile,
              canonical_participant_id, script_code, restriction_level,
              subject_participant_id, source_evidence_ref, source_evidence_digest,
              observed_at, fresh_until, authorization_id, mutation_receipt_id,
              bound_at, removed_at, removed_by_mutation_receipt_id,
              removed_authorization_id,
              -- memory_alias_bindings_tenant_binding requires the payload own
              -- scope to agree with the column, so the copy rewrites both.
              jsonb_set(payload, '{scope,tenantId}', to_jsonb($1::text)),
              created_at, pii_envelope,
              pii_key_ref, pii_key_version, pii_erased_at, pii_erasure_tombstone_id
         FROM memory_alias_bindings
        WHERE alias_id = 'alias-pii-001' AND tenant_id = $2`,
      [OTHER_TENANT, SCOPE.tenantId],
    );
    await client.query(
      `INSERT INTO memory_pii_key_erasures
         (tenant_id, workspace_id, tombstone_id, alias_id,
          binding_mutation_receipt_id, key_ref, provider_id, event)
       SELECT $1, workspace_id, tombstone_id, alias_id,
              binding_mutation_receipt_id, key_ref, provider_id, 'erasure_committed'
         FROM memory_pii_key_erasures
        WHERE tenant_id = $2 AND key_ref = $3 AND event = 'erasure_committed'`,
      [OTHER_TENANT, SCOPE.tenantId, binding.pii_key_ref],
    );
    await client.query(`ALTER TABLE memory_alias_bindings ENABLE TRIGGER USER`);
    await client.query(`ALTER TABLE memory_pii_key_erasures ENABLE TRIGGER USER`);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
  // ---- THE ORDERING THE DEFECT NEEDS -------------------------------
  // `due` is the PENDING rows followed by the EVIDENCED ones, each by id. The
  // defect took its single scope from `due[0]`, so it only leaks when the
  // SETTLED tenant is first — and the first tenant is only first if both rows
  // are evidenced. So the second tenant gets a mutator-forged `key_destroyed`
  // row, exactly as the security reviewer's reproduction did: its key is still
  // ALIVE, and the database's evidence is the thing that lies about it. This
  // is a real writable-evidence path, not a hole punched through a constraint —
  // the erasure guard permits it because a matching `erasure_committed` exists.
  await runAs(
    "aaliyah_memory_mutator",
    `INSERT INTO memory_pii_key_erasures
       (tenant_id, workspace_id, tombstone_id, alias_id,
        binding_mutation_receipt_id, key_ref, provider_id, event)
     SELECT tenant_id, workspace_id, tombstone_id, alias_id,
            binding_mutation_receipt_id, key_ref, provider_id, 'key_destroyed'
       FROM memory_pii_key_erasures
      WHERE tenant_id = $1 AND key_ref = $2 AND event = 'erasure_committed'`,
    [OTHER_TENANT, binding.pii_key_ref],
  );
  // ...and the batch really is ordered with the settled tenant FIRST. The
  // evidenced branch orders by least-recently-audited (NULLS FIRST), and the
  // first tenant already has an audit row from its honest erasure — so without
  // this the UNAUDITED second tenant sorts first, `scope` comes from IT, no
  // settlement is found for anyone, and the test passes against the defect it
  // exists to catch. Verified that way: instrumenting the unfixed store showed
  // `due=[second, first]` and an empty proof map.
  await runAs(
    "aaliyah_memory_mutator",
    `INSERT INTO memory_pii_key_audits
       (tenant_id, workspace_id, key_ref, last_audited_at, last_state, audits)
     VALUES ($1, $2, $3, now(), 'unknown', 1)
     ON CONFLICT (tenant_id, workspace_id, key_ref) DO UPDATE
        SET last_audited_at = now()`,
    [OTHER_TENANT, SCOPE.workspaceId, binding.pii_key_ref],
  );
  const ordering = await adminPool.query(
    `SELECT c.tenant_id
       FROM memory_pii_key_erasures AS c
       LEFT JOIN memory_pii_key_audits AS au
         ON au.tenant_id = c.tenant_id AND au.workspace_id = c.workspace_id
        AND au.key_ref = c.key_ref
      WHERE c.key_ref = $1 AND c.event = 'erasure_committed'
      ORDER BY au.last_audited_at ASC NULLS FIRST, c.id`,
    [binding.pii_key_ref],
  );
  assert.deepEqual(
    ordering.rows.map((r) => r.tenant_id),
    [SCOPE.tenantId, OTHER_TENANT],
    "the settled tenant must come first, or the defect this test exists for cannot fire",
  );

  // The guards really are back on. A committed `DISABLE TRIGGER` is how two
  // tombstone guards were silently stood down earlier in this round, and the
  // only way to know is to look.
  const enabled = await adminPool.query(
    `SELECT count(*)::int AS n FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
      WHERE NOT t.tgisinternal AND t.tgenabled <> 'O'
        AND c.relname IN ('memory_alias_bindings', 'memory_pii_key_erasures')`,
  );
  assert.equal(enabled.rows[0].n, 0, "the fixture left a guard disabled");

  // FIXTURE PRECONDITIONS: the collision is real, and only the FIRST tenant
  // has a settlement.
  const collision = await adminPool.query(
    `SELECT count(DISTINCT tenant_id)::int AS tenants FROM memory_pii_key_erasures
      WHERE key_ref = $1 AND event = 'erasure_committed'`,
    [binding.pii_key_ref],
  );
  assert.equal(collision.rows[0].tenants, 2, "the fixture must create a cross-tenant key collision");
  const settlements = await adminPool.query(
    `SELECT count(*)::int AS n FROM memory_key_destruction_settlements WHERE tenant_id = $1`,
    [OTHER_TENANT],
  );
  assert.equal(settlements.rows[0].n, 0, "the second tenant must have no settlement of its own");

  // THE UNFILTERED PASS — exactly what src/server.ts runs at boot.
  const pass = await store0.completePendingAliasErasures();

  // THE ASSERTION. The second tenant's key is NOT answered for by the first
  // tenant's settlement: it is unproven, and it has an obligation.
  assert.ok(
    pass.notProven >= 1,
    `the second tenant's live key was reported resolved: ${JSON.stringify(pass)}`,
  );
  const obligations = await adminPool.query(
    `SELECT tenant_id, state, not_proven_reason FROM memory_key_destruction_obligations
      WHERE key_ref = $1 ORDER BY tenant_id`,
    [binding.pii_key_ref],
  );
  const forOther = obligations.rows.filter((r) => r.tenant_id === OTHER_TENANT);
  assert.equal(
    forOther.length,
    1,
    `no obligation recorded for the second tenant: ${JSON.stringify(obligations.rows)}`,
  );
  assert.equal(forOther[0].state, "KEY_DESTRUCTION_NOT_PROVEN");
  assert.equal(forOther[0].not_proven_reason, "NO_PROVIDER_CONFIGURED");

  // POSITIVE CONTROL, the other half of the same defect: the FIRST tenant's
  // own settlement still answers for its own key. A fix that simply ignored
  // every settlement in an unfiltered batch would pass the assertion above and
  // break this one.
  const forFirst = obligations.rows.filter((r) => r.tenant_id === SCOPE.tenantId);
  assert.equal(forFirst.length, 1, JSON.stringify(obligations.rows));
  assert.equal(forFirst[0].state, "PROVEN_DESTROYED");
  assert.equal(forFirst[0].not_proven_reason, "SETTLED");
});

test("S-4: NO SELF-VERIFICATION — a settlement whose authority is also its verifier is refused, in the store and in the database", async () => {
  const { binding, tombstoneId, authorizationId } = await survivorWithAnUnprovableMergedKey();
  const same = await NO_VAULT().settleKeyDestruction(
    settlementFor(binding, tombstoneId, authorizationId, {
      settlementAuthorityId: "principal-one",
      verifierPrincipalId: "principal-one",
    }),
  );
  assert.deepEqual(same, { recorded: false, rejection: "settlement_self_verified" });
  // AND THE DATABASE REFUSES IT TOO, so the store's check is an answer and
  // not the enforcement (the register's own standard).
  await assert.rejects(
    () =>
      adminPool.query(
        `INSERT INTO memory_key_destruction_settlements
           (settlement_receipt_id, tenant_id, workspace_id, subject_record_id, alias_id,
            key_ref, key_version, provider_id, binding_mutation_receipt_id,
            erasure_authorization_id, erasure_tombstone_id, destruction_attempt_id,
            evidence, evidence_digest, settlement_authority_id, verifier_principal_id,
            decision, policy_version, nonce, predecessor_state, successor_state, decided_at)
         VALUES ('settlement-raw',$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'attempt','{}'::jsonb,
                 $11,'principal-one','principal-one','PROVEN_DESTROYED',
                 'aaliyah.key-destruction-settlement/v1','nonce-raw',
                 'ERASURE_PENDING_SETTLEMENT','PROVEN_DESTROYED',now())`,
        [
          SCOPE.tenantId, SCOPE.workspaceId, PARTICIPANT, binding.alias_id,
          binding.pii_key_ref, binding.pii_key_version, TEST_PII_KEYS.providerId,
          binding.mutation_receipt_id, authorizationId, tombstoneId,
          `sha256:${"0".repeat(64)}`,
        ],
      ),
    /memory_key_destruction_settlements_independent_verifier/,
  );
});

test("S-4b: a settlement naming the wrong key VERSION, or a future decision date, is refused", async () => {
  // Red team B8 against 86d33c9: `keyVersion: 999999` for a version-1 key was
  // accepted and the survivor erasure verified — while the trigger's own
  // header claimed the key "really does belong to that provider AND VERSION".
  // `decidedAt: 2099-01-01` was accepted too. Destruction is a claim about a
  // VERSION, not about a name.
  const { binding, tombstoneId, authorizationId } = await survivorWithAnUnprovableMergedKey();
  const store0 = NO_VAULT();
  const wrongVersion = await store0.settleKeyDestruction(
    settlementFor(binding, tombstoneId, authorizationId, {
      keyVersion: 999_999,
      settlementReceiptId: "settlement-wrong-version",
      nonce: "nonce-wrong-version",
    }),
  );
  assert.deepEqual(wrongVersion, { recorded: false, rejection: "settlement_not_evidence_bound" });
  const future = await store0.settleKeyDestruction(
    settlementFor(binding, tombstoneId, authorizationId, {
      decidedAt: new Date("2099-01-01T00:00:00.000Z"),
      settlementReceiptId: "settlement-future",
      nonce: "nonce-future",
    }),
  );
  assert.deepEqual(future, { recorded: false, rejection: "settlement_malformed" });
  // Neither wrote anything.
  const rows = await adminPool.query(
    `SELECT count(*)::int AS n FROM memory_key_destruction_settlements`,
  );
  assert.equal(rows.rows[0].n, 0);

  // POSITIVE CONTROL: the real version and a real date are accepted.
  const ok = await store0.settleKeyDestruction(
    settlementFor(binding, tombstoneId, authorizationId),
  );
  assert.equal(ok.recorded, true, JSON.stringify(ok));
});

test("S-4c: a settlement naming an erasure AUTHORIZATION nobody issued is refused (mutation M-40)", async () => {
  // ---- RED TEAM B1, AND WHY ITS FIRST TEST DID NOT HOLD --------------
  // `erasure_authorization_id` was unverified free text, and
  // memory_key_destruction_settlements_scope_unique — UNIQUE (tenant,
  // workspace, key_ref, erasure_authorization_id) — was the whole of
  // "action-specific". So a settlement already refused as
  // settlement_already_resolved was ACCEPTED by editing that one string to an
  // id nobody ever issued, and a STILL_UNKNOWN key became ERASED.
  //
  // The fix binds the settlement to the authorization the TOMBSTONE recorded.
  // The mutation sweep then deleted that check and nothing failed: S-3b was
  // rebuilt with real authorizations, and S-5's forged id is refused by the
  // spent NONCE before the authorization is ever consulted. Neither test can
  // see this control. This one drives it directly — first settlement, fresh
  // nonce, fresh receipt, the ONLY defect being an authorization that does not
  // exist.
  const { binding, tombstoneId, authorizationId } = await survivorWithAnUnprovableMergedKey();
  const store0 = NO_VAULT();
  const forged = await store0.settleKeyDestruction(
    settlementFor(binding, tombstoneId, authorizationId, {
      erasureAuthorizationId: "authorization-nobody-ever-issued",
    }),
  );
  assert.deepEqual(
    forged,
    { recorded: false, rejection: "settlement_not_evidence_bound" },
    "a settlement named an authorization that was never issued",
  );
  // NOTHING was written. The nonce lives on the settlement row, so no row means
  // the nonce is unspent too — the forged attempt costs the subject nothing.
  const wrote = await adminPool.query(
    `SELECT count(*)::int AS n FROM memory_key_destruction_settlements`,
  );
  assert.equal(wrote.rows[0].n, 0, "a refused settlement was written anyway");
  const obligation = await store0.listKeyDestructionObligations({ actor: SCOPE });
  assert.ok(
    obligation.every((o) => o.state === "KEY_DESTRUCTION_NOT_PROVEN"),
    `a forged settlement resolved an obligation: ${JSON.stringify(obligation)}`,
  );
  // AND THE SUBJECT IS STILL NOT ERASED, which is the consequence B1 reached.
  const stillRefused = await eraseRecordAtHead(
    SURVIVOR, "mutation.s4c.refused", "tombstone-s4c", "subject_erasure_request", store0,
  );
  assert.equal(stillRefused.result.rejection, "key_destruction_not_proven");

  // POSITIVE CONTROL: the authorization the tombstone actually recorded is
  // accepted, on the same key, through the same call.
  const real = await store0.settleKeyDestruction(
    settlementFor(binding, tombstoneId, authorizationId, {
      settlementReceiptId: "settlement-s4c-real",
      nonce: "nonce-s4c-real",
    }),
  );
  assert.equal(real.recorded, true, JSON.stringify(real));
});

test("S-5: a settlement nonce is spent once per tenant", async () => {
  const { binding, tombstoneId, authorizationId } = await survivorWithAnUnprovableMergedKey();
  const store0 = NO_VAULT();
  const first = await store0.settleKeyDestruction(settlementFor(binding, tombstoneId, authorizationId));
  assert.equal(first.recorded, true);
  // A DIFFERENT key, so `scope_unique` is not what refuses this — only the
  // reused nonce can be.
  const replayed = await store0.settleKeyDestruction(
    settlementFor(binding, tombstoneId, authorizationId, {
      settlementReceiptId: "settlement-002",
      decision: "STILL_UNKNOWN",
      erasureAuthorizationId: `${authorizationId}-other`,
    }),
  );
  assert.deepEqual(replayed, { recorded: false, rejection: "settlement_nonce_replayed" });
});

test("S-6: replaying the SAME settlement receipt is free; repointing it at another decision is refused", async () => {
  const { binding, tombstoneId, authorizationId } = await survivorWithAnUnprovableMergedKey();
  const store0 = NO_VAULT();
  const request = settlementFor(binding, tombstoneId, authorizationId);
  const first = await store0.settleKeyDestruction(request);
  assert.equal(first.recorded, true);
  const again = await store0.settleKeyDestruction(request);
  assert.deepEqual(again, { recorded: true, replay: true, evidenceDigest: first.recorded ? first.evidenceDigest : "" });
  // Exactly one row, whatever the caller does.
  const rows = await adminPool.query(
    `SELECT count(*)::int AS n FROM memory_key_destruction_settlements WHERE settlement_receipt_id = 'settlement-001'`,
  );
  assert.equal(rows.rows[0].n, 1);
  // A receipt that can mean two things is not a receipt.
  const repointed = await store0.settleKeyDestruction(
    settlementFor(binding, tombstoneId, authorizationId, { decision: "STILL_UNKNOWN", nonce: "nonce-other" }),
  );
  assert.deepEqual(repointed, { recorded: false, rejection: "settlement_receipt_conflict" });
});

test("S-7: a settlement must be EVIDENCE-BOUND — one naming a key, alias or tombstone that is not real is refused", async () => {
  const { binding, tombstoneId, authorizationId } = await survivorWithAnUnprovableMergedKey();
  const store0 = NO_VAULT();
  for (const [label, overrides] of [
    ["an unknown key", { keyRef: "pii-key:local-test/v1:00000000-0000-0000-0000-000000000000" }],
    ["an unknown alias", { aliasId: "alias-does-not-exist" }],
    ["another subject", { subjectRecordId: SURVIVOR }],
    ["an unknown tombstone", { erasureTombstoneId: "tombstone-does-not-exist" }],
  ] as const) {
    const refused = await store0.settleKeyDestruction(
      settlementFor(binding, tombstoneId, authorizationId, {
        ...overrides,
        settlementReceiptId: `settlement-${label.replace(/\s+/g, "-")}`,
        nonce: `nonce-${label.replace(/\s+/g, "-")}`,
      }),
    );
    assert.deepEqual(refused, { recorded: false, rejection: "settlement_not_evidence_bound" }, label);
  }
  // POSITIVE CONTROL: the correctly bound one is accepted.
  const ok = await store0.settleKeyDestruction(settlementFor(binding, tombstoneId, authorizationId));
  assert.equal(ok.recorded, true, JSON.stringify(ok));
});

test("S-8: a completed settlement is IMMUTABLE, and the MUTATION role cannot write one at all", async () => {
  const { binding, tombstoneId, authorizationId } = await survivorWithAnUnprovableMergedKey();
  const recorded = await NO_VAULT().settleKeyDestruction(settlementFor(binding, tombstoneId, authorizationId));
  assert.equal(recorded.recorded, true);
  for (const statement of [
    `UPDATE memory_key_destruction_settlements SET decision = 'STILL_UNKNOWN' WHERE settlement_receipt_id = 'settlement-001'`,
    `DELETE FROM memory_key_destruction_settlements WHERE settlement_receipt_id = 'settlement-001'`,
  ]) {
    await assert.rejects(() => adminPool.query(statement), /append-only|forbidden|immutable/i, statement);
  }
  // A settlement written by the role that can already forge erasure evidence
  // would be a bypass with extra paperwork. Refused by PRIVILEGE.
  await assert.rejects(
    () =>
      runAs(
        "aaliyah_memory_mutator",
        `INSERT INTO memory_key_destruction_settlements
           (settlement_receipt_id, tenant_id, workspace_id, subject_record_id, alias_id,
            key_ref, key_version, provider_id, binding_mutation_receipt_id,
            erasure_authorization_id, erasure_tombstone_id, destruction_attempt_id,
            evidence, evidence_digest, settlement_authority_id, verifier_principal_id,
            decision, policy_version, nonce, predecessor_state, successor_state, decided_at)
         VALUES ('settlement-by-mutator','t','w','r','a','k',1,'p','b','auth','tomb','att',
                 '{}'::jsonb,$1,'authority','verifier','PROVEN_DESTROYED',
                 'aaliyah.key-destruction-settlement/v1','n',
                 'ERASURE_PENDING_SETTLEMENT','PROVEN_DESTROYED',now())`,
        [`sha256:${"0".repeat(64)}`],
      ),
    /permission denied/,
  );
});

test("S-9: a settlement whose digest is not the digest of its own evidence proves NOTHING", async () => {
  // The one integrity check the database cannot make. The settler role writes
  // the row directly here, with a digest of something else, because the store
  // always computes it correctly — so this is the only way the state is
  // reachable, and it must not be believed.
  const { binding, tombstoneId, authorizationId } = await survivorWithAnUnprovableMergedKey();
  await runAs(
    "aaliyah_memory_settler",
    `INSERT INTO memory_key_destruction_settlements
       (settlement_receipt_id, tenant_id, workspace_id, subject_record_id, alias_id,
        key_ref, key_version, provider_id, binding_mutation_receipt_id,
        erasure_authorization_id, erasure_tombstone_id, destruction_attempt_id,
        evidence, evidence_digest, settlement_authority_id, verifier_principal_id,
        decision, policy_version, nonce, predecessor_state, successor_state, decided_at)
     VALUES ('settlement-liar',$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'attempt',
             $11::jsonb,$12,'authority','verifier','PROVEN_DESTROYED',
             'aaliyah.key-destruction-settlement/v1','nonce-liar',
             'ERASURE_PENDING_SETTLEMENT','PROVEN_DESTROYED',now())`,
    [
      SCOPE.tenantId, SCOPE.workspaceId, PARTICIPANT, binding.alias_id,
      binding.pii_key_ref, binding.pii_key_version, TEST_PII_KEYS.providerId,
      binding.mutation_receipt_id, authorizationId, tombstoneId,
      JSON.stringify({ kind: "certificate", statement: "trust me" }),
      settlementEvidenceDigest({ kind: "something", else: "entirely" }),
    ],
  );
  const refused = await eraseRecordAtHead(
    SURVIVOR, "mutation.s9.survivor", "tombstone-s9-survivor", "subject_erasure_request", NO_VAULT(),
  );
  assert.equal(refused.result.verified, false);
  assert.equal(refused.result.rejection, "key_destruction_not_proven");
  const obligations = await NO_VAULT().listKeyDestructionObligations({ actor: SCOPE });
  assert.equal(obligations[0]!.notProvenReason, "CONTRADICTORY_EVIDENCE", JSON.stringify(obligations));
});

test("S-11 K-09: a MERGED-IN key held by another provider is not proven by the PRE-CHECK either", async () => {
  // ---- A REAL MUTATION SURVIVOR, AND THE TEST THAT KILLS IT ---------
  // Found by this round's own sweep (M-08). `askProvider`'s
  // PROVIDER_DOES_NOT_OWN_KEY branch could be changed to report
  // PROVEN_DESTROYED and every test still passed — because S-10 and K-9 reach
  // the provider-mismatch case through the COMPLETION PASS, which has its own
  // mismatch branch and never calls `askProvider` at all. The PRE-CHECK's
  // mismatch path, the one that decides whether a survivor's erasure proceeds,
  // was claimed and not discriminated.
  //
  // The shape: the merged-in key was destroyed HONESTLY by its owning
  // provider, so the database's evidence is real and its helper is satisfied.
  // The survivor's erasure is then attempted by a store that speaks for a
  // DIFFERENT provider — a provider migration — and cannot establish anything
  // about that key.
  await absorbVictim("mutation.s11.merge");
  const binding = await bindingState("alias-pii-001");
  const erased = await eraseRecordAtHead(PARTICIPANT, "mutation.s11.absorbed", "tombstone-s11-absorbed");
  assert.equal(erased.result.verified, true, erased.result.rejection ?? "");
  assert.equal(
    await TEST_PII_KEYS.dataKeyState({ scope: DATA_SCOPE, keyRef: binding.pii_key_ref }),
    "destroyed",
    "fixture precondition: the merged-in key really is destroyed, with real evidence",
  );

  const other = { ...TEST_PII_KEYS, providerId: "other-kms/v1" } as typeof TEST_PII_KEYS;
  const refused = await eraseRecordAtHead(
    SURVIVOR, "mutation.s11.survivor", "tombstone-s11-survivor", "subject_erasure_request",
    createPostgresTrustedMemoryStore(writePool, readPool, { piiKeys: other }),
  );
  assert.equal(
    refused.result.verified,
    false,
    "a store that cannot speak for the key reported the survivor erased",
  );
  assert.equal(refused.result.rejection, "key_destruction_not_proven");
  assert.equal(await nonceConsumed(refused.receipt.authorizationId), false);
  const obligations = await store().listKeyDestructionObligations({ actor: SCOPE });
  assert.deepEqual(obligations.map((o) => o.notProvenReason), ["PROVIDER_DOES_NOT_OWN_KEY"]);

  // POSITIVE CONTROL: the store that DOES own the key erases the same
  // survivor. So the refusal is which provider is asking, and nothing else.
  const allowed = await eraseRecordAtHead(SURVIVOR, "mutation.s11.ok", "tombstone-s11-ok");
  assert.equal(allowed.result.verified, true, allowed.result.rejection ?? "");
});

test("S-10 K-09: a key held by ANOTHER provider is not proven, is named, and heals by PROVIDER when the owner answers", async () => {
  // Security NEW-2's shape: the store's provider never held the key. It is
  // counted and named rather than skipped, and when the owning provider
  // finally destroys it the obligation closes as resolved BY PROVIDER — so
  // the ledger does not fill up with rows that healed on their own.
  await bindVictimAddress();
  const binding = await bindingState("alias-pii-001");
  const other = { ...TEST_PII_KEYS, providerId: "other-kms/v1" } as typeof TEST_PII_KEYS;
  const otherStore = createPostgresTrustedMemoryStore(writePool, readPool, { piiKeys: other });
  const { result } = await eraseRecordAtHead(
    PARTICIPANT, "mutation.s10.erase", "tombstone-s10", "subject_erasure_request", otherStore,
  );
  assert.equal(result.rejection, "key_destruction_not_proven");
  let obligations = await otherStore.listKeyDestructionObligations({ actor: SCOPE });
  assert.equal(obligations.length, 1, JSON.stringify(obligations));
  assert.equal(obligations[0]!.notProvenReason, "PROVIDER_DOES_NOT_OWN_KEY");

  const completed = await store().completePendingAliasErasures();
  assert.equal(completed.destroyed, 1, JSON.stringify(completed));
  obligations = await otherStore.listKeyDestructionObligations({ actor: SCOPE });
  assert.equal(obligations[0]!.state, "PROVEN_DESTROYED");
  assert.equal(obligations[0]!.resolvedBy, "PROVIDER");
  assert.equal(obligations[0]!.settledBy, null, "a provider answer is not a settlement");
  assert.equal(
    await TEST_PII_KEYS.dataKeyState({ scope: DATA_SCOPE, keyRef: binding.pii_key_ref }),
    "destroyed",
  );
});

test("K-9 SECURITY 03581a3 F2: forged key_destroyed evidence for another provider's key does not remove it from the pending count", async () => {
  await bindVictimAddress();
  const before = await bindingState("alias-pii-001");
  const other = { ...TEST_PII_KEYS, providerId: "other-kms/v1" } as typeof TEST_PII_KEYS;
  const otherStore = createPostgresTrustedMemoryStore(writePool, readPool, { piiKeys: other });
  const { result } = await eraseRecordAtHead(PARTICIPANT, "mutation.k9.erase", "tombstone-k9", "subject_erasure_request", otherStore);
  // The key belongs to `local-test/v1` and this store speaks for
  // `other-kms/v1`, so it cannot establish anything about it — named as
  // PROVIDER_DOES_NOT_OWN_KEY rather than silently skipped, which is how the
  // key used to disappear from the count altogether (F2).
  assert.equal(result.rejection, "key_destruction_not_proven");
  const NOT_OURS = {
    destroyed: 0,
    repaired: 0,
    contradictions: 0,
    pending: 1,
    notProven: 1,
    notProvenReasons: { PROVIDER_DOES_NOT_OWN_KEY: 1 },
  };
  assert.deepEqual(await otherStore.completePendingAliasErasures(), NOT_OURS);
  await forgeKeyDestroyed("tombstone-k9");
  // The forgery does not change the answer: still counted, still named, still
  // pending. This is F2's property, now with the reason attached.
  assert.deepEqual(await otherStore.completePendingAliasErasures(), NOT_OURS);
  assert.equal(await TEST_PII_KEYS.dataKeyState({ scope: DATA_SCOPE, keyRef: before.pii_key_ref }), "active");
  // Positive control: the provider that owns the key destroys it. The forged
  // row already holds the evidence slot, so this lands as a `repaired`
  // forgery rather than a fresh `destroyed` — which is the more useful of the
  // two facts, and the one that was invisible before.
  assert.deepEqual(await store().completePendingAliasErasures(), {
    destroyed: 0,
    repaired: 1,
    contradictions: 1,
    pending: 0,
    notProven: 0,
    notProvenReasons: {},
  });
});
