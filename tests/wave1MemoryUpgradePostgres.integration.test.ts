import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test, { after, before } from "node:test";
import { Pool } from "pg";

import {
  MEMORY_ALIAS_NORMALIZATION_VERSION,
  MEMORY_AUTHORIZATION_NONCE_SCHEMA_VERSION,
  MEMORY_CONFUSABLE_SKELETON_ALGORITHM,
  MemoryAuthorizationReceiptSchema,
  CanonicalAliasIdentitySchema,
  WAVE1_TRUSTED_MEMORY_CONTRACT_VERSION,
  Wave1SubjectBoundEvidenceSchema,
  memoryAuthorizationNonce,
  type AliasScriptDetermination,
  type CanonicalAliasIdentity,
  type MemoryAuthorizationReceipt,
  type MemoryExpectedHead,
  type MemoryScope,
  type UnicodeRestrictionLevel,
  type Wave1SubjectBoundEvidence,
} from "@aaliyah/contracts/v1";

import {
  aliasRemovalDigest,
  type AliasCrossWorkspacePolicy,
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
  MEMORY_RECORD_VERSION_SCHEMA_VERSION,
  memoryContentDigest,
} from "../src/application/memory/wave1TrustedMemory";
import { runMailMigrations } from "../src/persistence/postgres/migrations";
import { createMailDbPool } from "../src/persistence/postgres/pool";
import { createPostgresAliasRegistryStore } from "../src/persistence/postgres/wave1AliasRegistryStore";
import { createPostgresMemoryReconciler } from "../src/persistence/postgres/wave1MemoryReconciler";
import { MEMORY_DELETION_ORDER_SCHEMA_VERSION } from "../src/application/memory/wave1MemoryErasure";
import { createPostgresTrustedMemoryStore } from "../src/persistence/postgres/wave1TrustedMemoryStore";
import { TEST_PII_KEYS, testAliasAssignmentDigest } from "./support/piiKeys";

/**
 * MIGRATIONS 050–053 OVER A DATABASE POPULATED AT 049.
 *
 * Every other memory suite applies all migrations to an empty database. A real
 * deployment upgrades one that already holds rows, and the integration review
 * of 3ba769f named that path as unexercised: an alias bound before 050 then
 * retired, an alias mutation left UNKNOWN before 052 then reconciled, and a
 * participant bound before the upgrade then subject-erased.
 *
 * The rows at 049 are written by the CURRENT stores — the only writers this
 * repository has — against a schema stopped at 049. That is the rolling-upgrade
 * window in which new code serves before the next migration lands, for the
 * paths that do not require objects 050–053 introduce. (A merge does: the
 * store's chain-depth check calls a 053 function, so a merge at 049 by this
 * code is refused, and a chain that predates 053 is not built here — disclosed
 * in the register.)
 *
 * Runs on a database of its own: it stops migrations part-way, which no shared
 * database may observe.
 */

const ADMIN_URL =
  process.env.AALIYAH_TEST_DATABASE_URL ??
  "postgres://postgres:test@127.0.0.1:54329/aaliyah_test";
const UPGRADE_DB = "aaliyah_upgrade_test";
const DB_URL = ADMIN_URL.replace(/\/[^/]+$/, `/${UPGRADE_DB}`);
const EVIDENCE_DIGEST = `sha256:${"c".repeat(64)}`;
const CORPUS_REF = "corpus:alias-protected-domains/v1";
const TENANT = "tenant-alias";
const SCOPE: MemoryScope = {
  tenantId: TENANT,
  workspaceId: "workspace-alias-a",
  principalId: "principal-alias",
  userId: "user-alias",
};
const VICTIM = "participant-victim";
const SECOND = "participant-upgrade-second";
const SHADOW_RECORD_SCHEMA = "upgrade_readback_shadow_record";

let serverPool: Pool;
let adminPool: Pool;
let writePool: Pool;
let readPool: Pool;
let shadowRecordPool: Pool;

function store(options?: { readBack?: Pool }) {
  return createPostgresAliasRegistryStore(writePool, options?.readBack ?? readPool, {
    piiKeys: TEST_PII_KEYS,
  });
}

before(async () => {
  serverPool = new Pool({ connectionString: ADMIN_URL, max: 1 });
  await serverPool.query(`DROP DATABASE IF EXISTS ${UPGRADE_DB} WITH (FORCE)`);
  await serverPool.query(`CREATE DATABASE ${UPGRADE_DB}`);
  adminPool = new Pool({ connectionString: DB_URL, max: 4 });
  await runMailMigrations(adminPool, { through: "049_memory_reconciliation_bindings_not_vacuous" });
  writePool = createMailDbPool({ AALIYAH_DATABASE_URL: DB_URL } as NodeJS.ProcessEnv);
  readPool = createMailDbPool({ AALIYAH_DATABASE_URL: DB_URL } as NodeJS.ProcessEnv);
  await adminPool.query(`CREATE SCHEMA ${SHADOW_RECORD_SCHEMA}`);
  await adminPool.query(
    `CREATE TABLE ${SHADOW_RECORD_SCHEMA}.memory_record_versions (LIKE public.memory_record_versions INCLUDING ALL)`,
  );
  await adminPool.query(`GRANT USAGE ON SCHEMA ${SHADOW_RECORD_SCHEMA} TO aaliyah_memory_reader`);
  await adminPool.query(`GRANT SELECT ON ${SHADOW_RECORD_SCHEMA}.memory_record_versions TO aaliyah_memory_reader`);
  shadowRecordPool = new Pool({
    connectionString: DB_URL,
    max: 2,
    options: `${process.env.PGOPTIONS ?? ""} -c search_path=${SHADOW_RECORD_SCHEMA},public`,
  });
  await setPolicy(TENANT, "workspace_isolated");
});

after(async () => {
  await shadowRecordPool.end();
  await readPool.end();
  await writePool.end();
  await adminPool.end();
  await serverPool.query(`DROP DATABASE IF EXISTS ${UPGRADE_DB} WITH (FORCE)`);
  await serverPool.end();
});

async function setPolicy(
  tenantId: string,
  policy: AliasCrossWorkspacePolicy,
): Promise<void> {
  await adminPool.query(
    `INSERT INTO memory_alias_tenant_policy
       (tenant_id, cross_workspace_policy, set_by_actor_id, policy_version)
     VALUES ($1,$2,'actor.alias-steward','alias-policy/v1')
     ON CONFLICT (tenant_id) DO UPDATE SET cross_workspace_policy = $2`,
    [tenantId, policy],
  );
}


let authorizationCounter = 0;
function nextAuthorizationId(): string {
  authorizationCounter += 1;
  // MemoryAuthorizationIdSchema demands >= 26 characters.
  return `auth-alias-${String(authorizationCounter).padStart(20, "0")}`;
}

function isoOffset(ms: number): string {
  return new Date(Date.now() + ms).toISOString();
}

function evidenceFor(
  participantId: string,
  overrides: Partial<Wave1SubjectBoundEvidence> = {},
): Wave1SubjectBoundEvidence {
  return Wave1SubjectBoundEvidenceSchema.parse({
    evidenceRef: "identity:verification/participant-record",
    evidenceDigest: EVIDENCE_DIGEST,
    observedAt: isoOffset(-60_000),
    freshUntil: isoOffset(3_600_000),
    subjectParticipantId: participantId,
    ...overrides,
  });
}

/**
 * Build a structurally valid `CanonicalAliasIdentity`.
 *
 * Defaults are HONEST — every recomputable field is computed with Core's own
 * functions — so a test that wants to prove a control has to state its lie
 * explicitly, in the test, where a reader can see it. That is the opposite of
 * a fixture that is quietly wrong everywhere.
 */
function aliasIdentity(input: {
  aliasId: string;
  observedAlias: string;
  participantId: string;
  evidence: Wave1SubjectBoundEvidence;
  scope?: MemoryScope;
  skeleton?: string;
  normalizedAlias?: string;
  scriptDetermination?: AliasScriptDetermination;
  restrictionLevel?: UnicodeRestrictionLevel;
  registrableDomain?: string;
  risk?: "none_detected" | "idn_homograph_suspected" | "typosquat_suspected";
  dispositionProposal?: "propose_accept" | "propose_quarantine" | "propose_reject";
}): CanonicalAliasIdentity {
  const scope = input.scope ?? SCOPE;
  const coreNormalized = coreNormalizeAlias(input.observedAlias);
  // What contracts enforces, and therefore what an HONEST producer claims.
  const claimedNormalized =
    input.normalizedAlias ?? input.observedAlias.normalize("NFC").toLowerCase();
  const determination =
    input.scriptDetermination ?? determineAliasScript(coreNormalized);
  const host = splitEmailAlias(coreNormalized)?.domain ?? "example.com";
  return CanonicalAliasIdentitySchema.parse({
    schemaVersion: WAVE1_TRUSTED_MEMORY_CONTRACT_VERSION,
    aliasId: input.aliasId,
    scope,
    canonicalParticipantId: input.participantId,
    observedAlias: input.observedAlias,
    normalizationVersion: MEMORY_ALIAS_NORMALIZATION_VERSION,
    // Contracts' OWN rule, which contracts enforces. Core's normalization is
    // this plus invisible-character removal, and the difference is a control.
    normalizedAlias: claimedNormalized,
    skeletonAlgorithm: MEMORY_CONFUSABLE_SKELETON_ALGORITHM,
    skeleton: input.skeleton ?? coreAliasSkeleton(coreNormalized),
    scriptDetermination: determination,
    restrictionLevel:
      input.restrictionLevel ??
      aliasRestrictionLevel(claimedNormalized, determination),
    lookalikeDomain: {
      registrableDomain: input.registrableDomain ?? host,
      isInternationalized: isInternationalizedDomain(host),
      risk: input.risk ?? "none_detected",
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
    dispositionProposal: input.dispositionProposal ?? "propose_accept",
  });
}

/** Build a structurally valid, correctly nonce-bound authorization receipt. */
function authorization(input: {
  action: "assign_alias" | "remove_alias";
  scope?: MemoryScope;
  targetRecordId: string;
  expectedHead: MemoryExpectedHead;
  proposedContentDigest: string;
  authorizationId?: string;
  issuedAt?: string;
  expiresAt?: string;
  revokedAt?: string | null;
  consumedAt?: string | null;
}): MemoryAuthorizationReceipt {
  const scope = input.scope ?? SCOPE;
  const authorizationId = input.authorizationId ?? nextAuthorizationId();
  const bindingDigest = memoryAuthorizationNonce({
    bindingSchemaVersion: MEMORY_AUTHORIZATION_NONCE_SCHEMA_VERSION,
    authorizationId,
    action: input.action,
    scope,
    targetRecordId: input.targetRecordId,
    expectedHead: input.expectedHead,
    proposedContentDigest: input.proposedContentDigest,
  });
  return MemoryAuthorizationReceiptSchema.parse({
    schemaVersion: WAVE1_TRUSTED_MEMORY_CONTRACT_VERSION,
    authorizationId,
    action: input.action,
    approverAuthorityId: "authority.identity-steward",
    approverActorId: "actor.identity-steward",
    scope,
    targetRecordId: input.targetRecordId,
    expectedHead: input.expectedHead,
    proposedContentDigest: input.proposedContentDigest,
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
 * Issue an authorization: the receipt row AND the out-of-band nonce row,
 * written under the ISSUER role. The mutator cannot do this, and a fixture
 * that used the owner would never notice if it could.
 */
async function issue(
  receipt: MemoryAuthorizationReceipt,
  overrides: {
    nonceAction?: string;
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
        // Presence, not nullishness: `??` would swallow an EXPLICIT null and
        // fall through to the receipt's own value.
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
          receipt.authorizationId,
          overrides.nonceAction ?? receipt.action,
          receipt.targetRecordId,
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
 * Issued by the ISSUER role and spent by the MUTATOR role, so the fixture
 * itself depends on the privilege split it is standing in for.
 */
async function witnessAppend(input: {
  authorizationId: string;
  mutationReceiptId: string;
  targetRecordId: string;
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
      input.action ?? "assign_alias",
      input.targetRecordId,
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
      input.action ?? "assign_alias",
      input.targetRecordId,
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

/**
 * The participant version an alias mutation appends, for raw fixtures.
 *
 * Migration 050: a binding or retirement must be accompanied by the record
 * version its own mutation appended to the participant. A raw fixture that
 * writes the binding row writes that version too, rather than a row the
 * protocol could not have written.
 */
async function appendAliasVersion(input: {
  authorizationId: string;
  mutationReceiptId: string;
  targetRecordId: string;
  scope?: MemoryScope;
  action?: string;
  content?: unknown;
}): Promise<void> {
  const scope = input.scope ?? SCOPE;
  let head = await adminPool.query(
    `SELECT version, content_digest FROM memory_record_versions
      WHERE tenant_id = $1 AND workspace_id = $2 AND record_id = $3
      ORDER BY version DESC LIMIT 1`,
    [scope.tenantId, scope.workspaceId, input.targetRecordId],
  );
  if (head.rowCount === 0) {
    await seedGenesis(input.targetRecordId, scope);
    head = await adminPool.query(
      `SELECT version, content_digest FROM memory_record_versions
        WHERE tenant_id = $1 AND workspace_id = $2 AND record_id = $3
        ORDER BY version DESC LIMIT 1`,
      [scope.tenantId, scope.workspaceId, input.targetRecordId],
    );
  }
  const version = (head.rows[0].version as number) + 1;
  const content = input.content ?? successorContent(input.targetRecordId, version);
  const digest = memoryContentDigest(content);
  const payload = {
    schemaVersion: MEMORY_RECORD_VERSION_SCHEMA_VERSION,
    recordId: input.targetRecordId,
    version,
    state: "active",
    scope,
    content,
    contentDigest: digest,
    predecessorDigest: head.rows[0].content_digest as string,
    authorizationId: input.authorizationId,
    mutationReceiptId: input.mutationReceiptId,
    createdAt: isoOffset(-60_000),
  };
  await runAs(
    "aaliyah_memory_mutator",
    `INSERT INTO memory_record_versions
       (tenant_id, workspace_id, principal_id, user_id, record_id, version,
        state, content_digest, predecessor_digest, authorization_id,
        mutation_receipt_id, payload)
     VALUES ($1,$2,$3,$4,$5,$6,'active',$7,$8,$9,$10,$11)`,
    [
      scope.tenantId,
      scope.workspaceId,
      scope.principalId,
      scope.userId,
      input.targetRecordId,
      version,
      digest,
      payload.predecessorDigest,
      input.authorizationId,
      input.mutationReceiptId,
      JSON.stringify(payload),
    ],
  );
}

let genesisCounter = 0;

/** Seed version 1 of a participant identity record. */
async function seedGenesis(
  recordId: string,
  scope: MemoryScope = SCOPE,
): Promise<string> {
  const content = { participant: recordId, generation: 1 };
  const digest = memoryContentDigest(content);
  genesisCounter += 1;
  const authorizationId = `genesis-${String(genesisCounter).padStart(21, "0")}`;
  const mutationReceiptId = `mutation.genesis.${genesisCounter}`;
  await witnessAppend({
    authorizationId,
    mutationReceiptId,
    targetRecordId: recordId,
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

function successorContent(recordId: string, generation: number): unknown {
  return { participant: recordId, generation };
}

/**
 * The whole honest path in one call: seed the participant, build the alias,
 * issue the authorization bound to it, and return everything a test needs.
 */
async function prepareAssign(input: {
  aliasId: string;
  observedAlias: string;
  participantId: string;
  scope?: MemoryScope;
  evidence?: Wave1SubjectBoundEvidence;
  aliasOverrides?: Omit<
    Parameters<typeof aliasIdentity>[0],
    "aliasId" | "observedAlias" | "participantId" | "evidence"
  >;
  seed?: boolean;
}): Promise<{
  alias: CanonicalAliasIdentity;
  evidence: Wave1SubjectBoundEvidence;
  receipt: MemoryAuthorizationReceipt;
  content: unknown;
  genesis: string;
}> {
  const scope = input.scope ?? SCOPE;
  const genesis =
    input.seed === false
      ? await headDigestOf(input.participantId, scope)
      : await seedGenesis(input.participantId, scope);
  const evidence = input.evidence ?? evidenceFor(input.participantId);
  const alias = aliasIdentity({
    aliasId: input.aliasId,
    observedAlias: input.observedAlias,
    participantId: input.participantId,
    evidence,
    scope,
    ...input.aliasOverrides,
  });
  const content = successorContent(input.participantId, 2);
  const receipt = await issue(
    authorization({
      action: "assign_alias",
      scope,
      targetRecordId: input.participantId,
      expectedHead: headOf(1, genesis),
      proposedContentDigest: await testAliasAssignmentDigest({
        record: content,
        alias: alias,
        evidence: evidence,
        scope: scope,
      }),
    }),
  );
  return { alias, evidence, receipt, content, genesis };
}

async function headDigestOf(
  recordId: string,
  scope: MemoryScope,
): Promise<string> {
  const result = await adminPool.query(
    `SELECT content_digest FROM memory_record_versions
      WHERE tenant_id = $1 AND workspace_id = $2 AND record_id = $3
      ORDER BY id DESC LIMIT 1`,
    [scope.tenantId, scope.workspaceId, recordId],
  );
  return result.rows[0].content_digest as string;
}

/**
 * A DIRECT insert into the registry table, bypassing the store entirely.
 *
 * The store cannot produce a row that violates these constraints — that is the
 * point of the store — so the constraints would have no reachable input and no
 * killing test if they were only ever exercised through it. A replica, a
 * restored backup, a migration or a rogue service has no store in front of it.
 */

async function appliedMigrations(): Promise<string[]> {
  return (await adminPool.query(`SELECT id FROM aaliyah_mail_migrations ORDER BY id`)).rows.map((r) => r.id as string);
}

let boundBefore: { headDigest: string } | undefined;
let unknownAuthorizationId: string | undefined;

test("U-0 at 049: a binding commits and an alias mutation is left UNKNOWN, by the current stores", async () => {
  const applied = await appliedMigrations();
  assert.equal(applied.at(-1), "049_memory_reconciliation_bindings_not_vacuous");
  assert.equal(applied.some((id) => id >= "050"), false);
  const triggers = await adminPool.query(
    `SELECT count(*)::int AS n FROM pg_trigger WHERE tgname LIKE '%\\_zy\\_%'`,
  );
  assert.equal(triggers.rows[0].n, 0, "no 050–053 trigger exists yet");

  const first = await prepareAssign({ aliasId: "alias-upgrade-1", observedAlias: "ceo@example.com", participantId: VICTIM });
  const bound = await store().assignAlias({
    actor: SCOPE,
    authorizationId: first.receipt.authorizationId,
    participantRecordId: VICTIM,
    alias: first.alias,
    evidence: first.evidence,
    proposedContent: first.content,
    mutationReceiptId: "mutation.upgrade.bind",
  });
  assert.equal(bound.verified, true, bound.rejection ?? "");
  boundBefore = { headDigest: await headDigestOf(VICTIM, SCOPE) };

  const second = await prepareAssign({ aliasId: "alias-upgrade-2", observedAlias: "cfo@example.com", participantId: SECOND });
  const unknown = await store({ readBack: shadowRecordPool }).assignAlias({
    actor: SCOPE,
    authorizationId: second.receipt.authorizationId,
    participantRecordId: SECOND,
    alias: second.alias,
    evidence: second.evidence,
    proposedContent: second.content,
    mutationReceiptId: "mutation.upgrade.unknown",
  });
  assert.equal(unknown.rejection, "unknown_outcome");
  unknownAuthorizationId = second.receipt.authorizationId;
});

test("U-1 050–056 apply over the populated database, and refuse nothing that is already there", async () => {
  assert.ok(boundBefore && unknownAuthorizationId, "U-0 must have run");
  await runMailMigrations(adminPool);
  const applied = await appliedMigrations();
  assert.equal(applied.at(-1), "056_memory_least_privilege_trim");
  for (const id of ["050_memory_alias_authorization_action_bound", "051_memory_erasure_reaches_merged_records", "052_memory_alias_reconciliation_derivable", "053_memory_merge_chain_bounded", "054_memory_merged_erasure_requires_destroyed_keys", "055_memory_key_destruction_settlement", "056_memory_least_privilege_trim"]) {
    assert.ok(applied.includes(id), id);
  }
  const triggers = await adminPool.query(
    `SELECT tgname FROM pg_trigger WHERE tgname LIKE '%\\_zy\\_%' ORDER BY tgname`,
  );
  assert.deepEqual(triggers.rows.map((r) => r.tgname), [
    "memory_alias_bindings_zy_authorization_action",
    "memory_identity_edges_zy_merge_chain_bounded",
    "memory_tombstones_zy_erasure_reaches_merged",
  ]);
  const helpers = await adminPool.query(
    `SELECT proname FROM pg_proc WHERE proname IN
       ('aaliyah_memory_alias_effect_present','aaliyah_memory_unerased_merged_records','aaliyah_memory_merge_chain_hops')
     ORDER BY proname`,
  );
  assert.equal(helpers.rowCount, 3);
  const rows = await adminPool.query(`SELECT count(*)::int AS n FROM memory_alias_bindings WHERE removed_at IS NULL`);
  assert.equal(rows.rows[0].n, 2);
});

test("U-5 a migration name that does not exist is refused before anything is applied", async () => {
  const before = await appliedMigrations();
  await assert.rejects(
    () => runMailMigrations(adminPool, { through: "999_no_such_migration" }),
    /runMailMigrations: no migration named 999_no_such_migration/,
  );
  assert.deepEqual(await appliedMigrations(), before);
});

test("U-2 a binding made BEFORE 050 is retired honestly AFTER it: 050's witness and version rules accept the real path", async () => {
  assert.ok(boundBefore);
  const content = successorContent(VICTIM, 3);
  const removal = await issue(
    authorization({
      action: "remove_alias",
      targetRecordId: VICTIM,
      expectedHead: headOf(2, boundBefore.headDigest),
      proposedContentDigest: aliasRemovalDigest({ record: content, aliasId: "alias-upgrade-1" }),
    }),
  );
  const removed = await store().removeAlias({
    actor: SCOPE,
    authorizationId: removal.authorizationId,
    participantRecordId: VICTIM,
    aliasId: "alias-upgrade-1",
    proposedContent: content,
    mutationReceiptId: "mutation.upgrade.remove",
  });
  assert.equal(removed.verified, true, removed.rejection ?? "");
});

test("U-3 an alias mutation left UNKNOWN before 052 reconciles to COMMITTED_CONFIRMED after it", async () => {
  assert.ok(unknownAuthorizationId);
  const verdicts = await createPostgresMemoryReconciler(writePool).reconcileAll();
  const verdict = verdicts.find((v) => v.mutationReceiptId === "mutation.upgrade.unknown");
  assert.equal(verdict?.verdict, "COMMITTED_CONFIRMED");
  assert.equal(verdict?.evidence.derivation, "alias_effect_and_authorized_head");
});

test("U-4 a participant whose address was bound before the upgrade is subject-erased after it: address, key and index gone", async () => {
  const head = await adminPool.query(
    `SELECT version, content_digest FROM memory_record_versions WHERE record_id = $1 ORDER BY version DESC LIMIT 1`,
    [SECOND],
  );
  const order = {
    schemaVersion: MEMORY_DELETION_ORDER_SCHEMA_VERSION,
    reason: "subject_erasure_request",
    reasonEvidenceRef: "matter:erasure/upgrade-0001",
  };
  const receipt = await issue(
    authorization({
      action: "delete" as "remove_alias",
      targetRecordId: SECOND,
      expectedHead: headOf(head.rows[0].version as number, head.rows[0].content_digest as string),
      proposedContentDigest: memoryContentDigest(order),
    }),
  );
  const keyRef = (
    await adminPool.query(`SELECT pii_key_ref FROM memory_alias_bindings WHERE alias_id = 'alias-upgrade-2'`)
  ).rows[0].pii_key_ref as string;
  const erased = await createPostgresTrustedMemoryStore(writePool, readPool, { piiKeys: TEST_PII_KEYS }).delete({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: SECOND,
    proposedContent: order,
    mutationReceiptId: "mutation.upgrade.erase",
    tombstoneId: "tombstone-upgrade-erase",
  });
  assert.equal(erased.verified, true, erased.rejection ?? "");
  assert.deepEqual(erased.aliasErasure, { bindingsErased: 1, keysDestroyed: 1, keysPending: 0, keysNotProven: 0, notProvenReasons: {} });
  const binding = await adminPool.query(`SELECT pii_envelope FROM memory_alias_bindings WHERE alias_id = 'alias-upgrade-2'`);
  assert.equal(binding.rows[0].pii_envelope, null);
  assert.equal(
    await TEST_PII_KEYS.dataKeyState({ scope: { tenantId: SCOPE.tenantId, workspaceId: SCOPE.workspaceId }, keyRef }),
    "destroyed",
  );
});
