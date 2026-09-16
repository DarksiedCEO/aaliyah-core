import assert from "node:assert/strict";
import test, { after, before, beforeEach } from "node:test";
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
  aliasAssignmentDigest,
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
import {
  lockSharedMemoryTables,
  type SharedTableLock,
} from "./support/sharedMemoryTables";

/**
 * Wave 1.3 Part D — THE AUTHORITATIVE ALIAS REGISTRY, against a REAL
 * PostgreSQL 16.
 *
 * No mocks, no fakes, no in-memory stand-in. The founder authorization names
 * one property verbatim — "Two concurrent attempts to assign the same
 * protected alias to different identities: EXACTLY ONE MAY WIN" — and a
 * simulated race proves that a simulation is deterministic and nothing else.
 * Every race below is two stores, two connections, real rows, `Promise.all`.
 *
 * Every negative assertion carries a matcher. A bare `assert.rejects` passes
 * when the code throws for a completely unrelated reason, which is how a
 * control appears tested while never having been exercised once.
 *
 * ON THE CYRILLIC CASE, STATED UP FRONT so no reader has to infer it. The
 * assignment names "аdmin@x.com" (U+0430) against "admin@x.com". That alias is
 * refused — but by the MIXED-SCRIPT gate, which fires before the skeleton
 * index is ever consulted, because one Cyrillic letter among Latin ones is
 * mixed script. The skeleton index is reached by SINGLE-SCRIPT confusables
 * (combining marks, ligatures, fullwidth and mathematical alphanumeric forms),
 * and those are what prove it below. Both facts are asserted; neither is
 * rounded up into the other.
 */

const DB_URL =
  process.env.AALIYAH_TEST_DATABASE_URL ??
  "postgres://postgres:test@127.0.0.1:54329/aaliyah_test";

const EVIDENCE_DIGEST = `sha256:${"c".repeat(64)}`;
const CORPUS_REF = "corpus:alias-protected-domains/v1";

/**
 * Real relations the READ-BACK resolves to first, used only by the read-back
 * tests. Forcing a divergence this way leaves the production read path
 * completely untouched — no injected failure hook, no stubbed client — and it
 * is the pattern `wave1TrustedMemoryPostgres.integration.test.ts` already uses.
 *
 * Each shadow holds exactly ONE of the two relations the read-back consults, so
 * the record agreement and the binding agreement are separable: whatever the
 * shadow does not define resolves from `public` and is therefore correct.
 */
const SHADOW_RECORD_SCHEMA = "alias_readback_shadow_record";
const SHADOW_BINDING_SCHEMA = "alias_readback_shadow_binding";

/** Same shape as the binding table, WITHOUT its CHECK constraints. */
const UNCHECKED_SCHEMA = "alias_binding_unchecked";

const TENANT = "tenant-alias";
const TENANT_EXCLUSIVE = "tenant-alias-exclusive";
const TENANT_OTHER = "tenant-alias-other";
const TENANT_UNGOVERNED = "tenant-alias-ungoverned";

const SCOPE: MemoryScope = {
  tenantId: TENANT,
  workspaceId: "workspace-alias-a",
  principalId: "principal-alias",
  userId: "user-alias",
};
const SCOPE_WORKSPACE_B: MemoryScope = {
  ...SCOPE,
  workspaceId: "workspace-alias-b",
};
const SCOPE_EXCLUSIVE_A: MemoryScope = {
  ...SCOPE,
  tenantId: TENANT_EXCLUSIVE,
};
const SCOPE_EXCLUSIVE_B: MemoryScope = {
  ...SCOPE,
  tenantId: TENANT_EXCLUSIVE,
  workspaceId: "workspace-alias-b",
};
const SCOPE_OTHER_TENANT: MemoryScope = { ...SCOPE, tenantId: TENANT_OTHER };
const SCOPE_UNGOVERNED: MemoryScope = { ...SCOPE, tenantId: TENANT_UNGOVERNED };

const VICTIM = "participant-victim";
const ATTACKER = "participant-attacker";

let writePool: Pool;
let readPool: Pool;
let shadowRecordPool: Pool;
let shadowBindingPool: Pool;
let uncheckedPool: Pool;
let adminPool: Pool;
// See tests/support/sharedMemoryTables.ts: this file TRUNCATEs tables the
// trusted-memory suite also TRUNCATEs, and `node --test` runs files in
// parallel processes.
let sharedTableLock: SharedTableLock;

function store(options?: { write?: Pool; readBack?: Pool }) {
  return createPostgresAliasRegistryStore(
    options?.write ?? writePool,
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

  for (const [schema, table] of [
    [SHADOW_RECORD_SCHEMA, "memory_record_versions"],
    [SHADOW_BINDING_SCHEMA, "memory_alias_bindings"],
  ] as const) {
    await adminPool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await adminPool.query(`CREATE SCHEMA ${schema}`);
    await adminPool.query(
      `CREATE TABLE ${schema}.${table} (LIKE public.${table} INCLUDING ALL)`,
    );
    await adminPool.query(
      `GRANT USAGE ON SCHEMA ${schema} TO aaliyah_memory_reader`,
    );
    await adminPool.query(
      `GRANT SELECT ON ${schema}.${table} TO aaliyah_memory_reader`,
    );
  }
  shadowRecordPool = new Pool({
    connectionString: DB_URL,
    max: 4,
    options: `-c search_path=${SHADOW_RECORD_SCHEMA},public`,
  });
  shadowBindingPool = new Pool({
    connectionString: DB_URL,
    max: 4,
    options: `-c search_path=${SHADOW_BINDING_SCHEMA},public`,
  });

  // A relation shaped like the binding table but WITHOUT its CHECK
  // constraints. In `public`, migration 031 makes a row whose columns disagree
  // with its jsonb payload physically unrepresentable — which would leave the
  // application-level binding check with no reachable input and therefore no
  // killing test. A replica, a restored backup, or a table created by
  // something other than these migrations has no such guarantee, so the check
  // is exercised against a relation that has no guarantee either.
  await adminPool.query(`DROP SCHEMA IF EXISTS ${UNCHECKED_SCHEMA} CASCADE`);
  await adminPool.query(`CREATE SCHEMA ${UNCHECKED_SCHEMA}`);
  await adminPool.query(
    `CREATE TABLE ${UNCHECKED_SCHEMA}.memory_alias_bindings
       (LIKE public.memory_alias_bindings INCLUDING DEFAULTS)`,
  );
  await adminPool.query(
    `GRANT USAGE ON SCHEMA ${UNCHECKED_SCHEMA} TO aaliyah_memory_reader`,
  );
  await adminPool.query(
    `GRANT SELECT ON ${UNCHECKED_SCHEMA}.memory_alias_bindings
       TO aaliyah_memory_reader`,
  );
  uncheckedPool = new Pool({
    connectionString: DB_URL,
    max: 2,
    options: `-c search_path=${UNCHECKED_SCHEMA},public`,
  });
});

after(async () => {
  await uncheckedPool.end();
  await shadowBindingPool.end();
  await shadowRecordPool.end();
  await readPool.end();
  await writePool.end();
  await adminPool.query(`DROP SCHEMA IF EXISTS ${SHADOW_RECORD_SCHEMA} CASCADE`);
  await adminPool.query(`DROP SCHEMA IF EXISTS ${SHADOW_BINDING_SCHEMA} CASCADE`);
  await adminPool.query(`DROP SCHEMA IF EXISTS ${UNCHECKED_SCHEMA} CASCADE`);
  await sharedTableLock.release();
  await adminPool.end();
});

beforeEach(async () => {
  // The binding table carries a foreign key onto the policy table, so both are
  // truncated in one statement rather than with CASCADE, which would silently
  // widen what is being reset.
  await adminPool.query(
    `TRUNCATE memory_alias_bindings,
              memory_alias_tenant_policy,
              memory_alias_protected_domains,
              memory_record_versions,
              memory_authorization_receipts,
              memory_authorization_nonces,
              memory_mutation_receipts,
              memory_tombstones,
              memory_legal_hold_carve_outs,
              memory_legal_hold_records,
              memory_legal_hold_subjects,
              memory_legal_holds,
              memory_retention_obligations
     RESTART IDENTITY`,
  );
  for (const tenantId of [TENANT, TENANT_EXCLUSIVE, TENANT_OTHER]) {
    await setPolicy(
      tenantId,
      tenantId === TENANT_EXCLUSIVE ? "tenant_exclusive" : "workspace_isolated",
    );
  }
  genesisCounter = 0;
  // TENANT_UNGOVERNED deliberately gets NO policy row.
  await adminPool.query(
    `TRUNCATE ${SHADOW_RECORD_SCHEMA}.memory_record_versions RESTART IDENTITY`,
  );
  await adminPool.query(
    `TRUNCATE ${SHADOW_BINDING_SCHEMA}.memory_alias_bindings RESTART IDENTITY`,
  );
  await adminPool.query(
    `TRUNCATE ${UNCHECKED_SCHEMA}.memory_alias_bindings RESTART IDENTITY`,
  );
});

/**
 * The cross-workspace policy is ADMINISTRATIVE state. It is written by the
 * table owner, never by the mutation role — a role that can weaken its own
 * gate has no gate, and `the mutator cannot rewrite the policy` below proves
 * the grant is actually absent.
 */
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

async function protectDomain(
  scope: MemoryScope,
  domain: string,
): Promise<void> {
  await adminPool.query(
    `INSERT INTO memory_alias_protected_domains
       (tenant_id, workspace_id, registrable_domain, corpus_ref, added_by_actor_id)
     VALUES ($1,$2,$3,$4,'actor.alias-steward')`,
    [scope.tenantId, scope.workspaceId, domain, CORPUS_REF],
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
      proposedContentDigest: aliasAssignmentDigest({
        record: content,
        alias,
        evidence,
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
const BINDING_INSERT_COLUMNS = [
  "tenant_id",
  "workspace_id",
  "principal_id",
  "user_id",
  "cross_workspace_policy",
  "scope_key",
  "alias_id",
  "normalized_alias",
  "skeleton",
  "skeleton_algorithm",
  "normalization_profile",
  "canonical_participant_id",
  "registrable_domain",
  "script_code",
  "restriction_level",
  "subject_participant_id",
  "source_evidence_ref",
  "source_evidence_digest",
  "observed_at",
  "fresh_until",
  "authorization_id",
  "mutation_receipt_id",
  "bound_at",
  "removed_at",
  "removed_by_mutation_receipt_id",
  "removed_authorization_id",
  "payload",
] as const;

function rawBindingRow(
  overrides: Partial<Record<(typeof BINDING_INSERT_COLUMNS)[number], unknown>> = {},
  payloadOverrides: Record<string, unknown> = {},
): { columns: unknown[]; payload: Record<string, unknown> } {
  const aliasId = (overrides.alias_id as string) ?? "alias-raw";
  const payload: Record<string, unknown> = {
    scope: {
      tenantId: TENANT,
      workspaceId: SCOPE.workspaceId,
      principalId: SCOPE.principalId,
      userId: SCOPE.userId,
    },
    aliasId,
    normalizedAlias: "ceo@example.com",
    skeleton: "ceo@example.com",
    canonicalParticipantId: VICTIM,
    subjectParticipantId: VICTIM,
    crossWorkspacePolicy: "workspace_isolated",
    scopeKey: SCOPE.workspaceId,
    authorizationId: "auth-alias-00000000000000000000",
    mutationReceiptId: "mutation.raw",
    ...payloadOverrides,
  };
  const base: Record<string, unknown> = {
    tenant_id: TENANT,
    workspace_id: SCOPE.workspaceId,
    principal_id: SCOPE.principalId,
    user_id: SCOPE.userId,
    cross_workspace_policy: "workspace_isolated",
    scope_key: SCOPE.workspaceId,
    alias_id: aliasId,
    normalized_alias: "ceo@example.com",
    skeleton: "ceo@example.com",
    skeleton_algorithm: "aaliyah.alias-skeleton/core-subset-v1",
    normalization_profile: "aaliyah.alias-normalization/core-v1",
    canonical_participant_id: VICTIM,
    registrable_domain: "example.com",
    script_code: "Latn",
    restriction_level: "ascii_only",
    subject_participant_id: VICTIM,
    source_evidence_ref: "identity:verification/participant-record",
    source_evidence_digest: EVIDENCE_DIGEST,
    observed_at: new Date(Date.now() - 60_000),
    fresh_until: new Date(Date.now() + 3_600_000),
    authorization_id: "auth-alias-00000000000000000000",
    mutation_receipt_id: "mutation.raw",
    bound_at: new Date(Date.now() - 1_000),
    removed_at: null,
    removed_by_mutation_receipt_id: null,
    removed_authorization_id: null,
    payload: JSON.stringify(payload),
    ...overrides,
  };
  if (!("payload" in overrides)) base.payload = JSON.stringify(payload);
  return {
    columns: BINDING_INSERT_COLUMNS.map((column) => base[column]),
    payload,
  };
}

async function insertRawBinding(
  overrides: Partial<Record<(typeof BINDING_INSERT_COLUMNS)[number], unknown>> = {},
  payloadOverrides: Record<string, unknown> = {},
  pool: Pool = adminPool,
): Promise<void> {
  const row = rawBindingRow(overrides, payloadOverrides);
  const placeholders = BINDING_INSERT_COLUMNS.map(
    (_column, index) => `$${index + 1}`,
  ).join(",");
  await pool.query(
    `INSERT INTO memory_alias_bindings (${BINDING_INSERT_COLUMNS.join(", ")})
     VALUES (${placeholders})`,
    row.columns,
  );
}

async function nonceConsumedAt(bindingDigest: string): Promise<Date | null> {
  const result = await adminPool.query(
    `SELECT consumed_at FROM memory_authorization_nonces WHERE binding_digest = $1`,
    [bindingDigest],
  );
  return (result.rows[0]?.consumed_at as Date | null) ?? null;
}

async function activeBindings(tenantId = TENANT): Promise<number> {
  const result = await adminPool.query(
    `SELECT count(*)::int AS n FROM memory_alias_bindings
      WHERE tenant_id = $1 AND removed_at IS NULL`,
    [tenantId],
  );
  return result.rows[0].n as number;
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
// The honest path, and what "verified" is allowed to mean.
// ---------------------------------------------------------------------------

test("an alias assignment commits, reads back on an independent session, and only then reports verified", async () => {
  const prepared = await prepareAssign({
    aliasId: "alias-ceo-001",
    observedAlias: "ceo@example.com",
    participantId: VICTIM,
  });

  const result = await store().assignAlias({
    actor: SCOPE,
    authorizationId: prepared.receipt.authorizationId,
    participantRecordId: VICTIM,
    alias: prepared.alias,
    evidence: prepared.evidence,
    proposedContent: prepared.content,
    mutationReceiptId: "mutation.alias.assign.001",
  });

  assert.equal(result.rejection, null);
  assert.equal(result.verified, true);
  assert.ok(
    result.receipt && result.receipt.outcome.status === "COMMITTED_AND_READ_BACK",
  );
  assert.equal(result.receipt.action, "assign_alias");
  assert.equal(result.receipt.outcome.resultingHead.version, 2);
  assert.equal(result.receipt.outcome.readBackSource, "independent_session");

  // The binding is visible to an INDEPENDENT reader under the SELECT-only role.
  const view = await store().readAliasBinding(SCOPE, "alias-ceo-001");
  assert.ok(view, "the binding must be readable on the read-back pool");
  assert.equal(view.removed, false);
  assert.equal(view.binding.canonicalParticipantId, VICTIM);
  assert.equal(view.binding.normalizedAlias, "ceo@example.com");
  assert.equal(view.binding.skeleton, "ceo@example.com");
  assert.equal(view.binding.scriptCode, "Latn");
  assert.equal(view.binding.restrictionLevel, "ascii_only");
  assert.equal(view.binding.registrableDomain, "example.com");
  assert.equal(view.binding.crossWorkspacePolicy, "workspace_isolated");
  assert.equal(view.binding.scopeKey, SCOPE.workspaceId);
  assert.equal(view.binding.subjectParticipantId, VICTIM);
  // Core's values, and the producer's whole claim, kept separable.
  assert.equal(view.binding.claimed.observedAlias, "ceo@example.com");
  assert.equal(
    view.binding.skeletonAlgorithm,
    "aaliyah.alias-skeleton/core-subset-v1",
  );

  const resolved = await store().resolveAlias(SCOPE, "ceo@example.com");
  assert.equal(resolved?.binding.aliasId, "alias-ceo-001");

  // The durable receipt log is append-only and passes through UNKNOWN first.
  assert.deepEqual(await receiptStatuses("mutation.alias.assign.001"), [
    { phase: "pending", status: "UNKNOWN_PENDING_RECONCILIATION" },
    { phase: "terminal", status: "COMMITTED_AND_READ_BACK" },
  ]);
  assert.notEqual(
    await nonceConsumedAt(prepared.receipt.nonce.bindingDigest),
    null,
  );
});

// ---------------------------------------------------------------------------
// Uniqueness in one scope.
// ---------------------------------------------------------------------------

test("the same normalized alias cannot bind to a second identity in one scope", async () => {
  const first = await prepareAssign({
    aliasId: "alias-ceo-001",
    observedAlias: "ceo@example.com",
    participantId: VICTIM,
  });
  const firstResult = await store().assignAlias({
    actor: SCOPE,
    authorizationId: first.receipt.authorizationId,
    participantRecordId: VICTIM,
    alias: first.alias,
    evidence: first.evidence,
    proposedContent: first.content,
    mutationReceiptId: "mutation.alias.collide.a",
  });
  assert.equal(firstResult.verified, true);

  const second = await prepareAssign({
    aliasId: "alias-ceo-002",
    observedAlias: "ceo@example.com",
    participantId: ATTACKER,
  });
  const secondResult = await store().assignAlias({
    actor: SCOPE,
    authorizationId: second.receipt.authorizationId,
    participantRecordId: ATTACKER,
    alias: second.alias,
    evidence: second.evidence,
    proposedContent: second.content,
    mutationReceiptId: "mutation.alias.collide.b",
  });

  assert.equal(secondResult.verified, false);
  assert.equal(secondResult.rejection, "alias_already_bound");
  assert.equal(secondResult.receipt?.outcome.status, "ABORTED_NO_MUTATION");
  assert.equal(await activeBindings(), 1);
  // The refused attempt spent nothing: the rollback un-consumed its nonce.
  assert.equal(await nonceConsumedAt(second.receipt.nonce.bindingDigest), null);
  // And the victim's record was not advanced by the refused attempt.
  const attackerHead = await adminPool.query(
    `SELECT count(*)::int AS n FROM memory_record_versions WHERE record_id = $1`,
    [ATTACKER],
  );
  assert.equal(attackerHead.rows[0].n, 1);
});

test("a visually confusable alias cannot bind alongside the one it imitates", async () => {
  const first = await prepareAssign({
    aliasId: "alias-jose-001",
    observedAlias: "jose@corp.example",
    participantId: VICTIM,
  });
  assert.equal(
    (
      await store().assignAlias({
        actor: SCOPE,
        authorizationId: first.receipt.authorizationId,
        participantRecordId: VICTIM,
        alias: first.alias,
        evidence: first.evidence,
        proposedContent: first.content,
        mutationReceiptId: "mutation.alias.skel.a",
      })
    ).verified,
    true,
  );

  // Combining acute accent. Single-script Latin, ASCII host, and therefore
  // past the script gate and the domain gate — the SKELETON INDEX is the only
  // thing standing between these two.
  const confusable = await prepareAssign({
    aliasId: "alias-jose-002",
    observedAlias: "josé@corp.example",
    participantId: ATTACKER,
  });
  assert.notEqual(
    confusable.alias.normalizedAlias,
    first.alias.normalizedAlias,
    "the two normalized aliases must differ, or this proves the wrong index",
  );
  assert.equal(confusable.alias.skeleton, first.alias.skeleton);

  const result = await store().assignAlias({
    actor: SCOPE,
    authorizationId: confusable.receipt.authorizationId,
    participantRecordId: ATTACKER,
    alias: confusable.alias,
    evidence: confusable.evidence,
    proposedContent: confusable.content,
    mutationReceiptId: "mutation.alias.skel.b",
  });
  assert.equal(result.verified, false);
  assert.equal(result.rejection, "alias_skeleton_collision");
  assert.equal(await activeBindings(), 1);
  assert.equal(
    await nonceConsumedAt(confusable.receipt.nonce.bindingDigest),
    null,
  );
});

test("a fullwidth confusable is refused by the skeleton index too", async () => {
  const first = await prepareAssign({
    aliasId: "alias-jose-001",
    observedAlias: "jose@corp.example",
    participantId: VICTIM,
  });
  await store().assignAlias({
    actor: SCOPE,
    authorizationId: first.receipt.authorizationId,
    participantRecordId: VICTIM,
    alias: first.alias,
    evidence: first.evidence,
    proposedContent: first.content,
    mutationReceiptId: "mutation.alias.fw.a",
  });
  const confusable = await prepareAssign({
    aliasId: "alias-jose-003",
    observedAlias: "ｊose@corp.example",
    participantId: ATTACKER,
  });
  const result = await store().assignAlias({
    actor: SCOPE,
    authorizationId: confusable.receipt.authorizationId,
    participantRecordId: ATTACKER,
    alias: confusable.alias,
    evidence: confusable.evidence,
    proposedContent: confusable.content,
    mutationReceiptId: "mutation.alias.fw.b",
  });
  assert.equal(result.rejection, "alias_skeleton_collision");
});

// ---------------------------------------------------------------------------
// REAL CONCURRENCY. The defining requirement.
// ---------------------------------------------------------------------------

test("two concurrent attempts to assign ONE alias to DIFFERENT identities: exactly one wins", async () => {
  const victim = await prepareAssign({
    aliasId: "alias-race-victim",
    observedAlias: "ceo@example.com",
    participantId: VICTIM,
  });
  const attacker = await prepareAssign({
    aliasId: "alias-race-attacker",
    observedAlias: "ceo@example.com",
    participantId: ATTACKER,
  });

  // Two stores on two INDEPENDENT write pools. The two participants take two
  // DIFFERENT advisory locks, so nothing in application code serializes them:
  // the partial UNIQUE index is the only exclusion in play.
  const storeA = store();
  const storeB = store({ write: adminPool });

  const [resultA, resultB] = await Promise.all([
    storeA.assignAlias({
      actor: SCOPE,
      authorizationId: victim.receipt.authorizationId,
      participantRecordId: VICTIM,
      alias: victim.alias,
      evidence: victim.evidence,
      proposedContent: victim.content,
      mutationReceiptId: "mutation.alias.race.a",
    }),
    storeB.assignAlias({
      actor: SCOPE,
      authorizationId: attacker.receipt.authorizationId,
      participantRecordId: ATTACKER,
      alias: attacker.alias,
      evidence: attacker.evidence,
      proposedContent: attacker.content,
      mutationReceiptId: "mutation.alias.race.b",
    }),
  ]);

  const winners = [resultA, resultB].filter((r) => r.verified);
  const losers = [resultA, resultB].filter((r) => !r.verified);
  assert.equal(winners.length, 1, "EXACTLY ONE MAY WIN");
  assert.equal(losers.length, 1);
  const loser = losers[0];
  assert.ok(loser, "one writer must be refused");
  assert.equal(loser.rejection, "alias_already_bound");
  assert.equal(loser.receipt?.outcome.status, "ABORTED_NO_MUTATION");

  // Exactly one binding, and it names exactly one participant.
  assert.equal(await activeBindings(), 1);
  const bound = await adminPool.query(
    `SELECT canonical_participant_id FROM memory_alias_bindings
      WHERE tenant_id = $1 AND removed_at IS NULL`,
    [TENANT],
  );
  assert.equal(bound.rows.length, 1);

  // THE LOSER SPENT NOTHING: its nonce is still unconsumed after the rollback.
  const loserAuth = loser === resultA ? victim.receipt : attacker.receipt;
  assert.equal(await nonceConsumedAt(loserAuth.nonce.bindingDigest), null);
  const winnerAuth = loser === resultA ? attacker.receipt : victim.receipt;
  assert.notEqual(await nonceConsumedAt(winnerAuth.nonce.bindingDigest), null);
});

test("two concurrent CONFUSABLE aliases that share one skeleton: exactly one wins", async () => {
  const plain = await prepareAssign({
    aliasId: "alias-race-plain",
    observedAlias: "jose@corp.example",
    participantId: VICTIM,
  });
  const accented = await prepareAssign({
    aliasId: "alias-race-accented",
    observedAlias: "josé@corp.example",
    participantId: ATTACKER,
  });
  assert.notEqual(plain.alias.normalizedAlias, accented.alias.normalizedAlias);
  assert.equal(plain.alias.skeleton, accented.alias.skeleton);

  const storeA = store();
  const storeB = store({ write: adminPool });
  const [resultA, resultB] = await Promise.all([
    storeA.assignAlias({
      actor: SCOPE,
      authorizationId: plain.receipt.authorizationId,
      participantRecordId: VICTIM,
      alias: plain.alias,
      evidence: plain.evidence,
      proposedContent: plain.content,
      mutationReceiptId: "mutation.alias.skelrace.a",
    }),
    storeB.assignAlias({
      actor: SCOPE,
      authorizationId: accented.receipt.authorizationId,
      participantRecordId: ATTACKER,
      alias: accented.alias,
      evidence: accented.evidence,
      proposedContent: accented.content,
      mutationReceiptId: "mutation.alias.skelrace.b",
    }),
  ]);

  assert.equal([resultA, resultB].filter((r) => r.verified).length, 1);
  const loser = [resultA, resultB].find((r) => !r.verified);
  assert.ok(loser);
  assert.equal(loser.rejection, "alias_skeleton_collision");
  assert.equal(await activeBindings(), 1);
  const loserAuth = loser === resultA ? plain.receipt : accented.receipt;
  assert.equal(await nonceConsumedAt(loserAuth.nonce.bindingDigest), null);
});

// ---------------------------------------------------------------------------
// Confusables, scripts and look-alike domains.
// ---------------------------------------------------------------------------

test("the Cyrillic homoglyph alias is REFUSED, by the mixed-script gate", async () => {
  const first = await prepareAssign({
    aliasId: "alias-admin-001",
    observedAlias: "admin@x.com",
    participantId: VICTIM,
  });
  assert.equal(
    (
      await store().assignAlias({
        actor: SCOPE,
        authorizationId: first.receipt.authorizationId,
        participantRecordId: VICTIM,
        alias: first.alias,
        evidence: first.evidence,
        proposedContent: first.content,
        mutationReceiptId: "mutation.alias.cyr.a",
      })
    ).verified,
    true,
  );

  // U+0430 CYRILLIC SMALL LETTER A. The producer LIES about the script and the
  // level — it has to, because contracts forbids proposing acceptance for a
  // mixed-script alias. Core recomputes and catches the lie.
  const homoglyph = await prepareAssign({
    aliasId: "alias-admin-002",
    observedAlias: "аdmin@x.com",
    participantId: ATTACKER,
    aliasOverrides: {
      scriptDetermination: { kind: "single_script", script: "Latn" },
      restrictionLevel: "single_script",
    },
  });
  assert.equal(homoglyph.alias.skeleton, "admin@x.com");
  assert.equal(homoglyph.alias.skeleton, first.alias.skeleton);

  const result = await store().assignAlias({
    actor: SCOPE,
    authorizationId: homoglyph.receipt.authorizationId,
    participantRecordId: ATTACKER,
    alias: homoglyph.alias,
    evidence: homoglyph.evidence,
    proposedContent: homoglyph.content,
    mutationReceiptId: "mutation.alias.cyr.b",
  });
  assert.equal(result.verified, false);
  assert.equal(result.rejection, "alias_mixed_script");
  assert.equal(await activeBindings(), 1);
  assert.equal(
    await nonceConsumedAt(homoglyph.receipt.nonce.bindingDigest),
    null,
  );
});

test("a whole-script Cyrillic look-alike is refused by the IDN homograph gate", async () => {
  // "сео@х.сом" is genuinely single-script Cyrillic, so the mixed-script gate
  // cannot see it. Its HOST is not ASCII, and that is what refuses it.
  const prepared = await prepareAssign({
    aliasId: "alias-whole-cyr",
    observedAlias: "сео@х.сом",
    participantId: VICTIM,
    // `RegistrableDomainSchema` admits only an ASCII A-label, so the producer
    // CANNOT claim this host truthfully. It claims the punycode form. Core
    // never gets as far as comparing that claim: the risk it computes from the
    // host it extracted refuses the alias first.
    aliasOverrides: { registrableDomain: "xn--80ak6aa92e.xn--c1avg" },
  });
  assert.equal(prepared.alias.skeleton, "ceo@x.com");
  const result = await store().assignAlias({
    actor: SCOPE,
    authorizationId: prepared.receipt.authorizationId,
    participantRecordId: VICTIM,
    alias: prepared.alias,
    evidence: prepared.evidence,
    proposedContent: prepared.content,
    mutationReceiptId: "mutation.alias.wholecyr",
  });
  assert.equal(result.rejection, "alias_lookalike_domain");
});

test("a look-alike of a PROTECTED domain is refused", async () => {
  await protectDomain(SCOPE, "example.com");
  const prepared = await prepareAssign({
    aliasId: "alias-typosquat",
    observedAlias: "ceo@examp1e.com",
    participantId: ATTACKER,
  });
  // The producer claims a clean domain signal. Core recomputes it against the
  // corpus the OPERATOR configured, which the producer cannot see or change.
  assert.equal(prepared.alias.lookalikeDomain.risk, "none_detected");
  const result = await store().assignAlias({
    actor: SCOPE,
    authorizationId: prepared.receipt.authorizationId,
    participantRecordId: ATTACKER,
    alias: prepared.alias,
    evidence: prepared.evidence,
    proposedContent: prepared.content,
    mutationReceiptId: "mutation.alias.typo",
  });
  assert.equal(result.verified, false);
  assert.equal(result.rejection, "alias_lookalike_domain");
  assert.equal(await activeBindings(), 0);
});

test("an address AT the protected domain itself is the legitimate case", async () => {
  await protectDomain(SCOPE, "example.com");
  const prepared = await prepareAssign({
    aliasId: "alias-at-protected",
    observedAlias: "ceo@example.com",
    participantId: VICTIM,
  });
  const result = await store().assignAlias({
    actor: SCOPE,
    authorizationId: prepared.receipt.authorizationId,
    participantRecordId: VICTIM,
    alias: prepared.alias,
    evidence: prepared.evidence,
    proposedContent: prepared.content,
    mutationReceiptId: "mutation.alias.atprotected",
  });
  assert.equal(result.verified, true);
});

test("an alias whose script Core cannot name is refused, never guessed", async () => {
  const prepared = await prepareAssign({
    aliasId: "alias-unsupported",
    observedAlias: "ሀdmin@x.com",
    participantId: VICTIM,
    aliasOverrides: {
      scriptDetermination: { kind: "single_script", script: "Latn" },
      restrictionLevel: "single_script",
    },
  });
  const result = await store().assignAlias({
    actor: SCOPE,
    authorizationId: prepared.receipt.authorizationId,
    participantRecordId: VICTIM,
    alias: prepared.alias,
    evidence: prepared.evidence,
    proposedContent: prepared.content,
    mutationReceiptId: "mutation.alias.unsupported",
  });
  assert.equal(result.rejection, "alias_script_undetermined");
});

// ---------------------------------------------------------------------------
// Recomputation. Nothing the producer claims is believed.
// ---------------------------------------------------------------------------

test("a skeleton claim that disagrees with Core's recomputation is refused", async () => {
  const prepared = await prepareAssign({
    aliasId: "alias-skeleton-lie",
    observedAlias: "ceo@example.com",
    participantId: VICTIM,
    aliasOverrides: { skeleton: "somethingelse@example.com" },
  });
  const result = await store().assignAlias({
    actor: SCOPE,
    authorizationId: prepared.receipt.authorizationId,
    participantRecordId: VICTIM,
    alias: prepared.alias,
    evidence: prepared.evidence,
    proposedContent: prepared.content,
    mutationReceiptId: "mutation.alias.skeletonlie",
  });
  assert.equal(result.verified, false);
  assert.equal(result.rejection, "alias_skeleton_disagreement");
  assert.equal(await activeBindings(), 0);
});

test("an invisible character makes the producer's normalization claim disagree", async () => {
  const prepared = await prepareAssign({
    aliasId: "alias-zero-width",
    observedAlias: "ad​min@x.com",
    participantId: VICTIM,
  });
  // The claim is exactly what contracts enforces, and contracts accepted it.
  assert.equal(
    prepared.alias.normalizedAlias,
    prepared.alias.observedAlias.normalize("NFC").toLowerCase(),
  );
  const result = await store().assignAlias({
    actor: SCOPE,
    authorizationId: prepared.receipt.authorizationId,
    participantRecordId: VICTIM,
    alias: prepared.alias,
    evidence: prepared.evidence,
    proposedContent: prepared.content,
    mutationReceiptId: "mutation.alias.zerowidth",
  });
  assert.equal(result.rejection, "alias_normalization_disagreement");
});

test("a claimed registrable domain that is not the alias's host is refused", async () => {
  const prepared = await prepareAssign({
    aliasId: "alias-domain-lie",
    observedAlias: "ceo@example.com",
    participantId: VICTIM,
    aliasOverrides: { registrableDomain: "unrelated.test" },
  });
  const result = await store().assignAlias({
    actor: SCOPE,
    authorizationId: prepared.receipt.authorizationId,
    participantRecordId: VICTIM,
    alias: prepared.alias,
    evidence: prepared.evidence,
    proposedContent: prepared.content,
    mutationReceiptId: "mutation.alias.domainlie",
  });
  assert.equal(result.rejection, "alias_domain_disagreement");
});

test("an alias that is not email shaped is refused", async () => {
  const prepared = await prepareAssign({
    aliasId: "alias-not-email",
    observedAlias: "not-an-email-address",
    participantId: VICTIM,
  });
  const result = await store().assignAlias({
    actor: SCOPE,
    authorizationId: prepared.receipt.authorizationId,
    participantRecordId: VICTIM,
    alias: prepared.alias,
    evidence: prepared.evidence,
    proposedContent: prepared.content,
    mutationReceiptId: "mutation.alias.notemail",
  });
  assert.equal(result.rejection, "alias_not_email_shaped");
});

test("an alias not proposed for acceptance is refused", async () => {
  const prepared = await prepareAssign({
    aliasId: "alias-quarantine",
    observedAlias: "ceo@example.com",
    participantId: VICTIM,
    aliasOverrides: { dispositionProposal: "propose_quarantine" },
  });
  const result = await store().assignAlias({
    actor: SCOPE,
    authorizationId: prepared.receipt.authorizationId,
    participantRecordId: VICTIM,
    alias: prepared.alias,
    evidence: prepared.evidence,
    proposedContent: prepared.content,
    mutationReceiptId: "mutation.alias.quarantine",
  });
  assert.equal(result.rejection, "alias_disposition_not_acceptable");
});

test("a structurally invalid alias or evidence never reaches the database", async () => {
  const result = await store().assignAlias({
    actor: SCOPE,
    authorizationId: nextAuthorizationId(),
    participantRecordId: VICTIM,
    alias: { not: "an alias" },
    evidence: evidenceFor(VICTIM),
    proposedContent: {},
    mutationReceiptId: "mutation.alias.malformed",
  });
  assert.equal(result.rejection, "alias_malformed");
  assert.equal(result.receipt, null);

  const evidenceResult = await store().assignAlias({
    actor: SCOPE,
    authorizationId: nextAuthorizationId(),
    participantRecordId: VICTIM,
    alias: aliasIdentity({
      aliasId: "alias-x",
      observedAlias: "ceo@example.com",
      participantId: VICTIM,
      evidence: evidenceFor(VICTIM),
    }),
    // Missing `subjectParticipantId`: the exact gap contracts closed.
    evidence: {
      evidenceRef: "identity:verification/participant-record",
      evidenceDigest: EVIDENCE_DIGEST,
      observedAt: isoOffset(-60_000),
      freshUntil: isoOffset(3_600_000),
    },
    proposedContent: {},
    mutationReceiptId: "mutation.alias.malformed.evidence",
  });
  assert.equal(evidenceResult.rejection, "alias_evidence_malformed");
});

// ---------------------------------------------------------------------------
// Evidence: the hijack that was proven live.
// ---------------------------------------------------------------------------

test("evidence issued ABOUT A DIFFERENT PARTICIPANT cannot bind an alias", async () => {
  await seedGenesis(ATTACKER);
  // Evidence that is perfectly valid, perfectly fresh — and about somebody
  // else. This is the live hijack, reproduced against the registry.
  const stolen = evidenceFor(ATTACKER);
  const prepared = await prepareAssign({
    aliasId: "alias-hijack",
    observedAlias: "attacker@evil.example",
    participantId: VICTIM,
    evidence: stolen,
  });
  assert.equal(prepared.evidence.subjectParticipantId, ATTACKER);
  assert.equal(prepared.alias.canonicalParticipantId, VICTIM);

  const result = await store().assignAlias({
    actor: SCOPE,
    authorizationId: prepared.receipt.authorizationId,
    participantRecordId: VICTIM,
    alias: prepared.alias,
    evidence: prepared.evidence,
    proposedContent: prepared.content,
    mutationReceiptId: "mutation.alias.hijack",
  });
  assert.equal(result.verified, false);
  assert.equal(result.rejection, "alias_evidence_subject_mismatch");
  assert.equal(await activeBindings(), 0);
});

test("evidence that is not the evidence the alias cites is refused", async () => {
  const prepared = await prepareAssign({
    aliasId: "alias-evidence-swap",
    observedAlias: "ceo@example.com",
    participantId: VICTIM,
  });
  const other = evidenceFor(VICTIM, {
    evidenceRef: "identity:verification/some-other-observation",
  });
  // Re-issue an authorization bound to the SWAPPED evidence, so the digest
  // check passes and the disagreement check is what fires.
  const receipt = await issue(
    authorization({
      action: "assign_alias",
      targetRecordId: VICTIM,
      expectedHead: headOf(1, prepared.genesis),
      proposedContentDigest: aliasAssignmentDigest({
        record: prepared.content,
        alias: prepared.alias,
        evidence: other,
      }),
    }),
  );
  const result = await store().assignAlias({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    participantRecordId: VICTIM,
    alias: prepared.alias,
    evidence: other,
    proposedContent: prepared.content,
    mutationReceiptId: "mutation.alias.evidenceswap",
  });
  assert.equal(result.rejection, "alias_evidence_disagreement");
});

test("stale alias evidence is refused", async () => {
  const stale = evidenceFor(VICTIM, {
    observedAt: isoOffset(-7_200_000),
    freshUntil: isoOffset(-3_600_000),
  });
  const prepared = await prepareAssign({
    aliasId: "alias-stale",
    observedAlias: "ceo@example.com",
    participantId: VICTIM,
    evidence: stale,
  });
  const result = await store().assignAlias({
    actor: SCOPE,
    authorizationId: prepared.receipt.authorizationId,
    participantRecordId: VICTIM,
    alias: prepared.alias,
    evidence: prepared.evidence,
    proposedContent: prepared.content,
    mutationReceiptId: "mutation.alias.stale",
  });
  assert.equal(result.verified, false);
  assert.equal(result.rejection, "alias_evidence_stale");
  assert.equal(await activeBindings(), 0);
});

// ---------------------------------------------------------------------------
// Scope: the alias's own declaration, and the participant it names.
// ---------------------------------------------------------------------------

test("an alias declaring a scope other than the authorized one is refused", async () => {
  const genesis = await seedGenesis(VICTIM);
  const evidence = evidenceFor(VICTIM);
  const alias = aliasIdentity({
    aliasId: "alias-scope-lie",
    observedAlias: "ceo@example.com",
    participantId: VICTIM,
    evidence,
    scope: SCOPE_WORKSPACE_B,
  });
  const content = successorContent(VICTIM, 2);
  const receipt = await issue(
    authorization({
      action: "assign_alias",
      targetRecordId: VICTIM,
      expectedHead: headOf(1, genesis),
      proposedContentDigest: aliasAssignmentDigest({
        record: content,
        alias,
        evidence,
      }),
    }),
  );
  const result = await store().assignAlias({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    participantRecordId: VICTIM,
    alias,
    evidence,
    proposedContent: content,
    mutationReceiptId: "mutation.alias.scopelie",
  });
  assert.equal(result.rejection, "alias_scope_mismatch");
});

test("an alias naming a participant other than the authorized record is refused", async () => {
  const genesis = await seedGenesis(VICTIM);
  const evidence = evidenceFor(ATTACKER);
  const alias = aliasIdentity({
    aliasId: "alias-participant-lie",
    observedAlias: "ceo@example.com",
    participantId: ATTACKER,
    evidence,
  });
  const content = successorContent(VICTIM, 2);
  const receipt = await issue(
    authorization({
      action: "assign_alias",
      targetRecordId: VICTIM,
      expectedHead: headOf(1, genesis),
      proposedContentDigest: aliasAssignmentDigest({
        record: content,
        alias,
        evidence,
      }),
    }),
  );
  const result = await store().assignAlias({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    participantRecordId: VICTIM,
    alias,
    evidence,
    proposedContent: content,
    mutationReceiptId: "mutation.alias.participantlie",
  });
  assert.equal(result.rejection, "alias_participant_mismatch");
});

for (const dimension of [
  "tenantId",
  "workspaceId",
  "principalId",
  "userId",
] as const) {
  test(`an actor whose ${dimension} is not the authorization's is refused`, async () => {
    const prepared = await prepareAssign({
      aliasId: "alias-scope-check",
      observedAlias: "ceo@example.com",
      participantId: VICTIM,
    });
    const impostor: MemoryScope = { ...SCOPE, [dimension]: "someone-else" };
    const result = await store().assignAlias({
      actor: impostor,
      authorizationId: prepared.receipt.authorizationId,
      participantRecordId: VICTIM,
      alias: prepared.alias,
      evidence: prepared.evidence,
      proposedContent: prepared.content,
      mutationReceiptId: `mutation.alias.scope.${dimension.toLowerCase()}`,
    });
    assert.equal(result.rejection, "authorization_scope_mismatch");
    assert.equal(await activeBindings(), 0);
  });
}

// ---------------------------------------------------------------------------
// Cross-workspace policy: explicit, never implicit.
// ---------------------------------------------------------------------------

test("a tenant with NO explicit cross-workspace policy cannot bind an alias", async () => {
  const prepared = await prepareAssign({
    aliasId: "alias-ungoverned",
    observedAlias: "ceo@example.com",
    participantId: VICTIM,
    scope: SCOPE_UNGOVERNED,
  });
  const result = await store().assignAlias({
    actor: SCOPE_UNGOVERNED,
    authorizationId: prepared.receipt.authorizationId,
    participantRecordId: VICTIM,
    alias: prepared.alias,
    evidence: prepared.evidence,
    proposedContent: prepared.content,
    mutationReceiptId: "mutation.alias.ungoverned",
  });
  assert.equal(result.verified, false);
  assert.equal(result.rejection, "alias_scope_policy_missing");
  assert.equal(await activeBindings(TENANT_UNGOVERNED), 0);
});

test("under workspace_isolated the same alias binds in two workspaces of one tenant", async () => {
  const a = await prepareAssign({
    aliasId: "alias-ws-a",
    observedAlias: "ceo@example.com",
    participantId: VICTIM,
    scope: SCOPE,
  });
  assert.equal(
    (
      await store().assignAlias({
        actor: SCOPE,
        authorizationId: a.receipt.authorizationId,
        participantRecordId: VICTIM,
        alias: a.alias,
        evidence: a.evidence,
        proposedContent: a.content,
        mutationReceiptId: "mutation.alias.ws.a",
      })
    ).verified,
    true,
  );
  const b = await prepareAssign({
    aliasId: "alias-ws-b",
    observedAlias: "ceo@example.com",
    participantId: ATTACKER,
    scope: SCOPE_WORKSPACE_B,
  });
  const result = await store().assignAlias({
    actor: SCOPE_WORKSPACE_B,
    authorizationId: b.receipt.authorizationId,
    participantRecordId: ATTACKER,
    alias: b.alias,
    evidence: b.evidence,
    proposedContent: b.content,
    mutationReceiptId: "mutation.alias.ws.b",
  });
  assert.equal(result.rejection, null);
  assert.equal(result.verified, true);
  assert.equal(await activeBindings(), 2);
});

test("under tenant_exclusive the same alias is refused in a SECOND workspace", async () => {
  const a = await prepareAssign({
    aliasId: "alias-excl-a",
    observedAlias: "ceo@example.com",
    participantId: VICTIM,
    scope: SCOPE_EXCLUSIVE_A,
  });
  const first = await store().assignAlias({
    actor: SCOPE_EXCLUSIVE_A,
    authorizationId: a.receipt.authorizationId,
    participantRecordId: VICTIM,
    alias: a.alias,
    evidence: a.evidence,
    proposedContent: a.content,
    mutationReceiptId: "mutation.alias.excl.a",
  });
  assert.equal(first.verified, true);
  const view = await store().readAliasBinding(SCOPE_EXCLUSIVE_A, "alias-excl-a");
  assert.equal(view?.binding.scopeKey, "*");

  const b = await prepareAssign({
    aliasId: "alias-excl-b",
    observedAlias: "ceo@example.com",
    participantId: ATTACKER,
    scope: SCOPE_EXCLUSIVE_B,
  });
  const result = await store().assignAlias({
    actor: SCOPE_EXCLUSIVE_B,
    authorizationId: b.receipt.authorizationId,
    participantRecordId: ATTACKER,
    alias: b.alias,
    evidence: b.evidence,
    proposedContent: b.content,
    mutationReceiptId: "mutation.alias.excl.b",
  });
  assert.equal(result.verified, false);
  assert.equal(result.rejection, "alias_already_bound");
  assert.equal(await activeBindings(TENANT_EXCLUSIVE), 1);

  // The excluded workspace can still SEE what excludes it, which is the point
  // of the policy being tenant-wide rather than a per-query convention.
  const resolved = await store().resolveAlias(
    SCOPE_EXCLUSIVE_B,
    "ceo@example.com",
  );
  assert.equal(resolved?.binding.canonicalParticipantId, VICTIM);
});

test("the same alias binds freely in a DIFFERENT tenant, always", async () => {
  const a = await prepareAssign({
    aliasId: "alias-tenant-a",
    observedAlias: "ceo@example.com",
    participantId: VICTIM,
    scope: SCOPE,
  });
  await store().assignAlias({
    actor: SCOPE,
    authorizationId: a.receipt.authorizationId,
    participantRecordId: VICTIM,
    alias: a.alias,
    evidence: a.evidence,
    proposedContent: a.content,
    mutationReceiptId: "mutation.alias.tenant.a",
  });
  const b = await prepareAssign({
    aliasId: "alias-tenant-b",
    observedAlias: "ceo@example.com",
    participantId: VICTIM,
    scope: SCOPE_OTHER_TENANT,
  });
  const result = await store().assignAlias({
    actor: SCOPE_OTHER_TENANT,
    authorizationId: b.receipt.authorizationId,
    participantRecordId: VICTIM,
    alias: b.alias,
    evidence: b.evidence,
    proposedContent: b.content,
    mutationReceiptId: "mutation.alias.tenant.b",
  });
  assert.equal(result.verified, true);
  assert.equal(await activeBindings(TENANT), 1);
  assert.equal(await activeBindings(TENANT_OTHER), 1);
});

// ---------------------------------------------------------------------------
// Removal and reassignment.
// ---------------------------------------------------------------------------

/** Bind an alias on the honest path and answer everything needed to remove it. */
async function bindThen(
  aliasId: string,
  observedAlias: string,
  participantId: string,
  mutationReceiptId: string,
): Promise<{ headDigest: string }> {
  const prepared = await prepareAssign({
    aliasId,
    observedAlias,
    participantId,
  });
  const result = await store().assignAlias({
    actor: SCOPE,
    authorizationId: prepared.receipt.authorizationId,
    participantRecordId: participantId,
    alias: prepared.alias,
    evidence: prepared.evidence,
    proposedContent: prepared.content,
    mutationReceiptId,
  });
  assert.equal(result.verified, true, "the honest bind must succeed first");
  return { headDigest: await headDigestOf(participantId, SCOPE) };
}

test("removing an alias retires the binding and frees it for reassignment", async () => {
  const bound = await bindThen(
    "alias-recycle",
    "ceo@example.com",
    VICTIM,
    "mutation.alias.recycle.bind",
  );

  const removalContent = successorContent(VICTIM, 3);
  const removal = await issue(
    authorization({
      action: "remove_alias",
      targetRecordId: VICTIM,
      expectedHead: headOf(2, bound.headDigest),
      proposedContentDigest: aliasRemovalDigest({
        record: removalContent,
        aliasId: "alias-recycle",
      }),
    }),
  );
  const removed = await store().removeAlias({
    actor: SCOPE,
    authorizationId: removal.authorizationId,
    participantRecordId: VICTIM,
    aliasId: "alias-recycle",
    proposedContent: removalContent,
    mutationReceiptId: "mutation.alias.recycle.remove",
  });
  assert.equal(removed.rejection, null);
  assert.equal(removed.verified, true);
  assert.equal(removed.receipt?.action, "remove_alias");
  assert.equal(await activeBindings(), 0);

  const view = await store().readAliasBinding(SCOPE, "alias-recycle");
  assert.equal(view?.removed, true);
  assert.equal(await store().resolveAlias(SCOPE, "ceo@example.com"), null);

  // The retired binding is still on disk: retirement, not erasure.
  const rows = await adminPool.query(
    `SELECT count(*)::int AS n FROM memory_alias_bindings WHERE tenant_id = $1`,
    [TENANT],
  );
  assert.equal(rows.rows[0].n, 1);

  // And the alias is free again, for a DIFFERENT participant.
  await seedGenesis(ATTACKER);
  const reassigned = await prepareAssign({
    aliasId: "alias-recycle-2",
    observedAlias: "ceo@example.com",
    participantId: ATTACKER,
    seed: false,
  });
  const result = await store().assignAlias({
    actor: SCOPE,
    authorizationId: reassigned.receipt.authorizationId,
    participantRecordId: ATTACKER,
    alias: reassigned.alias,
    evidence: reassigned.evidence,
    proposedContent: reassigned.content,
    mutationReceiptId: "mutation.alias.recycle.reassign",
  });
  assert.equal(result.verified, true);
  assert.equal(await activeBindings(), 1);
});

test("removing an alias that is not bound is refused", async () => {
  const genesis = await seedGenesis(VICTIM);
  const content = successorContent(VICTIM, 2);
  const removal = await issue(
    authorization({
      action: "remove_alias",
      targetRecordId: VICTIM,
      expectedHead: headOf(1, genesis),
      proposedContentDigest: aliasRemovalDigest({
        record: content,
        aliasId: "alias-never-bound",
      }),
    }),
  );
  const result = await store().removeAlias({
    actor: SCOPE,
    authorizationId: removal.authorizationId,
    participantRecordId: VICTIM,
    aliasId: "alias-never-bound",
    proposedContent: content,
    mutationReceiptId: "mutation.alias.removemissing",
  });
  assert.equal(result.verified, false);
  assert.equal(result.rejection, "alias_not_bound");
  assert.equal(await nonceConsumedAt(removal.nonce.bindingDigest), null);
});

test("an authorization to remove ONE alias cannot remove another", async () => {
  await bindThen(
    "alias-keep",
    "ceo@example.com",
    VICTIM,
    "mutation.alias.keep.bind",
  );
  const headDigest = await headDigestOf(VICTIM, SCOPE);
  const content = successorContent(VICTIM, 3);
  // Bound to "alias-keep"...
  const removal = await issue(
    authorization({
      action: "remove_alias",
      targetRecordId: VICTIM,
      expectedHead: headOf(2, headDigest),
      proposedContentDigest: aliasRemovalDigest({
        record: content,
        aliasId: "alias-keep",
      }),
    }),
  );
  // ...and spent on a different alias id.
  const result = await store().removeAlias({
    actor: SCOPE,
    authorizationId: removal.authorizationId,
    participantRecordId: VICTIM,
    aliasId: "alias-something-else",
    proposedContent: content,
    mutationReceiptId: "mutation.alias.keep.wrongalias",
  });
  assert.equal(result.rejection, "proposed_content_digest_mismatch");
  assert.equal(await activeBindings(), 1);
});

test("removing an alias bound to a DIFFERENT participant is refused", async () => {
  await bindThen(
    "alias-owned",
    "ceo@example.com",
    VICTIM,
    "mutation.alias.owned.bind",
  );
  const attackerGenesis = await seedGenesis(ATTACKER);
  const content = successorContent(ATTACKER, 2);
  const removal = await issue(
    authorization({
      action: "remove_alias",
      targetRecordId: ATTACKER,
      expectedHead: headOf(1, attackerGenesis),
      proposedContentDigest: aliasRemovalDigest({
        record: content,
        aliasId: "alias-owned",
      }),
    }),
  );
  const result = await store().removeAlias({
    actor: SCOPE,
    authorizationId: removal.authorizationId,
    participantRecordId: ATTACKER,
    aliasId: "alias-owned",
    proposedContent: content,
    mutationReceiptId: "mutation.alias.owned.steal",
  });
  assert.equal(result.verified, false);
  assert.equal(result.rejection, "alias_participant_mismatch");
  assert.equal(await activeBindings(), 1);
});

// ---------------------------------------------------------------------------
// The authorization mechanism, on this path.
// ---------------------------------------------------------------------------

test("replaying an assign authorization is refused the second time", async () => {
  const prepared = await prepareAssign({
    aliasId: "alias-replay",
    observedAlias: "ceo@example.com",
    participantId: VICTIM,
  });
  const first = await store().assignAlias({
    actor: SCOPE,
    authorizationId: prepared.receipt.authorizationId,
    participantRecordId: VICTIM,
    alias: prepared.alias,
    evidence: prepared.evidence,
    proposedContent: prepared.content,
    mutationReceiptId: "mutation.alias.replay.1",
  });
  assert.equal(first.verified, true);

  const replay = await store().assignAlias({
    actor: SCOPE,
    authorizationId: prepared.receipt.authorizationId,
    participantRecordId: VICTIM,
    alias: prepared.alias,
    evidence: prepared.evidence,
    proposedContent: prepared.content,
    mutationReceiptId: "mutation.alias.replay.2",
  });
  assert.equal(replay.verified, false);
  assert.equal(replay.rejection, "authorization_already_consumed");
  assert.equal(await activeBindings(), 1);
});

test("two concurrent attempts on the SAME assign authorization consume it once", async () => {
  const prepared = await prepareAssign({
    aliasId: "alias-double",
    observedAlias: "ceo@example.com",
    participantId: VICTIM,
  });
  const storeA = store();
  const storeB = store({ write: adminPool });
  const [a, b] = await Promise.all([
    storeA.assignAlias({
      actor: SCOPE,
      authorizationId: prepared.receipt.authorizationId,
      participantRecordId: VICTIM,
      alias: prepared.alias,
      evidence: prepared.evidence,
      proposedContent: prepared.content,
      mutationReceiptId: "mutation.alias.double.a",
    }),
    storeB.assignAlias({
      actor: SCOPE,
      authorizationId: prepared.receipt.authorizationId,
      participantRecordId: VICTIM,
      alias: prepared.alias,
      evidence: prepared.evidence,
      proposedContent: prepared.content,
      mutationReceiptId: "mutation.alias.double.b",
    }),
  ]);
  assert.equal([a, b].filter((r) => r.verified).length, 1);
  const loser = [a, b].find((r) => !r.verified);
  assert.equal(loser?.rejection, "authorization_already_consumed");
  assert.equal(await activeBindings(), 1);
});

test("an assign authorization cannot be spent on a DIFFERENT alias", async () => {
  const prepared = await prepareAssign({
    aliasId: "alias-bound-to-auth",
    observedAlias: "ceo@example.com",
    participantId: VICTIM,
  });
  const substituted = aliasIdentity({
    aliasId: "alias-substituted",
    observedAlias: "attacker@evil.example",
    participantId: VICTIM,
    evidence: prepared.evidence,
  });
  const result = await store().assignAlias({
    actor: SCOPE,
    authorizationId: prepared.receipt.authorizationId,
    participantRecordId: VICTIM,
    alias: substituted,
    evidence: prepared.evidence,
    proposedContent: prepared.content,
    mutationReceiptId: "mutation.alias.substituted",
  });
  assert.equal(result.rejection, "proposed_content_digest_mismatch");
  assert.equal(await activeBindings(), 0);
});

test("an assign_alias authorization cannot perform a removal, and vice versa", async () => {
  const prepared = await prepareAssign({
    aliasId: "alias-action",
    observedAlias: "ceo@example.com",
    participantId: VICTIM,
  });
  const result = await store().removeAlias({
    actor: SCOPE,
    authorizationId: prepared.receipt.authorizationId,
    participantRecordId: VICTIM,
    aliasId: "alias-action",
    proposedContent: prepared.content,
    mutationReceiptId: "mutation.alias.wrongaction",
  });
  assert.equal(result.rejection, "authorization_action_mismatch");
});

test("an authorization for a different participant record is refused", async () => {
  const prepared = await prepareAssign({
    aliasId: "alias-target",
    observedAlias: "ceo@example.com",
    participantId: VICTIM,
  });
  await seedGenesis(ATTACKER);
  const result = await store().assignAlias({
    actor: SCOPE,
    authorizationId: prepared.receipt.authorizationId,
    participantRecordId: ATTACKER,
    alias: prepared.alias,
    evidence: prepared.evidence,
    proposedContent: prepared.content,
    mutationReceiptId: "mutation.alias.wrongtarget",
  });
  assert.equal(result.rejection, "authorization_target_mismatch");
});

test("an authorization whose expected head is stale refuses the assignment", async () => {
  const prepared = await prepareAssign({
    aliasId: "alias-stalehead",
    observedAlias: "ceo@example.com",
    participantId: VICTIM,
  });
  // Somebody else advanced the record between issuance and use. Even an
  // interloper has to have spent an authorization now (migration 034), so the
  // fixture spends one: the point of this test is the STALE HEAD, and an
  // append that the database would refuse for an unrelated reason would prove
  // nothing about it.
  await witnessAppend({
    authorizationId: "interloper-000000000000000000",
    mutationReceiptId: "mutation.interloper",
    targetRecordId: VICTIM,
    action: "correct",
  });
  await adminPool.query(
    `INSERT INTO memory_record_versions
       (tenant_id, workspace_id, principal_id, user_id, record_id, version,
        state, content_digest, predecessor_digest, authorization_id,
        mutation_receipt_id, payload)
     VALUES ($1,$2,$3,$4,$5,2,'active',$6,$7,$8,$9,$10)`,
    [
      SCOPE.tenantId,
      SCOPE.workspaceId,
      SCOPE.principalId,
      SCOPE.userId,
      VICTIM,
      `sha256:${"d".repeat(64)}`,
      prepared.genesis,
      "interloper-000000000000000000",
      "mutation.interloper",
      JSON.stringify({
        schemaVersion: MEMORY_RECORD_VERSION_SCHEMA_VERSION,
        recordId: VICTIM,
        version: 2,
        state: "active",
        scope: SCOPE,
        content: { participant: VICTIM, generation: 99 },
        contentDigest: `sha256:${"d".repeat(64)}`,
        predecessorDigest: prepared.genesis,
        authorizationId: "interloper-000000000000000000",
        mutationReceiptId: "mutation.interloper",
        createdAt: isoOffset(-1000),
      }),
    ],
  );
  const result = await store().assignAlias({
    actor: SCOPE,
    authorizationId: prepared.receipt.authorizationId,
    participantRecordId: VICTIM,
    alias: prepared.alias,
    evidence: prepared.evidence,
    proposedContent: prepared.content,
    mutationReceiptId: "mutation.alias.stalehead",
  });
  assert.equal(result.rejection, "head_mismatch");
  assert.equal(await activeBindings(), 0);
});

test("a revoked authorization, an expired one and a missing nonce are all refused", async () => {
  const revoked = await prepareAssign({
    aliasId: "alias-revoked",
    observedAlias: "ceo@example.com",
    participantId: VICTIM,
  });
  await adminPool.query(
    `UPDATE memory_authorization_nonces SET revoked_at = now()
      WHERE binding_digest = $1`,
    [revoked.receipt.nonce.bindingDigest],
  );
  assert.equal(
    (
      await store().assignAlias({
        actor: SCOPE,
        authorizationId: revoked.receipt.authorizationId,
        participantRecordId: VICTIM,
        alias: revoked.alias,
        evidence: revoked.evidence,
        proposedContent: revoked.content,
        mutationReceiptId: "mutation.alias.revoked",
      })
    ).rejection,
    "authorization_revoked",
  );

  const genesis = await headDigestOf(VICTIM, SCOPE);
  const evidence = evidenceFor(VICTIM);
  const alias = aliasIdentity({
    aliasId: "alias-expired",
    observedAlias: "ops@example.com",
    participantId: VICTIM,
    evidence,
  });
  const content = successorContent(VICTIM, 2);
  const expired = await issue(
    authorization({
      action: "assign_alias",
      targetRecordId: VICTIM,
      expectedHead: headOf(1, genesis),
      proposedContentDigest: aliasAssignmentDigest({
        record: content,
        alias,
        evidence,
      }),
      issuedAt: isoOffset(-7_200_000),
      expiresAt: isoOffset(-3_600_000),
    }),
  );
  assert.equal(
    (
      await store().assignAlias({
        actor: SCOPE,
        authorizationId: expired.authorizationId,
        participantRecordId: VICTIM,
        alias,
        evidence,
        proposedContent: content,
        mutationReceiptId: "mutation.alias.expired",
      })
    ).rejection,
    "authorization_expired",
  );

  const orphanAlias = aliasIdentity({
    aliasId: "alias-orphan",
    observedAlias: "legal@example.com",
    participantId: VICTIM,
    evidence,
  });
  const orphan = await issue(
    authorization({
      action: "assign_alias",
      targetRecordId: VICTIM,
      expectedHead: headOf(1, genesis),
      proposedContentDigest: aliasAssignmentDigest({
        record: content,
        alias: orphanAlias,
        evidence,
      }),
    }),
    { skipNonceRow: true },
  );
  assert.equal(
    (
      await store().assignAlias({
        actor: SCOPE,
        authorizationId: orphan.authorizationId,
        participantRecordId: VICTIM,
        alias: orphanAlias,
        evidence,
        proposedContent: content,
        mutationReceiptId: "mutation.alias.orphan",
      })
    ).rejection,
    "nonce_missing",
  );
  assert.equal(await activeBindings(), 0);
});

test("an assign authorization cannot be spent on DIFFERENT record content", async () => {
  const prepared = await prepareAssign({
    aliasId: "alias-content-bound",
    observedAlias: "ceo@example.com",
    participantId: VICTIM,
  });
  const result = await store().assignAlias({
    actor: SCOPE,
    authorizationId: prepared.receipt.authorizationId,
    participantRecordId: VICTIM,
    alias: prepared.alias,
    evidence: prepared.evidence,
    // Same alias, same evidence, DIFFERENT successor content.
    proposedContent: successorContent(VICTIM, 99),
    mutationReceiptId: "mutation.alias.contentswap",
  });
  assert.equal(result.rejection, "proposed_content_digest_mismatch");
  assert.equal(await activeBindings(), 0);
});

test("a receipt ROW marked consumed refuses the assignment even when its nonce is unspent", async () => {
  const genesis = await seedGenesis(VICTIM);
  const evidence = evidenceFor(VICTIM);
  const alias = aliasIdentity({
    aliasId: "alias-row-consumed",
    observedAlias: "ceo@example.com",
    participantId: VICTIM,
    evidence,
  });
  const content = successorContent(VICTIM, 2);
  const receipt = await issue(
    authorization({
      action: "assign_alias",
      targetRecordId: VICTIM,
      expectedHead: headOf(1, genesis),
      proposedContentDigest: aliasAssignmentDigest({
        record: content,
        alias,
        evidence,
      }),
    }),
    { receiptConsumedAt: isoOffset(-30_000) },
  );
  // The nonce is genuinely unspent, so only the receipt ROW can refuse this.
  assert.equal(await nonceConsumedAt(receipt.nonce.bindingDigest), null);
  const result = await store().assignAlias({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    participantRecordId: VICTIM,
    alias,
    evidence,
    proposedContent: content,
    mutationReceiptId: "mutation.alias.rowconsumed",
  });
  assert.equal(result.rejection, "authorization_already_consumed");
  assert.equal(await activeBindings(), 0);
});

test("a receipt whose jsonb PAYLOAD is already consumed is refused", async () => {
  const genesis = await seedGenesis(VICTIM);
  const evidence = evidenceFor(VICTIM);
  const alias = aliasIdentity({
    aliasId: "alias-payload-consumed",
    observedAlias: "ceo@example.com",
    participantId: VICTIM,
    evidence,
  });
  const content = successorContent(VICTIM, 2);
  const receipt = await issue(
    authorization({
      action: "assign_alias",
      targetRecordId: VICTIM,
      expectedHead: headOf(1, genesis),
      proposedContentDigest: aliasAssignmentDigest({
        record: content,
        alias,
        evidence,
      }),
      consumedAt: isoOffset(-30_000),
    }),
    // Column explicitly NULL, so the PAYLOAD is the only source that says
    // consumed. Fail-closed means the safest reading wins.
    { receiptConsumedAt: null },
  );
  assert.equal(await nonceConsumedAt(receipt.nonce.bindingDigest), null);
  const result = await store().assignAlias({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    participantRecordId: VICTIM,
    alias,
    evidence,
    proposedContent: content,
    mutationReceiptId: "mutation.alias.payloadconsumed",
  });
  assert.equal(result.rejection, "authorization_already_consumed");
});

test("a NONCE already spent refuses the assignment even when its receipt looks unspent", async () => {
  const prepared = await prepareAssign({
    aliasId: "alias-nonce-spent",
    observedAlias: "ceo@example.com",
    participantId: VICTIM,
  });
  // Spend the token out of band and leave BOTH receipt sources untouched, so
  // the atomic `UPDATE ... WHERE consumed_at IS NULL` is the only control that
  // can refuse this. It is the authority on single use; the receipt columns are
  // bookkeeping.
  await adminPool.query(
    `UPDATE memory_authorization_nonces
        SET consumed_at = now(), consumed_by_mutation_receipt_id = 'mutation.elsewhere'
      WHERE binding_digest = $1`,
    [prepared.receipt.nonce.bindingDigest],
  );
  const result = await store().assignAlias({
    actor: SCOPE,
    authorizationId: prepared.receipt.authorizationId,
    participantRecordId: VICTIM,
    alias: prepared.alias,
    evidence: prepared.evidence,
    proposedContent: prepared.content,
    mutationReceiptId: "mutation.alias.noncespent",
  });
  assert.equal(result.rejection, "authorization_already_consumed");
  assert.equal(await activeBindings(), 0);
});

test("a head at the WRONG VERSION is refused even when its content digest matches", async () => {
  const prepared = await prepareAssign({
    aliasId: "alias-wrongversion",
    observedAlias: "ceo@example.com",
    participantId: VICTIM,
  });
  // A second row whose content digest is EXACTLY the one the authorization
  // expects, at a version the authorization does not expect. Only the VERSION
  // comparison can refuse this.
  await witnessAppend({
    authorizationId: "interloper-000000000000000001",
    mutationReceiptId: "mutation.interloper.same-digest",
    targetRecordId: VICTIM,
    action: "correct",
  });
  await adminPool.query(
    `INSERT INTO memory_record_versions
       (tenant_id, workspace_id, principal_id, user_id, record_id, version,
        state, content_digest, predecessor_digest, authorization_id,
        mutation_receipt_id, payload)
     VALUES ($1,$2,$3,$4,$5,2,'active',$6,$6,$7,$8,$9)`,
    [
      SCOPE.tenantId,
      SCOPE.workspaceId,
      SCOPE.principalId,
      SCOPE.userId,
      VICTIM,
      prepared.genesis,
      "interloper-000000000000000001",
      "mutation.interloper.same-digest",
      JSON.stringify({
        schemaVersion: MEMORY_RECORD_VERSION_SCHEMA_VERSION,
        recordId: VICTIM,
        version: 2,
        state: "active",
        scope: SCOPE,
        content: { participant: VICTIM, generation: 1 },
        contentDigest: prepared.genesis,
        predecessorDigest: prepared.genesis,
        authorizationId: "interloper-000000000000000001",
        mutationReceiptId: "mutation.interloper.same-digest",
        createdAt: isoOffset(-1000),
      }),
    ],
  );
  const result = await store().assignAlias({
    actor: SCOPE,
    authorizationId: prepared.receipt.authorizationId,
    participantRecordId: VICTIM,
    alias: prepared.alias,
    evidence: prepared.evidence,
    proposedContent: prepared.content,
    mutationReceiptId: "mutation.alias.wrongversion",
  });
  assert.equal(result.rejection, "head_mismatch");
  assert.equal(await activeBindings(), 0);
});

test("a head at the RIGHT VERSION with the wrong content digest is refused", async () => {
  const genesis = await seedGenesis(VICTIM);
  const evidence = evidenceFor(VICTIM);
  const alias = aliasIdentity({
    aliasId: "alias-wrongdigest",
    observedAlias: "ceo@example.com",
    participantId: VICTIM,
    evidence,
  });
  const content = successorContent(VICTIM, 2);
  // The authorization expects version 1 — which IS the head — but names a
  // predecessor digest the record does not have. Only the DIGEST comparison
  // can refuse this.
  assert.notEqual(genesis, `sha256:${"e".repeat(64)}`);
  const receipt = await issue(
    authorization({
      action: "assign_alias",
      targetRecordId: VICTIM,
      expectedHead: headOf(1, `sha256:${"e".repeat(64)}`),
      proposedContentDigest: aliasAssignmentDigest({
        record: content,
        alias,
        evidence,
      }),
    }),
  );
  const result = await store().assignAlias({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    participantRecordId: VICTIM,
    alias,
    evidence,
    proposedContent: content,
    mutationReceiptId: "mutation.alias.wrongdigest",
  });
  assert.equal(result.rejection, "head_mismatch");
  assert.equal(await activeBindings(), 0);
});

test("a nonce row that disagrees with its receipt refuses the assignment", async () => {
  const genesis = await seedGenesis(VICTIM);
  const evidence = evidenceFor(VICTIM);
  const alias = aliasIdentity({
    aliasId: "alias-nonce-disagree",
    observedAlias: "ceo@example.com",
    participantId: VICTIM,
    evidence,
  });
  const content = successorContent(VICTIM, 2);
  const receipt = await issue(
    authorization({
      action: "assign_alias",
      targetRecordId: VICTIM,
      expectedHead: headOf(1, genesis),
      proposedContentDigest: aliasAssignmentDigest({
        record: content,
        alias,
        evidence,
      }),
    }),
    { nonceAction: "remove_alias" },
  );
  const result = await store().assignAlias({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    participantRecordId: VICTIM,
    alias,
    evidence,
    proposedContent: content,
    mutationReceiptId: "mutation.alias.noncedisagree",
  });
  assert.equal(result.rejection, "nonce_disagrees_with_receipt");
});

// ---------------------------------------------------------------------------
// Database-level controls: privileges, append-only-ness, derived scope key.
// ---------------------------------------------------------------------------

test("the binding table refuses DELETE and refuses any update but retirement", async () => {
  await bindThen(
    "alias-immutable",
    "ceo@example.com",
    VICTIM,
    "mutation.alias.immutable.bind",
  );
  await assert.rejects(
    () =>
      adminPool.query(`DELETE FROM memory_alias_bindings WHERE tenant_id = $1`, [
        TENANT,
      ]),
    /a binding is retired, never erased/,
  );
  await assert.rejects(
    () =>
      adminPool.query(
        `UPDATE memory_alias_bindings SET canonical_participant_id = $2
          WHERE tenant_id = $1`,
        [TENANT, ATTACKER],
      ),
    /retirement is the only permitted update/,
  );
  await assert.rejects(
    () =>
      adminPool.query(
        `UPDATE memory_alias_bindings
            SET removed_at = now(),
                removed_by_mutation_receipt_id = 'mutation.x',
                removed_authorization_id = 'auth-x',
                canonical_participant_id = $2
          WHERE tenant_id = $1`,
        [TENANT, ATTACKER],
      ),
    /retirement may not rewrite a binding/,
  );
  assert.equal(await activeBindings(), 1);
});

test("the mutation role cannot set a tenant policy or add a protected domain", async () => {
  const client = await adminPool.connect();
  try {
    await client.query("BEGIN");
    await client.query('SET LOCAL ROLE "aaliyah_memory_mutator"');
    await assert.rejects(
      () =>
        client.query(
          `INSERT INTO memory_alias_tenant_policy
             (tenant_id, cross_workspace_policy, set_by_actor_id, policy_version)
           VALUES ('tenant-rogue','workspace_isolated','actor.rogue','p/v1')`,
        ),
      /permission denied for table memory_alias_tenant_policy/,
    );
  } finally {
    await client.query("ROLLBACK").catch(() => undefined);
    client.release();
  }

  const second = await adminPool.connect();
  try {
    await second.query("BEGIN");
    await second.query('SET LOCAL ROLE "aaliyah_memory_mutator"');
    await assert.rejects(
      () =>
        second.query(
          `INSERT INTO memory_alias_protected_domains
             (tenant_id, workspace_id, registrable_domain, corpus_ref, added_by_actor_id)
           VALUES ($1,$2,'evil.example','corpus:x','actor.rogue')`,
          [TENANT, SCOPE.workspaceId],
        ),
      /permission denied for table memory_alias_protected_domains/,
    );
  } finally {
    await second.query("ROLLBACK").catch(() => undefined);
    second.release();
  }
});

test("a binding row cannot lie about its scope key or its tenant's policy", async () => {
  // A payload that satisfies every jsonb-to-column binding CHECK, so the ONLY
  // constraint left to refuse the row is the one under test. A `'{}'` payload
  // would trip a binding CHECK first and prove nothing about scope_key.
  const payload = (policy: string, scopeKey: string, aliasId: string) =>
    JSON.stringify({
      scope: {
        tenantId: TENANT,
        workspaceId: SCOPE.workspaceId,
        principalId: "p",
        userId: "u",
      },
      aliasId,
      normalizedAlias: "a@x.com",
      skeleton: "a@x.com",
      canonicalParticipantId: "part",
      subjectParticipantId: "part",
      crossWorkspacePolicy: policy,
      scopeKey,
      authorizationId: "auth-x",
      mutationReceiptId: "m.x",
    });
  const insert = (policy: string, scopeKey: string, aliasId: string) =>
    adminPool.query(
      `INSERT INTO memory_alias_bindings
         (tenant_id, workspace_id, principal_id, user_id,
          cross_workspace_policy, scope_key, alias_id, normalized_alias,
          skeleton, skeleton_algorithm, normalization_profile,
          canonical_participant_id, registrable_domain, script_code,
          restriction_level, subject_participant_id, source_evidence_ref,
          source_evidence_digest, observed_at, fresh_until,
          authorization_id, mutation_receipt_id, bound_at, payload)
       VALUES ($1,$2,'p','u',$4,$5,$6,'a@x.com',
               'a@x.com','sk','np','part','x.com','Latn','ascii_only','part',
               'identity:x/y',$3, now(), now() + interval '1 hour',
               'auth-x','m.x', now(), $7::jsonb)`,
      [
        TENANT,
        SCOPE.workspaceId,
        EVIDENCE_DIGEST,
        policy,
        scopeKey,
        aliasId,
        payload(policy, scopeKey, aliasId),
      ],
    );

  // workspace_isolated must carry its own workspace, never the sentinel.
  await assert.rejects(
    () => insert("workspace_isolated", "*", "alias-lie"),
    /memory_alias_bindings_scope_key_derivation/,
  );
  // tenant_exclusive must carry the sentinel, never its workspace.
  await assert.rejects(
    () => insert("tenant_exclusive", SCOPE.workspaceId, "alias-lie2"),
    /memory_alias_bindings_scope_key_derivation/,
  );
  // And a policy the tenant has not declared is refused by the foreign key.
  await assert.rejects(
    () => insert("tenant_exclusive", "*", "alias-lie3"),
    /memory_alias_bindings_policy_fk/,
  );
});

test("the registry's scalar CHECK constraints each refuse the row they exist for", async () => {
  const cases: ReadonlyArray<{
    constraint: string;
    columns?: Record<string, unknown>;
    payload?: Record<string, unknown>;
  }> = [
    {
      // The '*' sentinel must never collide with a real workspace.
      constraint: "memory_alias_bindings_workspace_not_sentinel",
      columns: { workspace_id: "*", scope_key: "*", alias_id: "alias-raw-1" },
      payload: {
        scope: {
          tenantId: TENANT,
          workspaceId: "*",
          principalId: SCOPE.principalId,
          userId: SCOPE.userId,
        },
        aliasId: "alias-raw-1",
        scopeKey: "*",
      },
    },
    {
      constraint: "memory_alias_bindings_evidence_digest_form",
      columns: { source_evidence_digest: "not-a-digest", alias_id: "alias-raw-2" },
      payload: { aliasId: "alias-raw-2" },
    },
    {
      constraint: "memory_alias_bindings_freshness_window",
      columns: {
        observed_at: new Date(Date.now()),
        fresh_until: new Date(Date.now() - 60_000),
        alias_id: "alias-raw-3",
      },
      payload: { aliasId: "alias-raw-3" },
    },
    {
      // "Retired with nobody who retired it" is unrepresentable.
      constraint: "memory_alias_bindings_removal_witness",
      columns: { removed_at: new Date(), alias_id: "alias-raw-4" },
      payload: { aliasId: "alias-raw-4" },
    },
    {
      constraint: "memory_alias_bindings_removal_after_binding",
      columns: {
        bound_at: new Date(Date.now() - 1_000),
        removed_at: new Date(Date.now() - 3_600_000),
        removed_by_mutation_receipt_id: "mutation.raw",
        removed_authorization_id: "auth-raw",
        alias_id: "alias-raw-5",
      },
      payload: { aliasId: "alias-raw-5" },
    },
    {
      // A NON-OBJECT payload is refused — but NOT by
      // `memory_alias_bindings_payload_object`, and this test says so rather
      // than pretending otherwise. PostgreSQL evaluates CHECK constraints in
      // NAME order, and every `payload->...` binding CHECK that sorts earlier
      // also fails on a non-object payload (the dereference is NULL). That
      // constraint is therefore a redundant backstop which can never be the
      // reported violation, and it is reported as such, not claimed as a
      // separately exercised control.
      constraint: "memory_alias_bindings_alias_id_binding",
      columns: { payload: "[]", alias_id: "alias-raw-6" },
    },
  ];
  for (const testCase of cases) {
    await assert.rejects(
      () => insertRawBinding(testCase.columns ?? {}, testCase.payload ?? {}),
      new RegExp(testCase.constraint),
      `${testCase.constraint} must refuse the row it exists for`,
    );
  }
});

test("the exact-numeric trigger covers the registry payload too", async () => {
  await assert.rejects(
    () => insertRawBinding({ alias_id: "alias-raw-num" }, {
      aliasId: "alias-raw-num",
      // jsonb keeps 0.5 exactly; JSON.parse in Node does not. A digest taken
      // over the round-tripped value would not describe what is on disk.
      inexact: 0.5,
    }),
    /outside the exact numeric domain/,
  );
});

test("one tenant cannot hold two cross-workspace policies", async () => {
  await assert.rejects(
    () =>
      adminPool.query(
        `INSERT INTO memory_alias_tenant_policy
           (tenant_id, cross_workspace_policy, set_by_actor_id, policy_version)
         VALUES ($1,'tenant_exclusive','actor.rogue','alias-policy/v1')`,
        [TENANT],
      ),
    /memory_alias_tenant_policy_pkey/,
  );
  await assert.rejects(
    () =>
      adminPool.query(
        `INSERT INTO memory_alias_tenant_policy
           (tenant_id, cross_workspace_policy, set_by_actor_id, policy_version)
         VALUES ('tenant-nonsense','anything_goes','actor.rogue','alias-policy/v1')`,
      ),
    /memory_alias_tenant_policy_domain/,
  );
});

test("the protected-domain corpus refuses a malformed host and a duplicate", async () => {
  await assert.rejects(
    () => protectDomain(SCOPE, "NOT A DOMAIN"),
    /memory_alias_protected_domains_host_form/,
  );
  await protectDomain(SCOPE, "example.com");
  await assert.rejects(
    () => protectDomain(SCOPE, "example.com"),
    /memory_alias_protected_domains_unique/,
  );
});

test("the mutation role can bind and retire, and can do nothing else to a binding", async () => {
  await bindThen(
    "alias-privilege",
    "ceo@example.com",
    VICTIM,
    "mutation.alias.privilege.bind",
  );
  const client = await adminPool.connect();
  try {
    await client.query("BEGIN");
    await client.query('SET LOCAL ROLE "aaliyah_memory_mutator"');
    // Column-level UPDATE: the three retirement columns, and nothing else.
    await assert.rejects(
      () =>
        client.query(
          `UPDATE memory_alias_bindings SET normalized_alias = 'other@x.com'
            WHERE tenant_id = $1`,
          [TENANT],
        ),
      /permission denied/,
    );
  } finally {
    await client.query("ROLLBACK").catch(() => undefined);
    client.release();
  }

  const second = await adminPool.connect();
  try {
    await second.query("BEGIN");
    await second.query('SET LOCAL ROLE "aaliyah_memory_mutator"');
    await assert.rejects(
      () =>
        second.query(`DELETE FROM memory_alias_bindings WHERE tenant_id = $1`, [
          TENANT,
        ]),
      /permission denied/,
    );
  } finally {
    await second.query("ROLLBACK").catch(() => undefined);
    second.release();
  }

  const reader = await adminPool.connect();
  try {
    await reader.query("BEGIN");
    await reader.query('SET LOCAL ROLE "aaliyah_memory_reader"');
    // The matcher names the TABLE deliberately. `/permission denied/` alone
    // also matches "permission denied for sequence
    // memory_alias_bindings_id_seq", which the reader is refused anyway — so a
    // grant of INSERT on the table would leave the loose matcher green and the
    // control unkilled.
    await assert.rejects(
      () =>
        reader.query(
          `INSERT INTO memory_alias_bindings (tenant_id, workspace_id,
             principal_id, user_id, cross_workspace_policy, scope_key, alias_id,
             normalized_alias, skeleton, skeleton_algorithm,
             normalization_profile, canonical_participant_id,
             registrable_domain, script_code, restriction_level,
             subject_participant_id, source_evidence_ref, source_evidence_digest,
             observed_at, fresh_until, authorization_id, mutation_receipt_id,
             bound_at, payload)
           VALUES ($1,$2,'p','u','workspace_isolated',$2,'alias-reader',
                   'a@x.com','a@x.com','sk','np','part','x.com','Latn',
                   'ascii_only','part','identity:x/y',$3, now(),
                   now() + interval '1 hour','auth-x','m.x', now(),
                   '{}'::jsonb)`,
          [TENANT, SCOPE.workspaceId, EVIDENCE_DIGEST],
        ),
      /permission denied for table memory_alias_bindings/,
    );
  } finally {
    await reader.query("ROLLBACK").catch(() => undefined);
    reader.release();
  }
});

test("a read-back pool identical to the mutation pool is refused at construction", () => {
  assert.throws(
    () => createPostgresAliasRegistryStore(writePool, writePool),
    /post-commit read-back pool must be independent/,
  );
});

test("a role option that is not a plain identifier is refused at construction", () => {
  assert.throws(
    () =>
      createPostgresAliasRegistryStore(writePool, readPool, {
        mutationRole: 'evil"; DROP TABLE memory_alias_bindings; --',
      }),
    /mutationRole is not a valid role identifier/,
  );
  assert.throws(
    () =>
      createPostgresAliasRegistryStore(writePool, readPool, {
        readBackRole: "Not-A-Role",
      }),
    /readBackRole is not a valid role identifier/,
  );
});

test("an alias whose HOST is malformed is refused as not email shaped", async () => {
  const prepared = await prepareAssign({
    aliasId: "alias-bad-host",
    observedAlias: "ceo@-bad.example",
    participantId: VICTIM,
    // The producer must claim a well-formed A-label; contracts admits nothing
    // else. Core extracts the real host and refuses it.
    aliasOverrides: { registrableDomain: "example.com" },
  });
  const result = await store().assignAlias({
    actor: SCOPE,
    authorizationId: prepared.receipt.authorizationId,
    participantRecordId: VICTIM,
    alias: prepared.alias,
    evidence: prepared.evidence,
    proposedContent: prepared.content,
    mutationReceiptId: "mutation.alias.badhost",
  });
  assert.equal(result.rejection, "alias_not_email_shaped");
});

test("one alias id cannot name two active bindings in a scope", async () => {
  await bindThen(
    "alias-duplicate-id",
    "ceo@example.com",
    VICTIM,
    "mutation.alias.dupid.a",
  );
  const second = await prepareAssign({
    aliasId: "alias-duplicate-id",
    observedAlias: "ops@example.com",
    participantId: ATTACKER,
  });
  const result = await store().assignAlias({
    actor: SCOPE,
    authorizationId: second.receipt.authorizationId,
    participantRecordId: ATTACKER,
    alias: second.alias,
    evidence: second.evidence,
    proposedContent: second.content,
    mutationReceiptId: "mutation.alias.dupid.b",
  });
  assert.equal(result.verified, false);
  assert.equal(result.rejection, "alias_already_bound");
  assert.equal(await activeBindings(), 1);
});

// ---------------------------------------------------------------------------
// The read-back. No read-back agreement, no verified success.
// ---------------------------------------------------------------------------

test("a read-back whose CONTENT matches but whose post-state does not is UNKNOWN", async () => {
  const prepared = await prepareAssign({
    aliasId: "alias-readback-head",
    observedAlias: "ceo@example.com",
    participantId: VICTIM,
  });
  // The shadow holds a record whose content digests to EXACTLY the proposed
  // content — so the divergence branch cannot fire — but whose version is not
  // the version that was written.
  const digest = memoryContentDigest(prepared.content);
  await adminPool.query(
    `INSERT INTO ${SHADOW_RECORD_SCHEMA}.memory_record_versions
       (tenant_id, workspace_id, principal_id, user_id, record_id, version,
        state, content_digest, predecessor_digest, authorization_id,
        mutation_receipt_id, payload)
     VALUES ($1,$2,$3,$4,$5,1,'active',$6,NULL,$7,$8,$9)`,
    [
      SCOPE.tenantId,
      SCOPE.workspaceId,
      SCOPE.principalId,
      SCOPE.userId,
      VICTIM,
      digest,
      "genesis-000000000000000000000",
      "mutation.genesis",
      JSON.stringify({
        schemaVersion: MEMORY_RECORD_VERSION_SCHEMA_VERSION,
        recordId: VICTIM,
        version: 1,
        state: "active",
        scope: SCOPE,
        content: prepared.content,
        contentDigest: digest,
        predecessorDigest: null,
        authorizationId: "genesis-000000000000000000000",
        mutationReceiptId: "mutation.genesis",
        createdAt: isoOffset(-120_000),
      }),
    ],
  );
  const result = await store({
    readBack: shadowRecordPool,
  }).assignAlias({
    actor: SCOPE,
    authorizationId: prepared.receipt.authorizationId,
    participantRecordId: VICTIM,
    alias: prepared.alias,
    evidence: prepared.evidence,
    proposedContent: prepared.content,
    mutationReceiptId: "mutation.alias.readbackhead",
  });
  assert.equal(result.verified, false);
  assert.equal(result.rejection, "unknown_outcome");
  assert.equal(result.receipt?.outcome.status, "UNKNOWN_PENDING_RECONCILIATION");
  // The mutation DID commit. Unknown is the honest answer, and it is durable.
  assert.equal(await activeBindings(), 1);
  assert.deepEqual(await receiptStatuses("mutation.alias.readbackhead"), [
    { phase: "pending", status: "UNKNOWN_PENDING_RECONCILIATION" },
    { phase: "terminal", status: "UNKNOWN_PENDING_RECONCILIATION" },
  ]);
});

test("a read-back whose CONTENT diverges from what was committed is not success", async () => {
  const prepared = await prepareAssign({
    aliasId: "alias-readback-diverged",
    observedAlias: "ceo@example.com",
    participantId: VICTIM,
  });
  // The shadow holds a record whose content is NOT the content that was
  // committed, so the digest recomputed from the bytes that came BACK differs
  // from the digest of the bytes that went out.
  const otherContent = { participant: VICTIM, generation: 41 };
  const otherDigest = memoryContentDigest(otherContent);
  assert.notEqual(otherDigest, memoryContentDigest(prepared.content));
  await adminPool.query(
    `INSERT INTO ${SHADOW_RECORD_SCHEMA}.memory_record_versions
       (tenant_id, workspace_id, principal_id, user_id, record_id, version,
        state, content_digest, predecessor_digest, authorization_id,
        mutation_receipt_id, payload)
     VALUES ($1,$2,$3,$4,$5,2,'active',$6,$10,$7,$8,$9)`,
    [
      SCOPE.tenantId,
      SCOPE.workspaceId,
      SCOPE.principalId,
      SCOPE.userId,
      VICTIM,
      otherDigest,
      "genesis-000000000000000000000",
      "mutation.genesis",
      JSON.stringify({
        schemaVersion: MEMORY_RECORD_VERSION_SCHEMA_VERSION,
        recordId: VICTIM,
        version: 2,
        state: "active",
        scope: SCOPE,
        content: otherContent,
        contentDigest: otherDigest,
        predecessorDigest: prepared.genesis,
        authorizationId: "genesis-000000000000000000000",
        mutationReceiptId: "mutation.genesis",
        createdAt: isoOffset(-120_000),
      }),
      prepared.genesis,
    ],
  );
  const result = await store({ readBack: shadowRecordPool }).assignAlias({
    actor: SCOPE,
    authorizationId: prepared.receipt.authorizationId,
    participantRecordId: VICTIM,
    alias: prepared.alias,
    evidence: prepared.evidence,
    proposedContent: prepared.content,
    mutationReceiptId: "mutation.alias.readbackdiverged",
  });
  assert.equal(result.verified, false);
  assert.equal(result.rejection, "read_back_diverged");
  assert.equal(result.receipt?.outcome.status, "COMMITTED_READ_BACK_DIVERGED");
  assert.deepEqual(await receiptStatuses("mutation.alias.readbackdiverged"), [
    { phase: "pending", status: "UNKNOWN_PENDING_RECONCILIATION" },
    { phase: "terminal", status: "COMMITTED_READ_BACK_DIVERGED" },
  ]);
});

test("a record head that advanced while the REGISTRY did not is UNKNOWN, not success", async () => {
  const prepared = await prepareAssign({
    aliasId: "alias-readback-binding",
    observedAlias: "ceo@example.com",
    participantId: VICTIM,
  });
  // The shadow's binding table is EMPTY and resolves first, so the read-back
  // sees a correctly advanced record and NO binding. Reporting that as a
  // successful alias assignment is precisely the defect this file exists to
  // prevent.
  const result = await store({
    readBack: shadowBindingPool,
  }).assignAlias({
    actor: SCOPE,
    authorizationId: prepared.receipt.authorizationId,
    participantRecordId: VICTIM,
    alias: prepared.alias,
    evidence: prepared.evidence,
    proposedContent: prepared.content,
    mutationReceiptId: "mutation.alias.readbackbinding",
  });
  assert.equal(result.verified, false);
  assert.equal(result.rejection, "unknown_outcome");
  assert.equal(result.receipt?.outcome.status, "UNKNOWN_PENDING_RECONCILIATION");
});

test("a binding row whose columns disagree with its payload is refused, not reconciled", async () => {
  // Only possible on a relation without migration 031's CHECK constraints.
  await adminPool.query(
    `INSERT INTO ${UNCHECKED_SCHEMA}.memory_alias_bindings
       (tenant_id, workspace_id, principal_id, user_id,
        cross_workspace_policy, scope_key, alias_id, normalized_alias,
        skeleton, skeleton_algorithm, normalization_profile,
        canonical_participant_id, registrable_domain, script_code,
        restriction_level, subject_participant_id, source_evidence_ref,
        source_evidence_digest, observed_at, fresh_until,
        authorization_id, mutation_receipt_id, bound_at, payload)
     VALUES ($1,$2,$3,$4,'workspace_isolated',$2,'alias-unchecked',
             'ceo@example.com','ceo@example.com',
             'aaliyah.alias-skeleton/core-subset-v1',
             'aaliyah.alias-normalization/core-v1',
             $5,'example.com','Latn','ascii_only',$5,
             'identity:verification/participant-record',$6,
             now(), now() + interval '1 hour',
             'auth-alias-00000000000000000000','mutation.unchecked',
             now(), $7::jsonb)`,
    [
      SCOPE.tenantId,
      SCOPE.workspaceId,
      SCOPE.principalId,
      SCOPE.userId,
      VICTIM,
      EVIDENCE_DIGEST,
      JSON.stringify({
        schemaVersion: `${WAVE1_TRUSTED_MEMORY_CONTRACT_VERSION}#alias-binding`,
        aliasId: "alias-unchecked",
        scope: SCOPE,
        crossWorkspacePolicy: "workspace_isolated",
        scopeKey: SCOPE.workspaceId,
        // THE LIE: the payload names a different participant than the column.
        canonicalParticipantId: ATTACKER,
        normalizedAlias: "ceo@example.com",
        normalizationProfile: "aaliyah.alias-normalization/core-v1",
        skeleton: "ceo@example.com",
        skeletonAlgorithm: "aaliyah.alias-skeleton/core-subset-v1",
        registrableDomain: "example.com",
        scriptCode: "Latn",
        restrictionLevel: "ascii_only",
        subjectParticipantId: VICTIM,
        sourceEvidenceRef: "identity:verification/participant-record",
        sourceEvidenceDigest: EVIDENCE_DIGEST,
        observedAt: isoOffset(-60_000),
        freshUntil: isoOffset(3_600_000),
        authorizationId: "auth-alias-00000000000000000000",
        mutationReceiptId: "mutation.unchecked",
        boundAt: isoOffset(-1000),
        claimed: aliasIdentity({
          aliasId: "alias-unchecked",
          observedAlias: "ceo@example.com",
          participantId: VICTIM,
          evidence: evidenceFor(VICTIM),
        }),
      }),
    ],
  );
  await assert.rejects(
    () =>
      store({ readBack: uncheckedPool }).readAliasBinding(
        SCOPE,
        "alias-unchecked",
      ),
    /binding row and payload mismatch/,
  );
});

test("every jsonb-to-column binding CHECK on the registry refuses a row that lies", async () => {
  // One row, one lie at a time, and the NAME of the constraint that must
  // refuse it. A CHECK nobody can trip is not a control.
  const cases: ReadonlyArray<{
    constraint: string;
    corrupt: (payload: Record<string, unknown>) => void;
  }> = [
    {
      constraint: "memory_alias_bindings_tenant_binding",
      corrupt: (p) => {
        (p.scope as Record<string, string>).tenantId = "tenant-elsewhere";
      },
    },
    {
      constraint: "memory_alias_bindings_workspace_binding",
      corrupt: (p) => {
        (p.scope as Record<string, string>).workspaceId = "workspace-elsewhere";
      },
    },
    {
      constraint: "memory_alias_bindings_principal_binding",
      corrupt: (p) => {
        (p.scope as Record<string, string>).principalId = "principal-elsewhere";
      },
    },
    {
      constraint: "memory_alias_bindings_user_binding",
      corrupt: (p) => {
        (p.scope as Record<string, string>).userId = "user-elsewhere";
      },
    },
    {
      constraint: "memory_alias_bindings_alias_id_binding",
      corrupt: (p) => {
        p.aliasId = "alias-elsewhere";
      },
    },
    {
      constraint: "memory_alias_bindings_normalized_binding",
      corrupt: (p) => {
        p.normalizedAlias = "elsewhere@example.com";
      },
    },
    {
      constraint: "memory_alias_bindings_skeleton_binding",
      corrupt: (p) => {
        p.skeleton = "elsewhere@example.com";
      },
    },
    {
      constraint: "memory_alias_bindings_participant_binding",
      corrupt: (p) => {
        p.canonicalParticipantId = ATTACKER;
      },
    },
    {
      constraint: "memory_alias_bindings_subject_binding",
      corrupt: (p) => {
        p.subjectParticipantId = ATTACKER;
      },
    },
    {
      constraint: "memory_alias_bindings_policy_binding",
      corrupt: (p) => {
        p.crossWorkspacePolicy = "tenant_exclusive";
      },
    },
    {
      constraint: "memory_alias_bindings_scope_key_binding",
      corrupt: (p) => {
        p.scopeKey = "*";
      },
    },
    {
      constraint: "memory_alias_bindings_authorization_binding",
      corrupt: (p) => {
        p.authorizationId = "auth-elsewhere";
      },
    },
    {
      constraint: "memory_alias_bindings_mutation_receipt_binding",
      corrupt: (p) => {
        p.mutationReceiptId = "mutation.elsewhere";
      },
    },
  ];

  for (const [index, testCase] of cases.entries()) {
    const payload: Record<string, unknown> = {
      scope: { ...SCOPE },
      aliasId: `alias-check-${index}`,
      normalizedAlias: "ceo@example.com",
      skeleton: "ceo@example.com",
      canonicalParticipantId: VICTIM,
      subjectParticipantId: VICTIM,
      crossWorkspacePolicy: "workspace_isolated",
      scopeKey: SCOPE.workspaceId,
      authorizationId: "auth-alias-00000000000000000000",
      mutationReceiptId: "mutation.check",
    };
    testCase.corrupt(payload);
    await assert.rejects(
      () =>
        adminPool.query(
          `INSERT INTO memory_alias_bindings
             (tenant_id, workspace_id, principal_id, user_id,
              cross_workspace_policy, scope_key, alias_id, normalized_alias,
              skeleton, skeleton_algorithm, normalization_profile,
              canonical_participant_id, registrable_domain, script_code,
              restriction_level, subject_participant_id, source_evidence_ref,
              source_evidence_digest, observed_at, fresh_until,
              authorization_id, mutation_receipt_id, bound_at, payload)
           VALUES ($1,$2,$3,$4,'workspace_isolated',$2,$5,'ceo@example.com',
                   'ceo@example.com','sk','np',$6,'example.com','Latn',
                   'ascii_only',$6,'identity:x/y',$7,
                   now(), now() + interval '1 hour',
                   'auth-alias-00000000000000000000','mutation.check',
                   now(), $8::jsonb)`,
          [
            SCOPE.tenantId,
            SCOPE.workspaceId,
            SCOPE.principalId,
            SCOPE.userId,
            `alias-check-${index}`,
            VICTIM,
            EVIDENCE_DIGEST,
            JSON.stringify(payload),
          ],
        ),
      new RegExp(testCase.constraint),
      `${testCase.constraint} must refuse a payload that disagrees with its column`,
    );
  }
});

test("a malformed request never reaches the database", async () => {
  const result = await store().assignAlias({
    actor: SCOPE,
    authorizationId: nextAuthorizationId(),
    participantRecordId: "NOT A CANONICAL ID",
    alias: {},
    evidence: {},
    proposedContent: {},
    mutationReceiptId: "mutation.alias.badrequest",
  });
  assert.equal(result.rejection, "request_malformed");
  assert.equal(result.receipt, null);
});

// ---------------------------------------------------------------------------
// W1.3 Part B2, Part D half — a binding is an APPENDED FACT and needs the same
// witness a record version does.
//
// The same defect that let the least-privilege mutator forge a record chain
// applies here: the alias registry's uniqueness indexes decide races, but
// nothing tied a binding row to an authorization that was actually spent. A
// forged binding would have been globally unique and completely unauthorized.
// ---------------------------------------------------------------------------

test("Part D a binding with no consumed authorization behind it is refused", async () => {
  await assert.rejects(
    () => insertRawBinding(),
    /no consumed authorization witnesses this binding/,
  );
  assert.equal(await activeBindings(), 0);
});

test("Part D the mutation role cannot forge a binding either", async () => {
  const client = await adminPool.connect();
  try {
    await client.query("BEGIN");
    await client.query('SET LOCAL ROLE "aaliyah_memory_mutator"');
    await assert.rejects(
      () =>
        client.query(
          `INSERT INTO memory_alias_bindings
             (tenant_id, workspace_id, principal_id, user_id,
              cross_workspace_policy, scope_key, alias_id, normalized_alias,
              skeleton, skeleton_algorithm, normalization_profile,
              canonical_participant_id, registrable_domain, script_code,
              restriction_level, subject_participant_id, source_evidence_ref,
              source_evidence_digest, observed_at, fresh_until,
              authorization_id, mutation_receipt_id, bound_at, payload)
           VALUES ($1,$2,'p','u','workspace_isolated',$2,'alias-forged',
                   'ceo@example.com','ceo@example.com','sk','np',$4,
                   'example.com','Latn','ascii_only',$4,'identity:x/y',$3,
                   now(), now() + interval '1 hour',
                   'auth-does-not-exist-0000000','mutation.forged', now(), $5)`,
          [
            TENANT,
            SCOPE.workspaceId,
            EVIDENCE_DIGEST,
            VICTIM,
            JSON.stringify({
              scope: {
                tenantId: TENANT,
                workspaceId: SCOPE.workspaceId,
                principalId: "p",
                userId: "u",
              },
              aliasId: "alias-forged",
              normalizedAlias: "ceo@example.com",
              skeleton: "ceo@example.com",
              canonicalParticipantId: VICTIM,
              subjectParticipantId: VICTIM,
              crossWorkspacePolicy: "workspace_isolated",
              scopeKey: SCOPE.workspaceId,
              authorizationId: "auth-does-not-exist-0000000",
              mutationReceiptId: "mutation.forged",
            }),
          ],
        ),
      /no consumed authorization witnesses this binding/,
    );
    await client.query("ROLLBACK");
  } finally {
    client.release();
  }
  assert.equal(await activeBindings(), 0);
});

test("Part D a WITNESSED raw binding is accepted, so the guard is not a blanket refusal", async () => {
  // Without this the guard could be a statement that refuses everything, and
  // every assertion above would still pass.
  await witnessAppend({
    authorizationId: "auth-alias-00000000000000000000",
    mutationReceiptId: "mutation.raw",
    targetRecordId: VICTIM,
  });
  await insertRawBinding();
  assert.equal(await activeBindings(), 1);
});

test("Part D a retirement with no consumed authorization behind it is refused", async () => {
  const bound = await bindThen(
    "alias-retire-guard",
    "ceo@example.com",
    VICTIM,
    "mutation.alias.retireguard.bind",
  );
  assert.equal(typeof bound.headDigest, "string");
  assert.equal(await activeBindings(), 1);
  await assert.rejects(
    () =>
      adminPool.query(
        `UPDATE memory_alias_bindings
            SET removed_at = now(),
                removed_by_mutation_receipt_id = 'mutation.forged.retire',
                removed_authorization_id = 'auth-does-not-exist-0000000'
          WHERE alias_id = $1`,
        ["alias-retire-guard"],
      ),
    /no consumed authorization witnesses this retirement/,
  );
  assert.equal(await activeBindings(), 1);
});

test("Part D the retirement guard still reports the more specific violation first", async () => {
  // The witness check is deliberately LAST in the trigger, so a retirement
  // that also rewrites the binding is still refused as a rewrite. Ordering the
  // checks the other way would hide every message the earlier controls own.
  await bindThen(
    "alias-retire-order",
    "ceo@example.com",
    VICTIM,
    "mutation.alias.retireorder.bind",
  );
  await assert.rejects(
    () =>
      adminPool.query(
        `UPDATE memory_alias_bindings
            SET removed_at = now(),
                removed_by_mutation_receipt_id = 'mutation.forged.retire',
                removed_authorization_id = 'auth-does-not-exist-0000000',
                canonical_participant_id = $2
          WHERE alias_id = $1`,
        ["alias-retire-order", ATTACKER],
      ),
    /retirement may not rewrite a binding/,
  );
});

// ---------------------------------------------------------------------------
// W1.3 Part B3 — ONE CONSUMED AUTHORIZATION, ONE BINDING MUTATION.
//
// Part D gave a binding and a retirement a WITNESS. It did not bound how many
// of either one consumed nonce could witness, because this table carried no
// uniqueness on `mutation_receipt_id` OR on `removed_by_mutation_receipt_id`.
// One approval therefore bound an unbounded number of aliases, retired an
// unbounded number of bindings, and — because the spend can be claimed from
// two different columns — did one of each.
// ---------------------------------------------------------------------------

/** Bind a raw alias under an explicit approval, with everything else honest. */
async function rawBindUnder(input: {
  aliasId: string;
  alias: string;
  authorizationId: string;
  mutationReceiptId: string;
}): Promise<void> {
  await insertRawBinding(
    {
      alias_id: input.aliasId,
      normalized_alias: input.alias,
      skeleton: input.alias,
      authorization_id: input.authorizationId,
      mutation_receipt_id: input.mutationReceiptId,
    },
    {
      normalizedAlias: input.alias,
      skeleton: input.alias,
      authorizationId: input.authorizationId,
      mutationReceiptId: input.mutationReceiptId,
    },
  );
}

/** Retire a binding directly, naming the approval it claims to have spent. */
async function rawRetire(input: {
  aliasId: string;
  authorizationId: string;
  mutationReceiptId: string;
}): Promise<void> {
  await adminPool.query(
    `UPDATE memory_alias_bindings
        SET removed_at = now(),
            removed_by_mutation_receipt_id = $2,
            removed_authorization_id = $3
      WHERE alias_id = $1 AND removed_at IS NULL`,
    [input.aliasId, input.mutationReceiptId, input.authorizationId],
  );
}

test("B3 one consumed authorization binds exactly ONE alias", async () => {
  await witnessAppend({
    authorizationId: "b3-bind-00000000000000000001",
    mutationReceiptId: "mutation.b3.bind",
    targetRecordId: VICTIM,
  });
  // The FIRST binding under this approval is legitimate and must land, or the
  // refusal below would be indistinguishable from a blanket one.
  await rawBindUnder({
    aliasId: "alias-b3-one",
    alias: "ceo@example.com",
    authorizationId: "b3-bind-00000000000000000001",
    mutationReceiptId: "mutation.b3.bind",
  });
  assert.equal(await activeBindings(), 1);
  // A SECOND alias — different alias id, different normalized form, different
  // skeleton, so none of the 031 exclusions can be what refuses it — charged
  // to the same single approval.
  await assert.rejects(
    () =>
      rawBindUnder({
        aliasId: "alias-b3-two",
        alias: "chair@example.com",
        authorizationId: "b3-bind-00000000000000000001",
        mutationReceiptId: "mutation.b3.bind",
      }),
    /duplicate key value violates unique constraint "memory_alias_bindings_receipt_unique"/,
  );
  assert.equal(await activeBindings(), 1);
});

test("B3 one consumed authorization retires exactly ONE binding", async () => {
  for (const [index, alias] of ["ceo@example.com", "chair@example.com"].entries()) {
    await witnessAppend({
      authorizationId: `b3-retire-bind-${index}`.padEnd(28, "0"),
      mutationReceiptId: `mutation.b3.retire.bind.${index}`,
      targetRecordId: VICTIM,
    });
    await rawBindUnder({
      aliasId: `alias-b3-retire-${index}`,
      alias,
      authorizationId: `b3-retire-bind-${index}`.padEnd(28, "0"),
      mutationReceiptId: `mutation.b3.retire.bind.${index}`,
    });
  }
  assert.equal(await activeBindings(), 2);
  await witnessAppend({
    authorizationId: "b3-retire-0000000000000000001",
    mutationReceiptId: "mutation.b3.retire",
    targetRecordId: VICTIM,
    action: "remove_alias",
  });
  await rawRetire({
    aliasId: "alias-b3-retire-0",
    authorizationId: "b3-retire-0000000000000000001",
    mutationReceiptId: "mutation.b3.retire",
  });
  assert.equal(await activeBindings(), 1);
  await assert.rejects(
    () =>
      rawRetire({
        aliasId: "alias-b3-retire-1",
        authorizationId: "b3-retire-0000000000000000001",
        mutationReceiptId: "mutation.b3.retire",
      }),
    /duplicate key value violates unique constraint "memory_alias_bindings_removal_receipt_unique"/,
  );
  assert.equal(await activeBindings(), 1);
});

test("B3 one consumed authorization cannot both bind one alias and retire another", async () => {
  // THE CASE NO B-TREE INDEX CAN EXPRESS. The spend is claimed from TWO
  // different columns of two different rows, so the two unique indexes above
  // never collide and the exclusion has to be stated in the guards.
  await witnessAppend({
    authorizationId: "b3-cross-existing-000000000001",
    mutationReceiptId: "mutation.b3.cross.existing",
    targetRecordId: VICTIM,
  });
  await rawBindUnder({
    aliasId: "alias-b3-cross-existing",
    alias: "chair@example.com",
    authorizationId: "b3-cross-existing-000000000001",
    mutationReceiptId: "mutation.b3.cross.existing",
  });
  await witnessAppend({
    authorizationId: "b3-cross-0000000000000000001",
    mutationReceiptId: "mutation.b3.cross",
    targetRecordId: VICTIM,
  });
  await rawBindUnder({
    aliasId: "alias-b3-cross-bound",
    alias: "ceo@example.com",
    authorizationId: "b3-cross-0000000000000000001",
    mutationReceiptId: "mutation.b3.cross",
  });
  assert.equal(await activeBindings(), 2);
  // The same approval, already spent on a bind, reaching for a retirement.
  await assert.rejects(
    () =>
      rawRetire({
        aliasId: "alias-b3-cross-existing",
        authorizationId: "b3-cross-0000000000000000001",
        mutationReceiptId: "mutation.b3.cross",
      }),
    /this authorization has already been spent on another binding/,
  );
  assert.equal(await activeBindings(), 2);
});

test("B3 one consumed authorization cannot both retire one alias and bind another", async () => {
  // The mirror of the case above, and a SEPARATE control: the insert guard has
  // to look at the retirement column just as the retirement guard looks at the
  // bind column. Deleting either one leaves the other direction open.
  await witnessAppend({
    authorizationId: "b3-mirror-bound-00000000001",
    mutationReceiptId: "mutation.b3.mirror.bound",
    targetRecordId: VICTIM,
  });
  await rawBindUnder({
    aliasId: "alias-b3-mirror-bound",
    alias: "chair@example.com",
    authorizationId: "b3-mirror-bound-00000000001",
    mutationReceiptId: "mutation.b3.mirror.bound",
  });
  await witnessAppend({
    authorizationId: "b3-mirror-000000000000000001",
    mutationReceiptId: "mutation.b3.mirror",
    targetRecordId: VICTIM,
    action: "remove_alias",
  });
  await rawRetire({
    aliasId: "alias-b3-mirror-bound",
    authorizationId: "b3-mirror-000000000000000001",
    mutationReceiptId: "mutation.b3.mirror",
  });
  assert.equal(await activeBindings(), 0);
  await assert.rejects(
    () =>
      rawBindUnder({
        aliasId: "alias-b3-mirror-new",
        alias: "ceo@example.com",
        authorizationId: "b3-mirror-000000000000000001",
        mutationReceiptId: "mutation.b3.mirror",
      }),
    /this authorization has already been spent on another binding/,
  );
  assert.equal(await activeBindings(), 0);
});

test("B3 a binding witnessed by a nonce consumed after it lapsed is refused", async () => {
  // The window half of the finding, on the alias path. The approval is real,
  // it names this tenant, and it was spent — hours after it stopped being
  // valid.
  const authorizationId = "b3-alias-lapsed-000000000001";
  const bindingDigest = memoryContentDigest(authorizationId);
  await runAs(
    "aaliyah_memory_issuer",
    `INSERT INTO memory_authorization_nonces
       (tenant_id, workspace_id, binding_digest, authorization_id, action,
        target_record_id, issued_at, expires_at)
     VALUES ($1,$2,$3,$4,'assign_alias',$5,
             now() - interval '2 hours', now() - interval '1 hour')`,
    [TENANT, SCOPE.workspaceId, bindingDigest, authorizationId, VICTIM],
  );
  await runAs(
    "aaliyah_memory_mutator",
    `UPDATE memory_authorization_nonces
        SET consumed_at = now(), consumed_by_mutation_receipt_id = $2
      WHERE binding_digest = $1 AND consumed_at IS NULL`,
    [bindingDigest, "mutation.b3.alias.lapsed"],
  );
  await assert.rejects(
    () =>
      rawBindUnder({
        aliasId: "alias-b3-lapsed",
        alias: "ceo@example.com",
        authorizationId,
        mutationReceiptId: "mutation.b3.alias.lapsed",
      }),
    /no consumed authorization witnesses this binding/,
  );
  assert.equal(await activeBindings(), 0);
});
