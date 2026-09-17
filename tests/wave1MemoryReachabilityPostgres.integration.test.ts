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
  MEMORY_ALIAS_NORMALIZATION_VERSION,
  MEMORY_CONFUSABLE_SKELETON_ALGORITHM,
  CanonicalAliasIdentitySchema,
  Wave1SubjectBoundEvidenceSchema,
  type CanonicalAliasIdentity,
} from "@aaliyah/contracts/v1";

import { aliasAssignmentDigest } from "../src/application/memory/wave1AliasRegistry";
import {
  aliasRestrictionLevel,
  coreAliasSkeleton,
  coreNormalizeAlias,
  determineAliasScript,
  isInternationalizedDomain,
  splitEmailAlias,
} from "../src/application/memory/wave1AliasSkeleton";
import { createPostgresAliasRegistryStore } from "../src/persistence/postgres/wave1AliasRegistryStore";

import { runEaPipeline } from "../src/application/executive/eaPipeline";
import {
  MEMORY_IDENTITY_MERGE_ORDER_SCHEMA_VERSION,
  MEMORY_IDENTITY_SPLIT_ORDER_SCHEMA_VERSION,
} from "../src/application/memory/wave1MemoryIdentity";
import {
  MemoryCanonicalResolutionFailed,
  createWave1MemoryService,
} from "../src/application/memory/wave1MemoryService";
import { memoryContentDigest } from "../src/application/memory/wave1TrustedMemory";
import { runMailMigrations } from "../src/persistence/postgres/migrations";
import { createPostgresWave1MemoryService } from "../src/persistence/postgres/wave1IdentityGraphStore";
import { createPostgresTrustedMemoryStore } from "../src/persistence/postgres/wave1TrustedMemoryStore";
import {
  lockSharedMemoryTables,
  type SharedTableLock,
} from "./support/sharedMemoryTables";

/**
 * W1.3 REACHABILITY — IS THE AUTHORITATIVE STORE ACTUALLY USED?
 *
 * Every control in the trusted-memory store was real and proven, and until
 * this file nothing in Core called any of it: the only callers were tests. A
 * store with no production consumer cannot be wrong in production because it
 * does not run there, and calling it a completed capability would be reporting
 * the tests rather than the system.
 *
 * These drive the REAL chain — executive email -> sender alias -> identity ->
 * canonical identity -> authoritative trusted-memory read -> the pipeline that
 * consumes it — against a live PostgreSQL, through the SAME composition
 * function `src/server.ts` calls at boot. Nothing here builds a convenient
 * stand-in for the store.
 */

const DB_URL =
  process.env.AALIYAH_TEST_DATABASE_URL ??
  "postgres://postgres:test@127.0.0.1:54329/aaliyah_test";

const SCOPE: MemoryScope = {
  tenantId: "tenant-reach",
  workspaceId: "workspace-reach",
  principalId: "principal-reach",
  userId: "user-reach",
};

const CONTACT = "record-reach-contact";
const CONTACT_ALIAS = "dana@example.com";

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
  await adminPool.query(
    `INSERT INTO memory_alias_tenant_policy
       (tenant_id, cross_workspace_policy, set_by_actor_id, policy_version)
     VALUES ($1, 'workspace_isolated', 'actor.memory-steward', 'alias-policy/v1')
     ON CONFLICT DO NOTHING`,
    [SCOPE.tenantId],
  );
});

after(async () => {
  await readPool.end();
  await writePool.end();
  await sharedTableLock.release();
  await adminPool.end();
});

beforeEach(async () => {
  await adminPool.query(
    `TRUNCATE memory_reconciliations,
              memory_identity_edges,
              memory_alias_bindings,
              memory_record_versions,
              memory_authorization_receipts,
              memory_authorization_nonces,
              memory_mutation_receipts,
              memory_tombstones
     RESTART IDENTITY`,
  );
  authCounter = 0;
});

/** Exactly what `src/server.ts` builds at boot. */
function memoryService() {
  return createPostgresWave1MemoryService(writePool, readPool);
}

function isoOffset(ms: number): string {
  return new Date(Date.now() + ms).toISOString();
}

function authorization(input: {
  action: MemoryAction;
  targetRecordId: string;
  expectedHead: MemoryExpectedHead;
  proposedContent?: unknown;
  /** The alias path binds a COMPOSED digest, not a digest of the record. */
  proposedContentDigest?: string;
}): MemoryAuthorizationReceipt {
  authCounter += 1;
  const authorizationId = `reach-auth-${String(authCounter).padStart(16, "0")}`;
  const proposedContentDigest =
    input.proposedContentDigest ?? memoryContentDigest(input.proposedContent);
  const bindingDigest = memoryAuthorizationNonce({
    bindingSchemaVersion: MEMORY_AUTHORIZATION_NONCE_SCHEMA_VERSION,
    authorizationId,
    action: input.action,
    scope: SCOPE,
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
    scope: SCOPE,
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

/** Create a record through the real protocol. */
async function createRecord(recordId: string, content: unknown): Promise<string> {
  const receipt = await issue(
    authorization({
      action: "create",
      targetRecordId: recordId,
      expectedHead: { kind: "no_prior_version" },
      proposedContent: content,
    }),
  );
  const result = await createPostgresTrustedMemoryStore(
    writePool,
    readPool,
  ).create({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId,
    proposedContent: content,
    mutationReceiptId: `mutation.reach.create.${recordId}`,
  });
  assert.equal(result.rejection, null);
  assert.equal(result.verified, true);
  return memoryContentDigest(content);
}

async function mergeInto(input: {
  absorbed: string;
  survivor: string;
  mutationReceiptId: string;
}) {
  // Read the head rather than taking it on faith: an alias binding advances
  // the participant record, so hard-coding version 1 here made the test lie
  // about what it was merging.
  const head = await createPostgresTrustedMemoryStore(
    writePool,
    readPool,
  ).readHead(SCOPE, input.absorbed);
  assert.notEqual(head, null);
  const order = {
    schemaVersion: MEMORY_IDENTITY_MERGE_ORDER_SCHEMA_VERSION,
    reason: "duplicate_participant" as const,
    reasonEvidenceRef: "matter:identity-merge/reach",
    survivorRecordId: input.survivor,
  };
  const receipt = await issue(
    authorization({
      action: "merge_identity",
      targetRecordId: input.absorbed,
      expectedHead: {
        kind: "version",
        version: head!.version,
        contentDigest: head!.contentDigest,
      },
      proposedContent: order,
    }),
  );
  const result = await createPostgresTrustedMemoryStore(
    writePool,
    readPool,
  ).mergeIdentity({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: input.absorbed,
    proposedContent: order,
    mutationReceiptId: input.mutationReceiptId,
  });
  assert.equal(result.rejection, null);
  assert.equal(result.verified, true);
}

/** Bind an alias straight into the registry table, under the issuer role. */
/**
 * Bind an alias through the REAL alias registry, not by inserting a row.
 *
 * A hand-built binding row was the first attempt and it was wrong twice over:
 * the registry's guards refused it (no consumed authorization, no valid
 * payload), and even had it landed, the alias hop of this chain would have
 * been a fixture rather than the thing under test. `assignAlias` is what
 * production calls, so it is what this calls.
 */
async function bindAlias(
  alias: string,
  canonicalParticipantId: string,
  /**
   * The record content the binding ADVANCES the participant to. An alias
   * assignment is a mutation on the participant record, not a side table, so
   * it writes a successor version like any other authorized change.
   */
  successor: unknown = { participant: canonicalParticipantId, generation: 2 },
): Promise<void> {
  const head = await createPostgresTrustedMemoryStore(
    writePool,
    readPool,
  ).readHead(SCOPE, canonicalParticipantId);
  assert.notEqual(head, null, "the participant record must exist first");

  const evidence = Wave1SubjectBoundEvidenceSchema.parse({
    evidenceRef: "identity:verification/participant-record",
    evidenceDigest: `sha256:${"c".repeat(64)}`,
    observedAt: isoOffset(-60_000),
    freshUntil: isoOffset(3_600_000),
    subjectParticipantId: canonicalParticipantId,
  });
  const coreNormalized = coreNormalizeAlias(alias);
  const determination = determineAliasScript(coreNormalized);
  const host = splitEmailAlias(coreNormalized)?.domain ?? "example.com";
  const identity: CanonicalAliasIdentity = CanonicalAliasIdentitySchema.parse({
    schemaVersion: WAVE1_TRUSTED_MEMORY_CONTRACT_VERSION,
    aliasId: `alias-${canonicalParticipantId}`,
    scope: SCOPE,
    canonicalParticipantId,
    observedAlias: alias,
    normalizationVersion: MEMORY_ALIAS_NORMALIZATION_VERSION,
    normalizedAlias: alias.normalize("NFC").toLowerCase(),
    skeletonAlgorithm: MEMORY_CONFUSABLE_SKELETON_ALGORITHM,
    skeleton: coreAliasSkeleton(coreNormalized),
    scriptDetermination: determination,
    restrictionLevel: aliasRestrictionLevel(
      alias.normalize("NFC").toLowerCase(),
      determination,
    ),
    lookalikeDomain: {
      registrableDomain: host,
      isInternationalized: isInternationalizedDomain(host),
      risk: "none_detected",
      comparedCorpusRef: "corpus:protected-domains/v1",
      determinedAt: isoOffset(-30_000),
    },
    sourceEvidenceRef: evidence.evidenceRef,
    sourceEvidenceDigest: evidence.evidenceDigest,
    observedAt: evidence.observedAt,
    freshUntil: evidence.freshUntil,
    verifyingAuthorityId: "authority.identity-steward",
    verifyingActorId: "actor.identity-steward",
    determinedAt: isoOffset(-30_000),
    dispositionProposal: "propose_accept",
  });
  const content = successor;
  const receipt = await issue(
    authorization({
      action: "assign_alias",
      targetRecordId: canonicalParticipantId,
      expectedHead: {
        kind: "version",
        version: head!.version,
        contentDigest: head!.contentDigest,
      },
      proposedContentDigest: aliasAssignmentDigest({
        record: content,
        alias: identity,
        evidence,
      }),
    }),
  );
  const result = await createPostgresAliasRegistryStore(
    writePool,
    readPool,
  ).assignAlias({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    participantRecordId: canonicalParticipantId,
    alias: identity,
    evidence,
    proposedContent: content,
    mutationReceiptId: `mutation.reach.alias.${canonicalParticipantId}`,
  });
  assert.equal(result.rejection, null);
  assert.equal(result.verified, true);
}

function inboundEmail(fromEmail: string) {
  return {
    messageId: "msg-reach-0001",
    threadId: "thread-reach-0001",
    fromEmail,
    subject: "Following up on the proposal",
    body: "Can we talk next week?",
    receivedAt: isoOffset(0),
  };
}

/** A router that answers deterministically, so triage is not the variable. */
function router(payload: unknown) {
  return {
    async generate() {
      return {
        text: JSON.stringify(payload),
        provider: "anthropic" as const,
        model: "test-model",
        latencyMs: 1,
      };
    },
  };
}

// ---------------------------------------------------------------------------
// The chain.
// ---------------------------------------------------------------------------

test("an alias resolves through the registry to an AUTHORITATIVE trusted-memory record", async () => {
  await createRecord(CONTACT, { name: "Dana" });
  await bindAlias(CONTACT_ALIAS, CONTACT, {
    name: "Dana",
    relationship: "client",
  });

  const context = await memoryService().resolveExecutiveContext({
    actor: SCOPE,
    normalizedAlias: CONTACT_ALIAS,
  });

  assert.notEqual(context, null);
  assert.equal(context?.canonicalRecordId, CONTACT);
  assert.equal(context?.resolvedFrom, null);
  // The CONTENT came out of the record versions table, not out of a fixture.
  assert.deepEqual(context?.record.content, {
    name: "Dana",
    relationship: "client",
  });
});

test("an alias pointing at a MERGED-AWAY identity resolves to the survivor, without rewriting history", async () => {
  const survivor = await createRecord(CONTACT, {
    name: "Dana",
    relationship: "client",
  });
  await createRecord("record-reach-dup", { name: "D. Rivera" });
  await bindAlias(CONTACT_ALIAS, "record-reach-dup");
  const duplicate = (await createPostgresTrustedMemoryStore(
    writePool,
    readPool,
  ).readHead(SCOPE, "record-reach-dup"))!.contentDigest;
  await mergeInto({
    absorbed: "record-reach-dup",
    survivor: CONTACT,
    mutationReceiptId: "mutation.reach.merge",
  });

  const context = await memoryService().resolveExecutiveContext({
    actor: SCOPE,
    normalizedAlias: CONTACT_ALIAS,
  });

  assert.equal(context?.canonicalRecordId, CONTACT);
  // The reader is TOLD it was redirected. A resolver that hid this could not
  // explain its own output.
  assert.equal(context?.resolvedFrom, "record-reach-dup");
  assert.deepEqual(context?.record.content, {
    name: "Dana",
    relationship: "client",
  });

  // AND THE ABSORBED RECORD IS UNTOUCHED. Read-time resolution rewrote
  // nothing: its chain is still there, at the version the merge left it.
  const absorbed = await createPostgresTrustedMemoryStore(
    writePool,
    readPool,
  ).retrieve(SCOPE, "record-reach-dup");
  assert.equal(absorbed?.version, 3);
  const survivorHead = await createPostgresTrustedMemoryStore(
    writePool,
    readPool,
  ).readHead(SCOPE, CONTACT);
  assert.equal(survivorHead?.version, 1);
  assert.equal(survivorHead?.contentDigest, survivor);
});

test("a merge CHAIN resolves all the way to the identity that still stands", async () => {
  await createRecord(CONTACT, { name: "Dana" });
  const second = await createRecord("record-reach-b", { name: "D. R." });
  const third = await createRecord("record-reach-c", { name: "Dana R" });
  await bindAlias(CONTACT_ALIAS, "record-reach-c");
  // c -> b, then b -> CONTACT. Ordered so neither merge names an already
  // absorbed record, which migration 042 refuses.
  await mergeInto({
    absorbed: "record-reach-c",
    survivor: "record-reach-b",
    mutationReceiptId: "mutation.reach.chain1",
  });
  await mergeInto({
    absorbed: "record-reach-b",
    survivor: CONTACT,
    mutationReceiptId: "mutation.reach.chain2",
  });

  const context = await memoryService().resolveExecutiveContext({
    actor: SCOPE,
    normalizedAlias: CONTACT_ALIAS,
  });

  assert.equal(context?.canonicalRecordId, CONTACT);
  assert.equal(context?.resolvedFrom, "record-reach-c");
});

test("an unknown alias answers null — an ANSWER, not an assumption", async () => {
  await createRecord(CONTACT, { name: "Dana" });

  const context = await memoryService().resolveExecutiveContext({
    actor: SCOPE,
    normalizedAlias: "stranger@example.com",
  });

  assert.equal(context, null);
});

test("an alias bound in ANOTHER principal's scope does not resolve here", async () => {
  await createRecord(CONTACT, { name: "Dana" });
  await bindAlias(CONTACT_ALIAS, CONTACT);

  const context = await memoryService().resolveExecutiveContext({
    actor: { ...SCOPE, principalId: "principal-intruder" },
    normalizedAlias: CONTACT_ALIAS,
  });

  assert.equal(context, null);
});

test("a merge chain that does not terminate is REFUSED, never truncated", async () => {
  // Migration 042 stops a cycle being created. This proves the reader is
  // bounded anyway, because a replica or a restored backup carries no such
  // guarantee — and a truncated walk returns a non-canonical id that looks
  // exactly like a canonical one.
  const service = createWave1MemoryService({
    store: createPostgresTrustedMemoryStore(writePool, readPool),
    aliases: { async resolveAlias() { return null; } },
    identityGraph: {
      async mergedInto(_actor, recordId) {
        return recordId === "a" ? "b" : "a";
      },
    },
    reconciler: { async reconcileAll() { return []; } },
  });

  await assert.rejects(
    () => service.canonicalIdentity(SCOPE, "a"),
    (error: unknown) => {
      assert.ok(error instanceof MemoryCanonicalResolutionFailed);
      assert.match(String(error), /cycles at/);
      return true;
    },
  );
});

// ---------------------------------------------------------------------------
// The consumer.
// ---------------------------------------------------------------------------

test("THE EXECUTIVE PIPELINE READS TRUSTED MEMORY — the reachability proof", async () => {
  await createRecord(CONTACT, { name: "Dana" });
  await bindAlias(CONTACT_ALIAS, CONTACT, {
    name: "Dana",
    relationship: "client",
  });

  const outcome = await runEaPipeline(
    {
      triageRouter: router({
        category: "real_lead",
        risk: "low",
        confidence: 0.9,
        reason: "known client following up",
      }),
      draftRouter: router({ body: "Happy to talk next week." }),
      profile: {
        name: "Test Exec",
        role: "CEO",
        company: "Test Co",
        tone: "warm",
        boundaries: [],
      } as never,
      memory: { service: memoryService(), actor: SCOPE },
    },
    { email: inboundEmail(CONTACT_ALIAS), signals: {} as never },
  );

  // The pipeline carried authoritative memory, read from PostgreSQL, for the
  // sender of the email. This is the whole point of the file.
  assert.equal(outcome.memory?.canonicalRecordId, CONTACT);
  assert.deepEqual(outcome.memory?.record.content, {
    name: "Dana",
    relationship: "client",
  });
  assert.notEqual(outcome.memoryUnavailable, true);
});

test("the pipeline distinguishes 'no memory for this contact' from 'memory unavailable'", async () => {
  const outcome = await runEaPipeline(
    {
      triageRouter: router({
        category: "real_lead",
        risk: "low",
        confidence: 0.9,
        reason: "unknown sender",
      }),
      draftRouter: router({ body: "Thanks for reaching out." }),
      profile: {
        name: "Test Exec",
        role: "CEO",
        company: "Test Co",
        tone: "warm",
        boundaries: [],
      } as never,
      memory: { service: memoryService(), actor: SCOPE },
    },
    { email: inboundEmail("nobody@example.com"), signals: {} as never },
  );

  // Unknown contact: no memory, and NOT flagged unavailable.
  assert.equal(outcome.memory, undefined);
  assert.notEqual(outcome.memoryUnavailable, true);

  // Now a service that cannot answer at all.
  const broken = await runEaPipeline(
    {
      triageRouter: router({
        category: "real_lead",
        risk: "low",
        confidence: 0.9,
        reason: "known client",
      }),
      draftRouter: router({ body: "Thanks." }),
      profile: {
        name: "Test Exec",
        role: "CEO",
        company: "Test Co",
        tone: "warm",
        boundaries: [],
      } as never,
      memory: {
        service: {
          async resolveExecutiveContext(): Promise<never> {
            throw new Error("memory down");
          },
          async reconcilePending() {
            return 0;
          },
          async canonicalIdentity(_a, id) {
            return id;
          },
        },
        actor: SCOPE,
      },
    },
    { email: inboundEmail(CONTACT_ALIAS), signals: {} as never },
  );

  // Drafting continued, and SAID it had no memory rather than implying none
  // existed. These two outcomes must never look identical to a reader.
  assert.equal(broken.memory, undefined);
  assert.equal(broken.memoryUnavailable, true);
});

test("the reconciler is reachable through the service the server builds at boot", async () => {
  // `src/server.ts` calls exactly this, on exactly this composition, before it
  // opens a socket. An outcome left UNKNOWN by a crash has no caller waiting
  // on it, so a restart is what settles it.
  const settled = await memoryService().reconcilePending();
  assert.equal(settled, 0);

  // And it is the real reconciler: give it something unresolved and it
  // resolves it.
  await adminPool.query(
    `INSERT INTO memory_mutation_receipts
       (tenant_id, workspace_id, principal_id, user_id, mutation_receipt_id,
        phase, authorization_id, consumed_nonce_digest, action,
        target_record_id, outcome_status, emitted_at, payload)
     VALUES ($1,$2,$3,$4,'mutation.reach.unknown','terminal',
             'reach-unknown-000000001',$5,'create',$6,
             'UNKNOWN_PENDING_RECONCILIATION', now(),
             jsonb_build_object(
               'mutationReceiptId','mutation.reach.unknown',
               'authorizationId','reach-unknown-000000001',
               'consumedNonceDigest',$5::text,
               'action','create','targetRecordId',$6::text,
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
      `sha256:${"b".repeat(64)}`,
      CONTACT,
    ],
  );

  assert.equal(await memoryService().reconcilePending(), 1);
  const verdict = await adminPool.query(
    `SELECT verdict FROM memory_reconciliations
      WHERE mutation_receipt_id = 'mutation.reach.unknown'`,
  );
  assert.equal(verdict.rows[0].verdict, "NOT_COMMITTED");
});

test("the split order schema is exported for consumers, and a split does not redirect reads", async () => {
  // A split records history; it is NOT a redirect. A reader following the
  // graph must not treat a split edge the way it treats a merge.
  assert.equal(
    MEMORY_IDENTITY_SPLIT_ORDER_SCHEMA_VERSION.endsWith("#identity-split-order"),
    true,
  );
  const source = await createRecord(CONTACT, { name: "Dana and Sam" });
  await createRecord("record-reach-sam", { name: "Sam" });
  await bindAlias(CONTACT_ALIAS, CONTACT);
  const order = {
    schemaVersion: MEMORY_IDENTITY_SPLIT_ORDER_SCHEMA_VERSION,
    reason: "conflated_participants" as const,
    reasonEvidenceRef: "matter:identity-split/reach",
    splitRecordId: "record-reach-sam",
  };
  const receipt = await issue(
    authorization({
      action: "split_identity",
      targetRecordId: CONTACT,
      expectedHead: { kind: "version", version: 1, contentDigest: source },
      proposedContent: order,
    }),
  );
  await createPostgresTrustedMemoryStore(writePool, readPool).splitIdentity({
    actor: SCOPE,
    authorizationId: receipt.authorizationId,
    recordId: CONTACT,
    proposedContent: order,
    mutationReceiptId: "mutation.reach.split",
  });

  const context = await memoryService().resolveExecutiveContext({
    actor: SCOPE,
    normalizedAlias: CONTACT_ALIAS,
  });

  // Still the source. A split edge is history, not a redirect.
  assert.equal(context?.canonicalRecordId, CONTACT);
  assert.equal(context?.resolvedFrom, null);
});

test("S-6 an alias REDIRECTED to a survivor that cannot be retrieved is refused as unresolvable, never answered as 'no memory'", async () => {
  // Falsified against b3efc82: A merged into B, B erased, and resolving an
  // alias of A returned null — "no memory for this contact" — while A itself
  // was active and held content. Resolution hid evidence.
  const heldByAbsorbed = {
    recordId: "a",
    version: 2,
    contentDigest: "sha256:" + "a".repeat(64),
    content: { name: "still here" },
    scope: SCOPE,
  };
  function serviceWith(retrieve: (recordId: string) => unknown) {
    return createWave1MemoryService({
      store: {
        async retrieve(_actor: unknown, recordId: string) {
          return retrieve(recordId);
        },
      } as never,
      aliases: {
        async resolveAlias() {
          return { binding: { canonicalParticipantId: "a" } };
        },
      },
      identityGraph: {
        async mergedInto(_actor, recordId) {
          return recordId === "a" ? "b" : null;
        },
      },
      reconciler: { async reconcileAll() { return []; } },
    });
  }

  await assert.rejects(
    () =>
      serviceWith((id) => (id === "a" ? heldByAbsorbed : null)).resolveExecutiveContext({
        actor: SCOPE,
        normalizedAlias: "dana@example.com",
      }),
    (error: unknown) => {
      assert.ok(error instanceof MemoryCanonicalResolutionFailed);
      assert.match(String(error), /canonical record b is not retrievable/);
      return true;
    },
  );

  // Positive control: a retrievable survivor resolves, and says it was followed.
  const resolved = await serviceWith((id) =>
    id === "b" ? { ...heldByAbsorbed, recordId: "b" } : null,
  ).resolveExecutiveContext({ actor: SCOPE, normalizedAlias: "dana@example.com" });
  assert.equal(resolved?.canonicalRecordId, "b");
  assert.equal(resolved?.resolvedFrom, "a");

  // And with NO redirect, an unretrievable record is still the honest null.
  const standalone = createWave1MemoryService({
    store: { async retrieve() { return null; } } as never,
    aliases: { async resolveAlias() { return { binding: { canonicalParticipantId: "a" } }; } },
    identityGraph: { async mergedInto() { return null; } },
    reconciler: { async reconcileAll() { return []; } },
  });
  assert.equal(
    await standalone.resolveExecutiveContext({ actor: SCOPE, normalizedAlias: "dana@example.com" }),
    null,
  );
});
