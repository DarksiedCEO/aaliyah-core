import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import test, { after, before, beforeEach } from "node:test";
import { Pool } from "pg";

import {
  MEMORY_ALIAS_NORMALIZATION_VERSION,
  MEMORY_AUTHORIZATION_NONCE_SCHEMA_VERSION,
  MEMORY_CONFUSABLE_SKELETON_ALGORITHM,
  CanonicalAliasIdentitySchema,
  MemoryAuthorizationReceiptSchema,
  WAVE1_TRUSTED_MEMORY_CONTRACT_VERSION,
  Wave1SubjectBoundEvidenceSchema,
  memoryAuthorizationNonce,
  type MemoryAction,
  type MemoryAuthorizationReceipt,
  type MemoryExpectedHead,
  type MemoryScope,
  type Principal,
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
import { memoryContentDigest } from "../src/application/memory/wave1TrustedMemory";
import {
  CEO_PROFILE_SCHEMA_VERSION,
  CeoProfileSchema,
} from "../src/application/executive/ceoProfile";
import { createCoreApp } from "../src/http/createCoreApp";
import { runMailMigrations } from "../src/persistence/postgres/migrations";
import { createPostgresAliasRegistryStore } from "../src/persistence/postgres/wave1AliasRegistryStore";
import { createPostgresWave1MemoryService } from "../src/persistence/postgres/wave1IdentityGraphStore";
import { createPostgresTrustedMemoryStore } from "../src/persistence/postgres/wave1TrustedMemoryStore";
import {
  lockSharedMemoryTables,
  type SharedTableLock,
} from "./support/sharedMemoryTables";

/**
 * W1BR-016 — A REAL REQUEST ENTERS THE TRUSTED-MEMORY CHAIN.
 *
 * The chain was already proven end to end and could not be ENTERED: the only
 * caller of `runEaPipeline` was a test. These drive it over HTTP, against a
 * listening server, with the memory service composed exactly as `server.ts`
 * composes it — so "production reachable" stops meaning "reachable from a test
 * that calls the function directly".
 *
 * Nothing here sends anything. The route produces a draft for review and has
 * no send path.
 */

const DB_URL =
  process.env.AALIYAH_TEST_DATABASE_URL ??
  "postgres://postgres:test@127.0.0.1:54329/aaliyah_test";

const SCOPE: MemoryScope = {
  tenantId: "tenant-http",
  workspaceId: "workspace-http",
  // The route maps principalId to the authenticated user's id (W1BR-017).
  principalId: "user-http",
  userId: "user-http",
};
const CONTACT = "record-http-contact";
const CONTACT_ALIAS = "dana@example.com";
const TOKEN = "session-token-http";

let adminPool: Pool;
let writePool: Pool;
let readPool: Pool;
let sharedTableLock: SharedTableLock;
let server: Server;
let baseUrl: string;
let authCounter = 0;

const PRINCIPAL: Principal = {
  actorType: "user",
  userId: SCOPE.userId,
  tenantId: SCOPE.tenantId,
  workspaceIds: [SCOPE.workspaceId],
  roles: ["workspace_member"],
  sessionId: "session-http-0001",
  authStrength: "password",
};

/** A router answering with fixed TEXT, so the model is not the variable. */
function textRouter(text: string) {
  return {
    async generate() {
      return {
        text,
        provider: "anthropic" as const,
        model: "test-model",
        latencyMs: 1,
      };
    },
  };
}

/** Triage answers JSON; the drafting router answers a body. */
function classifyRouter(payload: unknown) {
  return textRouter(JSON.stringify(payload));
}

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

  const app = createCoreApp({
    // The ONLY principal source, same shape production uses.
    mailAuth: {
      principalForToken: async (token: string) =>
        token === TOKEN ? PRINCIPAL : null,
    },
    executive: {
      // Composed exactly as src/server.ts composes it at boot.
      memory: createPostgresWave1MemoryService(writePool, readPool),
      pipeline: {
        triageRouter: classifyRouter({
          category: "real_lead",
          risk: "green",
          confidence: 0.9,
          reason: "known contact following up",
        }),
        draftRouter: textRouter("Happy to talk next week."),
        // A REAL profile, parsed by its own schema. The `as never` this
        // replaced was hiding a shape mismatch, and the route then threw a
        // 500 that arrived as an HTML error page.
        profile: CeoProfileSchema.parse({
          schemaVersion: CEO_PROFILE_SCHEMA_VERSION,
          name: "Test Exec",
          title: "CEO",
          companies: ["Test Co"],
          tone: "warm and direct",
          greeting: "Hi",
          signoff: "Best",
        }),
      },
    },
  });
  await new Promise<void>((resolve) => {
    server = app.listen(0, () => resolve());
  });
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
  await readPool.end();
  await writePool.end();
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
              memory_tombstones
     RESTART IDENTITY`,
  );
  authCounter = 0;
});

function isoOffset(ms: number): string {
  return new Date(Date.now() + ms).toISOString();
}

function authorization(input: {
  action: MemoryAction;
  targetRecordId: string;
  expectedHead: MemoryExpectedHead;
  proposedContent?: unknown;
  proposedContentDigest?: string;
}): MemoryAuthorizationReceipt {
  authCounter += 1;
  const authorizationId = `http-auth-${String(authCounter).padStart(18, "0")}`;
  const proposedContentDigest =
    input.proposedContentDigest ?? memoryContentDigest(input.proposedContent);
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
      bindingDigest: memoryAuthorizationNonce({
        bindingSchemaVersion: MEMORY_AUTHORIZATION_NONCE_SCHEMA_VERSION,
        authorizationId,
        action: input.action,
        scope: SCOPE,
        targetRecordId: input.targetRecordId,
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

async function createRecord(recordId: string, content: unknown): Promise<void> {
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
    mutationReceiptId: `mutation.http.create.${recordId}`,
  });
  assert.equal(result.verified, true);
}

/** Bind the alias through the REAL registry, as production would. */
async function bindAlias(alias: string, participantId: string, successor: unknown) {
  const head = await createPostgresTrustedMemoryStore(
    writePool,
    readPool,
  ).readHead(SCOPE, participantId);
  const evidence = Wave1SubjectBoundEvidenceSchema.parse({
    evidenceRef: "identity:verification/participant-record",
    evidenceDigest: `sha256:${"c".repeat(64)}`,
    observedAt: isoOffset(-60_000),
    freshUntil: isoOffset(3_600_000),
    subjectParticipantId: participantId,
  });
  const normalized = coreNormalizeAlias(alias);
  const determination = determineAliasScript(normalized);
  const host = splitEmailAlias(normalized)?.domain ?? "example.com";
  const identity = CanonicalAliasIdentitySchema.parse({
    schemaVersion: WAVE1_TRUSTED_MEMORY_CONTRACT_VERSION,
    aliasId: `alias-${participantId}`,
    scope: SCOPE,
    canonicalParticipantId: participantId,
    observedAlias: alias,
    normalizationVersion: MEMORY_ALIAS_NORMALIZATION_VERSION,
    normalizedAlias: alias.normalize("NFC").toLowerCase(),
    skeletonAlgorithm: MEMORY_CONFUSABLE_SKELETON_ALGORITHM,
    skeleton: coreAliasSkeleton(normalized),
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
  const receipt = await issue(
    authorization({
      action: "assign_alias",
      targetRecordId: participantId,
      expectedHead: {
        kind: "version",
        version: head!.version,
        contentDigest: head!.contentDigest,
      },
      proposedContentDigest: aliasAssignmentDigest({
        record: successor,
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
    participantRecordId: participantId,
    alias: identity,
    evidence,
    proposedContent: successor,
    mutationReceiptId: `mutation.http.alias.${participantId}`,
  });
  assert.equal(result.verified, true);
}

function inboundBody(overrides: Record<string, unknown> = {}) {
  return {
    workspaceId: SCOPE.workspaceId,
    email: {
      messageId: "msg-http-0001",
      threadId: "thread-http-0001",
      fromEmail: CONTACT_ALIAS,
      subject: "Following up",
      body: "Can we talk next week?",
      receivedAt: isoOffset(0),
    },
    ...overrides,
  };
}

async function post(
  body: unknown,
  headers: Record<string, string> = { authorization: `Bearer ${TOKEN}` },
) {
  const response = await fetch(`${baseUrl}/executive/inbound/draft`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
  return {
    status: response.status,
    json: (await response.json()) as Record<string, unknown>,
  };
}

// ---------------------------------------------------------------------------
// The proof.
// ---------------------------------------------------------------------------

test("W1BR-016: an HTTP request reaches the AUTHORITATIVE trusted-memory record", async () => {
  await createRecord(CONTACT, { name: "Dana" });
  await bindAlias(CONTACT_ALIAS, CONTACT, {
    name: "Dana",
    relationship: "client",
  });

  const { status, json } = await post(inboundBody());

  assert.equal(status, 200);
  // The response carries memory that came out of PostgreSQL, for the sender of
  // the request's own email. This is the reachability proof.
  assert.deepEqual(json.memory, {
    canonicalRecordId: CONTACT,
    resolvedFrom: null,
  });
  assert.equal(json.memoryUnavailable, false);
  assert.equal(json.category, "real_lead");
});

test("an unauthenticated request never reaches memory at all", async () => {
  await createRecord(CONTACT, { name: "Dana" });
  await bindAlias(CONTACT_ALIAS, CONTACT, { name: "Dana" });

  const { status, json } = await post(inboundBody(), {});

  assert.equal(status, 401);
  assert.equal(json.error, "unauthenticated");
  assert.equal(json.memory, undefined);
});

test("a bad token never reaches memory either", async () => {
  await createRecord(CONTACT, { name: "Dana" });

  const { status } = await post(inboundBody(), {
    authorization: "Bearer not-the-token",
  });

  assert.equal(status, 401);
});

test("a workspace the principal does not belong to is REFUSED, not served", async () => {
  await createRecord(CONTACT, { name: "Dana" });
  await bindAlias(CONTACT_ALIAS, CONTACT, { name: "Dana" });

  const { status, json } = await post(
    inboundBody({ workspaceId: "workspace-somebody-else" }),
  );

  // The store scopes on workspace; a route that accepted the caller's claim
  // would read another workspace's memory with a perfectly valid session.
  assert.equal(status, 403);
  assert.equal(json.error, "workspace_forbidden");
});

test("a malformed request is refused before anything is read", async () => {
  const { status, json } = await post({ workspaceId: SCOPE.workspaceId });
  assert.equal(status, 400);
  assert.equal(json.error, "malformed_request");
});

test("an unknown sender returns NO memory, and does not claim memory was unavailable", async () => {
  await createRecord(CONTACT, { name: "Dana" });
  await bindAlias(CONTACT_ALIAS, CONTACT, { name: "Dana" });

  const { status, json } = await post(
    inboundBody({
      email: { ...inboundBody().email, fromEmail: "stranger@example.com" },
    }),
  );

  assert.equal(status, 200);
  assert.equal(json.memory, null);
  // The distinction the route exists to preserve.
  assert.equal(json.memoryUnavailable, false);
});

test("the route produces a draft for REVIEW and has no send path", async () => {
  await createRecord(CONTACT, { name: "Dana" });
  await bindAlias(CONTACT_ALIAS, CONTACT, { name: "Dana" });

  const { status, json } = await post(inboundBody());

  assert.equal(status, 200);
  assert.equal(json.action, "draft");
  assert.ok(json.draft, "a draft must be returned for review");
  // Nothing in the response is a send, an approval, or a delivery receipt.
  assert.equal(json.sent, undefined);
  assert.equal(json.approved, undefined);
  assert.equal(json.messageId, undefined);
});
