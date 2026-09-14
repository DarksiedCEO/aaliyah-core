import {
  MemoryAuthorizationReceiptSchema,
  MemoryIdSchema,
  MemoryMutationReceiptSchema,
  type MemoryAbortReason,
  type MemoryAction,
  type MemoryAuthorizationReceipt,
  type MemoryExpectedHead,
  type MemoryMutationPhase,
  type MemoryMutationReceipt,
  type MemoryScope,
} from "@aaliyah/contracts/v1";
import type { Pool, PoolClient } from "pg";

import {
  ALIAS_TENANT_SCOPE_KEY,
  AliasCrossWorkspacePolicySchema,
  MEMORY_ALIAS_BINDING_SCHEMA_VERSION,
  MemoryAliasBindingSchema,
  aliasAssignmentDigest,
  aliasRemovalDigest,
  aliasScopeKey,
  parseAliasIdentity,
  parseSubjectBoundEvidence,
  type AliasAssignRequest,
  type AliasBindingView,
  type AliasCrossWorkspacePolicy,
  type AliasRegistryRejection,
  type AliasRegistryResult,
  type AliasRegistryStore,
  type AliasRemoveRequest,
  type MemoryAliasBinding,
} from "../../application/memory/wave1AliasRegistry";
import {
  CORE_ALIAS_NORMALIZATION_PROFILE,
  CORE_ALIAS_SKELETON_ALGORITHM,
  HOST_FORM,
  aliasRestrictionLevel,
  coreAliasSkeleton,
  coreNormalizeAlias,
  determineAliasScript,
  lookalikeDomainRisk,
  splitEmailAlias,
} from "../../application/memory/wave1AliasSkeleton";
import {
  MEMORY_RECORD_VERSION_SCHEMA_VERSION,
  MemoryRecordVersionSchema,
  memoryContentDigest,
  type TrustedMemoryActor,
} from "../../application/memory/wave1TrustedMemory";

/**
 * THE AUTHORITATIVE ALIAS REGISTRY, against real PostgreSQL.
 *
 * SAME SHAPE AS `wave1TrustedMemoryStore`, deliberately, because that shape is
 * the one in this repository that has actually been reproduced green against a
 * live database:
 *
 *   BEGIN
 *   SET LOCAL ROLE aaliyah_memory_mutator      -- 029 / 032
 *   SELECT pg_advisory_xact_lock(...)          -- single-flight on the record
 *   ... resolve the authorization from STORED state, four scope checks ...
 *   ... RECOMPUTE the alias: normalization, skeleton, script, domain ...
 *   UPDATE memory_authorization_nonces WHERE consumed_at IS NULL  -- once
 *   SELECT head ORDER BY id DESC; compare-and-swap
 *   INSERT the successor record version
 *   INSERT (or retire) the alias binding   -- UNIQUE indexes exclude here
 *   INSERT pending receipt (UNKNOWN_PENDING_RECONCILIATION)
 *   COMMIT
 *   -- then, on a DIFFERENT pool/session/role: read back both the record head
 *   --   and the binding, and only then say "verified"
 *
 * WHERE THE EXCLUSION ACTUALLY LIVES, AND WHY IT IS NOT IN THIS FILE
 * -----------------------------------------------------------------
 * There is NO "does this alias already exist" SELECT anywhere below, and that
 * absence is the design. A read-then-write pre-check cannot exclude a
 * concurrent writer — two transactions both read "free", both write, both
 * commit — and worse, a pre-check would make the UNIQUE indexes unkillable by
 * any test, because the pre-check would answer first in every reachable case
 * and dropping the index would change nothing observable. The exclusion is
 * `memory_alias_bindings_alias_unique` and
 * `memory_alias_bindings_skeleton_unique` (migration 031), both partial on
 * `removed_at IS NULL`. This file only TRANSLATES the resulting SQLSTATE 23505
 * into a rejection name.
 *
 * For the same reason the advisory lock is taken on the PARTICIPANT RECORD and
 * never on the alias. Locking the alias key would serialize the racers and let
 * a pre-check decide the winner in application code; leaving it unlocked means
 * two concurrent assignments of one alias to two DIFFERENT participants take
 * two DIFFERENT locks, proceed in parallel, and are separated by the index and
 * by nothing else. That is exactly the property the founder authorization names:
 * "Two concurrent attempts to assign the same protected alias to different
 * identities: EXACTLY ONE MAY WIN."
 *
 * ORDERING: THE LOSER SPENDS NOTHING. Nonce consumption happens BEFORE the
 * binding INSERT, inside the same transaction. When the index refuses the
 * INSERT, the ROLLBACK un-consumes the nonce, so the loser has spent nothing
 * and may retry against a truthful answer. This mirrors the correction path and
 * it is why consumption is not done in a transaction of its own.
 *
 * NOTHING THE PRODUCER CLAIMS IS BELIEVED. `normalizedAlias`, `skeleton`,
 * `scriptDetermination`, `restrictionLevel` and `lookalikeDomain` are all
 * recomputed from `observedAlias` and compared; a disagreement is a refusal,
 * never a correction. The stored row carries CORE's values in its columns and
 * the producer's whole claim in `payload.claimed`, so the two are separable
 * afterwards.
 *
 * WHAT THE SKELETON DOES AND DOES NOT COVER is documented, at length and
 * without overclaiming, in `src/application/memory/wave1AliasSkeleton.ts`. It
 * is NOT a conformant UTS-39 skeleton and nothing here says it is.
 *
 * STILL NOT SOLVED, SAID PLAINLY: `canonicalDigest` is unkeyed, so a party able
 * to write both the authorization table and the nonce table can forge an
 * authorization; a superuser can drop every constraint and trigger relied on
 * here; and legal-hold enforcement and tombstones remain other assignments.
 */

const RECORD_COLUMNS = `id, tenant_id, workspace_id, principal_id, user_id,
  record_id, version, state, content_digest, predecessor_digest,
  authorization_id, mutation_receipt_id, payload`;

const AUTHORIZATION_COLUMNS = `tenant_id, workspace_id, principal_id, user_id,
  authorization_id, action, target_record_id, binding_digest,
  issued_at, expires_at, revoked_at, consumed_at, payload`;

const NONCE_COLUMNS = `tenant_id, workspace_id, binding_digest,
  authorization_id, action, target_record_id,
  issued_at, expires_at, revoked_at, consumed_at`;

const BINDING_COLUMNS = `tenant_id, workspace_id, alias_id, normalized_alias,
  skeleton, canonical_participant_id, scope_key, cross_workspace_policy,
  mutation_receipt_id, removed_at, removed_by_mutation_receipt_id, payload`;

/** Unit separator. Keeps a lock key unambiguous across its components. */
const LOCK_KEY_SEPARATOR = "\u001f";

/** SQLSTATE for unique_violation. */
const UNIQUE_VIOLATION = "23505";

type AuthorizationRow = {
  tenant_id: string;
  workspace_id: string;
  principal_id: string;
  user_id: string;
  authorization_id: string;
  action: string;
  target_record_id: string;
  binding_digest: string;
  issued_at: Date;
  expires_at: Date;
  revoked_at: Date | null;
  consumed_at: Date | null;
  payload: unknown;
};

type NonceRow = {
  tenant_id: string;
  workspace_id: string;
  binding_digest: string;
  authorization_id: string;
  action: string;
  target_record_id: string;
  issued_at: Date;
  expires_at: Date;
  revoked_at: Date | null;
  consumed_at: Date | null;
};

type RecordRow = {
  tenant_id: string;
  workspace_id: string;
  record_id: string;
  version: number;
  state: string;
  content_digest: string;
  predecessor_digest: string | null;
  payload: unknown;
};

type BindingRow = {
  tenant_id: string;
  workspace_id: string;
  alias_id: string;
  normalized_alias: string;
  skeleton: string;
  canonical_participant_id: string;
  scope_key: string;
  cross_workspace_policy: string;
  mutation_receipt_id: string;
  removed_at: Date | null;
  removed_by_mutation_receipt_id: string | null;
  payload: unknown;
};

/** A rejection that must unwind the transaction and emit an abort receipt. */
class AliasMutationAborted extends Error {
  constructor(readonly rejection: AliasRegistryRejection) {
    super(`alias registry: ${rejection}`);
    this.name = "AliasMutationAborted";
  }
}

/**
 * The coarse contracts-level reason each rejection maps onto.
 * `MemoryAbortReasonSchema` has seven values and no free text — by design, so
 * an alias value can never be quoted back on a receipt. Nearly every alias
 * gate is therefore `policy_rejected`, and the precise name lives only in the
 * returned `rejection`.
 */
const ABORT_REASON: Record<string, MemoryAbortReason> = {
  request_malformed: "policy_rejected",
  authorization_not_found: "policy_rejected",
  authorization_malformed: "policy_rejected",
  authorization_scope_mismatch: "policy_rejected",
  authorization_action_mismatch: "policy_rejected",
  authorization_target_mismatch: "policy_rejected",
  authorization_expected_head_mismatch: "policy_rejected",
  authorization_expired: "authorization_expired",
  authorization_revoked: "authorization_revoked",
  authorization_already_consumed: "authorization_already_consumed",
  nonce_missing: "policy_rejected",
  nonce_disagrees_with_receipt: "policy_rejected",
  proposed_content_digest_mismatch: "policy_rejected",
  head_mismatch: "head_mismatch",
  storage_rejected: "storage_rejected",
};

/** A role name is an SQL IDENTIFIER, so it can never be a bind parameter. */
const ROLE_NAME = /^[a-z][a-z0-9_]{0,62}$/u;

export type AliasRegistryStoreOptions = {
  /** Role the mutating transaction runs as. See migrations 029 and 032. */
  mutationRole?: string | null;
  /** Role the independent post-commit read-back runs as. SELECT only. */
  readBackRole?: string | null;
};

function assertRole(name: string | null, label: string): string | null {
  if (name === null) return null;
  if (!ROLE_NAME.test(name)) {
    throw new Error(`alias registry: ${label} is not a valid role identifier`);
  }
  return name;
}

/** Earliest of the supplied instants. Expiry takes the safest reading. */
function earliest(values: readonly number[]): number {
  return values.reduce((low, value) => (value < low ? value : low));
}

function isUniqueViolation(error: unknown): error is { constraint?: string } {
  return (
    typeof error === "object" &&
    error !== null &&
    (error as { code?: unknown }).code === UNIQUE_VIOLATION
  );
}

export function createPostgresAliasRegistryStore(
  pool: Pool,
  readBackPool: Pool,
  options: AliasRegistryStoreOptions = {},
): AliasRegistryStore {
  if (readBackPool === pool) {
    // "Independent read-back" has to mean something. Same pool, same session
    // state, same in-flight visibility — a read-back through it would be the
    // writer marking its own homework.
    throw new Error(
      "alias registry: the post-commit read-back pool must be independent of the mutation pool",
    );
  }
  const mutationRole = assertRole(
    options.mutationRole === undefined
      ? "aaliyah_memory_mutator"
      : options.mutationRole,
    "mutationRole",
  );
  const readBackRole = assertRole(
    options.readBackRole === undefined
      ? "aaliyah_memory_reader"
      : options.readBackRole,
    "readBackRole",
  );

  async function enterRole(
    client: PoolClient,
    role: string | null,
  ): Promise<void> {
    if (role === null) return;
    await client.query(`SET LOCAL ROLE "${role}"`);
  }

  function evidenceRef(mutationReceiptId: string, kind: string): string {
    return `memory:${mutationReceiptId}/${kind}`;
  }

  function buildReceipt(input: {
    mutationReceiptId: string;
    targetRecordId: string;
    action: MemoryAction;
    scope: MemoryScope;
    authorizationId: string;
    consumedNonceDigest: string;
    fromHead: MemoryExpectedHead;
    emittedAt: string;
    outcome: MemoryMutationReceipt["outcome"];
  }): MemoryMutationReceipt {
    return MemoryMutationReceiptSchema.parse({
      schemaVersion: "aaliyah.trusted-memory/v1",
      mutationReceiptId: input.mutationReceiptId,
      authorizationId: input.authorizationId,
      consumedNonceDigest: input.consumedNonceDigest,
      action: input.action,
      scope: input.scope,
      targetRecordId: input.targetRecordId,
      fromHead: input.fromHead,
      emittedAt: input.emittedAt,
      outcome: input.outcome,
    });
  }

  async function persistReceipt(
    client: PoolClient,
    receipt: MemoryMutationReceipt,
    phase: "pending" | "terminal",
  ): Promise<void> {
    await client.query(
      `INSERT INTO memory_mutation_receipts
         (tenant_id, workspace_id, principal_id, user_id, mutation_receipt_id,
          phase, authorization_id, consumed_nonce_digest, action,
          target_record_id, outcome_status, emitted_at, payload)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
      [
        receipt.scope.tenantId,
        receipt.scope.workspaceId,
        receipt.scope.principalId,
        receipt.scope.userId,
        receipt.mutationReceiptId,
        phase,
        receipt.authorizationId,
        receipt.consumedNonceDigest,
        receipt.action,
        receipt.targetRecordId,
        receipt.outcome.status,
        receipt.emittedAt,
        JSON.stringify(receipt),
      ],
    );
  }

  /** Append a terminal receipt on its own connection, under the mutation role. */
  async function appendTerminal(receipt: MemoryMutationReceipt): Promise<void> {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await enterRole(client, mutationRole);
      await persistReceipt(client, receipt, "terminal");
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  function unknownOutcome(
    mutationReceiptId: string,
    phase: MemoryMutationPhase,
    at: string,
  ): MemoryMutationReceipt["outcome"] {
    return {
      status: "UNKNOWN_PENDING_RECONCILIATION",
      lastObservedPhase: phase,
      unknownSince: at,
      reconciliationRef: evidenceRef(mutationReceiptId, "reconciliation"),
      reconciliationState: "open",
    };
  }

  async function finishUnknown(
    mutationReceiptId: string,
    targetRecordId: string,
    action: MemoryAction,
    stored: MemoryAuthorizationReceipt | null,
    phase: MemoryMutationPhase,
  ): Promise<AliasRegistryResult> {
    if (stored === null || stored.expectedHead.kind !== "version") {
      return { verified: false, rejection: "unknown_outcome", receipt: null };
    }
    const at = new Date().toISOString();
    const receipt = buildReceipt({
      mutationReceiptId,
      targetRecordId,
      action,
      scope: stored.scope,
      authorizationId: stored.authorizationId,
      consumedNonceDigest: stored.nonce.bindingDigest,
      fromHead: stored.expectedHead,
      emittedAt: at,
      outcome: unknownOutcome(mutationReceiptId, phase, at),
    });
    // Best effort: the pending row written inside the transaction already
    // carries UNKNOWN, so failing here loses detail, never the verdict.
    await appendTerminal(receipt).catch(() => undefined);
    return { verified: false, rejection: "unknown_outcome", receipt };
  }

  async function abortResult(
    mutationReceiptId: string,
    targetRecordId: string,
    actor: TrustedMemoryActor,
    action: MemoryAction,
    stored: MemoryAuthorizationReceipt | null,
    rejection: AliasRegistryRejection,
  ): Promise<AliasRegistryResult> {
    if (stored === null || stored.expectedHead.kind !== "version") {
      // Not enough real stored state to fill a structurally valid receipt.
      return { verified: false, rejection, receipt: null };
    }
    const at = new Date().toISOString();
    const receipt = buildReceipt({
      mutationReceiptId,
      targetRecordId,
      action,
      // The ACTOR's scope, not the receipt's: a cross-tenant attempt must not
      // be filed under the tenant it tried to reach.
      scope: actor,
      authorizationId: stored.authorizationId,
      consumedNonceDigest: stored.nonce.bindingDigest,
      fromHead: stored.expectedHead,
      emittedAt: at,
      outcome: {
        status: "ABORTED_NO_MUTATION",
        abortedAt: at,
        abortReason: ABORT_REASON[rejection] ?? "policy_rejected",
      },
    });
    await appendTerminal(receipt).catch(() => undefined);
    return { verified: false, rejection, receipt };
  }

  function headFromRow(row: RecordRow): {
    recordId: string;
    version: number;
    state: string;
    contentDigest: string;
    scope: MemoryScope;
    content: unknown;
  } {
    const parsed = MemoryRecordVersionSchema.parse(row.payload);
    if (
      parsed.recordId !== row.record_id ||
      parsed.version !== row.version ||
      parsed.state !== row.state ||
      parsed.contentDigest !== row.content_digest ||
      parsed.predecessorDigest !== row.predecessor_digest ||
      parsed.scope.tenantId !== row.tenant_id ||
      parsed.scope.workspaceId !== row.workspace_id
    ) {
      throw new Error("alias registry: record row and payload binding mismatch");
    }
    return {
      recordId: parsed.recordId,
      version: parsed.version,
      state: parsed.state,
      contentDigest: parsed.contentDigest,
      scope: parsed.scope,
      content: parsed.content,
    };
  }

  function bindingFromRow(row: BindingRow): MemoryAliasBinding {
    const parsed = MemoryAliasBindingSchema.parse(row.payload);
    if (
      parsed.aliasId !== row.alias_id ||
      parsed.normalizedAlias !== row.normalized_alias ||
      parsed.skeleton !== row.skeleton ||
      parsed.canonicalParticipantId !== row.canonical_participant_id ||
      parsed.scopeKey !== row.scope_key ||
      parsed.crossWorkspacePolicy !== row.cross_workspace_policy ||
      parsed.scope.tenantId !== row.tenant_id ||
      parsed.scope.workspaceId !== row.workspace_id
    ) {
      throw new Error("alias registry: binding row and payload mismatch");
    }
    return parsed;
  }

  /**
   * The authorization is REAL STORED STATE. Resolved by id ALONE — not
   * filtered by tenant, because a filtered lookup would make the tenant
   * comparison below unfalsifiable and no test could kill it. The four scope
   * comparisons are the control, and they are four separate statements.
   */
  async function resolveAuthorization(
    client: PoolClient,
    action: MemoryAction,
    actor: TrustedMemoryActor,
    authorizationId: string,
    targetRecordId: string,
    txNow: Date,
  ): Promise<{
    stored: MemoryAuthorizationReceipt;
    expectedHead: Extract<MemoryExpectedHead, { kind: "version" }>;
  }> {
    const authResult = await client.query(
      `SELECT ${AUTHORIZATION_COLUMNS}
         FROM memory_authorization_receipts
        WHERE authorization_id = $1
        LIMIT 1`,
      [authorizationId],
    );
    const authRow = authResult.rows[0] as AuthorizationRow | undefined;
    if (!authRow) throw new AliasMutationAborted("authorization_not_found");

    const parsedAuth = MemoryAuthorizationReceiptSchema.safeParse(
      authRow.payload,
    );
    if (!parsedAuth.success) {
      throw new AliasMutationAborted("authorization_malformed");
    }
    const stored = parsedAuth.data;

    if (stored.scope.tenantId !== actor.tenantId) {
      throw new AliasMutationAborted("authorization_scope_mismatch");
    }
    if (stored.scope.workspaceId !== actor.workspaceId) {
      throw new AliasMutationAborted("authorization_scope_mismatch");
    }
    if (stored.scope.principalId !== actor.principalId) {
      throw new AliasMutationAborted("authorization_scope_mismatch");
    }
    if (stored.scope.userId !== actor.userId) {
      throw new AliasMutationAborted("authorization_scope_mismatch");
    }
    if (stored.action !== action) {
      throw new AliasMutationAborted("authorization_action_mismatch");
    }
    if (stored.targetRecordId !== targetRecordId) {
      throw new AliasMutationAborted("authorization_target_mismatch");
    }
    if (stored.expectedHead.kind !== "version") {
      throw new AliasMutationAborted("authorization_expected_head_mismatch");
    }
    const expectedHead = stored.expectedHead;

    // The out-of-band token, resolved BEFORE any liveness verdict because its
    // revoked_at and expires_at participate in that verdict.
    const nonceResult = await client.query(
      `SELECT ${NONCE_COLUMNS}
         FROM memory_authorization_nonces
        WHERE tenant_id = $1 AND binding_digest = $2
        LIMIT 1`,
      [stored.scope.tenantId, stored.nonce.bindingDigest],
    );
    const nonceRow = nonceResult.rows[0] as NonceRow | undefined;
    if (!nonceRow) throw new AliasMutationAborted("nonce_missing");
    if (
      nonceRow.authorization_id !== stored.authorizationId ||
      nonceRow.workspace_id !== stored.scope.workspaceId ||
      nonceRow.action !== stored.action ||
      nonceRow.target_record_id !== stored.targetRecordId
    ) {
      throw new AliasMutationAborted("nonce_disagrees_with_receipt");
    }
    if (
      stored.revokedAt !== null ||
      authRow.revoked_at !== null ||
      nonceRow.revoked_at !== null
    ) {
      throw new AliasMutationAborted("authorization_revoked");
    }
    // `nonceRow.consumed_at` is deliberately NOT read here: it is the ATOMIC
    // authority and it is read inside the UPDATE's WHERE clause, where it
    // cannot race. Reading it twice would let the two controls cover for each
    // other and neither would be evidence of anything.
    if (stored.consumedAt !== null || authRow.consumed_at !== null) {
      throw new AliasMutationAborted("authorization_already_consumed");
    }
    const expiresAt = earliest([
      Date.parse(stored.expiresAt),
      authRow.expires_at.getTime(),
      nonceRow.expires_at.getTime(),
    ]);
    if (expiresAt <= txNow.getTime()) {
      throw new AliasMutationAborted("authorization_expired");
    }
    return { stored, expectedHead };
  }

  /**
   * Consume exactly once. The WHERE clause is the exclusion, not any SELECT
   * before it: two transactions that both read `consumed_at IS NULL` still
   * have exactly one of these UPDATEs report rowCount 1.
   */
  async function consumeNonce(
    client: PoolClient,
    stored: MemoryAuthorizationReceipt,
    mutationReceiptId: string,
  ): Promise<void> {
    const consumed = await client.query(
      `UPDATE memory_authorization_nonces
          SET consumed_at = now(), consumed_by_mutation_receipt_id = $3
        WHERE tenant_id = $1
          AND binding_digest = $2
          AND consumed_at IS NULL
          AND revoked_at IS NULL
          AND expires_at > now()
        RETURNING id`,
      [stored.scope.tenantId, stored.nonce.bindingDigest, mutationReceiptId],
    );
    if (consumed.rowCount !== 1) {
      throw new AliasMutationAborted("authorization_already_consumed");
    }
    // Bookkeeping on the receipt row. NOT the authority on single use.
    await client.query(
      `UPDATE memory_authorization_receipts
          SET consumed_at = now()
        WHERE authorization_id = $1 AND consumed_at IS NULL`,
      [stored.authorizationId],
    );
  }

  /** Read the ACTUAL head, compare-and-swap, and append the successor. */
  async function compareAndAppend(
    client: PoolClient,
    stored: MemoryAuthorizationReceipt,
    expectedHead: Extract<MemoryExpectedHead, { kind: "version" }>,
    proposedContent: unknown,
    mutationReceiptId: string,
    txNow: Date,
  ): Promise<{ nextVersion: number; recordDigest: string; committedAt: string }> {
    const headResult = await client.query(
      `SELECT ${RECORD_COLUMNS}
         FROM memory_record_versions
        WHERE tenant_id = $1 AND workspace_id = $2 AND record_id = $3
        ORDER BY id DESC
        LIMIT 1`,
      [stored.scope.tenantId, stored.scope.workspaceId, stored.targetRecordId],
    );
    const headRow = headResult.rows[0] as RecordRow | undefined;
    if (!headRow) throw new AliasMutationAborted("head_mismatch");
    const head = headFromRow(headRow);
    if (head.version !== expectedHead.version) {
      throw new AliasMutationAborted("head_mismatch");
    }
    if (head.contentDigest !== expectedHead.contentDigest) {
      throw new AliasMutationAborted("head_mismatch");
    }

    let recordDigest: string;
    try {
      recordDigest = memoryContentDigest(proposedContent);
    } catch {
      throw new AliasMutationAborted("proposed_content_digest_mismatch");
    }
    const committedAt = txNow.toISOString();
    const version = MemoryRecordVersionSchema.parse({
      schemaVersion: MEMORY_RECORD_VERSION_SCHEMA_VERSION,
      recordId: stored.targetRecordId,
      version: head.version + 1,
      state: "active",
      scope: stored.scope,
      content: proposedContent,
      contentDigest: recordDigest,
      predecessorDigest: head.contentDigest,
      authorizationId: stored.authorizationId,
      mutationReceiptId,
      createdAt: committedAt,
    });
    await client.query(
      `INSERT INTO memory_record_versions
         (tenant_id, workspace_id, principal_id, user_id, record_id, version,
          state, content_digest, predecessor_digest, authorization_id,
          mutation_receipt_id, payload)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
      [
        version.scope.tenantId,
        version.scope.workspaceId,
        version.scope.principalId,
        version.scope.userId,
        version.recordId,
        version.version,
        version.state,
        version.contentDigest,
        version.predecessorDigest,
        version.authorizationId,
        version.mutationReceiptId,
        JSON.stringify(version),
      ],
    );
    return { nextVersion: version.version, recordDigest, committedAt };
  }

  /**
   * THE CROSS-WORKSPACE POLICY, READ FROM THE DATABASE, NEVER DEFAULTED.
   *
   * A tenant with no policy row cannot bind an alias. There is no fallback
   * branch here on purpose: the only other outcome is a refusal.
   */
  async function readCrossWorkspacePolicy(
    client: PoolClient,
    tenantId: string,
  ): Promise<AliasCrossWorkspacePolicy> {
    const result = await client.query(
      `SELECT cross_workspace_policy
         FROM memory_alias_tenant_policy
        WHERE tenant_id = $1
        LIMIT 1`,
      [tenantId],
    );
    const row = result.rows[0] as { cross_workspace_policy: string } | undefined;
    if (!row) throw new AliasMutationAborted("alias_scope_policy_missing");
    const parsed = AliasCrossWorkspacePolicySchema.safeParse(
      row.cross_workspace_policy,
    );
    if (!parsed.success) {
      throw new AliasMutationAborted("alias_scope_policy_missing");
    }
    return parsed.data;
  }

  /** Read the scope's protected-domain corpus. Empty is a legitimate answer. */
  async function readProtectedDomains(
    client: PoolClient,
    tenantId: string,
    workspaceId: string,
  ): Promise<string[]> {
    const result = await client.query(
      `SELECT registrable_domain
         FROM memory_alias_protected_domains
        WHERE tenant_id = $1 AND workspace_id = $2
        ORDER BY id DESC`,
      [tenantId, workspaceId],
    );
    return result.rows.map(
      (row: { registrable_domain: string }) => row.registrable_domain,
    );
  }

  // -------------------------------------------------------------------------
  // assign_alias
  // -------------------------------------------------------------------------

  async function assignAlias(
    request: AliasAssignRequest,
  ): Promise<AliasRegistryResult> {
    const action: MemoryAction = "assign_alias";
    if (
      !MemoryIdSchema.safeParse(request.participantRecordId).success ||
      !MemoryIdSchema.safeParse(request.mutationReceiptId).success
    ) {
      return { verified: false, rejection: "request_malformed", receipt: null };
    }
    const alias = parseAliasIdentity(request.alias);
    if (alias === null) {
      return { verified: false, rejection: "alias_malformed", receipt: null };
    }
    const evidence = parseSubjectBoundEvidence(request.evidence);
    if (evidence === null) {
      return {
        verified: false,
        rejection: "alias_evidence_malformed",
        receipt: null,
      };
    }

    let stored: MemoryAuthorizationReceipt | null = null;
    let failure:
      | { kind: "abort"; rejection: AliasRegistryRejection }
      | { kind: "unknown" }
      | null = null;
    let commitIssued = false;
    let committed = false;
    let committedAt: string | null = null;
    let nextVersion = 0;
    let recordDigest = "";
    let binding: MemoryAliasBinding | null = null;

    const lockKey = [
      request.actor.tenantId,
      request.actor.workspaceId,
      request.participantRecordId,
    ].join(LOCK_KEY_SEPARATOR);

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await enterRole(client, mutationRole);
      // Single-flight on the PARTICIPANT RECORD only. Never on the alias: see
      // the header — locking the alias would let application code decide a
      // race that the UNIQUE index must decide.
      await client.query(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
        [lockKey],
      );
      const txNow = (await client.query("SELECT now() AS tx_now")).rows[0]
        .tx_now as Date;

      const resolved = await resolveAuthorization(
        client,
        action,
        request.actor,
        request.authorizationId,
        request.participantRecordId,
        txNow,
      );
      stored = resolved.stored;
      const expectedHead = resolved.expectedHead;

      // ---- THE ALIAS IS BOUND TO THE AUTHORIZATION ----------------------
      // Record content, alias value and evidence value, all three inside one
      // digest. Swap any of them and this is a different mutation than the
      // one that was approved.
      let proposedDigest: string;
      try {
        proposedDigest = aliasAssignmentDigest({
          record: request.proposedContent,
          alias,
          evidence,
        });
      } catch {
        throw new AliasMutationAborted("proposed_content_digest_mismatch");
      }
      if (proposedDigest !== stored.proposedContentDigest) {
        throw new AliasMutationAborted("proposed_content_digest_mismatch");
      }

      // ---- SCOPE AND SUBJECT --------------------------------------------
      if (
        alias.scope.tenantId !== stored.scope.tenantId ||
        alias.scope.workspaceId !== stored.scope.workspaceId ||
        alias.scope.principalId !== stored.scope.principalId ||
        alias.scope.userId !== stored.scope.userId
      ) {
        throw new AliasMutationAborted("alias_scope_mismatch");
      }
      if (alias.canonicalParticipantId !== stored.targetRecordId) {
        throw new AliasMutationAborted("alias_participant_mismatch");
      }
      // THE HIJACK THAT WAS PROVEN LIVE. Evidence issued about one
      // participant must not verify an alias for another one.
      if (evidence.subjectParticipantId !== alias.canonicalParticipantId) {
        throw new AliasMutationAborted("alias_evidence_subject_mismatch");
      }
      if (
        evidence.evidenceRef !== alias.sourceEvidenceRef ||
        evidence.evidenceDigest !== alias.sourceEvidenceDigest ||
        evidence.observedAt !== alias.observedAt ||
        evidence.freshUntil !== alias.freshUntil
      ) {
        // The alias and the evidence it cites describe different observations.
        throw new AliasMutationAborted("alias_evidence_disagreement");
      }
      // Freshness against the TRANSACTION clock, taking the earliest window.
      const freshUntil = earliest([
        Date.parse(alias.freshUntil),
        Date.parse(evidence.freshUntil),
      ]);
      if (freshUntil <= txNow.getTime()) {
        throw new AliasMutationAborted("alias_evidence_stale");
      }

      // ---- RECOMPUTATION. NOTHING CLAIMED IS BELIEVED --------------------
      const normalized = coreNormalizeAlias(alias.observedAlias);
      if (normalized !== alias.normalizedAlias) {
        throw new AliasMutationAborted("alias_normalization_disagreement");
      }
      const skeleton = coreAliasSkeleton(normalized);
      if (skeleton !== alias.skeleton) {
        throw new AliasMutationAborted("alias_skeleton_disagreement");
      }
      const parts = splitEmailAlias(normalized);
      if (parts === null || !HOST_FORM.test(parts.domain)) {
        throw new AliasMutationAborted("alias_not_email_shaped");
      }
      const determination = determineAliasScript(normalized);
      if (determination.kind === "mixed_script") {
        throw new AliasMutationAborted("alias_mixed_script");
      }
      if (determination.kind === "undetermined") {
        throw new AliasMutationAborted("alias_script_undetermined");
      }
      // THE LOOK-ALIKE GATE RUNS BEFORE THE CLAIM IS COMPARED, on purpose.
      // `RegistrableDomainSchema` in contracts admits only an ASCII A-label,
      // so an internationalized host can NEVER be claimed truthfully; checking
      // the claim first would answer `alias_domain_disagreement` for every IDN
      // homograph and leave this gate with no reachable input. The risk is a
      // property of the host Core extracted, not of anything the producer said.
      const corpus = await readProtectedDomains(
        client,
        stored.scope.tenantId,
        stored.scope.workspaceId,
      );
      if (lookalikeDomainRisk(parts.domain, corpus) !== "none_detected") {
        throw new AliasMutationAborted("alias_lookalike_domain");
      }
      if (parts.domain !== alias.lookalikeDomain.registrableDomain) {
        throw new AliasMutationAborted("alias_domain_disagreement");
      }
      if (alias.dispositionProposal !== "propose_accept") {
        throw new AliasMutationAborted("alias_disposition_not_acceptable");
      }

      const policy = await readCrossWorkspacePolicy(
        client,
        stored.scope.tenantId,
      );
      const scopeKey = aliasScopeKey(policy, stored.scope.workspaceId);

      // ---- CONSUME EXACTLY ONCE, BEFORE ANY WRITE -----------------------
      await consumeNonce(client, stored, request.mutationReceiptId);

      const appended = await compareAndAppend(
        client,
        stored,
        expectedHead,
        request.proposedContent,
        request.mutationReceiptId,
        txNow,
      );
      nextVersion = appended.nextVersion;
      recordDigest = appended.recordDigest;
      committedAt = appended.committedAt;

      binding = MemoryAliasBindingSchema.parse({
        schemaVersion: MEMORY_ALIAS_BINDING_SCHEMA_VERSION,
        aliasId: alias.aliasId,
        scope: stored.scope,
        crossWorkspacePolicy: policy,
        scopeKey,
        canonicalParticipantId: alias.canonicalParticipantId,
        normalizedAlias: normalized,
        normalizationProfile: CORE_ALIAS_NORMALIZATION_PROFILE,
        skeleton,
        skeletonAlgorithm: CORE_ALIAS_SKELETON_ALGORITHM,
        registrableDomain: parts.domain,
        scriptCode: determination.script,
        restrictionLevel: aliasRestrictionLevel(normalized, determination),
        subjectParticipantId: evidence.subjectParticipantId,
        sourceEvidenceRef: alias.sourceEvidenceRef,
        sourceEvidenceDigest: alias.sourceEvidenceDigest,
        observedAt: alias.observedAt,
        freshUntil: alias.freshUntil,
        authorizationId: stored.authorizationId,
        mutationReceiptId: request.mutationReceiptId,
        boundAt: committedAt,
        claimed: alias,
      });

      // ---- THE EXCLUSION. One statement, two partial UNIQUE indexes ------
      try {
        await client.query(
          `INSERT INTO memory_alias_bindings
             (tenant_id, workspace_id, principal_id, user_id,
              cross_workspace_policy, scope_key, alias_id, normalized_alias,
              skeleton, skeleton_algorithm, normalization_profile,
              canonical_participant_id, registrable_domain, script_code,
              restriction_level, subject_participant_id, source_evidence_ref,
              source_evidence_digest, observed_at, fresh_until,
              authorization_id, mutation_receipt_id, bound_at, payload)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,
                   $17,$18,$19,$20,$21,$22,$23,$24)`,
          [
            binding.scope.tenantId,
            binding.scope.workspaceId,
            binding.scope.principalId,
            binding.scope.userId,
            binding.crossWorkspacePolicy,
            binding.scopeKey,
            binding.aliasId,
            binding.normalizedAlias,
            binding.skeleton,
            binding.skeletonAlgorithm,
            binding.normalizationProfile,
            binding.canonicalParticipantId,
            binding.registrableDomain,
            binding.scriptCode,
            binding.restrictionLevel,
            binding.subjectParticipantId,
            binding.sourceEvidenceRef,
            binding.sourceEvidenceDigest,
            binding.observedAt,
            binding.freshUntil,
            binding.authorizationId,
            binding.mutationReceiptId,
            binding.boundAt,
            JSON.stringify(binding),
          ],
        );
      } catch (error) {
        if (isUniqueViolation(error)) {
          // Translation only. The EXCLUSION happened in the index.
          if (error.constraint === "memory_alias_bindings_skeleton_unique") {
            throw new AliasMutationAborted("alias_skeleton_collision");
          }
          throw new AliasMutationAborted("alias_already_bound");
        }
        throw error;
      }

      await persistReceipt(
        client,
        buildReceipt({
          mutationReceiptId: request.mutationReceiptId,
          targetRecordId: stored.targetRecordId,
          action,
          scope: stored.scope,
          authorizationId: stored.authorizationId,
          consumedNonceDigest: stored.nonce.bindingDigest,
          fromHead: expectedHead,
          emittedAt: committedAt,
          outcome: unknownOutcome(
            request.mutationReceiptId,
            "commit_issued",
            committedAt,
          ),
        }),
        "pending",
      );

      commitIssued = true;
      await client.query("COMMIT");
      committed = true;
    } catch (error) {
      if (!commitIssued) {
        await client.query("ROLLBACK").catch(() => undefined);
      }
      if (error instanceof AliasMutationAborted) {
        failure = { kind: "abort", rejection: error.rejection };
      } else if (!commitIssued) {
        failure = { kind: "abort", rejection: "storage_rejected" };
      } else {
        failure = { kind: "unknown" };
      }
    } finally {
      // Released BEFORE any receipt is emitted: emitting one takes a second
      // connection, and holding two at once self-deadlocks a small pool under
      // exactly the concurrency this store exists to survive.
      client.release();
    }

    if (failure !== null) {
      return failure.kind === "abort"
        ? await abortResult(
            request.mutationReceiptId,
            request.participantRecordId,
            request.actor,
            action,
            stored,
            failure.rejection,
          )
        : await finishUnknown(
            request.mutationReceiptId,
            request.participantRecordId,
            action,
            stored,
            "commit_issued",
          );
    }
    if (
      !committed ||
      stored === null ||
      committedAt === null ||
      binding === null
    ) {
      return await finishUnknown(
        request.mutationReceiptId,
        request.participantRecordId,
        action,
        stored,
        "commit_issued",
      );
    }
    return await verifyByReadBack({
      action,
      stored,
      mutationReceiptId: request.mutationReceiptId,
      committedAt,
      nextVersion,
      recordDigest,
      aliasId: binding.aliasId,
      expectRemoved: false,
    });
  }

  // -------------------------------------------------------------------------
  // remove_alias
  // -------------------------------------------------------------------------

  async function removeAlias(
    request: AliasRemoveRequest,
  ): Promise<AliasRegistryResult> {
    const action: MemoryAction = "remove_alias";
    if (
      !MemoryIdSchema.safeParse(request.participantRecordId).success ||
      !MemoryIdSchema.safeParse(request.mutationReceiptId).success ||
      !MemoryIdSchema.safeParse(request.aliasId).success
    ) {
      return { verified: false, rejection: "request_malformed", receipt: null };
    }

    let stored: MemoryAuthorizationReceipt | null = null;
    let failure:
      | { kind: "abort"; rejection: AliasRegistryRejection }
      | { kind: "unknown" }
      | null = null;
    let commitIssued = false;
    let committed = false;
    let committedAt: string | null = null;
    let nextVersion = 0;
    let recordDigest = "";

    const lockKey = [
      request.actor.tenantId,
      request.actor.workspaceId,
      request.participantRecordId,
    ].join(LOCK_KEY_SEPARATOR);

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await enterRole(client, mutationRole);
      await client.query(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
        [lockKey],
      );
      const txNow = (await client.query("SELECT now() AS tx_now")).rows[0]
        .tx_now as Date;

      const resolved = await resolveAuthorization(
        client,
        action,
        request.actor,
        request.authorizationId,
        request.participantRecordId,
        txNow,
      );
      stored = resolved.stored;
      const expectedHead = resolved.expectedHead;

      let proposedDigest: string;
      try {
        proposedDigest = aliasRemovalDigest({
          record: request.proposedContent,
          aliasId: request.aliasId,
        });
      } catch {
        throw new AliasMutationAborted("proposed_content_digest_mismatch");
      }
      if (proposedDigest !== stored.proposedContentDigest) {
        throw new AliasMutationAborted("proposed_content_digest_mismatch");
      }

      const policy = await readCrossWorkspacePolicy(
        client,
        stored.scope.tenantId,
      );
      const scopeKey = aliasScopeKey(policy, stored.scope.workspaceId);

      await consumeNonce(client, stored, request.mutationReceiptId);

      const appended = await compareAndAppend(
        client,
        stored,
        expectedHead,
        request.proposedContent,
        request.mutationReceiptId,
        txNow,
      );
      nextVersion = appended.nextVersion;
      recordDigest = appended.recordDigest;
      committedAt = appended.committedAt;

      // ATOMIC SINGLE-USE RETIREMENT. ONE statement, and deliberately NOT a
      // SELECT followed by an UPDATE: a prior SELECT would answer
      // `alias_not_bound` in every reachable case and leave the
      // `removed_at IS NULL` guard — the part that actually makes retirement
      // happen at most once — with no input any test could reach. The row is
      // RETURNED, so the participant it belongs to is checked against the
      // authorization AFTER the guard has fired, in its own statement, and
      // the mismatch rolls the retirement back with everything else.
      const retired = await client.query(
        `UPDATE memory_alias_bindings
            SET removed_at = now(),
                removed_by_mutation_receipt_id = $4,
                removed_authorization_id = $5
          WHERE tenant_id = $1 AND scope_key = $2 AND alias_id = $3
            AND removed_at IS NULL
        RETURNING ${BINDING_COLUMNS}`,
        [
          stored.scope.tenantId,
          scopeKey,
          request.aliasId,
          request.mutationReceiptId,
          stored.authorizationId,
        ],
      );
      if (retired.rowCount !== 1) {
        throw new AliasMutationAborted("alias_not_bound");
      }
      const existing = bindingFromRow(retired.rows[0] as BindingRow);
      if (existing.canonicalParticipantId !== stored.targetRecordId) {
        throw new AliasMutationAborted("alias_participant_mismatch");
      }

      await persistReceipt(
        client,
        buildReceipt({
          mutationReceiptId: request.mutationReceiptId,
          targetRecordId: stored.targetRecordId,
          action,
          scope: stored.scope,
          authorizationId: stored.authorizationId,
          consumedNonceDigest: stored.nonce.bindingDigest,
          fromHead: expectedHead,
          emittedAt: committedAt,
          outcome: unknownOutcome(
            request.mutationReceiptId,
            "commit_issued",
            committedAt,
          ),
        }),
        "pending",
      );

      commitIssued = true;
      await client.query("COMMIT");
      committed = true;
    } catch (error) {
      if (!commitIssued) {
        await client.query("ROLLBACK").catch(() => undefined);
      }
      if (error instanceof AliasMutationAborted) {
        failure = { kind: "abort", rejection: error.rejection };
      } else if (!commitIssued) {
        failure = { kind: "abort", rejection: "storage_rejected" };
      } else {
        failure = { kind: "unknown" };
      }
    } finally {
      client.release();
    }

    if (failure !== null) {
      return failure.kind === "abort"
        ? await abortResult(
            request.mutationReceiptId,
            request.participantRecordId,
            request.actor,
            action,
            stored,
            failure.rejection,
          )
        : await finishUnknown(
            request.mutationReceiptId,
            request.participantRecordId,
            action,
            stored,
            "commit_issued",
          );
    }
    if (!committed || stored === null || committedAt === null) {
      return await finishUnknown(
        request.mutationReceiptId,
        request.participantRecordId,
        action,
        stored,
        "commit_issued",
      );
    }
    return await verifyByReadBack({
      action,
      stored,
      mutationReceiptId: request.mutationReceiptId,
      committedAt,
      nextVersion,
      recordDigest,
      aliasId: request.aliasId,
      expectRemoved: true,
    });
  }

  // -------------------------------------------------------------------------
  // The independent post-commit read-back. No read-back, no verified success.
  // -------------------------------------------------------------------------

  async function verifyByReadBack(input: {
    action: MemoryAction;
    stored: MemoryAuthorizationReceipt;
    mutationReceiptId: string;
    committedAt: string;
    nextVersion: number;
    recordDigest: string;
    aliasId: string;
    expectRemoved: boolean;
  }): Promise<AliasRegistryResult> {
    const { stored } = input;
    const fromHead = stored.expectedHead;
    if (fromHead.kind !== "version") {
      return await finishUnknown(
        input.mutationReceiptId,
        stored.targetRecordId,
        input.action,
        stored,
        "read_back_attempted",
      );
    }

    let observedHead: ReturnType<typeof headFromRow> | null;
    let observedBinding: BindingRow | null;
    let readBackAt: string;
    let readBackDigest: string;
    try {
      const readClient = await readBackPool.connect();
      try {
        await readClient.query("BEGIN");
        await enterRole(readClient, readBackRole);
        const now = (await readClient.query("SELECT now() AS tx_now")).rows[0]
          .tx_now as Date;
        const headResult = await readClient.query(
          `SELECT ${RECORD_COLUMNS}
             FROM memory_record_versions
            WHERE tenant_id = $1 AND workspace_id = $2 AND record_id = $3
            ORDER BY id DESC
            LIMIT 1`,
          [
            stored.scope.tenantId,
            stored.scope.workspaceId,
            stored.targetRecordId,
          ],
        );
        const bindingResult = await readClient.query(
          `SELECT ${BINDING_COLUMNS}
             FROM memory_alias_bindings
            WHERE tenant_id = $1 AND workspace_id = $2 AND alias_id = $3
            ORDER BY id DESC
            LIMIT 1`,
          [stored.scope.tenantId, stored.scope.workspaceId, input.aliasId],
        );
        await readClient.query("COMMIT");
        readBackAt = now.toISOString();
        const row = headResult.rows[0] as RecordRow | undefined;
        observedHead = row ? headFromRow(row) : null;
        observedBinding =
          (bindingResult.rows[0] as BindingRow | undefined) ?? null;
        // Recomputed from the bytes that came BACK, not the bytes that went
        // out. jsonb does not preserve key order, which is why this digest is
        // canonical rather than a stringify-and-hash.
        readBackDigest = observedHead
          ? memoryContentDigest(observedHead.content)
          : "";
      } finally {
        readClient.release();
      }
    } catch {
      return await finishUnknown(
        input.mutationReceiptId,
        stored.targetRecordId,
        input.action,
        stored,
        "read_back_attempted",
      );
    }

    if (observedHead === null || readBackDigest === "") {
      return await finishUnknown(
        input.mutationReceiptId,
        stored.targetRecordId,
        input.action,
        stored,
        "read_back_attempted",
      );
    }

    if (readBackDigest !== input.recordDigest) {
      const receipt = buildReceipt({
        mutationReceiptId: input.mutationReceiptId,
        targetRecordId: stored.targetRecordId,
        action: input.action,
        scope: stored.scope,
        authorizationId: stored.authorizationId,
        consumedNonceDigest: stored.nonce.bindingDigest,
        fromHead,
        emittedAt: readBackAt,
        outcome: {
          status: "COMMITTED_READ_BACK_DIVERGED",
          committedAt: input.committedAt,
          expectedContentDigest: input.recordDigest,
          readBackAt,
          readBackSource: "independent_session",
          readBackDigest,
          divergenceRef: evidenceRef(input.mutationReceiptId, "divergence"),
        },
      });
      try {
        await appendTerminal(receipt);
      } catch {
        return await finishUnknown(
          input.mutationReceiptId,
          stored.targetRecordId,
          input.action,
          stored,
          "read_back_attempted",
        );
      }
      return { verified: false, rejection: "read_back_diverged", receipt };
    }

    const headAgrees =
      observedHead.recordId === stored.targetRecordId &&
      observedHead.version === input.nextVersion &&
      observedHead.contentDigest === input.recordDigest &&
      observedHead.state === "active" &&
      observedHead.scope.tenantId === stored.scope.tenantId &&
      observedHead.scope.workspaceId === stored.scope.workspaceId &&
      observedHead.scope.principalId === stored.scope.principalId &&
      observedHead.scope.userId === stored.scope.userId;
    // The BINDING is read back too. A record head that advanced while the
    // registry did not is not a successful alias mutation, and reporting it as
    // one would be the whole defect this file exists to prevent.
    const bindingAgrees =
      observedBinding !== null &&
      observedBinding.alias_id === input.aliasId &&
      (input.expectRemoved
        ? observedBinding.removed_at !== null &&
          observedBinding.removed_by_mutation_receipt_id ===
            input.mutationReceiptId
        : observedBinding.removed_at === null &&
          observedBinding.mutation_receipt_id === input.mutationReceiptId &&
          observedBinding.canonical_participant_id === stored.targetRecordId);
    if (!headAgrees || !bindingAgrees) {
      return await finishUnknown(
        input.mutationReceiptId,
        stored.targetRecordId,
        input.action,
        stored,
        "read_back_attempted",
      );
    }

    const receipt = buildReceipt({
      mutationReceiptId: input.mutationReceiptId,
      targetRecordId: stored.targetRecordId,
      action: input.action,
      scope: stored.scope,
      authorizationId: stored.authorizationId,
      consumedNonceDigest: stored.nonce.bindingDigest,
      fromHead,
      emittedAt: readBackAt,
      outcome: {
        status: "COMMITTED_AND_READ_BACK",
        committedAt: input.committedAt,
        resultingHead: {
          recordId: observedHead.recordId,
          version: observedHead.version,
          contentDigest: observedHead.contentDigest,
          scope: observedHead.scope,
        },
        readBackAt,
        readBackSource: "independent_session",
        readBackDigest,
      },
    });
    try {
      await appendTerminal(receipt);
    } catch {
      return await finishUnknown(
        input.mutationReceiptId,
        stored.targetRecordId,
        input.action,
        stored,
        "read_back_attempted",
      );
    }
    return { verified: true, rejection: null, receipt };
  }

  // -------------------------------------------------------------------------
  // Reads, always on the independent pool under the SELECT-only role.
  // -------------------------------------------------------------------------

  async function readOnIndependentPool(
    sql: string,
    params: readonly unknown[],
  ): Promise<BindingRow | null> {
    const client = await readBackPool.connect();
    try {
      await client.query("BEGIN");
      await enterRole(client, readBackRole);
      const result = await client.query(sql, params as unknown[]);
      await client.query("COMMIT");
      return (result.rows[0] as BindingRow | undefined) ?? null;
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  async function readAliasBinding(
    actor: TrustedMemoryActor,
    aliasId: string,
  ): Promise<AliasBindingView | null> {
    const row = await readOnIndependentPool(
      `SELECT ${BINDING_COLUMNS}
         FROM memory_alias_bindings
        WHERE tenant_id = $1 AND workspace_id = $2 AND alias_id = $3
        ORDER BY id DESC
        LIMIT 1`,
      [actor.tenantId, actor.workspaceId, aliasId],
    );
    if (row === null) return null;
    return { binding: bindingFromRow(row), removed: row.removed_at !== null };
  }

  async function resolveAlias(
    actor: TrustedMemoryActor,
    normalizedAlias: string,
  ): Promise<AliasBindingView | null> {
    // Scoped by BOTH tenant and the two possible scope keys, so a
    // tenant-exclusive binding made in another workspace is still resolvable
    // by the workspace that is excluded by it — which is the whole point of
    // the policy being tenant-wide.
    const row = await readOnIndependentPool(
      `SELECT ${BINDING_COLUMNS}
         FROM memory_alias_bindings
        WHERE tenant_id = $1
          AND scope_key IN ($2, $3)
          AND normalized_alias = $4
          AND removed_at IS NULL
        ORDER BY id DESC
        LIMIT 1`,
      [actor.tenantId, actor.workspaceId, ALIAS_TENANT_SCOPE_KEY, normalizedAlias],
    );
    if (row === null) return null;
    return { binding: bindingFromRow(row), removed: false };
  }

  return { assignAlias, removeAlias, readAliasBinding, resolveAlias };
}
