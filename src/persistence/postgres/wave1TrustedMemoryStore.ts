import {
  MemoryAuthorizationIdSchema,
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
  MEMORY_RECORD_VERSION_SCHEMA_VERSION,
  MemoryRecordVersionSchema,
  memoryContentDigest,
  type MemoryRecordVersion,
  type TrustedMemoryActor,
  type TrustedMemoryHead,
  type TrustedMemoryMutationRequest,
  type TrustedMemoryMutationResult,
  type TrustedMemoryRejection,
  type TrustedMemoryStore,
} from "../../application/memory/wave1TrustedMemory";

/**
 * PostgreSQL trusted-memory mutation service.
 *
 * THE SHAPE, and it is deliberately the same shape as
 * `wave1LifecycleStore.appendIfCurrent`, which is the concurrency pattern in
 * this repository that has actually been reproduced green:
 *
 *   BEGIN
 *   SET LOCAL ROLE <least privilege>            -- 029_memory_privilege_separation
 *   SELECT pg_advisory_xact_lock(hashtextextended($1, 0))   -- single-flight
 *   ... resolve the authorization from STORED state ...
 *   UPDATE ... WHERE consumed_at IS NULL        -- consume exactly once
 *   SELECT ... ORDER BY id DESC LIMIT 1         -- the ACTUAL current head
 *   if (actual !== expected) { ROLLBACK; abort } -- compare-and-swap
 *   INSERT new version
 *   INSERT pending receipt (UNKNOWN_PENDING_RECONCILIATION)
 *   COMMIT
 *   -- then, on a DIFFERENT connection: read back, and only then say "verified"
 *
 * ORDERING MATTERS AND IS NOT ARBITRARY. Consumption happens BEFORE the
 * compare-and-swap, inside the same transaction. If the CAS then fails, the
 * ROLLBACK un-consumes the nonce too, so a losing racer has spent nothing and
 * the record is untouched: the transaction either did everything or did
 * nothing. That is the "database rollback leaves no partial state" property,
 * and it is why consumption is not done in its own transaction.
 *
 * WHY THE PENDING RECEIPT EXISTS. A crash between COMMIT and read-back is a
 * real, reachable state. The pending row is written INSIDE the mutation
 * transaction and always carries `UNKNOWN_PENDING_RECONCILIATION`; the
 * terminal row is appended only after an independent read-back has said what
 * happened. A process that dies in between leaves UNKNOWN on disk. Success is
 * never the residue of a crash.
 *
 * FAIL-CLOSED DISJUNCTIONS. Expiry, revocation and consumption are each
 * asserted across MORE THAN ONE piece of stored state — the receipt's jsonb
 * payload, the receipt's relational columns, and the out-of-band nonce row —
 * and the SAFEST reading always wins: the EARLIEST expiry, revoked if ANY
 * source says revoked, consumed if ANY source says consumed. Extending an
 * authorization therefore requires rewriting every source consistently.
 *
 * THAT CLAIM USED TO BE FALSE FOR CONSUMPTION AND IS NOW TRUE. Migration 029
 * granted the mutation role UPDATE on the nonce's `consumed_at` AND on the
 * receipt's, so one role held both sources and could consume, un-consume and
 * re-consume an approval — executed, against a live database. Migration 035
 * REVOKES the receipt grant, mirrors consumption from the nonce onto the
 * receipt inside the database, and makes `consumed_at` monotonic on both
 * tables for every writer including the owner. This code therefore no longer
 * writes the receipt's `consumed_at` at all: it cannot, and it must not claim
 * a separation it is itself violating.
 *
 * THE DATABASE IS THE ENFORCEMENT POINT, NOT THIS FILE. Everything below —
 * the authorization exists, it was consumed, the predecessor links, version =
 * head + 1, the owner does not change mid-chain — is ALSO enforced by triggers
 * in migration 034, because a property that lives only here binds only writes
 * that come through here. Deleting a check in this file changes the error a
 * caller sees; it does not make the forgery representable.
 *
 * WHAT THIS DOES NOT SOLVE, SAID PLAINLY. `canonicalDigest` is UNKEYED. It
 * gives integrity of a binding and no authenticity whatsoever. Splitting the
 * consumable token into a payload-free table under a separate privilege raises
 * the cost of forgery; it does not make forgery detectable by a party that can
 * write both tables, and it does nothing at all against a superuser.
 * Authenticity needs a KEYED construction — an issuer signature or HMAC whose
 * key lives in a KMS or HSM, outside the database — verified before a receipt
 * is honoured. That primitive is not in this repository and nothing here
 * claims it. The same unkeyed digest makes a head digest an offline ORACLE for
 * guessed content: see W1BR-008 in docs/WAVE1_BLOCKER_REGISTER.md.
 *
 * ALSO NOT HERE, ON PURPOSE: tombstones, the alias registry and legal-hold
 * ENFORCEMENT are later assignments. `delete()` advances the head to a
 * `deleted` state with the content the approver authorized; it destroys no
 * prior version, emits no `MemoryTombstone`, and must not be read as erasure.
 * `legalHoldRestricts` is never consulted, so the `legal_hold_active` abort
 * reason is currently unreachable — a gap, disclosed, not a claim.
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

/** Unit separator. Keeps a lock key unambiguous across its components. */
const LOCK_KEY_SEPARATOR = "\u001f";

/**
 * The nonce digest an ATTEMPT THAT RESOLVED NO AUTHORIZATION is filed under.
 *
 * An attempt with an unknown authorization id used to write nothing at all,
 * which made id enumeration — the highest-volume attack against an id-only
 * lookup — the one attempt that left no trace. It is now audited, and the
 * durable row has to carry a `consumedNonceDigest` because the receipt shape
 * requires one. This value is all zeroes: it is not the digest of anything, no
 * nonce row can ever carry it (`memory_authorization_nonces` rows are written
 * by the issuer from a real binding digest), and the outcome recorded with it
 * is always ABORTED_NO_MUTATION, which migration 034 refuses to let anyone
 * upgrade into a committed claim. Read it as "no authorization was resolved",
 * never as a nonce.
 */
const UNRESOLVED_NONCE_DIGEST = `sha256:${"0".repeat(64)}`;

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

/** A rejection that must unwind the transaction and emit an abort receipt. */
class MutationAborted extends Error {
  constructor(readonly rejection: TrustedMemoryRejection) {
    super(`trusted memory: ${rejection}`);
    this.name = "MutationAborted";
  }
}

const ABORT_REASON: Record<string, MemoryAbortReason> = {
  request_malformed: "policy_rejected",
  authorization_not_found: "policy_rejected",
  authorization_malformed: "policy_rejected",
  authorization_scope_mismatch: "policy_rejected",
  authorization_action_mismatch: "policy_rejected",
  authorization_target_mismatch: "policy_rejected",
  record_owner_mismatch: "policy_rejected",
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

/**
 * A role name is an SQL IDENTIFIER, so it cannot be a bind parameter. It is
 * therefore restricted to a narrow pattern and rejected at construction rather
 * than interpolated hopefully at query time.
 */
const ROLE_NAME = /^[a-z][a-z0-9_]{0,62}$/u;

export type TrustedMemoryStoreOptions = {
  /**
   * Role the mutating transaction runs as. Defaults to the least-privilege
   * role created by migration 029, which can consume a nonce but can neither
   * issue one, revoke one, move an expiry, nor touch a binding digest. Pass
   * null only where the deployment cannot grant role membership, and
   * understand that doing so removes the privilege boundary.
   */
  mutationRole?: string | null;
  /** Role the independent post-commit read-back runs as. SELECT only. */
  readBackRole?: string | null;
};

function assertRole(
  name: string | null,
  label: string,
): string | null {
  if (name === null) return null;
  if (!ROLE_NAME.test(name)) {
    throw new Error(`trusted memory: ${label} is not a valid role identifier`);
  }
  return name;
}

/** Earliest of the supplied instants. Expiry always takes the safest reading. */
function earliest(values: readonly number[]): number {
  return values.reduce((low, value) => (value < low ? value : low));
}

export function createPostgresTrustedMemoryStore(
  pool: Pool,
  readBackPool: Pool,
  options: TrustedMemoryStoreOptions = {},
): TrustedMemoryStore {
  if (readBackPool === pool) {
    // "Independent read-back" has to mean something. Same pool, same
    // connection, same session state, same in-flight transaction visibility —
    // a read-back through it would be the writer marking its own homework.
    throw new Error(
      "trusted memory: the post-commit read-back pool must be independent of the mutation pool",
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
    // SET LOCAL, so the privilege drop is scoped to this transaction and is
    // undone by COMMIT/ROLLBACK rather than leaking onto a pooled connection.
    await client.query(`SET LOCAL ROLE "${role}"`);
  }

  function headFromRow(row: RecordRow): TrustedMemoryHead {
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
      throw new Error("trusted memory: record row and payload binding mismatch");
    }
    return {
      recordId: parsed.recordId,
      version: parsed.version,
      state: parsed.state,
      contentDigest: parsed.contentDigest,
      predecessorDigest: parsed.predecessorDigest,
      scope: parsed.scope,
    };
  }

  /**
   * The record's head AS THIS ACTOR IS ENTITLED TO SEE IT.
   *
   * All FOUR scope dimensions are predicates, not two. Filtering on tenant and
   * workspace alone let an actor from another principal in the same workspace
   * read a record it has no relationship to, INCLUDING the owner's identity —
   * executed, against a live database. Principal and user are columns on every
   * row and migration 034 pins them constant across a chain, so a head that
   * belongs to somebody else can never be returned as this actor's head.
   *
   * WHAT THIS DOES NOT CLOSE: `contentDigest` is UNKEYED and deterministic, so
   * whoever holds a head digest can confirm guessed content offline. That is
   * W1BR-008 and it needs a keyed construction that is not in this repository.
   */
  async function readHead(
    actor: TrustedMemoryActor,
    recordId: string,
  ): Promise<TrustedMemoryHead | null> {
    const client = await readBackPool.connect();
    try {
      await client.query("BEGIN");
      await enterRole(client, readBackRole);
      const result = await client.query(
        `SELECT ${RECORD_COLUMNS}
           FROM memory_record_versions
          WHERE tenant_id = $1 AND workspace_id = $2 AND record_id = $3
            AND principal_id = $4 AND user_id = $5
          ORDER BY id DESC
          LIMIT 1`,
        [
          actor.tenantId,
          actor.workspaceId,
          recordId,
          actor.principalId,
          actor.userId,
        ],
      );
      await client.query("COMMIT");
      const row = result.rows[0] as RecordRow | undefined;
      return row ? headFromRow(row) : null;
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  function evidenceRef(mutationReceiptId: string, kind: string): string {
    return `memory:${mutationReceiptId}/${kind}`;
  }

  function unknownOutcome(
    request: TrustedMemoryMutationRequest,
    phase: MemoryMutationPhase,
    at: string,
  ): MemoryMutationReceipt["outcome"] {
    return {
      status: "UNKNOWN_PENDING_RECONCILIATION",
      lastObservedPhase: phase,
      unknownSince: at,
      reconciliationRef: evidenceRef(
        request.mutationReceiptId,
        "reconciliation",
      ),
      reconciliationState: "open",
    };
  }

  function buildReceipt(input: {
    request: TrustedMemoryMutationRequest;
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
      mutationReceiptId: input.request.mutationReceiptId,
      authorizationId: input.authorizationId,
      consumedNonceDigest: input.consumedNonceDigest,
      action: input.action,
      scope: input.scope,
      targetRecordId: input.request.recordId,
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

  async function finishUnknown(
    request: TrustedMemoryMutationRequest,
    action: MemoryAction,
    stored: MemoryAuthorizationReceipt | null,
    phase: MemoryMutationPhase,
  ): Promise<TrustedMemoryMutationResult> {
    if (stored === null || stored.expectedHead.kind !== "version") {
      return { verified: false, rejection: "unknown_outcome", receipt: null };
    }
    const at = new Date().toISOString();
    const receipt = buildReceipt({
      request,
      action,
      scope: stored.scope,
      authorizationId: stored.authorizationId,
      consumedNonceDigest: stored.nonce.bindingDigest,
      fromHead: stored.expectedHead,
      emittedAt: at,
      outcome: unknownOutcome(request, phase, at),
    });
    // Best effort: the pending row written inside the transaction already
    // carries UNKNOWN, so failing to append here loses detail, never the
    // unknown verdict itself.
    await appendTerminal(receipt).catch(() => undefined);
    return { verified: false, rejection: "unknown_outcome", receipt };
  }

  /**
   * AUDIT AN ATTEMPT THAT RESOLVED NOTHING.
   *
   * An unknown or unparseable authorization id is the enumeration case, and it
   * was the one path in this store that wrote ZERO rows. Cross-tenant attempts
   * were logged; guessing at ids was not. This writes the attempt down under
   * the ACTOR's scope — never the scope it was reaching for — with the
   * unresolved sentinel above, so the volume and the origin of an enumeration
   * sweep are visible on disk.
   *
   * The CALLER still gets `receipt: null`. Handing back a receipt that names an
   * authorization which does not exist would be a token to hide behind, and
   * the honest answer to the caller is that there is nothing to return. The
   * operator's evidence and the caller's answer are not the same artefact.
   *
   * `fromHead` IS OBSERVED, NOT INVENTED. The contract requires a `correct` or
   * a `delete` receipt to name a prior version, so this reads the head the
   * ACTOR is entitled to see and records that — the head the attempt would
   * have been compared against, which is what `fromHead` means. DISCLOSED
   * LIMIT: when the actor can see no head for the named record there is no
   * honest value for that field and no row is written, so enumeration against
   * record ids that do not exist for the actor is still unaudited here. That
   * is a narrower gap than the one it replaces and it is not closed.
   */
  async function auditUnresolvedAttempt(
    request: TrustedMemoryMutationRequest,
    action: MemoryAction,
  ): Promise<void> {
    const head = await readHead(request.actor, request.recordId).catch(
      () => null,
    );
    if (head === null) return;
    const at = new Date().toISOString();
    const receipt = MemoryMutationReceiptSchema.parse({
      schemaVersion: "aaliyah.trusted-memory/v1",
      mutationReceiptId: request.mutationReceiptId,
      authorizationId: request.authorizationId,
      consumedNonceDigest: UNRESOLVED_NONCE_DIGEST,
      action,
      scope: request.actor,
      targetRecordId: request.recordId,
      fromHead: {
        kind: "version",
        version: head.version,
        contentDigest: head.contentDigest,
      },
      emittedAt: at,
      outcome: {
        status: "ABORTED_NO_MUTATION",
        abortedAt: at,
        abortReason: "policy_rejected",
      },
    });
    await appendTerminal(receipt).catch(() => undefined);
  }

  async function abortResult(
    request: TrustedMemoryMutationRequest,
    action: MemoryAction,
    stored: MemoryAuthorizationReceipt | null,
    rejection: TrustedMemoryRejection,
  ): Promise<TrustedMemoryMutationResult> {
    if (stored === null || stored.expectedHead.kind !== "version") {
      // Not enough real stored state to fill a structurally valid receipt for
      // the CALLER. The attempt is still written down.
      await auditUnresolvedAttempt(request, action);
      return { verified: false, rejection, receipt: null };
    }
    const at = new Date().toISOString();
    const receipt = buildReceipt({
      request,
      action,
      // The ACTOR's scope, not the receipt's: this records the failed attempt
      // of the party that made it, and a cross-tenant attempt must not be
      // filed under the tenant it tried to reach.
      scope: request.actor,
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

  async function mutate(
    action: Extract<MemoryAction, "correct" | "delete">,
    request: TrustedMemoryMutationRequest,
  ): Promise<TrustedMemoryMutationResult> {
    if (
      !MemoryIdSchema.safeParse(request.recordId).success ||
      !MemoryIdSchema.safeParse(request.mutationReceiptId).success ||
      // Checked here so the enumeration audit below can always write a
      // structurally valid row: a malformed id is refused before it reaches
      // the database, exactly like a malformed record id.
      !MemoryAuthorizationIdSchema.safeParse(request.authorizationId).success
    ) {
      return { verified: false, rejection: "request_malformed", receipt: null };
    }

    // Everything below that the abort and read-back paths need, filled in as
    // it becomes known from STORED state. Null means "never learned".
    let stored: MemoryAuthorizationReceipt | null = null;
    let failure:
      | { kind: "abort"; rejection: TrustedMemoryRejection }
      | { kind: "unknown" }
      | null = null;
    let commitIssued = false;
    let committed = false;
    let committedAt: string | null = null;
    let nextVersion = 0;
    let proposedDigest = "";
    let predecessorDigest = "";

    const lockKey = [
      request.actor.tenantId,
      request.actor.workspaceId,
      request.recordId,
    ].join(LOCK_KEY_SEPARATOR);

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await enterRole(client, mutationRole);
      // Single-flight on the record. Two writers racing the same head
      // serialize here, so the loser reads the winner's head and fails its
      // compare-and-swap rather than both reading the stale one.
      await client.query(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
        [lockKey],
      );
      const txNow = (await client.query("SELECT now() AS tx_now")).rows[0]
        .tx_now as Date;

      // ---- 2. THE AUTHORIZATION IS REAL STORED STATE --------------------
      // Resolved by id ALONE. Not filtered by tenant: if the lookup filtered
      // by tenant, the tenant comparison below would be unfalsifiable and no
      // test could kill it. The four scope comparisons are the control.
      const authResult = await client.query(
        `SELECT ${AUTHORIZATION_COLUMNS}
           FROM memory_authorization_receipts
          WHERE authorization_id = $1
          LIMIT 1`,
        [request.authorizationId],
      );
      const authRow = authResult.rows[0] as AuthorizationRow | undefined;
      if (!authRow) throw new MutationAborted("authorization_not_found");

      const parsedAuth = MemoryAuthorizationReceiptSchema.safeParse(
        authRow.payload,
      );
      if (!parsedAuth.success) {
        throw new MutationAborted("authorization_malformed");
      }
      stored = parsedAuth.data;

      // ---- 1. AUTHORITATIVE ACTOR AND SCOPE -----------------------------
      // Four separate statements, four independently killable controls.
      if (stored.scope.tenantId !== request.actor.tenantId) {
        throw new MutationAborted("authorization_scope_mismatch");
      }
      if (stored.scope.workspaceId !== request.actor.workspaceId) {
        throw new MutationAborted("authorization_scope_mismatch");
      }
      if (stored.scope.principalId !== request.actor.principalId) {
        throw new MutationAborted("authorization_scope_mismatch");
      }
      if (stored.scope.userId !== request.actor.userId) {
        throw new MutationAborted("authorization_scope_mismatch");
      }

      // ---- 3. ACTION, TARGET, LIVENESS ----------------------------------
      if (stored.action !== action) {
        throw new MutationAborted("authorization_action_mismatch");
      }
      if (stored.targetRecordId !== request.recordId) {
        throw new MutationAborted("authorization_target_mismatch");
      }
      if (stored.expectedHead.kind !== "version") {
        throw new MutationAborted("authorization_expected_head_mismatch");
      }
      const expectedHead = stored.expectedHead;

      // The out-of-band token. Resolved BEFORE any liveness verdict, because
      // its `revoked_at` and `expires_at` participate in that verdict.
      const nonceResult = await client.query(
        `SELECT ${NONCE_COLUMNS}
           FROM memory_authorization_nonces
          WHERE tenant_id = $1 AND binding_digest = $2
          LIMIT 1`,
        [stored.scope.tenantId, stored.nonce.bindingDigest],
      );
      const nonceRow = nonceResult.rows[0] as NonceRow | undefined;
      // Contracts header: "a nonce presented for consumption with no matching
      // issued row" is a hard failure, never a pass.
      if (!nonceRow) throw new MutationAborted("nonce_missing");
      if (
        nonceRow.authorization_id !== stored.authorizationId ||
        nonceRow.workspace_id !== stored.scope.workspaceId ||
        nonceRow.action !== stored.action ||
        nonceRow.target_record_id !== stored.targetRecordId
      ) {
        // The two tables disagree about what this token authorizes. One of
        // them has been rewritten. Refuse both readings.
        throw new MutationAborted("nonce_disagrees_with_receipt");
      }

      // Revoked if ANY source says so; consumed if ANY source says so;
      // expired at the EARLIEST expiry any source names.
      if (
        stored.revokedAt !== null ||
        authRow.revoked_at !== null ||
        nonceRow.revoked_at !== null
      ) {
        throw new MutationAborted("authorization_revoked");
      }
      // Deliberately NOT reading `nonceRow.consumed_at` here. That column is
      // the ATOMIC authority and it is read inside the UPDATE's WHERE clause
      // below, where it cannot race. Checking it twice would make the two
      // controls cover for each other, so neither could be killed by a test
      // and neither would be evidence of anything.
      if (stored.consumedAt !== null || authRow.consumed_at !== null) {
        throw new MutationAborted("authorization_already_consumed");
      }
      const expiresAt = earliest([
        Date.parse(stored.expiresAt),
        authRow.expires_at.getTime(),
        nonceRow.expires_at.getTime(),
      ]);
      if (expiresAt <= txNow.getTime()) {
        throw new MutationAborted("authorization_expired");
      }

      // ---- THE SUCCESSOR IS BOUND TO THE AUTHORIZATION ------------------
      // The caller hands over content, never a digest. If the content does
      // not hash to exactly what was authorized, this is a different
      // mutation than the one that was approved.
      try {
        proposedDigest = memoryContentDigest(request.proposedContent);
      } catch {
        throw new MutationAborted("proposed_content_digest_mismatch");
      }
      if (proposedDigest !== stored.proposedContentDigest) {
        throw new MutationAborted("proposed_content_digest_mismatch");
      }

      // ---- 4. CONSUME EXACTLY ONCE --------------------------------------
      // One statement. The WHERE clause is the exclusion, not the SELECT
      // above it: two transactions that both read `consumed_at IS NULL` will
      // still have exactly one of these UPDATEs report rowCount 1.
      const consumed = await client.query(
        `UPDATE memory_authorization_nonces
            SET consumed_at = now(), consumed_by_mutation_receipt_id = $3
          WHERE tenant_id = $1
            AND binding_digest = $2
            AND consumed_at IS NULL
            AND revoked_at IS NULL
            AND expires_at > now()
          RETURNING id`,
        [
          stored.scope.tenantId,
          stored.nonce.bindingDigest,
          request.mutationReceiptId,
        ],
      );
      if (consumed.rowCount !== 1) {
        throw new MutationAborted("authorization_already_consumed");
      }
      // THE RECEIPT'S `consumed_at` IS NOT WRITTEN HERE, AND CANNOT BE.
      // Migration 035 revoked this role's UPDATE grant on that column and
      // mirrors consumption from the nonce onto the receipt inside the
      // database. One role writing both sources was the reason "the sources
      // are under different privileges" was false; a statement here would
      // simply fail with permission denied, and passing it through a role
      // that could do it would re-open the hole.

      // ---- 5. READ THE ACTUAL HEAD AND COMPARE-AND-SWAP -----------------
      const headResult = await client.query(
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
      const headRow = headResult.rows[0] as RecordRow | undefined;
      if (!headRow) throw new MutationAborted("head_mismatch");
      const head = headFromRow(headRow);

      // ---- THE ACTOR MUST OWN THE RECORD IT IS MUTATING -----------------
      // The four scope comparisons above are actor <-> AUTHORIZATION. They
      // say nothing about the record. An authorization scoped to
      // principal-attacker naming a record owned by principal-victim passed
      // every one of them, overwrote the victim's content, changed the
      // ownership columns mid-chain, and the post-commit read-back CONFIRMED
      // the takeover because it compared the observed scope against the
      // AUTHORIZATION rather than against the record that was there before.
      //
      // Deliberately read from the HEAD ROW and not from the CAS predicate:
      // filtering the head lookup by principal and user would turn a takeover
      // into an indistinguishable `head_mismatch` and leave these two
      // comparisons with no reachable input, so no test could kill them.
      // Migration 034 pins the same continuity for writers that never come
      // through this function.
      if (head.scope.principalId !== request.actor.principalId) {
        throw new MutationAborted("record_owner_mismatch");
      }
      if (head.scope.userId !== request.actor.userId) {
        throw new MutationAborted("record_owner_mismatch");
      }

      if (head.version !== expectedHead.version) {
        throw new MutationAborted("head_mismatch");
      }
      // The PREDECESSOR digest. A forged one fails here even when the version
      // happens to line up.
      if (head.contentDigest !== expectedHead.contentDigest) {
        throw new MutationAborted("head_mismatch");
      }

      // ---- 6. WRITE THE NEW VERSION -------------------------------------
      nextVersion = head.version + 1;
      predecessorDigest = head.contentDigest;
      committedAt = txNow.toISOString();
      const version: MemoryRecordVersion = MemoryRecordVersionSchema.parse({
        schemaVersion: MEMORY_RECORD_VERSION_SCHEMA_VERSION,
        recordId: stored.targetRecordId,
        version: nextVersion,
        state: action === "delete" ? "deleted" : "active",
        scope: stored.scope,
        content: request.proposedContent,
        contentDigest: proposedDigest,
        predecessorDigest,
        authorizationId: stored.authorizationId,
        mutationReceiptId: request.mutationReceiptId,
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

      // ---- 7. PENDING RECEIPT, INSIDE THE TRANSACTION -------------------
      await persistReceipt(
        client,
        buildReceipt({
          request,
          action,
          scope: stored.scope,
          authorizationId: stored.authorizationId,
          consumedNonceDigest: stored.nonce.bindingDigest,
          fromHead: expectedHead,
          emittedAt: committedAt,
          outcome: unknownOutcome(request, "commit_issued", committedAt),
        }),
        "pending",
      );

      // ---- 8. COMMIT ----------------------------------------------------
      commitIssued = true;
      await client.query("COMMIT");
      committed = true;
    } catch (error) {
      if (!commitIssued) {
        await client.query("ROLLBACK").catch(() => undefined);
      }
      if (error instanceof MutationAborted) {
        failure = { kind: "abort", rejection: error.rejection };
      } else if (!commitIssued) {
        failure = { kind: "abort", rejection: "storage_rejected" };
      } else {
        // The COMMIT itself did not come back cleanly. Whether it landed is
        // genuinely unknown, and unknown is the answer.
        failure = { kind: "unknown" };
      }
    } finally {
      // Released BEFORE any receipt is emitted. Emitting a receipt takes a
      // second connection, and holding two at once turns a small pool into a
      // self-deadlock under the concurrency this store exists to survive.
      client.release();
    }

    if (failure !== null) {
      return failure.kind === "abort"
        ? await abortResult(request, action, stored, failure.rejection)
        : await finishUnknown(request, action, stored, "commit_issued");
    }

    if (!committed || stored === null || committedAt === null) {
      return await finishUnknown(request, action, stored, "commit_issued");
    }
    const authorized = stored;
    const fromHead = authorized.expectedHead;
    if (fromHead.kind !== "version") {
      return await finishUnknown(
        request,
        action,
        authorized,
        "read_back_attempted",
      );
    }

    // ---- 9. INDEPENDENT POST-COMMIT READ-BACK ---------------------------
    // Different pool, different connection, different session, SELECT-only
    // role, after the commit returned. No read-back, no verified success.
    let observed: TrustedMemoryHead | null;
    let readBackAt: string;
    let readBackDigest: string;
    try {
      const readClient = await readBackPool.connect();
      try {
        await readClient.query("BEGIN");
        await enterRole(readClient, readBackRole);
        const now = (await readClient.query("SELECT now() AS tx_now")).rows[0]
          .tx_now as Date;
        const result = await readClient.query(
          `SELECT ${RECORD_COLUMNS}
             FROM memory_record_versions
            WHERE tenant_id = $1 AND workspace_id = $2 AND record_id = $3
            ORDER BY id DESC
            LIMIT 1`,
          [
            authorized.scope.tenantId,
            authorized.scope.workspaceId,
            authorized.targetRecordId,
          ],
        );
        await readClient.query("COMMIT");
        readBackAt = now.toISOString();
        const row = result.rows[0] as RecordRow | undefined;
        observed = row ? headFromRow(row) : null;
        // Recomputed from the bytes that came BACK, not from the bytes that
        // went out. This is what catches a jsonb round-trip that did not
        // preserve the value, and it is why the digest is canonical: jsonb
        // does not preserve object key order, and a stringify-and-hash would
        // report a spurious divergence on a perfectly correct read.
        readBackDigest = row
          ? memoryContentDigest(
              MemoryRecordVersionSchema.parse(row.payload).content,
            )
          : "";
      } finally {
        readClient.release();
      }
    } catch {
      return await finishUnknown(
        request,
        action,
        authorized,
        "read_back_attempted",
      );
    }

    if (observed === null || readBackDigest === "") {
      return await finishUnknown(
        request,
        action,
        authorized,
        "read_back_attempted",
      );
    }

    // THE VERSION COMES FIRST, AND THAT ORDER IS THE FIX.
    //
    // `pg_advisory_xact_lock` is released by COMMIT, and the read-back runs
    // after the commit on a different pool, taking the newest row. A
    // legitimate concurrent append landing in that window made `readBackDigest`
    // the digest of SOMEBODY ELSE'S version, and because the digest comparison
    // came first, a correct, committed mutation was durably recorded as
    // COMMITTED_READ_BACK_DIVERGED — the strongest alarm in the system firing
    // for a healthy write. Reproduced deterministically.
    //
    // A head that is not the version this mutation wrote is not evidence about
    // what this mutation wrote. It is UNKNOWN, which is exactly what the
    // post-state comparison further down already says for every other way the
    // observed head can fail to be ours; this only moves the version half of
    // that comparison ahead of the digest so divergence keeps its meaning:
    // OUR version came back holding content that is not the content we wrote.
    if (observed.version !== nextVersion) {
      return await finishUnknown(
        request,
        action,
        authorized,
        "read_back_attempted",
      );
    }

    if (readBackDigest !== proposedDigest) {
      const receipt = buildReceipt({
        request,
        action,
        scope: authorized.scope,
        authorizationId: authorized.authorizationId,
        consumedNonceDigest: authorized.nonce.bindingDigest,
        fromHead,
        emittedAt: readBackAt,
        outcome: {
          status: "COMMITTED_READ_BACK_DIVERGED",
          committedAt,
          expectedContentDigest: proposedDigest,
          readBackAt,
          readBackSource: "independent_session",
          readBackDigest,
          divergenceRef: evidenceRef(request.mutationReceiptId, "divergence"),
        },
      });
      try {
        await appendTerminal(receipt);
      } catch {
        return await finishUnknown(
          request,
          action,
          authorized,
          "read_back_attempted",
        );
      }
      return { verified: false, rejection: "read_back_diverged", receipt };
    }

    const postStateAgrees =
      observed.recordId === authorized.targetRecordId &&
      observed.version === nextVersion &&
      observed.contentDigest === proposedDigest &&
      observed.predecessorDigest === predecessorDigest &&
      observed.state === (action === "delete" ? "deleted" : "active") &&
      observed.scope.tenantId === authorized.scope.tenantId &&
      observed.scope.workspaceId === authorized.scope.workspaceId &&
      observed.scope.principalId === authorized.scope.principalId &&
      observed.scope.userId === authorized.scope.userId;
    if (!postStateAgrees) {
      // The content is the authorized content but the post-state is not the
      // post-state that was written. That is not success, and it is not a
      // content divergence either; it is unknown, and it stays unknown.
      return await finishUnknown(
        request,
        action,
        authorized,
        "read_back_attempted",
      );
    }

    const receipt = buildReceipt({
      request,
      action,
      scope: authorized.scope,
      authorizationId: authorized.authorizationId,
      consumedNonceDigest: authorized.nonce.bindingDigest,
      fromHead,
      emittedAt: readBackAt,
      outcome: {
        status: "COMMITTED_AND_READ_BACK",
        committedAt,
        resultingHead: {
          recordId: observed.recordId,
          version: observed.version,
          contentDigest: observed.contentDigest,
          scope: observed.scope,
        },
        readBackAt,
        readBackSource: "independent_session",
        readBackDigest,
      },
    });
    try {
      await appendTerminal(receipt);
    } catch {
      // The mutation committed and the read-back agreed, but the durable
      // record of that says only pending/unknown. Report what is on disk.
      return await finishUnknown(
        request,
        action,
        authorized,
        "read_back_attempted",
      );
    }
    return { verified: true, rejection: null, receipt };
  }

  return {
    correct: (request) => mutate("correct", request),
    delete: (request) => mutate("delete", request),
    readHead,
  };
}
