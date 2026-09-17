import {
  MemoryAuthorizationIdSchema,
  MemoryAuthorizationReceiptSchema,
  MemoryIdSchema,
  MemoryMutationReceiptSchema,
  MemoryTombstoneSchema,
  type MemoryAbortReason,
  type MemoryAction,
  type MemoryAuthorizationReceipt,
  type MemoryExpectedHead,
  type MemoryMutationPhase,
  type MemoryMutationReceipt,
  type MemoryScope,
  type MemoryTombstone,
} from "@aaliyah/contracts/v1";
import type { Pool, PoolClient } from "pg";

import {
  identityCounterparty,
  parseIdentityMergeOrder,
  parseIdentitySplitOrder,
  type MemoryIdentityEdgeKind,
} from "../../application/memory/wave1MemoryIdentity";
import {
  buildTombstone,
  destroyedContentFieldNames,
  parseDeletionOrder,
  unknownDerivativeDispositions,
} from "../../application/memory/wave1MemoryErasure";
import {
  MEMORY_RECORD_VERSION_SCHEMA_VERSION,
  MemoryRecordVersionSchema,
  memoryContentDigest,
  type MemoryRecordVersion,
  type TrustedMemoryActor,
  type TrustedMemoryDeleteRequest,
  type TrustedMemoryDeleteResult,
  type TrustedMemoryHead,
  type TrustedMemoryMutationRequest,
  type TrustedMemoryMutationResult,
  type TrustedMemoryRecord,
  type TrustedMemoryRejection,
  type TrustedMemoryStore,
} from "../../application/memory/wave1TrustedMemory";
import { appendMutationAttempt } from "./memoryMutationAttempts";
import { MEMORY_CANONICAL_RESOLUTION_MAX_DEPTH } from "../../application/memory/wave1MemoryService";
import type { MemoryPiiKeyProvider } from "../../crypto/memoryPiiKeys";

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
 * WAVE 1.3 PART F CLOSED TWO OF THE GAPS THIS HEADER USED TO DISCLOSE.
 *
 * LEGAL HOLDS ARE CONSULTED AND ENFORCED. `restrictingHoldOn()` below runs
 * inside the mutation transaction, BEFORE the nonce is consumed, for EVERY
 * action this store performs — correct, delete, restore and promote — not only
 * for delete. That ordering matters twice: a held record refuses without
 * burning the approver's authorization, and the caller receives an
 * `ABORTED_NO_MUTATION` receipt carrying the contract's `legal_hold_active`
 * reason, which no code path could reach before. The ENFORCEMENT POINT is
 * still not this file: migration 036 puts the same lookup in an AFTER INSERT
 * trigger on `memory_record_versions` that reads the action from the consumed
 * nonce, so a hostile writer holding `aaliyah_memory_mutator` and issuing a
 * direct INSERT is refused by the database. Deleting the check here changes
 * the error a caller sees; it does not make the write possible.
 *
 * `delete()` IS ERASURE. It no longer advances the head to a `deleted` label
 * over intact content. Inside one transaction it appends the deletion version,
 * writes a `MemoryTombstone` accounting for exactly which field names were
 * destroyed and which chain metadata was retained, and NULLS
 * `payload->'content'` on every prior version of the record. The deferred
 * constraint trigger `memory_record_versions_deletion_erases` refuses at COMMIT
 * any deleted head that still has an unerased predecessor, for every writer.
 *
 * ERASURE VERSUS APPEND-ONLY, RESOLVED. Chain METADATA — version, state,
 * digests, authorization linkage, the four scope columns — remains immutable
 * and append-only; only `payload->'content'` is mutable, exactly once, under a
 * tombstone. Every integrity property migration 034 enforces is stated over the
 * metadata, so all of them still hold after an erasure and the chain stays
 * walkable. The full argument is in the header of migration 037.
 *
 * WHAT ERASURE STILL DOES NOT DO, SAID PLAINLY. Nulling a jsonb member writes a
 * new heap tuple; the pre-image survives in the old tuple until VACUUM, in the
 * WAL, in every replica, and in any physical backup taken beforehand. This
 * store cannot speak for those and does not: the tombstone records
 * `unknown` propagation rather than a reassurance. The retained
 * `content_digest` also remains an unkeyed oracle for guessed content
 * (W1BR-008). Erasure removes the plaintext from the live row. That is the
 * claim, and it is the whole claim.
 */

const RECORD_COLUMNS = `id, tenant_id, workspace_id, principal_id, user_id,
  record_id, version, state, content_digest, predecessor_digest,
  authorization_id, mutation_receipt_id, payload`;

/** The same members, minus the surrogate key the view does not expose. */
const RETRIEVABLE_COLUMNS = `tenant_id, workspace_id, principal_id, user_id,
  record_id, version, state, content_digest, predecessor_digest,
  authorization_id, mutation_receipt_id, payload`;

const TOMBSTONE_COLUMNS = `tenant_id, workspace_id, principal_id, user_id,
  tombstone_id, target_record_id, target_version, tombstone_version,
  authorization_id, mutation_receipt_id, reason, effective_at, retain_until,
  legal_hold_state, cache_index_propagation, restoration_eligibility_kind,
  tombstone_digest, payload`;

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
  identity_order_malformed: "policy_rejected",
  identity_counterparty_invalid: "policy_rejected",
  identity_counterparty_missing: "policy_rejected",
  identity_counterparty_merged_away: "policy_rejected",
  record_merged_away: "policy_rejected",
  merged_records_not_erased: "policy_rejected",
  identity_chain_too_deep: "policy_rejected",
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
  // THE REASON THAT WAS UNREACHABLE. `legal_hold_active` existed in the
  // contract's abort enum and nothing in Core could ever emit it, because
  // nothing in Core consulted a hold. This is the one mapping that makes it
  // reachable, and the tests that exercise it are the evidence.
  legal_hold_active: "legal_hold_active",
  retention_obligation_active: "policy_rejected",
  deletion_order_malformed: "policy_rejected",
  restore_head_not_deleted: "policy_rejected",
  record_deleted: "policy_rejected",
  erasure_incomplete: "storage_rejected",
  // The contract's abort vocabulary has no "busy"; a lock that could not be
  // taken is a refusal by storage, and nothing was mutated or consumed.
  record_busy: "storage_rejected",
  mutation_receipt_id_reused: "policy_rejected",
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
  /**
   * How long a mutation waits for ANY lock — the record's advisory lock, a
   * row lock on the nonce — before refusing with `record_busy`. Set on the
   * transaction itself, so it holds whatever pool the store was handed.
   */
  lockWaitMs?: number;
  /**
   * The provider holding alias data keys. A deletion erases the subject's
   * alias envelopes and indexes in the database regardless; destroying the
   * KEYS needs the provider, and without one the deletion reports the erasure
   * incomplete rather than done.
   */
  piiKeys?: MemoryPiiKeyProvider | null;
};

/** Default bound on a mutation's lock waits. */
export const TRUSTED_MEMORY_LOCK_WAIT_MS = 5_000;

/** SQLSTATE `lock_not_available`: a `lock_timeout` expired. */
const LOCK_NOT_AVAILABLE = "55P03";

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
  const lockWaitMs = options.lockWaitMs ?? TRUSTED_MEMORY_LOCK_WAIT_MS;
  const piiKeys = options.piiKeys ?? null;
  if (!Number.isSafeInteger(lockWaitMs) || lockWaitMs <= 0) {
    // Zero is PostgreSQL's "wait forever". Refused at construction so it can
    // never be configured by accident.
    throw new Error("trusted memory: lockWaitMs must be a positive integer");
  }

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

  /**
   * THE EXPECTED-HEAD SHAPE THIS ACTION IS ALLOWED TO CARRY.
   *
   * `MemoryMutationReceiptSchema` refines a BICONDITIONAL: a receipt names
   * `no_prior_version` if and only if its action is `create`. Stated once,
   * here, because the three paths below all build receipts and a copy of this
   * rule in each is three rules — and the one that drifts turns a refusal into
   * an unparseable receipt, which is the same as no evidence at all.
   */
  function expectedHeadKindFor(action: MemoryAction): MemoryExpectedHead["kind"] {
    return action === "create" ? "no_prior_version" : "version";
  }

  async function finishUnknown(
    request: TrustedMemoryMutationRequest,
    action: MemoryAction,
    stored: MemoryAuthorizationReceipt | null,
    phase: MemoryMutationPhase,
  ): Promise<TrustedMemoryMutationResult> {
    if (
      stored === null ||
      stored.expectedHead.kind !== expectedHeadKindFor(action)
    ) {
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
   *
   * `create` IS THE EXCEPTION, AND IT NARROWS THAT GAP. A genesis receipt is
   * required by the contract to carry `no_prior_version`, which is a CONSTANT:
   * there is nothing to observe, so nothing to be unable to observe. An
   * unresolved `create` is therefore audited whether or not the record exists,
   * including the enumeration case the limit above describes — probing ids
   * that are absent is exactly what a `create` sweep looks like.
   */
  async function auditUnresolvedAttempt(
    request: TrustedMemoryMutationRequest,
    action: MemoryAction,
    rejection: TrustedMemoryRejection,
  ): Promise<void> {
    let fromHead: MemoryExpectedHead;
    if (action === "create") {
      fromHead = { kind: "no_prior_version" };
    } else {
      const head = await readHead(request.actor, request.recordId).catch(
        () => null,
      );
      if (head === null) return;
      fromHead = {
        kind: "version",
        version: head.version,
        contentDigest: head.contentDigest,
      };
    }
    const at = new Date().toISOString();
    const receipt = MemoryMutationReceiptSchema.parse({
      schemaVersion: "aaliyah.trusted-memory/v1",
      mutationReceiptId: request.mutationReceiptId,
      authorizationId: request.authorizationId,
      consumedNonceDigest: UNRESOLVED_NONCE_DIGEST,
      action,
      scope: request.actor,
      targetRecordId: request.recordId,
      fromHead,
      emittedAt: at,
      outcome: {
        status: "ABORTED_NO_MUTATION",
        abortedAt: at,
        abortReason: "policy_rejected",
      },
    });
    // An ATTEMPT, filed where attempts go — never as a terminal mutation
    // receipt under an id a later real mutation may carry. See
    // memoryMutationAttempts.ts.
    await appendMutationAttempt({ pool, role: mutationRole, receipt, rejection }).catch(
      () => undefined,
    );
  }

  async function abortResult(
    request: TrustedMemoryMutationRequest,
    action: MemoryAction,
    stored: MemoryAuthorizationReceipt | null,
    rejection: TrustedMemoryRejection,
  ): Promise<TrustedMemoryMutationResult> {
    if (
      stored === null ||
      stored.expectedHead.kind !== expectedHeadKindFor(action)
    ) {
      // Not enough real stored state to fill a structurally valid receipt for
      // the CALLER. The attempt is still written down.
      await auditUnresolvedAttempt(request, action, rejection);
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
    await appendMutationAttempt({ pool, role: mutationRole, receipt, rejection }).catch(
      () => undefined,
    );
    return { verified: false, rejection, receipt };
  }

  /**
   * WHICH HOLD RESTRICTS THIS ACTION ON THIS RECORD, OR NULL.
   *
   * Deliberately the SAME SQL FUNCTION the AFTER INSERT trigger calls, rather
   * than a second implementation of the same rule in TypeScript. Two
   * implementations of one policy is two policies, and the one that drifts is
   * always the one nobody is testing. This call is the caller's ANSWER; the
   * trigger is the ENFORCEMENT, and the trigger is what binds a writer that
   * never comes through this function.
   */
  async function restrictingHoldOn(
    client: PoolClient,
    scope: MemoryScope,
    recordId: string,
    action: MemoryAction,
  ): Promise<string | null> {
    const result = await client.query(
      `SELECT public.aaliyah_memory_restricting_hold($1, $2, $3, NULL, $4)
                AS hold_id`,
      [scope.tenantId, scope.workspaceId, recordId, action],
    );
    return (result.rows[0]?.hold_id as string | null) ?? null;
  }

  async function mutate(
    action: Extract<
      MemoryAction,
      | "create"
      | "correct"
      | "delete"
      | "restore"
      | "promote"
      | "merge_identity"
      | "split_identity"
    >,
    request: TrustedMemoryMutationRequest,
    deletion: TrustedMemoryDeleteRequest | null = null,
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
    // Null is the GENESIS value, not "not yet known": version 1 has no
    // predecessor, and writing a digest there would forge a chain link to a
    // version that never existed.
    let predecessorDigest: string | null = "";
    // The head this mutation compared against, kept for the post-commit
    // comparison and for the erasure sweep. Null for a `create`, which is
    // the one action that expects to find nothing.
    let priorHead: TrustedMemoryHead | null = null;
    let deletionOrder: ReturnType<typeof parseDeletionOrder> = null;
    // The identity order and the counterparty it names, filled in only for the
    // two graph actions. Null everywhere else, so the edge write below cannot
    // fire for an action that never parsed one.
    let identityEdge:
      | { kind: MemoryIdentityEdgeKind; toRecordId: string; reason: string; evidenceRef: string }
      | null = null;

    // ---- WHICH RECORDS THIS MUTATION MUST HOLD --------------------------
    // Every action holds the record it targets. A merge or split ALSO holds
    // the counterparty, because its checks read the counterparty's head and
    // its incoming merge edges — and read unlocked, under READ COMMITTED,
    // neither sees a concurrent transaction's uncommitted write. Falsified
    // against b3efc82: `merge A->B` racing `merge B->A` closed a cycle on the
    // first trial, and `merge A->B` racing `delete B` merged into a destroyed
    // record.
    //
    // The counterparty is read from the PROPOSED content, before anything is
    // resolved, because the lock has to be held before the first read. That
    // is safe: content that does not digest to what was authorized is refused
    // below, so a caller naming some other record gains at most a lock on it,
    // never a mutation.
    //
    // Sorted, so two transactions locking one pair from opposite ends take it
    // in the same order and cannot deadlock. Migration 043 takes the same keys
    // in the same order inside the database.
    const lockRecordIds = new Set<string>([request.recordId]);
    if (action === "merge_identity" || action === "split_identity") {
      const order =
        action === "merge_identity"
          ? parseIdentityMergeOrder(request.proposedContent)
          : parseIdentitySplitOrder(request.proposedContent);
      if (order !== null) {
        const counterpartyId = identityCounterparty(order).recordId;
        if (MemoryIdSchema.safeParse(counterpartyId).success) {
          lockRecordIds.add(counterpartyId);
        }
      }
    }
    const lockKeys = [...lockRecordIds]
      .map((recordId) =>
        [request.actor.tenantId, request.actor.workspaceId, recordId].join(
          LOCK_KEY_SEPARATOR,
        ),
      )
      .sort();

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      // BOUNDED. Found by the b3efc82 reliability review: with the record's
      // advisory lock held elsewhere, `create()` was still pending after 8s
      // with no error, holding a pool slot, and nothing anywhere bounded it.
      // Transaction-local, so it cannot leak onto the pooled connection.
      await client.query("SELECT set_config('lock_timeout', $1, true)", [
        `${lockWaitMs}ms`,
      ]);
      await enterRole(client, mutationRole);
      // Single-flight on the record — and, for an identity change, on its
      // counterparty. Two writers racing the same head serialize here, so the
      // loser reads the winner's head and fails its compare-and-swap rather
      // than both reading the stale one.
      for (const lockKey of lockKeys) {
        await client.query(
          "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
          [lockKey],
        );
      }
      const txNow = (await client.query("SELECT now() AS tx_now")).rows[0]
        .tx_now as Date;

      // ---- A RECEIPT ID NAMES ONE MUTATION ------------------------------
      // An id that already carries a receipt — pending or terminal — is that
      // mutation's identity. Reusing it would make this mutation's evidence
      // collide with the earlier one's, which is exactly how a committed,
      // read-back-verified mutation was filed as UNKNOWN against b3efc82.
      // Refused before anything is resolved or spent. Migration 045 refuses
      // the same reuse in the database.
      const spentReceiptId = await client.query(
        `SELECT 1 FROM memory_mutation_receipts
          WHERE tenant_id = $1 AND workspace_id = $2
            AND mutation_receipt_id = $3
          LIMIT 1`,
        [
          request.actor.tenantId,
          request.actor.workspaceId,
          request.mutationReceiptId,
        ],
      );
      if (spentReceiptId.rowCount === 1) {
        throw new MutationAborted("mutation_receipt_id_reused");
      }

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
      // A GENESIS NAMES THE ABSENCE IT EXPECTS; EVERY OTHER ACTION NAMES A
      // CONCRETE PREDECESSOR. A `create` carrying a version would be a genesis
      // grant with a compare-and-swap target, which is an approval that can be
      // aimed at an existing chain. A `correct` carrying `no_prior_version`
      // would have no CAS target at all.
      //
      // DISCLOSED UNREACHABLE BACKSTOP. No test in this repository can kill
      // this branch, and the reason is structural rather than an oversight:
      // `MemoryAuthorizationReceiptSchema` refines the same pair as a
      // BICONDITIONAL, so a crossed authorization fails `safeParse` above and
      // is refused as `authorization_malformed` before reaching here; and
      // `stored.action !== action` is refused between the two, so by this line
      // the stored action IS this action and the refinement has already fixed
      // the expected-head kind. Kept because the property it states is the one
      // the contract depends on, and a weakened refinement would otherwise
      // leave nothing checking it in Core. Reported as a surviving mutant, not
      // claimed as a tested control. The REACHABLE refusal is proven in
      // "a stored create authorization rewritten to name a version is refused
      // as malformed".
      if (action === "create") {
        if (stored.expectedHead.kind !== "no_prior_version") {
          throw new MutationAborted("authorization_expected_head_mismatch");
        }
      } else if (stored.expectedHead.kind !== "version") {
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

      // ---- THE LEGAL HOLD, BEFORE ANYTHING IS SPENT ---------------------
      // EVERY action, not only delete. The confirmed defect was a hold that
      // gated deletion alone, which left `correct` — a schema that REQUIRES
      // the content to change — as a supported, audited path to rewriting
      // held evidence. Checked BEFORE the consumption UPDATE below so a held
      // record refuses without burning the approver's authorization.
      if (
        (await restrictingHoldOn(
          client,
          stored.scope,
          stored.targetRecordId,
          action,
        )) !== null
      ) {
        throw new MutationAborted("legal_hold_active");
      }

      // ---- A MERGED-AWAY RECORD IS CLOSED TO MUTATION -------------------
      // Checked here, alongside the hold and BEFORE the consumption UPDATE, so
      // a mutation aimed at an absorbed record refuses without burning the
      // approver's authorization. Migration 041 carries the same rule as a
      // trigger, which is what binds writers that never come through here;
      // this is the caller's ANSWER, that is the ENFORCEMENT.
      //
      // One exception, and only one: a SUBJECT ERASURE of the absorbed record
      // (red team BREAK A against 2b2e554). Without it a merge put the
      // subject's address beyond erasure for good. Migration 051 admits the
      // same single exception in the freeze trigger.
      const subjectErasure =
        action === "delete" &&
        parseDeletionOrder(request.proposedContent)?.reason ===
          "subject_erasure_request";
      const mergedAway = await client.query(
        `SELECT 1 FROM memory_identity_edges
          WHERE tenant_id = $1 AND workspace_id = $2
            AND from_record_id = $3 AND kind = 'merged_into'
          LIMIT 1`,
        [
          stored.scope.tenantId,
          stored.scope.workspaceId,
          stored.targetRecordId,
        ],
      );
      if (mergedAway.rowCount === 1 && !subjectErasure) {
        throw new MutationAborted("record_merged_away");
      }
      if (subjectErasure) {
        // A survivor's erasure does not reach the records merged into it, and
        // must not report success over them. Refused before consumption; the
        // database refuses the tombstone on the same terms.
        const unerased = await client.query(
          `SELECT r FROM aaliyah_memory_unerased_merged_records($1, $2, $3) AS r LIMIT 1`,
          [
            stored.scope.tenantId,
            stored.scope.workspaceId,
            stored.targetRecordId,
          ],
        );
        if (unerased.rowCount !== 0) {
          throw new MutationAborted("merged_records_not_erased");
        }
      }

      if (action === "delete") {
        // ---- THE RETENTION CLOCK ----------------------------------------
        // A separate obligation from a hold, refused separately, so each has
        // its own killing test. `now()` is the transaction's clock, not the
        // application's.
        const obligation = await client.query(
          `SELECT max(retain_until) AS retain_until
             FROM memory_retention_obligations
            WHERE tenant_id = $1 AND workspace_id = $2 AND record_id = $3
              AND retain_until > now()`,
          [
            stored.scope.tenantId,
            stored.scope.workspaceId,
            stored.targetRecordId,
          ],
        );
        if ((obligation.rows[0]?.retain_until as Date | null) !== null) {
          throw new MutationAborted("retention_obligation_active");
        }
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
      const head = headRow ? headFromRow(headRow) : null;

      if (action === "create") {
        // ---- THE COMPARE-AND-SWAP IS AGAINST ABSENCE --------------------
        //
        // Any head refuses the genesis, WHATEVER STATE IT IS IN. A `deleted`
        // head is still a head: if this looked only for an `active` record, a
        // destroyed record could be re-founded with a fresh version 1 sitting
        // on top of its own tombstone, the erasure accounting would still
        // describe a chain nobody could reach, and the record would read as
        // though the destruction never happened. Returning a deleted record
        // to service is `restore`, under its own authority, over the chain
        // that is already there.
        //
        // There is no owner comparison here and there cannot be one: the
        // record does not exist, so there is no prior owner to continue. The
        // owner of a genesis IS the authorization's scope, and all four of
        // its dimensions were compared against the AUTHENTICATED actor above,
        // each in its own statement.
        //
        // THAT SENTENCE WAS AN UNENFORCED CLAIM WHEN IT WAS FIRST WRITTEN,
        // and an independent security review executed the consequence. The
        // comment here used to cite migration 034, which pins ownership
        // CONTINUITY — version N+1 may not change principal or user from
        // version N — on the path taken when a prior version is found. A
        // genesis never reaches it. So the mutation role, holding one
        // legitimately issued `create` authorization for its own scope, wrote
        // version 1 under another principal and user in another workspace,
        // and the victim's own reads returned it. Migration 039 is what makes
        // the claim true: it binds a genesis row's workspace, principal and
        // user to the authorization its id resolves to, in the database,
        // where it binds writers that never come through this function.
        if (head !== null) throw new MutationAborted("head_mismatch");
      } else {
        if (head === null) throw new MutationAborted("head_mismatch");
        // Refused above for every non-create action; restated so the
        // narrowing below is a control and not a type assertion.
        if (expectedHead.kind !== "version") {
          throw new MutationAborted("authorization_expected_head_mismatch");
        }
        priorHead = head;

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

        // ---- RESTORATION IS A SEPARATE AUTHORITY --------------------------
        // The contract binds the ACTION into the nonce, so a `delete` receipt
        // relabelled as `restore` no longer matches its own token, and
        // `stored.action !== action` above refuses a receipt handed to the
        // wrong call site. These two statements are the STATE half: a restore
        // only ever lifts a deleted head, and nothing but a restore may append
        // onto one. Migration 037 pins exactly the same pair in the database,
        // reading the action from the consumed nonce, for writers that never
        // come through here.
        if (action === "restore" && head.state !== "deleted") {
          throw new MutationAborted("restore_head_not_deleted");
        }
        if (action !== "restore" && head.state === "deleted") {
          throw new MutationAborted("record_deleted");
        }

        if (action === "delete") {
          // The reason and the order reference are the APPROVER's, carried
          // inside the content the authorization's digest binds. A caller
          // cannot name a reason nobody approved.
          //
          // Checked HERE, after ownership and the compare-and-swap, so that an
          // attacker aiming a delete at somebody else's record is still told
          // `record_owner_mismatch`: the more specific refusal must not be
          // masked by a shape complaint about the attacker's own payload.
          deletionOrder = parseDeletionOrder(request.proposedContent);
          if (deletionOrder === null) {
            throw new MutationAborted("deletion_order_malformed");
          }
        }

        if (action === "merge_identity" || action === "split_identity") {
          // ---- THE GRAPH CHANGE THE APPROVER AUTHORIZED -----------------
          // The counterparty is read out of the AUTHORIZED content, whose
          // digest the approval is bound to, so a caller cannot redirect a
          // merge at a record nobody approved.
          //
          // Parsed AFTER ownership and the compare-and-swap, for the same
          // reason the deletion order is: an attacker aiming a merge at
          // somebody else's record must still be told `record_owner_mismatch`
          // rather than a shape complaint about their own payload.
          const order =
            action === "merge_identity"
              ? parseIdentityMergeOrder(request.proposedContent)
              : parseIdentitySplitOrder(request.proposedContent);
          if (order === null) {
            throw new MutationAborted("identity_order_malformed");
          }
          const counterparty = identityCounterparty(order);
          // A self-edge would freeze the record against every future mutation
          // while reading as a legitimate graph entry.
          if (counterparty.recordId === stored.targetRecordId) {
            throw new MutationAborted("identity_counterparty_invalid");
          }
          // BOTH ENDS MUST ALREADY EXIST, ACTIVE, IN THIS ACTOR'S SCOPE.
          // Read on the mutating connection so it is the same transaction the
          // edge is written in; migration 041's trigger carries the same rule
          // for writers that never come through here.
          const other = await client.query(
            `SELECT ${RECORD_COLUMNS}
               FROM memory_record_versions
              WHERE tenant_id = $1 AND workspace_id = $2
                AND principal_id = $3 AND user_id = $4
                AND record_id = $5
              ORDER BY id DESC
              LIMIT 1`,
            [
              stored.scope.tenantId,
              stored.scope.workspaceId,
              stored.scope.principalId,
              stored.scope.userId,
              counterparty.recordId,
            ],
          );
          const otherRow = other.rows[0] as RecordRow | undefined;
          if (!otherRow || headFromRow(otherRow).state !== "active") {
            throw new MutationAborted("identity_counterparty_missing");
          }
          // A MERGE MAY NOT POINT AT A RECORD THAT WAS ITSELF MERGED AWAY.
          // Naming one is a merge into a ghost, and A-into-B followed by
          // B-into-A closes a cycle that a read-time resolver walks forever.
          // `state` does not catch it: a merge freezes, it does not delete, so
          // an absorbed record's head is still `active`. Migration 042 carries
          // the same rule as a trigger.
          //
          // Merges only. A `split_to` edge may name a record that is later
          // absorbed, because a split records history rather than a redirect.
          if (counterparty.kind === "merged_into") {
            const counterpartyMerged = await client.query(
              `SELECT 1 FROM memory_identity_edges
                WHERE tenant_id = $1 AND workspace_id = $2
                  AND from_record_id = $3 AND kind = 'merged_into'
                LIMIT 1`,
              [
                stored.scope.tenantId,
                stored.scope.workspaceId,
                counterparty.recordId,
              ],
            );
            if (counterpartyMerged.rowCount === 1) {
              throw new MutationAborted("identity_counterparty_merged_away");
            }
            // Red team M3 against 2b2e554: a chain longer than the resolver
            // walks makes every identity on it unresolvable, for good.
            // Migration 053 refuses the edge under a workspace graph lock;
            // this answers first, by name.
            const hops = await client.query(
              `SELECT aaliyah_memory_merge_chain_hops($1, $2, $3, $4) AS hops`,
              [
                stored.scope.tenantId,
                stored.scope.workspaceId,
                stored.targetRecordId,
                counterparty.recordId,
              ],
            );
            if ((hops.rows[0].hops as number) > MEMORY_CANONICAL_RESOLUTION_MAX_DEPTH) {
              throw new MutationAborted("identity_chain_too_deep");
            }
          }
          identityEdge = {
            kind: counterparty.kind,
            toRecordId: counterparty.recordId,
            reason: order.reason,
            evidenceRef: order.reasonEvidenceRef,
          };
        }
      }

      // ---- 6. WRITE THE NEW VERSION -------------------------------------
      // A genesis is version 1 with NO predecessor. Every other action
      // advances the head it just compared against, and chains to its digest.
      if (priorHead === null) {
        nextVersion = 1;
        predecessorDigest = null;
      } else {
        nextVersion = priorHead.version + 1;
        predecessorDigest = priorHead.contentDigest;
      }
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

      // ---- 6a. THE IDENTITY EDGE, INSIDE THE SAME TRANSACTION -----------
      // Written AFTER the record version deliberately. The freeze trigger on
      // `memory_record_versions` refuses a version on a record that already
      // has an outgoing merge edge, and it is a non-deferred AFTER ROW
      // trigger — so writing the edge first would make the merge refuse its
      // own version. Both land or neither does.
      if (identityEdge !== null) {
        await client.query(
          `INSERT INTO memory_identity_edges
             (tenant_id, workspace_id, principal_id, user_id, kind,
              from_record_id, to_record_id, from_version, authorization_id,
              mutation_receipt_id, reason, reason_evidence_ref, effective_at,
              payload)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
          [
            stored.scope.tenantId,
            stored.scope.workspaceId,
            stored.scope.principalId,
            stored.scope.userId,
            identityEdge.kind,
            stored.targetRecordId,
            identityEdge.toRecordId,
            nextVersion,
            stored.authorizationId,
            request.mutationReceiptId,
            identityEdge.reason,
            identityEdge.evidenceRef,
            committedAt,
            JSON.stringify({
              kind: identityEdge.kind,
              fromRecordId: stored.targetRecordId,
              toRecordId: identityEdge.toRecordId,
              fromVersion: nextVersion,
              authorizationId: stored.authorizationId,
              mutationReceiptId: request.mutationReceiptId,
              reason: identityEdge.reason,
              reasonEvidenceRef: identityEdge.evidenceRef,
              effectiveAt: committedAt,
            }),
          ],
        );
      }

      // ---- 6b. ERASURE, INSIDE THE SAME TRANSACTION ---------------------
      //
      // Everything below happens before COMMIT, so a deletion is all of it or
      // none of it. The database refuses the half-done state independently:
      // `memory_record_versions_deletion_erases` is a DEFERRED constraint
      // trigger that fires at COMMIT and rejects a deleted head that still
      // has an unerased predecessor, no matter who wrote it.
      if (action === "delete" && deletionOrder !== null) {
        // `delete` always compared against a head — the branch above throws
        // `head_mismatch` when there is none — so this is a contradiction,
        // not a skippable case. Refused rather than silently erasing nothing
        // and reporting a destruction that did not happen.
        if (priorHead === null) throw new MutationAborted("head_mismatch");
        // The field names are computed from the content that was ACTUALLY
        // stored, never from a caller's description of it.
        const priorResult = await client.query(
          `SELECT version, payload
             FROM memory_record_versions
            WHERE tenant_id = $1 AND workspace_id = $2 AND record_id = $3
              AND version <= $4
              AND content_erased_at IS NULL
            ORDER BY version ASC`,
          [
            stored.scope.tenantId,
            stored.scope.workspaceId,
            stored.targetRecordId,
            priorHead.version,
          ],
        );
        const destroyedFieldNames = destroyedContentFieldNames(
          priorResult.rows.map(
            (row: { payload: unknown }) =>
              MemoryRecordVersionSchema.parse(row.payload).content,
          ),
        );

        // A hold that was RELEASED is recorded, because "there was a hold and
        // it was lifted" and "there was never a hold" are different facts
        // about a destruction. An ACTIVE hold cannot be here: the check above
        // already aborted, and the tombstone's own CHECK refuses `held`.
        const releasedHold = await client.query(
          `SELECT h.hold_id, h.released_at
             FROM memory_legal_holds AS h
            WHERE h.tenant_id = $1 AND h.workspace_id = $2
              AND h.status_state = 'released'
              AND (h.coverage_kind = 'entire_scope'
                   OR h.coverage_kind = 'subjects'
                   OR EXISTS (SELECT 1 FROM memory_legal_hold_records AS r
                               WHERE r.tenant_id = h.tenant_id
                                 AND r.workspace_id = h.workspace_id
                                 AND r.hold_id = h.hold_id
                                 AND r.record_id = $3))
            ORDER BY h.released_at DESC
            LIMIT 1`,
          [
            stored.scope.tenantId,
            stored.scope.workspaceId,
            stored.targetRecordId,
          ],
        );
        const heldRow = releasedHold.rows[0] as
          | { hold_id: string; released_at: Date }
          | undefined;

        // Every obligation over this record has expired — the live ones
        // aborted above — so this is the latest one that ever bound it.
        const retention = await client.query(
          `SELECT max(retain_until) AS retain_until
             FROM memory_retention_obligations
            WHERE tenant_id = $1 AND workspace_id = $2 AND record_id = $3`,
          [
            stored.scope.tenantId,
            stored.scope.workspaceId,
            stored.targetRecordId,
          ],
        );
        const retainUntil =
          (retention.rows[0]?.retain_until as Date | null) ?? null;

        const tombstone = buildTombstone({
          tombstoneId: deletion?.tombstoneId ?? request.mutationReceiptId,
          scope: stored.scope,
          targetRecordId: stored.targetRecordId,
          targetVersion: priorHead.version,
          tombstoneVersion: nextVersion,
          deletionAuthority: {
            authorizationId: stored.authorizationId,
            authorityId: stored.approverAuthorityId,
            approverActorId: stored.approverActorId,
            executingActorId: request.actor.userId,
          },
          order: deletionOrder,
          effectiveAt: committedAt,
          retainUntil: retainUntil === null ? null : retainUntil.toISOString(),
          legalHoldState: heldRow
            ? {
                state: "released",
                holdId: heldRow.hold_id,
                releasedAt: heldRow.released_at.toISOString(),
              }
            : { state: "none" },
          destroyedFieldNames,
          derivedData:
            deletion?.derivedData ?? unknownDerivativeDispositions(),
          cacheIndexPropagation: deletion?.cacheIndexPropagation ?? "unknown",
          downstreamPropagation: deletion?.downstreamPropagation ?? [],
        });

        await client.query(
          `INSERT INTO memory_tombstones (${TOMBSTONE_COLUMNS})
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
          [
            tombstone.scope.tenantId,
            tombstone.scope.workspaceId,
            tombstone.scope.principalId,
            tombstone.scope.userId,
            tombstone.tombstoneId,
            tombstone.targetRecordId,
            tombstone.targetVersion,
            tombstone.tombstoneVersion,
            tombstone.deletionAuthority.authorizationId,
            request.mutationReceiptId,
            tombstone.reason,
            tombstone.effectiveAt,
            tombstone.retention.retainUntil,
            tombstone.retention.legalHoldState.state,
            tombstone.cacheIndexPropagation,
            tombstone.restorationEligibility.kind,
            tombstone.tombstoneDigest,
            JSON.stringify(tombstone),
          ],
        );

        // THE DESTRUCTION ITSELF. `payload->'content'` becomes JSON null on
        // every version that still held content. Nothing else on the row is
        // touched, which is what keeps migration 034's chain properties true
        // after an erasure, and the rewrite guard refuses any other shape of
        // update for every writer including the owner.
        const erased = await client.query(
          `UPDATE memory_record_versions
              SET payload = jsonb_set(payload, '{content}', 'null'::jsonb),
                  content_erased_at = now(),
                  erasure_tombstone_id = $5
            WHERE tenant_id = $1 AND workspace_id = $2 AND record_id = $3
              AND version <= $4
              AND content_erased_at IS NULL`,
          [
            stored.scope.tenantId,
            stored.scope.workspaceId,
            stored.targetRecordId,
            priorHead.version,
            tombstone.tombstoneId,
          ],
        );
        // ---- 6c. THE SUBJECT'S ALIASES, IN THE SAME TRANSACTION ----------
        //
        // Red team BREAK 4 against b3efc82: the record's content was destroyed
        // and the subject's email address survived, active and in cleartext,
        // in the alias registry. Every binding naming this participant — active
        // or already retired, under any principal — loses its envelope and is
        // retired; its blind indexes are nulled; and each data key is recorded
        // as due for destruction. Migration 047 refuses the COMMIT if any
        // binding naming this participant is left unerased, and refuses the
        // binding update without this tombstone or under a legal hold.
        const erasedAliases = await client.query(
          `UPDATE memory_alias_bindings
              SET removed_at = COALESCE(removed_at, now()),
                  pii_envelope = NULL,
                  pii_erased_at = now(),
                  pii_erasure_tombstone_id = $4
            WHERE tenant_id = $1 AND workspace_id = $2
              AND canonical_participant_id = $3
              AND pii_erased_at IS NULL
          RETURNING alias_id, mutation_receipt_id, pii_key_ref,
                    payload->'pii'->>'providerId' AS provider_id`,
          [
            stored.scope.tenantId,
            stored.scope.workspaceId,
            stored.targetRecordId,
            tombstone.tombstoneId,
          ],
        );
        const aliasRows = erasedAliases.rows as Array<{
          alias_id: string;
          mutation_receipt_id: string;
          pii_key_ref: string;
          provider_id: string;
        }>;
        if (aliasRows.length > 0) {
          await client.query(
            `UPDATE memory_alias_blind_indexes
                SET index_value = NULL, active = false,
                    erased_at = now(), erasure_tombstone_id = $4
              WHERE tenant_id = $1 AND workspace_id = $2
                AND binding_mutation_receipt_id = ANY($3::text[])
                AND erased_at IS NULL`,
            [
              stored.scope.tenantId,
              stored.scope.workspaceId,
              aliasRows.map((row) => row.mutation_receipt_id),
              tombstone.tombstoneId,
            ],
          );
          for (const row of aliasRows) {
            await client.query(
              `INSERT INTO memory_pii_key_erasures
                 (tenant_id, workspace_id, tombstone_id, alias_id,
                  binding_mutation_receipt_id, key_ref, provider_id, event)
               VALUES ($1,$2,$3,$4,$5,$6,$7,'erasure_committed')`,
              [
                stored.scope.tenantId,
                stored.scope.workspaceId,
                tombstone.tombstoneId,
                row.alias_id,
                row.mutation_receipt_id,
                row.pii_key_ref,
                row.provider_id,
              ],
            );
          }
        }

        if (erased.rowCount !== priorResult.rowCount) {
          // A partial erasure is not a deletion. Unwind rather than report a
          // destruction that did not happen.
          //
          // DISCLOSED REDUNDANT BACKSTOP. No test in this repository can kill
          // this branch: both counts come from the same predicate inside one
          // transaction holding the record's advisory lock, so they cannot
          // diverge in process. It is kept because the property it states is
          // the one the reviewed defect violated, and the DATABASE carries it
          // independently — dropping
          // `memory_record_versions_deletion_erases` fails the suite. Reported
          // as a surviving mutant, not claimed as a tested control.
          throw new MutationAborted("erasure_incomplete");
        }
      }

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
      } else if (
        !commitIssued &&
        (error as { code?: unknown } | null)?.code === LOCK_NOT_AVAILABLE
      ) {
        // Somebody else holds this record. Nothing was consumed — the
        // ROLLBACK above undid everything — and the answer says so
        // specifically, rather than as a generic storage failure a caller
        // cannot distinguish from a broken database.
        failure = { kind: "abort", rejection: "record_busy" };
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
    // `no_prior_version` is the LEGITIMATE expected head of a genesis, and for
    // no other action. Reaching the read-back with that pair mismatched means
    // the commit went through under an expected head this action never
    // accepts, which is not something to report a verdict on.
    if (
      fromHead.kind !== (action === "create" ? "no_prior_version" : "version")
    ) {
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

    // DISCLOSED UNREACHABLE CONJUNCTS. Four of the nine comparisons below can
    // never be false by the time they run, and no test can kill them — the
    // b3efc82 mutation sweep confirmed each survives (A54 recordId, A55
    // version, A59 tenantId, A60 workspaceId). `recordId`, `tenantId` and
    // `workspaceId` are the read-back query's own WHERE predicates, bound to
    // exactly these values; `version` is refused earlier, above, by
    // `observed.version !== nextVersion`. They are kept because the receipt
    // they gate states all nine, and a later change to the read-back query
    // would otherwise silently drop a comparison nobody could see was implied.
    // The five REACHABLE conjuncts — content digest, predecessor digest,
    // state, principal and user — each have a killing test (W1BR-013).
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

  /**
   * READ A TOMBSTONE BACK, ON THE INDEPENDENT POOL.
   *
   * All four scope dimensions are predicates, for the same reason `readHead`
   * uses four: filtering on tenant and workspace alone lets another principal
   * in the same workspace read an accounting of somebody else's destruction,
   * including the authority that ordered it.
   */
  async function readTombstone(
    actor: TrustedMemoryActor,
    tombstoneId: string,
  ): Promise<MemoryTombstone | null> {
    if (!MemoryIdSchema.safeParse(tombstoneId).success) return null;
    const client = await readBackPool.connect();
    try {
      await client.query("BEGIN");
      await enterRole(client, readBackRole);
      const result = await client.query(
        `SELECT payload FROM memory_tombstones
          WHERE tenant_id = $1 AND workspace_id = $2 AND tombstone_id = $3
            AND principal_id = $4 AND user_id = $5
          LIMIT 1`,
        [
          actor.tenantId,
          actor.workspaceId,
          tombstoneId,
          actor.principalId,
          actor.userId,
        ],
      );
      await client.query("COMMIT");
      const row = result.rows[0] as { payload: unknown } | undefined;
      if (!row) return null;
      const parsed = MemoryTombstoneSchema.safeParse(row.payload);
      // A stored value that does not parse is not a tombstone. Answering
      // null is the fail-closed reading: "no accounting was read back", never
      // "here is an accounting we could not validate".
      return parsed.success ? parsed.data : null;
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * ORDINARY RETRIEVAL.
   *
   * Reads `memory_records_retrievable`, which is a VIEW in migration 037 that
   * excludes any record whose head is `deleted` and any version whose content
   * has been erased. The exclusion is therefore a property of the relation,
   * not a WHERE clause a future caller can forget. `readHead` deliberately
   * still answers for a deleted record, because a compare-and-swap has to be
   * able to see the head it is swapping against — a restore would otherwise be
   * impossible.
   */
  async function retrieve(
    actor: TrustedMemoryActor,
    recordId: string,
  ): Promise<TrustedMemoryRecord | null> {
    if (!MemoryIdSchema.safeParse(recordId).success) return null;
    const client = await readBackPool.connect();
    try {
      await client.query("BEGIN");
      await enterRole(client, readBackRole);
      const result = await client.query(
        `SELECT ${RETRIEVABLE_COLUMNS}
           FROM memory_records_retrievable
          WHERE tenant_id = $1 AND workspace_id = $2 AND record_id = $3
            AND principal_id = $4 AND user_id = $5
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
      if (!row) return null;
      const parsed = MemoryRecordVersionSchema.parse(row.payload);
      const head = headFromRow(row);
      return {
        recordId: head.recordId,
        version: head.version,
        contentDigest: head.contentDigest,
        content: parsed.content,
        scope: head.scope,
      };
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * DELETE, WHICH IS ERASURE, AND THEN AN INDEPENDENT READ-BACK OF THE
   * ACCOUNTING.
   *
   * The tombstone is NOT returned from the writing transaction. It is read
   * back on the read-back pool, on a different connection under the SELECT-only
   * role, exactly as the head is — because a tombstone the writer hands back
   * to itself proves only that the writer built one. A verified deletion whose
   * accounting cannot be read back is reported as `erasure_incomplete` and
   * never as success.
   */
  /**
   * DESTROY THE DATA KEYS WHOSE ERASURE COMMITTED, and record each one the
   * provider CONFIRMS. Filtered to one tombstone after a deletion, or across
   * the whole store for the boot-time completion pass.
   */
  async function destroyCommittedAliasKeys(filter: {
    tenantId?: string;
    workspaceId?: string;
    tombstoneId?: string;
    limit: number;
  }): Promise<{ destroyed: number; pending: number; erased: number }> {
    const client = await pool.connect();
    let due: Array<{
      tenant_id: string;
      workspace_id: string;
      tombstone_id: string;
      alias_id: string;
      binding_mutation_receipt_id: string;
      key_ref: string;
      provider_id: string;
      evidenced: boolean;
    }>;
    let erased = 0;
    try {
      await client.query("BEGIN");
      await enterRole(client, mutationRole);
      const found = await client.query(
        // Keys already EVIDENCED destroyed are included too, after the rest.
        // Red team M2 against 2b2e554: the mutation role could insert a
        // `key_destroyed` row for a key that was still alive, and this pass
        // then never looked at it again. The database cannot see a key
        // outside it, so the evidence row is not trusted here: the provider
        // is asked, and a contradicted row's key is destroyed.
        `SELECT c.tenant_id, c.workspace_id, c.tombstone_id, c.alias_id,
                c.binding_mutation_receipt_id, c.key_ref, c.provider_id,
                EXISTS (
                  SELECT 1 FROM memory_pii_key_erasures AS d
                   WHERE d.tenant_id = c.tenant_id AND d.workspace_id = c.workspace_id
                     AND d.key_ref = c.key_ref AND d.event = 'key_destroyed') AS evidenced
           FROM memory_pii_key_erasures AS c
          WHERE c.event = 'erasure_committed'
            AND ($1::text IS NULL OR c.tenant_id = $1)
            AND ($2::text IS NULL OR c.workspace_id = $2)
            AND ($3::text IS NULL OR c.tombstone_id = $3)
          ORDER BY evidenced, c.id
          LIMIT $4`,
        [filter.tenantId ?? null, filter.workspaceId ?? null, filter.tombstoneId ?? null, filter.limit],
      );
      due = found.rows;
      if (filter.tombstoneId !== undefined) {
        erased = (
          await client.query(
            `SELECT count(*)::int AS n FROM memory_pii_key_erasures
              WHERE tenant_id = $1 AND workspace_id = $2 AND tombstone_id = $3
                AND event = 'erasure_committed'`,
            [filter.tenantId, filter.workspaceId, filter.tombstoneId],
          )
        ).rows[0].n as number;
      }
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }

    let destroyed = 0;
    let settled = 0;
    for (const row of due) {
      if (piiKeys === null || row.provider_id !== piiKeys.providerId) continue;
      if (row.evidenced) {
        const claimed = await piiKeys
          .dataKeyState({
            scope: { tenantId: row.tenant_id, workspaceId: row.workspace_id },
            keyRef: row.key_ref,
          })
          .catch(() => null);
        if (claimed === "destroyed") {
          settled += 1;
          continue;
        }
      }
      try {
        await piiKeys.destroyDataKey({
          scope: { tenantId: row.tenant_id, workspaceId: row.workspace_id },
          keyRef: row.key_ref,
        });
        // Confirmed by asking again, not by trusting the call's return.
        const state = await piiKeys.dataKeyState({
          scope: { tenantId: row.tenant_id, workspaceId: row.workspace_id },
          keyRef: row.key_ref,
        });
        if (state !== "destroyed") continue;
      } catch {
        continue;
      }
      const writer = await pool.connect();
      try {
        await writer.query("BEGIN");
        await enterRole(writer, mutationRole);
        await writer.query(
          `INSERT INTO memory_pii_key_erasures
             (tenant_id, workspace_id, tombstone_id, alias_id,
              binding_mutation_receipt_id, key_ref, provider_id, event)
           VALUES ($1,$2,$3,$4,$5,$6,$7,'key_destroyed')
           ON CONFLICT ON CONSTRAINT memory_pii_key_erasures_once DO NOTHING`,
          [
            row.tenant_id,
            row.workspace_id,
            row.tombstone_id,
            row.alias_id,
            row.binding_mutation_receipt_id,
            row.key_ref,
            row.provider_id,
          ],
        );
        await writer.query("COMMIT");
        destroyed += 1;
      } catch {
        await writer.query("ROLLBACK").catch(() => undefined);
      } finally {
        writer.release();
      }
    }
    return { destroyed, pending: due.length - settled - destroyed, erased };
  }

  /**
   * DELETE, WHICH IS ERASURE, AND THEN AN INDEPENDENT READ-BACK OF THE
   * ACCOUNTING.
   *
   * The tombstone is NOT returned from the writing transaction. It is read
   * back on the read-back pool, on a different connection under the SELECT-only
   * role, exactly as the head is — because a tombstone the writer hands back
   * to itself proves only that the writer built one. A verified deletion whose
   * accounting cannot be read back is reported as `erasure_incomplete` and
   * never as success.
   *
   * THE SAME HOLDS FOR THE SUBJECT'S ALIASES. After the tombstone reads back,
   * every data key the deleting transaction recorded as due is destroyed by the
   * provider and confirmed. A key the provider did not confirm leaves the
   * deletion `erasure_incomplete`: the database has forgotten the identifier,
   * but a copy of its ciphertext somewhere else could still be decrypted, and
   * that is not an erasure.
   */
  async function deleteRecord(
    request: TrustedMemoryDeleteRequest,
  ): Promise<TrustedMemoryDeleteResult> {
    const result = await mutate("delete", request, request);
    if (!result.verified) return { ...result, tombstone: null, aliasErasure: null };
    const tombstoneId = request.tombstoneId ?? request.mutationReceiptId;
    const tombstone = await readTombstone(request.actor, tombstoneId).catch(() => null);
    const keys = await destroyCommittedAliasKeys({
      tenantId: request.actor.tenantId,
      workspaceId: request.actor.workspaceId,
      tombstoneId,
      limit: 10_000,
    }).catch(() => null);
    const aliasErasure =
      keys === null
        ? null
        : {
            bindingsErased: keys.erased,
            keysDestroyed: keys.erased - keys.pending,
            keysPending: keys.pending,
          };
    if (tombstone === null || aliasErasure === null || aliasErasure.keysPending > 0) {
      return {
        verified: false,
        rejection: "erasure_incomplete",
        receipt: result.receipt,
        tombstone,
        aliasErasure,
      };
    }
    return { ...result, tombstone, aliasErasure };
  }

  return {
    create: (request) => mutate("create", request),
    correct: (request) => mutate("correct", request),
    delete: deleteRecord,
    completePendingAliasErasures: async (limit = 100) => {
      const done = await destroyCommittedAliasKeys({ limit });
      return { destroyed: done.destroyed, pending: done.pending };
    },
    restore: (request) => mutate("restore", request),
    promote: (request) => mutate("promote", request),
    mergeIdentity: (request) => mutate("merge_identity", request),
    splitIdentity: (request) => mutate("split_identity", request),
    readHead,
    retrieve,
    readTombstone,
  };
}
