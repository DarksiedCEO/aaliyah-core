import type { Pool, PoolClient } from "pg";
import { enterMemoryRole } from "./pool";

/**
 * RECONCILING AN UNKNOWN OUTCOME.
 *
 * `UNKNOWN_PENDING_RECONCILIATION` is what the store records when a COMMIT did
 * not come back cleanly, or a read-back could not be performed. Until now
 * nothing consumed it: the ambiguity was persisted honestly and then sat
 * there, so "unknown" was durable but permanent.
 *
 * WHY THE VERDICT IS DETERMINATE AND NOT A GUESS. The pending receipt is
 * written on the mutation's OWN transaction, immediately before its COMMIT.
 * A durable pending row is therefore proof that the transaction committed, and
 * the absence of one is proof that it did not. Reconciliation is a reading of
 * authoritative state — never an inference from elapsed time, never a retry
 * that hopes to observe the same thing twice, and never a timeout treated as
 * a failure.
 *
 * AMBIGUITY IS NEVER CONVERTED TO SUCCESS. A `COMMITTED_*` verdict requires a
 * `memory_record_versions` row carrying this exact `mutation_receipt_id`.
 * Migration 038 makes that row unique per receipt, so the evidence is the
 * mutation itself rather than something that resembles it. Anything that does
 * not resolve to one of the four verdicts is escalated as `IMPOSSIBLE_STATE`,
 * which is a durable alarm, not a silent pass.
 *
 * THE RECONCILER CANNOT MUTATE. It runs as `aaliyah_memory_reconciler`, which
 * holds SELECT on the evidence tables and INSERT on `memory_reconciliations`
 * and nothing else — no INSERT on `memory_record_versions`, no consumption
 * UPDATE. "Reconciliation never produces a duplicate mutation" is a privilege
 * boundary enforced by PostgreSQL, not a property of this file's control flow.
 */

/** Four verdicts, and every one of them names what was observed. */
export const MEMORY_RECONCILIATION_VERDICTS = [
  /** The mutation committed and the stored content is what was authorized. */
  "COMMITTED_CONFIRMED",
  /** The mutation committed and the stored content is NOT what was authorized. */
  "COMMITTED_DIVERGED",
  /** The transaction never landed. Nothing was written, nothing was spent. */
  "NOT_COMMITTED",
  /** The evidence contradicts itself. Never resolved here; raised. */
  "IMPOSSIBLE_STATE",
] as const;
export type MemoryReconciliationVerdict =
  (typeof MEMORY_RECONCILIATION_VERDICTS)[number];

export type MemoryReconciliationScope = {
  tenantId: string;
  workspaceId: string;
  principalId: string;
  userId: string;
};

export type UnresolvedMutation = {
  scope: MemoryReconciliationScope;
  mutationReceiptId: string;
  authorizationId: string;
  action: string;
  targetRecordId: string;
};

export type MemoryReconciliation = {
  scope: MemoryReconciliationScope;
  mutationReceiptId: string;
  authorizationId: string;
  action: string;
  targetRecordId: string;
  verdict: MemoryReconciliationVerdict;
  observedVersion: number | null;
  observedContentDigest: string | null;
  reconciledAt: string;
  evidence: Record<string, unknown>;
  /** True when this call found an existing verdict rather than writing one. */
  alreadyReconciled: boolean;
};

const RECONCILER_ROLE = "aaliyah_memory_reconciler";
// UNIT SEPARATOR, written as an escape. NOT NUL: PostgreSQL text cannot
// carry a 0x00 byte, so a NUL-joined lock key is rejected by the server
// with "invalid byte sequence for encoding UTF8" rather than hashing to
// anything. Matches LOCK_KEY_SEPARATOR in the trusted-memory store.
const LOCK_SEPARATOR = "\u001f";

type ReconciliationRow = {
  tenant_id: string;
  workspace_id: string;
  principal_id: string;
  user_id: string;
  mutation_receipt_id: string;
  authorization_id: string;
  action: string;
  target_record_id: string;
  verdict: MemoryReconciliationVerdict;
  observed_version: number | null;
  observed_content_digest: string | null;
  reconciled_at: Date;
  evidence: Record<string, unknown>;
};

function fromRow(row: ReconciliationRow, alreadyReconciled: boolean): MemoryReconciliation {
  return {
    scope: {
      tenantId: row.tenant_id,
      workspaceId: row.workspace_id,
      principalId: row.principal_id,
      userId: row.user_id,
    },
    mutationReceiptId: row.mutation_receipt_id,
    authorizationId: row.authorization_id,
    action: row.action,
    targetRecordId: row.target_record_id,
    verdict: row.verdict,
    observedVersion: row.observed_version,
    observedContentDigest: row.observed_content_digest,
    reconciledAt: row.reconciled_at.toISOString(),
    evidence: row.evidence,
    alreadyReconciled,
  };
}

export type MemoryReconcilerOptions = {
  /** Overridable so a test can prove the role is what confines this. */
  reconcilerRole?: string;
  /** How long one reconciliation waits for a lock before failing. */
  lockWaitMs?: number;
};

/** Default bound on a reconciliation's lock waits. */
export const RECONCILER_LOCK_WAIT_MS = 5_000;

export function createPostgresMemoryReconciler(
  pool: Pool,
  options: MemoryReconcilerOptions = {},
) {
  const role = options.reconcilerRole ?? RECONCILER_ROLE;
  const lockWaitMs = options.lockWaitMs ?? RECONCILER_LOCK_WAIT_MS;
  if (!Number.isSafeInteger(lockWaitMs) || lockWaitMs <= 0) {
    throw new Error("memory reconciler: lockWaitMs must be a positive integer");
  }

  async function enterRole(client: PoolClient): Promise<void> {
    // Quoted and validated: a role name is an identifier and cannot be bound
    // as a parameter, so it must not be caller-shaped text.
    if (!/^[a-z_][a-z0-9_]*$/.test(role)) {
      throw new Error(`unsafe reconciler role: ${role}`);
    }
    // Least privilege AND a pinned search path (K-07): `"$user"` off the
    // path, `pg_temp` last. One helper, so no call site can forget either.
    await enterMemoryRole(client, role);
  }

  /**
   * MUTATIONS WHOSE LAST WORD IS STILL "UNKNOWN".
   *
   * Excludes anything that later reached a real terminal outcome, and anything
   * already reconciled — so a restarted worker picks up exactly what is left
   * rather than re-deciding settled history.
   */
  async function findUnresolved(limit = 100): Promise<UnresolvedMutation[]> {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await enterRole(client);
      const result = await client.query(
        `SELECT DISTINCT r.tenant_id, r.workspace_id, r.principal_id, r.user_id,
                r.mutation_receipt_id, r.authorization_id, r.action,
                r.target_record_id
           FROM memory_mutation_receipts AS r
          WHERE r.outcome_status = 'UNKNOWN_PENDING_RECONCILIATION'
            -- Settled only by a COMMITTED terminal. Against b3efc82 this read
            -- "any terminal that is not UNKNOWN", so an ABORTED row squatting
            -- the same id hid a genuinely committed mutation from
            -- reconciliation forever. Migration 045 now refuses ABORTED rows
            -- in this table; this no longer depends on that.
            AND NOT EXISTS (
              SELECT 1 FROM memory_mutation_receipts AS t
               WHERE t.tenant_id = r.tenant_id
                 AND t.workspace_id = r.workspace_id
                 AND t.mutation_receipt_id = r.mutation_receipt_id
                 AND t.phase = 'terminal'
                 AND t.outcome_status IN ('COMMITTED_AND_READ_BACK',
                                          'COMMITTED_READ_BACK_DIVERGED'))
            AND NOT EXISTS (
              SELECT 1 FROM memory_reconciliations AS c
               WHERE c.tenant_id = r.tenant_id
                 AND c.workspace_id = r.workspace_id
                 AND c.mutation_receipt_id = r.mutation_receipt_id)
          ORDER BY r.mutation_receipt_id
          LIMIT $1`,
        [limit],
      );
      await client.query("COMMIT");
      return result.rows.map((row: ReconciliationRow) => ({
        scope: {
          tenantId: row.tenant_id,
          workspaceId: row.workspace_id,
          principalId: row.principal_id,
          userId: row.user_id,
        },
        mutationReceiptId: row.mutation_receipt_id,
        authorizationId: row.authorization_id,
        action: row.action,
        targetRecordId: row.target_record_id,
      }));
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  async function readExisting(
    client: PoolClient,
    scope: MemoryReconciliationScope,
    mutationReceiptId: string,
  ): Promise<ReconciliationRow | undefined> {
    const result = await client.query(
      `SELECT * FROM memory_reconciliations
        WHERE tenant_id = $1 AND workspace_id = $2 AND mutation_receipt_id = $3
        LIMIT 1`,
      [scope.tenantId, scope.workspaceId, mutationReceiptId],
    );
    return result.rows[0] as ReconciliationRow | undefined;
  }

  /**
   * RECONCILE ONE MUTATION.
   *
   * Idempotent by two independent mechanisms, because either alone leaves a
   * race: the advisory lock serialises workers that arrive together, and the
   * table's UNIQUE constraint refuses a second verdict even if a worker
   * somehow bypassed the lock. A conflict is not an error — it means somebody
   * else answered first, and their answer is returned.
   */
  async function reconcile(
    unresolved: UnresolvedMutation,
  ): Promise<MemoryReconciliation> {
    const { scope, mutationReceiptId } = unresolved;
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      // Bounded, for the same reason the mutation path is: a reconciliation
      // that waits forever on a wedged holder is a boot that never listens.
      await client.query("SELECT set_config('lock_timeout', $1, true)", [
        `${lockWaitMs}ms`,
      ]);
      await enterRole(client);
      await client.query(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
        [
          [scope.tenantId, scope.workspaceId, mutationReceiptId].join(
            LOCK_SEPARATOR,
          ),
        ],
      );

      const existing = await readExisting(client, scope, mutationReceiptId);
      if (existing !== undefined) {
        await client.query("COMMIT");
        return fromRow(existing, true);
      }

      // ---- THE PENDING ROW: DID THE TRANSACTION COMMIT? -----------------
      const pending = await client.query(
        `SELECT 1 FROM memory_mutation_receipts
          WHERE tenant_id = $1 AND workspace_id = $2
            AND mutation_receipt_id = $3 AND phase = 'pending'
          LIMIT 1`,
        [scope.tenantId, scope.workspaceId, mutationReceiptId],
      );
      const pendingPresent = pending.rowCount === 1;

      // ---- THE MUTATION ITSELF ------------------------------------------
      // Resolved by mutation receipt id, which migration 038 makes unique per
      // record version. Deliberately NOT resolved by head: a later mutation
      // may have advanced the record since, and this one still committed.
      const version = await client.query(
        `SELECT version, content_digest, state, record_id, authorization_id,
                predecessor_digest
           FROM memory_record_versions
          WHERE tenant_id = $1 AND workspace_id = $2
            AND mutation_receipt_id = $3
          LIMIT 1`,
        [scope.tenantId, scope.workspaceId, mutationReceiptId],
      );
      const versionRow = version.rows[0] as
        | {
            version: number;
            content_digest: string;
            state: string;
            record_id: string;
            authorization_id: string;
            predecessor_digest: string | null;
          }
        | undefined;

      // ---- WHAT WAS AUTHORIZED ------------------------------------------
      // Resolved from the STORED unknown receipt, never from the caller's
      // description of it. Red team M2 against b3efc82: handed an unrelated
      // authorization id, `reconcile()` turned a correct committed mutation
      // into a durable COMMITTED_DIVERGED — the strongest alarm in the
      // system — and the once-only constraint made the wrong verdict permanent.
      const recorded = await client.query(
        `SELECT DISTINCT principal_id, user_id, authorization_id, action,
                target_record_id
           FROM memory_mutation_receipts
          WHERE tenant_id = $1 AND workspace_id = $2
            AND mutation_receipt_id = $3
            AND outcome_status = 'UNKNOWN_PENDING_RECONCILIATION'`,
        [scope.tenantId, scope.workspaceId, mutationReceiptId],
      );
      if (recorded.rowCount !== 1) {
        throw new Error(
          recorded.rowCount === 0
            ? `reconciliation for ${mutationReceiptId}: no unknown outcome is on record`
            : `reconciliation for ${mutationReceiptId}: its unknown receipts disagree about the mutation`,
        );
      }
      const stored = recorded.rows[0] as {
        principal_id: string;
        user_id: string;
        authorization_id: string;
        action: string;
        target_record_id: string;
      };
      if (
        stored.principal_id !== scope.principalId ||
        stored.user_id !== scope.userId ||
        stored.authorization_id !== unresolved.authorizationId ||
        stored.action !== unresolved.action ||
        stored.target_record_id !== unresolved.targetRecordId
      ) {
        // Nothing is filed. A request that does not describe the mutation on
        // record is not a request to reconcile it.
        throw new Error(
          `reconciliation for ${mutationReceiptId}: the request does not match the unknown outcome on record`,
        );
      }
      const authorization = await client.query(
        `SELECT payload FROM memory_authorization_receipts
          WHERE tenant_id = $1 AND authorization_id = $2 LIMIT 1`,
        [scope.tenantId, stored.authorization_id],
      );
      const authorizationPayload = authorization.rows[0]?.payload as
        | Record<string, unknown>
        | undefined;
      const authorizedDigest =
        (authorizationPayload?.["proposedContentDigest"] as string | undefined) ?? null;
      const authorizedHead = authorizationPayload?.["expectedHead"] as
        | { version?: unknown; contentDigest?: unknown }
        | undefined;

      // ---- AN ALIAS MUTATION'S OWN EFFECT -------------------------------
      // Red team BREAK B against 2b2e554: an alias authorization binds a
      // KEYED digest, never the version's content digest, so comparing the
      // two filed every correct alias mutation as DIVERGED. Migration 052
      // derives the alias verdict from what stored state can prove, and this
      // mirrors it exactly: the authorization's own version extended the
      // head it authorized, and its alias effect is on record under it.
      const aliasAction =
        stored.action === "assign_alias" || stored.action === "remove_alias";
      let aliasEffectPresent: boolean | null = null;
      if (aliasAction) {
        const effect = await client.query(
          `SELECT aaliyah_memory_alias_effect_present($1, $2, $3, $4, $5, $6) AS present`,
          [
            scope.tenantId,
            scope.workspaceId,
            stored.action,
            mutationReceiptId,
            stored.authorization_id,
            stored.target_record_id,
          ],
        );
        aliasEffectPresent = effect.rows[0]?.present === true;
      }

      let verdict: MemoryReconciliationVerdict;
      let escalation: string | null = null;
      if (pendingPresent && versionRow !== undefined) {
        // The content is compared against the AUTHORIZATION, not against what
        // the caller said it sent. A committed row holding something nobody
        // approved is a divergence, and it is reported as one rather than
        // being rounded up to success because the row exists.
        verdict = aliasAction
          ? aliasEffectPresent === true &&
            versionRow.record_id === stored.target_record_id &&
            versionRow.authorization_id === stored.authorization_id &&
            versionRow.state === "active" &&
            typeof authorizedHead?.version === "number" &&
            versionRow.version === authorizedHead.version + 1 &&
            versionRow.predecessor_digest === (authorizedHead.contentDigest ?? null)
            ? "COMMITTED_CONFIRMED"
            : "COMMITTED_DIVERGED"
          : authorizedDigest !== null &&
              versionRow.content_digest === authorizedDigest
            ? "COMMITTED_CONFIRMED"
            : "COMMITTED_DIVERGED";
      } else if (!pendingPresent && versionRow === undefined) {
        verdict = "NOT_COMMITTED";
      } else {
        // The pending receipt and the record version are written by ONE
        // transaction. Observing one without the other means something
        // outside that transaction wrote or removed a row, and no verdict
        // about this mutation can be honestly derived from it.
        verdict = "IMPOSSIBLE_STATE";
        escalation = pendingPresent
          ? "pending receipt present with no record version"
          : "record version present with no pending receipt";
      }

      const observedVersion =
        verdict === "COMMITTED_CONFIRMED" || verdict === "COMMITTED_DIVERGED"
          ? (versionRow?.version ?? null)
          : null;
      const observedDigest =
        verdict === "COMMITTED_CONFIRMED" || verdict === "COMMITTED_DIVERGED"
          ? (versionRow?.content_digest ?? null)
          : null;

      const reconciledAt = new Date().toISOString();
      const evidence: Record<string, unknown> = {
        schemaVersion: "aaliyah.trusted-memory.reconciliation/v1",
        mutationReceiptId,
        authorizationId: unresolved.authorizationId,
        action: unresolved.action,
        targetRecordId: unresolved.targetRecordId,
        // The raw observations, so the verdict can be re-derived from the
        // record rather than taken on the reconciler's word.
        pendingReceiptPresent: pendingPresent,
        recordVersionPresent: versionRow !== undefined,
        authorizedContentDigest: authorizedDigest,
        // For alias actions the verdict is NOT a digest comparison; the
        // observations it rests on are recorded instead (migration 052).
        derivation: aliasAction ? "alias_effect_and_authorized_head" : "content_digest",
        authorizedHeadVersion:
          typeof authorizedHead?.version === "number" ? authorizedHead.version : null,
        aliasEffectPresent,
        observedContentDigest: versionRow?.content_digest ?? null,
        observedState: versionRow?.state ?? null,
        escalation,
        reconciledAt,
      };

      const inserted = await client.query(
        `INSERT INTO memory_reconciliations
           (tenant_id, workspace_id, principal_id, user_id, mutation_receipt_id,
            authorization_id, action, target_record_id, verdict,
            observed_version, observed_content_digest, reconciled_at, evidence)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
         ON CONFLICT ON CONSTRAINT memory_reconciliations_once DO NOTHING
         RETURNING *`,
        [
          scope.tenantId,
          scope.workspaceId,
          scope.principalId,
          scope.userId,
          mutationReceiptId,
          unresolved.authorizationId,
          unresolved.action,
          unresolved.targetRecordId,
          verdict,
          observedVersion,
          observedDigest,
          reconciledAt,
          JSON.stringify(evidence),
        ],
      );

      if (inserted.rowCount === 1) {
        await client.query("COMMIT");
        return fromRow(inserted.rows[0] as ReconciliationRow, false);
      }

      // Somebody else got there first. Theirs stands; this one does not
      // overwrite it, and does not pretend to have written it.
      const winner = await readExisting(client, scope, mutationReceiptId);
      await client.query("COMMIT");
      if (winner === undefined) {
        throw new Error(
          `reconciliation for ${mutationReceiptId} neither inserted nor readable`,
        );
      }
      return fromRow(winner, true);
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  /** Reconcile every unresolved mutation currently visible. */
  async function reconcileAll(limit = 100): Promise<MemoryReconciliation[]> {
    const unresolved = await findUnresolved(limit);
    const results: MemoryReconciliation[] = [];
    for (const item of unresolved) {
      // Sequential on purpose: each takes a transaction and an advisory lock,
      // and a batch that opened one connection per mutation would exhaust a
      // small pool exactly when the system is already unhealthy.
      results.push(await reconcile(item));
    }
    return results;
  }

  async function readReconciliation(
    scope: MemoryReconciliationScope,
    mutationReceiptId: string,
  ): Promise<MemoryReconciliation | null> {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await enterRole(client);
      const row = await readExisting(client, scope, mutationReceiptId);
      await client.query("COMMIT");
      return row === undefined ? null : fromRow(row, true);
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  return { findUnresolved, reconcile, reconcileAll, readReconciliation };
}
