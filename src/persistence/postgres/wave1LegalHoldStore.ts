import {
  LegalHoldSchema,
  MEMORY_ACTIONS_NEVER_CARVED_OUT,
  type LegalHold,
  type MemoryAction,
} from "@aaliyah/contracts/v1";
import type { Pool, PoolClient } from "pg";
import { enterMemoryRole, releaseClient } from "./pool";

import {
  MemoryRetentionObligationSchema,
  type LegalHoldResult,
  type LegalHoldStore,
  type LegalHoldView,
  type ReleaseHoldRequest,
} from "../../application/memory/wave1LegalHold";
import type { TrustedMemoryActor } from "../../application/memory/wave1TrustedMemory";

/**
 * PostgreSQL legal-hold and retention store.
 *
 * WHY THIS IS A SEPARATE STORE UNDER A SEPARATE ROLE.
 * ---------------------------------------------------
 * The point of a hold is that the party being restrained cannot lift it. If
 * the mutation role could place, narrow or release a hold, the hold would be
 * an advisory note. Migration 036 grants `aaliyah_memory_hold_officer` the
 * INSERT and the release UPDATE, and grants `aaliyah_memory_mutator` SELECT
 * and nothing else — the same argument migration 032 makes about the alias
 * policy tables, and the same argument migration 029 makes about the issuer.
 *
 * This file runs every write under the hold officer. It is not a convenience:
 * a store that used the owner would pass whether or not the privilege split
 * existed, and the split is the control.
 *
 * WHAT THIS STORE DOES NOT DO. It does not enforce anything. A hold row is
 * inert. Enforcement is `aaliyah_memory_restricting_hold` and the AFTER INSERT
 * triggers migration 036 installs on `memory_record_versions` and
 * `memory_alias_bindings`, and those bind writers that never load this module.
 *
 * RELEASE IS MONOTONIC AND COVERAGE IS IMMUTABLE. The
 * `memory_legal_holds_release_only` trigger permits exactly one transition,
 * active to released, refuses DELETE outright, and refuses any release that
 * also rewrites the hold's coverage or its matter. Narrowing a hold by editing
 * what it covers is not representable; the only narrowing is a carve-out row,
 * and the four spoliation-capable actions cannot be carved out at all.
 */

const ROLE_NAME = /^[a-z][a-z0-9_]{0,62}$/u;

const HOLD_COLUMNS = `tenant_id, workspace_id, principal_id, user_id, hold_id,
  matter_ref, issuing_authority_id, issued_at, coverage_kind, status_state,
  released_at, releasing_authority_id, release_order_ref, payload`;

export type LegalHoldStoreOptions = {
  /**
   * Role every WRITE runs as. Defaults to the least-privilege hold officer
   * created by migration 036, which can place and release a hold and impose a
   * retention obligation, and can do nothing at all to a record version, an
   * authorization or a nonce. Pass null only where the deployment cannot grant
   * role membership, and understand that removes the boundary.
   */
  holdRole?: string | null;
  /** Role the independent read-back runs as. SELECT only. */
  readRole?: string | null;
};

function assertRole(name: string | null, label: string): string | null {
  if (name === null) return null;
  if (!ROLE_NAME.test(name)) {
    throw new Error(`legal hold: ${label} is not a valid role identifier`);
  }
  return name;
}

type HoldRow = {
  tenant_id: string;
  workspace_id: string;
  principal_id: string;
  user_id: string;
  hold_id: string;
  payload: unknown;
};

export function createPostgresLegalHoldStore(
  pool: Pool,
  readPool: Pool,
  options: LegalHoldStoreOptions = {},
): LegalHoldStore {
  if (readPool === pool) {
    // Same reason as the trusted-memory store: a read-back through the writing
    // pool is the writer marking its own homework.
    throw new Error(
      "legal hold: the read-back pool must be independent of the writing pool",
    );
  }
  const holdRole = assertRole(
    options.holdRole === undefined
      ? "aaliyah_memory_hold_officer"
      : options.holdRole,
    "holdRole",
  );
  const readRole = assertRole(
    options.readRole === undefined ? "aaliyah_memory_reader" : options.readRole,
    "readRole",
  );

  async function enterRole(
    client: PoolClient,
    role: string | null,
  ): Promise<void> {
    // Least privilege AND a pinned search path (K-07): `"$user"` off the
    // path, `pg_temp` last. The null-role early return that used to sit above
    // this skipped the path pinning too — and the pinning is the part that
    // matters even when no role is dropped into.
    await enterMemoryRole(client, role);
  }

  async function inWriteTransaction<T>(
    run: (client: PoolClient) => Promise<T>,
  ): Promise<T> {
    const client = await pool.connect();
    let ambiguous: unknown;
    try {
      await client.query("BEGIN");
      await enterRole(client, holdRole);
      const value = await run(client);
      await client.query("COMMIT");
      return value;
    } catch (error) {
      ambiguous = error;
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      releaseClient(client, ambiguous);
    }
  }

  async function placeHold(
    actor: TrustedMemoryActor,
    candidate: unknown,
  ): Promise<LegalHoldResult> {
    const parsed = LegalHoldSchema.safeParse(candidate);
    if (!parsed.success) {
      return { recorded: false, rejection: "hold_malformed" };
    }
    const hold: LegalHold = parsed.data;
    // The ACTOR is authoritative, exactly as on the mutation path: a hold is
    // never filed under the scope it names if that is not the scope of the
    // party placing it.
    if (
      hold.scope.tenantId !== actor.tenantId ||
      hold.scope.workspaceId !== actor.workspaceId ||
      hold.scope.principalId !== actor.principalId ||
      hold.scope.userId !== actor.userId
    ) {
      return { recorded: false, rejection: "hold_scope_mismatch" };
    }
    // Redundant with `memory_legal_hold_carve_outs_never` and with the
    // contract's own refinement, and kept as an ANSWER rather than a control:
    // it turns a database check violation into a named rejection for the
    // caller. Disclosed as redundant; the database is what enforces it.
    if (
      hold.carveOuts.some((carveOut) =>
        (MEMORY_ACTIONS_NEVER_CARVED_OUT as readonly MemoryAction[]).includes(
          carveOut.action,
        ),
      )
    ) {
      return { recorded: false, rejection: "hold_carve_out_forbidden" };
    }
    try {
      await inWriteTransaction(async (client) => {
        await client.query(
          `INSERT INTO memory_legal_holds (${HOLD_COLUMNS})
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
          [
            hold.scope.tenantId,
            hold.scope.workspaceId,
            hold.scope.principalId,
            hold.scope.userId,
            hold.holdId,
            hold.matterRef,
            hold.issuingAuthorityId,
            hold.issuedAt,
            hold.coverage.kind,
            hold.status.state,
            hold.status.state === "released" ? hold.status.releasedAt : null,
            hold.status.state === "released"
              ? hold.status.releasingAuthorityId
              : null,
            hold.status.state === "released"
              ? hold.status.releaseOrderRef
              : null,
            JSON.stringify(hold),
          ],
        );
        if (hold.coverage.kind === "records") {
          for (const recordId of hold.coverage.recordIds) {
            await client.query(
              `INSERT INTO memory_legal_hold_records
                 (tenant_id, workspace_id, hold_id, coverage_kind, record_id)
               VALUES ($1,$2,$3,'records',$4)`,
              [
                hold.scope.tenantId,
                hold.scope.workspaceId,
                hold.holdId,
                recordId,
              ],
            );
          }
        }
        if (hold.coverage.kind === "subjects") {
          for (const participantId of hold.coverage.canonicalParticipantIds) {
            await client.query(
              `INSERT INTO memory_legal_hold_subjects
                 (tenant_id, workspace_id, hold_id, coverage_kind,
                  canonical_participant_id)
               VALUES ($1,$2,$3,'subjects',$4)`,
              [
                hold.scope.tenantId,
                hold.scope.workspaceId,
                hold.holdId,
                participantId,
              ],
            );
          }
        }
        for (const carveOut of hold.carveOuts) {
          await client.query(
            `INSERT INTO memory_legal_hold_carve_outs
               (tenant_id, workspace_id, hold_id, action, order_ref,
                granting_authority_id, granted_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7)`,
            [
              hold.scope.tenantId,
              hold.scope.workspaceId,
              hold.holdId,
              carveOut.action,
              carveOut.orderRef,
              carveOut.grantingAuthorityId,
              carveOut.grantedAt,
            ],
          );
        }
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : "";
      if (/memory_legal_holds_unique/u.test(message)) {
        return { recorded: false, rejection: "hold_already_exists" };
      }
      if (/memory_legal_hold_carve_outs_never/u.test(message)) {
        return { recorded: false, rejection: "hold_carve_out_forbidden" };
      }
      return { recorded: false, rejection: "storage_rejected" };
    }
    // READ BACK, on the independent pool, before saying it was recorded.
    const observed = await readHold(actor, hold.holdId).catch(() => null);
    if (observed === null) {
      return { recorded: false, rejection: "storage_rejected" };
    }
    return { recorded: true, rejection: null };
  }

  async function releaseHold(
    request: ReleaseHoldRequest,
  ): Promise<LegalHoldResult> {
    const existing = await readHold(request.actor, request.holdId).catch(
      () => null,
    );
    if (existing === null) {
      return { recorded: false, rejection: "hold_not_found" };
    }
    if (existing.hold.status.state !== "active") {
      // DISCLOSED REDUNDANT BACKSTOP, reported as a surviving mutant rather
      // than claimed as a tested control. Removing this branch leaves the
      // suite GREEN, because the UPDATE below carries
      // `AND status_state = 'active'` and answers `hold_not_active` from a
      // rowCount of zero — executed, and the observable is identical. It is
      // kept because it is the branch that distinguishes the two outcomes
      // WITHOUT a write attempt, and because the SQL predicate is one
      // migration away from being edited.
      return { recorded: false, rejection: "hold_not_active" };
    }
    const released = LegalHoldSchema.safeParse({
      ...existing.hold,
      status: {
        state: "released",
        releasedAt: request.releasedAt,
        releasingAuthorityId: request.releasingAuthorityId,
        releaseOrderRef: request.releaseOrderRef,
      },
    });
    if (!released.success) {
      return { recorded: false, rejection: "hold_malformed" };
    }
    try {
      const updated = await inWriteTransaction(async (client) => {
        const result = await client.query(
          `UPDATE memory_legal_holds
              SET status_state = 'released',
                  released_at = $4,
                  releasing_authority_id = $5,
                  release_order_ref = $6,
                  payload = $7
            WHERE tenant_id = $1 AND workspace_id = $2 AND hold_id = $3
              AND status_state = 'active'`,
          [
            request.actor.tenantId,
            request.actor.workspaceId,
            request.holdId,
            request.releasedAt,
            request.releasingAuthorityId,
            request.releaseOrderRef,
            JSON.stringify(released.data),
          ],
        );
        return result.rowCount;
      });
      if (updated !== 1) {
        return { recorded: false, rejection: "hold_not_active" };
      }
    } catch {
      return { recorded: false, rejection: "storage_rejected" };
    }
    const observed = await readHold(request.actor, request.holdId).catch(
      () => null,
    );
    if (observed === null || observed.hold.status.state !== "released") {
      return { recorded: false, rejection: "storage_rejected" };
    }
    return { recorded: true, rejection: null };
  }

  async function imposeRetention(
    actor: TrustedMemoryActor,
    candidate: unknown,
  ): Promise<LegalHoldResult> {
    const parsed = MemoryRetentionObligationSchema.safeParse(candidate);
    if (!parsed.success) {
      return { recorded: false, rejection: "retention_malformed" };
    }
    const obligation = parsed.data;
    try {
      await inWriteTransaction((client) =>
        client.query(
          `INSERT INTO memory_retention_obligations
             (tenant_id, workspace_id, obligation_id, record_id, policy_ref,
              retain_until, imposing_authority_id, imposed_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
          [
            actor.tenantId,
            actor.workspaceId,
            obligation.obligationId,
            obligation.recordId,
            obligation.policyRef,
            obligation.retainUntil,
            obligation.imposingAuthorityId,
            obligation.imposedAt,
          ],
        ),
      );
    } catch (error) {
      const message = error instanceof Error ? error.message : "";
      if (/memory_retention_obligations_unique/u.test(message)) {
        return { recorded: false, rejection: "retention_already_exists" };
      }
      return { recorded: false, rejection: "storage_rejected" };
    }
    return { recorded: true, rejection: null };
  }

  async function readHold(
    actor: TrustedMemoryActor,
    holdId: string,
  ): Promise<LegalHoldView | null> {
    const client = await readPool.connect();
    let ambiguous: unknown;
    try {
      await client.query("BEGIN");
      await enterRole(client, readRole);
      const result = await client.query(
        `SELECT ${HOLD_COLUMNS} FROM memory_legal_holds
          WHERE tenant_id = $1 AND workspace_id = $2 AND hold_id = $3
            AND principal_id = $4 AND user_id = $5
          LIMIT 1`,
        [
          actor.tenantId,
          actor.workspaceId,
          holdId,
          actor.principalId,
          actor.userId,
        ],
      );
      const row = result.rows[0] as HoldRow | undefined;
      if (!row) {
        await client.query("COMMIT");
        return null;
      }
      const parsed = LegalHoldSchema.safeParse(row.payload);
      if (!parsed.success) {
        // A stored value that does not parse is not a hold. Answering null is
        // the fail-closed reading for a READER; it is emphatically NOT what
        // the enforcement trigger does, and the trigger does not read jsonb.
        await client.query("COMMIT");
        return null;
      }
      const records = await client.query(
        `SELECT record_id FROM memory_legal_hold_records
          WHERE tenant_id = $1 AND workspace_id = $2 AND hold_id = $3
          ORDER BY record_id ASC`,
        [actor.tenantId, actor.workspaceId, holdId],
      );
      const subjects = await client.query(
        `SELECT canonical_participant_id FROM memory_legal_hold_subjects
          WHERE tenant_id = $1 AND workspace_id = $2 AND hold_id = $3
          ORDER BY canonical_participant_id ASC`,
        [actor.tenantId, actor.workspaceId, holdId],
      );
      await client.query("COMMIT");
      return {
        hold: parsed.data,
        recordIds: records.rows.map(
          (entry: { record_id: string }) => entry.record_id,
        ),
        canonicalParticipantIds: subjects.rows.map(
          (entry: { canonical_participant_id: string }) =>
            entry.canonical_participant_id,
        ),
      };
    } catch (error) {
      ambiguous = error;
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      releaseClient(client, ambiguous);
    }
  }

  async function restrictingHold(
    actor: TrustedMemoryActor,
    recordId: string,
    action: MemoryAction,
  ): Promise<string | null> {
    const client = await readPool.connect();
    let ambiguous: unknown;
    try {
      await client.query("BEGIN");
      await enterRole(client, readRole);
      const result = await client.query(
        `SELECT public.aaliyah_memory_restricting_hold($1, $2, $3, NULL, $4)
                  AS hold_id`,
        [actor.tenantId, actor.workspaceId, recordId, action],
      );
      await client.query("COMMIT");
      return (result.rows[0]?.hold_id as string | null) ?? null;
    } catch (error) {
      ambiguous = error;
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      releaseClient(client, ambiguous);
    }
  }

  return {
    placeHold,
    releaseHold,
    readHold,
    imposeRetention,
    restrictingHold,
  };
}
