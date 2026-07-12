import type { Pool } from "pg";

import type { TenantScope } from "../tenantScopedStore";
import type { ApprovalReviewRecord } from "../../services/followup/recordApprovalReview";

/**
 * Durable backend for the application stores that were previously file-backed
 * JSON/JSONL. Two generic shapes cover them all:
 *
 *  - `documents`: one latest payload per (store, scope, docKey) — style
 *    profiles, onboarding preferences, relationship maps.
 *  - `logs`: append-only, ordered per (store, scope) — decision traces,
 *    draft-quality, revenue signals, observability traces, reply/follow-up
 *    outcomes.
 *
 * Plus the pre-existing typed `approvals` table (follow-up approval reviews).
 * Every read filters on tenant_id + workspace_id — scoping is a query contract.
 */
export type ApplicationStore = ReturnType<typeof createPostgresApplicationStore>;

export function createPostgresApplicationStore(pool: Pool) {
  return {
    documents: {
      async put(store: string, scope: TenantScope, docKey: string, payload: unknown): Promise<void> {
        await pool.query(
          `INSERT INTO aaliyah_documents (store, tenant_id, workspace_id, doc_key, payload, updated_at)
           VALUES ($1,$2,$3,$4,$5, now())
           ON CONFLICT (store, tenant_id, workspace_id, doc_key)
           DO UPDATE SET payload = EXCLUDED.payload, updated_at = now()`,
          [store, scope.tenantId, scope.workspaceId, docKey, JSON.stringify(payload)],
        );
      },
      async get(store: string, scope: TenantScope, docKey: string): Promise<unknown | null> {
        const res = await pool.query(
          `SELECT payload FROM aaliyah_documents
           WHERE store = $1 AND tenant_id = $2 AND workspace_id = $3 AND doc_key = $4`,
          [store, scope.tenantId, scope.workspaceId, docKey],
        );
        return res.rows[0] ? res.rows[0].payload : null;
      },
      /** Cache-reset semantics only: durable rows are never dropped here (the
       * previous file-backed cache clears never deleted the file). No-op. */
      async reset(_store: string): Promise<void> {
        // Postgres holds the durable truth; there is no process cache to clear.
      },
    },

    logs: {
      async append(store: string, scope: TenantScope, payload: unknown): Promise<void> {
        await pool.query(
          `INSERT INTO aaliyah_append_logs (store, tenant_id, workspace_id, payload)
           VALUES ($1,$2,$3,$4)`,
          [store, scope.tenantId, scope.workspaceId, JSON.stringify(payload)],
        );
      },
      async list(store: string, scope: TenantScope): Promise<unknown[]> {
        const res = await pool.query(
          `SELECT payload FROM aaliyah_append_logs
           WHERE store = $1 AND tenant_id = $2 AND workspace_id = $3
           ORDER BY id`,
          [store, scope.tenantId, scope.workspaceId],
        );
        return res.rows.map((r) => r.payload);
      },
      async clear(store: string, scope: TenantScope): Promise<void> {
        await pool.query(
          `DELETE FROM aaliyah_append_logs
           WHERE store = $1 AND tenant_id = $2 AND workspace_id = $3`,
          [store, scope.tenantId, scope.workspaceId],
        );
      },
    },

    approvals: {
      async insert(review: ApprovalReviewRecord, scope?: TenantScope): Promise<void> {
        await pool.query(
          `INSERT INTO aaliyah_followup_approvals
             (task_id, thread_id, approved, edited, edit_distance, rejection_reason,
              reviewer_id, reviewer_role, draft_confidence, review_source, category,
              live_operator_pilot, tenant_id, workspace_id)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
          [
            review.taskId, review.threadId, review.approved, review.edited,
            review.editDistance, review.rejectionReason ?? null, review.reviewerId,
            review.reviewerRole ?? null, review.draftConfidence,
            review.reviewSource ?? null, review.category ?? null,
            review.liveOperatorPilot ?? false,
            scope?.tenantId ?? null, scope?.workspaceId ?? null,
          ],
        );
      },
      async list(scope?: TenantScope): Promise<ApprovalReviewRecord[]> {
        const res = await pool.query(
          `SELECT task_id, thread_id, approved, edited, edit_distance, rejection_reason,
                  reviewer_id, reviewer_role, draft_confidence, review_source, category,
                  live_operator_pilot, created_at
           FROM aaliyah_followup_approvals
           ${scope ? "WHERE tenant_id = $1 AND workspace_id = $2" : ""}
           ORDER BY created_at ASC, id ASC`,
          scope ? [scope.tenantId, scope.workspaceId] : [],
        );
        return res.rows.map(approvalFromRow);
      },
      async clear(scope?: TenantScope): Promise<void> {
        await pool.query(
          `DELETE FROM aaliyah_followup_approvals
           ${scope ? "WHERE tenant_id = $1 AND workspace_id = $2" : ""}`,
          scope ? [scope.tenantId, scope.workspaceId] : [],
        );
      },
    },
  };
}

/** Row → ApprovalReviewRecord, preserving the exact optional-field semantics of
 * the prior file/DB reader (only set optionals when present). */
function approvalFromRow(row: Record<string, unknown>): ApprovalReviewRecord {
  const record: ApprovalReviewRecord = {
    taskId: row.task_id as string,
    threadId: row.thread_id as string,
    approved: row.approved as boolean,
    edited: row.edited as boolean,
    editDistance: row.edit_distance as number,
    reviewerId: row.reviewer_id as string,
    draftConfidence: Number(row.draft_confidence ?? 0),
    reviewedAt: new Date(row.created_at as string).toISOString(),
  };
  if (row.rejection_reason) record.rejectionReason = row.rejection_reason as string;
  if (row.reviewer_role) record.reviewerRole = row.reviewer_role as string;
  if (row.review_source) record.reviewSource = row.review_source as "seeded" | "live_operator";
  if (row.category) record.category = row.category as string;
  if (row.live_operator_pilot !== null && row.live_operator_pilot !== undefined) {
    record.liveOperatorPilot = Boolean(row.live_operator_pilot);
  }
  return record;
}
