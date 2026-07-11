import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Pool } from "pg";

import { scopedJsonlPath, type TenantScope } from "../../persistence/tenantScopedStore";
import type { ApprovalReviewRecord } from "./recordApprovalReview";

function defaultPath(filename: string): string {
  return path.join(os.tmpdir(), filename);
}

function durableDataPath(filename: string): string {
  return path.join(
    process.env.AALIYAH_DATA_DIR ?? path.join(os.homedir(), ".aaliyah"),
    filename,
  );
}

export const approvalPersistenceInternals = {
  buildPool: () =>
    new Pool({
      connectionString: process.env.DATABASE_URL,
    }),
};

export function readJsonlFile<T>(filePath: string): T[] {
  if (!fs.existsSync(filePath)) {
    return [];
  }

  return fs
    .readFileSync(filePath, "utf8")
    .split("\n")
    .filter((line) => line.trim().length > 0)
    .map((line) => JSON.parse(line) as T);
}

export function appendJsonlFile(filePath: string, record: unknown): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.appendFileSync(filePath, `${JSON.stringify(record)}\n`, "utf8");
}

export function removeFileIfExists(filePath: string): void {
  if (fs.existsSync(filePath)) {
    fs.unlinkSync(filePath);
  }
}

export function approvalReviewLogPath(scope?: TenantScope): string {
  if (scope) {
    return scopedJsonlPath("aaliyah-followup-approvals.jsonl", scope);
  }
  return (
    process.env.AALIYAH_APPROVAL_REVIEW_LOG_PATH ??
    durableDataPath("aaliyah-followup-approvals.jsonl")
  );
}

export function replyOutcomeLogPath(scope?: TenantScope): string {
  if (scope) {
    return scopedJsonlPath("aaliyah-reply-outcomes.jsonl", scope);
  }
  return (
    process.env.AALIYAH_REPLY_OUTCOME_LOG_PATH ??
    durableDataPath("aaliyah-reply-outcomes.jsonl")
  );
}

export function followupOutcomeLogPath(scope?: TenantScope): string {
  if (scope) {
    return scopedJsonlPath("aaliyah-followup-outcomes.jsonl", scope);
  }
  return (
    process.env.AALIYAH_FOLLOWUP_OUTCOME_LOG_PATH ??
    durableDataPath("aaliyah-followup-outcomes.jsonl")
  );
}

/**
 * Idempotent DDL shared by the approval-review reader/writer. Includes the
 * additive multi-tenant isolation columns; uniqueness is unaffected.
 */
const APPROVALS_DDL = `
  CREATE TABLE IF NOT EXISTS aaliyah_followup_approvals (
    id BIGSERIAL PRIMARY KEY,
    task_id TEXT NOT NULL,
    thread_id TEXT NOT NULL,
    approved BOOLEAN NOT NULL,
    edited BOOLEAN NOT NULL,
    edit_distance INT NOT NULL,
    rejection_reason TEXT,
    reviewer_id TEXT NOT NULL,
    reviewer_role TEXT,
    draft_confidence INT,
    review_source TEXT,
    category TEXT,
    live_operator_pilot BOOLEAN,
    tenant_id TEXT,
    workspace_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )
`;

async function ensureApprovalsSchema(pool: Pool): Promise<void> {
  await pool.query(APPROVALS_DDL);
  await pool.query(
    "ALTER TABLE aaliyah_followup_approvals ADD COLUMN IF NOT EXISTS tenant_id TEXT",
  );
  await pool.query(
    "ALTER TABLE aaliyah_followup_approvals ADD COLUMN IF NOT EXISTS workspace_id TEXT",
  );
}

export async function persistApprovalReview(
  review: ApprovalReviewRecord,
  scope?: TenantScope,
): Promise<void> {
  if (!process.env.DATABASE_URL) {
    appendJsonlFile(approvalReviewLogPath(scope), review);
    return;
  }

  const pool = approvalPersistenceInternals.buildPool();

  try {
    await ensureApprovalsSchema(pool);

    await pool.query(
      `
      INSERT INTO aaliyah_followup_approvals
        (task_id, thread_id, approved, edited, edit_distance, rejection_reason, reviewer_id, reviewer_role, draft_confidence, review_source, category, live_operator_pilot, tenant_id, workspace_id)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
      `,
      [
        review.taskId,
        review.threadId,
        review.approved,
        review.edited,
        review.editDistance,
        review.rejectionReason ?? null,
        review.reviewerId,
        review.reviewerRole ?? null,
        review.draftConfidence,
        review.reviewSource ?? null,
        review.category ?? null,
        review.liveOperatorPilot ?? false,
        scope?.tenantId ?? null,
        scope?.workspaceId ?? null,
      ],
    );
  } finally {
    await pool.end();
  }
}

export async function listPersistedApprovalReviews(
  scope?: TenantScope,
): Promise<ApprovalReviewRecord[]> {
  if (!process.env.DATABASE_URL) {
    return readJsonlFile<ApprovalReviewRecord>(approvalReviewLogPath(scope));
  }

  const pool = approvalPersistenceInternals.buildPool();

  try {
    await ensureApprovalsSchema(pool);

    const result = await pool.query(
      `
      SELECT
        task_id,
        thread_id,
        approved,
        edited,
        edit_distance,
        rejection_reason,
        reviewer_id,
        reviewer_role,
        draft_confidence,
        review_source,
        category,
        live_operator_pilot,
        created_at
      FROM aaliyah_followup_approvals
      ${scope ? "WHERE tenant_id = $1 AND workspace_id = $2" : ""}
      ORDER BY created_at ASC
      `,
      scope ? [scope.tenantId, scope.workspaceId] : [],
    );

    return result.rows.map((row) => {
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

      if (row.rejection_reason) {
        record.rejectionReason = row.rejection_reason as string;
      }

      if (row.reviewer_role) {
        record.reviewerRole = row.reviewer_role as string;
      }

      if (row.review_source) {
        record.reviewSource = row.review_source as "seeded" | "live_operator";
      }

      if (row.category) {
        record.category = row.category as string;
      }

      if (row.live_operator_pilot !== null && row.live_operator_pilot !== undefined) {
        record.liveOperatorPilot = Boolean(row.live_operator_pilot);
      }

      return record;
    });
  } finally {
    await pool.end();
  }
}

export async function clearPersistedApprovalReviews(
  scope?: TenantScope,
): Promise<void> {
  if (!process.env.DATABASE_URL) {
    removeFileIfExists(approvalReviewLogPath(scope));
    return;
  }

  const pool = approvalPersistenceInternals.buildPool();

  try {
    await ensureApprovalsSchema(pool);
    await pool.query(
      `DELETE FROM aaliyah_followup_approvals ${
        scope ? "WHERE tenant_id = $1 AND workspace_id = $2" : ""
      }`,
      scope ? [scope.tenantId, scope.workspaceId] : [],
    );
  } finally {
    await pool.end();
  }
}
