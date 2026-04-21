import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Pool } from "pg";

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

export function approvalReviewLogPath(): string {
  return (
    process.env.AALIYAH_APPROVAL_REVIEW_LOG_PATH ??
    durableDataPath("aaliyah-followup-approvals.jsonl")
  );
}

export function replyOutcomeLogPath(): string {
  return (
    process.env.AALIYAH_REPLY_OUTCOME_LOG_PATH ??
    durableDataPath("aaliyah-reply-outcomes.jsonl")
  );
}

export function followupOutcomeLogPath(): string {
  return (
    process.env.AALIYAH_FOLLOWUP_OUTCOME_LOG_PATH ??
    durableDataPath("aaliyah-followup-outcomes.jsonl")
  );
}

export async function persistApprovalReview(
  review: ApprovalReviewRecord,
): Promise<void> {
  if (!process.env.DATABASE_URL) {
    appendJsonlFile(approvalReviewLogPath(), review);
    return;
  }

  const pool = approvalPersistenceInternals.buildPool();

  try {
    await pool.query(`
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
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await pool.query(
      `
      INSERT INTO aaliyah_followup_approvals
        (task_id, thread_id, approved, edited, edit_distance, rejection_reason, reviewer_id, reviewer_role, draft_confidence, review_source, category, live_operator_pilot)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
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
      ],
    );
  } finally {
    await pool.end();
  }
}

export async function listPersistedApprovalReviews(): Promise<ApprovalReviewRecord[]> {
  if (!process.env.DATABASE_URL) {
    return readJsonlFile<ApprovalReviewRecord>(approvalReviewLogPath());
  }

  const pool = approvalPersistenceInternals.buildPool();

  try {
    await pool.query(`
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
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

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
      ORDER BY created_at ASC
      `,
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

export async function clearPersistedApprovalReviews(): Promise<void> {
  if (!process.env.DATABASE_URL) {
    removeFileIfExists(approvalReviewLogPath());
    return;
  }

  const pool = approvalPersistenceInternals.buildPool();

  try {
    await pool.query(`
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
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await pool.query("DELETE FROM aaliyah_followup_approvals");
  } finally {
    await pool.end();
  }
}
