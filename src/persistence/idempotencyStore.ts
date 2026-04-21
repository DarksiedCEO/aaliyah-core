import crypto from "node:crypto";
import { Pool } from "pg";

type IdempotencyRecord = {
  requestHash: string;
  operationType: string;
  status: "in_progress" | "completed" | "failed";
  resultPayload: unknown | null;
  createdAt: string;
  completedAt: string | null;
};

const fallbackStore = new Map<string, IdempotencyRecord>();
const STALE_IN_PROGRESS_MS = 5 * 60 * 1000;

export const idempotencyStoreInternals = {
  buildPool: () =>
    new Pool({
      connectionString: process.env.DATABASE_URL,
    }),
  resetInMemory: () => fallbackStore.clear(),
};

type EnsureIdempotentResult<T> = {
  replay: boolean;
  result: T | undefined;
};

function nowIso(): string {
  return new Date().toISOString();
}

function hashRequest(payload: unknown): string {
  return crypto.createHash("sha256").update(JSON.stringify(payload)).digest("hex");
}

function parseResultPayload<T>(resultPayload: unknown | null): T | undefined {
  if (resultPayload === null) {
    return undefined;
  }

  return resultPayload as T;
}

function isStaleInProgress(createdAt: string): boolean {
  return Date.now() - new Date(createdAt).getTime() > STALE_IN_PROGRESS_MS;
}

async function ensureIdempotentExecutionInMemory<T>(
  idempotencyKey: string,
  payload: unknown,
  operationType: string,
): Promise<EnsureIdempotentResult<T>> {
  const requestHash = hashRequest(payload);
  const existing = fallbackStore.get(idempotencyKey);

  if (existing) {
    if (existing.requestHash !== requestHash) {
      throw new Error("Idempotency key reuse with different payload");
    }

    if (existing.status === "completed") {
      return {
        replay: true,
        result: parseResultPayload<T>(existing.resultPayload),
      };
    }

    if (existing.status === "failed") {
      fallbackStore.set(idempotencyKey, {
        ...existing,
        operationType,
        status: "in_progress",
        resultPayload: null,
        completedAt: null,
      });

      return { replay: false, result: undefined };
    }

    if (isStaleInProgress(existing.createdAt)) {
      fallbackStore.set(idempotencyKey, {
        ...existing,
        operationType,
        status: "in_progress",
        resultPayload: null,
        createdAt: nowIso(),
        completedAt: null,
      });

      return { replay: false, result: undefined };
    }

    throw new Error("Idempotent request already in progress");
  }

  fallbackStore.set(idempotencyKey, {
    requestHash,
    operationType,
    status: "in_progress",
    resultPayload: null,
    createdAt: nowIso(),
    completedAt: null,
  });

  return { replay: false, result: undefined };
}

export async function ensureIdempotentExecution<T>(
  idempotencyKey: string,
  payload: unknown,
  operationType: string,
): Promise<EnsureIdempotentResult<T>> {
  if (!process.env.DATABASE_URL) {
    if (
      process.env.NODE_ENV !== "test" &&
      process.env.AALIYAH_ALLOW_INMEMORY_IDEMPOTENCY !== "true"
    ) {
      throw new Error("DATABASE_URL is required for durable idempotency");
    }

    return ensureIdempotentExecutionInMemory<T>(idempotencyKey, payload, operationType);
  }

  const pool = idempotencyStoreInternals.buildPool();
  const client = await pool.connect();
  const requestHash = hashRequest(payload);

  try {
    await client.query("BEGIN");

    await client.query(`
      CREATE TABLE IF NOT EXISTS aaliyah_idempotency (
        id BIGSERIAL PRIMARY KEY,
        idempotency_key TEXT NOT NULL UNIQUE,
        request_hash TEXT NOT NULL,
        operation_type TEXT NOT NULL,
        status TEXT NOT NULL,
        result_payload JSONB,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        completed_at TIMESTAMPTZ
      )
    `);

    await client.query(`
      ALTER TABLE aaliyah_idempotency
      ADD COLUMN IF NOT EXISTS result_payload JSONB
    `);

    const existing = await client.query(
      `
      SELECT request_hash, status, result_payload, created_at
      FROM aaliyah_idempotency
      WHERE idempotency_key = $1
      `,
      [idempotencyKey],
    );

    if ((existing.rowCount ?? 0) > 0) {
      const row = existing.rows[0] as {
        request_hash: string;
        status: string;
        result_payload: unknown | null;
        created_at: string;
      };

      if (row.request_hash !== requestHash) {
        await client.query("COMMIT");
        throw new Error("Idempotency key reuse with different payload");
      }

      if (row.status === "completed") {
        await client.query("COMMIT");
        return {
          replay: true,
          result: parseResultPayload<T>(row.result_payload),
        };
      }

      if (row.status === "failed" || isStaleInProgress(row.created_at)) {
        await client.query(
          `
          UPDATE aaliyah_idempotency
          SET status = $2,
              result_payload = NULL,
              completed_at = NULL,
              request_hash = $3,
              operation_type = $4,
              created_at = NOW()
          WHERE idempotency_key = $1
          `,
          [idempotencyKey, "in_progress", requestHash, operationType],
        );

        await client.query("COMMIT");
        return { replay: false, result: undefined };
      }

      await client.query("COMMIT");
      throw new Error("Idempotent request already in progress");
    }

    await client.query(
      `
      INSERT INTO aaliyah_idempotency
        (idempotency_key, request_hash, operation_type, status)
      VALUES ($1, $2, $3, $4)
      `,
      [idempotencyKey, requestHash, operationType, "in_progress"],
    );

    await client.query("COMMIT");
    return { replay: false, result: undefined };
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
    await pool.end();
  }
}

async function updateInMemoryResult(
  idempotencyKey: string,
  status: IdempotencyRecord["status"],
  resultPayload: unknown | null,
): Promise<void> {
  const record = fallbackStore.get(idempotencyKey);

  if (!record) {
    return;
  }

  fallbackStore.set(idempotencyKey, {
    ...record,
    status,
    resultPayload,
    completedAt: nowIso(),
  });
}

export async function markCompleted(
  idempotencyKey: string,
  result: unknown,
): Promise<void> {
  if (!process.env.DATABASE_URL) {
    await updateInMemoryResult(idempotencyKey, "completed", result);
    return;
  }

  const pool = idempotencyStoreInternals.buildPool();

  try {
    await pool.query(
      `
      UPDATE aaliyah_idempotency
      SET status = 'completed',
          result_payload = $2::jsonb,
          completed_at = NOW()
      WHERE idempotency_key = $1
      `,
      [idempotencyKey, JSON.stringify(result)],
    );
  } finally {
    await pool.end();
  }
}

export async function recordIdempotentResult(
  idempotencyKey: string,
  result: unknown,
): Promise<void> {
  await markCompleted(idempotencyKey, result);
}

export async function recordIdempotentFailure(
  idempotencyKey: string,
  message: string,
): Promise<void> {
  if (!process.env.DATABASE_URL) {
    await updateInMemoryResult(
      idempotencyKey,
      "failed",
      { success: false, message },
    );
    return;
  }

  const pool = idempotencyStoreInternals.buildPool();

  try {
    await pool.query(
      `
      UPDATE aaliyah_idempotency
      SET status = $2,
          result_payload = $3::jsonb,
          completed_at = NOW()
      WHERE idempotency_key = $1
      `,
      [idempotencyKey, "failed", JSON.stringify({ success: false, message })],
    );
  } finally {
    await pool.end();
  }
}
