import { AuditLifecycleEventSchema } from "@aaliyah/contracts/v1";
import type { Pool } from "pg";

import type { Wave1LifecycleStore } from "../../application/executive/wave1Lifecycle";

export function createPostgresWave1LifecycleStore(
  pool: Pool,
): Wave1LifecycleStore {
  return {
    async findByEventId(tenantId, workspaceId, eventId) {
      const result = await pool.query(
        `SELECT payload
         FROM wave1_lifecycle_events
         WHERE tenant_id = $1
           AND workspace_id = $2
           AND event_id = $3
         LIMIT 1`,
        [tenantId, workspaceId, eventId],
      );
      return result.rows[0]
        ? AuditLifecycleEventSchema.parse(result.rows[0].payload)
        : null;
    },

    async findByIdempotencyKey(
      tenantId,
      workspaceId,
      taskId,
      idempotencyKey,
    ) {
      const result = await pool.query(
        `SELECT payload
         FROM wave1_lifecycle_events
         WHERE tenant_id = $1
           AND workspace_id = $2
           AND task_id = $3
           AND idempotency_key = $4
         ORDER BY id DESC
         LIMIT 1`,
        [tenantId, workspaceId, taskId, idempotencyKey],
      );
      return result.rows[0]
        ? AuditLifecycleEventSchema.parse(result.rows[0].payload)
        : null;
    },

    async appendIfCurrent({ event, expectedPreviousEventId }) {
      const client = await pool.connect();
      const operationLock = [
        event.tenantId,
        event.workspaceId,
        event.taskId,
        event.idempotencyKey,
      ].join("\u001f");
      try {
        await client.query("BEGIN");
        await client.query(
          "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
          [operationLock],
        );
        const current = await client.query(
          `SELECT event_id
           FROM wave1_lifecycle_events
           WHERE tenant_id = $1
             AND workspace_id = $2
             AND task_id = $3
             AND idempotency_key = $4
           ORDER BY id DESC
           LIMIT 1`,
          [
            event.tenantId,
            event.workspaceId,
            event.taskId,
            event.idempotencyKey,
          ],
        );
        const actualPreviousEventId =
          (current.rows[0]?.event_id as string | undefined) ?? null;
        if (actualPreviousEventId !== expectedPreviousEventId) {
          await client.query("ROLLBACK");
          return null;
        }
        await client.query(
          `INSERT INTO wave1_lifecycle_events
             (event_id, tenant_id, workspace_id, task_id, idempotency_key, payload)
           VALUES ($1,$2,$3,$4,$5,$6)`,
          [
            event.eventId,
            event.tenantId,
            event.workspaceId,
            event.taskId,
            event.idempotencyKey,
            JSON.stringify(event),
          ],
        );
        await client.query("COMMIT");
        return event;
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        client.release();
      }
    },
  };
}
