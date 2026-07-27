import assert from "node:assert/strict";
import test from "node:test";
import type { Pool } from "pg";

import { createPostgresWave1LifecycleStore } from "../src/persistence/postgres/wave1LifecycleStore";

const DIGEST = `sha256:${"a".repeat(64)}`;
const EVENT = {
  contractVersion: "aaliyah.executive-communications/wave1",
  tenantId: "tenant-1",
  workspaceId: "workspace-1",
  userId: "user-1",
  taskId: "task-1",
  requestId: "request-1",
  idempotencyKey: "operation-1",
  eventId: "event-1",
  state: "RECEIVED",
  occurredAt: "2026-07-26T10:00:00.000Z",
  actorId: "mail.ingress",
  evidenceRefs: ["audit:item-1234"],
  artifactDigest: DIGEST,
} as const;

function poolReturning(row: Record<string, unknown>): Pool {
  return {
    query: async () => ({ rows: [row] }),
  } as unknown as Pool;
}

test("both PostgreSQL lookup paths reject relational/payload binding corruption", async () => {
  const baseRow = {
    event_id: EVENT.eventId,
    tenant_id: EVENT.tenantId,
    workspace_id: EVENT.workspaceId,
    task_id: EVENT.taskId,
    idempotency_key: EVENT.idempotencyKey,
    payload: EVENT,
  };
  for (const mutation of [
    { event_id: "other-event" },
    { tenant_id: "other-tenant" },
    { workspace_id: "other-workspace" },
    { task_id: "other-task" },
    { idempotency_key: "other-operation" },
  ]) {
    const store = createPostgresWave1LifecycleStore(
      poolReturning({ ...baseRow, ...mutation }),
    );
    await assert.rejects(() =>
      store.findByEventId(EVENT.tenantId, EVENT.workspaceId, EVENT.eventId),
    );
    await assert.rejects(() =>
      store.findByIdempotencyKey(
        EVENT.tenantId,
        EVENT.workspaceId,
        EVENT.taskId,
        EVENT.idempotencyKey,
      ),
    );
  }
});
