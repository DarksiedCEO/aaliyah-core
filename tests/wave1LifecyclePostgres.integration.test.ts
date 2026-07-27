import assert from "node:assert/strict";
import test, { after, before, beforeEach } from "node:test";
import { Pool } from "pg";

import { recordWave1LifecycleEvent } from "../src/application/executive/wave1Lifecycle";
import { runMailMigrations } from "../src/persistence/postgres/migrations";
import { createMailDbPool } from "../src/persistence/postgres/pool";
import { createPostgresWave1LifecycleStore } from "../src/persistence/postgres/wave1LifecycleStore";

const DB_URL =
  process.env.AALIYAH_TEST_DATABASE_URL ??
  "postgres://postgres:test@127.0.0.1:54329/aaliyah_test";
const DIGEST = `sha256:${"a".repeat(64)}`;
const BINDING = {
  contractVersion: "aaliyah.executive-communications/wave1",
  tenantId: "tenant-wave1",
  workspaceId: "workspace-wave1",
  userId: "user-wave1",
  taskId: "task-wave1",
  requestId: "request-wave1",
  idempotencyKey: "operation-wave1",
} as const;

let poolA: Pool;
let poolB: Pool;

before(async () => {
  poolA = createMailDbPool({ AALIYAH_DATABASE_URL: DB_URL } as NodeJS.ProcessEnv);
  poolB = createMailDbPool({ AALIYAH_DATABASE_URL: DB_URL } as NodeJS.ProcessEnv);
  await runMailMigrations(poolA);
});

after(async () => {
  await poolA.end();
  await poolB.end();
});

beforeEach(async () => {
  await poolA.query("TRUNCATE wave1_lifecycle_events RESTART IDENTITY");
});

function event(
  eventId: string,
  state: "RECEIVED" | "NORMALIZED",
  previousEventId?: string,
) {
  return {
    ...BINDING,
    eventId,
    ...(previousEventId
      ? { previousEventId, previousState: "RECEIVED" as const }
      : {}),
    state,
    occurredAt:
      state === "RECEIVED"
        ? "2026-07-26T10:00:00.000Z"
        : "2026-07-26T10:00:10.000Z",
    actorId: state === "RECEIVED" ? "mail.ingress" : "mail.normalizer",
    evidenceRefs: [`audit:${eventId}`],
    artifactDigest: DIGEST,
  };
}

function evidence(raw: ReturnType<typeof event>) {
  return {
    ...BINDING,
    eventId: raw.eventId,
    ...(raw.previousEventId
      ? { previousEventId: raw.previousEventId }
      : {}),
    state: raw.state,
    occurredAt: raw.occurredAt,
    artifactKind:
      raw.state === "RECEIVED" ? "inbound_message" : "normalized_thread",
    artifactDigest: DIGEST,
    evidence: {
      evidenceRef: `audit:${raw.eventId}`,
      evidenceDigest: DIGEST,
      observedAt: raw.occurredAt,
      freshUntil: "2026-07-26T10:05:00.000Z",
    },
  } as const;
}

function record(store: ReturnType<typeof createPostgresWave1LifecycleStore>, raw: ReturnType<typeof event>) {
  return recordWave1LifecycleEvent({
    raw,
    trustedNowMs: Date.parse("2026-07-26T10:01:00.000Z"),
    store,
    resolveEvidence: () => evidence(raw),
    resolveActorAuthority: (_actorId, state) =>
      state === "RECEIVED" ? "mail.ingress" : "mail.normalizer",
  });
}

test("PostgreSQL lifecycle store persists exact replay across instances", async () => {
  const storeA = createPostgresWave1LifecycleStore(poolA);
  const storeB = createPostgresWave1LifecycleStore(poolB);
  const received = event("received-event", "RECEIVED");
  assert.deepEqual(await record(storeA, received), received);
  assert.deepEqual(await record(storeB, received), received);
  const count = await poolA.query(
    "SELECT count(*)::int AS count FROM wave1_lifecycle_events",
  );
  assert.equal(count.rows[0]?.count, 1);
});

test("two PostgreSQL stores atomically admit only one competing branch", async () => {
  const storeA = createPostgresWave1LifecycleStore(poolA);
  const storeB = createPostgresWave1LifecycleStore(poolB);
  await record(storeA, event("received-event", "RECEIVED"));
  const outcomes = await Promise.allSettled([
    record(storeA, event("normalized-a", "NORMALIZED", "received-event")),
    record(storeB, event("normalized-b", "NORMALIZED", "received-event")),
  ]);
  assert.equal(
    outcomes.filter((outcome) => outcome.status === "fulfilled").length,
    1,
  );
  assert.equal(
    outcomes.filter((outcome) => outcome.status === "rejected").length,
    1,
  );
  const rows = await poolA.query(
    `SELECT payload->>'eventId' AS event_id
     FROM wave1_lifecycle_events
     ORDER BY id`,
  );
  assert.equal(rows.rows.length, 2);
  assert.equal(rows.rows[0]?.event_id, "received-event");
  assert.ok(["normalized-a", "normalized-b"].includes(rows.rows[1]?.event_id));
});

test("event-id lookup cannot cross tenant or workspace boundaries", async () => {
  const store = createPostgresWave1LifecycleStore(poolA);
  await record(store, event("received-event", "RECEIVED"));
  assert.equal(
    await store.findByEventId(
      "other-tenant",
      BINDING.workspaceId,
      "received-event",
    ),
    null,
  );
  assert.equal(
    await store.findByEventId(
      BINDING.tenantId,
      "other-workspace",
      "received-event",
    ),
    null,
  );
});

test("database rejects every relational row and payload binding mismatch", async () => {
  const received = event("received-event", "RECEIVED");
  for (const [column, value] of [
    ["event_id", "other-event"],
    ["tenant_id", "other-tenant"],
    ["workspace_id", "other-workspace"],
    ["task_id", "other-task"],
    ["idempotency_key", "other-operation"],
  ] as const) {
    await assert.rejects(() =>
      poolA.query(
        `INSERT INTO wave1_lifecycle_events
           (event_id, tenant_id, workspace_id, task_id, idempotency_key, payload)
         VALUES (
           $1, $2, $3, $4, $5, $6
         )`,
        [
          column === "event_id" ? value : received.eventId,
          column === "tenant_id" ? value : received.tenantId,
          column === "workspace_id" ? value : received.workspaceId,
          column === "task_id" ? value : received.taskId,
          column === "idempotency_key" ? value : received.idempotencyKey,
          JSON.stringify(received),
        ],
      ),
    );
  }
  const count = await poolA.query(
    "SELECT count(*)::int AS count FROM wave1_lifecycle_events",
  );
  assert.equal(count.rows[0]?.count, 0);
  for (const payload of [
    {},
    { ...received, tenantId: null },
    { ...received, workspaceId: null },
    { ...received, taskId: null },
    { ...received, idempotencyKey: null },
    { ...received, eventId: null },
    "not-an-object",
  ]) {
    await assert.rejects(() =>
      poolA.query(
        `INSERT INTO wave1_lifecycle_events
           (event_id, tenant_id, workspace_id, task_id, idempotency_key, payload)
         VALUES ($1,$2,$3,$4,$5,$6)`,
        [
          received.eventId,
          received.tenantId,
          received.workspaceId,
          received.taskId,
          received.idempotencyKey,
          JSON.stringify(payload),
        ],
      ),
    );
  }
});

test("insert failure rolls back and leaves the store connection reusable", async () => {
  const store = createPostgresWave1LifecycleStore(poolA);
  const received = event("received-event", "RECEIVED");
  await record(store, received);
  await assert.rejects(() =>
    store.appendIfCurrent({
      event: {
        ...received,
        taskId: "collision-task",
        requestId: "collision-request",
        idempotencyKey: "collision-operation",
      },
      expectedPreviousEventId: null,
    }),
  );
  const afterFailure = {
    ...received,
    eventId: "after-failure-event",
    taskId: "after-failure-task",
    requestId: "after-failure-request",
    idempotencyKey: "after-failure-operation",
  };
  assert.deepEqual(
    await store.appendIfCurrent({
      event: afterFailure,
      expectedPreviousEventId: null,
    }),
    afterFailure,
  );
  assert.deepEqual(
    await store.findByEventId(
      received.tenantId,
      received.workspaceId,
      received.eventId,
    ),
    received,
  );
});
