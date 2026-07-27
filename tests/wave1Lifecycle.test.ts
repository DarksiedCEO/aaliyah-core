import assert from "node:assert/strict";
import test from "node:test";

import {
  type Wave1LifecycleStore,
  recordWave1LifecycleEvent,
} from "../src/application/executive/wave1Lifecycle";

const DIGEST = `sha256:${"a".repeat(64)}`;
const BINDING = {
  contractVersion: "aaliyah.executive-communications/wave1",
  tenantId: "tenant-1",
  workspaceId: "workspace-1",
  userId: "user-1",
  taskId: "task-1",
  requestId: "request-1",
  idempotencyKey: "operation-1",
} as const;
const EVENT = {
  ...BINDING,
  eventId: "received-event",
  state: "RECEIVED",
  occurredAt: "2026-07-26T10:00:00.000Z",
  actorId: "gmail.adapter",
  evidenceRefs: ["audit:item-1234"],
  artifactDigest: DIGEST,
} as const;
const EVIDENCE = {
  ...BINDING,
  eventId: "received-event",
  state: "RECEIVED",
  occurredAt: "2026-07-26T10:00:00.000Z",
  artifactKind: "inbound_message",
  artifactDigest: DIGEST,
  evidence: {
    evidenceRef: "audit:item-1234",
    evidenceDigest: DIGEST,
    observedAt: "2026-07-26T10:00:00.000Z",
    freshUntil: "2026-07-26T10:05:00.000Z",
  },
} as const;

function memoryStore(): Wave1LifecycleStore & {
  events: Map<string, unknown>;
  appendCalls: number;
} {
  const events = new Map<string, any>();
  return {
    events,
    appendCalls: 0,
    async findByEventId(eventId) {
      return events.get(eventId) ?? null;
    },
    async findByIdempotencyKey(tenantId, workspaceId, taskId, key) {
      return (
        [...events.values()].reverse().find(
          (event) =>
            event.tenantId === tenantId &&
            event.workspaceId === workspaceId &&
            event.taskId === taskId &&
            event.idempotencyKey === key,
        ) ?? null
      );
    },
    async appendIfCurrent({ event, expectedPreviousEventId }) {
      this.appendCalls += 1;
      if ((event.previousEventId ?? null) !== expectedPreviousEventId) return null;
      events.set(event.eventId, event);
      return events.get(event.eventId) ?? null;
    },
  };
}

function input(store: Wave1LifecycleStore, raw: unknown = EVENT) {
  return {
    raw,
    trustedNowMs: Date.parse("2026-07-26T10:01:00.000Z"),
    store,
    resolveEvidence: () => EVIDENCE,
    resolveActorAuthority: () => "mail.ingress",
  };
}

test("records an evidence-bound lifecycle event and exact replay is idempotent", async () => {
  const store = memoryStore();
  assert.deepEqual(await recordWave1LifecycleEvent(input(store)), EVENT);
  assert.deepEqual(await recordWave1LifecycleEvent(input(store)), EVENT);
  assert.equal(store.appendCalls, 1);
});

test("fails closed on missing authority, evidence, and persistence read-back", async () => {
  const store = memoryStore();
  await assert.rejects(() =>
    recordWave1LifecycleEvent({
      ...input(store),
      resolveActorAuthority: () => null,
    }),
  );
  await assert.rejects(() =>
    recordWave1LifecycleEvent({
      ...input(store),
      resolveActorAuthority: () =>
        ({ status: "allowed" }) as unknown as string,
    }),
  );
  await assert.rejects(() =>
    recordWave1LifecycleEvent({
      ...input(store),
      resolveEvidence: () => null,
    }),
  );
  await assert.rejects(() =>
    recordWave1LifecycleEvent({
      ...input({
        ...store,
        appendIfCurrent: async ({ event }) => event,
      }),
    }),
  );
  await assert.rejects(() =>
    recordWave1LifecycleEvent({
      ...input({
        ...store,
        appendIfCurrent: async () => null,
      }),
    }),
  );
});

test("rejects conflicting duplicates and unverified provider states", async () => {
  const store = memoryStore();
  await recordWave1LifecycleEvent(input(store));
  await assert.rejects(() =>
    recordWave1LifecycleEvent(
      input(store, { ...EVENT, eventId: "other-event" }),
    ),
  );
  await assert.rejects(() =>
    recordWave1LifecycleEvent(
      input(store, {
        ...EVENT,
        eventId: "provider-event",
        previousEventId: "human-review-event",
        previousState: "AWAITING_HUMAN_REVIEW",
        state: "PROVIDER_DRAFT_CREATED",
        authorizationId: "authorization-1",
        providerDraftReceipt: {},
      }),
    ),
  );
});

test("requires the exact authoritative predecessor", async () => {
  const store = memoryStore();
  await recordWave1LifecycleEvent(input(store));
  const normalized = {
    ...BINDING,
    eventId: "normalized-event",
    previousEventId: "received-event",
    previousState: "RECEIVED",
    state: "NORMALIZED",
    occurredAt: "2026-07-26T10:00:10.000Z",
    actorId: "normalizer.actor",
    evidenceRefs: ["audit:normalized-1234"],
    artifactDigest: DIGEST,
  } as const;
  const normalizedEvidence = {
    ...EVIDENCE,
    eventId: "normalized-event",
    previousEventId: "received-event",
    state: "NORMALIZED",
    occurredAt: "2026-07-26T10:00:10.000Z",
    artifactKind: "normalized_thread",
    evidence: {
      ...EVIDENCE.evidence,
      evidenceRef: "audit:normalized-1234",
    },
  } as const;
  await assert.rejects(() =>
    recordWave1LifecycleEvent({
      ...input(memoryStore(), normalized),
      resolveEvidence: () => normalizedEvidence,
    }),
  );
  assert.deepEqual(
    await recordWave1LifecycleEvent({
      ...input(store, normalized),
      resolveEvidence: () => normalizedEvidence,
    }),
    normalized,
  );
});
