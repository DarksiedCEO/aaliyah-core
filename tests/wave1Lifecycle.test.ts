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
      const current = [...events.values()].at(-1) ?? null;
      if ((current?.eventId ?? null) !== expectedPreviousEventId) return null;
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
  await assert.rejects(() =>
    recordWave1LifecycleEvent(
      input({
        ...store,
        findByEventId: async () => null,
        findByIdempotencyKey: async () => ({
          ...EVENT,
          evidenceRefs: [...EVENT.evidenceRefs],
        }),
        appendIfCurrent: async () => {
          throw new Error("append must not rescue an unverified replay");
        },
      }),
    ),
  );
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
  const providerReceipt = {
    receiptId: "provider-receipt-1",
    adapterId: "gmail.adapter",
    connectionId: "connection-1",
    tenantId: BINDING.tenantId,
    workspaceId: BINDING.workspaceId,
    userId: BINDING.userId,
    requestId: BINDING.requestId,
    taskId: BINDING.taskId,
    threadId: "thread-1",
    contextDigest: DIGEST,
    providerDraftId: "provider-draft-1",
    candidateDigest: DIGEST,
    capabilityCandidateDigest: DIGEST,
    createdAt: "2026-07-26T10:00:30.000Z",
  };
  const providerDraftReceipt = {
    ...BINDING,
    authorizationId: "authorization-1",
    recipientDigest: DIGEST,
    approvalId: "approval-1",
    qualityBundleId: "quality-1",
    verifiedEnvelopeDigest: DIGEST,
    providerReceipt,
  };
  const created = {
    ...BINDING,
    eventId: "provider-event",
    previousEventId: "human-review-event",
    previousState: "AWAITING_HUMAN_REVIEW",
    state: "PROVIDER_DRAFT_CREATED",
    occurredAt: "2026-07-26T10:00:40.000Z",
    actorId: "gmail.adapter",
    evidenceRefs: ["audit:provider-created-1234"],
    artifactDigest: DIGEST,
    authorizationId: "authorization-1",
    providerDraftReceipt,
  } as const;
  await assert.rejects(() =>
    recordWave1LifecycleEvent(input(store, created)),
  );
  const readbackReceipt = {
    ...BINDING,
    receiptId: "readback-1",
    providerDraftReceipt,
    verifierActorId: "provider.readback",
    verifierMethod: "independent_provider_read",
    providerDraftId: "provider-draft-1",
    adapterId: "gmail.adapter",
    connectionId: "connection-1",
    threadId: "thread-1",
    contextDigest: DIGEST,
    candidateDigest: DIGEST,
    capabilityCandidateDigest: DIGEST,
    observedAt: "2026-07-26T10:00:45.000Z",
    freshUntil: "2026-07-26T10:05:00.000Z",
    matched: true,
  } as const;
  await assert.rejects(() =>
    recordWave1LifecycleEvent(
      input(store, {
        ...BINDING,
        eventId: "verified-event",
        previousEventId: "provider-event",
        previousState: "PROVIDER_DRAFT_CREATED",
        state: "PROVIDER_DRAFT_VERIFIED",
        occurredAt: "2026-07-26T10:00:50.000Z",
        actorId: "provider.readback",
        evidenceRefs: ["audit:provider-verified-1234"],
        artifactDigest: DIGEST,
        readbackReceipt,
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

  const transitions = [
    ["CONTEXT_ASSEMBLED", "context_assembly"],
    ["SCREENED", "injection_screening"],
    ["TRIAGED", "triage_result"],
    ["AUTHORITY_DECIDED", "authority_decision"],
    ["DRAFT_PROPOSED", "draft_proposal"],
    ["QUALITY_REVIEWED", "quality_evidence_bundle"],
    ["AWAITING_HUMAN_REVIEW", "human_review_record"],
  ] as const;
  let previous: {
    eventId: string;
    state: "NORMALIZED" | (typeof transitions)[number][0];
  } = normalized;
  for (const [state, artifactKind] of transitions) {
    const eventId = `${state.toLowerCase()}-event`;
    const evidenceRef = `audit:${state.toLowerCase()}-1234`;
    const next = {
      ...BINDING,
      eventId,
      previousEventId: previous.eventId,
      previousState: previous.state,
      state,
      occurredAt: "2026-07-26T10:00:20.000Z",
      actorId: "pipeline.actor",
      evidenceRefs: [evidenceRef],
      artifactDigest: DIGEST,
    };
    const evidence = {
      ...BINDING,
      eventId,
      previousEventId: previous.eventId,
      state,
      occurredAt: "2026-07-26T10:00:20.000Z",
      artifactKind,
      artifactDigest: DIGEST,
      evidence: {
        ...EVIDENCE.evidence,
        evidenceRef,
      },
    };
    assert.deepEqual(
      await recordWave1LifecycleEvent({
        ...input(store, next),
        resolveEvidence: () => evidence,
      }),
      next,
    );
    if (state === "DRAFT_PROPOSED") {
      await assert.rejects(() =>
        recordWave1LifecycleEvent({
          ...input(store, next),
          resolveEvidence: () => evidence,
          resolveActorAuthority: (_actorId, lifecycleState) =>
            lifecycleState === "DRAFT_PROPOSED" ? null : "pipeline.authority",
        }),
      );
    }
    previous = next;
  }
});

test("atomic tail comparison admits only one competing branch", async () => {
  const store = memoryStore();
  await recordWave1LifecycleEvent(input(store));
  const branch = (suffix: string) => {
    const eventId = `normalized-${suffix}`;
    const evidenceRef = `audit:normalized-${suffix}`;
    const event = {
      ...BINDING,
      eventId,
      previousEventId: EVENT.eventId,
      previousState: "RECEIVED",
      state: "NORMALIZED",
      occurredAt: "2026-07-26T10:00:10.000Z",
      actorId: "normalizer.actor",
      evidenceRefs: [evidenceRef],
      artifactDigest: DIGEST,
    } as const;
    return recordWave1LifecycleEvent({
      ...input(store, event),
      resolveEvidence: () => ({
        ...EVIDENCE,
        eventId,
        previousEventId: EVENT.eventId,
        state: "NORMALIZED",
        occurredAt: event.occurredAt,
        artifactKind: "normalized_thread",
        evidence: { ...EVIDENCE.evidence, evidenceRef },
      }),
    });
  };
  const outcomes = await Promise.allSettled([branch("a"), branch("b")]);
  assert.equal(
    outcomes.filter((outcome) => outcome.status === "fulfilled").length,
    1,
  );
  assert.equal(
    outcomes.filter((outcome) => outcome.status === "rejected").length,
    1,
  );
});
