import {
  AuditLifecycleEventSchema,
  LifecycleArtifactKindSchema,
  LifecycleEvidenceRecordSchema,
  Wave1AuthorityIdSchema,
  assertWave1EvidenceFresh,
  sameWave1Binding,
} from "@aaliyah/contracts/v1";
import { z } from "zod";

type LifecycleEvent = z.infer<typeof AuditLifecycleEventSchema>;
type LifecycleEvidence = z.infer<typeof LifecycleEvidenceRecordSchema>;

const INTERMEDIATE_ARTIFACT = {
  RECEIVED: "inbound_message",
  NORMALIZED: "normalized_thread",
  CONTEXT_ASSEMBLED: "context_assembly",
  SCREENED: "injection_screening",
  TRIAGED: "triage_result",
  AUTHORITY_DECIDED: "authority_decision",
  DRAFT_PROPOSED: "draft_proposal",
  QUALITY_REVIEWED: "quality_evidence_bundle",
  AWAITING_HUMAN_REVIEW: "human_review_record",
  FAILED: "failure_record",
} as const satisfies Record<string, z.infer<typeof LifecycleArtifactKindSchema>>;

export interface Wave1LifecycleStore {
  findByEventId(
    tenantId: string,
    workspaceId: string,
    eventId: string,
  ): Promise<LifecycleEvent | null>;
  findByIdempotencyKey(
    tenantId: string,
    workspaceId: string,
    taskId: string,
    idempotencyKey: string,
  ): Promise<LifecycleEvent | null>;
  appendIfCurrent(input: {
    event: LifecycleEvent;
    expectedPreviousEventId: string | null;
  }): Promise<LifecycleEvent | null>;
}

export interface RecordWave1LifecycleEventInput {
  raw: unknown;
  trustedNowMs: number;
  store: Wave1LifecycleStore;
  resolveEvidence: (evidenceRef: string) => LifecycleEvidence | null;
  resolveActorAuthority: (
    actorId: string,
    state: LifecycleEvent["state"],
    tenantId: string,
    workspaceId: string,
  ) => string | null;
}

function exactRecord(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

export async function recordWave1LifecycleEvent(
  input: RecordWave1LifecycleEventInput,
): Promise<LifecycleEvent> {
  if (!Number.isFinite(input.trustedNowMs)) {
    throw new Error("trusted lifecycle clock must be finite");
  }
  const event = AuditLifecycleEventSchema.parse(input.raw);
  if (
    event.state === "PROVIDER_DRAFT_CREATED" ||
    event.state === "PROVIDER_DRAFT_VERIFIED"
  ) {
    throw new Error(
      "provider lifecycle states require independent provider verification",
    );
  }
  if (new Date(event.occurredAt).getTime() > input.trustedNowMs) {
    throw new Error("lifecycle event is future-dated");
  }
  if (event.evidenceRefs.length === 0) {
    throw new Error("lifecycle event requires authoritative evidence");
  }

  const authority = Wave1AuthorityIdSchema.safeParse(
    input.resolveActorAuthority(
      event.actorId,
      event.state,
      event.tenantId,
      event.workspaceId,
    ),
  );
  if (!authority.success) {
    throw new Error("lifecycle actor authority is unavailable");
  }

  for (const evidenceRef of event.evidenceRefs) {
    const parsedEvidence = LifecycleEvidenceRecordSchema.safeParse(
      input.resolveEvidence(evidenceRef),
    );
    if (
      !parsedEvidence.success ||
      parsedEvidence.data.evidence.evidenceRef !== evidenceRef ||
      parsedEvidence.data.eventId !== event.eventId ||
      parsedEvidence.data.state !== event.state ||
      parsedEvidence.data.previousEventId !== event.previousEventId ||
      parsedEvidence.data.occurredAt !== event.occurredAt ||
      parsedEvidence.data.artifactKind !== INTERMEDIATE_ARTIFACT[event.state] ||
      parsedEvidence.data.artifactDigest !== event.artifactDigest ||
      !sameWave1Binding(parsedEvidence.data, event)
    ) {
      throw new Error("lifecycle evidence is missing or mismatched");
    }
    assertWave1EvidenceFresh(parsedEvidence.data.evidence, input.trustedNowMs);
    if (
      new Date(parsedEvidence.data.evidence.observedAt).getTime() >
      new Date(event.occurredAt).getTime()
    ) {
      throw new Error("lifecycle event predates its evidence");
    }
  }

  const existing = await input.store.findByIdempotencyKey(
    event.tenantId,
    event.workspaceId,
    event.taskId,
    event.idempotencyKey,
  );
  if (existing) {
    const parsedExisting = AuditLifecycleEventSchema.safeParse(existing);
    if (parsedExisting.success && exactRecord(parsedExisting.data, event)) {
      const independentlyRead = AuditLifecycleEventSchema.safeParse(
        await input.store.findByEventId(
          event.tenantId,
          event.workspaceId,
          event.eventId,
        ),
      );
      if (
        !independentlyRead.success ||
        !exactRecord(independentlyRead.data, parsedExisting.data)
      ) {
        throw new Error("lifecycle replay persistence read-back failed");
      }
      return independentlyRead.data;
    }
    if (
      !parsedExisting.success ||
      parsedExisting.data.eventId !== event.previousEventId
    ) {
      throw new Error("conflicting lifecycle idempotency record");
    }
  }

  if (event.previousEventId) {
    const parsedPrevious = AuditLifecycleEventSchema.safeParse(
      await input.store.findByEventId(
        event.tenantId,
        event.workspaceId,
        event.previousEventId,
      ),
    );
    if (
      !parsedPrevious.success ||
      parsedPrevious.data.eventId !== event.previousEventId ||
      parsedPrevious.data.state !== event.previousState ||
      !sameWave1Binding(parsedPrevious.data, event) ||
      new Date(parsedPrevious.data.occurredAt).getTime() >
        new Date(event.occurredAt).getTime()
    ) {
      throw new Error("lifecycle predecessor is missing or mismatched");
    }
  }

  const stored = await input.store.appendIfCurrent({
    event,
    expectedPreviousEventId: event.previousEventId ?? null,
  });
  const parsedStored = AuditLifecycleEventSchema.safeParse(stored);
  if (!parsedStored.success || !exactRecord(parsedStored.data, event)) {
    throw new Error("lifecycle persistence read-back failed");
  }
  const independentlyRead = AuditLifecycleEventSchema.safeParse(
    await input.store.findByEventId(
      event.tenantId,
      event.workspaceId,
      event.eventId,
    ),
  );
  if (
    !independentlyRead.success ||
    !exactRecord(independentlyRead.data, parsedStored.data)
  ) {
    throw new Error("lifecycle persistence read-back failed");
  }
  return independentlyRead.data;
}
