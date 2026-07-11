import {
  FollowupOutcomeSchema,
  type FollowupOutcome,
  type FollowupOutcomeStatus,
} from "@aaliyah/contracts/v1";

import {
  scopeBucketKey,
  type TenantScope,
} from "../../persistence/tenantScopedStore";
import {
  appendJsonlFile,
  followupOutcomeLogPath,
  readJsonlFile,
  removeFileIfExists,
} from "./persistence";

// Per-(tenant, workspace) bucket of outcomes. Keeping the transition state
// per-bucket means a taskId/threadId in one workspace can never be mistaken for
// the same identifiers in another, so the doctrine's transition checks stay
// correct under multi-tenancy.
const outcomeStores = new Map<string, Map<string, FollowupOutcome>>();

const allowedTransitions: Record<FollowupOutcomeStatus, FollowupOutcomeStatus[]> = {
  detected: ["drafted", "dismissed", "escalated"],
  drafted: ["approved", "dismissed", "escalated"],
  approved: ["sent", "escalated"],
  sent: [],
  escalated: [],
  dismissed: [],
};

function key(taskId: string, threadId: string): string {
  return `${taskId}:${threadId}`;
}

function bucket(scope?: TenantScope): Map<string, FollowupOutcome> {
  const bucketKey = scopeBucketKey(scope);
  let store = outcomeStores.get(bucketKey);
  if (!store) {
    store = new Map<string, FollowupOutcome>();
    outcomeStores.set(bucketKey, store);
  }
  return store;
}

export async function trackFollowupOutcome(
  outcome: FollowupOutcome,
  scope?: TenantScope,
): Promise<FollowupOutcome> {
  const parsed = FollowupOutcomeSchema.parse(outcome);
  const store = bucket(scope);
  const existing = store.get(key(parsed.taskId, parsed.threadId));

  if (existing) {
    const allowed = allowedTransitions[existing.status] ?? [];
    if (!allowed.includes(parsed.status)) {
      throw new Error("Illegal follow-up outcome transition");
    }
  }

  store.set(key(parsed.taskId, parsed.threadId), parsed);
  appendJsonlFile(followupOutcomeLogPath(scope), parsed);
  return parsed;
}

export function getTrackedFollowupOutcome(
  taskId: string,
  threadId: string,
  scope?: TenantScope,
): FollowupOutcome | undefined {
  return bucket(scope).get(key(taskId, threadId));
}

export function listTrackedFollowupOutcomes(scope?: TenantScope): FollowupOutcome[] {
  return [
    ...bucket(scope).values(),
    ...readJsonlFile<FollowupOutcome>(followupOutcomeLogPath(scope)),
  ].filter(
    (record, index, records) =>
      records.findIndex(
        (candidate) =>
          candidate.taskId === record.taskId &&
          candidate.threadId === record.threadId &&
          candidate.status === record.status,
      ) === index,
  );
}

export function clearTrackedFollowupOutcomes(scope?: TenantScope): void {
  bucket(scope).clear();
  removeFileIfExists(followupOutcomeLogPath(scope));
}
