import {
  FollowupOutcomeSchema,
  type FollowupOutcome,
  type FollowupOutcomeStatus,
} from "@aaliyah/contracts/v1";

import {
  appendJsonlFile,
  followupOutcomeLogPath,
  readJsonlFile,
  removeFileIfExists,
} from "./persistence";

const outcomeStore = new Map<string, FollowupOutcome>();

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

export async function trackFollowupOutcome(
  outcome: FollowupOutcome,
): Promise<FollowupOutcome> {
  const parsed = FollowupOutcomeSchema.parse(outcome);
  const existing = outcomeStore.get(key(parsed.taskId, parsed.threadId));

  if (existing) {
    const allowed = allowedTransitions[existing.status] ?? [];
    if (!allowed.includes(parsed.status)) {
      throw new Error("Illegal follow-up outcome transition");
    }
  }

  outcomeStore.set(key(parsed.taskId, parsed.threadId), parsed);
  appendJsonlFile(followupOutcomeLogPath(), parsed);
  return parsed;
}

export function getTrackedFollowupOutcome(
  taskId: string,
  threadId: string,
): FollowupOutcome | undefined {
  return outcomeStore.get(key(taskId, threadId));
}

export function listTrackedFollowupOutcomes(): FollowupOutcome[] {
  return [...outcomeStore.values(), ...readJsonlFile<FollowupOutcome>(followupOutcomeLogPath())]
    .filter(
      (record, index, records) =>
        records.findIndex(
          (candidate) =>
            candidate.taskId === record.taskId &&
            candidate.threadId === record.threadId &&
            candidate.status === record.status,
        ) === index,
    );
}

export function clearTrackedFollowupOutcomes(): void {
  outcomeStore.clear();
  removeFileIfExists(followupOutcomeLogPath());
}
