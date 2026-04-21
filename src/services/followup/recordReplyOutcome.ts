import {
  ReplyOutcomeSchema,
  type ReplyOutcome,
} from "@aaliyah/contracts/v1";

import {
  appendJsonlFile,
  readJsonlFile,
  removeFileIfExists,
  replyOutcomeLogPath,
} from "./persistence";

const replyOutcomeStore: ReplyOutcome[] = [];

export async function recordReplyOutcome(
  outcome: ReplyOutcome,
): Promise<ReplyOutcome> {
  const parsed = ReplyOutcomeSchema.parse(outcome);
  replyOutcomeStore.push(parsed);
  appendJsonlFile(replyOutcomeLogPath(), parsed);
  return parsed;
}

export function listReplyOutcomes(): ReplyOutcome[] {
  return [...replyOutcomeStore, ...readJsonlFile<ReplyOutcome>(replyOutcomeLogPath())]
    .filter(
      (record, index, records) =>
        records.findIndex(
          (candidate) =>
            candidate.taskId === record.taskId &&
            candidate.threadId === record.threadId &&
            candidate.createdAt === record.createdAt,
        ) === index,
    );
}

export function clearReplyOutcomes(): void {
  replyOutcomeStore.length = 0;
  removeFileIfExists(replyOutcomeLogPath());
}
