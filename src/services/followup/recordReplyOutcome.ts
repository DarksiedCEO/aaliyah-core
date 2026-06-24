import {
  ReplyOutcomeSchema,
  type ReplyOutcome,
} from "@aaliyah/contracts/v1";

import {
  scopeBucketKey,
  type TenantScope,
} from "../../persistence/tenantScopedStore";
import {
  appendJsonlFile,
  readJsonlFile,
  removeFileIfExists,
  replyOutcomeLogPath,
} from "./persistence";

// In-memory store partitioned by tenant/workspace bucket so a read for one
// scope never surfaces another's rows within the same process.
const replyOutcomeStores = new Map<string, ReplyOutcome[]>();

function bucket(scope?: TenantScope): ReplyOutcome[] {
  const key = scopeBucketKey(scope);
  let store = replyOutcomeStores.get(key);
  if (!store) {
    store = [];
    replyOutcomeStores.set(key, store);
  }
  return store;
}

export async function recordReplyOutcome(
  outcome: ReplyOutcome,
  scope?: TenantScope,
): Promise<ReplyOutcome> {
  const parsed = ReplyOutcomeSchema.parse(outcome);
  bucket(scope).push(parsed);
  appendJsonlFile(replyOutcomeLogPath(scope), parsed);
  return parsed;
}

export function listReplyOutcomes(scope?: TenantScope): ReplyOutcome[] {
  return [...bucket(scope), ...readJsonlFile<ReplyOutcome>(replyOutcomeLogPath(scope))]
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

export function clearReplyOutcomes(scope?: TenantScope): void {
  bucket(scope).length = 0;
  removeFileIfExists(replyOutcomeLogPath(scope));
}
