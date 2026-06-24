import {
  ApprovalReviewSchema,
  type ApprovalReview,
} from "@aaliyah/contracts/v1";

import {
  scopeBucketKey,
  type TenantScope,
} from "../../persistence/tenantScopedStore";
import {
  clearPersistedApprovalReviews,
  listPersistedApprovalReviews,
  persistApprovalReview,
} from "./persistence";

export type ApprovalReviewRecord = ApprovalReview & {
  reviewerRole?: string;
  draftConfidence: number;
  reviewSource?: "seeded" | "live_operator";
  category?: string;
  liveOperatorPilot?: boolean;
};

// In-memory store partitioned by tenant/workspace bucket (see recordReplyOutcome).
const approvalReviewStores = new Map<string, ApprovalReviewRecord[]>();

function bucket(scope?: TenantScope): ApprovalReviewRecord[] {
  const key = scopeBucketKey(scope);
  let store = approvalReviewStores.get(key);
  if (!store) {
    store = [];
    approvalReviewStores.set(key, store);
  }
  return store;
}

function normalizeRejectionReason(reason: string | undefined): string | undefined {
  if (!reason || reason.trim().length === 0) {
    return "other_unspecified";
  }

  const normalized = reason.trim().toLowerCase();
  const normalizedWords = normalized.replace(/[^a-z0-9\s]/g, " ");

  if (
    normalized === "reviewer rejected follow-up draft." ||
    normalized === "reviewer rejected follow-up draft"
  ) {
    return "other_unspecified";
  }

  if (normalized.includes("tone")) {
    return "tone_off";
  }

  if (
    normalized.includes("too aggressive") ||
    normalized.includes("aggressive") ||
    normalized.includes("too strong") ||
    normalized.includes("harsh")
  ) {
    return "tone_off";
  }

  if (normalized.includes("owner") || normalized.includes("voice")) {
    return "wrong_owner_voice";
  }

  if (
    normalized.includes("context") ||
    normalized.includes("missing detail") ||
    normalized.includes("missing info") ||
    normalized.includes("needs more detail")
  ) {
    return "missing_context";
  }

  if (
    normalized.includes("incorrect") ||
    normalized.includes("not owed") ||
    normalized.includes("shouldn't send") ||
    normalized.includes("shouldnt send") ||
    normalized.includes("not needed") ||
    normalized.includes("no follow-up needed")
  ) {
    return "incorrect_followup";
  }

  if (normalized.includes("generic")) {
    return "too_generic";
  }

  if (
    normalized.includes("timing") ||
    normalized.includes("too early") ||
    normalized.includes("too late")
  ) {
    return "timing_wrong";
  }

  if (
    normalized.includes("cta") ||
    normalized.includes("call to action") ||
    normalizedWords.includes("unclear ask") ||
    normalizedWords.includes("weak ask") ||
    normalized.includes("weak close")
  ) {
    return "cta_weak";
  }

  return "other_unspecified";
}

export async function recordApprovalReview(
  review: ApprovalReviewRecord,
  scope?: TenantScope,
): Promise<ApprovalReviewRecord> {
  const base = ApprovalReviewSchema.parse(review);
  let parsed: ApprovalReviewRecord = {
    ...base,
    rejectionReason: review.approved
      ? undefined
      : normalizeRejectionReason(review.rejectionReason),
    draftConfidence: review.draftConfidence,
  };

  if (typeof review.reviewerRole === "string") {
    parsed = { ...parsed, reviewerRole: review.reviewerRole };
  }

  if (review.reviewSource === "seeded" || review.reviewSource === "live_operator") {
    parsed = { ...parsed, reviewSource: review.reviewSource };
  }

  if (typeof review.category === "string") {
    parsed = { ...parsed, category: review.category };
  }

  if (typeof review.liveOperatorPilot === "boolean") {
    parsed = { ...parsed, liveOperatorPilot: review.liveOperatorPilot };
  }

  bucket(scope).push(parsed);
  await persistApprovalReview(parsed, scope);
  return parsed;
}

export async function listApprovalReviews(
  scope?: TenantScope,
): Promise<ApprovalReviewRecord[]> {
  return [...bucket(scope), ...(await listPersistedApprovalReviews(scope))]
    .filter(
      (record, index, records) =>
        records.findIndex(
          (candidate) =>
            candidate.taskId === record.taskId &&
            candidate.threadId === record.threadId &&
            candidate.reviewedAt === record.reviewedAt,
        ) === index,
    );
}

export async function clearApprovalReviews(scope?: TenantScope): Promise<void> {
  bucket(scope).length = 0;
  await clearPersistedApprovalReviews(scope);
}
