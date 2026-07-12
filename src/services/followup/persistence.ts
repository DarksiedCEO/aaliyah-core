import { LEGACY_BUCKET, type TenantScope } from "../../persistence/tenantScopedStore";
import { applicationStoreFromEnv } from "../../persistence/applicationState";
import type { ApprovalReviewRecord } from "./recordApprovalReview";

// Durable follow-up persistence. Formerly JSON/JSONL under a data directory
// (which does not survive a disposable container filesystem); now backed by the
// shared durable application store — Postgres in production (fail-closed via
// applicationStoreFromEnv, no local-file fallback), in-memory twin for
// dev/tests. Public data shapes, scoping, and dedup semantics are unchanged.

const REPLY_OUTCOME_STORE = "followup_reply_outcomes";
const FOLLOWUP_OUTCOME_STORE = "followup_outcomes";

/** Scope-free callers share one legacy bucket, matching the prior flat-path
 * behaviour for records recorded without a (tenant, workspace). */
function scopeOrLegacy(scope?: TenantScope): TenantScope {
  return scope ?? { tenantId: LEGACY_BUCKET, workspaceId: LEGACY_BUCKET };
}

// ---- Reply outcomes (append-only history) ----

export async function appendReplyOutcome(record: unknown, scope?: TenantScope): Promise<void> {
  await applicationStoreFromEnv().logs.append(REPLY_OUTCOME_STORE, scopeOrLegacy(scope), record);
}

export async function listReplyOutcomeHistory<T>(scope?: TenantScope): Promise<T[]> {
  return (await applicationStoreFromEnv().logs.list(REPLY_OUTCOME_STORE, scopeOrLegacy(scope))) as T[];
}

export async function clearReplyOutcomeHistory(scope?: TenantScope): Promise<void> {
  await applicationStoreFromEnv().logs.clear(REPLY_OUTCOME_STORE, scopeOrLegacy(scope));
}

// ---- Follow-up outcomes (append-only history) ----

export async function appendFollowupOutcome(record: unknown, scope?: TenantScope): Promise<void> {
  await applicationStoreFromEnv().logs.append(FOLLOWUP_OUTCOME_STORE, scopeOrLegacy(scope), record);
}

export async function listFollowupOutcomeHistory<T>(scope?: TenantScope): Promise<T[]> {
  return (await applicationStoreFromEnv().logs.list(FOLLOWUP_OUTCOME_STORE, scopeOrLegacy(scope))) as T[];
}

export async function clearFollowupOutcomeHistory(scope?: TenantScope): Promise<void> {
  await applicationStoreFromEnv().logs.clear(FOLLOWUP_OUTCOME_STORE, scopeOrLegacy(scope));
}

// ---- Approval reviews (typed table) ----
// Signatures preserved exactly — recordApprovalReview.ts (frozen) depends on
// them. Only the storage backing changed (fail-closed durable store, no file).

export async function persistApprovalReview(
  review: ApprovalReviewRecord,
  scope?: TenantScope,
): Promise<void> {
  await applicationStoreFromEnv().approvals.insert(review, scope);
}

export async function listPersistedApprovalReviews(
  scope?: TenantScope,
): Promise<ApprovalReviewRecord[]> {
  return applicationStoreFromEnv().approvals.list(scope);
}

export async function clearPersistedApprovalReviews(scope?: TenantScope): Promise<void> {
  await applicationStoreFromEnv().approvals.clear(scope);
}
