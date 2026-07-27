import crypto from "node:crypto";

import {
  InboundDraftRequestSchema,
  InboundDraftResultSchema,
  type InboundDraftResult,
} from "@aaliyah/contracts/v1";

import { logger } from "../../observability/logger";
import { persistTrace } from "../../observability/persistTrace";
import { requireTenantContext } from "../../governance/requireTenantContext";
import {
  ensureIdempotentExecution,
  recordIdempotentFailure,
  recordIdempotentResult,
} from "../../persistence/idempotencyStore";
import { analyzeInbound } from "./analyzeInbound";
import type { DraftGenerator } from "./generateInboundDraft";
import { requireSafeMailHeader } from "./untrustedContent";

export type InboundDraftRuntime = {
  generator: DraftGenerator;
  authorize: (
    email: Parameters<DraftGenerator>[0]["email"],
  ) => Promise<{
    allowed: boolean;
    risk: "green" | "yellow" | "red";
    confidence: number;
    reason: string;
  }>;
};

let quarantinedLegacyRuntime: InboundDraftRuntime | undefined;

/** @deprecated Legacy runtime is quarantined and cannot reach a provider. */
export function configureInboundDraftRuntime(runtime: InboundDraftRuntime): void {
  quarantinedLegacyRuntime = runtime;
}

/** @deprecated Legacy runtime is quarantined and cannot reach a provider. */
export function clearInboundDraftRuntime(): void {
  quarantinedLegacyRuntime = undefined;
}

/**
 * Legacy inbound entry point. It may classify no-action mail, but any
 * reply-worthy message fails closed before model, credential, or provider
 * access. Trusted executive drafting uses runTrustedExecutiveDraftReviewOnly.
 */
export async function runInboundDraft(raw: unknown): Promise<InboundDraftResult> {
  const request = InboundDraftRequestSchema.parse(raw);
  requireSafeMailHeader("from", request.email.fromEmail);
  requireSafeMailHeader("subject", request.email.subject);
  requireSafeMailHeader("message_id", request.email.messageId);
  const tenant = requireTenantContext({
    tenantId: request.tenantId,
    userId: request.userId,
    workspaceId: request.workspaceId,
  });
  const scope = { tenantId: tenant.tenantId, workspaceId: tenant.workspaceId };
  const idempotencyKey = `inbound:${request.email.messageId}`;

  const idempotency = await ensureIdempotentExecution<InboundDraftResult>(
    idempotencyKey,
    request,
    "inbound_draft",
    scope,
  );

  if (idempotency.replay && idempotency.result) {
    logger.info(
      { messageId: request.email.messageId, tenantId: tenant.tenantId },
      "aaliyah.inbound.replayed",
    );
    return idempotency.result;
  }

  try {
    const analysis = analyzeInbound(request.email);
    const traceId = crypto.randomUUID();

    if (!analysis.shouldDraft) {
      const skipped = InboundDraftResultSchema.parse({
        threadId: request.email.threadId,
        status: "no_action",
        mode: "inbound_draft",
        autoSend: false,
        reason: analysis.reason,
      });

      await persistTrace({
        traceId,
        ...scope,
        userId: tenant.userId,
        flow: "inbound_draft",
        messageId: request.email.messageId,
        decisionPath: "inbound -> no_action",
        analysis,
        outcome: skipped,
      });
      await recordIdempotentResult(idempotencyKey, skipped, scope);
      return skipped;
    }

    // This legacy request-body entry point cannot establish a server-authenticated
    // principal or independently resolve the Phase 5 evidence registries. It is
    // therefore permanently fail-closed before model, credential, or provider
    // access. Trusted callers must use runTrustedExecutiveDraftReviewOnly.
    const blocked = InboundDraftResultSchema.parse({
      threadId: request.email.threadId,
      status: "failed",
      mode: "inbound_draft",
      autoSend: false,
      reason: "trusted_executive_runtime_required",
    });
    await persistTrace({
      traceId,
      ...scope,
      userId: tenant.userId,
      flow: "inbound_draft",
      messageId: request.email.messageId,
      decisionPath: "inbound -> failed_closed",
      analysis,
      outcome: blocked,
    });
    await recordIdempotentResult(idempotencyKey, blocked, scope);
    return blocked;
  } catch (error) {
    await recordIdempotentFailure(
      idempotencyKey,
      error instanceof Error ? error.message : "unknown error",
      scope,
    );
    throw error;
  }
}
