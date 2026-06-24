import {
  InboundDraftRequestSchema,
  InboundDraftResultSchema,
  type InboundDraftResult,
} from "@aaliyah/contracts/v1";

import { logger } from "../../observability/logger";
import { persistTrace } from "../../observability/persistTrace";
import { requireTenantContext } from "../../governance/requireTenantContext";
import { getCredential } from "../../governance/credentialProvider";
import { createGmailDraft } from "../../integrations/gmail/createDraft";
import {
  ensureIdempotentExecution,
  recordIdempotentFailure,
  recordIdempotentResult,
} from "../../persistence/idempotencyStore";
import { analyzeInbound } from "./analyzeInbound";
import {
  deterministicDraftGenerator,
  type DraftGenerator,
} from "./generateInboundDraft";
import { buildConfidence } from "../trust/confidenceEngine";
import { recordDecisionTrace } from "../trust/decisionTrace";

/**
 * Injectable seams so the flow is testable without Gmail/credentials and so the
 * model router (Block 3) can replace the generator with no flow change.
 */
export const inboundDraftInternals: {
  generator: DraftGenerator;
  createDraft: (rawMessage: string, accessToken: string) => Promise<string>;
  resolveAccessToken: (
    tenantId: string,
    userId: string,
    workspaceId?: string,
  ) => string;
} = {
  generator: deterministicDraftGenerator,
  createDraft: createGmailDraft,
  resolveAccessToken: (tenantId, userId, workspaceId) =>
    getCredential(tenantId, userId, "google", workspaceId).accessToken,
};

function buildRawReply(input: {
  toEmail: string;
  subject: string;
  body: string;
  inReplyToMessageId: string;
}): string {
  return [
    `To: ${input.toEmail}`,
    `Subject: ${input.subject}`,
    `In-Reply-To: ${input.inReplyToMessageId}`,
    `References: ${input.inReplyToMessageId}`,
    'Content-Type: text/plain; charset="UTF-8"',
    "",
    input.body,
  ].join("\r\n");
}

/**
 * Inbound Draft Mode: analyze an inbound email, draft a reply, save it as a
 * Gmail draft, and leave it pending human approval. NEVER sends. The follow-up
 * doctrine and guarded-execution path are not involved.
 */
export async function runInboundDraft(raw: unknown): Promise<InboundDraftResult> {
  const request = InboundDraftRequestSchema.parse(raw);
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

    if (!analysis.shouldDraft) {
      const skipped = InboundDraftResultSchema.parse({
        threadId: request.email.threadId,
        status: "no_action",
        mode: "inbound_draft",
        autoSend: false,
        reason: analysis.reason,
      });

      await persistTrace({
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

    const draft = await inboundDraftInternals.generator({
      email: request.email,
      replyType: analysis.replyType,
    });

    const accessToken = inboundDraftInternals.resolveAccessToken(
      tenant.tenantId,
      tenant.userId,
      tenant.workspaceId,
    );

    const rawMessage = buildRawReply({
      // A reply is addressed to the sender of the inbound message. `toEmail`
      // (the user's own address that received it) is never the reply target.
      toEmail: request.email.fromEmail,
      subject: draft.subject,
      body: draft.body,
      inReplyToMessageId: request.email.messageId,
    });

    const draftId = await inboundDraftInternals.createDraft(rawMessage, accessToken);

    // Trust metadata (Block 6): confidence on every generated draft. Low
    // confidence forces manual review — inbound already requires approval
    // unconditionally, so the draft stays awaiting_approval regardless.
    const confidence = buildConfidence(
      draft.confidence,
      `${analysis.reason}; generator=${draft.generatorMode}`,
    );

    const result = InboundDraftResultSchema.parse({
      threadId: request.email.threadId,
      status: "awaiting_approval",
      mode: "inbound_draft",
      autoSend: false,
      draftId,
      replyType: draft.replyType,
      generatorMode: draft.generatorMode,
      confidence,
    });

    // Every inbound draft has a decision trace.
    recordDecisionTrace({
      tenantId: tenant.tenantId,
      workspaceId: tenant.workspaceId,
      userId: tenant.userId,
      inputSummary: `inbound ${request.email.messageId} from ${request.email.fromEmail}`,
      decision: "draft_reply_awaiting_approval",
      evidenceUsed: [request.email.threadId],
      reason: confidence.reason,
      provider: draft.generatorMode,
    });

    await persistTrace({
      ...scope,
      userId: tenant.userId,
      flow: "inbound_draft",
      messageId: request.email.messageId,
      decisionPath: "inbound -> awaiting_approval",
      analysis,
      generatorMode: draft.generatorMode,
      outcome: result,
    });
    await recordIdempotentResult(idempotencyKey, result, scope);

    logger.info(
      { messageId: request.email.messageId, tenantId: tenant.tenantId, draftId },
      "aaliyah.inbound.draft_saved",
    );
    return result;
  } catch (error) {
    await recordIdempotentFailure(
      idempotencyKey,
      error instanceof Error ? error.message : "unknown error",
      scope,
    );
    throw error;
  }
}
