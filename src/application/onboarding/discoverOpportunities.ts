import type { DraftOpportunity, InboundEmail } from "@aaliyah/contracts/v1";

import { analyzeInbound } from "../inbound/analyzeInbound";

/**
 * Surface the most useful first draft opportunities from a sample of inbox
 * messages, reusing the inbound reply-worthiness analysis. Read-only — it never
 * drafts or sends, it only points at threads worth drafting for.
 */
export function discoverOpportunities(
  inbox: InboundEmail[],
  max = 3,
): DraftOpportunity[] {
  const opportunities: DraftOpportunity[] = [];

  for (const email of inbox) {
    const analysis = analyzeInbound(email);
    if (analysis.shouldDraft) {
      opportunities.push({
        threadId: email.threadId,
        messageId: email.messageId,
        fromEmail: email.fromEmail,
        subject: email.subject,
        reason: analysis.reason,
      });
    }
    if (opportunities.length >= max) {
      break;
    }
  }

  return opportunities;
}
