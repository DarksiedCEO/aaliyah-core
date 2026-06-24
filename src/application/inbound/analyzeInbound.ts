import type { InboundEmail, InboundReplyType } from "@aaliyah/contracts/v1";

export type InboundAnalysis = {
  shouldDraft: boolean;
  replyType: InboundReplyType;
  reason: string;
};

const NON_REPLYABLE_PATTERNS = [
  /no-?reply@/i,
  /do-?not-?reply@/i,
  /mailer-daemon@/i,
  /postmaster@/i,
  /notifications?@/i,
];

/**
 * Deterministic reply-worthiness analysis for inbound mail. This is platform
 * logic, fully independent of the frozen follow-up doctrine — it decides only
 * whether to DRAFT a reply, never whether to send one.
 */
export function analyzeInbound(email: InboundEmail): InboundAnalysis {
  if (NON_REPLYABLE_PATTERNS.some((pattern) => pattern.test(email.fromEmail))) {
    return {
      shouldDraft: false,
      replyType: "first_touch",
      reason: "sender is a non-replyable system address",
    };
  }

  if (email.body.trim().length === 0) {
    return {
      shouldDraft: false,
      replyType: "first_touch",
      reason: "inbound message has no body to respond to",
    };
  }

  const isReply = /^\s*re:/i.test(email.subject);

  return {
    shouldDraft: true,
    replyType: isReply ? "existing_conversation" : "first_touch",
    reason: isReply
      ? "ongoing conversation warranting a reply draft"
      : "first-touch inbound warranting a reply draft",
  };
}
