import type {
  InboundEmail,
  InboundGeneratedDraft,
  InboundReplyType,
} from "@aaliyah/contracts/v1";

export type DraftGeneratorInput = {
  email: InboundEmail;
  replyType: InboundReplyType;
};

/**
 * Pluggable draft generator. Block 2 ships a deterministic default; Block 3
 * (Multi-Model Router) will inject a router-backed generator here WITHOUT any
 * change to the inbound flow. Business logic must never depend on a specific
 * provider — it depends only on this interface.
 */
export type DraftGenerator = (
  input: DraftGeneratorInput,
) => Promise<InboundGeneratedDraft>;

function replySubject(subject: string): string {
  const trimmed = subject.trim();
  if (trimmed.length === 0) {
    return "Re: your message";
  }
  return /^\s*re:/i.test(trimmed) ? trimmed : `Re: ${trimmed}`;
}

/**
 * Deterministic, provider-free draft. Intentionally conservative — it produces
 * a safe acknowledgement that a human edits and approves. Quality improves when
 * the model router is wired in (Block 3); the flow and safety contract do not.
 */
export const deterministicDraftGenerator: DraftGenerator = async ({
  email,
  replyType,
}) => {
  const greeting =
    replyType === "first_touch" ? "Thanks for reaching out." : "Thanks for the note.";

  const body = [
    greeting,
    "",
    "I've received your message and will follow up with the details shortly.",
    "",
    "Best,",
  ].join("\n");

  return {
    subject: replySubject(email.subject),
    body,
    replyType,
    confidence: 40,
    generatorMode: "deterministic-v1",
  };
};
