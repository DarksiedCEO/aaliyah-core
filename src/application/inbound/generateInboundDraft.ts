import type {
  InboundEmail,
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
export type GeneratedDraftCandidate = {
  subject: string;
  body: string;
  replyType: InboundReplyType;
  generatorMode: string;
};

export type DraftGenerator = (
  input: DraftGeneratorInput,
) => Promise<GeneratedDraftCandidate>;
