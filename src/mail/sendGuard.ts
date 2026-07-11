import type { MailSendApproval, SendMessageInput } from "@aaliyah/contracts/v1";

/**
 * Claims an approval for sending — validates every bound field and atomically
 * transitions issued → sending. Adapters call this at the top of `sendMessage`;
 * automated flows hold no claimable approval, so they cannot begin a send.
 */
export type ApprovalConsumer = (input: SendMessageInput) => MailSendApproval;

export type SendOutcome =
  | { sent: true; providerMessageId: string }
  | { sent: false; retryable: boolean };

/** Settles a claimed send. An ambiguous outcome must NOT be settled here — the
 * record stays `sending` for reconciliation. */
export type SendSettler = (approvalId: string, outcome: SendOutcome) => void;

/** Default consumer: refuse everything (fail closed; no auto-send). */
export const denyAllSends: ApprovalConsumer = () => {
  throw new Error("send refused: no approval subsystem configured (no auto-send)");
};

export const noopSettler: SendSettler = () => {};

/**
 * Classify a provider send error. Only an UNAMBIGUOUS rejection is settled; an
 * ambiguous failure (timeout / 5xx / network) returns null so the caller leaves
 * the record `sending` for reconciliation rather than guessing.
 */
export function classifySendError(error: unknown): SendOutcome | null {
  const message = error instanceof Error ? error.message : String(error);
  if (/\b4\d\d\b|\(4\d\d\)/.test(message)) {
    return { sent: false, retryable: false }; // client rejection: not delivered
  }
  if (/\b429\b/.test(message)) {
    return { sent: false, retryable: true }; // rate limited before send
  }
  return null; // ambiguous → do not settle; reconcile later
}
