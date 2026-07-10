import type { MailSendApproval, SendMessageInput } from "@aaliyah/contracts/v1";

/**
 * Claims an approval for sending — validates every bound field and atomically
 * transitions issued → sending against the DURABLE approval store. Adapters
 * call this at the top of `sendMessage`; automated flows hold no claimable
 * approval, so they cannot begin a send. Async since the B4 unlock: the claim
 * is a conditional database operation, atomic across instances.
 */
export type ApprovalConsumer = (input: SendMessageInput) => Promise<MailSendApproval>;

export type SendOutcome =
  | { sent: true; providerMessageId: string }
  | { sent: false; retryable: boolean };

export type SettleSendInput = {
  approvalId: string;
  /** The operation id assigned at claim time — settlement must present it. */
  operationId: string;
  outcome: SendOutcome;
};

/** Settles a claimed send. An ambiguous outcome must NOT be settled here — the
 * record stays `sending` for reconciliation. Returns the settled approval, or
 * null from the fail-closed default settler. */
export type SendSettler = (input: SettleSendInput) => Promise<MailSendApproval | null>;

/** Default consumer: refuse everything (fail closed; no auto-send). */
export const denyAllSends: ApprovalConsumer = async () => {
  throw new Error("send refused: no approval subsystem configured (no auto-send)");
};

export const noopSettler: SendSettler = async () => null;

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
