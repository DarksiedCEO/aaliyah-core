import type { MailSendApproval, SendMessageInput } from "@aaliyah/contracts/v1";

/**
 * A send may only proceed by validating and atomically consuming a server-issued
 * approval that binds tenant/workspace/connection/recipients/body. Adapters call
 * the injected consumer at the top of `sendMessage`; automated flows hold no
 * valid, unconsumed approval, so they cannot send.
 */
export type ApprovalConsumer = (input: SendMessageInput) => MailSendApproval;

/**
 * Default consumer: refuse everything. An adapter with no approval subsystem
 * wired can never send — fail closed by construction.
 */
export const denyAllSends: ApprovalConsumer = () => {
  throw new Error("send refused: no approval subsystem configured (no auto-send)");
};
