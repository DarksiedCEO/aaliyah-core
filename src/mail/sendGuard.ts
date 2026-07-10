import type { SendMessageInput } from "@aaliyah/contracts/v1";

/**
 * Aaliyah never auto-sends. `sendMessage` may only proceed with an approval
 * token that a human-approval step issued for THIS connection. Adapters call
 * this at the top of `sendMessage`; automated flows hold no token, so they
 * cannot send.
 */
export function assertSendApproved(
  input: SendMessageInput,
  isValidToken: (connectionId: string, token: string) => boolean,
): void {
  if (!input.approvalToken || !isValidToken(input.connectionId, input.approvalToken)) {
    throw new Error(
      "Refusing to send: a valid human-approval token is required (no auto-send)",
    );
  }
}
