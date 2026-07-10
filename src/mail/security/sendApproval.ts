import crypto from "node:crypto";

import {
  MailSendApprovalSchema,
  type MailSendApproval,
  type MailAddress,
  type SendMessageInput,
} from "@aaliyah/contracts/v1";

import { bodyHash, recipientHash } from "./hashing";

// Process-local approval store. In production this MUST be a durable,
// tenant-scoped, transactional table so consume() is atomic across instances.
const store = new Map<string, MailSendApproval>();

const DEFAULT_TTL_MS = 15 * 60 * 1000;

export type IssueApprovalInput = {
  tenantId: string;
  workspaceId: string;
  connectionId: string;
  draftId?: string;
  to: MailAddress[];
  subject: string;
  body: string;
  approvedByUserId: string;
  ttlMs?: number;
  now?: () => number;
};

/**
 * Record a human approval to send ONE specific message. Called only after a
 * real person approved the exact content; it binds tenant/workspace/connection/
 * recipients/body so nothing else can be substituted later.
 */
export function issueSendApproval(input: IssueApprovalInput): MailSendApproval {
  if (!input.approvedByUserId) {
    throw new Error("cannot issue send approval without an approver");
  }
  const now = input.now ?? (() => Date.now());
  const at = now();
  const approval = MailSendApprovalSchema.parse({
    approvalId: crypto.randomUUID(),
    tenantId: input.tenantId,
    workspaceId: input.workspaceId,
    connectionId: input.connectionId,
    ...(input.draftId ? { draftId: input.draftId } : {}),
    recipientHash: recipientHash(input.to),
    bodyHash: bodyHash(input.subject, input.body),
    approvedByUserId: input.approvedByUserId,
    approvedAt: new Date(at).toISOString(),
    expiresAt: new Date(at + (input.ttlMs ?? DEFAULT_TTL_MS)).toISOString(),
    consumedAt: null,
  });
  store.set(approval.approvalId, approval);
  return approval;
}

/**
 * Validate the approval against the message actually being sent and consume it
 * atomically. Throws — fail closed — on any mismatch, expiry, or reuse. Because
 * consumption happens before the network send, a spent approval can never be
 * replayed even if the send itself later fails.
 */
export function consumeSendApproval(
  input: SendMessageInput,
  ctx?: { now?: () => number },
): MailSendApproval {
  const now = ctx?.now ?? (() => Date.now());
  const approval = store.get(input.approvalId);

  if (!approval) throw new Error("send refused: no such approval");
  if (approval.consumedAt) throw new Error("send refused: approval already consumed");
  if (now() > new Date(approval.expiresAt).getTime()) {
    throw new Error("send refused: approval expired");
  }
  if (approval.connectionId !== input.connectionId) {
    throw new Error("send refused: connection mismatch");
  }
  if (input.draftId && approval.draftId && approval.draftId !== input.draftId) {
    throw new Error("send refused: draft mismatch");
  }
  if (approval.recipientHash !== recipientHash(input.to)) {
    throw new Error("send refused: recipient mismatch");
  }
  if (approval.bodyHash !== bodyHash(input.subject ?? "", input.body)) {
    throw new Error("send refused: content mismatch (possible tamper)");
  }
  if (!approval.approvedByUserId) {
    throw new Error("send refused: no authorized approver");
  }

  // Atomic consume (single-threaded event loop): mark spent before returning.
  const consumed = { ...approval, consumedAt: new Date(now()).toISOString() };
  store.set(approval.approvalId, consumed);
  return consumed;
}

/** Invalidate every pending approval for a connection (used on disconnect). */
export function invalidateApprovalsForConnection(connectionId: string): number {
  let count = 0;
  const at = new Date().toISOString();
  for (const [id, a] of store) {
    if (a.connectionId === connectionId && !a.consumedAt) {
      store.set(id, { ...a, consumedAt: at });
      count += 1;
    }
  }
  return count;
}

export function clearSendApprovals(): void {
  store.clear();
}
