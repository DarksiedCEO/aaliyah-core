import crypto from "node:crypto";

import {
  MailSendApprovalSchema,
  type MailSendApproval,
  type MailAddress,
  type SendMessageInput,
} from "@aaliyah/contracts/v1";

import { bodyHash, recipientHash } from "./hashing";

// Process-local approval store. In production this MUST be a durable,
// tenant-scoped, transactional table so the issued→sending transition is atomic
// across instances (a conditional UPDATE ... WHERE status='issued').
const store = new Map<string, MailSendApproval>();

const DEFAULT_TTL_MS = 15 * 60 * 1000;
/** How long a `sending` record may sit before it is considered ambiguous. */
export const RECONCILE_AFTER_MS = 60 * 1000;

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

function iso(ms: number): string {
  return new Date(ms).toISOString();
}

/** Record a human approval to send ONE specific message (status `issued`). */
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
    approvedAt: iso(at),
    expiresAt: iso(at + (input.ttlMs ?? DEFAULT_TTL_MS)),
    status: "issued",
    operationId: null,
    providerMessageId: null,
    updatedAt: iso(at),
  });
  store.set(approval.approvalId, approval);
  return approval;
}

/**
 * Claim an approval for sending: validate it against the message actually being
 * sent and atomically transition `issued` (or a reconciled `failed_retryable`)
 * → `sending`, assigning a stable operationId. Throws — fail closed — on any
 * mismatch, expiry, an in-flight `sending` (must reconcile first), or a spent
 * `sent`/`failed_terminal`. This is the ONLY way to begin a send.
 */
export function beginSend(
  input: SendMessageInput,
  ctx?: { now?: () => number },
): MailSendApproval {
  const now = ctx?.now ?? (() => Date.now());
  const approval = store.get(input.approvalId);

  if (!approval) throw new Error("send refused: no such approval");

  if (now() > new Date(approval.expiresAt).getTime() && approval.status === "issued") {
    const expired = { ...approval, status: "expired" as const, updatedAt: iso(now()) };
    store.set(approval.approvalId, expired);
    throw new Error("send refused: approval expired");
  }

  switch (approval.status) {
    case "sending":
      throw new Error("send refused: a send is already in flight — reconcile first");
    case "sent":
      throw new Error("send refused: already sent");
    case "failed_terminal":
      throw new Error("send refused: approval terminally failed");
    case "expired":
      throw new Error("send refused: approval expired");
    case "issued":
    case "failed_retryable":
      break; // claimable
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

  const claimed: MailSendApproval = {
    ...approval,
    status: "sending",
    operationId: crypto.randomUUID(),
    updatedAt: iso(now()),
  };
  store.set(approval.approvalId, claimed);
  return claimed;
}

export function markSent(
  approvalId: string,
  providerMessageId: string,
  now: () => number = () => Date.now(),
): void {
  const a = store.get(approvalId);
  if (!a || a.status !== "sending") return;
  store.set(approvalId, { ...a, status: "sent", providerMessageId, updatedAt: iso(now()) });
}

export function markFailed(
  approvalId: string,
  retryable: boolean,
  now: () => number = () => Date.now(),
): void {
  const a = store.get(approvalId);
  if (!a || a.status !== "sending") return;
  store.set(approvalId, {
    ...a,
    status: retryable ? "failed_retryable" : "failed_terminal",
    updatedAt: iso(now()),
  });
}

/**
 * Reconcile an ambiguous `sending` record after checking the provider for the
 * message: delivered → `sent`; confirmed-not-delivered → `failed_retryable`.
 * Only reconciliation can move a record out of `sending`.
 */
export function reconcileSend(
  approvalId: string,
  wasDelivered: boolean,
  providerMessageId?: string,
  now: () => number = () => Date.now(),
): void {
  const a = store.get(approvalId);
  if (!a || a.status !== "sending") return;
  store.set(
    approvalId,
    wasDelivered
      ? { ...a, status: "sent", providerMessageId: providerMessageId ?? a.providerMessageId, updatedAt: iso(now()) }
      : { ...a, status: "failed_retryable", updatedAt: iso(now()) },
  );
}

/** Approvals stuck `sending` past the reconcile window — need provider lookup. */
export function approvalsNeedingReconciliation(
  now: () => number = () => Date.now(),
): MailSendApproval[] {
  return [...store.values()].filter(
    (a) => a.status === "sending" && now() - new Date(a.updatedAt).getTime() > RECONCILE_AFTER_MS,
  );
}

export function getApproval(approvalId: string): MailSendApproval | undefined {
  return store.get(approvalId);
}

/** Terminally fail every non-sent approval for a connection (used on disconnect). */
export function invalidateApprovalsForConnection(connectionId: string): number {
  let count = 0;
  const at = new Date().toISOString();
  for (const [id, a] of store) {
    if (a.connectionId === connectionId && a.status !== "sent" && a.status !== "failed_terminal") {
      store.set(id, { ...a, status: "failed_terminal", updatedAt: at });
      count += 1;
    }
  }
  return count;
}

export function clearSendApprovals(): void {
  store.clear();
}
