import crypto from "node:crypto";

import {
  MailSendApprovalSchema,
  type MailSendApproval,
  type MailAddress,
} from "@aaliyah/contracts/v1";

import type { TenantScope } from "../../persistence/tenantScopedStore";
import type { MailStateBackend } from "../mailState";
import type { ApprovalConsumer, SendSettler } from "../sendGuard";
import { bodyHash, recipientHash } from "./hashing";

// Durable send-approval service. Persistence lives behind MailStateBackend —
// Postgres in production (conditional single-statement claim/settle, atomic
// across instances), the conformance-tested in-memory twin for dev/tests.
// There is NO module-level store: two sources of truth are worse than one.

const DEFAULT_TTL_MS = 15 * 60 * 1000;
/** How long a `sending` record may sit before it is considered ambiguous. */
export const RECONCILE_AFTER_MS = 60 * 1000;

export type ApprovalDeps = { state: MailStateBackend };

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

/**
 * Audit a send-plane mutation — fail closed. If the audit record cannot be
 * persisted the mutation is reported failed; a claim left `sending` by an
 * audit failure surfaces through reconciliation, never through a silent send.
 * Audit never contains message content — only ids and hashes already stored.
 */
async function auditOrFail(
  deps: ApprovalDeps,
  approval: MailSendApproval,
  action: string,
  detail?: string,
): Promise<void> {
  try {
    await deps.state.audit.append({
      auditId: crypto.randomUUID(),
      tenantId: approval.tenantId,
      workspaceId: approval.workspaceId,
      connectionId: approval.connectionId,
      action,
      ...(detail ? { detail } : {}),
      at: new Date().toISOString(),
    });
  } catch (error) {
    throw new Error(
      `audit persistence failed for ${action}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

/** Record a human approval to send ONE specific message (status `issued`). */
export async function issueSendApproval(
  input: IssueApprovalInput,
  deps: ApprovalDeps,
): Promise<MailSendApproval> {
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
  await deps.state.sendApprovals.insert(approval);
  try {
    await auditOrFail(deps, approval, "mail.approval.issued", `by=${input.approvedByUserId}`);
  } catch (error) {
    // Fail closed: an unaudited approval must not remain claimable. Expire is
    // conditional on `issued`, so exactly this record is neutralized.
    await deps.state.sendApprovals.expire(approval.approvalId);
    throw error;
  }
  return approval;
}

/**
 * Build the ApprovalConsumer for the guarded send path. Claiming validates the
 * approval against the message actually being sent — tenant/workspace scope,
 * connection, draft, recipient and content hashes, approver — then atomically
 * transitions `issued` (or a reconciled `failed_retryable`) → `sending` with a
 * fresh stable operationId, persisted BEFORE any provider execution. Throws —
 * fail closed — on any mismatch, expiry, an in-flight `sending` (must
 * reconcile first), or a spent `sent`/`failed_terminal`/`expired`. This is the
 * ONLY way to begin a send.
 */
export function createBeginSend(
  deps: ApprovalDeps,
  opts: { scope?: TenantScope; now?: () => number } = {},
): ApprovalConsumer {
  return async (input) => {
    const now = opts.now ?? (() => Date.now());
    const approval = await deps.state.sendApprovals.get(input.approvalId);

    if (!approval) throw new Error("send refused: no such approval");

    if (opts.scope) {
      if (approval.tenantId !== opts.scope.tenantId) {
        throw new Error("send refused: tenant scope mismatch");
      }
      if (approval.workspaceId !== opts.scope.workspaceId) {
        throw new Error("send refused: workspace scope mismatch");
      }
    }

    if (now() > new Date(approval.expiresAt).getTime() && approval.status === "issued") {
      await deps.state.sendApprovals.expire(input.approvalId, () => iso(now()));
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

    // Atomic conditional claim — exactly one winner across all instances. The
    // validation above is on immutable bound fields, so it cannot race.
    const claimed = await deps.state.sendApprovals.claim(input.approvalId, {
      operationId: crypto.randomUUID(),
      now: () => iso(now()),
    });
    if (!claimed) {
      throw new Error("send refused: approval was claimed concurrently or is no longer claimable");
    }
    // Audit BEFORE the caller may touch the provider: if this fails, no send
    // happens; the claim stays `sending` and surfaces via reconciliation.
    await auditOrFail(deps, claimed, "mail.approval.claimed", `op=${claimed.operationId}`);
    return claimed;
  };
}

/**
 * Build the SendSettler for the guarded send path. Settlement is accepted only
 * from `sending` and only with the operationId assigned at claim time; wrong
 * ids and duplicates are rejected loudly. Ambiguous outcomes must never be
 * settled — leave the record `sending` for reconciliation.
 */
export function createSendSettler(
  deps: ApprovalDeps,
  opts: { now?: () => number } = {},
): SendSettler {
  return async (input) => {
    const now = opts.now ?? (() => Date.now());
    const settled = await deps.state.sendApprovals.settle(input.approvalId, {
      operationId: input.operationId,
      outcome: input.outcome,
      now: () => iso(now()),
    });
    await auditOrFail(
      deps,
      settled,
      "mail.send.settled",
      `op=${input.operationId} status=${settled.status}`,
    );
    return settled;
  };
}

/**
 * Reconcile an ambiguous `sending` record after checking the provider for the
 * message: delivered → `sent`; confirmed-not-delivered → `failed_retryable`.
 * Only reconciliation can move a record out of `sending`; it is never
 * automatic. The decision is durably recorded and audited.
 */
export async function reconcileSend(
  approvalId: string,
  wasDelivered: boolean,
  providerMessageId: string | undefined,
  deps: ApprovalDeps,
  now: () => number = () => Date.now(),
): Promise<void> {
  const approval = await deps.state.sendApprovals.get(approvalId);
  if (!approval || approval.status !== "sending" || !approval.operationId) return;

  const settled = await deps.state.sendApprovals.settle(approvalId, {
    operationId: approval.operationId,
    outcome: wasDelivered
      ? { sent: true, providerMessageId: providerMessageId ?? approval.providerMessageId ?? "unknown" }
      : { sent: false, retryable: true },
    now: () => iso(now()),
  });
  await deps.state.reconciliation.record({
    approvalId,
    operationId: approval.operationId,
    checkedAt: iso(now()),
    outcome: wasDelivered ? "confirmed_delivered" : "confirmed_not_delivered",
    detail: providerMessageId ?? null,
  });
  await auditOrFail(
    deps,
    settled,
    "mail.reconciliation.decided",
    wasDelivered ? "confirmed_delivered" : "confirmed_not_delivered",
  );
}

/** Approvals stuck `sending` past the reconcile window — need provider lookup. */
export async function approvalsNeedingReconciliation(
  deps: ApprovalDeps,
  now: () => number = () => Date.now(),
): Promise<MailSendApproval[]> {
  return deps.state.sendApprovals.needingReconciliation(now() - RECONCILE_AFTER_MS);
}

export async function getApproval(
  approvalId: string,
  deps: ApprovalDeps,
): Promise<MailSendApproval | null> {
  return deps.state.sendApprovals.get(approvalId);
}

/** Terminally fail every non-sent approval for a connection (used on disconnect). */
export async function invalidateApprovalsForConnection(
  connectionId: string,
  deps: ApprovalDeps,
  now: () => number = () => Date.now(),
): Promise<void> {
  await deps.state.sendApprovals.invalidateForConnection(connectionId, () => iso(now()));
}
