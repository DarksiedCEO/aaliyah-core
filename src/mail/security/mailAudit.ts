import crypto from "node:crypto";

import type { TenantScope } from "../../persistence/tenantScopedStore";
import type { MailStateBackend } from "../mailState";

export type MailAuditEvent = {
  auditId: string;
  tenantId: string;
  workspaceId: string;
  connectionId?: string;
  /** Who acted: a human session or a workload identity. */
  actorType?: "user" | "service";
  actorUserId?: string;
  actorServiceId?: string;
  action: string;
  detail?: string;
  at: string;
};

/**
 * Append a security-sensitive mail audit event to the durable audit store —
 * the SOLE production audit sink. NEVER contains secrets (tokens, ciphertext,
 * message content) — only actions, ids, and non-secret detail.
 *
 * Throws when the record cannot be persisted; callers apply the policy:
 * administrative and send-related mutations fail closed, health reads may
 * continue with an operational error signal.
 */
export async function recordMailAudit(
  input: {
    tenantId: string;
    workspaceId: string;
    connectionId?: string;
    actorType?: "user" | "service";
    actorUserId?: string;
    actorServiceId?: string;
    action: string;
    detail?: string;
    now?: () => string;
  },
  store: MailStateBackend["audit"],
): Promise<MailAuditEvent> {
  const now = input.now ?? (() => new Date().toISOString());
  const event: MailAuditEvent = {
    auditId: crypto.randomUUID(),
    tenantId: input.tenantId,
    workspaceId: input.workspaceId,
    ...(input.connectionId ? { connectionId: input.connectionId } : {}),
    ...(input.actorType ? { actorType: input.actorType } : {}),
    ...(input.actorUserId ? { actorUserId: input.actorUserId } : {}),
    ...(input.actorServiceId ? { actorServiceId: input.actorServiceId } : {}),
    action: input.action,
    ...(input.detail ? { detail: input.detail } : {}),
    at: now(),
  };
  await store.append(event);
  return event;
}

export async function readMailAudit(
  scope: TenantScope,
  store: MailStateBackend["audit"],
): Promise<MailAuditEvent[]> {
  return store.read(scope);
}
