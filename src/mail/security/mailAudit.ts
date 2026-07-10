import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import {
  scopedJsonlPath,
  type TenantScope,
} from "../../persistence/tenantScopedStore";

const FILE = "mail-audit.jsonl";

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
 * Append a security-sensitive mail audit event. NEVER contains secrets (tokens,
 * ciphertext) — only actions, ids, and non-secret detail.
 */
export function recordMailAudit(input: {
  tenantId: string;
  workspaceId: string;
  connectionId?: string;
  actorType?: "user" | "service";
  actorUserId?: string;
  actorServiceId?: string;
  action: string;
  detail?: string;
  now?: () => string;
}): MailAuditEvent {
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
  const fp = scopedJsonlPath(FILE, {
    tenantId: input.tenantId,
    workspaceId: input.workspaceId,
  });
  fs.mkdirSync(path.dirname(fp), { recursive: true });
  fs.appendFileSync(fp, `${JSON.stringify(event)}\n`, "utf8");
  return event;
}

export function readMailAudit(scope: TenantScope): MailAuditEvent[] {
  const fp = scopedJsonlPath(FILE, scope);
  if (!fs.existsSync(fp)) return [];
  return fs
    .readFileSync(fp, "utf8")
    .split("\n")
    .filter((l) => l.trim().length > 0)
    .map((l) => JSON.parse(l) as MailAuditEvent);
}
