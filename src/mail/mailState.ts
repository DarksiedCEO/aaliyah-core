import type {
  MailboxConnection,
  MailOAuthState,
  MailSendApproval,
} from "@aaliyah/contracts/v1";

import type { TenantScope } from "../persistence/tenantScopedStore";
import type { MailAuditEvent } from "./security/mailAudit";
import {
  createPostgresMailState,
  type ConnectionHealthRecord,
  type DurableMailCredential,
  type ReconciliationRecord,
} from "../persistence/postgres/mailStateStore";

/**
 * The mail-state backend contract. Postgres is the production implementation
 * (createPostgresMailState); the in-memory implementation below exists for
 * dev/tests with the SAME semantics, conformance-tested side by side.
 */
export type MailStateBackend = ReturnType<typeof createPostgresMailState>;

export function createInMemoryMailState(): MailStateBackend & {
  /** Test-only: raw stored records for at-rest assertions. */
  dump(): Record<string, unknown[]>;
} {
  const oauthStates = new Map<string, MailOAuthState>();
  const connections = new Map<string, MailboxConnection>();
  const credentials = new Map<string, DurableMailCredential>();
  const health = new Map<string, ConnectionHealthRecord>();
  const approvals = new Map<string, MailSendApproval>();
  const reconciliation: ReconciliationRecord[] = [];
  const jobMarkers = new Map<string, { tenantId: string; workspaceId: string; stoppedAt: string }>();
  const audit: MailAuditEvent[] = [];

  const scoped = <T extends { tenantId: string; workspaceId: string }>(
    record: T | undefined,
    scope: TenantScope,
  ): T | null =>
    record && record.tenantId === scope.tenantId && record.workspaceId === scope.workspaceId
      ? record
      : null;

  return {
    oauthStates: {
      async put(state) {
        oauthStates.set(state.stateHash, state);
      },
      async consume(stateHash, input) {
        const now = input.now ?? (() => Date.now());
        const state = oauthStates.get(stateHash);
        if (!state) throw new Error("oauth callback rejected: unknown state");
        if (state.consumedAt) throw new Error("oauth callback rejected: state already used");
        if (now() > new Date(state.expiresAt).getTime()) {
          throw new Error("oauth callback rejected: state expired");
        }
        if (state.redirectUri !== input.redirectUri) {
          throw new Error("oauth callback rejected: redirect URI mismatch");
        }
        if (state.sessionId !== input.sessionId) {
          throw new Error("oauth callback rejected: session mismatch");
        }
        const consumed = { ...state, consumedAt: new Date(now()).toISOString() };
        oauthStates.set(stateHash, consumed);
        return consumed;
      },
    },

    connections: {
      async save(conn) {
        connections.set(conn.connectionId, conn);
      },
      async get(connectionId, scope) {
        return scoped(connections.get(connectionId), scope);
      },
      async delete(connectionId) {
        connections.delete(connectionId);
      },
    },

    credentials: {
      async save(cred) {
        credentials.set(cred.connectionId, cred);
      },
      async get(connectionId, scope) {
        return scoped(credentials.get(connectionId), scope);
      },
      async revoke(connectionId, scope, now = () => new Date().toISOString()) {
        const record = scoped(credentials.get(connectionId), scope);
        if (!record || record.revokedAt) return;
        credentials.set(connectionId, {
          ...record,
          envelope: { keyId: record.envelope.keyId, wrappedDataKey: "revoked", ciphertext: "revoked" },
          revokedAt: now(),
        });
      },
      async delete(connectionId) {
        credentials.delete(connectionId);
      },
    },

    health: {
      async upsert(record) {
        health.set(record.connectionId, record);
      },
      async get(connectionId, scope) {
        return scoped(health.get(connectionId), scope);
      },
    },

    sendApprovals: {
      async insert(approval) {
        approvals.set(approval.approvalId, approval);
      },
      async get(approvalId) {
        return approvals.get(approvalId) ?? null;
      },
      async claim(approvalId, input) {
        const now = input.now ?? (() => new Date().toISOString());
        const at = now();
        const approval = approvals.get(approvalId);
        // Synchronous check-and-set — atomic within the event loop turn.
        if (
          !approval ||
          approval.status !== "issued" ||
          new Date(approval.expiresAt).getTime() <= new Date(at).getTime()
        ) {
          return null;
        }
        const claimed: MailSendApproval = {
          ...approval,
          status: "sending",
          operationId: input.operationId,
          updatedAt: at,
        };
        approvals.set(approvalId, claimed);
        return claimed;
      },
      async settle(approvalId, outcome, now = () => new Date().toISOString()) {
        const approval = approvals.get(approvalId);
        if (!approval || approval.status !== "sending") return;
        approvals.set(approvalId, {
          ...approval,
          status: outcome.sent ? "sent" : outcome.retryable ? "failed_retryable" : "failed_terminal",
          providerMessageId: outcome.sent ? outcome.providerMessageId : approval.providerMessageId,
          updatedAt: now(),
        });
      },
      async needingReconciliation(staleSinceEpochMs) {
        return [...approvals.values()]
          .filter(
            (a) => a.status === "sending" && new Date(a.updatedAt).getTime() <= staleSinceEpochMs,
          )
          .sort((a, b) => a.updatedAt.localeCompare(b.updatedAt));
      },
      async invalidateForConnection(connectionId, now = () => new Date().toISOString()) {
        for (const [id, approval] of approvals) {
          if (
            approval.connectionId === connectionId &&
            (approval.status === "issued" || approval.status === "sending")
          ) {
            approvals.set(id, { ...approval, status: "failed_terminal", updatedAt: now() });
          }
        }
      },
    },

    reconciliation: {
      async record(rec) {
        reconciliation.push(rec);
      },
      async listForApproval(approvalId) {
        return reconciliation
          .filter((r) => r.approvalId === approvalId)
          .sort((a, b) => a.checkedAt.localeCompare(b.checkedAt));
      },
    },

    jobMarkers: {
      async setStopped(marker) {
        jobMarkers.set(marker.connectionId, {
          tenantId: marker.tenantId,
          workspaceId: marker.workspaceId,
          stoppedAt: marker.stoppedAt,
        });
      },
      async isStopped(connectionId) {
        return jobMarkers.has(connectionId);
      },
    },

    audit: {
      async append(event) {
        audit.push(event);
      },
      async read(scope) {
        return audit.filter(
          (e) => e.tenantId === scope.tenantId && e.workspaceId === scope.workspaceId,
        );
      },
    },

    dump() {
      return {
        oauthStates: [...oauthStates.values()],
        connections: [...connections.values()],
        credentials: [...credentials.values()],
        health: [...health.values()],
        approvals: [...approvals.values()],
        reconciliation: [...reconciliation],
        jobMarkers: [...jobMarkers.entries()],
        audit: [...audit],
      };
    },
  };
}
