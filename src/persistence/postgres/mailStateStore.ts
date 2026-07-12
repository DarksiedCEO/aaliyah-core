import type { Pool } from "pg";

import type {
  MailboxConnection,
  MailOAuthState,
  MailSendApproval,
} from "@aaliyah/contracts/v1";

import type { EnvelopeSealed } from "../../crypto/envelopeEncryption";
import type { TenantScope } from "../tenantScopedStore";
import type { MailAuditEvent } from "../../mail/security/mailAudit";

const iso = (value: Date | string | null): string | null =>
  value === null ? null : new Date(value).toISOString();

/** Durable credential: refresh token exists only as an envelope. */
export type DurableMailCredential = {
  connectionId: string;
  tenantId: string;
  workspaceId: string;
  userId: string;
  provider: "google";
  envelope: EnvelopeSealed;
  grantedScopes: string[];
  connectedEmail: string;
  accessTokenExpiresAt: string | null;
  revokedAt: string | null;
};

/**
 * Credential lifecycle state, persisted so every app instance sees the same
 * durable health signal. `healthy` is the coarse boolean; `state` is the
 * precise transition the last check produced.
 */
export type CredentialHealthState =
  | "healthy"
  | "refreshing"
  | "degraded"
  | "reauthorization_required"
  | "revoked";

export type ConnectionHealthRecord = {
  connectionId: string;
  tenantId: string;
  workspaceId: string;
  state: CredentialHealthState;
  healthy: boolean;
  detail: string | null;
  checkedAt: string;
};

export type ReconciliationRecord = {
  approvalId: string;
  operationId: string | null;
  checkedAt: string;
  outcome: string;
  detail: string | null;
};

export type PostgresMailState = ReturnType<typeof createPostgresMailState>;

/**
 * Durable, tenant-scoped mail state on Postgres. Every read filters on
 * tenant_id + workspace_id where a scope applies; one-time semantics (oauth
 * consume, approval claim) are single-statement conditional UPDATEs so they
 * stay atomic across many app instances — the property the in-memory Maps
 * could only promise per-process.
 */
export function createPostgresMailState(pool: Pool) {
  return {
    oauthStates: {
      async put(state: MailOAuthState): Promise<void> {
        await pool.query(
          `INSERT INTO mail_oauth_states
           (state_hash, provider, tenant_id, workspace_id, user_id, session_id,
            redirect_uri, code_verifier_encrypted, code_verifier_key_version,
            created_at, expires_at, consumed_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
          [
            state.stateHash, state.provider, state.tenantId, state.workspaceId,
            state.userId, state.sessionId, state.redirectUri,
            state.codeVerifierEncrypted, state.codeVerifierKeyVersion,
            state.createdAt, state.expiresAt, state.consumedAt,
          ],
        );
      },

      /**
       * Atomic one-time consume: the UPDATE claims the row only when it is
       * unconsumed AND unexpired AND redirect/session match. On failure a
       * follow-up read distinguishes the precise refusal (fail closed).
       */
      async consume(
        stateHash: string,
        input: { redirectUri: string; sessionId: string; now?: () => number },
      ): Promise<MailOAuthState> {
        const now = input.now ?? (() => Date.now());
        const nowIso = new Date(now()).toISOString();
        const claimed = await pool.query(
          `UPDATE mail_oauth_states SET consumed_at = $2
           WHERE state_hash = $1 AND consumed_at IS NULL AND expires_at > $2
             AND redirect_uri = $3 AND session_id = $4
           RETURNING *`,
          [stateHash, nowIso, input.redirectUri, input.sessionId],
        );
        if (claimed.rows.length === 1) {
          const r = claimed.rows[0];
          return {
            stateHash: r.state_hash, provider: r.provider,
            tenantId: r.tenant_id, workspaceId: r.workspace_id,
            userId: r.user_id, sessionId: r.session_id,
            redirectUri: r.redirect_uri,
            codeVerifierEncrypted: r.code_verifier_encrypted,
            codeVerifierKeyVersion: r.code_verifier_key_version,
            createdAt: iso(r.created_at)!, expiresAt: iso(r.expires_at)!,
            consumedAt: iso(r.consumed_at),
          };
        }
        const existing = await pool.query(
          "SELECT * FROM mail_oauth_states WHERE state_hash = $1",
          [stateHash],
        );
        const row = existing.rows[0];
        if (!row) throw new Error("oauth callback rejected: unknown state");
        if (row.consumed_at) throw new Error("oauth callback rejected: state already used");
        if (now() > new Date(row.expires_at).getTime()) {
          throw new Error("oauth callback rejected: state expired");
        }
        if (row.redirect_uri !== input.redirectUri) {
          throw new Error("oauth callback rejected: redirect URI mismatch");
        }
        if (row.session_id !== input.sessionId) {
          throw new Error("oauth callback rejected: session mismatch");
        }
        // Row matched every condition after the UPDATE missed: lost a race.
        throw new Error("oauth callback rejected: state already used");
      },
    },

    connections: {
      async save(conn: MailboxConnection): Promise<void> {
        await pool.query(
          `INSERT INTO mail_connections
           (connection_id, tenant_id, workspace_id, user_id, provider,
            email_address, auth_kind, status, connected_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
           ON CONFLICT (connection_id) DO UPDATE SET
             status = EXCLUDED.status, connected_at = EXCLUDED.connected_at`,
          [
            conn.connectionId, conn.tenantId, conn.workspaceId, conn.userId,
            conn.provider, conn.emailAddress, conn.authKind, conn.status,
            conn.connectedAt,
          ],
        );
      },

      async get(connectionId: string, scope: TenantScope): Promise<MailboxConnection | null> {
        const res = await pool.query(
          `SELECT * FROM mail_connections
           WHERE connection_id = $1 AND tenant_id = $2 AND workspace_id = $3`,
          [connectionId, scope.tenantId, scope.workspaceId],
        );
        const r = res.rows[0];
        if (!r) return null;
        return {
          connectionId: r.connection_id, tenantId: r.tenant_id,
          workspaceId: r.workspace_id, userId: r.user_id, provider: r.provider,
          emailAddress: r.email_address, authKind: r.auth_kind,
          status: r.status, connectedAt: iso(r.connected_at)!,
        };
      },

      async delete(connectionId: string): Promise<void> {
        await pool.query("DELETE FROM mail_connections WHERE connection_id = $1", [connectionId]);
      },
    },

    credentials: {
      async save(cred: DurableMailCredential): Promise<void> {
        await pool.query(
          `INSERT INTO mail_credentials
           (connection_id, tenant_id, workspace_id, user_id, provider, key_id,
            wrapped_data_key, ciphertext, granted_scopes, connected_email,
            access_token_expires_at, revoked_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
           ON CONFLICT (connection_id) DO UPDATE SET
             key_id = EXCLUDED.key_id,
             wrapped_data_key = EXCLUDED.wrapped_data_key,
             ciphertext = EXCLUDED.ciphertext,
             granted_scopes = EXCLUDED.granted_scopes,
             access_token_expires_at = EXCLUDED.access_token_expires_at,
             revoked_at = EXCLUDED.revoked_at`,
          [
            cred.connectionId, cred.tenantId, cred.workspaceId, cred.userId,
            cred.provider, cred.envelope.keyId, cred.envelope.wrappedDataKey,
            cred.envelope.ciphertext, JSON.stringify(cred.grantedScopes),
            cred.connectedEmail, cred.accessTokenExpiresAt, cred.revokedAt,
          ],
        );
      },

      async get(connectionId: string, scope: TenantScope): Promise<DurableMailCredential | null> {
        const res = await pool.query(
          `SELECT * FROM mail_credentials
           WHERE connection_id = $1 AND tenant_id = $2 AND workspace_id = $3`,
          [connectionId, scope.tenantId, scope.workspaceId],
        );
        const r = res.rows[0];
        if (!r) return null;
        return {
          connectionId: r.connection_id, tenantId: r.tenant_id,
          workspaceId: r.workspace_id, userId: r.user_id, provider: r.provider,
          envelope: { keyId: r.key_id, wrappedDataKey: r.wrapped_data_key, ciphertext: r.ciphertext },
          grantedScopes: r.granted_scopes,
          connectedEmail: r.connected_email,
          accessTokenExpiresAt: iso(r.access_token_expires_at),
          revokedAt: iso(r.revoked_at),
        };
      },

      /**
       * Record a successful refresh: bump the access-token expiry and, when the
       * provider rotated the refresh token, replace the envelope. Scoped and
       * refuses to touch a revoked row.
       */
      async touchAfterRefresh(
        connectionId: string,
        scope: TenantScope,
        input: { accessTokenExpiresAt: string; envelope?: EnvelopeSealed },
      ): Promise<void> {
        if (input.envelope) {
          await pool.query(
            `UPDATE mail_credentials
             SET access_token_expires_at = $4, key_id = $5,
                 wrapped_data_key = $6, ciphertext = $7
             WHERE connection_id = $1 AND tenant_id = $2 AND workspace_id = $3
               AND revoked_at IS NULL`,
            [
              connectionId, scope.tenantId, scope.workspaceId,
              input.accessTokenExpiresAt, input.envelope.keyId,
              input.envelope.wrappedDataKey, input.envelope.ciphertext,
            ],
          );
        } else {
          await pool.query(
            `UPDATE mail_credentials SET access_token_expires_at = $4
             WHERE connection_id = $1 AND tenant_id = $2 AND workspace_id = $3
               AND revoked_at IS NULL`,
            [connectionId, scope.tenantId, scope.workspaceId, input.accessTokenExpiresAt],
          );
        }
      },

      /** Revoke = destroy the ciphertext AND mark revoked — unrecoverable. */
      async revoke(connectionId: string, scope: TenantScope, now: () => string = () => new Date().toISOString()): Promise<void> {
        await pool.query(
          `UPDATE mail_credentials
           SET revoked_at = $4, ciphertext = 'revoked', wrapped_data_key = 'revoked'
           WHERE connection_id = $1 AND tenant_id = $2 AND workspace_id = $3 AND revoked_at IS NULL`,
          [connectionId, scope.tenantId, scope.workspaceId, now()],
        );
      },

      async delete(connectionId: string): Promise<void> {
        await pool.query("DELETE FROM mail_credentials WHERE connection_id = $1", [connectionId]);
      },
    },

    health: {
      async upsert(record: ConnectionHealthRecord): Promise<void> {
        await pool.query(
          `INSERT INTO mail_connection_health
           (connection_id, tenant_id, workspace_id, state, healthy, detail, checked_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7)
           ON CONFLICT (connection_id) DO UPDATE SET
             state = EXCLUDED.state, healthy = EXCLUDED.healthy,
             detail = EXCLUDED.detail, checked_at = EXCLUDED.checked_at`,
          [
            record.connectionId, record.tenantId, record.workspaceId,
            record.state, record.healthy, record.detail, record.checkedAt,
          ],
        );
      },

      async get(connectionId: string, scope: TenantScope): Promise<ConnectionHealthRecord | null> {
        const res = await pool.query(
          `SELECT * FROM mail_connection_health
           WHERE connection_id = $1 AND tenant_id = $2 AND workspace_id = $3`,
          [connectionId, scope.tenantId, scope.workspaceId],
        );
        const r = res.rows[0];
        if (!r) return null;
        return {
          connectionId: r.connection_id, tenantId: r.tenant_id,
          workspaceId: r.workspace_id, state: r.state,
          healthy: r.healthy, detail: r.detail, checkedAt: iso(r.checked_at)!,
        };
      },
    },

    sendApprovals: {
      async insert(approval: MailSendApproval): Promise<void> {
        await pool.query(
          `INSERT INTO mail_send_approvals
           (approval_id, tenant_id, workspace_id, connection_id, draft_id,
            recipient_hash, body_hash, approved_by_user_id, approved_at,
            expires_at, status, operation_id, provider_message_id, updated_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
          [
            approval.approvalId, approval.tenantId, approval.workspaceId,
            approval.connectionId, approval.draftId ?? null,
            approval.recipientHash, approval.bodyHash,
            approval.approvedByUserId, approval.approvedAt, approval.expiresAt,
            approval.status, approval.operationId, approval.providerMessageId,
            approval.updatedAt,
          ],
        );
      },

      async get(approvalId: string): Promise<MailSendApproval | null> {
        const res = await pool.query(
          "SELECT * FROM mail_send_approvals WHERE approval_id = $1",
          [approvalId],
        );
        return res.rows[0] ? approvalFromRow(res.rows[0]) : null;
      },

      /**
       * Atomic claim: issued (or a reconciled/unambiguous failed_retryable —
       * the certified B2 retry path) → sending with a fresh operation id, only
       * while unexpired. Concurrent claims race on the conditional UPDATE —
       * exactly one wins, across any number of instances; the rest get null
       * and must not send.
       */
      async claim(
        approvalId: string,
        input: { operationId: string; now?: () => string },
      ): Promise<MailSendApproval | null> {
        const now = input.now ?? (() => new Date().toISOString());
        const at = now();
        const res = await pool.query(
          `UPDATE mail_send_approvals
           SET status = 'sending', operation_id = $2, updated_at = $3
           WHERE approval_id = $1 AND status IN ('issued', 'failed_retryable')
             AND expires_at > $3
           RETURNING *`,
          [approvalId, input.operationId, at],
        );
        return res.rows[0] ? approvalFromRow(res.rows[0]) : null;
      },

      /**
       * Settle a claimed send — only from `sending`, only with the operation
       * id assigned at claim time. A wrong operation id or a duplicate
       * settlement is rejected loudly. Ambiguous outcomes are NEVER settled —
       * the row stays `sending` and surfaces via needingReconciliation.
       */
      async settle(
        approvalId: string,
        input: {
          operationId: string;
          outcome: { sent: true; providerMessageId: string } | { sent: false; retryable: boolean };
          now?: () => string;
        },
      ): Promise<MailSendApproval> {
        const now = input.now ?? (() => new Date().toISOString());
        const { outcome } = input;
        const status = outcome.sent
          ? "sent"
          : outcome.retryable
            ? "failed_retryable"
            : "failed_terminal";
        const res = await pool.query(
          `UPDATE mail_send_approvals
           SET status = $2,
               provider_message_id = COALESCE($3, provider_message_id),
               updated_at = $4
           WHERE approval_id = $1 AND status = 'sending' AND operation_id = $5
           RETURNING *`,
          [
            approvalId, status,
            outcome.sent ? outcome.providerMessageId : null,
            now(), input.operationId,
          ],
        );
        if (res.rows[0]) return approvalFromRow(res.rows[0]);
        const existing = await pool.query(
          "SELECT * FROM mail_send_approvals WHERE approval_id = $1",
          [approvalId],
        );
        const row = existing.rows[0];
        if (!row) throw new Error("settle refused: no such approval");
        if (row.status !== "sending") {
          throw new Error(`settle refused: approval is not sending (status=${row.status})`);
        }
        throw new Error("settle refused: operation id mismatch");
      },

      /** Expire an approval — conditional on `issued` so nothing in flight is touched. */
      async expire(
        approvalId: string,
        now: () => string = () => new Date().toISOString(),
      ): Promise<void> {
        await pool.query(
          `UPDATE mail_send_approvals SET status = 'expired', updated_at = $2
           WHERE approval_id = $1 AND status = 'issued'`,
          [approvalId, now()],
        );
      },

      /** Rows stuck `sending` since before the cutoff — the reconciliation queue. */
      async needingReconciliation(staleSinceEpochMs: number): Promise<MailSendApproval[]> {
        const res = await pool.query(
          `SELECT * FROM mail_send_approvals
           WHERE status = 'sending' AND updated_at <= $1
           ORDER BY updated_at`,
          [new Date(staleSinceEpochMs).toISOString()],
        );
        return res.rows.map(approvalFromRow);
      },

      async invalidateForConnection(
        connectionId: string,
        now: () => string = () => new Date().toISOString(),
      ): Promise<void> {
        await pool.query(
          `UPDATE mail_send_approvals SET status = 'failed_terminal', updated_at = $2
           WHERE connection_id = $1 AND status IN ('issued', 'sending')`,
          [connectionId, now()],
        );
      },
    },

    reconciliation: {
      async record(rec: ReconciliationRecord): Promise<void> {
        await pool.query(
          `INSERT INTO mail_reconciliation (approval_id, operation_id, checked_at, outcome, detail)
           VALUES ($1,$2,$3,$4,$5)`,
          [rec.approvalId, rec.operationId, rec.checkedAt, rec.outcome, rec.detail],
        );
      },

      async listForApproval(approvalId: string): Promise<ReconciliationRecord[]> {
        const res = await pool.query(
          `SELECT * FROM mail_reconciliation WHERE approval_id = $1 ORDER BY checked_at, id`,
          [approvalId],
        );
        return res.rows.map((r) => ({
          approvalId: r.approval_id, operationId: r.operation_id,
          checkedAt: iso(r.checked_at)!, outcome: r.outcome, detail: r.detail,
        }));
      },
    },

    jobMarkers: {
      async setStopped(marker: {
        connectionId: string;
        tenantId: string;
        workspaceId: string;
        stoppedAt: string;
      }): Promise<void> {
        await pool.query(
          `INSERT INTO mail_job_markers (connection_id, tenant_id, workspace_id, stopped_at)
           VALUES ($1,$2,$3,$4)
           ON CONFLICT (connection_id) DO UPDATE SET stopped_at = EXCLUDED.stopped_at`,
          [marker.connectionId, marker.tenantId, marker.workspaceId, marker.stoppedAt],
        );
      },

      async isStopped(connectionId: string): Promise<boolean> {
        const res = await pool.query(
          "SELECT 1 FROM mail_job_markers WHERE connection_id = $1",
          [connectionId],
        );
        return res.rows.length > 0;
      },
    },

    audit: {
      async append(event: MailAuditEvent): Promise<void> {
        await pool.query(
          `INSERT INTO mail_audit_events
           (audit_id, tenant_id, workspace_id, connection_id, actor_type,
            actor_user_id, actor_service_id, action, detail, at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
          [
            event.auditId, event.tenantId, event.workspaceId,
            event.connectionId ?? null, event.actorType ?? null,
            event.actorUserId ?? null, event.actorServiceId ?? null,
            event.action, event.detail ?? null, event.at,
          ],
        );
      },

      async read(scope: TenantScope): Promise<MailAuditEvent[]> {
        const res = await pool.query(
          `SELECT * FROM mail_audit_events
           WHERE tenant_id = $1 AND workspace_id = $2 ORDER BY at, audit_id`,
          [scope.tenantId, scope.workspaceId],
        );
        return res.rows.map((r) => ({
          auditId: r.audit_id, tenantId: r.tenant_id, workspaceId: r.workspace_id,
          ...(r.connection_id ? { connectionId: r.connection_id } : {}),
          ...(r.actor_type ? { actorType: r.actor_type } : {}),
          ...(r.actor_user_id ? { actorUserId: r.actor_user_id } : {}),
          ...(r.actor_service_id ? { actorServiceId: r.actor_service_id } : {}),
          action: r.action,
          ...(r.detail ? { detail: r.detail } : {}),
          at: iso(r.at)!,
        }));
      },
    },
  };
}

function approvalFromRow(r: Record<string, unknown>): MailSendApproval {
  return {
    approvalId: r.approval_id as string,
    tenantId: r.tenant_id as string,
    workspaceId: r.workspace_id as string,
    connectionId: r.connection_id as string,
    ...(r.draft_id ? { draftId: r.draft_id as string } : {}),
    recipientHash: r.recipient_hash as string,
    bodyHash: r.body_hash as string,
    approvedByUserId: r.approved_by_user_id as string,
    approvedAt: iso(r.approved_at as Date)!,
    expiresAt: iso(r.expires_at as Date)!,
    status: r.status as MailSendApproval["status"],
    operationId: (r.operation_id as string | null) ?? null,
    providerMessageId: (r.provider_message_id as string | null) ?? null,
    updatedAt: iso(r.updated_at as Date)!,
  };
}
