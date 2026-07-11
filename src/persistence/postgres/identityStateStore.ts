import type { Pool } from "pg";

import type {
  AuthSession,
  ExternalProvider,
  ServiceIdentity,
  UserIdentity,
  WorkspaceMembership,
} from "@aaliyah/contracts/v1";

const iso = (value: Date | string | null): string | null =>
  value === null ? null : new Date(value).toISOString();

function userFromRow(r: Record<string, unknown>): UserIdentity {
  return {
    id: r.id as string,
    tenantId: r.tenant_id as string,
    externalProvider: r.external_provider as UserIdentity["externalProvider"],
    externalSubject: r.external_subject as string,
    email: r.email as string,
    emailVerified: r.email_verified as boolean,
    status: r.status as UserIdentity["status"],
    createdAt: iso(r.created_at as Date)!,
    updatedAt: iso(r.updated_at as Date)!,
  };
}

function membershipFromRow(r: Record<string, unknown>): WorkspaceMembership {
  return {
    userId: r.user_id as string,
    tenantId: r.tenant_id as string,
    workspaceId: r.workspace_id as string,
    roleIds: r.role_ids as string[],
    status: r.status as WorkspaceMembership["status"],
    createdAt: iso(r.created_at as Date)!,
    revokedAt: iso(r.revoked_at as Date | null),
  };
}

function sessionFromRow(r: Record<string, unknown>): AuthSession {
  return {
    id: r.id as string,
    userId: r.user_id as string,
    tenantId: r.tenant_id as string,
    sessionTokenHash: r.session_token_hash as string,
    authStrength: r.auth_strength as AuthSession["authStrength"],
    createdAt: iso(r.created_at as Date)!,
    expiresAt: iso(r.expires_at as Date)!,
    lastSeenAt: iso(r.last_seen_at as Date)!,
    revokedAt: iso(r.revoked_at as Date | null),
  };
}

function serviceFromRow(r: Record<string, unknown>): ServiceIdentity {
  return {
    id: r.id as string,
    tenantId: (r.tenant_id as string | null) ?? null,
    name: r.name as string,
    permissionIds: r.permission_ids as string[],
    credentialHash: r.credential_hash as string,
    status: r.status as ServiceIdentity["status"],
    createdAt: iso(r.created_at as Date)!,
    rotatedAt: iso(r.rotated_at as Date)!,
  };
}

/**
 * Durable identity state on Postgres — the authoritative production source of
 * user → tenant → workspace → roles, sessions (hash-addressed), and workload
 * identities. Revocations are single UPDATEs, visible to every instance on
 * the next read: no per-process identity truth.
 */
export function createPostgresIdentityState(pool: Pool) {
  return {
    users: {
      async create(user: UserIdentity): Promise<void> {
        await pool.query(
          `INSERT INTO auth_users
           (id, tenant_id, external_provider, external_subject, email,
            email_verified, status, created_at, updated_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
          [
            user.id, user.tenantId, user.externalProvider, user.externalSubject,
            user.email, user.emailVerified, user.status, user.createdAt, user.updatedAt,
          ],
        );
      },

      async get(id: string): Promise<UserIdentity | null> {
        const res = await pool.query("SELECT * FROM auth_users WHERE id = $1", [id]);
        return res.rows[0] ? userFromRow(res.rows[0]) : null;
      },

      async findByExternalSubject(
        provider: ExternalProvider,
        subject: string,
      ): Promise<UserIdentity | null> {
        const res = await pool.query(
          "SELECT * FROM auth_users WHERE external_provider = $1 AND external_subject = $2",
          [provider, subject],
        );
        return res.rows[0] ? userFromRow(res.rows[0]) : null;
      },

      async setStatus(
        id: string,
        status: UserIdentity["status"],
        now: () => string = () => new Date().toISOString(),
      ): Promise<void> {
        await pool.query("UPDATE auth_users SET status = $2, updated_at = $3 WHERE id = $1", [
          id, status, now(),
        ]);
      },
    },

    memberships: {
      async grant(membership: WorkspaceMembership): Promise<void> {
        await pool.query(
          `INSERT INTO workspace_memberships
           (user_id, tenant_id, workspace_id, role_ids, status, created_at, revoked_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7)
           ON CONFLICT (user_id, tenant_id, workspace_id) DO UPDATE SET
             role_ids = EXCLUDED.role_ids, status = EXCLUDED.status,
             revoked_at = EXCLUDED.revoked_at`,
          [
            membership.userId, membership.tenantId, membership.workspaceId,
            JSON.stringify(membership.roleIds), membership.status,
            membership.createdAt, membership.revokedAt,
          ],
        );
      },

      async listActiveForUser(userId: string, tenantId: string): Promise<WorkspaceMembership[]> {
        const res = await pool.query(
          `SELECT * FROM workspace_memberships
           WHERE user_id = $1 AND tenant_id = $2 AND status = 'active'
           ORDER BY workspace_id`,
          [userId, tenantId],
        );
        return res.rows.map(membershipFromRow);
      },

      async setStatus(
        userId: string,
        tenantId: string,
        workspaceId: string,
        status: WorkspaceMembership["status"],
        now: () => string = () => new Date().toISOString(),
      ): Promise<void> {
        await pool.query(
          `UPDATE workspace_memberships
           SET status = $4, revoked_at = CASE WHEN $4 = 'revoked' THEN $5::timestamptz ELSE revoked_at END
           WHERE user_id = $1 AND tenant_id = $2 AND workspace_id = $3`,
          [userId, tenantId, workspaceId, status, now()],
        );
      },
    },

    sessions: {
      async insert(session: AuthSession): Promise<void> {
        await pool.query(
          `INSERT INTO auth_sessions
           (id, user_id, tenant_id, session_token_hash, auth_strength,
            created_at, expires_at, last_seen_at, revoked_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
          [
            session.id, session.userId, session.tenantId, session.sessionTokenHash,
            session.authStrength, session.createdAt, session.expiresAt,
            session.lastSeenAt, session.revokedAt,
          ],
        );
      },

      async getByTokenHash(tokenHash: string): Promise<AuthSession | null> {
        const res = await pool.query(
          "SELECT * FROM auth_sessions WHERE session_token_hash = $1",
          [tokenHash],
        );
        return res.rows[0] ? sessionFromRow(res.rows[0]) : null;
      },

      async touch(sessionId: string, lastSeenAt: string): Promise<void> {
        await pool.query("UPDATE auth_sessions SET last_seen_at = $2 WHERE id = $1", [
          sessionId, lastSeenAt,
        ]);
      },

      async revoke(sessionId: string, revokedAt: string): Promise<void> {
        await pool.query(
          "UPDATE auth_sessions SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL",
          [sessionId, revokedAt],
        );
      },

      async revokeAllForUser(userId: string, revokedAt: string): Promise<void> {
        await pool.query(
          "UPDATE auth_sessions SET revoked_at = $2 WHERE user_id = $1 AND revoked_at IS NULL",
          [userId, revokedAt],
        );
      },
    },

    serviceIdentities: {
      async register(identity: ServiceIdentity): Promise<void> {
        await pool.query(
          `INSERT INTO service_identities
           (id, tenant_id, name, permission_ids, credential_hash, status, created_at, rotated_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
          [
            identity.id, identity.tenantId, identity.name,
            JSON.stringify(identity.permissionIds), identity.credentialHash,
            identity.status, identity.createdAt, identity.rotatedAt,
          ],
        );
      },

      async findActiveByCredentialHash(credentialHash: string): Promise<ServiceIdentity | null> {
        const res = await pool.query(
          "SELECT * FROM service_identities WHERE credential_hash = $1 AND status = 'active'",
          [credentialHash],
        );
        return res.rows[0] ? serviceFromRow(res.rows[0]) : null;
      },

      async rotate(id: string, newCredentialHash: string, rotatedAt: string): Promise<void> {
        await pool.query(
          "UPDATE service_identities SET credential_hash = $2, rotated_at = $3 WHERE id = $1",
          [id, newCredentialHash, rotatedAt],
        );
      },

      async setStatus(id: string, status: ServiceIdentity["status"]): Promise<void> {
        await pool.query("UPDATE service_identities SET status = $2 WHERE id = $1", [id, status]);
      },
    },
  };
}
