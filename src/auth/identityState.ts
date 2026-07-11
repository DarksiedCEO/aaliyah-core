import type {
  AuthSession,
  ServiceIdentity,
  UserIdentity,
  WorkspaceMembership,
} from "@aaliyah/contracts/v1";

import { createPostgresIdentityState } from "../persistence/postgres/identityStateStore";

/**
 * The identity backend contract. Postgres (createPostgresIdentityState) is
 * the authoritative production implementation; this in-memory twin exists for
 * dev/tests with the SAME semantics, conformance-tested side by side in
 * tests/identityState.test.ts. Production cannot boot on the twin.
 */
export type IdentityBackend = ReturnType<typeof createPostgresIdentityState>;

export function createInMemoryIdentityState(): IdentityBackend & {
  /** Test-only: raw stored records for at-rest assertions. */
  dump(): Record<string, unknown[]>;
} {
  const users = new Map<string, UserIdentity>();
  const memberships = new Map<string, WorkspaceMembership>();
  const sessions = new Map<string, AuthSession>();
  const services = new Map<string, ServiceIdentity>();

  const membershipKey = (userId: string, tenantId: string, workspaceId: string): string =>
    `${userId}|${tenantId}|${workspaceId}`;

  return {
    users: {
      async create(user) {
        users.set(user.id, user);
      },
      async get(id) {
        return users.get(id) ?? null;
      },
      async findByExternalSubject(provider, subject) {
        return (
          [...users.values()].find(
            (u) => u.externalProvider === provider && u.externalSubject === subject,
          ) ?? null
        );
      },
      async setStatus(id, status, now = () => new Date().toISOString()) {
        const user = users.get(id);
        if (user) users.set(id, { ...user, status, updatedAt: now() });
      },
    },

    memberships: {
      async grant(membership) {
        memberships.set(
          membershipKey(membership.userId, membership.tenantId, membership.workspaceId),
          membership,
        );
      },
      async listActiveForUser(userId, tenantId) {
        return [...memberships.values()]
          .filter((m) => m.userId === userId && m.tenantId === tenantId && m.status === "active")
          .sort((a, b) => a.workspaceId.localeCompare(b.workspaceId));
      },
      async setStatus(userId, tenantId, workspaceId, status, now = () => new Date().toISOString()) {
        const key = membershipKey(userId, tenantId, workspaceId);
        const membership = memberships.get(key);
        if (!membership) return;
        memberships.set(key, {
          ...membership,
          status,
          revokedAt: status === "revoked" ? now() : membership.revokedAt,
        });
      },
    },

    sessions: {
      async insert(session) {
        sessions.set(session.id, session);
      },
      async getByTokenHash(tokenHash) {
        return [...sessions.values()].find((s) => s.sessionTokenHash === tokenHash) ?? null;
      },
      async touch(sessionId, lastSeenAt) {
        const session = sessions.get(sessionId);
        if (session) sessions.set(sessionId, { ...session, lastSeenAt });
      },
      async revoke(sessionId, revokedAt) {
        const session = sessions.get(sessionId);
        if (session && !session.revokedAt) sessions.set(sessionId, { ...session, revokedAt });
      },
      async revokeAllForUser(userId, revokedAt) {
        for (const [id, session] of sessions) {
          if (session.userId === userId && !session.revokedAt) {
            sessions.set(id, { ...session, revokedAt });
          }
        }
      },
    },

    serviceIdentities: {
      async register(identity) {
        services.set(identity.id, identity);
      },
      async findActiveByCredentialHash(credentialHash) {
        return (
          [...services.values()].find(
            (s) => s.credentialHash === credentialHash && s.status === "active",
          ) ?? null
        );
      },
      async rotate(id, newCredentialHash, rotatedAt) {
        const identity = services.get(id);
        if (identity) services.set(id, { ...identity, credentialHash: newCredentialHash, rotatedAt });
      },
      async setStatus(id, status) {
        const identity = services.get(id);
        if (identity) services.set(id, { ...identity, status });
      },
    },

    dump() {
      return {
        users: [...users.values()],
        memberships: [...memberships.values()],
        sessions: [...sessions.values()],
        services: [...services.values()],
      };
    },
  };
}
