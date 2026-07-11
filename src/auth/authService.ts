import crypto from "node:crypto";

import {
  AuthenticatedPrincipalSchema,
  MailPermissionSchema,
  MailRoleSchema,
  ServicePrincipalSchema,
  type AuthSession,
  type ExternalProvider,
  type MailPermission,
  type MailRole,
  type Principal,
  type UserIdentity,
} from "@aaliyah/contracts/v1";

import type { IdentityBackend } from "./identityState";
import { verifyGoogleIdToken, type JwksProvider } from "./googleIdentity";

/** Grants a background service may never hold, regardless of who registers it. */
const REFUSED_SERVICE_GRANTS: readonly MailPermission[] = [
  "mail.connection.create",
  "mail.connection.disconnect",
  "mail.send.execute",
];

export class ServiceGrantRefusedError extends Error {
  constructor(grant: MailPermission) {
    super(`service identities may not hold ${grant}`);
    this.name = "ServiceGrantRefusedError";
  }
}

const DEFAULT_SESSION_TTL_MS = 12 * 60 * 60 * 1000; // absolute
const DEFAULT_IDLE_TTL_MS = 60 * 60 * 1000;

function hashToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function b64url(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export type AuthServiceOpts = {
  google: { clientId: string; jwks: JwksProvider };
  sessionTtlMs?: number;
  idleTtlMs?: number;
  now?: () => number;
};

export type AuthService = ReturnType<typeof createAuthService>;

/**
 * The durable authentication and authorization authority (Phase B5). Every
 * fact — user, membership, roles, session, workload identity — is resolved
 * from the identity backend per request: revocations, suspensions, and role
 * changes apply on the very next call, across every instance, with no
 * restart. Raw tokens are returned exactly once and exist at rest only as
 * SHA-256 digests. A backend outage propagates loudly — authentication never
 * fails open.
 */
export function createAuthService(identity: IdentityBackend, opts: AuthServiceOpts) {
  const now = opts.now ?? (() => Date.now());
  const sessionTtlMs = opts.sessionTtlMs ?? DEFAULT_SESSION_TTL_MS;
  const idleTtlMs = opts.idleTtlMs ?? DEFAULT_IDLE_TTL_MS;
  const iso = (ms: number): string => new Date(ms).toISOString();

  async function issueSession(input: {
    userId: string;
    tenantId: string;
    authStrength: AuthSession["authStrength"];
  }): Promise<{ token: string; sessionId: string }> {
    const token = b64url(crypto.randomBytes(32));
    const sessionId = `sess_${b64url(crypto.randomBytes(16))}`;
    const at = now();
    await identity.sessions.insert({
      id: sessionId,
      userId: input.userId,
      tenantId: input.tenantId,
      sessionTokenHash: hashToken(token),
      authStrength: input.authStrength,
      createdAt: iso(at),
      expiresAt: iso(at + sessionTtlMs),
      lastSeenAt: iso(at),
      revokedAt: null,
    });
    return { token, sessionId };
  }

  /** Validate a session token: revocation, absolute expiry, idle expiry, and
   * the user's live status — then touch lastSeenAt. */
  async function resolveSession(
    token: string,
  ): Promise<{ session: AuthSession; user: UserIdentity } | null> {
    const session = await identity.sessions.getByTokenHash(hashToken(token));
    if (!session || session.revokedAt) return null;
    const at = now();
    if (at >= new Date(session.expiresAt).getTime()) return null;
    if (at - new Date(session.lastSeenAt).getTime() > idleTtlMs) return null;
    const user = await identity.users.get(session.userId);
    if (!user || user.status !== "active") return null;
    await identity.sessions.touch(session.id, iso(at));
    return { session, user };
  }

  return {
    /** Operator provisioning: create the durable user record. Membership is
     * granted separately — a provisioned user with no membership has no access. */
    async provisionUser(input: {
      tenantId: string;
      externalProvider: ExternalProvider;
      externalSubject: string;
      email: string;
      emailVerified: boolean;
    }): Promise<UserIdentity> {
      const at = iso(now());
      const user: UserIdentity = {
        id: `user_${b64url(crypto.randomBytes(12))}`,
        tenantId: input.tenantId,
        externalProvider: input.externalProvider,
        externalSubject: input.externalSubject,
        email: input.email,
        emailVerified: input.emailVerified,
        status: "active",
        createdAt: at,
        updatedAt: at,
      };
      await identity.users.create(user);
      return user;
    },

    /**
     * Google sign-in: verify the real IdP assertion (issuer, audience,
     * signature, expiry, nonce, verified email), anchor on the external
     * subject, resolve membership server-side, issue an Aaliyah session.
     * This authenticates the HUMAN only — it grants nothing over any mailbox.
     */
    async loginWithGoogle(input: {
      idToken: string;
      tenantId: string;
      expectedNonce?: string;
    }): Promise<{ token: string; sessionId: string; userId: string; tenantId: string }> {
      const verified = await verifyGoogleIdToken(input.idToken, {
        clientId: opts.google.clientId,
        jwks: opts.google.jwks,
        ...(input.expectedNonce !== undefined ? { expectedNonce: input.expectedNonce } : {}),
        now,
      });
      const user = await identity.users.findByExternalSubject("google", verified.subject);
      if (!user || user.status !== "active") {
        throw new Error("login refused: identity not provisioned");
      }
      const memberships = await identity.memberships.listActiveForUser(user.id, input.tenantId);
      if (memberships.length === 0) {
        throw new Error("login refused: no active workspace membership in tenant");
      }
      const { token, sessionId } = await issueSession({
        userId: user.id,
        tenantId: input.tenantId,
        authStrength: "sso",
      });
      return { token, sessionId, userId: user.id, tenantId: input.tenantId };
    },

    resolveSession,

    /** Issue a session directly — the seam for non-Google auth flows
     * (password/mfa) and for tests. Callers must have authenticated the user
     * by other verified means first; this never runs from client input. */
    issueSession,

    /** Logout: durably revoke — a revoked record remains for audit. */
    async logout(token: string): Promise<void> {
      const session = await identity.sessions.getByTokenHash(hashToken(token));
      if (session && !session.revokedAt) {
        await identity.sessions.revoke(session.id, iso(now()));
      }
    },

    async revokeAllForUser(userId: string): Promise<void> {
      await identity.sessions.revokeAllForUser(userId, iso(now()));
    },

    /** Rotate: fresh token + record, old one revoked in the same call —
     * required after auth-strength changes; also kills fixation attempts. */
    async rotateSession(token: string): Promise<{ token: string; sessionId: string }> {
      const resolved = await resolveSession(token);
      if (!resolved) throw new Error("rotate refused: no valid session");
      const fresh = await issueSession({
        userId: resolved.session.userId,
        tenantId: resolved.session.tenantId,
        authStrength: resolved.session.authStrength,
      });
      await identity.sessions.revoke(resolved.session.id, iso(now()));
      return fresh;
    },

    /**
     * The single production principal resolver: user sessions and service
     * credentials, both durable. Tenant, workspaces, and PER-WORKSPACE roles
     * come exclusively from the membership tables, read at call time.
     */
    async principalForToken(token: string): Promise<Principal | null> {
      const resolved = await resolveSession(token);
      if (resolved) {
        const memberships = await identity.memberships.listActiveForUser(
          resolved.user.id,
          resolved.session.tenantId,
        );
        const workspaceRoles: Record<string, MailRole[]> = {};
        for (const membership of memberships) {
          workspaceRoles[membership.workspaceId] = membership.roleIds
            .map((roleId) => MailRoleSchema.safeParse(roleId))
            .filter((r) => r.success)
            .map((r) => r.data);
        }
        return AuthenticatedPrincipalSchema.parse({
          actorType: "user",
          userId: resolved.user.id,
          tenantId: resolved.session.tenantId,
          workspaceIds: memberships.map((m) => m.workspaceId),
          roles: [...new Set(Object.values(workspaceRoles).flat())],
          workspaceRoles,
          sessionId: resolved.session.id,
          authStrength: resolved.session.authStrength,
        });
      }

      const service = await identity.serviceIdentities.findActiveByCredentialHash(
        hashToken(token),
      );
      if (service && service.tenantId) {
        return ServicePrincipalSchema.parse({
          actorType: "service",
          serviceId: service.name,
          workloadIdentity: `workload://aaliyah/${service.id}`,
          tenantId: service.tenantId,
          workspaceIds: service.workspaceIds,
          // Belt and braces: even a hand-edited row cannot smuggle refused
          // or unknown grants into a live principal.
          grants: service.permissionIds.filter(
            (p): p is MailPermission =>
              MailPermissionSchema.safeParse(p).success &&
              !REFUSED_SERVICE_GRANTS.includes(p as MailPermission),
          ),
        });
      }
      return null;
    },

    /** Register a narrow workload identity. Connection administration and
     * send execution are refused at registration — fail closed, not at use. */
    async registerServiceIdentity(input: {
      name: string;
      tenantId: string;
      workspaceIds: string[];
      grants: MailPermission[];
    }): Promise<{ serviceId: string; serviceToken: string }> {
      for (const grant of input.grants) {
        if (REFUSED_SERVICE_GRANTS.includes(grant)) {
          throw new ServiceGrantRefusedError(grant);
        }
      }
      const serviceToken = b64url(crypto.randomBytes(32));
      const serviceId = `svc_${b64url(crypto.randomBytes(12))}`;
      const at = iso(now());
      await identity.serviceIdentities.register({
        id: serviceId,
        tenantId: input.tenantId,
        name: input.name,
        workspaceIds: [...input.workspaceIds],
        permissionIds: [...input.grants],
        credentialHash: hashToken(serviceToken),
        status: "active",
        createdAt: at,
        rotatedAt: at,
      });
      return { serviceId, serviceToken };
    },

    /** Rotate a workload credential: the previous token dies immediately. */
    async rotateServiceCredential(serviceId: string): Promise<{ serviceToken: string }> {
      const serviceToken = b64url(crypto.randomBytes(32));
      await identity.serviceIdentities.rotate(serviceId, hashToken(serviceToken), iso(now()));
      return { serviceToken };
    },
  };
}
