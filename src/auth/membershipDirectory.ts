import crypto from "node:crypto";

import {
  AuthenticatedPrincipalSchema,
  ServicePrincipalSchema,
  type AuthenticatedPrincipal,
  type AuthStrength,
  type MailPermission,
  type MailRole,
  type ServicePrincipal,
} from "@aaliyah/contracts/v1";

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

type UserMembership = {
  tenantId: string;
  workspaceIds: string[];
  roles: MailRole[];
};

function hashToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function b64url(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export type MembershipDirectory = {
  registerUserMembership(input: {
    userId: string;
    tenantId: string;
    workspaceIds: string[];
    roles: MailRole[];
  }): void;
  /**
   * Build the server-verified principal for an authenticated session. Tenant,
   * workspaces, and roles come exclusively from this directory — the caller
   * contributes only the proven session identity. null when the user has no
   * registered membership.
   */
  principalForSession(session: {
    userId: string;
    sessionId: string;
    authStrength: AuthStrength;
  }): AuthenticatedPrincipal | null;
  /**
   * Register a narrow workload identity. Connection administration and send
   * execution are refused at registration time — fail closed, not at use time.
   */
  registerServiceIdentity(input: {
    serviceId: string;
    workloadIdentity: string;
    tenantId: string;
    workspaceIds: string[];
    grants: MailPermission[];
  }): { serviceToken: string };
  servicePrincipalForToken(token: string): ServicePrincipal | null;
};

/** In-memory membership directory. Production replaces this with the tenant DB. */
export function createMembershipDirectory(): MembershipDirectory {
  const memberships = new Map<string, UserMembership>();
  const servicesByTokenHash = new Map<string, ServicePrincipal>();

  return {
    registerUserMembership(input) {
      memberships.set(input.userId, {
        tenantId: input.tenantId,
        workspaceIds: [...input.workspaceIds],
        roles: [...input.roles],
      });
    },

    principalForSession(session) {
      const membership = memberships.get(session.userId);
      if (!membership) return null;
      return AuthenticatedPrincipalSchema.parse({
        actorType: "user",
        userId: session.userId,
        tenantId: membership.tenantId,
        workspaceIds: [...membership.workspaceIds],
        roles: [...membership.roles],
        sessionId: session.sessionId,
        authStrength: session.authStrength,
      });
    },

    registerServiceIdentity(input) {
      for (const grant of input.grants) {
        if (REFUSED_SERVICE_GRANTS.includes(grant)) {
          throw new ServiceGrantRefusedError(grant);
        }
      }
      const principal = ServicePrincipalSchema.parse({
        actorType: "service",
        serviceId: input.serviceId,
        workloadIdentity: input.workloadIdentity,
        tenantId: input.tenantId,
        workspaceIds: [...input.workspaceIds],
        grants: [...input.grants],
      });
      const serviceToken = b64url(crypto.randomBytes(32));
      servicesByTokenHash.set(hashToken(serviceToken), principal);
      return { serviceToken };
    },

    servicePrincipalForToken(token) {
      return servicesByTokenHash.get(hashToken(token)) ?? null;
    },
  };
}
