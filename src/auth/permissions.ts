import type { MailPermission, MailRole, Principal } from "@aaliyah/contracts/v1";

export type AuthorizationDenialCode =
  | "cross_tenant"
  | "workspace_forbidden"
  | "permission_denied";

export class AuthorizationError extends Error {
  readonly code: AuthorizationDenialCode;
  constructor(code: AuthorizationDenialCode, detail: string) {
    super(`authorization denied (${code}): ${detail}`);
    this.name = "AuthorizationError";
    this.code = code;
  }
}

/**
 * Role → permission policy for Phase B3. Deliberately, NO role maps to
 * mail.send.execute: sending is reserved for the internal execution service
 * presenting a valid cryptographic send approval, and that path is not
 * exposed through role policy this phase.
 */
export const ROLE_PERMISSIONS: Record<MailRole, readonly MailPermission[]> = {
  workspace_member: ["mail.connection.read"],
  mail_operator: ["mail.connection.read", "mail.connection.test"],
  workspace_admin: [
    "mail.connection.read",
    "mail.connection.test",
    "mail.connection.create",
    "mail.connection.disconnect",
  ],
  draft_approver: ["mail.connection.read", "mail.draft.approve"],
};

function permissionsOf(principal: Principal): readonly MailPermission[] {
  if (principal.actorType === "service") return principal.grants;
  return principal.roles.flatMap((role) => ROLE_PERMISSIONS[role]);
}

/**
 * The single mail-plane authorization decision: tenant match, workspace
 * membership, then permission — in that order, all server-resolved. Throws
 * AuthorizationError so callers cannot forget to handle a denial.
 */
export function authorizeMail(
  principal: Principal,
  permission: MailPermission,
  target: { tenantId: string; workspaceId: string },
): void {
  if (principal.tenantId !== target.tenantId) {
    throw new AuthorizationError("cross_tenant", "principal tenant does not match target tenant");
  }
  if (!principal.workspaceIds.includes(target.workspaceId)) {
    throw new AuthorizationError("workspace_forbidden", "principal is not a member of the target workspace");
  }
  if (!permissionsOf(principal).includes(permission)) {
    throw new AuthorizationError("permission_denied", `missing ${permission}`);
  }
}
