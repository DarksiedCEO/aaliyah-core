import assert from "node:assert/strict";
import test from "node:test";

import { authorizeMail, AuthorizationError } from "../src/auth/permissions";

import type { AuthenticatedPrincipal, ServicePrincipal } from "@aaliyah/contracts/v1";

// The permission engine's role policy. Session/membership/service identity
// behavior lives in authService.test.ts against the durable identity backend.

const TENANT = "tenant_a";
const WS = "tenant_a:default";

function principal(overrides: Partial<AuthenticatedPrincipal> = {}): AuthenticatedPrincipal {
  return {
    actorType: "user",
    userId: "u1",
    tenantId: TENANT,
    workspaceIds: [WS],
    roles: ["workspace_member"],
    sessionId: "sess_1",
    authStrength: "password",
    ...overrides,
  };
}

function denied(fn: () => void, code: string): void {
  try {
    fn();
    assert.fail("expected AuthorizationError");
  } catch (e) {
    assert.ok(e instanceof AuthorizationError, String(e));
    assert.equal((e as AuthorizationError).code, code);
  }
}

test("cross-tenant access is denied regardless of role", () => {
  const admin = principal({ roles: ["workspace_admin"] });
  denied(
    () => authorizeMail(admin, "mail.connection.read", { tenantId: "tenant_b", workspaceId: "tenant_b:default" }),
    "cross_tenant",
  );
});

test("workspace membership is enforced within the tenant", () => {
  const admin = principal({ roles: ["workspace_admin"] });
  denied(
    () => authorizeMail(admin, "mail.connection.read", { tenantId: TENANT, workspaceId: "tenant_a:other" }),
    "workspace_forbidden",
  );
});

test("role policy: member reads health only; operator tests; admin administers; approver approves", () => {
  const member = principal({ roles: ["workspace_member"] });
  const operator = principal({ roles: ["mail_operator"] });
  const admin = principal({ roles: ["workspace_admin"] });
  const approver = principal({ roles: ["draft_approver"] });
  const target = { tenantId: TENANT, workspaceId: WS };

  // Member: read yes, everything else no.
  authorizeMail(member, "mail.connection.read", target);
  denied(() => authorizeMail(member, "mail.connection.test", target), "permission_denied");
  denied(() => authorizeMail(member, "mail.connection.create", target), "permission_denied");
  denied(() => authorizeMail(member, "mail.connection.disconnect", target), "permission_denied");
  denied(() => authorizeMail(member, "mail.draft.approve", target), "permission_denied");

  // Operator: safe test yes, connection admin no.
  authorizeMail(operator, "mail.connection.test", target);
  denied(() => authorizeMail(operator, "mail.connection.create", target), "permission_denied");
  denied(() => authorizeMail(operator, "mail.connection.disconnect", target), "permission_denied");

  // Admin: connect/disconnect yes.
  authorizeMail(admin, "mail.connection.create", target);
  authorizeMail(admin, "mail.connection.disconnect", target);

  // Approver: draft approval yes, connection admin no.
  authorizeMail(approver, "mail.draft.approve", target);
  denied(() => authorizeMail(approver, "mail.connection.create", target), "permission_denied");
});

test("no role grants mail.send.execute this phase — not even workspace admin", () => {
  const target = { tenantId: TENANT, workspaceId: WS };
  for (const roles of [
    ["workspace_member"],
    ["mail_operator"],
    ["workspace_admin"],
    ["draft_approver"],
    ["workspace_admin", "draft_approver", "mail_operator", "workspace_member"],
  ] as const) {
    denied(
      () => authorizeMail(principal({ roles: [...roles] }), "mail.send.execute", target),
      "permission_denied",
    );
  }
});

test("per-workspace role map wins over flat roles when present", () => {
  const p = principal({
    workspaceIds: [WS, "tenant_a:ops"],
    roles: ["workspace_admin", "workspace_member"],
    workspaceRoles: { [WS]: ["workspace_admin"], "tenant_a:ops": ["workspace_member"] },
  });
  authorizeMail(p, "mail.connection.create", { tenantId: TENANT, workspaceId: WS });
  denied(
    () => authorizeMail(p, "mail.connection.create", { tenantId: TENANT, workspaceId: "tenant_a:ops" }),
    "permission_denied",
  );
});

test("service principals are authorized by explicit grants and stay tenant/workspace-scoped", () => {
  const reader: ServicePrincipal = {
    actorType: "service",
    serviceId: "mail.reader",
    workloadIdentity: "workload://aaliyah/mail-reader",
    tenantId: TENANT,
    workspaceIds: [WS],
    grants: ["mail.connection.read"],
  };
  const target = { tenantId: TENANT, workspaceId: WS };

  authorizeMail(reader, "mail.connection.read", target);
  denied(() => authorizeMail(reader, "mail.connection.test", target), "permission_denied");
  denied(() => authorizeMail(reader, "mail.connection.create", target), "permission_denied");
  denied(() => authorizeMail(reader, "mail.connection.disconnect", target), "permission_denied");
  denied(
    () => authorizeMail(reader, "mail.connection.read", { tenantId: "tenant_b", workspaceId: "tenant_b:x" }),
    "cross_tenant",
  );
});
