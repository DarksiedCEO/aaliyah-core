import assert from "node:assert/strict";
import test, { beforeEach } from "node:test";

import { createSessionStore } from "../src/auth/sessionStore";
import {
  createMembershipDirectory,
  ServiceGrantRefusedError,
} from "../src/auth/membershipDirectory";
import { authorizeMail, AuthorizationError } from "../src/auth/permissions";

import type { AuthenticatedPrincipal, ServicePrincipal } from "@aaliyah/contracts/v1";

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

// ---- Session store ----

test("issued session resolves; unknown and revoked tokens do not", () => {
  const sessions = createSessionStore();
  const { token, sessionId } = sessions.issueSession({ userId: "u1", authStrength: "mfa" });

  const resolved = sessions.resolveSession(token);
  assert.ok(resolved);
  assert.equal(resolved!.userId, "u1");
  assert.equal(resolved!.sessionId, sessionId);
  assert.equal(resolved!.authStrength, "mfa");

  assert.equal(sessions.resolveSession("forged-token"), null);

  sessions.revokeSession(sessionId);
  assert.equal(sessions.resolveSession(token), null);
});

test("session tokens are opaque and never stored in plaintext", () => {
  const sessions = createSessionStore();
  const { token } = sessions.issueSession({ userId: "u1", authStrength: "password" });
  // The store must not hold the raw token anywhere in its serializable state.
  assert.ok(!JSON.stringify(sessions.debugState()).includes(token));
});

// ---- Membership directory: server-side resolution ----

test("tenant and workspace membership are resolved server-side, not from claims", () => {
  const directory = createMembershipDirectory();
  directory.registerUserMembership({
    userId: "u1",
    tenantId: TENANT,
    workspaceIds: [WS],
    roles: ["workspace_admin"],
  });

  const p = directory.principalForSession({
    userId: "u1",
    sessionId: "sess_1",
    authStrength: "password",
  });
  assert.ok(p);
  assert.equal(p!.tenantId, TENANT);
  assert.deepEqual(p!.workspaceIds, [WS]);
  assert.deepEqual(p!.roles, ["workspace_admin"]);

  // A user with a valid session but no registered membership resolves to nothing.
  assert.equal(
    directory.principalForSession({ userId: "ghost", sessionId: "sess_2", authStrength: "sso" }),
    null,
  );
});

test("service identities get narrow grants; admin and send grants are refused", () => {
  const directory = createMembershipDirectory();

  const { serviceToken } = directory.registerServiceIdentity({
    serviceId: "mail.reader",
    workloadIdentity: "workload://aaliyah/mail-reader",
    tenantId: TENANT,
    workspaceIds: [WS],
    grants: ["mail.connection.read"],
  });
  const sp = directory.servicePrincipalForToken(serviceToken);
  assert.ok(sp);
  assert.equal(sp!.actorType, "service");
  assert.deepEqual(sp!.grants, ["mail.connection.read"]);

  for (const refused of [
    "mail.connection.create",
    "mail.connection.disconnect",
    "mail.send.execute",
  ] as const) {
    assert.throws(
      () =>
        directory.registerServiceIdentity({
          serviceId: "greedy.worker",
          workloadIdentity: "workload://aaliyah/greedy",
          tenantId: TENANT,
          workspaceIds: [WS],
          grants: [refused],
        }),
      ServiceGrantRefusedError,
      refused,
    );
  }

  assert.equal(directory.servicePrincipalForToken("forged"), null);
});

// ---- Permission engine ----

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

beforeEach(() => {
  // no shared state between tests: each test builds its own stores
});
