import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test, { after, before, beforeEach } from "node:test";
import type { AddressInfo } from "node:net";

import express from "express";

import { localMasterKms } from "../src/crypto/envelopeEncryption";
import { createMailRouter, type MailRoutesDeps } from "../src/http/mailRoutes";
import { createAuthService, type AuthService } from "../src/auth/authService";
import { createInMemoryIdentityState } from "../src/auth/identityState";
import type { MailRole } from "@aaliyah/contracts/v1";
import type { GoogleConnectDeps, GoogleOAuthHttp } from "../src/mail/google/googleConnect";
import { createInMemoryMailState } from "../src/mail/mailState";
import { readMailAudit } from "../src/mail/security/mailAudit";
import { connectionIdFor } from "../src/mail/adapters/helpers";

const KMS = localMasterKms({ keyId: "v1", masterKey: Buffer.alloc(32, 5) });
const EMAIL = "sales@pussycatalley.com";
const REDIRECT = "https://app.example/oauth/google/callback";
const TENANT_A = "tenant_a";
const WS_A = "tenant_a:default";
const TENANT_B = "tenant_b";
const WS_B = "tenant_b:default";

let identity: ReturnType<typeof createInMemoryIdentityState>;
let auth: AuthService;
let mailState: ReturnType<typeof createInMemoryMailState>;
let server: ReturnType<express.Express["listen"]>;
let baseUrl: string;
let revokedTokens: string[];

function fakeHttp(): GoogleOAuthHttp {
  return {
    exchangeAuthorizationCode: async () => ({
      accessToken: "at",
      refreshToken: "rt-SECRET",
      expiresIn: 3600,
      scope: "email",
    }),
    fetchMailboxProfile: async () => ({ email: EMAIL }),
    refreshAccessToken: async () => ({ accessToken: "at2", expiresIn: 3600, scope: "" }),
    revokeToken: async (t) => {
      revokedTokens.push(t);
    },
  };
}

function connectDeps(): GoogleConnectDeps {
  return { http: fakeHttp(), kms: KMS, state: mailState, clientId: "client-1" };
}

function routesDeps(): MailRoutesDeps {
  return {
    capability: { provider: "google", available: true },
    redirectUri: REDIRECT,
    frontendInboxesUrl: "https://app.example/settings/inboxes",
    connectDeps: connectDeps(),
    auth: { principalForToken: auth.principalForToken },
    state: mailState,
  };
}

type Actor = { token: string; sessionId: string; userId: string };

/** Provision a durable user + memberships, then issue a durable session. */
async function loginUser(
  name: string,
  tenantId: string,
  workspaceIds: string[],
  roles: string[],
): Promise<Actor> {
  const user = await auth.provisionUser({
    tenantId,
    externalProvider: "google",
    externalSubject: `sub-${name}`,
    email: `${name}@pussycatalley.com`,
    emailVerified: true,
  });
  for (const workspaceId of workspaceIds) {
    await identity.memberships.grant({
      userId: user.id, tenantId, workspaceId,
      roleIds: roles as MailRole[], status: "active",
      createdAt: new Date().toISOString(), revokedAt: null,
    });
  }
  const { token, sessionId } = await auth.issueSession({
    userId: user.id, tenantId, authStrength: "password",
  });
  return { token, sessionId, userId: user.id };
}

async function api(
  method: string,
  urlPath: string,
  opts: { token?: string; body?: unknown; headers?: Record<string, string>; redirect?: "manual" | "follow" } = {},
): Promise<Response> {
  return fetch(`${baseUrl}${urlPath}`, {
    method,
    redirect: opts.redirect ?? "manual",
    headers: {
      "content-type": "application/json",
      ...(opts.token ? { authorization: `Bearer ${opts.token}` } : {}),
      ...(opts.headers ?? {}),
    },
    ...(opts.body ? { body: JSON.stringify(opts.body) } : {}),
  });
}

/** Full happy-path connect as the given actor; returns the connectionId. */
async function connectAs(actor: Actor, workspaceId: string): Promise<string> {
  const start = await api("POST", "/api/mail/connections/google/start", {
    token: actor.token,
    body: { workspaceId },
  });
  assert.equal(start.status, 200);
  const { authorizationUrl } = (await start.json()) as { authorizationUrl: string };
  const state = new URL(authorizationUrl).searchParams.get("state")!;
  const cb = await api(
    "GET",
    `/api/mail/connections/google/callback?code=auth-code&state=${encodeURIComponent(state)}`,
    { token: actor.token },
  );
  assert.equal(cb.status, 302);
  assert.ok(cb.headers.get("location")!.includes("connection=success"));
  return connectionIdFor({
    tenantId: TENANT_A,
    workspaceId,
    userId: actor.userId,
    provider: "google",
    emailAddress: EMAIL,
  });
}

before(() => {
  process.env.AALIYAH_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "aaliyah-authroutes-"));
});

beforeEach(async () => {
  revokedTokens = [];
  identity = createInMemoryIdentityState();
  auth = createAuthService(identity, {
    google: { clientId: "unused", jwks: async () => ({ keys: [] }) },
  });
  mailState = createInMemoryMailState();
  if (server) server.close();
  const app = express();
  app.use(express.json());
  app.use(createMailRouter(routesDeps()));
  await new Promise<void>((resolve) => {
    server = app.listen(0, () => resolve());
  });
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(() => {
  if (server) server.close();
});

// ---- Gate: missing auth → 401; spoofed identity headers are ignored/rejected ----

test("requests without a bearer token are 401 even with x-aaliyah identity headers", async () => {
  const res = await api("POST", "/api/mail/connections/google/start", {
    body: { workspaceId: WS_A },
    headers: {
      "x-aaliyah-tenant": TENANT_A,
      "x-aaliyah-workspace": WS_A,
      "x-aaliyah-user": "u_admin",
    },
  });
  assert.equal(res.status, 401);

  const res2 = await api("GET", "/api/mail/connections/whatever", {
    headers: { "x-aaliyah-tenant": TENANT_A, "x-aaliyah-workspace": WS_A, "x-aaliyah-user": "u" },
  });
  assert.equal(res2.status, 401);
});

test("spoofed identity headers cannot redirect an authenticated operation to another tenant", async () => {
  const admin = await loginUser("u_admin", TENANT_A, [WS_A], ["workspace_admin"]);
  const connectionId = await connectAs(admin, WS_A);

  // Claim tenant_b via headers — the connection must still be found via the
  // principal's real tenant, proving headers carry zero identity weight.
  const res = await api("GET", `/api/mail/connections/${connectionId}?workspaceId=${WS_A}`, {
    token: admin.token,
    headers: { "x-aaliyah-tenant": TENANT_B, "x-aaliyah-workspace": WS_B, "x-aaliyah-user": "evil" },
  });
  assert.equal(res.status, 200);
  const body = (await res.json()) as { connectionId: string };
  assert.equal(body.connectionId, connectionId);
  // And the connection genuinely lives in tenant_a, not tenant_b.
  assert.ok(await mailState.connections.get(connectionId, { tenantId: TENANT_A, workspaceId: WS_A }));
  assert.equal(await mailState.connections.get(connectionId, { tenantId: TENANT_B, workspaceId: WS_B }), null);
});

// ---- Gate: authorized-but-unpermissioned → 403; role policy on routes ----

test("workspace member can view health but cannot test, connect, or disconnect", async () => {
  const admin = await loginUser("u_admin", TENANT_A, [WS_A], ["workspace_admin"]);
  const member = await loginUser("u_member", TENANT_A, [WS_A], ["workspace_member"]);
  const connectionId = await connectAs(admin, WS_A);

  const read = await api("GET", `/api/mail/connections/${connectionId}?workspaceId=${WS_A}`, {
    token: member.token,
  });
  assert.equal(read.status, 200);

  const startRes = await api("POST", "/api/mail/connections/google/start", {
    token: member.token,
    body: { workspaceId: WS_A },
  });
  assert.equal(startRes.status, 403);

  const testRes = await api("POST", `/api/mail/connections/${connectionId}/test`, {
    token: member.token,
    body: { workspaceId: WS_A },
  });
  assert.equal(testRes.status, 403);

  const delRes = await api("DELETE", `/api/mail/connections/${connectionId}?workspaceId=${WS_A}`, {
    token: member.token,
  });
  assert.equal(delRes.status, 403);
  // Still connected.
  assert.ok(await mailState.connections.get(connectionId, { tenantId: TENANT_A, workspaceId: WS_A }));
});

test("workspace admin can connect and disconnect a shared mailbox", async () => {
  const admin = await loginUser("u_admin", TENANT_A, [WS_A], ["workspace_admin"]);
  const connectionId = await connectAs(admin, WS_A);

  const delRes = await api("DELETE", `/api/mail/connections/${connectionId}?workspaceId=${WS_A}`, {
    token: admin.token,
  });
  assert.equal(delRes.status, 200);
  assert.equal(await mailState.connections.get(connectionId, { tenantId: TENANT_A, workspaceId: WS_A }), null);
  // Provider token revoked on disconnect.
  assert.ok(revokedTokens.length >= 1);
});

// ---- Gate: workspace membership resolved server-side ----

test("naming a workspace outside the principal's membership is 403", async () => {
  const admin = await loginUser("u_admin", TENANT_A, [WS_A], ["workspace_admin"]);
  const res = await api("POST", "/api/mail/connections/google/start", {
    token: admin.token,
    body: { workspaceId: "tenant_a:finance" },
  });
  assert.equal(res.status, 403);
});

// ---- Gate: cross-tenant lookup and disconnect fail ----

test("a tenant_b admin can neither read nor disconnect a tenant_a connection", async () => {
  const adminA = await loginUser("u_admin_a", TENANT_A, [WS_A], ["workspace_admin"]);
  const adminB = await loginUser("u_admin_b", TENANT_B, [WS_B], ["workspace_admin"]);
  const connectionId = await connectAs(adminA, WS_A);

  const read = await api("GET", `/api/mail/connections/${connectionId}?workspaceId=${WS_B}`, {
    token: adminB.token,
  });
  assert.equal(read.status, 404);

  const del = await api("DELETE", `/api/mail/connections/${connectionId}?workspaceId=${WS_B}`, {
    token: adminB.token,
  });
  assert.equal(del.status, 404);
  assert.ok(await mailState.connections.get(connectionId, { tenantId: TENANT_A, workspaceId: WS_A }));
});

// ---- Gate: OAuth state bound to user+session+tenant+workspace at the route level ----

test("a callback presented by a different user/session fails and connects nothing", async () => {
  const admin = await loginUser("u_admin", TENANT_A, [WS_A], ["workspace_admin"]);
  const otherAdmin = await loginUser("u_other", TENANT_A, [WS_A], ["workspace_admin"]);

  const start = await api("POST", "/api/mail/connections/google/start", {
    token: admin.token,
    body: { workspaceId: WS_A },
  });
  const { authorizationUrl } = (await start.json()) as { authorizationUrl: string };
  const state = new URL(authorizationUrl).searchParams.get("state")!;

  const cb = await api(
    "GET",
    `/api/mail/connections/google/callback?code=auth-code&state=${encodeURIComponent(state)}`,
    { token: otherAdmin.token },
  );
  assert.equal(cb.status, 302);
  assert.ok(cb.headers.get("location")!.includes("connection=failed"));

  const expectedId = connectionIdFor({
    tenantId: TENANT_A,
    workspaceId: WS_A,
    userId: admin.userId,
    provider: "google",
    emailAddress: EMAIL,
  });
  assert.equal(await mailState.connections.get(expectedId, { tenantId: TENANT_A, workspaceId: WS_A }), null);
});

test("callback query params cannot choose tenant or workspace", async () => {
  const admin = await loginUser("u_admin", TENANT_A, [WS_A], ["workspace_admin"]);
  const start = await api("POST", "/api/mail/connections/google/start", {
    token: admin.token,
    body: { workspaceId: WS_A },
  });
  const { authorizationUrl } = (await start.json()) as { authorizationUrl: string };
  const state = new URL(authorizationUrl).searchParams.get("state")!;

  // Malicious extra params claiming another tenant/workspace are inert.
  const cb = await api(
    "GET",
    `/api/mail/connections/google/callback?code=auth-code&state=${encodeURIComponent(state)}&tenantId=${TENANT_B}&workspaceId=${WS_B}`,
    { token: admin.token },
  );
  assert.equal(cb.status, 302);
  assert.ok(cb.headers.get("location")!.includes("connection=success"));

  const connectionId = connectionIdFor({
    tenantId: TENANT_A,
    workspaceId: WS_A,
    userId: admin.userId,
    provider: "google",
    emailAddress: EMAIL,
  });
  assert.ok(await mailState.connections.get(connectionId, { tenantId: TENANT_A, workspaceId: WS_A }));
  assert.equal(await mailState.connections.get(connectionId, { tenantId: TENANT_B, workspaceId: WS_B }), null);
});

// ---- Gate: revoked sessions cannot start OAuth ----

test("a revoked session cannot start OAuth or act at all", async () => {
  const admin = await loginUser("u_admin", TENANT_A, [WS_A], ["workspace_admin"]);
  await auth.logout(admin.token);
  const res = await api("POST", "/api/mail/connections/google/start", {
    token: admin.token,
    body: { workspaceId: WS_A },
  });
  assert.equal(res.status, 401);
});

// ---- Gate: worker identities cannot administer connections ----

test("service identity can read health but cannot start or disconnect", async () => {
  const admin = await loginUser("u_admin", TENANT_A, [WS_A], ["workspace_admin"]);
  const connectionId = await connectAs(admin, WS_A);

  const { serviceToken } = await auth.registerServiceIdentity({
    name: "mail.reader",
    tenantId: TENANT_A,
    workspaceIds: [WS_A],
    grants: ["mail.connection.read"],
  });

  const read = await api("GET", `/api/mail/connections/${connectionId}?workspaceId=${WS_A}`, {
    token: serviceToken,
  });
  assert.equal(read.status, 200);

  const start = await api("POST", "/api/mail/connections/google/start", {
    token: serviceToken,
    body: { workspaceId: WS_A },
  });
  assert.equal(start.status, 403);

  const del = await api("DELETE", `/api/mail/connections/${connectionId}?workspaceId=${WS_A}`, {
    token: serviceToken,
  });
  assert.equal(del.status, 403);
  assert.ok(await mailState.connections.get(connectionId, { tenantId: TENANT_A, workspaceId: WS_A }));
});

// ---- Gate: audit distinguishes users from services; no secrets in mail logs ----

test("audit trail distinguishes user and service actors and never contains tokens", async () => {
  const admin = await loginUser("u_admin", TENANT_A, [WS_A], ["workspace_admin"]);
  const connectionId = await connectAs(admin, WS_A);

  const { serviceToken } = await auth.registerServiceIdentity({
    name: "mail.reader",
    tenantId: TENANT_A,
    workspaceIds: [WS_A],
    grants: ["mail.connection.read"],
  });
  await api("GET", `/api/mail/connections/${connectionId}?workspaceId=${WS_A}`, {
    token: serviceToken,
  });
  await api("DELETE", `/api/mail/connections/${connectionId}?workspaceId=${WS_A}`, {
    token: admin.token,
  });

  const audit = await readMailAudit({ tenantId: TENANT_A, workspaceId: WS_A }, mailState.audit);
  const userEvents = audit.filter((e) => e.actorType === "user");
  const serviceEvents = audit.filter((e) => e.actorType === "service");
  assert.ok(userEvents.length >= 1, "expected user-actor audit events");
  assert.ok(serviceEvents.length >= 1, "expected service-actor audit events");
  assert.ok(serviceEvents.some((e) => e.actorServiceId === "mail.reader"));

  const auditText = JSON.stringify(audit);
  assert.ok(!auditText.includes(admin.token), "session token leaked into audit");
  assert.ok(!auditText.includes(serviceToken), "service token leaked into audit");
  assert.ok(!auditText.includes("rt-SECRET"), "refresh token leaked into audit");
});
