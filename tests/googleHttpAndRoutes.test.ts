import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test, { before, beforeEach } from "node:test";

import { localMasterKms } from "../src/crypto/envelopeEncryption";
import { createGoogleOAuthHttp } from "../src/mail/google/googleOAuthHttp";
import { googleCapability, loadGoogleConfig } from "../src/mail/google/googleConfig";
import {
  buildGoogleAuthorizationUrl,
  type GoogleConnectDeps,
  type GoogleOAuthHttp,
} from "../src/mail/google/googleConnect";
import {
  startGoogleConnect,
  handleGoogleCallbackRoute,
  getConnectionStatus,
  disconnectConnection,
  type MailRoutesDeps,
} from "../src/http/mailRoutes";
import { createInMemoryMailState } from "../src/mail/mailState";
import { connectionIdFor } from "../src/mail/adapters/helpers";
import { AuthorizationError } from "../src/auth/permissions";
import type { AuthenticatedPrincipal } from "@aaliyah/contracts/v1";

const KMS = localMasterKms({ keyId: "v1", masterKey: Buffer.alloc(32, 9) });
const EMAIL = "sales@pussycatalley.com";
const REDIRECT = "https://app.example/oauth/google/callback";
const ID = { tenantId: "tenant_a", workspaceId: "tenant_a:default", userId: "u1" };
const SCOPE = { tenantId: "tenant_a", workspaceId: "tenant_a:default" };
const WS = "tenant_a:default";
const CONN_ID = connectionIdFor({ ...ID, provider: "google", emailAddress: EMAIL });

function adminPrincipal(over: Partial<AuthenticatedPrincipal> = {}): AuthenticatedPrincipal {
  return {
    actorType: "user",
    userId: "u1",
    tenantId: "tenant_a",
    workspaceIds: [WS],
    roles: ["workspace_admin"],
    sessionId: "sess_u1",
    authStrength: "password",
    ...over,
  };
}

let state: ReturnType<typeof createInMemoryMailState>;

before(() => {
  process.env.AALIYAH_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "aaliyah-routes-"));
});
beforeEach(() => {
  state = createInMemoryMailState();
});

function jsonRes(status: number, body: unknown): Response {
  return { ok: status < 400, status, json: async () => body } as Response;
}

// ---- Google HTTP client ----

test("http client validates the token schema (never trusts a 200 blindly)", async () => {
  const http = createGoogleOAuthHttp({
    clientId: "c", clientSecret: "s",
    fetchImpl: (async () => jsonRes(200, { wrong: "shape" })) as unknown as typeof fetch,
  });
  await assert.rejects(() => http.exchangeAuthorizationCode({ code: "x", codeVerifier: "v", redirectUri: REDIRECT }));
});

test("code exchange is NOT retried; refresh IS retried on 5xx", async () => {
  let exchangeCalls = 0;
  const http1 = createGoogleOAuthHttp({
    clientId: "c", clientSecret: "s", maxRetries: 3,
    fetchImpl: (async () => { exchangeCalls += 1; return jsonRes(500, {}); }) as unknown as typeof fetch,
  });
  await assert.rejects(() => http1.exchangeAuthorizationCode({ code: "x", codeVerifier: "v", redirectUri: REDIRECT }));
  assert.equal(exchangeCalls, 1); // single-use — never retried

  let refreshCalls = 0;
  const http2 = createGoogleOAuthHttp({
    clientId: "c", clientSecret: "s", maxRetries: 2,
    fetchImpl: (async () => {
      refreshCalls += 1;
      return refreshCalls < 3 ? jsonRes(500, {}) : jsonRes(200, { access_token: "at", expires_in: 3600, scope: "" });
    }) as unknown as typeof fetch,
  });
  const r = await http2.refreshAccessToken("rt");
  assert.equal(r.accessToken, "at");
  assert.equal(refreshCalls, 3); // retried through the transient 5xx
});

test("errors carry no secret material", async () => {
  const http = createGoogleOAuthHttp({
    clientId: "c", clientSecret: "super-secret",
    fetchImpl: (async () => jsonRes(400, { error: "invalid_grant" })) as unknown as typeof fetch,
  });
  let err: Error | undefined;
  try {
    await http.exchangeAuthorizationCode({ code: "SENSITIVE_CODE", codeVerifier: "v", redirectUri: REDIRECT });
  } catch (e) {
    err = e as Error;
  }
  assert.ok(err);
  assert.ok(!err!.message.includes("super-secret"));
  assert.ok(!err!.message.includes("SENSITIVE_CODE"));
});

// ---- Config / capability ----

test("capability reflects configuration; loadGoogleConfig fails closed when unset", () => {
  const bad = googleCapability({} as NodeJS.ProcessEnv);
  assert.equal(bad.available, false);
  assert.equal((bad as { reasonCode: string }).reasonCode, "provider_not_configured");
  assert.throws(() => loadGoogleConfig({} as NodeJS.ProcessEnv), /not configured/);

  const good = googleCapability({
    GOOGLE_CLIENT_ID: "a", GOOGLE_CLIENT_SECRET: "b", GOOGLE_OAUTH_REDIRECT_URI: REDIRECT,
    MAIL_CREDENTIAL_ENCRYPTION_KEY: Buffer.alloc(32).toString("base64"), MAIL_CREDENTIAL_KEY_VERSION: "v1",
  } as unknown as NodeJS.ProcessEnv);
  assert.equal(good.available, true);
});

// ---- Route handlers ----

function fakeHttp(): GoogleOAuthHttp & { revoked: string[] } {
  const revoked: string[] = [];
  return {
    revoked,
    exchangeAuthorizationCode: async () => ({ accessToken: "at", refreshToken: "rt-SECRET", expiresIn: 3600, scope: "email" }),
    fetchMailboxProfile: async () => ({ email: EMAIL }),
    refreshAccessToken: async () => ({ accessToken: "at2", expiresIn: 3600, scope: "" }),
    revokeToken: async (t) => { revoked.push(t); },
  };
}

function routeDeps(configured = true): MailRoutesDeps & { http: ReturnType<typeof fakeHttp> } {
  const http = fakeHttp();
  const connectDeps: GoogleConnectDeps = { http, kms: KMS, state, clientId: "client-123" };
  return {
    http,
    capability: configured ? { provider: "google", available: true } : { provider: "google", available: false, reasonCode: "provider_not_configured" },
    redirectUri: REDIRECT,
    frontendInboxesUrl: "https://app.example/settings/inboxes",
    ...(configured ? { connectDeps } : {}),
    // Handler-level tests pass principals directly; the resolver is unused.
    auth: { principalForToken: async () => null },
    state,
  };
}

test("start is capability-gated and never fakes availability", async () => {
  assert.deepEqual(await startGoogleConnect(adminPrincipal(), WS, routeDeps(false)), {
    available: false, reasonCode: "provider_not_configured",
  });
  const ok = await startGoogleConnect(adminPrincipal(), WS, routeDeps(true));
  assert.equal(ok.available, true);
  assert.match((ok as { authorizationUrl: string }).authorizationUrl, /accounts\.google\.com/);
});

test("callback returns only a sanitized redirect and never leaks", async () => {
  const deps = routeDeps(true);
  const principal = adminPrincipal();
  const { state: oauthState } = await buildGoogleAuthorizationUrl(
    { ...ID, sessionId: principal.sessionId, redirectUri: REDIRECT },
    deps.connectDeps!,
  );

  const ok = await handleGoogleCallbackRoute({ code: "auth-code", state: oauthState }, principal, deps);
  assert.equal(ok.redirectTo, "https://app.example/settings/inboxes?connection=success");
  assert.ok(!ok.redirectTo.includes("token") && !ok.redirectTo.includes("auth-code") && !ok.redirectTo.includes(EMAIL));

  // A bad/replayed state fails to a generic page (never encourages replay).
  const bad = await handleGoogleCallbackRoute({ code: "auth-code", state: oauthState }, principal, deps);
  assert.equal(bad.redirectTo, "https://app.example/settings/inboxes?connection=failed");

  // Missing params → failed, no crash.
  assert.equal(
    (await handleGoogleCallbackRoute({}, principal, deps)).redirectTo,
    "https://app.example/settings/inboxes?connection=failed",
  );

  // No principal at all → failed, nothing consumed.
  assert.equal(
    (await handleGoogleCallbackRoute({ code: "c", state: "s" }, null, deps)).redirectTo,
    "https://app.example/settings/inboxes?connection=failed",
  );
});

test("status is workspace-scoped and disconnect requires admin within the workspace", async () => {
  const deps = routeDeps(true);
  const principal = adminPrincipal();
  const { state: oauthState } = await buildGoogleAuthorizationUrl(
    { ...ID, sessionId: principal.sessionId, redirectUri: REDIRECT },
    deps.connectDeps!,
  );
  await handleGoogleCallbackRoute({ code: "c", state: oauthState }, principal, deps);

  assert.equal((await getConnectionStatus(CONN_ID, WS, principal, deps))!.status, "connected");
  // Another workspace member CAN see shared health (role policy)…
  const member = adminPrincipal({ userId: "other", roles: ["workspace_member"], sessionId: "sess_o" });
  assert.equal((await getConnectionStatus(CONN_ID, WS, member, deps))!.status, "connected");
  // …but a user outside the workspace cannot.
  const outsider = adminPrincipal({ userId: "out", workspaceIds: ["tenant_a:other"], sessionId: "sess_x" });
  await assert.rejects(() => getConnectionStatus(CONN_ID, WS, outsider, deps), AuthorizationError);
  // And a member cannot disconnect.
  await assert.rejects(() => disconnectConnection(CONN_ID, WS, member, deps), AuthorizationError);

  const dis = await disconnectConnection(CONN_ID, WS, principal, deps);
  assert.equal(dis.ok, true);
  assert.deepEqual(deps.http.revoked, ["rt-SECRET"]);
  assert.equal(await getConnectionStatus(CONN_ID, WS, principal, deps), null); // gone
});
