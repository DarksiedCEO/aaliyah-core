import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test, { after, before, beforeEach } from "node:test";
import type { AddressInfo } from "node:net";

import express from "express";

import { localMasterKms } from "../src/crypto/envelopeEncryption";
import { createAuthRouter } from "../src/http/authRoutes";
import { createMailRouter, type MailRoutesDeps } from "../src/http/mailRoutes";
import { identityStateFromEnv } from "../src/http/createCoreApp";
import { createAuthService, type AuthService } from "../src/auth/authService";
import { createInMemoryIdentityState } from "../src/auth/identityState";
import { createInMemoryMailState } from "../src/mail/mailState";
import type { GoogleConnectDeps, GoogleOAuthHttp } from "../src/mail/google/googleConnect";
import type { JwksProvider } from "../src/auth/googleIdentity";

const CLIENT_ID = "aaliyah-client-id.apps.googleusercontent.com";
const KMS = localMasterKms({ keyId: "v1", masterKey: Buffer.alloc(32, 5) });
const REDIRECT = "https://app.example/oauth/google/callback";
const EMAIL = "sales@pussycatalley.com";
const TENANT = "tenant_a";
const WS = "tenant_a:default";

const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = {
  ...(publicKey.export({ format: "jwk" }) as Record<string, unknown>),
  kid: "kid-1",
  alg: "RS256",
  use: "sig",
};
const jwks: JwksProvider = async () => ({ keys: [jwk] });

function idToken(): string {
  const b64u = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const nowSec = Math.floor(Date.now() / 1000);
  const input = `${b64u({ alg: "RS256", kid: "kid-1", typ: "JWT" })}.${b64u({
    iss: "https://accounts.google.com", aud: CLIENT_ID, sub: "goog-sub-andre",
    email: "andre@pussycatalley.com", email_verified: true, iat: nowSec, exp: nowSec + 3600,
  })}`;
  return `${input}.${crypto.sign("RSA-SHA256", Buffer.from(input), privateKey).toString("base64url")}`;
}

let identity: ReturnType<typeof createInMemoryIdentityState>;
let mailState: ReturnType<typeof createInMemoryMailState>;
let auth: AuthService;
let server: ReturnType<express.Express["listen"]>;
let baseUrl: string;

function fakeHttp(): GoogleOAuthHttp {
  return {
    exchangeAuthorizationCode: async () => ({
      accessToken: "at", refreshToken: "rt-SECRET", expiresIn: 3600, scope: "email",
    }),
    fetchMailboxProfile: async () => ({ email: EMAIL }),
    refreshAccessToken: async () => ({ accessToken: "at2", expiresIn: 3600, scope: "" }),
    revokeToken: async () => {},
  };
}

before(() => {
  process.env.AALIYAH_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "aaliyah-idhttp-"));
});

beforeEach(async () => {
  identity = createInMemoryIdentityState();
  mailState = createInMemoryMailState();
  auth = createAuthService(identity, { google: { clientId: CLIENT_ID, jwks } });
  const connectDeps: GoogleConnectDeps = { http: fakeHttp(), kms: KMS, state: mailState, clientId: "client-1" };
  const routesDeps: MailRoutesDeps = {
    capability: { provider: "google", available: true },
    redirectUri: REDIRECT,
    frontendInboxesUrl: "https://app.example/settings/inboxes",
    connectDeps,
    auth: { principalForToken: auth.principalForToken },
    state: mailState,
  };
  if (server) server.close();
  const app = express();
  app.use(express.json());
  app.use(createAuthRouter({ auth, googleLoginAvailable: true }));
  app.use(createMailRouter(routesDeps));
  await new Promise<void>((resolve) => {
    server = app.listen(0, () => resolve());
  });
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(() => {
  if (server) server.close();
});

async function provisionAndre(): Promise<void> {
  const user = await auth.provisionUser({
    tenantId: TENANT, externalProvider: "google", externalSubject: "goog-sub-andre",
    email: "andre@pussycatalley.com", emailVerified: true,
  });
  await identity.memberships.grant({
    userId: user.id, tenantId: TENANT, workspaceId: WS,
    roleIds: ["workspace_admin"], status: "active",
    createdAt: new Date().toISOString(), revokedAt: null,
  });
}

type LoginResult = { cookies: string[]; sessionCookie: string; csrfToken: string; body: Record<string, unknown> };

async function loginViaHttp(): Promise<LoginResult> {
  const res = await fetch(`${baseUrl}/api/auth/google/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ idToken: idToken(), tenantId: TENANT }),
  });
  assert.equal(res.status, 200);
  const cookies = res.headers.getSetCookie();
  const sessionCookie = cookies.find((c) => c.startsWith("aaliyah_session="))!;
  const body = (await res.json()) as Record<string, unknown>;
  return { cookies, sessionCookie, csrfToken: body.csrfToken as string, body };
}

function cookieHeader(login: LoginResult): string {
  return login.cookies.map((c) => c.split(";")[0]).join("; ");
}

// ---- Login route ----

test("login sets a Secure httpOnly SameSite session cookie and a CSRF token; token never echoed", async () => {
  await provisionAndre();
  const login = await loginViaHttp();

  assert.match(login.sessionCookie, /HttpOnly/);
  assert.match(login.sessionCookie, /Secure/);
  assert.match(login.sessionCookie, /SameSite=Strict/);
  const csrfCookie = login.cookies.find((c) => c.startsWith("aaliyah_csrf="))!;
  assert.ok(!/HttpOnly/.test(csrfCookie)); // double-submit needs JS access
  assert.ok(login.csrfToken.length > 10);

  // The response body never carries the session token itself.
  const sessionToken = /aaliyah_session=([^;]+)/.exec(login.sessionCookie)![1]!;
  assert.ok(!JSON.stringify(login.body).includes(sessionToken));
});

test("login failures are a single generic refusal — no oracle, no token echo", async () => {
  // Nobody provisioned.
  const res = await fetch(`${baseUrl}/api/auth/google/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ idToken: idToken(), tenantId: TENANT }),
  });
  assert.equal(res.status, 401);
  const text = await res.text();
  assert.equal(JSON.parse(text).error, "login_refused");
  assert.ok(!text.includes("goog-sub-andre"));
});

test("each login issues a fresh session — fixation impossible", async () => {
  await provisionAndre();
  const first = await loginViaHttp();
  const second = await loginViaHttp();
  assert.notEqual(first.sessionCookie, second.sessionCookie);
});

// ---- Cookie authentication + CSRF ----

test("cookie-authenticated mutation requires the CSRF header; reads do not", async () => {
  await provisionAndre();
  const login = await loginViaHttp();

  // Mutation without CSRF header → 403, nothing happens.
  const noCsrf = await fetch(`${baseUrl}/api/mail/connections/google/start`, {
    method: "POST",
    headers: { "content-type": "application/json", cookie: cookieHeader(login) },
    body: JSON.stringify({ workspaceId: WS }),
  });
  assert.equal(noCsrf.status, 403);
  assert.equal(((await noCsrf.json()) as { error: string }).error, "csrf_required");

  // Wrong CSRF value → 403.
  const wrongCsrf = await fetch(`${baseUrl}/api/mail/connections/google/start`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      cookie: cookieHeader(login),
      "x-aaliyah-csrf": "forged",
    },
    body: JSON.stringify({ workspaceId: WS }),
  });
  assert.equal(wrongCsrf.status, 403);

  // Matching CSRF → authorized mutation proceeds.
  const withCsrf = await fetch(`${baseUrl}/api/mail/connections/google/start`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      cookie: cookieHeader(login),
      "x-aaliyah-csrf": login.csrfToken,
    },
    body: JSON.stringify({ workspaceId: WS }),
  });
  assert.equal(withCsrf.status, 200);

  // GET with cookie alone works (no ambient-credential mutation risk).
  const read = await fetch(`${baseUrl}/api/mail/connections/nonexistent?workspaceId=${WS}`, {
    headers: { cookie: cookieHeader(login) },
  });
  assert.equal(read.status, 404); // authenticated, authorized, just absent
});

// ---- Logout + identity/mailbox separation ----

test("logout revokes the durable session and clears cookies — but never touches the mailbox", async () => {
  await provisionAndre();
  const login = await loginViaHttp();

  // Connect a mailbox first (bearer path for brevity).
  const sessionToken = decodeURIComponent(/aaliyah_session=([^;]+)/.exec(login.sessionCookie)![1]!);
  const start = await fetch(`${baseUrl}/api/mail/connections/google/start`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${sessionToken}` },
    body: JSON.stringify({ workspaceId: WS }),
  });
  const { authorizationUrl } = (await start.json()) as { authorizationUrl: string };
  const state = new URL(authorizationUrl).searchParams.get("state")!;
  const cb = await fetch(
    `${baseUrl}/api/mail/connections/google/callback?code=c&state=${encodeURIComponent(state)}`,
    { headers: { authorization: `Bearer ${sessionToken}` }, redirect: "manual" },
  );
  assert.ok(cb.headers.get("location")!.includes("connection=success"));
  const connections = mailState.dump().connections as Array<{ connectionId: string }>;
  assert.equal(connections.length, 1);

  // Logout.
  const logout = await fetch(`${baseUrl}/api/auth/logout`, {
    method: "POST",
    headers: { authorization: `Bearer ${sessionToken}` },
  });
  assert.equal(logout.status, 200);
  assert.ok(logout.headers.getSetCookie().some((c) => c.includes("aaliyah_session=;")));

  // The durable session is revoked…
  assert.equal(await auth.principalForToken(sessionToken), null);
  // …but the company mailbox connection and its credential are untouched.
  const dumped = mailState.dump();
  assert.equal((dumped.connections as unknown[]).length, 1);
  assert.equal((dumped.credentials as Array<{ revokedAt: string | null }>)[0]!.revokedAt, null);
});

test("disconnecting the mailbox never deletes the admin's login identity or session", async () => {
  await provisionAndre();
  const login = await loginViaHttp();
  const sessionToken = decodeURIComponent(/aaliyah_session=([^;]+)/.exec(login.sessionCookie)![1]!);
  const bearer = { "content-type": "application/json", authorization: `Bearer ${sessionToken}` };

  const start = await fetch(`${baseUrl}/api/mail/connections/google/start`, {
    method: "POST", headers: bearer, body: JSON.stringify({ workspaceId: WS }),
  });
  const { authorizationUrl } = (await start.json()) as { authorizationUrl: string };
  const state = new URL(authorizationUrl).searchParams.get("state")!;
  await fetch(
    `${baseUrl}/api/mail/connections/google/callback?code=c&state=${encodeURIComponent(state)}`,
    { headers: { authorization: `Bearer ${sessionToken}` }, redirect: "manual" },
  );
  const connectionId = (mailState.dump().connections as Array<{ connectionId: string }>)[0]!.connectionId;

  const del = await fetch(`${baseUrl}/api/mail/connections/${connectionId}?workspaceId=${WS}`, {
    method: "DELETE", headers: bearer,
  });
  assert.equal(del.status, 200);

  // Identity untouched: session still valid, user still active.
  assert.ok(await auth.principalForToken(sessionToken));
  const users = identity.dump().users as Array<{ status: string }>;
  assert.equal(users[0]!.status, "active");
});

// ---- Production fail-closed ----

test("production cannot boot with the in-memory identity backend", () => {
  assert.throws(
    () => identityStateFromEnv({ NODE_ENV: "production" } as NodeJS.ProcessEnv),
    /AALIYAH_DATABASE_URL/,
  );
  assert.ok(identityStateFromEnv({} as NodeJS.ProcessEnv)); // dev twin allowed
});
