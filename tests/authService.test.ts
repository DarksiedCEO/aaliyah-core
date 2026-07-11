import assert from "node:assert/strict";
import crypto from "node:crypto";
import test, { beforeEach } from "node:test";

import type { AuthenticatedPrincipal } from "@aaliyah/contracts/v1";

import { createInMemoryIdentityState } from "../src/auth/identityState";
import {
  createAuthService,
  ServiceGrantRefusedError,
  type AuthService,
} from "../src/auth/authService";
import { authorizeMail, AuthorizationError } from "../src/auth/permissions";
import type { JwksProvider } from "../src/auth/googleIdentity";

const CLIENT_ID = "aaliyah-client-id.apps.googleusercontent.com";
const T0 = new Date("2026-07-10T12:00:00.000Z").getTime();
const HOUR = 60 * 60 * 1000;

const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = {
  ...(publicKey.export({ format: "jwk" }) as Record<string, unknown>),
  kid: "kid-1",
  alg: "RS256",
  use: "sig",
};
const jwks: JwksProvider = async () => ({ keys: [jwk] });

function idToken(over: Record<string, unknown> = {}): string {
  const b64u = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const body = {
    iss: "https://accounts.google.com",
    aud: CLIENT_ID,
    sub: "goog-sub-andre",
    email: "andre@pussycatalley.com",
    email_verified: true,
    iat: Math.floor(T0 / 1000),
    exp: Math.floor(T0 / 1000) + 3600,
    ...over,
  };
  const input = `${b64u({ alg: "RS256", kid: "kid-1", typ: "JWT" })}.${b64u(body)}`;
  const sig = crypto.sign("RSA-SHA256", Buffer.from(input), privateKey).toString("base64url");
  return `${input}.${sig}`;
}

let identity: ReturnType<typeof createInMemoryIdentityState>;
let auth: AuthService;
let clock: number;

beforeEach(() => {
  identity = createInMemoryIdentityState();
  clock = T0;
  auth = createAuthService(identity, {
    google: { clientId: CLIENT_ID, jwks },
    sessionTtlMs: 12 * HOUR,
    idleTtlMs: 1 * HOUR,
    now: () => clock,
  });
});

async function provisionAndre(roles: string[] = ["workspace_admin"], workspaces = ["tenant_a:default"]) {
  const user = await auth.provisionUser({
    tenantId: "tenant_a",
    externalProvider: "google",
    externalSubject: "goog-sub-andre",
    email: "andre@pussycatalley.com",
    emailVerified: true,
  });
  for (const workspaceId of workspaces) {
    await identity.memberships.grant({
      userId: user.id, tenantId: "tenant_a", workspaceId,
      roleIds: roles, status: "active", createdAt: new Date(clock).toISOString(), revokedAt: null,
    });
  }
  return user;
}

// ---- Login ----

test("google login: verified assertion + provisioned membership → session; raw token never persists", async () => {
  await provisionAndre();
  const login = await auth.loginWithGoogle({ idToken: idToken(), tenantId: "tenant_a" });
  assert.ok(login.token.length > 20);

  const principal = (await auth.principalForToken(login.token)) as AuthenticatedPrincipal;
  assert.equal(principal.actorType, "user");
  assert.equal(principal.tenantId, "tenant_a");
  assert.deepEqual(principal.workspaceIds, ["tenant_a:default"]);

  // Raw token exists nowhere in the durable state.
  assert.ok(!JSON.stringify(identity.dump()).includes(login.token));
});

test("unprovisioned external subject cannot log in — same email, different subject is a different person", async () => {
  await provisionAndre();
  await assert.rejects(
    () => auth.loginWithGoogle({ idToken: idToken({ sub: "goog-sub-IMPOSTOR" }), tenantId: "tenant_a" }),
    /not provisioned/,
  );
});

test("login without an active membership in the tenant is refused", async () => {
  await auth.provisionUser({
    tenantId: "tenant_a", externalProvider: "google",
    externalSubject: "goog-sub-andre", email: "andre@pussycatalley.com", emailVerified: true,
  });
  await assert.rejects(
    () => auth.loginWithGoogle({ idToken: idToken(), tenantId: "tenant_a" }),
    /membership/,
  );
});

test("forged assertions and unverified email never reach a session", async () => {
  await provisionAndre();
  const { privateKey: rogue } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const b64u = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const input = `${b64u({ alg: "RS256", kid: "kid-1", typ: "JWT" })}.${b64u({
    iss: "https://accounts.google.com", aud: CLIENT_ID, sub: "goog-sub-andre",
    email: "andre@pussycatalley.com", email_verified: true,
    iat: Math.floor(T0 / 1000), exp: Math.floor(T0 / 1000) + 3600,
  })}`;
  const forged = `${input}.${crypto.sign("RSA-SHA256", Buffer.from(input), rogue).toString("base64url")}`;
  await assert.rejects(() => auth.loginWithGoogle({ idToken: forged, tenantId: "tenant_a" }), /signature/);

  await assert.rejects(
    () => auth.loginWithGoogle({ idToken: idToken({ email_verified: false }), tenantId: "tenant_a" }),
    /email/,
  );
});

// ---- Session lifecycle ----

test("forged, expired, idle, and revoked sessions all resolve to nothing", async () => {
  await provisionAndre();
  const { token } = await auth.loginWithGoogle({ idToken: idToken(), tenantId: "tenant_a" });

  assert.equal(await auth.principalForToken("forged-token"), null);

  // Idle expiry: 61 minutes of silence.
  clock = T0 + 61 * 60 * 1000;
  assert.equal(await auth.principalForToken(token), null);

  // Fresh login, then absolute expiry despite activity.
  clock = T0;
  const second = await auth.loginWithGoogle({ idToken: idToken(), tenantId: "tenant_a" });
  for (let i = 1; i <= 13; i += 1) {
    clock = T0 + i * 55 * 60 * 1000; // keep touching before idle timeout
    await auth.principalForToken(second.token);
  }
  clock = T0 + 13 * HOUR;
  assert.equal(await auth.principalForToken(second.token), null);

  // Revocation.
  clock = T0;
  const third = await auth.loginWithGoogle({ idToken: idToken(), tenantId: "tenant_a" });
  await auth.logout(third.token);
  assert.equal(await auth.principalForToken(third.token), null);
  // And the durable record is revoked, not deleted (auditability).
  const dumped = identity.dump().sessions as Array<{ id: string; revokedAt: string | null }>;
  assert.ok(dumped.some((s) => s.id === third.sessionId && s.revokedAt !== null));
});

test("session rotation: the old token dies the moment the new one exists", async () => {
  await provisionAndre();
  const { token } = await auth.loginWithGoogle({ idToken: idToken(), tenantId: "tenant_a" });
  const rotated = await auth.rotateSession(token);
  assert.notEqual(rotated.token, token);
  assert.equal(await auth.principalForToken(token), null);
  assert.ok(await auth.principalForToken(rotated.token));
});

test("every login issues a fresh server-generated session — no fixation", async () => {
  await provisionAndre();
  const a = await auth.loginWithGoogle({ idToken: idToken(), tenantId: "tenant_a" });
  const b = await auth.loginWithGoogle({ idToken: idToken(), tenantId: "tenant_a" });
  assert.notEqual(a.token, b.token);
  assert.notEqual(a.sessionId, b.sessionId);
});

test("a disabled user loses access immediately, on existing sessions too", async () => {
  const user = await provisionAndre();
  const { token } = await auth.loginWithGoogle({ idToken: idToken(), tenantId: "tenant_a" });
  assert.ok(await auth.principalForToken(token));

  await identity.users.setStatus(user.id, "disabled");
  assert.equal(await auth.principalForToken(token), null);
  await assert.rejects(
    () => auth.loginWithGoogle({ idToken: idToken(), tenantId: "tenant_a" }),
    /disabled|not provisioned/,
  );
});

// ---- Membership authority: live, per-workspace ----

test("suspended membership and role changes take effect without restart", async () => {
  const user = await provisionAndre(["workspace_admin"], ["tenant_a:default", "tenant_a:ops"]);
  const { token } = await auth.loginWithGoogle({ idToken: idToken(), tenantId: "tenant_a" });

  let principal = (await auth.principalForToken(token)) as AuthenticatedPrincipal;
  assert.deepEqual(principal.workspaceIds, ["tenant_a:default", "tenant_a:ops"]);

  await identity.memberships.setStatus(user.id, "tenant_a", "tenant_a:ops", "suspended");
  principal = (await auth.principalForToken(token)) as AuthenticatedPrincipal;
  assert.deepEqual(principal.workspaceIds, ["tenant_a:default"]);

  // Role downgrade applies on the very next request.
  await identity.memberships.grant({
    userId: user.id, tenantId: "tenant_a", workspaceId: "tenant_a:default",
    roleIds: ["workspace_member"], status: "active",
    createdAt: new Date(clock).toISOString(), revokedAt: null,
  });
  principal = (await auth.principalForToken(token)) as AuthenticatedPrincipal;
  assert.throws(
    () => authorizeMail(principal, "mail.connection.create", { tenantId: "tenant_a", workspaceId: "tenant_a:default" }),
    AuthorizationError,
  );
});

test("per-workspace roles: admin of one workspace is not admin of its sibling", async () => {
  const user = await provisionAndre([], []);
  await identity.memberships.grant({
    userId: user.id, tenantId: "tenant_a", workspaceId: "tenant_a:default",
    roleIds: ["workspace_admin"], status: "active", createdAt: new Date(clock).toISOString(), revokedAt: null,
  });
  await identity.memberships.grant({
    userId: user.id, tenantId: "tenant_a", workspaceId: "tenant_a:ops",
    roleIds: ["workspace_member"], status: "active", createdAt: new Date(clock).toISOString(), revokedAt: null,
  });
  const { token } = await auth.loginWithGoogle({ idToken: idToken(), tenantId: "tenant_a" });
  const principal = (await auth.principalForToken(token)) as AuthenticatedPrincipal;

  // Admin where admin…
  authorizeMail(principal, "mail.connection.create", { tenantId: "tenant_a", workspaceId: "tenant_a:default" });
  // …member where member, despite holding admin elsewhere in the tenant.
  assert.throws(
    () => authorizeMail(principal, "mail.connection.create", { tenantId: "tenant_a", workspaceId: "tenant_a:ops" }),
    AuthorizationError,
  );
});

// ---- Service identities ----

test("service identities: hashed rotatable credentials, narrow grants, refused admin/send", async () => {
  const registered = await auth.registerServiceIdentity({
    name: "mail.reader",
    tenantId: "tenant_a",
    workspaceIds: ["tenant_a:default"],
    grants: ["mail.connection.read"],
  });
  assert.ok(registered.serviceToken.length > 20);
  assert.ok(!JSON.stringify(identity.dump()).includes(registered.serviceToken));

  const principal = await auth.principalForToken(registered.serviceToken);
  assert.equal(principal?.actorType, "service");

  for (const refused of ["mail.connection.create", "mail.connection.disconnect", "mail.send.execute"] as const) {
    await assert.rejects(
      () =>
        auth.registerServiceIdentity({
          name: "greedy.worker", tenantId: "tenant_a", workspaceIds: [], grants: [refused],
        }),
      ServiceGrantRefusedError,
    );
  }

  const rotated = await auth.rotateServiceCredential(registered.serviceId);
  assert.equal(await auth.principalForToken(registered.serviceToken), null);
  assert.ok(await auth.principalForToken(rotated.serviceToken));
});

// ---- Fail-closed on identity backend outage ----

test("an identity backend outage fails authentication closed, loudly", async () => {
  await provisionAndre();
  const { token } = await auth.loginWithGoogle({ idToken: idToken(), tenantId: "tenant_a" });
  const broken = createAuthService(
    {
      ...identity,
      sessions: {
        ...identity.sessions,
        getByTokenHash: async () => {
          throw new Error("database unavailable");
        },
      },
    },
    { google: { clientId: CLIENT_ID, jwks }, now: () => clock },
  );
  await assert.rejects(() => broken.principalForToken(token), /database unavailable/);
});
