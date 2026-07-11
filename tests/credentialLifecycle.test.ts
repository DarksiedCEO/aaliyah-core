import assert from "node:assert/strict";
import test, { beforeEach } from "node:test";

import { localMasterKms, envelopeOpen } from "../src/crypto/envelopeEncryption";
import { createInMemoryMailState } from "../src/mail/mailState";
import { saveMailCredential } from "../src/mail/security/credentialVault";
import { connectionIdFor } from "../src/mail/adapters/helpers";
import { GoogleHttpError } from "../src/mail/google/googleOAuthHttp";
import {
  createCredentialLifecycle,
  CredentialRevokedError,
  ReauthRequiredError,
  TransientCredentialError,
} from "../src/mail/google/credentialLifecycle";

const KMS = localMasterKms({ keyId: "v1", masterKey: Buffer.alloc(32, 7) });
const EMAIL = "sales@pussycatalley.com";
const SCOPE = { tenantId: "tenant_a", workspaceId: "tenant_a:default" };
const SCOPE_B = { tenantId: "tenant_b", workspaceId: "tenant_b:default" };
const CONN_ID = connectionIdFor({
  tenantId: "tenant_a", workspaceId: "tenant_a:default", userId: "u1",
  provider: "google", emailAddress: EMAIL,
});

const T0 = Date.parse("2026-07-11T12:00:00.000Z");

let state: ReturnType<typeof createInMemoryMailState>;

async function seedCredential(
  scope = SCOPE,
  refreshToken = "rt-SUPER-SECRET",
): Promise<void> {
  await saveMailCredential(
    {
      connectionId: CONN_ID,
      tenantId: scope.tenantId,
      workspaceId: scope.workspaceId,
      userId: "u1",
      refreshToken,
      grantedScopes: ["https://www.googleapis.com/auth/gmail.modify"],
      connectedEmail: EMAIL,
      accessTokenExpiresAt: null,
    },
    { store: state.credentials, kms: KMS },
  );
}

/** Counting refresh transport; access token is a fixed sentinel unless overridden. */
function refresher(
  impl?: (rt: string) => Promise<{ accessToken: string; refreshToken?: string; expiresIn: number; scope: string }>,
) {
  let calls = 0;
  return {
    get calls() {
      return calls;
    },
    http: {
      async refreshAccessToken(rt: string) {
        calls += 1;
        if (impl) return impl(rt);
        return { accessToken: "at-SECRET-VALUE", expiresIn: 3600, scope: "" };
      },
    },
  };
}

beforeEach(() => {
  state = createInMemoryMailState();
});

test("a valid cached access token is reused without a second refresh", async () => {
  await seedCredential();
  const r = refresher();
  const life = createCredentialLifecycle({ state, kms: KMS, http: r.http, now: () => T0 });

  const first = await life.getFreshAccessToken(CONN_ID, SCOPE);
  const second = await life.getFreshAccessToken(CONN_ID, SCOPE);

  assert.equal(first, "at-SECRET-VALUE");
  assert.equal(second, "at-SECRET-VALUE");
  assert.equal(r.calls, 1, "second call must reuse the cached token");
});

test("a token inside the refresh-before-expiry skew is proactively refreshed", async () => {
  await seedCredential();
  const r = refresher();
  let clock = T0;
  const life = createCredentialLifecycle({
    state, kms: KMS, http: r.http, now: () => clock, refreshSkewMs: 60_000,
  });

  await life.getFreshAccessToken(CONN_ID, SCOPE); // caches exp = T0 + 3600s
  clock = T0 + 3600_000 - 30_000; // within the 60s skew window
  await life.getFreshAccessToken(CONN_ID, SCOPE);

  assert.equal(r.calls, 2, "near-expiry token must be refreshed");
});

test("ten simultaneous requests trigger exactly one refresh (single-flight)", async () => {
  await seedCredential();
  let calls = 0;
  const http = {
    async refreshAccessToken() {
      calls += 1;
      await new Promise((res) => setTimeout(res, 5));
      return { accessToken: "at-SECRET-VALUE", expiresIn: 3600, scope: "" };
    },
  };
  const life = createCredentialLifecycle({ state, kms: KMS, http, now: () => T0 });

  const tokens = await Promise.all(
    Array.from({ length: 10 }, () => life.getFreshAccessToken(CONN_ID, SCOPE)),
  );

  assert.equal(calls, 1, "concurrent callers must share one in-flight refresh");
  assert.ok(tokens.every((t) => t === "at-SECRET-VALUE"));
});

test("successful refresh persists the new expiry, rotates the refresh token, and marks healthy", async () => {
  await seedCredential();
  const r = refresher(async () => ({
    accessToken: "at-SECRET-VALUE",
    refreshToken: "rt-ROTATED-SECRET",
    expiresIn: 3600,
    scope: "",
  }));
  const life = createCredentialLifecycle({ state, kms: KMS, http: r.http, now: () => T0 });

  await life.getFreshAccessToken(CONN_ID, SCOPE);

  const cred = await state.credentials.get(CONN_ID, SCOPE);
  assert.ok(cred);
  assert.equal(cred!.accessTokenExpiresAt, new Date(T0 + 3600_000).toISOString());
  // The rotated refresh token replaced the old one, still only as an envelope.
  const opened = await envelopeOpen(cred!.envelope, KMS);
  assert.equal(opened, "rt-ROTATED-SECRET");

  const health = await state.health.get(CONN_ID, SCOPE);
  assert.equal(health!.state, "healthy");
  assert.equal(health!.healthy, true);
});

test("marks the connection refreshing while the refresh is in flight", async () => {
  await seedCredential();
  let observed: string | undefined;
  const http = {
    async refreshAccessToken() {
      observed = (await state.health.get(CONN_ID, SCOPE))?.state;
      return { accessToken: "at-SECRET-VALUE", expiresIn: 3600, scope: "" };
    },
  };
  const life = createCredentialLifecycle({ state, kms: KMS, http, now: () => T0 });

  await life.getFreshAccessToken(CONN_ID, SCOPE);
  assert.equal(observed, "refreshing");
});

test("a transient refresh failure marks degraded and returns no token", async () => {
  await seedCredential();
  const http = {
    async refreshAccessToken(): Promise<never> {
      throw new GoogleHttpError("refresh", 503, "cid-1");
    },
  };
  const life = createCredentialLifecycle({ state, kms: KMS, http, now: () => T0 });

  await assert.rejects(() => life.getFreshAccessToken(CONN_ID, SCOPE), TransientCredentialError);
  const health = await state.health.get(CONN_ID, SCOPE);
  assert.equal(health!.state, "degraded");
  assert.equal(health!.healthy, false);
});

test("invalid_grant marks reauthorization_required (never a transient failure)", async () => {
  await seedCredential();
  const http = {
    async refreshAccessToken(): Promise<never> {
      throw new GoogleHttpError("refresh", 400, "cid-1", "invalid_grant");
    },
  };
  const life = createCredentialLifecycle({ state, kms: KMS, http, now: () => T0 });

  await assert.rejects(() => life.getFreshAccessToken(CONN_ID, SCOPE), ReauthRequiredError);
  const health = await state.health.get(CONN_ID, SCOPE);
  assert.equal(health!.state, "reauthorization_required");
});

test("an already-revoked credential is refused without any provider call", async () => {
  await seedCredential();
  await state.credentials.revoke(CONN_ID, SCOPE);
  const r = refresher();
  const life = createCredentialLifecycle({ state, kms: KMS, http: r.http, now: () => T0 });

  await assert.rejects(() => life.getFreshAccessToken(CONN_ID, SCOPE), CredentialRevokedError);
  assert.equal(r.calls, 0, "revoked credentials must never hit the provider");
  const health = await state.health.get(CONN_ID, SCOPE);
  assert.equal(health!.state, "revoked");
});

test("a token cached for one tenant is never returned to another scope", async () => {
  await seedCredential(SCOPE);
  const r = refresher();
  const life = createCredentialLifecycle({ state, kms: KMS, http: r.http, now: () => T0 });

  await life.getFreshAccessToken(CONN_ID, SCOPE); // cache under tenant_a
  await assert.rejects(
    () => life.getFreshAccessToken(CONN_ID, SCOPE_B),
    /credential not found for scope/,
  );
  assert.equal(r.calls, 1, "cross-tenant lookup must not serve the cached token");
});

test("no refresh or access token ever reaches the logs", async () => {
  await seedCredential(SCOPE, "rt-SUPER-SECRET");
  const lines: string[] = [];
  const capture = {
    info: (o: unknown, m?: string) => lines.push(JSON.stringify(o) + String(m ?? "")),
    warn: (o: unknown, m?: string) => lines.push(JSON.stringify(o) + String(m ?? "")),
    error: (o: unknown, m?: string) => lines.push(JSON.stringify(o) + String(m ?? "")),
    debug: (o: unknown, m?: string) => lines.push(JSON.stringify(o) + String(m ?? "")),
  };
  const r = refresher(async () => ({
    accessToken: "at-SECRET-VALUE", refreshToken: "rt-ROTATED-SECRET", expiresIn: 3600, scope: "",
  }));
  const life = createCredentialLifecycle({
    state, kms: KMS, http: r.http, now: () => T0,
    logger: capture as unknown as import("pino").Logger,
  });

  await life.getFreshAccessToken(CONN_ID, SCOPE);

  const blob = lines.join("\n");
  assert.ok(!blob.includes("rt-SUPER-SECRET"), "refresh token leaked to logs");
  assert.ok(!blob.includes("rt-ROTATED-SECRET"), "rotated token leaked to logs");
  assert.ok(!blob.includes("at-SECRET-VALUE"), "access token leaked to logs");
});
