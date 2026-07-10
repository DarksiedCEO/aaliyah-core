import assert from "node:assert/strict";
import test, { beforeEach } from "node:test";

import type { KeyProvider } from "../src/crypto/authenticatedEncryption";
import {
  clearOAuthStates,
  createOAuthState,
  consumeOAuthState,
  debugOAuthStates,
} from "../src/mail/security/oauthStateStore";
import {
  handleGoogleCallback,
  type GoogleConnectDeps,
  type GoogleOAuthHttp,
} from "../src/mail/google/googleConnect";
import { clearMailCredentials } from "../src/mail/security/credentialVault";
import { clearConnections, getConnection } from "../src/mail/connectionStore";

const KP: KeyProvider = { currentVersion: () => "v1", key: () => Buffer.alloc(32, 7) };
const REDIRECT = "https://app.example/oauth/google/callback";
const BIND = {
  tenantId: "tenant_a",
  workspaceId: "tenant_a:default",
  userId: "u1",
  sessionId: "sess_original",
  redirectUri: REDIRECT,
  keyProvider: KP,
};

beforeEach(() => {
  clearOAuthStates();
  clearMailCredentials();
  clearConnections();
});

test("oauth state is persisted hashed with an encrypted verifier only", () => {
  const { stateValue, codeChallenge } = createOAuthState(BIND);
  assert.ok(stateValue.length > 20);
  assert.ok(codeChallenge.length > 20);

  const stored = JSON.stringify(debugOAuthStates());
  // Neither the raw state value nor any plaintext verifier may be persisted.
  assert.ok(!stored.includes(stateValue), "raw state value must not be stored");
  assert.ok(!stored.includes('"codeVerifier"'), "plaintext verifier field must not exist");
  assert.ok(stored.includes("codeVerifierEncrypted"));
  assert.ok(stored.includes(BIND.sessionId), "state must be bound to the session");
});

test("consume succeeds only for the original session and returns the verifier once", () => {
  const { stateValue } = createOAuthState(BIND);

  // A different authenticated session cannot consume the state.
  assert.throws(
    () =>
      consumeOAuthState(stateValue, {
        redirectUri: REDIRECT,
        sessionId: "sess_hijacker",
        keyProvider: KP,
      }),
    /session/,
  );

  const consumed = consumeOAuthState(stateValue, {
    redirectUri: REDIRECT,
    sessionId: "sess_original",
    keyProvider: KP,
  });
  assert.equal(consumed.tenantId, BIND.tenantId);
  assert.equal(consumed.workspaceId, BIND.workspaceId);
  assert.equal(consumed.userId, BIND.userId);
  assert.ok(consumed.codeVerifier.length > 20);

  // One-time: replay is dead even for the right session.
  assert.throws(
    () =>
      consumeOAuthState(stateValue, {
        redirectUri: REDIRECT,
        sessionId: "sess_original",
        keyProvider: KP,
      }),
    /already used/,
  );
});

test("expiry and redirect mismatch still fail closed under the new shape", () => {
  const t0 = Date.now();
  const { stateValue } = createOAuthState({ ...BIND, ttlMs: 1000, now: () => t0 });
  assert.throws(
    () =>
      consumeOAuthState(stateValue, {
        redirectUri: REDIRECT,
        sessionId: "sess_original",
        keyProvider: KP,
        now: () => t0 + 5000,
      }),
    /expired/,
  );

  const fresh = createOAuthState(BIND);
  assert.throws(
    () =>
      consumeOAuthState(fresh.stateValue, {
        redirectUri: "https://evil.example/callback",
        sessionId: "sess_original",
        keyProvider: KP,
      }),
    /redirect/,
  );
});

// ---- Callback transaction: bound to principal, tenant/workspace from state only ----

function fakeHttp(email: string): GoogleOAuthHttp & { revoked: string[] } {
  const revoked: string[] = [];
  return {
    revoked,
    exchangeAuthorizationCode: async () => ({
      accessToken: "at",
      refreshToken: "rt-SECRET",
      expiresIn: 3600,
      scope: "email",
    }),
    fetchMailboxProfile: async () => ({ email }),
    refreshAccessToken: async () => ({ accessToken: "at2", expiresIn: 3600, scope: "" }),
    revokeToken: async (t) => {
      revoked.push(t);
    },
  };
}

function connectDeps(http: GoogleOAuthHttp): GoogleConnectDeps {
  return { http, keyProvider: KP, clientId: "client-1" };
}

test("callback consumed under a different session is rejected and creates nothing", async () => {
  const { stateValue } = createOAuthState(BIND);
  const http = fakeHttp("sales@pussycatalley.com");

  await assert.rejects(
    () =>
      handleGoogleCallback(
        {
          code: "code-1",
          state: stateValue,
          redirectUri: REDIRECT,
          expectedSessionId: "sess_hijacker",
        },
        connectDeps(http),
      ),
    /session/,
  );
  // Nothing persisted for either tenant/workspace.
  assert.equal(debugOAuthStates().every((s) => s.consumedAt === null), true);
});

test("callback derives tenant and workspace from the bound state, never from caller input", async () => {
  const { stateValue } = createOAuthState(BIND);
  const http = fakeHttp("sales@pussycatalley.com");

  const sanitized = await handleGoogleCallback(
    { code: "code-1", state: stateValue, redirectUri: REDIRECT, expectedSessionId: "sess_original" },
    connectDeps(http),
  );
  assert.equal(sanitized.status, "connected");

  // The connection exists exactly in the state-bound scope…
  const inBoundScope = getConnection(sanitized.connectionId, {
    tenantId: BIND.tenantId,
    workspaceId: BIND.workspaceId,
  });
  assert.ok(inBoundScope);
  assert.equal(inBoundScope!.userId, BIND.userId);

  // …and is invisible to any other tenant, no matter what a caller claims.
  const crossTenant = getConnection(sanitized.connectionId, {
    tenantId: "tenant_b",
    workspaceId: "tenant_b:default",
  });
  assert.equal(crossTenant, undefined);
});
