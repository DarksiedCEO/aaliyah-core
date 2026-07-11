import assert from "node:assert/strict";
import test, { beforeEach } from "node:test";

import { localMasterKms } from "../src/crypto/envelopeEncryption";
import {
  createOAuthState,
  consumeOAuthState,
  type OAuthStateDeps,
} from "../src/mail/security/oauthStateStore";
import {
  handleGoogleCallback,
  type GoogleConnectDeps,
  type GoogleOAuthHttp,
} from "../src/mail/google/googleConnect";
import { createInMemoryMailState } from "../src/mail/mailState";

const KMS = localMasterKms({ keyId: "v1", masterKey: Buffer.alloc(32, 7) });
const REDIRECT = "https://app.example/oauth/google/callback";
const BINDING = {
  tenantId: "tenant_a",
  workspaceId: "tenant_a:default",
  userId: "u1",
  sessionId: "sess_original",
  redirectUri: REDIRECT,
};

let state: ReturnType<typeof createInMemoryMailState>;
let deps: OAuthStateDeps;

beforeEach(() => {
  state = createInMemoryMailState();
  deps = { store: state.oauthStates, kms: KMS };
});

test("oauth state is persisted hashed with an encrypted verifier only", async () => {
  const { stateValue, codeChallenge } = await createOAuthState(BINDING, deps);
  assert.ok(stateValue.length > 20);
  assert.ok(codeChallenge.length > 20);

  const stored = JSON.stringify(state.dump().oauthStates);
  // Neither the raw state value nor any plaintext verifier may be persisted.
  assert.ok(!stored.includes(stateValue), "raw state value must not be stored");
  assert.ok(!stored.includes('"codeVerifier"'), "plaintext verifier field must not exist");
  assert.ok(stored.includes("codeVerifierEncrypted"));
  assert.ok(stored.includes(BINDING.sessionId), "state must be bound to the session");
});

test("consume succeeds only for the original session and returns the verifier once", async () => {
  const { stateValue } = await createOAuthState(BINDING, deps);

  // A different authenticated session cannot consume the state.
  await assert.rejects(
    () =>
      consumeOAuthState(stateValue, { redirectUri: REDIRECT, sessionId: "sess_hijacker" }, deps),
    /session/,
  );

  const consumed = await consumeOAuthState(
    stateValue,
    { redirectUri: REDIRECT, sessionId: "sess_original" },
    deps,
  );
  assert.equal(consumed.tenantId, BINDING.tenantId);
  assert.equal(consumed.workspaceId, BINDING.workspaceId);
  assert.equal(consumed.userId, BINDING.userId);
  assert.ok(consumed.codeVerifier.length > 20);

  // One-time: replay is dead even for the right session.
  await assert.rejects(
    () =>
      consumeOAuthState(stateValue, { redirectUri: REDIRECT, sessionId: "sess_original" }, deps),
    /already used/,
  );
});

test("expiry and redirect mismatch still fail closed under the new shape", async () => {
  const t0 = Date.now();
  const { stateValue } = await createOAuthState({ ...BINDING, ttlMs: 1000, now: () => t0 }, deps);
  await assert.rejects(
    () =>
      consumeOAuthState(
        stateValue,
        { redirectUri: REDIRECT, sessionId: "sess_original", now: () => t0 + 5000 },
        deps,
      ),
    /expired/,
  );

  const fresh = await createOAuthState(BINDING, deps);
  await assert.rejects(
    () =>
      consumeOAuthState(
        fresh.stateValue,
        { redirectUri: "https://evil.example/callback", sessionId: "sess_original" },
        deps,
      ),
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
  return { http, kms: KMS, state, clientId: "client-1" };
}

test("callback consumed under a different session is rejected and creates nothing", async () => {
  const { stateValue } = await createOAuthState(BINDING, deps);
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
  const stored = state.dump();
  assert.equal(stored.connections!.length, 0);
  assert.equal(stored.credentials!.length, 0);
});

test("callback derives tenant and workspace from the bound state, never from caller input", async () => {
  const { stateValue } = await createOAuthState(BINDING, deps);
  const http = fakeHttp("sales@pussycatalley.com");

  const sanitized = await handleGoogleCallback(
    { code: "code-1", state: stateValue, redirectUri: REDIRECT, expectedSessionId: "sess_original" },
    connectDeps(http),
  );
  assert.equal(sanitized.status, "connected");

  // The connection exists exactly in the state-bound scope…
  const inBoundScope = await state.connections.get(sanitized.connectionId, {
    tenantId: BINDING.tenantId,
    workspaceId: BINDING.workspaceId,
  });
  assert.ok(inBoundScope);
  assert.equal(inBoundScope!.userId, BINDING.userId);

  // …and is invisible to any other tenant, no matter what a caller claims.
  const crossTenant = await state.connections.get(sanitized.connectionId, {
    tenantId: "tenant_b",
    workspaceId: "tenant_b:default",
  });
  assert.equal(crossTenant, null);
});
