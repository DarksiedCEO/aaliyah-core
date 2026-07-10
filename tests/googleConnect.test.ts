import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test, { before, beforeEach } from "node:test";

import type { KeyProvider } from "../src/crypto/authenticatedEncryption";
import { sealSecret, openSecret } from "../src/crypto/authenticatedEncryption";
import {
  buildGoogleAuthorizationUrl,
  handleGoogleCallback,
  refreshGoogleAccessToken,
  disconnectGoogle,
  type GoogleOAuthHttp,
  type GoogleConnectDeps,
} from "../src/mail/google/googleConnect";
import { clearOAuthStates } from "../src/mail/security/oauthStateStore";
import {
  getMailCredential,
  openRefreshToken,
  clearMailCredentials,
} from "../src/mail/security/credentialVault";
import { getConnection, clearConnections } from "../src/mail/connectionStore";
import {
  issueSendApproval,
  getApproval,
  clearSendApprovals,
} from "../src/mail/security/sendApproval";
import { readMailAudit } from "../src/mail/security/mailAudit";
import { connectionIdFor } from "../src/mail/adapters/helpers";

const NOW = () => "2026-06-23T12:00:00.000Z";
const KP: KeyProvider = { currentVersion: () => "v1", key: () => Buffer.alloc(32, 7) };
const REDIRECT = "https://app.aaliyah.example/oauth/google/callback";
const EMAIL = "sales@pussycatalley.com";
const SCOPE = { tenantId: "tenant_a", workspaceId: "tenant_a:default" };
const CONN_ID = connectionIdFor({
  tenantId: "tenant_a", workspaceId: "tenant_a:default", userId: "u1",
  provider: "google", emailAddress: EMAIL,
});

function fakeHttp(over: Partial<GoogleOAuthHttp> = {}): GoogleOAuthHttp & { revoked: string[] } {
  const revoked: string[] = [];
  return {
    revoked,
    exchangeAuthorizationCode: over.exchangeAuthorizationCode ?? (async () => ({
      accessToken: "at", refreshToken: "rt-SECRET", expiresIn: 3600,
      scope: "https://www.googleapis.com/auth/gmail.modify email",
    })),
    fetchMailboxProfile: over.fetchMailboxProfile ?? (async () => ({ email: EMAIL })),
    refreshAccessToken: over.refreshAccessToken ?? (async () => ({ accessToken: "at2", expiresIn: 3600, scope: "" })),
    revokeToken: over.revokeToken ?? (async (t: string) => { revoked.push(t); }),
  };
}

function deps(http: GoogleOAuthHttp): GoogleConnectDeps {
  return { http, keyProvider: KP, clientId: "client-123", now: NOW };
}

const SESSION = "sess_u1";

function authInput() {
  return {
    tenantId: "tenant_a", workspaceId: "tenant_a:default", userId: "u1",
    sessionId: SESSION, redirectUri: REDIRECT,
  };
}

before(() => {
  process.env.AALIYAH_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "aaliyah-google-"));
});
beforeEach(() => {
  clearOAuthStates();
  clearMailCredentials();
  clearConnections();
  clearSendApprovals();
});

test("authenticated encryption round-trips and detects tampering", () => {
  const sealed = sealSecret("rt-SECRET", KP);
  assert.notEqual(sealed.ciphertext, "rt-SECRET"); // ciphertext, not encoding
  assert.equal(openSecret(sealed, KP), "rt-SECRET");
  // Flip a byte in the ciphertext → GCM auth tag rejects it.
  const bytes = Buffer.from(sealed.ciphertext, "base64");
  bytes[30] = bytes[30]! ^ 1;
  assert.throws(() => openSecret({ ...sealed, ciphertext: bytes.toString("base64") }, KP));
});

test("authorization URL uses PKCE (S256) + state and leaks no secret", () => {
  const { url } = buildGoogleAuthorizationUrl(authInput(), deps(fakeHttp()));
  assert.match(url, /code_challenge=/);
  assert.match(url, /code_challenge_method=S256/);
  assert.match(url, /state=/);
  assert.ok(!url.includes("rt-SECRET"));
});

test("callback connects: sanitized status, encrypted-at-rest token, audit trail", async () => {
  const http = fakeHttp();
  const { state } = buildGoogleAuthorizationUrl(authInput(), deps(http));
  const result = await handleGoogleCallback(
    { code: "auth-code", state, redirectUri: REDIRECT, expectedSessionId: SESSION }, deps(http),
  );

  assert.equal(result.status, "connected");
  assert.equal(result.connectedEmail, EMAIL);
  assert.ok(!("refreshToken" in (result as object))); // no secret returned

  const cred = getMailCredential(CONN_ID, SCOPE)!;
  assert.notEqual(cred.encryptedRefreshToken, "rt-SECRET"); // stored as ciphertext
  assert.equal(openRefreshToken(CONN_ID, SCOPE, KP), "rt-SECRET"); // decrypts internally

  // Audit records the connect, and contains no secret.
  const audit = readMailAudit(SCOPE);
  assert.ok(audit.some((e) => e.action === "google.connected"));
  assert.ok(!JSON.stringify(audit).includes("rt-SECRET"));
});

test("OAuth state cannot be replayed and a foreign tenant is rejected", async () => {
  const http = fakeHttp();
  const { state } = buildGoogleAuthorizationUrl(authInput(), deps(http));

  await handleGoogleCallback({ code: "c", state, redirectUri: REDIRECT, expectedSessionId: SESSION }, deps(http));
  // Replay of the same state is dead.
  await assert.rejects(
    () => handleGoogleCallback({ code: "c", state, redirectUri: REDIRECT, expectedSessionId: SESSION }, deps(http)),
    /state already used/,
  );

  // Wrong redirect URI is rejected.
  const { state: s2 } = buildGoogleAuthorizationUrl(authInput(), deps(http));
  await assert.rejects(
    () => handleGoogleCallback({ code: "c", state: s2, redirectUri: "https://evil.example/cb", expectedSessionId: SESSION }, deps(http)),
    /redirect URI mismatch/,
  );

  // Tenant confusion is rejected.
  const { state: s3 } = buildGoogleAuthorizationUrl(authInput(), deps(http));
  await assert.rejects(
    () => handleGoogleCallback({ code: "c", state: s3, redirectUri: REDIRECT, expectedSessionId: SESSION, expectedTenantId: "tenant_b" }, deps(http)),
    /tenant mismatch/,
  );
});

test("a failed code exchange leaves no orphan credential or connection", async () => {
  const http = fakeHttp({ exchangeAuthorizationCode: async () => { throw new Error("google 400"); } });
  const { state } = buildGoogleAuthorizationUrl(authInput(), deps(http));
  await assert.rejects(() => handleGoogleCallback({ code: "c", state, redirectUri: REDIRECT, expectedSessionId: SESSION }, deps(http)));
  assert.equal(getMailCredential(CONN_ID, SCOPE), undefined);
  assert.equal(getConnection(CONN_ID, SCOPE), undefined);
});

test("tenant isolation: another tenant cannot read the connection or credential", async () => {
  const http = fakeHttp();
  const { state } = buildGoogleAuthorizationUrl(authInput(), deps(http));
  await handleGoogleCallback({ code: "c", state, redirectUri: REDIRECT, expectedSessionId: SESSION }, deps(http));

  const foreign = { tenantId: "tenant_b", workspaceId: "tenant_b:default" };
  assert.equal(getMailCredential(CONN_ID, foreign), undefined);
  assert.equal(getConnection(CONN_ID, foreign), undefined);
});

test("access token refresh works, and disconnect revokes + destroys + invalidates", async () => {
  const http = fakeHttp();
  const { state } = buildGoogleAuthorizationUrl(authInput(), deps(http));
  await handleGoogleCallback({ code: "c", state, redirectUri: REDIRECT, expectedSessionId: SESSION }, deps(http));

  // Refresh works from the encrypted token.
  assert.equal(await refreshGoogleAccessToken(CONN_ID, SCOPE, deps(http)), "at2");

  // A pending send approval exists for this connection.
  const approval = issueSendApproval({
    tenantId: "tenant_a", workspaceId: "tenant_a:default", connectionId: CONN_ID,
    to: [{ email: "c@e.com" }], subject: "s", body: "b", approvedByUserId: "u1",
  });

  let jobsStopped = false;
  await disconnectGoogle(CONN_ID, SCOPE, {
    ...deps(http), onDisconnect: () => { jobsStopped = true; },
  });

  // Provider token revoked, queued work stopped, connection gone.
  assert.deepEqual(http.revoked, ["rt-SECRET"]);
  assert.equal(jobsStopped, true);
  assert.equal(getConnection(CONN_ID, SCOPE), undefined);

  // Credential destroyed → refresh now impossible.
  await assert.rejects(() => refreshGoogleAccessToken(CONN_ID, SCOPE, deps(http)), /revoked|not found/);

  // Pending approval invalidated → terminally failed, cannot be claimed.
  assert.equal(getApproval(approval.approvalId)!.status, "failed_terminal");

  // Disconnect audited.
  assert.ok(readMailAudit(SCOPE).some((e) => e.action === "google.disconnected"));
});
